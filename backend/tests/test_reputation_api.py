import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest

from fastapi import HTTPException

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.main as main_module
from app.api import reputation as reputation_api
from app.core.config import settings
from app.core.database import Base, get_db
from app.models.reputation import IPReputationCache
from app.services import ip_reputation_service
from app.services.abuseipdb_client import (
    AbuseIPDBError,
    ProviderServerError,
    RateLimitError,
)
from app.services.reputation_cache import (
    NORMALIZED_FIELDS,
    upsert_reputation,
)


SECRET_API_KEY = "test-super-secret-api-key"

RESPONSE_KEYS = {
    "ip_address",
    "state",
    "risk_category",
    "provider",
    "reputation",
    "cache",
    "provider_error",
}

CACHE_KEYS = {
    "cached",
    "stale",
    "checked_at",
    "expires_at",
    "ttl_hours",
}

REPUTATION_KEYS = {
    "ip_address",
    "provider",
    *NORMALIZED_FIELDS,
}


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def normalized_data(ip_address="8.8.8.8", **overrides):
    data = {
        "ip_address": ip_address,
        "provider": "AbuseIPDB",
        "abuse_confidence_score": 87,
        "total_reports": 123,
        "num_distinct_users": 45,
        "last_reported_at": datetime(2025, 12, 31, 10, 30, 0),
        "isp": "Example ISP",
        "domain": "example.com",
        "country_code": "US",
        "usage_type": "Data Center/Web Hosting/Transit",
        "is_public": True,
        "is_whitelisted": False,
        "is_tor": False,
    }

    data.update(overrides)

    return data


def store_cache(
    db,
    ip_address="8.8.8.8",
    score=87,
    checked_at=None,
    ttl_hours=24,
    **overrides
):
    if checked_at is None:
        checked_at = utc_now()

    entry = upsert_reputation(
        db,
        normalized_data(
            ip_address,
            abuse_confidence_score=score,
            **overrides
        ),
        ttl_hours=ttl_hours,
        checked_at=checked_at
    )

    db.commit()
    db.refresh(entry)

    return entry


def parse_datetime(value):
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    return datetime.fromisoformat(value)


def assert_cache_consistency(payload, cached, stale):
    cache = payload["cache"]

    assert set(cache) == CACHE_KEYS
    assert cache["cached"] is cached
    assert cache["stale"] is stale
    assert cache["ttl_hours"] == (
        settings.IP_REPUTATION_CACHE_TTL_HOURS
    )

    if not cached:
        assert cache["checked_at"] is None
        assert cache["expires_at"] is None
        return

    checked_at = parse_datetime(cache["checked_at"])
    expires_at = parse_datetime(cache["expires_at"])

    assert expires_at == checked_at + timedelta(
        hours=cache["ttl_hours"]
    )


@pytest.fixture(autouse=True)
def enabled_reputation(monkeypatch):
    monkeypatch.setattr(settings, "IP_REPUTATION_ENABLED", True)


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )

    Base.metadata.create_all(bind=engine)

    TestingSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False
    )

    session = TestingSession()

    yield session

    session.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


async def _request_asgi(path, query_string):
    messages = []
    request_sent = False

    async def receive():
        nonlocal request_sent

        if not request_sent:
            request_sent = True
            return {
                "type": "http.request",
                "body": b"",
                "more_body": False,
            }

        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query_string,
        "headers": [],
        "client": ("testclient", 123),
        "server": ("testserver", 80),
        "root_path": "",
    }

    await main_module.app(scope, receive, send)

    start = next(
        message
        for message in messages
        if message["type"] == "http.response.start"
    )
    body = b"".join(
        message.get("body", b"")
        for message in messages
        if message["type"] == "http.response.body"
    )
    payload = json.loads(body.decode("utf-8")) if body else None

    return start["status"], payload


@pytest.fixture
def asgi_get(db):
    def override_get_db():
        yield db

    main_module.app.dependency_overrides[get_db] = override_get_db

    def request(path, query_string=b""):
        return asyncio.run(
            _request_asgi(path, query_string)
        )

    yield request

    main_module.app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def provider(monkeypatch):
    state = {
        "response": normalized_data(),
        "error": None,
        "calls": [],
    }

    def fake_check_ip(ip_address):
        state["calls"].append(ip_address)

        if state["error"] is not None:
            raise state["error"]

        response = dict(state["response"])
        response["ip_address"] = ip_address

        return response

    monkeypatch.setattr(
        ip_reputation_service,
        "check_ip",
        fake_check_ip
    )

    return state


def test_reputation_route_is_registered():
    paths = main_module.app.openapi()["paths"]
    route = paths.get("/api/reputation/{ip_address}")

    assert route is not None
    assert "get" in route

    parameters = {
        parameter["name"]: parameter
        for parameter in route["get"]["parameters"]
    }

    assert parameters["ip_address"]["in"] == "path"
    assert parameters["ip_address"]["required"] is True
    assert parameters["force_refresh"]["in"] == "query"
    assert parameters["force_refresh"]["required"] is False
    assert parameters["force_refresh"]["schema"]["default"] is False


def test_valid_public_ip_is_canonicalized_and_forwarded(
    db,
    monkeypatch
):
    calls = []

    def fake_get_reputation(db_arg, ip_address, force_refresh=False):
        calls.append((db_arg, ip_address, force_refresh))

        return {"ip_address": ip_address}

    monkeypatch.setattr(
        reputation_api,
        "get_reputation",
        fake_get_reputation
    )

    result = reputation_api.get_ip_reputation(
        "2606:4700:4700:0000:0000:0000:0000:1111",
        db=db
    )

    assert result == {
        "ip_address": "2606:4700:4700::1111"
    }
    assert calls == [
        (db, "2606:4700:4700::1111", False)
    ]


def test_fresh_cache_response_does_not_call_provider(db, provider):
    store_cache(db, score=87)
    provider["error"] = AssertionError(
        "provider should not be called"
    )

    result = reputation_api.get_ip_reputation("8.8.8.8", db=db)

    assert result["state"] == "cached"
    assert result["ip_address"] == "8.8.8.8"
    assert result["risk_category"] == "VERY_HIGH"
    assert result["provider"] == "AbuseIPDB"
    assert result["reputation"]["abuse_confidence_score"] == 87

    cache = result["cache"]

    assert cache["cached"] is True
    assert cache["stale"] is False
    assert cache["checked_at"] is not None
    assert cache["expires_at"] == (
        cache["checked_at"] + timedelta(hours=cache["ttl_hours"])
    )
    assert result["provider_error"] is None
    assert provider["calls"] == []


def test_provider_refresh_on_cache_miss(db, provider):
    provider["response"] = normalized_data(
        abuse_confidence_score=60
    )

    result = reputation_api.get_ip_reputation("8.8.8.8", db=db)

    assert result["state"] == "refreshed"
    assert result["risk_category"] == "HIGH"
    assert result["reputation"]["abuse_confidence_score"] == 60

    cache = result["cache"]

    assert cache["cached"] is True
    assert cache["stale"] is False
    assert cache["checked_at"] is not None
    assert cache["expires_at"] == (
        cache["checked_at"] + timedelta(hours=cache["ttl_hours"])
    )
    assert result["provider_error"] is None
    assert provider["calls"] == ["8.8.8.8"]
    assert db.query(IPReputationCache).count() == 1


def test_force_refresh_bypasses_fresh_cache(db, provider):
    store_cache(db, score=10)
    provider["response"] = normalized_data(
        abuse_confidence_score=90
    )

    result = reputation_api.get_ip_reputation(
        "8.8.8.8",
        force_refresh=True,
        db=db
    )

    assert result["state"] == "refreshed"
    assert result["risk_category"] == "VERY_HIGH"
    assert result["reputation"]["abuse_confidence_score"] == 90
    assert provider["calls"] == ["8.8.8.8"]

    db.expire_all()

    cached = db.query(IPReputationCache).filter(
        IPReputationCache.ip_address == "8.8.8.8"
    ).one()

    assert cached.abuse_confidence_score == 90


@pytest.mark.parametrize(
    "ip_address",
    [
        "192.168.1.1",
        "10.0.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "100.64.0.1",
        "08.08.08.08",
        "::1",
        "fe80::1",
        "ff02::1",
        "::",
        "2001:db8::1",
        "not-an-ip",
    ]
)
def test_invalid_or_non_public_ip_returns_400(
    db,
    monkeypatch,
    ip_address
):
    calls = []

    def fake_get_reputation(*args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.setattr(
        reputation_api,
        "get_reputation",
        fake_get_reputation
    )

    with pytest.raises(HTTPException) as error:
        reputation_api.get_ip_reputation(ip_address, db=db)

    assert error.value.status_code == 400
    assert error.value.detail == (
        "IP address must be a public IPv4 or IPv6 address"
    )
    assert ip_address not in error.value.detail
    assert calls == []


def test_feature_disabled_returns_503_without_lookup(
    db,
    monkeypatch
):
    monkeypatch.setattr(
        settings,
        "IP_REPUTATION_ENABLED",
        False
    )

    calls = []

    def fake_get_reputation(*args, **kwargs):
        calls.append((args, kwargs))

    monkeypatch.setattr(
        reputation_api,
        "get_reputation",
        fake_get_reputation
    )

    with pytest.raises(HTTPException) as error:
        reputation_api.get_ip_reputation("8.8.8.8", db=db)

    assert error.value.status_code == 503
    assert error.value.detail == (
        "IP reputation service is disabled"
    )
    assert calls == []


def test_provider_failure_without_cache_returns_unavailable(
    db,
    provider
):
    provider["error"] = RateLimitError()

    result = reputation_api.get_ip_reputation("8.8.8.8", db=db)

    assert result["state"] == "unavailable"
    assert result["risk_category"] == "UNKNOWN"
    assert result["provider"] is None
    assert result["reputation"] is None

    cache = result["cache"]

    assert cache["cached"] is False
    assert cache["stale"] is True
    assert cache["checked_at"] is None
    assert cache["expires_at"] is None
    assert cache["ttl_hours"] == 24
    assert result["provider_error"] == "rate_limited"
    assert provider["calls"] == ["8.8.8.8"]
    assert db.query(IPReputationCache).count() == 0


def test_provider_failure_with_stale_cache_returns_stale(
    db,
    provider
):
    stale_checked_at = utc_now() - timedelta(hours=48)

    store_cache(
        db,
        score=80,
        checked_at=stale_checked_at
    )

    provider["error"] = ProviderServerError(500)

    result = reputation_api.get_ip_reputation("8.8.8.8", db=db)

    assert result["state"] == "stale"
    assert result["risk_category"] == "VERY_HIGH"
    assert result["reputation"]["abuse_confidence_score"] == 80
    assert result["cache"]["cached"] is True
    assert result["cache"]["stale"] is True
    assert result["provider_error"] == "provider_server_error"
    assert provider["calls"] == ["8.8.8.8"]


def test_unexpected_service_error_returns_generic_500(
    db,
    monkeypatch
):
    secret = "super-secret-provider-token"

    def failing_get_reputation(*args, **kwargs):
        raise RuntimeError(
            f"raw provider response and {secret}"
        )

    monkeypatch.setattr(
        reputation_api,
        "get_reputation",
        failing_get_reputation
    )

    with pytest.raises(HTTPException) as error:
        reputation_api.get_ip_reputation("8.8.8.8", db=db)

    assert error.value.status_code == 500
    assert error.value.detail == "IP reputation lookup failed"
    assert secret not in error.value.detail
    assert "raw provider response" not in error.value.detail


def test_provider_error_response_is_sanitized(db, provider):
    secret = "super-secret-provider-token"

    provider["error"] = AbuseIPDBError(
        f"raw provider body {secret}"
    )

    result = reputation_api.get_ip_reputation("8.8.8.8", db=db)

    assert result["state"] == "unavailable"
    assert result["provider_error"] == "provider_error"
    assert secret not in str(result)
    assert secret not in repr(result)
    assert "raw provider body" not in str(result)


def test_response_schema_and_sensitive_data_absence(
    db,
    provider,
    monkeypatch
):
    monkeypatch.setattr(
        settings,
        "ABUSEIPDB_API_KEY",
        SECRET_API_KEY
    )

    result = reputation_api.get_ip_reputation("8.8.8.8", db=db)

    assert set(result) == RESPONSE_KEYS
    assert set(result["reputation"]) == REPUTATION_KEYS
    assert set(result["cache"]) == CACHE_KEYS

    response_text = f"{result!r} {result!s}"

    assert SECRET_API_KEY not in response_text
    assert "abuseConfidenceScore" not in response_text
    assert "totalReports" not in response_text
    assert "numDistinctUsers" not in response_text
    assert "lastReportedAt" not in response_text
    assert "usageType" not in response_text
    assert "isWhitelisted" not in response_text
    assert "isTor" not in response_text


def test_asgi_fresh_cache_returns_cached_response(
    db,
    provider,
    asgi_get
):
    entry = store_cache(db, score=87)
    provider["error"] = AssertionError(
        "provider should not be called"
    )

    status, payload = asgi_get("/api/reputation/8.8.8.8")

    assert status == 200
    assert set(payload) == RESPONSE_KEYS
    assert set(payload["reputation"]) == REPUTATION_KEYS
    assert payload["state"] == "cached"
    assert payload["ip_address"] == "8.8.8.8"
    assert payload["risk_category"] == "VERY_HIGH"
    assert payload["provider"] == "AbuseIPDB"
    assert payload["reputation"]["abuse_confidence_score"] == 87
    assert payload["provider_error"] is None
    assert_cache_consistency(payload, cached=True, stale=False)
    assert parse_datetime(
        payload["cache"]["checked_at"]
    ) == entry.checked_at
    assert provider["calls"] == []


def test_asgi_cache_miss_refreshes_and_returns_metadata(
    db,
    provider,
    asgi_get
):
    provider["response"] = normalized_data(
        abuse_confidence_score=60
    )

    status, payload = asgi_get("/api/reputation/8.8.8.8")

    assert status == 200
    assert set(payload) == RESPONSE_KEYS
    assert payload["state"] == "refreshed"
    assert payload["ip_address"] == "8.8.8.8"
    assert payload["risk_category"] == "HIGH"
    assert payload["reputation"]["abuse_confidence_score"] == 60
    assert payload["provider_error"] is None
    assert_cache_consistency(payload, cached=True, stale=False)
    assert provider["calls"] == ["8.8.8.8"]
    assert db.query(IPReputationCache).count() == 1


@pytest.mark.parametrize(
    ("value", "forces_refresh"),
    [
        ("true", True),
        ("1", True),
        ("false", False),
        ("0", False),
    ]
)
def test_asgi_force_refresh_query_parsing(
    db,
    provider,
    asgi_get,
    value,
    forces_refresh
):
    store_cache(db, score=10)
    provider["response"] = normalized_data(
        abuse_confidence_score=90
    )

    status, payload = asgi_get(
        "/api/reputation/8.8.8.8",
        f"force_refresh={value}".encode()
    )

    assert status == 200

    if forces_refresh:
        assert payload["state"] == "refreshed"
        assert payload["reputation"]["abuse_confidence_score"] == 90
        assert provider["calls"] == ["8.8.8.8"]
    else:
        assert payload["state"] == "cached"
        assert payload["reputation"]["abuse_confidence_score"] == 10
        assert provider["calls"] == []

    assert_cache_consistency(payload, cached=True, stale=False)


@pytest.mark.parametrize(
    "query_string",
    [
        b"force_refresh=maybe",
        b"force_refresh=2",
        b"force_refresh=",
    ]
)
def test_asgi_invalid_force_refresh_returns_422(
    db,
    provider,
    asgi_get,
    query_string
):
    status, payload = asgi_get(
        "/api/reputation/8.8.8.8",
        query_string
    )

    assert status == 422
    assert payload["detail"][0]["loc"] == [
        "query",
        "force_refresh",
    ]
    assert provider["calls"] == []


@pytest.mark.parametrize(
    "ip_address",
    [
        "192.168.1.1",
        "10.0.0.1",
        "0.0.0.0",
        "::1",
        "2001:db8::1",
        "not-an-ip",
    ]
)
def test_asgi_invalid_or_non_public_ip_returns_400(
    db,
    provider,
    asgi_get,
    ip_address
):
    status, payload = asgi_get(
        f"/api/reputation/{ip_address}"
    )

    assert status == 400
    assert payload == {
        "detail": (
            "IP address must be a public IPv4 or IPv6 address"
        )
    }
    assert ip_address not in payload["detail"]
    assert provider["calls"] == []


def test_asgi_ipv6_input_is_canonicalized(
    db,
    provider,
    asgi_get
):
    provider["response"] = normalized_data(
        "2606:4700:4700::1111",
        abuse_confidence_score=50
    )

    status, payload = asgi_get(
        "/api/reputation/"
        "2606:4700:4700:0000:0000:0000:0000:1111"
    )

    assert status == 200
    assert payload["ip_address"] == "2606:4700:4700::1111"
    assert payload["state"] == "refreshed"
    assert payload["risk_category"] == "HIGH"
    assert provider["calls"] == [
        "2606:4700:4700::1111"
    ]

    db.expire_all()

    cached = db.query(IPReputationCache).one()

    assert cached.ip_address == "2606:4700:4700::1111"


def test_asgi_feature_disabled_returns_503(
    db,
    provider,
    asgi_get,
    monkeypatch
):
    monkeypatch.setattr(
        settings,
        "IP_REPUTATION_ENABLED",
        False
    )

    status, payload = asgi_get("/api/reputation/8.8.8.8")

    assert status == 503
    assert payload == {
        "detail": "IP reputation service is disabled"
    }
    assert provider["calls"] == []


def test_asgi_provider_failure_without_cache_returns_unavailable(
    db,
    provider,
    asgi_get
):
    provider["error"] = RateLimitError()

    status, payload = asgi_get("/api/reputation/8.8.8.8")

    assert status == 200
    assert payload["state"] == "unavailable"
    assert payload["risk_category"] == "UNKNOWN"
    assert payload["provider"] is None
    assert payload["reputation"] is None
    assert payload["provider_error"] == "rate_limited"
    assert_cache_consistency(payload, cached=False, stale=True)
    assert provider["calls"] == ["8.8.8.8"]
    assert db.query(IPReputationCache).count() == 0


def test_asgi_provider_failure_with_stale_cache_returns_stale(
    db,
    provider,
    asgi_get
):
    stale_checked_at = utc_now() - timedelta(hours=48)

    store_cache(
        db,
        score=80,
        checked_at=stale_checked_at
    )

    provider["error"] = ProviderServerError(500)

    status, payload = asgi_get("/api/reputation/8.8.8.8")

    assert status == 200
    assert payload["state"] == "stale"
    assert payload["risk_category"] == "VERY_HIGH"
    assert payload["provider"] == "AbuseIPDB"
    assert payload["reputation"]["abuse_confidence_score"] == 80
    assert payload["provider_error"] == "provider_server_error"
    assert_cache_consistency(payload, cached=True, stale=True)
    assert provider["calls"] == ["8.8.8.8"]


def test_asgi_provider_error_response_is_sanitized(
    db,
    provider,
    asgi_get
):
    provider["error"] = AbuseIPDBError(
        f"raw provider body {SECRET_API_KEY}"
    )

    status, payload = asgi_get("/api/reputation/8.8.8.8")

    response_text = json.dumps(payload)

    assert status == 200
    assert payload["state"] == "unavailable"
    assert payload["provider_error"] == "provider_error"
    assert SECRET_API_KEY not in response_text
    assert "raw provider body" not in response_text


def test_asgi_unexpected_service_error_returns_generic_500(
    db,
    asgi_get,
    monkeypatch
):
    secret = "super-secret-provider-token"

    def failing_get_reputation(*args, **kwargs):
        raise RuntimeError(
            f"raw provider response and {secret}"
        )

    monkeypatch.setattr(
        reputation_api,
        "get_reputation",
        failing_get_reputation
    )

    status, payload = asgi_get("/api/reputation/8.8.8.8")

    response_text = json.dumps(payload)

    assert status == 500
    assert payload == {
        "detail": "IP reputation lookup failed"
    }
    assert secret not in response_text
    assert "raw provider response" not in response_text


def test_asgi_response_schema_and_sensitive_data_absence(
    db,
    provider,
    asgi_get,
    monkeypatch
):
    monkeypatch.setattr(
        settings,
        "ABUSEIPDB_API_KEY",
        SECRET_API_KEY
    )

    status, payload = asgi_get("/api/reputation/8.8.8.8")

    response_text = json.dumps(payload)

    assert status == 200
    assert set(payload) == RESPONSE_KEYS
    assert set(payload["reputation"]) == REPUTATION_KEYS
    assert set(payload["cache"]) == CACHE_KEYS
    assert SECRET_API_KEY not in response_text
    assert "abuseConfidenceScore" not in response_text
    assert "totalReports" not in response_text
    assert "numDistinctUsers" not in response_text
    assert "lastReportedAt" not in response_text
    assert "usageType" not in response_text
    assert "isWhitelisted" not in response_text
    assert "isTor" not in response_text
