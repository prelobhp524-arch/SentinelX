import asyncio
import json
import threading

from datetime import datetime, timedelta, timezone

import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.main as main_module
from app.api import reputation as reputation_api
from app.core.config import settings
from app.core.database import Base, get_db
from app.services import ip_reputation_service
from app.services.rate_limiter import (
    FixedWindowLimiter,
    ReputationRateLimiter,
)
from app.services.reputation_cache import upsert_reputation


DEFAULT_CLIENT = ("testclient", 123)


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
    checked_at=None
):
    if checked_at is None:
        checked_at = utc_now()

    entry = upsert_reputation(
        db,
        normalized_data(
            ip_address,
            abuse_confidence_score=score
        ),
        checked_at=checked_at
    )

    db.commit()
    db.refresh(entry)

    return entry


async def _request_asgi(
    path,
    query_string=b"",
    client=DEFAULT_CLIENT,
    headers=None
):
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

    raw_headers = [
        (
            name.lower().encode("latin-1"),
            value.encode("latin-1")
        )
        for name, value in (headers or [])
    ]

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": query_string,
        "headers": raw_headers,
        "client": client,
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

    response_headers = {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in start.get("headers", [])
    }

    return start["status"], payload, response_headers


@pytest.fixture(autouse=True)
def enabled_reputation(monkeypatch):
    monkeypatch.setattr(settings, "IP_REPUTATION_ENABLED", True)
    monkeypatch.setattr(
        settings,
        "IP_REPUTATION_CACHE_TTL_HOURS",
        24
    )


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


@pytest.fixture
def asgi_get(db):
    def override_get_db():
        yield db

    main_module.app.dependency_overrides[get_db] = override_get_db

    def request(
        path,
        query_string=b"",
        client=DEFAULT_CLIENT,
        headers=None
    ):
        return asyncio.run(
            _request_asgi(
                path,
                query_string=query_string,
                client=client,
                headers=headers
            )
        )

    yield request

    main_module.app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def provider(monkeypatch):
    state = {
        "response": normalized_data(),
        "error": None,
        "calls": [],
        "lock": threading.Lock(),
        "entered": threading.Event(),
        "release": threading.Event(),
        "barrier": None,
        "block": False,
    }

    def fake_check_ip(ip_address):
        with state["lock"]:
            state["calls"].append(ip_address)

        state["entered"].set()

        barrier = state["barrier"]

        if barrier is not None:
            barrier.wait(timeout=5)

        if state["block"]:
            assert state["release"].wait(timeout=5) is True

        error = state["error"]

        if error is not None:
            raise error

        response = dict(state["response"])
        response["ip_address"] = ip_address

        return response

    monkeypatch.setattr(
        ip_reputation_service,
        "check_ip",
        fake_check_ip
    )

    return state


@pytest.fixture
def make_limiter(monkeypatch):
    def factory(**overrides):
        values = {
            "request_limit": 100,
            "force_refresh_limit": 100,
            "provider_limit": 100,
            "window_seconds": 60,
        }

        values.update(overrides)

        limiter = ReputationRateLimiter(**values)

        monkeypatch.setattr(
            reputation_api,
            "reputation_rate_limiter",
            limiter
        )
        monkeypatch.setattr(
            ip_reputation_service,
            "reputation_rate_limiter",
            limiter
        )

        return limiter

    return factory


def test_normal_requests_within_limit_succeed(
    db,
    provider,
    asgi_get,
    make_limiter
):
    store_cache(db)
    make_limiter(
        request_limit=2,
        force_refresh_limit=2,
        provider_limit=10
    )

    for _ in range(2):
        status, payload, headers = asgi_get(
            "/api/reputation/8.8.8.8"
        )

        assert status == 200
        assert payload["state"] == "cached"
        assert "retry-after" not in headers

    assert provider["calls"] == []


def test_normal_requests_exceeding_limit_return_429(
    db,
    provider,
    asgi_get,
    make_limiter
):
    store_cache(db)
    make_limiter(
        request_limit=1,
        force_refresh_limit=1,
        provider_limit=10
    )

    status, payload, _ = asgi_get(
        "/api/reputation/8.8.8.8"
    )

    assert status == 200
    assert payload["state"] == "cached"

    status, payload, headers = asgi_get(
        "/api/reputation/8.8.8.8"
    )

    assert status == 429
    assert payload == {
        "detail": "IP reputation request rate limit exceeded"
    }
    assert 1 <= int(headers["retry-after"]) <= 60
    assert provider["calls"] == []


def test_forced_refresh_has_stricter_limit(
    db,
    provider,
    asgi_get,
    make_limiter
):
    store_cache(db, score=10)
    provider["response"] = normalized_data(
        abuse_confidence_score=90
    )
    make_limiter(
        request_limit=10,
        force_refresh_limit=2,
        provider_limit=10
    )

    for _ in range(2):
        status, payload, _ = asgi_get(
            "/api/reputation/8.8.8.8",
            b"force_refresh=true"
        )

        assert status == 200
        assert payload["state"] == "refreshed"

    status, payload, headers = asgi_get(
        "/api/reputation/8.8.8.8",
        b"force_refresh=true"
    )

    assert status == 429
    assert payload == {
        "detail": "IP reputation request rate limit exceeded"
    }
    assert 1 <= int(headers["retry-after"]) <= 60
    assert provider["calls"] == ["8.8.8.8", "8.8.8.8"]


def test_forced_refresh_cannot_bypass_normal_limit(
    db,
    provider,
    asgi_get,
    make_limiter
):
    store_cache(db, score=10)
    provider["response"] = normalized_data(
        abuse_confidence_score=90
    )
    make_limiter(
        request_limit=2,
        force_refresh_limit=10,
        provider_limit=10
    )

    for _ in range(2):
        status, payload, _ = asgi_get(
            "/api/reputation/8.8.8.8",
            b"force_refresh=true"
        )

        assert status == 200
        assert payload["state"] == "refreshed"

    status, _, _ = asgi_get(
        "/api/reputation/8.8.8.8",
        b"force_refresh=true"
    )

    assert status == 429
    assert provider["calls"] == ["8.8.8.8", "8.8.8.8"]


def test_rejected_request_does_not_call_provider(
    db,
    provider,
    asgi_get,
    make_limiter
):
    store_cache(db)
    make_limiter(
        request_limit=1,
        force_refresh_limit=10,
        provider_limit=10
    )

    assert asgi_get("/api/reputation/8.8.8.8")[0] == 200

    status, _, _ = asgi_get(
        "/api/reputation/8.8.8.8",
        b"force_refresh=true"
    )

    assert status == 429
    assert provider["calls"] == []


def test_fresh_cache_hits_do_not_consume_provider_quota(
    db,
    provider,
    asgi_get,
    make_limiter
):
    store_cache(db, score=10)
    make_limiter(
        request_limit=20,
        force_refresh_limit=20,
        provider_limit=1
    )

    for _ in range(3):
        status, payload, _ = asgi_get(
            "/api/reputation/8.8.8.8"
        )

        assert status == 200
        assert payload["state"] == "cached"

    assert provider["calls"] == []

    provider["response"] = normalized_data(
        "1.1.1.1",
        abuse_confidence_score=20
    )

    status, payload, _ = asgi_get(
        "/api/reputation/1.1.1.1"
    )

    assert status == 200
    assert payload["state"] == "refreshed"
    assert provider["calls"] == ["1.1.1.1"]


def test_stale_cache_falls_back_when_provider_quota_exhausted(
    db,
    provider,
    asgi_get,
    make_limiter
):
    store_cache(
        db,
        "8.8.8.8",
        score=42,
        checked_at=utc_now() - timedelta(hours=48)
    )
    make_limiter(
        request_limit=10,
        force_refresh_limit=10,
        provider_limit=1
    )

    provider["response"] = normalized_data(
        "1.1.1.1",
        abuse_confidence_score=20
    )

    status, payload, _ = asgi_get(
        "/api/reputation/1.1.1.1"
    )

    assert status == 200
    assert payload["state"] == "refreshed"

    status, payload, headers = asgi_get(
        "/api/reputation/8.8.8.8"
    )

    assert status == 200
    assert payload["state"] == "stale"
    assert payload["provider_error"] == "rate_limited"
    assert (
        payload["reputation"]["abuse_confidence_score"] == 42
    )
    assert "retry-after" not in headers
    assert provider["calls"] == ["1.1.1.1"]


def test_global_provider_limit_rejects_excessive_attempts(
    db,
    provider,
    asgi_get,
    make_limiter
):
    make_limiter(
        request_limit=100,
        force_refresh_limit=100,
        provider_limit=1
    )

    status, payload, _ = asgi_get(
        "/api/reputation/8.8.8.8"
    )

    assert status == 200
    assert payload["state"] == "refreshed"
    assert provider["calls"] == ["8.8.8.8"]

    status, payload, headers = asgi_get(
        "/api/reputation/1.1.1.1"
    )

    assert status == 429
    assert payload == {
        "detail": "IP reputation provider rate limit exceeded"
    }
    assert 1 <= int(headers["retry-after"]) <= 60
    assert provider["calls"] == ["8.8.8.8"]


def test_rate_limit_state_expires_and_is_cleaned_up():
    now = [100.0]
    limiter = FixedWindowLimiter(
        1,
        10,
        max_keys=4,
        clock=lambda: now[0]
    )

    assert limiter.try_acquire("client") == 0
    assert limiter.try_acquire("client") > 0
    assert limiter.active_keys() == 1

    now[0] += 10.0

    assert limiter.try_acquire("client") == 0

    now[0] += 10.0
    limiter.cleanup()

    assert limiter.active_keys() == 0


def test_rate_limit_state_is_bounded():
    now = [100.0]
    limiter = FixedWindowLimiter(
        10,
        60,
        max_keys=2,
        clock=lambda: now[0]
    )

    assert limiter.try_acquire("client-a") == 0
    assert limiter.try_acquire("client-b") == 0
    assert limiter.active_keys() == 2

    assert limiter.try_acquire("client-c") == 0
    assert limiter.active_keys() == 2


def test_different_clients_have_independent_allowances(
    db,
    provider,
    asgi_get,
    make_limiter
):
    store_cache(db)
    make_limiter(
        request_limit=1,
        force_refresh_limit=1,
        provider_limit=10
    )

    assert asgi_get(
        "/api/reputation/8.8.8.8",
        client=("10.0.0.1", 1000)
    )[0] == 200
    assert asgi_get(
        "/api/reputation/8.8.8.8",
        client=("10.0.0.1", 1001)
    )[0] == 429
    assert asgi_get(
        "/api/reputation/8.8.8.8",
        client=("10.0.0.2", 1000)
    )[0] == 200
    assert provider["calls"] == []


def test_spoofed_forwarding_headers_cannot_bypass_limit(
    db,
    provider,
    asgi_get,
    make_limiter
):
    store_cache(db)
    make_limiter(
        request_limit=1,
        force_refresh_limit=1,
        provider_limit=10
    )

    first_headers = [
        ("x-forwarded-for", "1.1.1.1"),
        ("x-real-ip", "1.1.1.1"),
    ]
    second_headers = [
        ("x-forwarded-for", "2.2.2.2"),
        ("x-real-ip", "2.2.2.2"),
    ]

    assert asgi_get(
        "/api/reputation/8.8.8.8",
        headers=first_headers
    )[0] == 200
    assert asgi_get(
        "/api/reputation/8.8.8.8",
        headers=second_headers
    )[0] == 429
    assert provider["calls"] == []


def test_missing_client_information_is_handled_safely(
    db,
    provider,
    asgi_get,
    make_limiter
):
    store_cache(db)
    make_limiter(
        request_limit=1,
        force_refresh_limit=1,
        provider_limit=10
    )

    assert asgi_get(
        "/api/reputation/8.8.8.8",
        client=None
    )[0] == 200
    assert asgi_get(
        "/api/reputation/8.8.8.8",
        client=None
    )[0] == 429
    assert provider["calls"] == []


def test_concurrent_requests_cannot_exceed_limit():
    limiter = ReputationRateLimiter(
        request_limit=5,
        force_refresh_limit=5,
        provider_limit=5,
        window_seconds=60,
        clock=lambda: 100.0
    )
    barrier = threading.Barrier(20)
    results = []
    errors = []
    lock = threading.Lock()

    def worker():
        try:
            barrier.wait(timeout=5)
            retry_after = limiter.check_client(
                "client",
                force_refresh=False,
                now=100.0
            )

            with lock:
                results.append(retry_after)
        except Exception as error:
            with lock:
                errors.append(error)

    threads = [
        threading.Thread(target=worker)
        for _ in range(20)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join(timeout=5)

    assert errors == []
    assert len(results) == 20
    assert sum(retry_after == 0 for retry_after in results) == 5
    assert all(
        retry_after > 0
        for retry_after in results
        if retry_after != 0
    )


def test_disabled_and_invalid_ip_behavior_remains(
    db,
    provider,
    asgi_get,
    make_limiter,
    monkeypatch
):
    make_limiter(
        request_limit=10,
        force_refresh_limit=10,
        provider_limit=10
    )

    status, payload, _ = asgi_get(
        "/api/reputation/not-an-ip"
    )

    assert status == 400
    assert payload == {
        "detail": (
            "IP address must be a public IPv4 or IPv6 address"
        )
    }

    status, payload, _ = asgi_get(
        "/api/reputation/8.8.8.8",
        b"force_refresh=maybe"
    )

    assert status == 422

    monkeypatch.setattr(
        settings,
        "IP_REPUTATION_ENABLED",
        False
    )

    status, payload, _ = asgi_get(
        "/api/reputation/8.8.8.8"
    )

    assert status == 503
    assert payload == {
        "detail": "IP reputation service is disabled"
    }
    assert provider["calls"] == []
