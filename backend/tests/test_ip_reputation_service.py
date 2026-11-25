from datetime import datetime, timedelta, timezone

import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.core.database import Base
from app.models.reputation import IPReputationCache
from app.services import ip_reputation_service
from app.services.abuseipdb_client import (
    AbuseIPDBError,
    ProviderServerError,
    RateLimitError,
)
from app.services.ip_reputation_service import (
    classify_reputation_risk,
    get_cached_reputation_only,
    get_reputation,
)
from app.services.ip_validation import canonicalize_public_ip
from app.services.reputation_cache import upsert_reputation


SECRET_API_KEY = "test-super-secret-api-key"


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


@pytest.fixture(autouse=True)
def deterministic_settings(monkeypatch):
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


def test_service_uses_shared_ip_validator():
    assert (
        ip_reputation_service.canonicalize_public_ip
        is canonicalize_public_ip
    )


def test_fresh_cache_returns_cached_without_provider(db, provider):
    store_cache(db, score=87)
    provider["error"] = AssertionError(
        "provider should not be called"
    )

    result = get_reputation(db, "8.8.8.8")

    assert result["state"] == "cached"
    assert result["ip_address"] == "8.8.8.8"
    assert result["risk_category"] == "VERY_HIGH"
    assert result["provider"] == "AbuseIPDB"
    assert result["reputation"]["abuse_confidence_score"] == 87
    assert result["cache"]["cached"] is True
    assert result["cache"]["stale"] is False
    assert result["provider_error"] is None
    assert provider["calls"] == []


def test_force_refresh_bypasses_fresh_cache(db, provider):
    store_cache(db, score=10)
    provider["response"] = normalized_data(
        abuse_confidence_score=90
    )

    result = get_reputation(
        db,
        "8.8.8.8",
        force_refresh=True
    )

    assert result["state"] == "refreshed"
    assert result["risk_category"] == "VERY_HIGH"
    assert result["reputation"]["abuse_confidence_score"] == 90
    assert result["cache"]["stale"] is False
    assert provider["calls"] == ["8.8.8.8"]

    db.rollback()

    cached = db.query(IPReputationCache).filter(
        IPReputationCache.ip_address == "8.8.8.8"
    ).one()

    assert cached.abuse_confidence_score == 90


def test_successful_refresh_creates_cache_entry(db, provider):
    provider["response"] = normalized_data(
        abuse_confidence_score=30,
        total_reports=5
    )

    result = get_reputation(db, "8.8.8.8")

    assert result["state"] == "refreshed"
    assert result["risk_category"] == "MODERATE"
    assert result["reputation"]["abuse_confidence_score"] == 30
    assert result["cache"]["cached"] is True
    assert result["cache"]["stale"] is False
    assert result["provider_error"] is None
    assert provider["calls"] == ["8.8.8.8"]

    db.rollback()

    cached = db.query(IPReputationCache).filter(
        IPReputationCache.ip_address == "8.8.8.8"
    ).one()

    assert cached.abuse_confidence_score == 30
    assert cached.total_reports == 5
    assert cached.provider == "AbuseIPDB"
    assert cached.checked_at is not None
    assert cached.expires_at is not None


def test_successful_refresh_updates_existing_entry(db, provider):
    store_cache(db, score=10, total_reports=1)
    provider["response"] = normalized_data(
        abuse_confidence_score=90,
        total_reports=99
    )

    result = get_reputation(
        db,
        "8.8.8.8",
        force_refresh=True
    )

    assert result["state"] == "refreshed"
    assert result["reputation"]["abuse_confidence_score"] == 90

    db.rollback()

    entries = db.query(IPReputationCache).filter(
        IPReputationCache.ip_address == "8.8.8.8"
    ).all()

    assert len(entries) == 1
    assert entries[0].abuse_confidence_score == 90
    assert entries[0].total_reports == 99


def test_expired_cache_is_refreshed(db, provider):
    stale_checked_at = utc_now() - timedelta(hours=48)

    store_cache(
        db,
        score=10,
        checked_at=stale_checked_at
    )

    provider["response"] = normalized_data(
        abuse_confidence_score=80
    )

    result = get_reputation(db, "8.8.8.8")

    assert result["state"] == "refreshed"
    assert result["risk_category"] == "VERY_HIGH"
    assert result["reputation"]["abuse_confidence_score"] == 80
    assert result["cache"]["stale"] is False
    assert provider["calls"] == ["8.8.8.8"]

    db.rollback()

    cached = db.query(IPReputationCache).filter(
        IPReputationCache.ip_address == "8.8.8.8"
    ).one()

    assert cached.abuse_confidence_score == 80


def test_provider_failure_with_stale_cache_returns_stale_fallback(
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

    result = get_reputation(db, "8.8.8.8")

    assert result["state"] == "stale"
    assert result["risk_category"] == "VERY_HIGH"
    assert result["reputation"]["abuse_confidence_score"] == 80
    assert result["cache"]["cached"] is True
    assert result["cache"]["stale"] is True
    assert result["provider_error"] == "provider_server_error"
    assert provider["calls"] == ["8.8.8.8"]

    db.expire_all()

    cached = db.query(IPReputationCache).filter(
        IPReputationCache.ip_address == "8.8.8.8"
    ).one()

    assert cached.checked_at == stale_checked_at
    assert cached.abuse_confidence_score == 80


def test_provider_failure_without_cache_returns_unavailable(
    db,
    provider
):
    provider["error"] = RateLimitError()

    result = get_reputation(db, "8.8.8.8")

    assert result["state"] == "unavailable"
    assert result["risk_category"] == "UNKNOWN"
    assert result["provider"] is None
    assert result["reputation"] is None
    assert result["cache"]["cached"] is False
    assert result["cache"]["stale"] is True
    assert result["provider_error"] == "rate_limited"
    assert provider["calls"] == ["8.8.8.8"]

    assert db.query(IPReputationCache).filter(
        IPReputationCache.ip_address == "8.8.8.8"
    ).first() is None


def test_cache_only_fresh_never_calls_provider(db, provider):
    store_cache(db, score=50)
    provider["error"] = AssertionError(
        "provider should not be called"
    )

    result = get_cached_reputation_only(db, "8.8.8.8")

    assert result["state"] == "cached"
    assert result["risk_category"] == "HIGH"
    assert result["reputation"]["abuse_confidence_score"] == 50
    assert result["cache"]["stale"] is False
    assert result["provider_error"] is None
    assert provider["calls"] == []


def test_cache_only_stale_returns_stale_without_provider(
    db,
    provider
):
    stale_checked_at = utc_now() - timedelta(hours=48)

    store_cache(
        db,
        score=25,
        checked_at=stale_checked_at
    )

    provider["error"] = AssertionError(
        "provider should not be called"
    )

    result = get_cached_reputation_only(db, "8.8.8.8")

    assert result["state"] == "stale"
    assert result["risk_category"] == "MODERATE"
    assert result["reputation"]["abuse_confidence_score"] == 25
    assert result["cache"]["stale"] is True
    assert result["provider_error"] is None
    assert provider["calls"] == []


def test_cache_only_miss_returns_unavailable_without_provider(
    db,
    provider
):
    provider["error"] = AssertionError(
        "provider should not be called"
    )

    result = get_cached_reputation_only(db, "8.8.8.8")

    assert result["state"] == "unavailable"
    assert result["risk_category"] == "UNKNOWN"
    assert result["provider"] is None
    assert result["reputation"] is None
    assert result["cache"]["cached"] is False
    assert result["cache"]["stale"] is True
    assert result["provider_error"] is None
    assert provider["calls"] == []


@pytest.mark.parametrize(
    "ip_address",
    [
        "192.168.1.1",
        "10.0.0.1",
        "127.0.0.1",
        "224.0.0.1",
        "0.0.0.0",
        "2001:db8::1",
        "not-an-ip",
    ]
)
def test_invalid_ip_rejected_before_provider(
    db,
    provider,
    ip_address
):
    provider["error"] = AssertionError(
        "provider should not be called"
    )

    with pytest.raises(ValueError):
        get_reputation(db, ip_address)

    assert provider["calls"] == []
    assert db.query(IPReputationCache).count() == 0


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (None, "UNKNOWN"),
        (0, "NONE"),
        (1, "LOW"),
        (24, "LOW"),
        (25, "MODERATE"),
        (49, "MODERATE"),
        (50, "HIGH"),
        (74, "HIGH"),
        (75, "VERY_HIGH"),
        (100, "VERY_HIGH"),
    ]
)
def test_risk_classification_boundaries(score, expected):
    assert classify_reputation_risk(score) == expected


@pytest.mark.parametrize(
    "score",
    [-1, 101, "50", 50.5, True, False]
)
def test_invalid_risk_scores_are_rejected(score):
    with pytest.raises(ValueError):
        classify_reputation_risk(score)


def test_fresh_cache_hit_does_not_commit(
    db,
    provider,
    monkeypatch
):
    store_cache(db, score=87)

    def fail_commit():
        raise AssertionError("commit should not be called")

    monkeypatch.setattr(db, "commit", fail_commit)

    result = get_reputation(db, "8.8.8.8")

    assert result["state"] == "cached"
    assert provider["calls"] == []


def test_cache_only_does_not_commit(
    db,
    provider,
    monkeypatch
):
    store_cache(db, score=87)

    def fail_commit():
        raise AssertionError("commit should not be called")

    monkeypatch.setattr(db, "commit", fail_commit)

    result = get_cached_reputation_only(db, "8.8.8.8")

    assert result["state"] == "cached"
    assert provider["calls"] == []


def test_provider_failure_does_not_commit(
    db,
    provider,
    monkeypatch
):
    stale_checked_at = utc_now() - timedelta(hours=48)

    store_cache(
        db,
        score=80,
        checked_at=stale_checked_at
    )

    provider["error"] = ProviderServerError(500)

    def fail_commit():
        raise AssertionError("commit should not be called")

    monkeypatch.setattr(db, "commit", fail_commit)

    result = get_reputation(db, "8.8.8.8")

    assert result["state"] == "stale"


def test_commit_failure_rolls_back_and_reraises(
    db,
    provider,
    monkeypatch
):
    rollback_calls = []
    original_rollback = db.rollback

    def tracked_rollback():
        rollback_calls.append(True)
        return original_rollback()

    def failing_commit():
        raise RuntimeError("commit failed")

    monkeypatch.setattr(db, "rollback", tracked_rollback)
    monkeypatch.setattr(db, "commit", failing_commit)

    with pytest.raises(RuntimeError, match="commit failed"):
        get_reputation(db, "8.8.8.8")

    assert rollback_calls == [True]
    assert db.query(IPReputationCache).filter(
        IPReputationCache.ip_address == "8.8.8.8"
    ).first() is None


def test_provider_error_response_is_sanitized_without_cache(
    db,
    provider
):
    provider["error"] = AbuseIPDBError(
        f"provider failed with {SECRET_API_KEY} and raw body"
    )

    result = get_reputation(db, "8.8.8.8")

    assert result["state"] == "unavailable"
    assert result["provider_error"] == "provider_error"
    assert SECRET_API_KEY not in str(result)
    assert SECRET_API_KEY not in repr(result)
    assert "raw body" not in str(result)
    assert "provider failed" not in str(result)


def test_provider_error_response_is_sanitized_with_stale_cache(
    db,
    provider
):
    stale_checked_at = utc_now() - timedelta(hours=48)

    store_cache(
        db,
        score=80,
        checked_at=stale_checked_at
    )

    provider["error"] = AbuseIPDBError(
        f"provider failed with {SECRET_API_KEY} and raw body"
    )

    result = get_reputation(db, "8.8.8.8")

    assert result["state"] == "stale"
    assert result["provider_error"] == "provider_error"
    assert SECRET_API_KEY not in str(result)
    assert SECRET_API_KEY not in repr(result)
    assert "raw body" not in str(result)
    assert "provider failed" not in str(result)


def test_programming_errors_are_not_swallowed(db, provider):
    provider["error"] = RuntimeError("programming boom")

    with pytest.raises(RuntimeError, match="programming boom"):
        get_reputation(db, "8.8.8.8")

    assert provider["calls"] == ["8.8.8.8"]


def test_canonical_ip_is_used_for_response_and_provider(
    db,
    provider
):
    provider["response"] = normalized_data(
        "2606:4700:4700::1111",
        abuse_confidence_score=50
    )

    result = get_reputation(
        db,
        "2606:4700:4700:0000:0000:0000:0000:1111"
    )

    assert result["ip_address"] == "2606:4700:4700::1111"
    assert result["state"] == "refreshed"
    assert provider["calls"] == ["2606:4700:4700::1111"]
