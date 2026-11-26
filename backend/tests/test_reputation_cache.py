from datetime import datetime, timedelta, timezone

import pytest

from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.core.database import Base
from app.models.reputation import IPReputationCache
from app.services.reputation_cache import (
    MAX_SIGNED_BIGINT,
    get_cached_reputation,
    get_cached_reputation_status,
    is_cache_fresh,
    upsert_reputation,
)


CHECKED_AT = datetime(2026, 1, 1, 12, 0, 0)


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


def normalized_data(ip_address, **overrides):
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


def test_cache_miss(db):
    assert get_cached_reputation(db, "8.8.8.8") is None


def test_cache_hit_ipv4(db):
    entry = upsert_reputation(
        db,
        normalized_data("8.8.8.8"),
        ttl_hours=24,
        checked_at=CHECKED_AT
    )

    db.commit()
    db.refresh(entry)

    cached = get_cached_reputation(db, "8.8.8.8")

    assert cached is not None
    assert cached.id == entry.id
    assert cached.ip_address == "8.8.8.8"
    assert cached.abuse_confidence_score == 87


def test_cache_hit_ipv6(db):
    entry = upsert_reputation(
        db,
        normalized_data("2606:4700:4700::1111"),
        ttl_hours=24,
        checked_at=CHECKED_AT
    )

    db.commit()
    db.refresh(entry)

    cached = get_cached_reputation(db, "2606:4700:4700::1111")

    assert cached is not None
    assert cached.id == entry.id
    assert cached.ip_address == "2606:4700:4700::1111"


def test_ipv6_canonicalization(db):
    entry = upsert_reputation(
        db,
        normalized_data("2606:4700:4700:0000:0000:0000:0000:1111"),
        ttl_hours=24,
        checked_at=CHECKED_AT
    )

    db.commit()
    db.refresh(entry)

    cached = get_cached_reputation(db, "2606:4700:4700::1111")

    assert cached is not None
    assert cached.id == entry.id
    assert cached.ip_address == "2606:4700:4700::1111"
    assert db.query(IPReputationCache).count() == 1


def test_invalid_ip_rejected(db):
    with pytest.raises(ValueError):
        get_cached_reputation(db, "not-an-ip")

    with pytest.raises(ValueError):
        upsert_reputation(
            db,
            normalized_data("not-an-ip"),
            checked_at=CHECKED_AT
        )


@pytest.mark.parametrize(
    "ip_address",
    [
        "192.168.1.1",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "240.0.0.1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
    ]
)
def test_non_public_ip_rejected(db, ip_address):
    with pytest.raises(ValueError):
        get_cached_reputation(db, ip_address)


def test_non_public_ip_rejected_on_upsert(db):
    with pytest.raises(ValueError):
        upsert_reputation(
            db,
            normalized_data("192.168.1.1"),
            checked_at=CHECKED_AT
        )


@pytest.mark.parametrize(
    "field",
    [
        "abuse_confidence_score",
        "total_reports",
        "num_distinct_users",
    ]
)
@pytest.mark.parametrize(
    "value",
    [True, False, -1, MAX_SIGNED_BIGINT + 1]
)
def test_invalid_persisted_integers_are_rejected_before_insert(
    db,
    field,
    value
):
    with pytest.raises(ValueError):
        upsert_reputation(
            db,
            normalized_data(
                "8.8.8.8",
                **{field: value}
            ),
            checked_at=CHECKED_AT
        )

    assert db.query(IPReputationCache).count() == 0


def test_abuse_confidence_score_above_provider_range_is_rejected(db):
    with pytest.raises(ValueError):
        upsert_reputation(
            db,
            normalized_data(
                "8.8.8.8",
                abuse_confidence_score=101
            ),
            checked_at=CHECKED_AT
        )

    assert db.query(IPReputationCache).count() == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("abuse_confidence_score", 0),
        ("abuse_confidence_score", 100),
        ("total_reports", 0),
        ("total_reports", MAX_SIGNED_BIGINT),
        ("num_distinct_users", 0),
        ("num_distinct_users", MAX_SIGNED_BIGINT),
    ]
)
def test_valid_persisted_integer_boundaries_are_accepted(
    db,
    field,
    value
):
    entry = upsert_reputation(
        db,
        normalized_data(
            "8.8.8.8",
            **{field: value}
        ),
        checked_at=CHECKED_AT
    )

    db.commit()
    db.refresh(entry)

    assert getattr(entry, field) == value


def test_fresh_and_expired_cache(db):
    entry = upsert_reputation(
        db,
        normalized_data("8.8.8.8"),
        ttl_hours=24,
        checked_at=CHECKED_AT
    )

    assert is_cache_fresh(
        entry,
        now=CHECKED_AT + timedelta(hours=1)
    ) is True

    assert is_cache_fresh(
        entry,
        now=CHECKED_AT + timedelta(hours=24)
    ) is False

    assert is_cache_fresh(
        entry,
        now=CHECKED_AT + timedelta(hours=25)
    ) is False


def test_deterministic_now_with_aware_and_naive_values(db):
    entry = upsert_reputation(
        db,
        normalized_data("8.8.8.8"),
        ttl_hours=24,
        checked_at=CHECKED_AT
    )

    aware_now = datetime(
        2026,
        1,
        1,
        13,
        0,
        0,
        tzinfo=timezone.utc
    )

    assert is_cache_fresh(entry, now=aware_now) is True
    assert is_cache_fresh(
        entry,
        now=aware_now.replace(tzinfo=None)
    ) is True


def test_is_cache_fresh_handles_missing_entry(db):
    assert is_cache_fresh(None) is False


def test_upsert_inserts_new_entry(db):
    entry = upsert_reputation(
        db,
        normalized_data("1.1.1.1"),
        ttl_hours=24,
        checked_at=CHECKED_AT
    )

    db.commit()
    db.refresh(entry)

    assert entry.id is not None
    assert entry.ip_address == "1.1.1.1"
    assert db.query(IPReputationCache).count() == 1


def test_upsert_updates_existing_ip_without_duplicate(db):
    first = upsert_reputation(
        db,
        normalized_data("8.8.8.8"),
        ttl_hours=24,
        checked_at=CHECKED_AT
    )

    db.commit()
    db.refresh(first)

    second = upsert_reputation(
        db,
        normalized_data(
            "8.8.8.8",
            abuse_confidence_score=95,
            total_reports=999
        ),
        ttl_hours=24,
        checked_at=CHECKED_AT + timedelta(hours=1)
    )

    db.commit()
    db.refresh(second)

    assert second.id == first.id
    assert second.abuse_confidence_score == 95
    assert second.total_reports == 999
    assert db.query(IPReputationCache).count() == 1


def test_upsert_does_not_commit_new_entry(db):
    entry = upsert_reputation(
        db,
        normalized_data("8.8.8.8"),
        ttl_hours=24,
        checked_at=CHECKED_AT
    )

    assert entry in db.new
    assert entry.id is None


def test_upsert_does_not_commit_existing_entry(db):
    entry = upsert_reputation(
        db,
        normalized_data("8.8.8.8"),
        ttl_hours=24,
        checked_at=CHECKED_AT
    )

    db.commit()
    db.refresh(entry)

    updated = upsert_reputation(
        db,
        normalized_data(
            "8.8.8.8",
            abuse_confidence_score=95
        ),
        ttl_hours=24,
        checked_at=CHECKED_AT + timedelta(hours=1)
    )

    assert updated in db.dirty


def test_caller_can_rollback_new_entry(db):
    upsert_reputation(
        db,
        normalized_data("8.8.8.8"),
        ttl_hours=24,
        checked_at=CHECKED_AT
    )

    db.rollback()

    assert get_cached_reputation(db, "8.8.8.8") is None


def test_caller_can_rollback_existing_entry_update(db):
    first = upsert_reputation(
        db,
        normalized_data(
            "8.8.8.8",
            abuse_confidence_score=10
        ),
        ttl_hours=24,
        checked_at=CHECKED_AT
    )

    db.commit()
    db.refresh(first)

    upsert_reputation(
        db,
        normalized_data(
            "8.8.8.8",
            abuse_confidence_score=95
        ),
        ttl_hours=24,
        checked_at=CHECKED_AT + timedelta(hours=1)
    )

    db.rollback()

    cached = get_cached_reputation(db, "8.8.8.8")

    assert cached is not None
    assert cached.abuse_confidence_score == 10


def test_ttl_calculation(db):
    entry = upsert_reputation(
        db,
        normalized_data("8.8.8.8"),
        ttl_hours=2,
        checked_at=CHECKED_AT
    )

    assert entry.checked_at == CHECKED_AT
    assert entry.expires_at == CHECKED_AT + timedelta(hours=2)


def test_invalid_ttl_rejected(db):
    with pytest.raises(ValueError):
        upsert_reputation(
            db,
            normalized_data("8.8.8.8"),
            ttl_hours=0,
            checked_at=CHECKED_AT
        )


def test_status_helper(db):
    entry = upsert_reputation(
        db,
        normalized_data("8.8.8.8"),
        ttl_hours=24,
        checked_at=CHECKED_AT
    )

    status = get_cached_reputation_status(
        entry,
        now=CHECKED_AT + timedelta(hours=1)
    )

    assert status == {
        "cached": True,
        "stale": False,
        "checked_at": entry.checked_at,
        "expires_at": entry.expires_at,
        "ttl_hours": settings.IP_REPUTATION_CACHE_TTL_HOURS,
    }

    expired_status = get_cached_reputation_status(
        entry,
        now=CHECKED_AT + timedelta(hours=25)
    )

    assert expired_status["cached"] is True
    assert expired_status["stale"] is True


def test_status_helper_with_missing_entry(db):
    status = get_cached_reputation_status(None)

    assert status == {
        "cached": False,
        "stale": True,
        "checked_at": None,
        "expires_at": None,
        "ttl_hours": settings.IP_REPUTATION_CACHE_TTL_HOURS,
    }


def test_unique_ip_constraint(db):
    db.add(
        IPReputationCache(
            ip_address="8.8.8.8",
            provider="AbuseIPDB",
            checked_at=CHECKED_AT,
            expires_at=CHECKED_AT + timedelta(hours=24)
        )
    )
    db.commit()

    db.add(
        IPReputationCache(
            ip_address="8.8.8.8",
            provider="AbuseIPDB",
            checked_at=CHECKED_AT,
            expires_at=CHECKED_AT + timedelta(hours=24)
        )
    )

    with pytest.raises(IntegrityError):
        db.commit()

    db.rollback()
