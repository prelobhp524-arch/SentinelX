from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

from app.core.config import settings
from app.models.reputation import IPReputationCache
from app.services.ip_validation import canonicalize_public_ip


NORMALIZED_FIELDS = (
    "abuse_confidence_score",
    "total_reports",
    "num_distinct_users",
    "last_reported_at",
    "isp",
    "domain",
    "country_code",
    "usage_type",
    "is_public",
    "is_whitelisted",
    "is_tor",
)

SQLITE_MAX_INTEGER = 2**63 - 1

PERSISTED_INTEGER_BOUNDS = {
    "abuse_confidence_score": (0, 100),
    "total_reports": (0, SQLITE_MAX_INTEGER),
    "num_distinct_users": (0, SQLITE_MAX_INTEGER),
}


def _validate_persisted_integers(normalized_data):
    for field, (minimum, maximum) in PERSISTED_INTEGER_BOUNDS.items():
        value = normalized_data.get(field)

        if value is None:
            continue

        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{field} must be an integer")

        if not minimum <= value <= maximum:
            raise ValueError(
                f"{field} must be between {minimum} and {maximum}"
            )


def _as_utc_naive(value):
    if value is None:
        return None

    if not isinstance(value, datetime):
        raise ValueError("Expected a datetime value")

    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    return value


def _utc_now_naive():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def get_cached_reputation(db, ip_address):
    canonical_ip = canonicalize_public_ip(ip_address)

    return db.query(IPReputationCache).filter(
        IPReputationCache.ip_address == canonical_ip
    ).first()


def is_cache_fresh(cache_entry, now=None):
    if cache_entry is None or cache_entry.expires_at is None:
        return False

    current_time = (
        _as_utc_naive(now)
        if now is not None
        else _utc_now_naive()
    )

    expires_at = _as_utc_naive(cache_entry.expires_at)

    return expires_at > current_time


def upsert_reputation(db, normalized_data, ttl_hours=None, checked_at=None):
    if not isinstance(normalized_data, Mapping):
        raise ValueError("normalized_data must be a mapping")

    canonical_ip = canonicalize_public_ip(
        normalized_data.get("ip_address")
    )

    _validate_persisted_integers(normalized_data)

    effective_ttl = (
        settings.IP_REPUTATION_CACHE_TTL_HOURS
        if ttl_hours is None
        else ttl_hours
    )

    if (
        not isinstance(effective_ttl, (int, float))
        or isinstance(effective_ttl, bool)
        or effective_ttl <= 0
    ):
        raise ValueError("ttl_hours must be greater than zero")

    checked = (
        _as_utc_naive(checked_at)
        if checked_at is not None
        else _utc_now_naive()
    )

    expires_at = checked + timedelta(hours=effective_ttl)

    last_reported_at = normalized_data.get("last_reported_at")

    if last_reported_at is not None:
        last_reported_at = _as_utc_naive(last_reported_at)

    cache_entry = db.query(IPReputationCache).filter(
        IPReputationCache.ip_address == canonical_ip
    ).first()

    if cache_entry is None:
        cache_entry = IPReputationCache(
            ip_address=canonical_ip
        )
        db.add(cache_entry)

    cache_entry.provider = (
        normalized_data.get("provider") or "AbuseIPDB"
    )

    for field in NORMALIZED_FIELDS:
        setattr(cache_entry, field, normalized_data.get(field))

    cache_entry.last_reported_at = last_reported_at
    cache_entry.checked_at = checked
    cache_entry.expires_at = expires_at

    return cache_entry


def get_cached_reputation_status(cache_entry, now=None):
    ttl_hours = settings.IP_REPUTATION_CACHE_TTL_HOURS

    if cache_entry is None:
        return {
            "cached": False,
            "stale": True,
            "checked_at": None,
            "expires_at": None,
            "ttl_hours": ttl_hours,
        }

    return {
        "cached": True,
        "stale": not is_cache_fresh(cache_entry, now=now),
        "checked_at": cache_entry.checked_at,
        "expires_at": cache_entry.expires_at,
        "ttl_hours": ttl_hours,
    }
