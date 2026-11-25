from app.services.abuseipdb_client import AbuseIPDBError, check_ip
from app.services.ip_reputation_coordinator import refresh_coordinator
from app.services.ip_validation import canonicalize_public_ip
from app.services.rate_limiter import (
    ProviderQuotaExceeded,
    reputation_rate_limiter,
)
from app.services.reputation_cache import (
    NORMALIZED_FIELDS,
    get_cached_reputation,
    get_cached_reputation_status,
    is_cache_fresh,
    upsert_reputation,
)


STATE_CACHED = "cached"
STATE_STALE = "stale"
STATE_REFRESHED = "refreshed"
STATE_UNAVAILABLE = "unavailable"

RISK_UNKNOWN = "UNKNOWN"
RISK_NONE = "NONE"
RISK_LOW = "LOW"
RISK_MODERATE = "MODERATE"
RISK_HIGH = "HIGH"
RISK_VERY_HIGH = "VERY_HIGH"


def classify_reputation_risk(abuse_confidence_score):
    if abuse_confidence_score is None:
        return RISK_UNKNOWN

    if (
        not isinstance(abuse_confidence_score, int)
        or isinstance(abuse_confidence_score, bool)
        or not 0 <= abuse_confidence_score <= 100
    ):
        raise ValueError(
            "abuse_confidence_score must be an integer from 0 to 100"
        )

    if abuse_confidence_score == 0:
        return RISK_NONE

    if abuse_confidence_score < 25:
        return RISK_LOW

    if abuse_confidence_score < 50:
        return RISK_MODERATE

    if abuse_confidence_score < 75:
        return RISK_HIGH

    return RISK_VERY_HIGH


def _normalized_reputation(cache_entry):
    if cache_entry is None:
        return None

    reputation = {
        "ip_address": cache_entry.ip_address,
        "provider": cache_entry.provider,
    }

    for field in NORMALIZED_FIELDS:
        reputation[field] = getattr(cache_entry, field)

    return reputation


def _build_response(
    ip_address,
    state,
    cache_entry,
    provider_error=None
):
    reputation = _normalized_reputation(cache_entry)

    return {
        "ip_address": ip_address,
        "state": state,
        "risk_category": classify_reputation_risk(
            cache_entry.abuse_confidence_score
            if cache_entry is not None
            else None
        ),
        "provider": (
            cache_entry.provider
            if cache_entry is not None
            else None
        ),
        "reputation": reputation,
        "cache": get_cached_reputation_status(cache_entry),
        "provider_error": provider_error,
    }


def _refresh_and_store(db, canonical_ip):
    normalized_data = check_ip(canonical_ip)

    try:
        cache_entry = upsert_reputation(db, normalized_data)
        db.commit()
    except Exception:
        db.rollback()
        raise

    db.refresh(cache_entry)

    return cache_entry


def _fallback_response(
    canonical_ip,
    cache_entry,
    cache_is_fresh,
    provider_error=None
):
    if cache_entry is None:
        return _build_response(
            canonical_ip,
            STATE_UNAVAILABLE,
            None,
            provider_error=provider_error
        )

    return _build_response(
        canonical_ip,
        STATE_CACHED if cache_is_fresh else STATE_STALE,
        cache_entry,
        provider_error=provider_error
    )


def _response_after_concurrent_refresh(
    canonical_ip,
    cache_entry,
    cache_is_fresh,
    force_refresh,
    lease
):
    error = lease.last_error

    if isinstance(error, AbuseIPDBError):
        return _fallback_response(
            canonical_ip,
            cache_entry,
            cache_is_fresh,
            provider_error=error.category
        )

    if isinstance(error, ProviderQuotaExceeded):
        if cache_entry is not None:
            return _fallback_response(
                canonical_ip,
                cache_entry,
                cache_is_fresh,
                provider_error=error.category
            )

        raise error

    if error is not None:
        raise error

    if cache_entry is not None:
        if force_refresh:
            state = STATE_REFRESHED
        else:
            state = STATE_CACHED if cache_is_fresh else STATE_STALE

        return _build_response(
            canonical_ip,
            state,
            cache_entry
        )

    if lease.last_response is not None:
        return lease.last_response

    return _build_response(
        canonical_ip,
        STATE_UNAVAILABLE,
        None
    )


def get_reputation(db, ip_address, force_refresh=False):
    canonical_ip = canonicalize_public_ip(ip_address)
    cache_entry = get_cached_reputation(db, canonical_ip)
    cache_is_fresh = (
        cache_entry is not None
        and is_cache_fresh(cache_entry)
    )

    if not force_refresh and cache_is_fresh:
        return _build_response(
            canonical_ip,
            STATE_CACHED,
            cache_entry
        )

    with refresh_coordinator.acquire(
        canonical_ip,
        before_wait=db.rollback
    ) as lease:
        db.expire_all()

        cache_entry = get_cached_reputation(db, canonical_ip)
        cache_is_fresh = (
            cache_entry is not None
            and is_cache_fresh(cache_entry)
        )

        if lease.refresh_completed():
            return _response_after_concurrent_refresh(
                canonical_ip,
                cache_entry,
                cache_is_fresh,
                force_refresh,
                lease
            )

        if not force_refresh and cache_is_fresh:
            return _build_response(
                canonical_ip,
                STATE_CACHED,
                cache_entry
            )

        try:
            retry_after = (
                reputation_rate_limiter.allow_provider_request()
            )

            if retry_after:
                raise ProviderQuotaExceeded(retry_after)

            refreshed_entry = _refresh_and_store(
                db,
                canonical_ip
            )
        except ProviderQuotaExceeded as error:
            lease.record_error(error)

            if cache_entry is None:
                raise

            return _fallback_response(
                canonical_ip,
                cache_entry,
                cache_is_fresh,
                provider_error=error.category
            )
        except AbuseIPDBError as error:
            lease.record_error(error)

            return _fallback_response(
                canonical_ip,
                cache_entry,
                cache_is_fresh,
                provider_error=error.category
            )
        except Exception as error:
            lease.record_error(error)
            raise

        response = _build_response(
            canonical_ip,
            STATE_REFRESHED,
            refreshed_entry
        )
        lease.record_success(response)

        return response


def get_cached_reputation_only(db, ip_address):
    canonical_ip = canonicalize_public_ip(ip_address)
    cache_entry = get_cached_reputation(db, canonical_ip)

    if cache_entry is None:
        return _build_response(
            canonical_ip,
            STATE_UNAVAILABLE,
            None
        )

    return _build_response(
        canonical_ip,
        STATE_CACHED
        if is_cache_fresh(cache_entry)
        else STATE_STALE,
        cache_entry
    )
