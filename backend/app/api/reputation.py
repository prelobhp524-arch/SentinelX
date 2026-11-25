from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.services.ip_reputation_service import get_reputation
from app.services.ip_validation import canonicalize_public_ip
from app.services.rate_limiter import (
    ProviderQuotaExceeded,
    reputation_rate_limiter,
)


router = APIRouter(
    prefix="/api/reputation",
    tags=["IP Reputation"]
)

FALSE_FORCE_REFRESH_VALUES = {
    "0",
    "false",
    "f",
    "n",
    "no",
    "off",
}


def _client_key(request):
    host = getattr(request.client, "host", None)

    return host or "unknown"


def _force_refresh_requested(request):
    values = request.query_params.getlist("force_refresh")

    return any(
        value.strip().lower() not in FALSE_FORCE_REFRESH_VALUES
        for value in values
    )


def enforce_reputation_rate_limit(request: Request):
    retry_after = reputation_rate_limiter.check_client(
        _client_key(request),
        force_refresh=_force_refresh_requested(request)
    )

    if retry_after:
        raise HTTPException(
            status_code=429,
            detail="IP reputation request rate limit exceeded",
            headers={"Retry-After": str(retry_after)}
        )


@router.get("/{ip_address}")
def get_ip_reputation(
    ip_address: str,
    force_refresh: bool = False,
    db: Session = Depends(get_db),
    _rate_limit: None = Depends(enforce_reputation_rate_limit)
):
    try:
        canonical_ip = canonicalize_public_ip(ip_address)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="IP address must be a public IPv4 or IPv6 address"
        )

    if not settings.IP_REPUTATION_ENABLED:
        raise HTTPException(
            status_code=503,
            detail="IP reputation service is disabled"
        )

    try:
        return get_reputation(
            db,
            canonical_ip,
            force_refresh=force_refresh
        )
    except ProviderQuotaExceeded as error:
        raise HTTPException(
            status_code=429,
            detail=(
                "IP reputation provider rate limit exceeded"
            ),
            headers={"Retry-After": str(error.retry_after)}
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="IP reputation lookup failed"
        )
