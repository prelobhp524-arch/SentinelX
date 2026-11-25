import json
import re
import requests
import urllib3

from datetime import datetime, timezone

from app.core.config import settings
from app.services.ip_validation import canonicalize_public_ip


ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSEIPDB_MAX_AGE_DAYS = 90
PROVIDER_NAME = "AbuseIPDB"

MAX_PROVIDER_RESPONSE_BYTES = 1024 * 1024
RESPONSE_READ_CHUNK_SIZE = 64 * 1024
SQLITE_MAX_INTEGER = 2**63 - 1

MAX_ISP_LENGTH = 255
MAX_DOMAIN_LENGTH = 255
MAX_COUNTRY_CODE_LENGTH = 2
MAX_USAGE_TYPE_LENGTH = 100
MAX_LAST_REPORTED_AT_LENGTH = 64
MAX_PROVIDER_IP_LENGTH = 64

LAST_REPORTED_AT_PATTERN = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d{1,6})?"
    r"(?:Z|[+-]\d{2}:\d{2})?$"
)

INVALID_RESPONSE = object()


class AbuseIPDBError(Exception):
    category = "provider_error"


class ReputationDisabledError(AbuseIPDBError):
    category = "disabled"

    def __init__(self):
        super().__init__("IP reputation lookups are disabled")


class MissingAPIKeyError(AbuseIPDBError):
    category = "missing_key"

    def __init__(self):
        super().__init__("AbuseIPDB API key is not configured")


class AuthenticationError(AbuseIPDBError):
    category = "authentication_error"

    def __init__(self, status_code):
        self.status_code = status_code
        super().__init__("AbuseIPDB authentication failed")


class RateLimitError(AbuseIPDBError):
    category = "rate_limited"

    def __init__(self):
        super().__init__("AbuseIPDB rate limit exceeded")


class ProviderServerError(AbuseIPDBError):
    category = "provider_server_error"

    def __init__(self, status_code):
        self.status_code = status_code
        super().__init__(
            f"AbuseIPDB server error: {status_code}"
        )


class RequestTimeoutError(AbuseIPDBError):
    category = "timeout"

    def __init__(self):
        super().__init__("AbuseIPDB request timed out")


class ProviderConnectionError(AbuseIPDBError):
    category = "connection_error"

    def __init__(self):
        super().__init__("Unable to connect to AbuseIPDB")


class InvalidProviderResponse(AbuseIPDBError):
    category = "invalid_response"

    def __init__(self, message="Invalid AbuseIPDB response"):
        super().__init__(message)


class ProviderResponseTooLarge(InvalidProviderResponse):
    def __init__(self):
        super().__init__("AbuseIPDB response exceeded size limit")


class UnexpectedHTTPError(AbuseIPDBError):
    category = "unexpected_http_error"

    def __init__(self, status_code=None):
        self.status_code = status_code

        if status_code is None:
            message = "Unexpected AbuseIPDB request failure"
        else:
            message = (
                f"Unexpected AbuseIPDB HTTP status: {status_code}"
            )

        super().__init__(message)


def _optional_string(data, field, max_length=None, uppercase=False):
    value = data.get(field)

    if value is None:
        return None

    if not isinstance(value, str):
        raise InvalidProviderResponse()

    value = value.strip()

    if value == "":
        return None

    if max_length is not None and len(value) > max_length:
        raise InvalidProviderResponse()

    if uppercase:
        value = value.upper()

    return value


def _optional_bool(data, field):
    value = data.get(field)

    if value is None:
        return None

    if not isinstance(value, bool):
        raise InvalidProviderResponse()

    return value


def _required_non_negative_int(data, field):
    value = data.get(field)

    if not isinstance(value, int) or isinstance(value, bool):
        raise InvalidProviderResponse()

    if not 0 <= value <= SQLITE_MAX_INTEGER:
        raise InvalidProviderResponse()

    return value


def _parse_last_reported_at(value):
    if value is None:
        return None

    if not isinstance(value, str):
        raise InvalidProviderResponse()

    if len(value) > MAX_LAST_REPORTED_AT_LENGTH:
        raise InvalidProviderResponse()

    if LAST_REPORTED_AT_PATTERN.fullmatch(value) is None:
        raise InvalidProviderResponse()

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError:
        parsed = INVALID_RESPONSE

    if parsed is INVALID_RESPONSE:
        raise InvalidProviderResponse()

    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)

    return parsed


def _declared_content_length_exceeds_limit(response):
    headers = getattr(response, "headers", None)

    if not headers:
        return False

    try:
        raw_length = headers.get("Content-Length")
    except AttributeError:
        return False

    if raw_length is None:
        return False

    try:
        content_length = int(raw_length)
    except (TypeError, ValueError):
        return False

    return content_length > MAX_PROVIDER_RESPONSE_BYTES


def _iter_exception_chain(error):
    seen = set()
    pending = [error]

    while pending:
        current = pending.pop()

        if current is None or id(current) in seen:
            continue

        seen.add(id(current))
        yield current

        pending.append(current.__cause__)
        pending.append(current.__context__)

        for arg in getattr(current, "args", ()):
            if isinstance(arg, BaseException):
                pending.append(arg)


def _is_timeout_error(error):
    timeout_types = (
        requests.exceptions.Timeout,
        urllib3.exceptions.ReadTimeoutError,
    )

    return any(
        isinstance(candidate, timeout_types)
        for candidate in _iter_exception_chain(error)
    )


def _read_bounded_response_body(response):
    if _declared_content_length_exceeds_limit(response):
        raise ProviderResponseTooLarge()

    body = bytearray()
    read_error = None

    try:
        for chunk in response.iter_content(
            chunk_size=RESPONSE_READ_CHUNK_SIZE
        ):
            if not chunk:
                continue

            if not isinstance(chunk, (bytes, bytearray)):
                raise InvalidProviderResponse()

            if (
                len(body) + len(chunk)
                > MAX_PROVIDER_RESPONSE_BYTES
            ):
                raise ProviderResponseTooLarge()

            body.extend(chunk)
    except requests.exceptions.Timeout:
        read_error = RequestTimeoutError()
    except requests.exceptions.ConnectionError as error:
        if _is_timeout_error(error):
            read_error = RequestTimeoutError()
        else:
            read_error = ProviderConnectionError()
    except requests.exceptions.RequestException:
        read_error = UnexpectedHTTPError(None)

    if read_error is not None:
        raise read_error

    return bytes(body)


def _parse_response_body(body):
    parse_error = None

    try:
        payload = json.loads(body)
    except (ValueError, RecursionError):
        parse_error = InvalidProviderResponse()

    if parse_error is not None:
        raise parse_error

    if not isinstance(payload, dict):
        raise InvalidProviderResponse()

    return payload


def _close_response(response):
    try:
        response.close()
    except Exception:
        pass


def _normalize_response(payload, requested_ip):
    if not isinstance(payload, dict):
        raise InvalidProviderResponse()

    data = payload.get("data")

    if not isinstance(data, dict):
        raise InvalidProviderResponse()

    provider_ip = data.get("ipAddress")

    if not isinstance(provider_ip, str):
        raise InvalidProviderResponse()

    if len(provider_ip) > MAX_PROVIDER_IP_LENGTH:
        raise InvalidProviderResponse()

    try:
        canonical_provider_ip = canonicalize_public_ip(provider_ip)
    except ValueError:
        canonical_provider_ip = None

    if canonical_provider_ip is None:
        raise InvalidProviderResponse()

    if canonical_provider_ip != requested_ip:
        raise InvalidProviderResponse()

    abuse_confidence_score = data.get("abuseConfidenceScore")

    if (
        not isinstance(abuse_confidence_score, int)
        or isinstance(abuse_confidence_score, bool)
        or not 0 <= abuse_confidence_score <= 100
    ):
        raise InvalidProviderResponse()

    total_reports = _required_non_negative_int(
        data,
        "totalReports"
    )
    num_distinct_users = _required_non_negative_int(
        data,
        "numDistinctUsers"
    )

    is_public = _optional_bool(data, "isPublic")

    if is_public is not True:
        raise InvalidProviderResponse()

    country_code = _optional_string(
        data,
        "countryCode",
        max_length=MAX_COUNTRY_CODE_LENGTH,
        uppercase=True
    )

    if country_code is not None and (
        len(country_code) != MAX_COUNTRY_CODE_LENGTH
        or not country_code.isascii()
        or not country_code.isalpha()
    ):
        raise InvalidProviderResponse()

    return {
        "ip_address": requested_ip,
        "provider": PROVIDER_NAME,
        "abuse_confidence_score": abuse_confidence_score,
        "total_reports": total_reports,
        "num_distinct_users": num_distinct_users,
        "last_reported_at": _parse_last_reported_at(
            data.get("lastReportedAt")
        ),
        "isp": _optional_string(
            data,
            "isp",
            max_length=MAX_ISP_LENGTH
        ),
        "domain": _optional_string(
            data,
            "domain",
            max_length=MAX_DOMAIN_LENGTH
        ),
        "country_code": country_code,
        "usage_type": _optional_string(
            data,
            "usageType",
            max_length=MAX_USAGE_TYPE_LENGTH
        ),
        "is_public": is_public,
        "is_whitelisted": _optional_bool(
            data,
            "isWhitelisted"
        ),
        "is_tor": _optional_bool(data, "isTor"),
    }


def check_ip(ip_address):
    canonical_ip = canonicalize_public_ip(ip_address)

    if not settings.IP_REPUTATION_ENABLED:
        raise ReputationDisabledError()

    api_key = settings.ABUSEIPDB_API_KEY

    if not api_key or not api_key.strip():
        raise MissingAPIKeyError()

    request_error = None

    try:
        response = requests.get(
            ABUSEIPDB_CHECK_URL,
            params={
                "ipAddress": canonical_ip,
                "maxAgeInDays": ABUSEIPDB_MAX_AGE_DAYS,
            },
            headers={
                "Key": api_key.strip(),
                "Accept": "application/json",
            },
            timeout=settings.ABUSEIPDB_TIMEOUT_SECONDS,
            allow_redirects=False,
            stream=True
        )
    except requests.exceptions.Timeout:
        request_error = RequestTimeoutError()
    except requests.exceptions.ConnectionError:
        request_error = ProviderConnectionError()
    except requests.exceptions.RequestException:
        request_error = UnexpectedHTTPError(None)

    if request_error is not None:
        raise request_error

    try:
        if response.status_code in (401, 403):
            raise AuthenticationError(response.status_code)

        if response.status_code == 429:
            raise RateLimitError()

        if 500 <= response.status_code <= 599:
            raise ProviderServerError(response.status_code)

        if response.status_code != 200:
            raise UnexpectedHTTPError(response.status_code)

        body = _read_bounded_response_body(response)

        return _normalize_response(
            _parse_response_body(body),
            canonical_ip
        )
    finally:
        _close_response(response)
