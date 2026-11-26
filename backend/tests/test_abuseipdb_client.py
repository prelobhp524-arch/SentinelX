import json
import logging

from datetime import datetime

import pytest
import requests
import urllib3

from app.core.config import settings
from app.services import abuseipdb_client, reputation_cache
from app.services.ip_validation import canonicalize_public_ip
from app.services.abuseipdb_client import (
    ABUSEIPDB_CHECK_URL,
    MAX_PROVIDER_RESPONSE_BYTES,
    MAX_SIGNED_BIGINT,
    AuthenticationError,
    InvalidProviderResponse,
    MissingAPIKeyError,
    ProviderConnectionError,
    ProviderResponseTooLarge,
    ProviderServerError,
    RateLimitError,
    ReputationDisabledError,
    RequestTimeoutError,
    UnexpectedHTTPError,
    check_ip,
)


SECRET_API_KEY = "test-super-secret-api-key"


class FakeResponse:
    def __init__(
        self,
        status_code=200,
        payload=None,
        body=None,
        headers=None,
        chunks=None,
        read_error=None,
        close_error=None
    ):
        self.status_code = status_code
        self.headers = headers or {}
        self._chunks = chunks
        self._read_error = read_error
        self._close_error = close_error
        self.close_count = 0
        self.closed = False

        if body is not None:
            self._body = body
        elif payload is not None:
            self._body = json.dumps(payload).encode("utf-8")
        else:
            self._body = b""

    def iter_content(self, chunk_size=1):
        if self._read_error is not None and self._chunks is None:
            raise self._read_error

        if self._chunks is not None:
            yield from self._chunks
        else:
            for start in range(0, len(self._body), chunk_size):
                yield self._body[start:start + chunk_size]

        if self._read_error is not None:
            raise self._read_error

    def close(self):
        self.close_count += 1
        self.closed = True

        if self._close_error is not None:
            raise self._close_error


class StreamingRaw:
    def __init__(self, chunks, error=None):
        self._chunks = chunks
        self._error = error
        self.closed = False
        self.release_count = 0

    def stream(self, chunk_size, decode_content=True):
        yield from self._chunks

        if self._error is not None:
            raise self._error

    def close(self):
        self.closed = True

    def release_conn(self):
        self.release_count += 1


def real_streaming_response(chunks, error=None, headers=None):
    response = requests.Response()
    response.status_code = 200
    response.headers = headers or {}
    response.raw = StreamingRaw(chunks, error)
    return response


def wrapped_connection_error(inner_error):
    try:
        try:
            raise inner_error
        except type(inner_error):
            raise requests.exceptions.ConnectionError(inner_error)
    except requests.exceptions.ConnectionError as error:
        return error


def provider_payload(ip_address="8.8.8.8", **overrides):
    data = {
        "ipAddress": ip_address,
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 87,
        "countryCode": "US",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Example ISP",
        "domain": "example.com",
        "hostnames": [],
        "isTor": False,
        "totalReports": 123,
        "numDistinctUsers": 45,
        "lastReportedAt": "2025-12-31T10:30:00Z",
    }

    data.update(overrides)

    return {"data": data}


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setattr(
        settings,
        "IP_REPUTATION_ENABLED",
        True
    )
    monkeypatch.setattr(
        settings,
        "ABUSEIPDB_API_KEY",
        SECRET_API_KEY
    )
    monkeypatch.setattr(
        settings,
        "ABUSEIPDB_TIMEOUT_SECONDS",
        5.0
    )


@pytest.fixture
def http(monkeypatch):
    state = {
        "response": FakeResponse(payload=provider_payload()),
        "error": None,
        "calls": [],
    }

    def fake_get(url, **kwargs):
        state["calls"].append({
            "url": url,
            **kwargs
        })

        if state["error"] is not None:
            raise state["error"]

        return state["response"]

    monkeypatch.setattr(
        abuseipdb_client.requests,
        "get",
        fake_get
    )

    return state


def test_check_ip_sends_expected_request(enabled, http):
    check_ip("8.8.8.8")

    assert len(http["calls"]) == 1

    call = http["calls"][0]

    assert call["url"] == ABUSEIPDB_CHECK_URL
    assert call["params"] == {
        "ipAddress": "8.8.8.8",
        "maxAgeInDays": 90,
    }
    assert call["headers"] == {
        "Key": SECRET_API_KEY,
        "Accept": "application/json",
    }
    assert call["timeout"] == 5.0
    assert call["allow_redirects"] is False
    assert call["stream"] is True
    assert "verbose" not in call["params"]


def test_check_ip_normalizes_response(enabled, http):
    result = check_ip("8.8.8.8")

    assert result == {
        "ip_address": "8.8.8.8",
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

    assert SECRET_API_KEY not in str(result)


@pytest.mark.parametrize(
    ("input_ip", "canonical_ip"),
    [
        ("8.8.8.8", "8.8.8.8"),
        (
            "2606:4700:4700:0000:0000:0000:0000:1111",
            "2606:4700:4700::1111"
        ),
    ]
)
def test_check_ip_canonicalizes_ipv4_and_ipv6(
    enabled,
    http,
    input_ip,
    canonical_ip
):
    http["response"] = FakeResponse(
        payload=provider_payload(canonical_ip)
    )

    result = check_ip(input_ip)

    assert result["ip_address"] == canonical_ip
    assert http["calls"][0]["params"]["ipAddress"] == canonical_ip


def test_client_and_cache_share_canonical_ip_validator():
    assert (
        abuseipdb_client.canonicalize_public_ip
        is canonicalize_public_ip
    )
    assert (
        reputation_cache.canonicalize_public_ip
        is canonicalize_public_ip
    )


def test_provider_ipv6_is_canonicalized_before_matching(
    enabled,
    http
):
    http["response"] = FakeResponse(
        payload=provider_payload(
            "2606:4700:4700:0000:0000:0000:0000:1111"
        )
    )

    result = check_ip("2606:4700:4700::1111")

    assert result["ip_address"] == "2606:4700:4700::1111"


@pytest.mark.parametrize(
    "ip_address",
    [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "0.0.0.0",
        "2001:db8::1",
        "::1",
        "not-an-ip",
        "999.1.1.1",
        "",
    ]
)
def test_check_ip_rejects_private_invalid_or_non_public_ip(
    enabled,
    http,
    ip_address
):
    with pytest.raises(ValueError):
        check_ip(ip_address)

    assert http["calls"] == []


def test_disabled_feature_prevents_http_request(monkeypatch, http):
    monkeypatch.setattr(
        settings,
        "IP_REPUTATION_ENABLED",
        False
    )
    monkeypatch.setattr(
        settings,
        "ABUSEIPDB_API_KEY",
        SECRET_API_KEY
    )

    with pytest.raises(ReputationDisabledError):
        check_ip("8.8.8.8")

    assert http["calls"] == []


@pytest.mark.parametrize("api_key", [None, "", "   "])
def test_missing_api_key_prevents_http_request(
    monkeypatch,
    http,
    api_key
):
    monkeypatch.setattr(
        settings,
        "IP_REPUTATION_ENABLED",
        True
    )
    monkeypatch.setattr(
        settings,
        "ABUSEIPDB_API_KEY",
        api_key
    )

    with pytest.raises(MissingAPIKeyError):
        check_ip("8.8.8.8")

    assert http["calls"] == []


def test_nullable_provider_fields(enabled, http):
    http["response"] = FakeResponse(
        payload=provider_payload(
            isWhitelisted=None,
            isTor=None,
            countryCode=None,
            usageType=None,
            isp=None,
            domain=None,
            lastReportedAt=None,
        )
    )

    result = check_ip("8.8.8.8")

    assert result["is_public"] is True
    assert result["is_whitelisted"] is None
    assert result["is_tor"] is None
    assert result["country_code"] is None
    assert result["usage_type"] is None
    assert result["isp"] is None
    assert result["domain"] is None
    assert result["total_reports"] == 123
    assert result["num_distinct_users"] == 45
    assert result["last_reported_at"] is None


def test_missing_nullable_provider_fields_become_none(
    enabled,
    http
):
    payload = provider_payload()

    for field in (
        "lastReportedAt",
        "isp",
        "domain",
        "countryCode",
        "usageType",
        "isWhitelisted",
        "isTor",
    ):
        del payload["data"][field]

    http["response"] = FakeResponse(payload=payload)

    result = check_ip("8.8.8.8")

    assert result["last_reported_at"] is None
    assert result["isp"] is None
    assert result["domain"] is None
    assert result["country_code"] is None
    assert result["usage_type"] is None
    assert result["is_whitelisted"] is None
    assert result["is_tor"] is None


def test_optional_empty_strings_become_none(enabled, http):
    http["response"] = FakeResponse(
        payload=provider_payload(
            isp="",
            domain="   ",
            countryCode="",
            usageType="",
        )
    )

    result = check_ip("8.8.8.8")

    assert result["isp"] is None
    assert result["domain"] is None
    assert result["country_code"] is None
    assert result["usage_type"] is None


def test_country_code_is_normalized_to_uppercase(enabled, http):
    http["response"] = FakeResponse(
        payload=provider_payload(countryCode="us")
    )

    result = check_ip("8.8.8.8")

    assert result["country_code"] == "US"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "2025-12-31T10:30:00Z",
            datetime(2025, 12, 31, 10, 30, 0)
        ),
        (
            "2025-12-31T10:30:00+00:00",
            datetime(2025, 12, 31, 10, 30, 0)
        ),
        (
            "2025-12-31T12:30:00+02:00",
            datetime(2025, 12, 31, 10, 30, 0)
        ),
        (
            "2025-12-31T05:30:00-05:00",
            datetime(2025, 12, 31, 10, 30, 0)
        ),
        (
            "2025-12-31T10:30:00.123456Z",
            datetime(2025, 12, 31, 10, 30, 0, 123456)
        ),
        (
            "2025-12-31T10:30:00",
            datetime(2025, 12, 31, 10, 30, 0)
        ),
    ]
)
def test_valid_last_reported_at_formats(
    enabled,
    http,
    value,
    expected
):
    http["response"] = FakeResponse(
        payload=provider_payload(lastReportedAt=value)
    )

    result = check_ip("8.8.8.8")

    assert result["last_reported_at"] == expected


def test_response_ip_mismatch_is_rejected(enabled, http):
    http["response"] = FakeResponse(
        payload=provider_payload("1.1.1.1")
    )

    with pytest.raises(InvalidProviderResponse):
        check_ip("8.8.8.8")


def test_oversized_provider_ip_is_rejected(enabled, http):
    http["response"] = FakeResponse(
        payload=provider_payload("a" * 65)
    )

    with pytest.raises(InvalidProviderResponse):
        check_ip("8.8.8.8")


def test_non_public_provider_ip_is_rejected(enabled, http):
    http["response"] = FakeResponse(
        payload=provider_payload("192.168.1.1")
    )

    with pytest.raises(InvalidProviderResponse):
        check_ip("8.8.8.8")


def test_malformed_json_is_rejected(enabled, http):
    http["response"] = FakeResponse(body=b"not json")

    with pytest.raises(InvalidProviderResponse):
        check_ip("8.8.8.8")

    assert http["response"].closed is True
    assert http["response"].close_count == 1


def test_response_is_closed_after_success(enabled, http):
    response = http["response"]

    check_ip("8.8.8.8")

    assert response.closed is True
    assert response.close_count == 1


def test_response_is_closed_after_http_error(enabled, http):
    response = FakeResponse(status_code=500)
    http["response"] = response

    with pytest.raises(ProviderServerError):
        check_ip("8.8.8.8")

    assert response.closed is True
    assert response.close_count == 1


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Content-Length": "not-a-number"},
        {"Content-Length": "-1"},
        {
            "Content-Length": str(
                MAX_PROVIDER_RESPONSE_BYTES - 1
            )
        },
    ]
)
def test_oversized_streaming_body_is_rejected_with_misleading_headers(
    enabled,
    http,
    headers
):
    response = FakeResponse(
        body=b"x" * (MAX_PROVIDER_RESPONSE_BYTES + 1),
        headers=headers
    )
    http["response"] = response

    with pytest.raises(ProviderResponseTooLarge):
        check_ip("8.8.8.8")

    assert response.closed is True
    assert response.close_count == 1


def test_oversized_response_does_not_leak_body_or_api_key(
    enabled,
    http
):
    body = (
        SECRET_API_KEY + "x" * MAX_PROVIDER_RESPONSE_BYTES
    ).encode("utf-8")
    response = FakeResponse(body=body)
    http["response"] = response

    with pytest.raises(ProviderResponseTooLarge) as exc_info:
        check_ip("8.8.8.8")

    error = exc_info.value

    assert SECRET_API_KEY not in str(error)
    assert SECRET_API_KEY not in repr(error)
    assert SECRET_API_KEY not in str(error.args)
    assert error.category == "invalid_response"
    assert error.__cause__ is None
    assert error.__context__ is None
    assert response.closed is True
    assert response.close_count == 1


def test_declared_oversized_content_length_is_rejected(
    enabled,
    http
):
    response = FakeResponse(
        payload=provider_payload(),
        headers={
            "Content-Length": str(
                MAX_PROVIDER_RESPONSE_BYTES + 1
            )
        }
    )
    http["response"] = response

    with pytest.raises(ProviderResponseTooLarge):
        check_ip("8.8.8.8")

    assert response.closed is True
    assert response.close_count == 1


def test_decompressed_chunks_are_counted_toward_size_limit(
    enabled,
    http
):
    chunk = b"x" * (MAX_PROVIDER_RESPONSE_BYTES // 2 + 1)
    response = FakeResponse(
        headers={
            "Content-Length": "1024",
            "Content-Encoding": "gzip",
        },
        chunks=[chunk, chunk]
    )
    http["response"] = response

    with pytest.raises(ProviderResponseTooLarge):
        check_ip("8.8.8.8")

    assert response.closed is True
    assert response.close_count == 1


def test_response_at_exact_size_limit_is_accepted(enabled, http):
    body = json.dumps(provider_payload()).encode("utf-8")
    body += b" " * (MAX_PROVIDER_RESPONSE_BYTES - len(body))
    response = FakeResponse(body=body)
    http["response"] = response

    result = check_ip("8.8.8.8")

    assert result["abuse_confidence_score"] == 87
    assert response.closed is True
    assert response.close_count == 1


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ChunkedEncodingError(
            f"bad chunk {SECRET_API_KEY}"
        ),
        requests.exceptions.ContentDecodingError(
            f"bad encoding {SECRET_API_KEY}"
        ),
        requests.exceptions.ReadTimeout(
            f"read timed out {SECRET_API_KEY}"
        ),
    ]
)
def test_streaming_read_errors_are_sanitized_and_close_response(
    enabled,
    http,
    error
):
    response = FakeResponse(
        chunks=[b"{"],
        read_error=error
    )
    http["response"] = response

    expected_error = (
        RequestTimeoutError
        if isinstance(error, requests.exceptions.Timeout)
        else UnexpectedHTTPError
    )

    with pytest.raises(expected_error) as exc_info:
        check_ip("8.8.8.8")

    caught = exc_info.value

    assert SECRET_API_KEY not in str(caught)
    assert SECRET_API_KEY not in repr(caught)
    assert caught.__cause__ is None
    assert caught.__context__ is None
    assert response.closed is True
    assert response.close_count == 1


def test_real_iter_content_read_timeout_is_classified_as_timeout(
    enabled,
    http
):
    timeout = urllib3.exceptions.ReadTimeoutError(
        None,
        ABUSEIPDB_CHECK_URL,
        f"Read timed out {SECRET_API_KEY}"
    )
    response = real_streaming_response([b"{"], timeout)
    http["response"] = response

    with pytest.raises(RequestTimeoutError) as exc_info:
        check_ip("8.8.8.8")

    caught = exc_info.value

    assert caught.category == "timeout"
    assert SECRET_API_KEY not in str(caught)
    assert SECRET_API_KEY not in repr(caught)
    assert SECRET_API_KEY not in str(caught.args)
    assert caught.__cause__ is None
    assert caught.__context__ is None
    assert response.raw.closed is True
    assert response.raw.release_count == 1


@pytest.mark.parametrize(
    "inner_error",
    [
        urllib3.exceptions.NewConnectionError(
            None,
            f"connection refused {SECRET_API_KEY}"
        ),
        urllib3.exceptions.ProtocolError(
            f"protocol failure {SECRET_API_KEY}"
        ),
    ]
)
def test_wrapped_non_timeout_connection_errors_stay_connection_errors(
    enabled,
    http,
    inner_error
):
    error = wrapped_connection_error(inner_error)
    response = FakeResponse(
        chunks=[b"{"],
        read_error=error
    )
    http["response"] = response

    with pytest.raises(ProviderConnectionError) as exc_info:
        check_ip("8.8.8.8")

    caught = exc_info.value

    assert caught.category == "connection_error"
    assert SECRET_API_KEY not in str(caught)
    assert SECRET_API_KEY not in repr(caught)
    assert caught.__cause__ is None
    assert caught.__context__ is None
    assert response.closed is True
    assert response.close_count == 1


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {},
        {"data": None},
        {"data": []},
        {"data": {}},
        {"data": {"ipAddress": "8.8.8.8"}},
    ]
)
def test_invalid_response_schema_is_rejected(
    enabled,
    http,
    payload
):
    http["response"] = FakeResponse(payload=payload)

    with pytest.raises(InvalidProviderResponse):
        check_ip("8.8.8.8")


@pytest.mark.parametrize(
    "score",
    [-1, 101, "50", 50.5, True]
)
def test_invalid_abuse_confidence_score_is_rejected(
    enabled,
    http,
    score
):
    http["response"] = FakeResponse(
        payload=provider_payload(
            abuseConfidenceScore=score
        )
    )

    with pytest.raises(InvalidProviderResponse):
        check_ip("8.8.8.8")


@pytest.mark.parametrize("value", [None, "missing"])
def test_missing_or_null_abuse_confidence_score_is_rejected(
    enabled,
    http,
    value
):
    payload = provider_payload()

    if value == "missing":
        del payload["data"]["abuseConfidenceScore"]
    else:
        payload["data"]["abuseConfidenceScore"] = value

    http["response"] = FakeResponse(payload=payload)

    with pytest.raises(InvalidProviderResponse):
        check_ip("8.8.8.8")


@pytest.mark.parametrize(
    "field",
    ["totalReports", "numDistinctUsers"]
)
@pytest.mark.parametrize("value", [-1, -100])
def test_negative_report_counts_are_rejected(
    enabled,
    http,
    field,
    value
):
    http["response"] = FakeResponse(
        payload=provider_payload(**{field: value})
    )

    with pytest.raises(InvalidProviderResponse):
        check_ip("8.8.8.8")


@pytest.mark.parametrize(
    "field",
    ["totalReports", "numDistinctUsers"]
)
@pytest.mark.parametrize("value", [True, False])
def test_boolean_report_counts_are_rejected(
    enabled,
    http,
    field,
    value
):
    http["response"] = FakeResponse(
        payload=provider_payload(**{field: value})
    )

    with pytest.raises(InvalidProviderResponse):
        check_ip("8.8.8.8")


@pytest.mark.parametrize(
    "field",
    ["totalReports", "numDistinctUsers"]
)
def test_integer_overflow_report_counts_are_rejected(
    enabled,
    http,
    field
):
    http["response"] = FakeResponse(
        payload=provider_payload(
            **{field: MAX_SIGNED_BIGINT + 1}
        )
    )

    with pytest.raises(InvalidProviderResponse):
        check_ip("8.8.8.8")


@pytest.mark.parametrize(
    ("field", "normalized_field"),
    [
        ("totalReports", "total_reports"),
        ("numDistinctUsers", "num_distinct_users"),
    ]
)
@pytest.mark.parametrize("value", [0, MAX_SIGNED_BIGINT])
def test_valid_report_count_boundaries_are_accepted(
    enabled,
    http,
    field,
    normalized_field,
    value
):
    http["response"] = FakeResponse(
        payload=provider_payload(**{field: value})
    )

    result = check_ip("8.8.8.8")

    assert result[normalized_field] == value


@pytest.mark.parametrize("score", [0, 100])
def test_valid_abuse_confidence_score_boundaries_are_accepted(
    enabled,
    http,
    score
):
    http["response"] = FakeResponse(
        payload=provider_payload(
            abuseConfidenceScore=score
        )
    )

    result = check_ip("8.8.8.8")

    assert result["abuse_confidence_score"] == score


@pytest.mark.parametrize(
    "field",
    ["totalReports", "numDistinctUsers"]
)
@pytest.mark.parametrize("value", [None, "missing"])
def test_missing_required_report_counts_are_rejected(
    enabled,
    http,
    field,
    value
):
    payload = provider_payload()

    if value == "missing":
        del payload["data"][field]
    else:
        payload["data"][field] = None

    http["response"] = FakeResponse(payload=payload)

    with pytest.raises(InvalidProviderResponse):
        check_ip("8.8.8.8")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("isp", 123),
        ("domain", []),
        ("countryCode", 1),
        ("usageType", 1.5),
        ("isPublic", "true"),
        ("isWhitelisted", 0),
        ("isTor", "false"),
        ("lastReportedAt", 123),
        ("totalReports", "5"),
        ("numDistinctUsers", 1.5),
    ]
)
def test_wrong_field_types_are_rejected(
    enabled,
    http,
    field,
    value
):
    http["response"] = FakeResponse(
        payload=provider_payload(**{field: value})
    )

    with pytest.raises(InvalidProviderResponse):
        check_ip("8.8.8.8")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("isp", "a" * 256),
        ("domain", "a" * 256),
        ("usageType", "a" * 101),
        ("countryCode", "USA"),
        ("countryCode", "U1"),
        ("countryCode", "\u00dcS"),
        ("lastReportedAt", "a" * 65),
    ]
)
def test_oversized_or_invalid_strings_are_rejected(
    enabled,
    http,
    field,
    value
):
    http["response"] = FakeResponse(
        payload=provider_payload(**{field: value})
    )

    with pytest.raises(InvalidProviderResponse):
        check_ip("8.8.8.8")


@pytest.mark.parametrize(
    "value",
    [
        "not-a-date",
        "",
        "2025-12-31",
        "2025-12-31 10:30:00",
        "20251231T103000",
        "2025-12-31T10:30Z",
        "2025-12-31T10:30:00z",
        "2025-12-31T10:30:00+0000",
        "2025-12-31T10:30:00.1234567Z",
        "2025-02-30T10:30:00Z",
        "2025-12-31T10:30:00Zjunk",
        "2025-12-31T10:30:00+24:00",
    ]
)
def test_invalid_last_reported_at_is_rejected(
    enabled,
    http,
    value
):
    http["response"] = FakeResponse(
        payload=provider_payload(lastReportedAt=value)
    )

    with pytest.raises(InvalidProviderResponse):
        check_ip("8.8.8.8")


@pytest.mark.parametrize("value", [None, False, "missing"])
def test_required_is_public_must_be_true(
    enabled,
    http,
    value
):
    payload = provider_payload()

    if value == "missing":
        del payload["data"]["isPublic"]
    else:
        payload["data"]["isPublic"] = value

    http["response"] = FakeResponse(payload=payload)

    with pytest.raises(InvalidProviderResponse):
        check_ip("8.8.8.8")


@pytest.mark.parametrize("status_code", [401, 403])
def test_authentication_errors(
    enabled,
    http,
    status_code
):
    http["response"] = FakeResponse(status_code=status_code)

    with pytest.raises(AuthenticationError) as exc_info:
        check_ip("8.8.8.8")

    assert exc_info.value.status_code == status_code


def test_rate_limit_error(enabled, http):
    http["response"] = FakeResponse(status_code=429)

    with pytest.raises(RateLimitError):
        check_ip("8.8.8.8")


@pytest.mark.parametrize("status_code", [500, 502, 503, 504])
def test_provider_server_errors(
    enabled,
    http,
    status_code
):
    http["response"] = FakeResponse(status_code=status_code)

    with pytest.raises(ProviderServerError) as exc_info:
        check_ip("8.8.8.8")

    assert exc_info.value.status_code == status_code


def test_no_retry_on_provider_error(enabled, http):
    http["response"] = FakeResponse(status_code=500)

    with pytest.raises(ProviderServerError):
        check_ip("8.8.8.8")

    assert len(http["calls"]) == 1


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.Timeout("timed out"),
        requests.exceptions.ReadTimeout("read timed out"),
        requests.exceptions.ConnectTimeout("connect timed out"),
    ]
)
def test_timeout_errors(enabled, http, error):
    http["error"] = error

    with pytest.raises(RequestTimeoutError):
        check_ip("8.8.8.8")


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ConnectionError("connection failed"),
        requests.exceptions.SSLError("tls failed"),
    ]
)
def test_connection_errors(enabled, http, error):
    http["error"] = error

    with pytest.raises(ProviderConnectionError):
        check_ip("8.8.8.8")


@pytest.mark.parametrize("status_code", [400, 404, 418, 302])
def test_unexpected_http_statuses(
    enabled,
    http,
    status_code
):
    http["response"] = FakeResponse(status_code=status_code)

    with pytest.raises(UnexpectedHTTPError) as exc_info:
        check_ip("8.8.8.8")

    assert exc_info.value.status_code == status_code


def test_other_request_errors_are_sanitized(enabled, http):
    http["error"] = requests.exceptions.RequestException(
        f"unexpected request failure with {SECRET_API_KEY}"
    )

    with pytest.raises(UnexpectedHTTPError) as exc_info:
        check_ip("8.8.8.8")

    error = exc_info.value

    assert error.status_code is None
    assert SECRET_API_KEY not in repr(error)
    assert error.__cause__ is None
    assert error.__context__ is None


def test_errors_do_not_leak_api_key_or_response_body(
    enabled,
    http
):
    http["response"] = FakeResponse(
        status_code=401,
        payload={
            "errors": [
                {
                    "detail": SECRET_API_KEY
                }
            ]
        }
    )

    with pytest.raises(AuthenticationError) as exc_info:
        check_ip("8.8.8.8")

    error = exc_info.value

    assert SECRET_API_KEY not in str(error)
    assert SECRET_API_KEY not in repr(error)
    assert SECRET_API_KEY not in str(error.args)
    assert error.__cause__ is None
    assert error.__context__ is None


def test_request_exception_context_does_not_leak_api_key(
    enabled,
    http
):
    http["error"] = requests.exceptions.ConnectionError(
        f"failed with {SECRET_API_KEY}"
    )

    with pytest.raises(ProviderConnectionError) as exc_info:
        check_ip("8.8.8.8")

    error = exc_info.value

    assert SECRET_API_KEY not in str(error)
    assert SECRET_API_KEY not in repr(error)
    assert error.__cause__ is None
    assert error.__context__ is None


def test_malformed_json_context_does_not_leak_response_body(
    enabled,
    http
):
    http["response"] = FakeResponse(
        body=f"not json: {SECRET_API_KEY}".encode("utf-8")
    )

    with pytest.raises(InvalidProviderResponse) as exc_info:
        check_ip("8.8.8.8")

    error = exc_info.value

    assert SECRET_API_KEY not in str(error)
    assert SECRET_API_KEY not in repr(error)
    assert error.__cause__ is None
    assert error.__context__ is None


def test_client_does_not_log_api_key(enabled, http, caplog):
    http["response"] = FakeResponse(status_code=500)

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(ProviderServerError):
            check_ip("8.8.8.8")

    assert SECRET_API_KEY not in caplog.text
