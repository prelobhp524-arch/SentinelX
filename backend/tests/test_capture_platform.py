import pytest
from fastapi import HTTPException

from app.api import capture as capture_api
from app.services import packet_capture


def test_unsupported_platform_reports_no_interfaces(monkeypatch):
    monkeypatch.setattr(packet_capture, "CAPTURE_SUPPORTED", False)

    assert packet_capture.get_available_interfaces() == []

    status = packet_capture.get_capture_status()

    assert status["status"] == "unsupported"
    assert status["supported"] is False
    assert status["reason"] == packet_capture.CAPTURE_UNSUPPORTED_MESSAGE
    assert status["interface"] is None


def test_start_capture_rejects_unsupported_platform(monkeypatch):
    monkeypatch.setattr(packet_capture, "CAPTURE_SUPPORTED", False)

    with pytest.raises(packet_capture.CaptureUnsupportedError):
        packet_capture.start_capture()


def test_capture_start_maps_unsupported_error_to_503(monkeypatch):
    def fake_start_capture(interface=None):
        raise packet_capture.CaptureUnsupportedError(
            packet_capture.CAPTURE_UNSUPPORTED_MESSAGE
        )

    monkeypatch.setattr(capture_api, "start_capture", fake_start_capture)

    with pytest.raises(HTTPException) as exc_info:
        capture_api.start_packet_capture(None)

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == packet_capture.CAPTURE_UNSUPPORTED_MESSAGE


def test_interfaces_endpoint_includes_support_metadata(monkeypatch):
    monkeypatch.setattr(capture_api, "CAPTURE_SUPPORTED", False)
    monkeypatch.setattr(
        capture_api,
        "get_available_interfaces",
        lambda: []
    )

    response = capture_api.available_interfaces()

    assert response["interfaces"] == []
    assert response["supported"] is False
    assert response["reason"] == packet_capture.CAPTURE_UNSUPPORTED_MESSAGE
