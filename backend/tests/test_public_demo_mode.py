import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api.reputation import get_ip_reputation
from app.core.config import settings
from app.main import PublicDemoModeMiddleware


class DummyApp:
    pass


def dispatch(method):
    middleware = PublicDemoModeMiddleware(DummyApp())
    called = False

    async def call_next(request):
        nonlocal called
        called = True
        return "next-response"

    request = SimpleNamespace(method=method)

    return asyncio.run(middleware.dispatch(request, call_next)), called


@pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS"])
def test_public_demo_mode_allows_safe_methods(monkeypatch, method):
    monkeypatch.setattr(settings, "PUBLIC_DEMO_MODE", True)

    response, called = dispatch(method)

    assert response == "next-response"
    assert called is True


@pytest.mark.parametrize("method", ["POST", "PATCH", "PUT", "DELETE"])
def test_public_demo_mode_blocks_state_changing_methods(
    monkeypatch,
    method
):
    monkeypatch.setattr(settings, "PUBLIC_DEMO_MODE", True)

    response, called = dispatch(method)

    assert response.status_code == 403
    assert "read-only" in response.body.decode()
    assert called is False


def test_state_changing_methods_are_allowed_outside_demo_mode(monkeypatch):
    monkeypatch.setattr(settings, "PUBLIC_DEMO_MODE", False)

    response, called = dispatch("POST")

    assert response == "next-response"
    assert called is True


def test_public_demo_mode_blocks_reputation_lookups(monkeypatch):
    monkeypatch.setattr(settings, "PUBLIC_DEMO_MODE", True)

    with pytest.raises(HTTPException) as exc_info:
        get_ip_reputation(
            "8.8.8.8",
            force_refresh=False,
            db=None,
            _rate_limit=None
        )

    assert exc_info.value.status_code == 403
    assert "public demo mode" in exc_info.value.detail
