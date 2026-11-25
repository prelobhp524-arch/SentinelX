import threading
import time
import uuid

from datetime import datetime, timedelta, timezone

import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool, StaticPool

from app.core.config import settings
from app.core.database import Base
from app.services import ip_reputation_service
from app.services.abuseipdb_client import ProviderServerError
from app.services.ip_reputation_coordinator import IPRefreshCoordinator
from app.services.rate_limiter import ReputationRateLimiter
from app.services.reputation_cache import upsert_reputation


def utc_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


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


def wait_until(predicate, timeout=2.0, interval=0.005):
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if predicate():
            return True

        time.sleep(interval)

    return bool(predicate())


def store_cache(
    session_factory,
    ip_address="8.8.8.8",
    score=87,
    checked_at=None
):
    if checked_at is None:
        checked_at = utc_now()

    db = session_factory()

    try:
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
    finally:
        db.close()


def fetch(session_factory, ip_address, force_refresh=False):
    db = session_factory()

    try:
        return ip_reputation_service.get_reputation(
            db,
            ip_address,
            force_refresh=force_refresh
        )
    finally:
        db.close()


def start_requests(
    session_factory,
    ip_addresses,
    force_refresh=False
):
    count = len(ip_addresses)
    barrier = threading.Barrier(count)
    results = [None] * count
    errors = [None] * count

    def run(index, ip_address):
        db = session_factory()

        try:
            barrier.wait(timeout=5)
            results[index] = ip_reputation_service.get_reputation(
                db,
                ip_address,
                force_refresh=force_refresh
            )
        except Exception as error:
            errors[index] = error
        finally:
            db.close()

    threads = [
        threading.Thread(
            target=run,
            args=(index, ip_address)
        )
        for index, ip_address in enumerate(ip_addresses)
    ]

    for thread in threads:
        thread.start()

    return threads, results, errors


def join_all(threads, timeout=5):
    for thread in threads:
        thread.join(timeout=timeout)

    assert all(not thread.is_alive() for thread in threads)


@pytest.fixture(autouse=True)
def enabled_reputation(monkeypatch):
    monkeypatch.setattr(settings, "IP_REPUTATION_ENABLED", True)
    monkeypatch.setattr(
        settings,
        "IP_REPUTATION_CACHE_TTL_HOURS",
        24
    )


@pytest.fixture
def coordinator(monkeypatch):
    coordinator = IPRefreshCoordinator()
    monkeypatch.setattr(
        ip_reputation_service,
        "refresh_coordinator",
        coordinator
    )

    return coordinator


@pytest.fixture
def session_factory():
    name = f"sx_reputation_{uuid.uuid4().hex}"
    url = (
        f"sqlite:///file:{name}"
        "?mode=memory&cache=shared&uri=true"
    )

    engine = create_engine(
        url,
        connect_args={
            "check_same_thread": False,
            "uri": True,
        },
        poolclass=NullPool
    )
    keeper = engine.connect()

    Base.metadata.create_all(bind=engine)

    TestingSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False
    )

    try:
        yield TestingSession
    finally:
        Base.metadata.drop_all(bind=engine)
        keeper.close()
        engine.dispose()


@pytest.fixture
def provider(monkeypatch):
    state = {
        "response": normalized_data("8.8.8.8"),
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


def test_concurrent_uncached_same_ip_uses_one_provider_call(
    session_factory,
    provider,
    coordinator
):
    ip_address = "8.8.8.8"
    provider["block"] = True

    threads, results, errors = start_requests(
        session_factory,
        [ip_address] * 4
    )

    try:
        assert provider["entered"].wait(timeout=2)
        assert wait_until(
            lambda: coordinator.active_requests(ip_address) == 4
        )
    finally:
        provider["release"].set()

    join_all(threads)

    assert errors == [None] * 4
    assert provider["calls"] == [ip_address]
    assert sum(
        result["state"] == "refreshed"
        for result in results
    ) == 1
    assert sum(
        result["state"] == "cached"
        for result in results
    ) == 3
    assert all(
        result["reputation"]["abuse_confidence_score"] == 87
        for result in results
    )
    assert wait_until(lambda: coordinator.active_count() == 0)


def test_concurrent_stale_same_ip_uses_one_provider_call(
    session_factory,
    provider,
    coordinator
):
    ip_address = "8.8.8.8"
    stale_checked_at = utc_now() - timedelta(hours=48)

    store_cache(
        session_factory,
        ip_address,
        score=10,
        checked_at=stale_checked_at
    )

    provider["response"] = normalized_data(
        ip_address,
        abuse_confidence_score=80
    )
    provider["block"] = True

    threads, results, errors = start_requests(
        session_factory,
        [ip_address] * 3
    )

    try:
        assert provider["entered"].wait(timeout=2)
        assert wait_until(
            lambda: coordinator.active_requests(ip_address) == 3
        )
    finally:
        provider["release"].set()

    join_all(threads)

    assert errors == [None] * 3
    assert provider["calls"] == [ip_address]
    assert sum(
        result["state"] == "refreshed"
        for result in results
    ) == 1
    assert sum(
        result["state"] == "cached"
        for result in results
    ) == 2
    assert all(
        result["reputation"]["abuse_confidence_score"] == 80
        for result in results
    )
    assert wait_until(lambda: coordinator.active_count() == 0)


def test_different_ips_can_refresh_independently(
    provider,
    coordinator
):
    ip_addresses = ["8.8.8.8", "1.1.1.1"]
    engines = []
    session_factories = []

    for _ in ip_addresses:
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool
        )

        Base.metadata.create_all(bind=engine)
        engines.append(engine)
        session_factories.append(
            sessionmaker(
                bind=engine,
                autoflush=False,
                autocommit=False
            )
        )

    provider["barrier"] = threading.Barrier(len(ip_addresses))
    barrier = threading.Barrier(len(ip_addresses))
    results = [None] * len(ip_addresses)
    errors = [None] * len(ip_addresses)

    def run(index, ip_address):
        db = session_factories[index]()

        try:
            barrier.wait(timeout=5)
            results[index] = ip_reputation_service.get_reputation(
                db,
                ip_address
            )
        except Exception as error:
            errors[index] = error
        finally:
            db.close()

    threads = [
        threading.Thread(
            target=run,
            args=(index, ip_address)
        )
        for index, ip_address in enumerate(ip_addresses)
    ]

    try:
        for thread in threads:
            thread.start()

        join_all(threads)

        assert errors == [None, None]
        assert sorted(provider["calls"]) == sorted(ip_addresses)
        assert all(
            result["state"] == "refreshed"
            for result in results
        )
        assert wait_until(lambda: coordinator.active_count() == 0)
    finally:
        for engine in engines:
            Base.metadata.drop_all(bind=engine)
            engine.dispose()


def test_concurrent_force_refresh_same_ip_is_coordinated(
    session_factory,
    provider,
    coordinator
):
    ip_address = "8.8.8.8"
    provider["block"] = True

    threads, results, errors = start_requests(
        session_factory,
        [ip_address] * 4,
        force_refresh=True
    )

    try:
        assert provider["entered"].wait(timeout=2)
        assert wait_until(
            lambda: coordinator.active_requests(ip_address) == 4
        )
    finally:
        provider["release"].set()

    join_all(threads)

    assert errors == [None] * 4
    assert provider["calls"] == [ip_address]
    assert all(
        result["state"] == "refreshed"
        for result in results
    )
    assert wait_until(lambda: coordinator.active_count() == 0)


def test_waiting_request_rechecks_cache_before_provider(
    session_factory,
    provider,
    coordinator
):
    ip_address = "8.8.8.8"
    result = {}
    errors = []
    started = threading.Event()

    provider["error"] = AssertionError(
        "provider should not be called"
    )

    def request():
        db = session_factory()

        try:
            started.set()
            result["value"] = ip_reputation_service.get_reputation(
                db,
                ip_address
            )
        except Exception as error:
            errors.append(error)
        finally:
            db.close()

    with coordinator.acquire(ip_address):
        thread = threading.Thread(target=request)
        thread.start()

        assert started.wait(timeout=2)
        assert wait_until(
            lambda: coordinator.active_requests(ip_address) == 2
        )

        store_cache(
            session_factory,
            ip_address,
            score=42
        )

    thread.join(timeout=5)

    assert not thread.is_alive()
    assert errors == []
    assert result["value"]["state"] == "cached"
    assert (
        result["value"]["reputation"]["abuse_confidence_score"] == 42
    )
    assert provider["calls"] == []
    assert wait_until(lambda: coordinator.active_count() == 0)


def test_provider_failure_does_not_permanently_lock_ip(
    session_factory,
    provider,
    coordinator
):
    ip_address = "8.8.8.8"
    provider["error"] = ProviderServerError(500)

    failed = fetch(session_factory, ip_address)

    assert failed["state"] == "unavailable"
    assert failed["provider_error"] == "provider_server_error"
    assert provider["calls"] == [ip_address]
    assert coordinator.active_count() == 0

    provider["error"] = None

    refreshed = fetch(session_factory, ip_address)

    assert refreshed["state"] == "refreshed"
    assert provider["calls"] == [ip_address, ip_address]
    assert coordinator.active_count() == 0


def test_concurrent_stale_requests_share_failed_refresh(
    session_factory,
    provider,
    coordinator
):
    ip_address = "8.8.8.8"
    stale_checked_at = utc_now() - timedelta(hours=48)

    store_cache(
        session_factory,
        ip_address,
        score=80,
        checked_at=stale_checked_at
    )

    provider["error"] = ProviderServerError(500)
    provider["block"] = True

    threads, results, errors = start_requests(
        session_factory,
        [ip_address] * 3
    )

    try:
        assert provider["entered"].wait(timeout=2)
        assert wait_until(
            lambda: coordinator.active_requests(ip_address) == 3
        )
    finally:
        provider["release"].set()

    join_all(threads)

    assert errors == [None] * 3
    assert provider["calls"] == [ip_address]
    assert all(
        result["state"] == "stale"
        for result in results
    )
    assert all(
        result["provider_error"] == "provider_server_error"
        for result in results
    )
    assert all(
        result["reputation"]["abuse_confidence_score"] == 80
        for result in results
    )
    assert wait_until(lambda: coordinator.active_count() == 0)


def test_coordination_state_is_cleaned_after_success_and_failure(
    session_factory,
    provider,
    coordinator
):
    provider["response"] = normalized_data(
        "8.8.8.8",
        abuse_confidence_score=50
    )

    success = fetch(session_factory, "8.8.8.8")

    assert success["state"] == "refreshed"
    assert coordinator.active_count() == 0

    provider["error"] = ProviderServerError(500)

    failure = fetch(session_factory, "1.1.1.1")

    assert failure["state"] == "unavailable"
    assert coordinator.active_count() == 0


def test_waiters_do_not_consume_extra_provider_quota(
    session_factory,
    provider,
    coordinator,
    monkeypatch
):
    ip_address = "8.8.8.8"
    limiter = ReputationRateLimiter(
        request_limit=100,
        force_refresh_limit=100,
        provider_limit=1,
        window_seconds=60
    )
    monkeypatch.setattr(
        ip_reputation_service,
        "reputation_rate_limiter",
        limiter
    )

    provider["block"] = True

    threads, results, errors = start_requests(
        session_factory,
        [ip_address] * 4
    )

    try:
        assert provider["entered"].wait(timeout=2)
        assert wait_until(
            lambda: coordinator.active_requests(ip_address) == 4
        )
    finally:
        provider["release"].set()

    join_all(threads)

    assert errors == [None] * 4
    assert provider["calls"] == [ip_address]
    assert sum(
        result["state"] == "refreshed"
        for result in results
    ) == 1
    assert sum(
        result["state"] == "cached"
        for result in results
    ) == 3
    assert wait_until(lambda: coordinator.active_count() == 0)


def test_fresh_cache_skips_coordination_and_provider(
    session_factory,
    provider,
    coordinator
):
    ip_address = "8.8.8.8"

    store_cache(
        session_factory,
        ip_address,
        score=50
    )

    provider["error"] = AssertionError(
        "provider should not be called"
    )

    result = fetch(session_factory, ip_address)

    assert result["state"] == "cached"
    assert result["reputation"]["abuse_confidence_score"] == 50
    assert provider["calls"] == []
    assert coordinator.active_count() == 0
