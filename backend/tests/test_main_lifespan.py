import asyncio
import logging
import threading
import time

import pytest

import app.main as main_module
from app.core.config import settings
from app.services.ip_reputation_worker import IPReputationWorker


def wait_until(predicate, timeout=2.0, interval=0.005):
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if predicate():
            return True

        time.sleep(interval)

    return bool(predicate())


class FakeWorker:
    def __init__(self):
        self.start_calls = 0
        self.stop_calls = 0
        self.stop_timeouts = []
        self.start_error = None
        self.stop_error = None
        self.stop_result = True

    def start(self):
        self.start_calls += 1

        if self.start_error is not None:
            raise self.start_error

        return True

    def stop(self, timeout=5.0):
        self.stop_calls += 1
        self.stop_timeouts.append(timeout)

        if self.stop_error is not None:
            raise self.stop_error

        return self.stop_result


class FakeWebSocketManager:
    def __init__(self):
        self.registered_loops = []
        self.clear_calls = 0
        self.clear_error = None

    def register_loop(self, loop):
        self.registered_loops.append(loop)

    def clear_loop(self):
        self.clear_calls += 1

        if self.clear_error is not None:
            raise self.clear_error


def run_lifespan():
    async def runner():
        async with main_module.lifespan(main_module.app):
            pass

    asyncio.run(runner())


def install_fakes(monkeypatch, worker, manager):
    monkeypatch.setattr(
        main_module,
        "ip_reputation_worker",
        worker
    )
    monkeypatch.setattr(
        main_module,
        "websocket_manager",
        manager
    )


def test_lifespan_starts_and_stops_worker_once(monkeypatch):
    worker = FakeWorker()
    manager = FakeWebSocketManager()
    install_fakes(monkeypatch, worker, manager)
    monkeypatch.setattr(settings, "IP_REPUTATION_ENABLED", True)

    async def runner():
        async with main_module.lifespan(main_module.app):
            assert worker.start_calls == 1
            assert worker.stop_calls == 0
            assert manager.clear_calls == 0
            assert len(manager.registered_loops) == 1
            assert (
                manager.registered_loops[0]
                is asyncio.get_running_loop()
            )

    asyncio.run(runner())

    assert worker.start_calls == 1
    assert worker.stop_calls == 1
    assert worker.stop_timeouts == [5.0]
    assert manager.clear_calls == 1


def test_lifespan_stops_worker_during_shutdown(monkeypatch):
    worker = FakeWorker()
    manager = FakeWebSocketManager()
    install_fakes(monkeypatch, worker, manager)
    monkeypatch.setattr(settings, "IP_REPUTATION_ENABLED", True)

    async def runner():
        async with main_module.lifespan(main_module.app):
            assert worker.stop_calls == 0

    asyncio.run(runner())

    assert worker.stop_calls == 1
    assert manager.clear_calls == 1


def test_disabled_lifespan_does_not_start_worker(monkeypatch):
    worker = FakeWorker()
    manager = FakeWebSocketManager()
    install_fakes(monkeypatch, worker, manager)
    monkeypatch.setattr(settings, "IP_REPUTATION_ENABLED", False)

    run_lifespan()

    assert worker.start_calls == 0
    assert worker.stop_calls == 1
    assert manager.clear_calls == 1


def test_disabled_lifespan_performs_no_reputation_lookups(monkeypatch):
    lookups = []

    def fake_getter(db, ip_address):
        lookups.append((db, ip_address))

    worker = IPReputationWorker(reputation_getter=fake_getter)
    manager = FakeWebSocketManager()
    install_fakes(monkeypatch, worker, manager)
    monkeypatch.setattr(settings, "IP_REPUTATION_ENABLED", False)

    try:
        run_lifespan()

        assert lookups == []
        assert worker.is_running() is False
    finally:
        worker.stop(timeout=2)


def test_websocket_cleanup_runs_when_worker_stop_fails(monkeypatch):
    worker = FakeWorker()
    worker.stop_error = RuntimeError("stop boom")
    manager = FakeWebSocketManager()
    install_fakes(monkeypatch, worker, manager)
    monkeypatch.setattr(settings, "IP_REPUTATION_ENABLED", True)

    with pytest.raises(RuntimeError, match="stop boom"):
        run_lifespan()

    assert worker.start_calls == 1
    assert worker.stop_calls == 1
    assert manager.clear_calls == 1


def test_worker_stops_when_websocket_cleanup_fails(monkeypatch):
    worker = FakeWorker()
    manager = FakeWebSocketManager()
    manager.clear_error = RuntimeError("clear boom")
    install_fakes(monkeypatch, worker, manager)
    monkeypatch.setattr(settings, "IP_REPUTATION_ENABLED", True)

    with pytest.raises(RuntimeError, match="clear boom"):
        run_lifespan()

    assert worker.start_calls == 1
    assert worker.stop_calls == 1
    assert manager.clear_calls == 1


def test_lifespan_cleans_up_when_worker_start_fails(monkeypatch):
    worker = FakeWorker()
    worker.start_error = RuntimeError("start boom")
    manager = FakeWebSocketManager()
    install_fakes(monkeypatch, worker, manager)
    monkeypatch.setattr(settings, "IP_REPUTATION_ENABLED", True)

    with pytest.raises(RuntimeError, match="start boom"):
        run_lifespan()

    assert worker.start_calls == 1
    assert worker.stop_calls == 1
    assert manager.clear_calls == 1


def test_lifespan_warns_when_worker_stop_times_out(
    monkeypatch,
    caplog
):
    worker = FakeWorker()
    worker.stop_result = False
    manager = FakeWebSocketManager()
    install_fakes(monkeypatch, worker, manager)
    monkeypatch.setattr(settings, "IP_REPUTATION_ENABLED", True)

    with caplog.at_level(logging.WARNING):
        run_lifespan()

    assert "did not stop within timeout" in caplog.text
    assert manager.clear_calls == 1


def test_real_worker_starts_once_and_leaves_no_thread(monkeypatch):
    lookups = []

    def fake_getter(db, ip_address):
        lookups.append((db, ip_address))

    worker = IPReputationWorker(reputation_getter=fake_getter)
    manager = FakeWebSocketManager()
    install_fakes(monkeypatch, worker, manager)
    monkeypatch.setattr(settings, "IP_REPUTATION_ENABLED", True)

    async def runner():
        async with main_module.lifespan(main_module.app):
            assert wait_until(worker.is_running)
            assert worker.status()["thread_name"] == (
                "ip-reputation-worker"
            )
            assert sum(
                thread.name == "ip-reputation-worker"
                for thread in threading.enumerate()
            ) == 1

    try:
        asyncio.run(runner())
    finally:
        worker.stop(timeout=2)

    assert worker.status()["running"] is False
    assert worker.status()["thread_alive"] is False
    assert worker.status()["thread_name"] is None
    assert lookups == []
    assert not any(
        thread.name == "ip-reputation-worker"
        for thread in threading.enumerate()
    )
