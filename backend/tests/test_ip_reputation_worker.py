import logging
import threading
import time

import pytest

from app.core.config import settings
from app.services.ip_reputation_worker import (
    ENQUEUE_DISABLED,
    ENQUEUE_DUPLICATE,
    ENQUEUE_FULL,
    ENQUEUE_NOT_RUNNING,
    ENQUEUE_QUEUED,
    IPReputationWorker,
)


def wait_until(predicate, timeout=2.0, interval=0.005):
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if predicate():
            return True

        time.sleep(interval)

    return bool(predicate())


class FakeSession:
    def __init__(self):
        self.closed = False
        self.close_calls = 0

    def close(self):
        self.close_calls += 1
        self.closed = True


class FakeSessionFactory:
    def __init__(self):
        self.sessions = []
        self.error = None

    def __call__(self):
        if self.error is not None:
            raise self.error

        session = FakeSession()
        self.sessions.append(session)

        return session


class RecordingGetter:
    def __init__(self):
        self.calls = []
        self.blocked_ips = set()
        self.errors = {}
        self.release_event = threading.Event()

    def __call__(self, db, ip_address):
        self.calls.append((ip_address, db))

        if ip_address in self.blocked_ips:
            self.release_event.wait(timeout=5)

        error = self.errors.get(ip_address)

        if error is not None:
            raise error


class RunningWorker:
    def __init__(self, worker, getter=None):
        self.worker = worker
        self.getter = getter

    def __enter__(self):
        assert self.worker.start() is True

        return self.worker

    def __exit__(self, exc_type, exc_value, traceback):
        if self.getter is not None:
            self.getter.release_event.set()

        self.worker.stop(timeout=2)

        return False


@pytest.fixture(autouse=True)
def enabled_reputation(monkeypatch):
    monkeypatch.setattr(settings, "IP_REPUTATION_ENABLED", True)


@pytest.mark.parametrize(
    "queue_capacity",
    [0, -1, 1001, True, False, "10", 1.5, None]
)
def test_constructor_rejects_invalid_queue_capacity(queue_capacity):
    with pytest.raises(ValueError):
        IPReputationWorker(queue_capacity=queue_capacity)


@pytest.mark.parametrize("queue_capacity", [1, 1000])
def test_constructor_accepts_valid_queue_capacity(queue_capacity):
    worker = IPReputationWorker(queue_capacity=queue_capacity)

    status = worker.status()

    assert status["queue_capacity"] == queue_capacity
    assert status["queue_size"] == 0
    assert status["tracked_count"] == 0
    assert status["running"] is False
    assert status["thread_alive"] is False
    assert status["thread_name"] is None


def test_status_before_start_reports_operational_state():
    worker = IPReputationWorker(queue_capacity=7)

    assert worker.status() == {
        "running": False,
        "thread_alive": False,
        "thread_name": None,
        "queue_size": 0,
        "queue_capacity": 7,
        "tracked_count": 0,
    }


def test_status_reports_pending_and_in_flight_counts():
    getter = RecordingGetter()
    getter.blocked_ips.add("8.8.8.8")
    worker = IPReputationWorker(
        queue_capacity=2,
        reputation_getter=getter
    )

    with RunningWorker(worker, getter):
        assert worker.enqueue("8.8.8.8") == ENQUEUE_QUEUED
        assert wait_until(lambda: len(getter.calls) == 1)

        in_flight_status = worker.status()

        assert in_flight_status["queue_size"] == 0
        assert in_flight_status["tracked_count"] == 1
        assert in_flight_status["running"] is True
        assert in_flight_status["thread_alive"] is True
        assert in_flight_status["thread_name"] == (
            "ip-reputation-worker"
        )
        assert in_flight_status["queue_capacity"] == 2

        assert worker.enqueue("1.1.1.1") == ENQUEUE_QUEUED

        combined_status = worker.status()

        assert combined_status["queue_size"] == 1
        assert combined_status["tracked_count"] == 2
        assert combined_status["running"] is True
        assert combined_status["thread_alive"] is True

        getter.release_event.set()

        assert wait_until(lambda: len(getter.calls) == 2)
        assert wait_until(
            lambda: worker.status()["tracked_count"] == 0
        )
        assert worker.status()["queue_size"] == 0


def test_status_reports_thread_alive_but_not_running_during_stop():
    getter = RecordingGetter()
    getter.blocked_ips.add("8.8.8.8")
    worker = IPReputationWorker(reputation_getter=getter)

    worker.start()

    try:
        assert worker.enqueue("8.8.8.8") == ENQUEUE_QUEUED
        assert wait_until(lambda: len(getter.calls) == 1)
        assert worker.stop(timeout=0.05) is False

        status = worker.status()

        assert status["running"] is False
        assert status["thread_alive"] is True
        assert status["thread_name"] == "ip-reputation-worker"
        assert status["queue_size"] == 0
        assert status["tracked_count"] == 0

        getter.release_event.set()

        assert wait_until(
            lambda: worker.status()["thread_alive"] is False
        )
    finally:
        getter.release_event.set()
        worker.stop(timeout=2)


def test_status_after_shutdown_reports_stopped_state():
    worker = IPReputationWorker(queue_capacity=3)

    assert worker.start() is True
    assert worker.stop() is True

    assert worker.status() == {
        "running": False,
        "thread_alive": False,
        "thread_name": None,
        "queue_size": 0,
        "queue_capacity": 3,
        "tracked_count": 0,
    }


def test_status_reads_are_thread_safe_and_consistent():
    getter = RecordingGetter()
    getter.blocked_ips.add("8.8.8.8")
    worker = IPReputationWorker(
        queue_capacity=2,
        reputation_getter=getter
    )

    with RunningWorker(worker, getter):
        assert worker.enqueue("8.8.8.8") == ENQUEUE_QUEUED
        assert wait_until(lambda: len(getter.calls) == 1)
        assert worker.enqueue("1.1.1.1") == ENQUEUE_QUEUED

        reader_count = 8
        barrier = threading.Barrier(reader_count + 1)
        snapshots = []
        errors = []

        def read_status():
            try:
                barrier.wait(timeout=2)
                snapshots.append(worker.status())
            except Exception as error:
                errors.append(error)

        readers = [
            threading.Thread(target=read_status)
            for _ in range(reader_count)
        ]

        for reader in readers:
            reader.start()

        barrier.wait(timeout=2)

        for reader in readers:
            reader.join(timeout=2)

        assert errors == []
        assert len(snapshots) == reader_count

        for snapshot in snapshots:
            assert snapshot["running"] is True
            assert snapshot["thread_alive"] is True
            assert snapshot["thread_name"] == (
                "ip-reputation-worker"
            )
            assert snapshot["queue_size"] == 1
            assert snapshot["queue_capacity"] == 2
            assert snapshot["tracked_count"] == 2

        getter.release_event.set()

        assert wait_until(lambda: len(getter.calls) == 2)
        assert wait_until(
            lambda: worker.status()["tracked_count"] == 0
        )


def test_status_does_not_expose_sensitive_data(monkeypatch):
    secret = "super-secret-api-key"
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", secret)

    getter = RecordingGetter()
    getter.blocked_ips.add("8.8.8.8")
    worker = IPReputationWorker(reputation_getter=getter)

    with RunningWorker(worker, getter):
        assert worker.enqueue("8.8.8.8") == ENQUEUE_QUEUED
        assert wait_until(lambda: len(getter.calls) == 1)

        status = worker.status()
        status_text = f"{status!r} {status!s}"

        assert set(status) == {
            "running",
            "thread_alive",
            "thread_name",
            "queue_size",
            "queue_capacity",
            "tracked_count",
        }
        assert "8.8.8.8" not in status_text
        assert secret not in status_text
        assert "AbuseIPDB" not in status_text


def test_start_starts_single_daemon_worker_thread():
    worker = IPReputationWorker()

    with RunningWorker(worker):
        assert worker.start() is False
        assert wait_until(worker.is_running)

        status = worker.status()

        assert status["running"] is True
        assert status["thread_alive"] is True
        assert status["thread_name"] == "ip-reputation-worker"
        assert worker._thread.daemon is True


def test_worker_can_restart_after_stop():
    getter = RecordingGetter()
    worker = IPReputationWorker(reputation_getter=getter)

    with RunningWorker(worker, getter):
        pass

    with RunningWorker(worker, getter):
        assert worker.enqueue("8.8.8.8") == ENQUEUE_QUEUED
        assert wait_until(lambda: len(getter.calls) == 1)

    assert getter.calls[0][0] == "8.8.8.8"


def test_disabled_enqueue_returns_disabled_without_validating(
    monkeypatch
):
    monkeypatch.setattr(settings, "IP_REPUTATION_ENABLED", False)

    worker = IPReputationWorker()

    assert worker.enqueue("not-an-ip") == ENQUEUE_DISABLED
    assert worker.status()["queue_size"] == 0
    assert worker.status()["tracked_count"] == 0


def test_enqueue_before_start_returns_not_running():
    worker = IPReputationWorker()

    assert worker.enqueue("8.8.8.8") == ENQUEUE_NOT_RUNNING
    assert worker.status()["queue_size"] == 0
    assert worker.status()["tracked_count"] == 0


def test_enqueue_processes_canonical_ipv4():
    getter = RecordingGetter()
    factory = FakeSessionFactory()
    worker = IPReputationWorker(
        session_factory=factory,
        reputation_getter=getter
    )

    with RunningWorker(worker, getter):
        assert worker.enqueue(" 8.8.8.8 ") == ENQUEUE_QUEUED
        assert wait_until(lambda: len(getter.calls) == 1)

        ip_address, session = getter.calls[0]

        assert ip_address == "8.8.8.8"
        assert isinstance(session, FakeSession)
        assert wait_until(lambda: session.closed)
        assert factory.sessions == [session]


def test_enqueue_processes_canonical_ipv6():
    getter = RecordingGetter()
    worker = IPReputationWorker(reputation_getter=getter)

    with RunningWorker(worker, getter):
        assert worker.enqueue(
            "2606:4700:4700:0000:0000:0000:0000:1111"
        ) == ENQUEUE_QUEUED
        assert wait_until(lambda: len(getter.calls) == 1)

    assert getter.calls[0][0] == "2606:4700:4700::1111"


@pytest.mark.parametrize(
    "ip_address",
    [
        "192.168.1.1",
        "10.0.0.1",
        "127.0.0.1",
        "224.0.0.1",
        "0.0.0.0",
        "2001:db8::1",
        "not-an-ip",
        None,
        123,
    ]
)
def test_enqueue_rejects_invalid_or_non_public_ip(ip_address):
    getter = RecordingGetter()
    worker = IPReputationWorker(reputation_getter=getter)

    with RunningWorker(worker, getter):
        with pytest.raises(ValueError):
            worker.enqueue(ip_address)

        assert worker.status()["queue_size"] == 0
        assert worker.status()["tracked_count"] == 0
        assert getter.calls == []


def test_duplicate_in_flight_and_pending_are_suppressed():
    getter = RecordingGetter()
    getter.blocked_ips.add("8.8.8.8")
    worker = IPReputationWorker(reputation_getter=getter)

    with RunningWorker(worker, getter):
        assert worker.enqueue("8.8.8.8") == ENQUEUE_QUEUED
        assert wait_until(lambda: len(getter.calls) == 1)
        assert worker.enqueue("8.8.8.8") == ENQUEUE_DUPLICATE
        assert worker.enqueue("1.1.1.1") == ENQUEUE_QUEUED
        assert worker.enqueue("1.1.1.1") == ENQUEUE_DUPLICATE
        assert worker.status()["tracked_count"] == 2

        getter.release_event.set()

        assert wait_until(lambda: len(getter.calls) == 2)
        assert wait_until(
            lambda: worker.status()["tracked_count"] == 0
        )

    assert [call[0] for call in getter.calls] == [
        "8.8.8.8",
        "1.1.1.1",
    ]


def test_dedup_is_released_after_successful_processing():
    getter = RecordingGetter()
    worker = IPReputationWorker(reputation_getter=getter)

    with RunningWorker(worker, getter):
        assert worker.enqueue("8.8.8.8") == ENQUEUE_QUEUED
        assert wait_until(lambda: len(getter.calls) == 1)
        assert wait_until(
            lambda: worker.status()["tracked_count"] == 0
        )
        assert worker.enqueue("8.8.8.8") == ENQUEUE_QUEUED
        assert wait_until(lambda: len(getter.calls) == 2)


def test_dedup_is_released_after_failed_processing_and_worker_survives():
    getter = RecordingGetter()
    getter.errors["8.8.8.8"] = RuntimeError("processing boom")
    worker = IPReputationWorker(reputation_getter=getter)

    with RunningWorker(worker, getter):
        assert worker.enqueue("8.8.8.8") == ENQUEUE_QUEUED
        assert wait_until(lambda: len(getter.calls) == 1)
        assert wait_until(
            lambda: worker.status()["tracked_count"] == 0
        )
        assert worker.is_running()

        getter.errors.clear()

        assert worker.enqueue("8.8.8.8") == ENQUEUE_QUEUED
        assert wait_until(lambda: len(getter.calls) == 2)
        assert worker.is_running()


def test_queue_full_returns_full_without_tracking_or_blocking():
    getter = RecordingGetter()
    getter.blocked_ips.add("8.8.8.8")
    worker = IPReputationWorker(
        queue_capacity=1,
        reputation_getter=getter
    )

    with RunningWorker(worker, getter):
        assert worker.enqueue("8.8.8.8") == ENQUEUE_QUEUED
        assert wait_until(lambda: len(getter.calls) == 1)
        assert worker.status()["queue_size"] == 0

        assert worker.enqueue("1.1.1.1") == ENQUEUE_QUEUED
        assert worker.status()["queue_size"] == 1
        assert worker.enqueue("9.9.9.9") == ENQUEUE_FULL
        assert worker.status()["tracked_count"] == 2
        assert worker.enqueue("1.1.1.1") == ENQUEUE_DUPLICATE

        getter.release_event.set()

        assert wait_until(lambda: len(getter.calls) == 2)
        assert wait_until(
            lambda: worker.status()["tracked_count"] == 0
        )

    assert [call[0] for call in getter.calls] == [
        "8.8.8.8",
        "1.1.1.1",
    ]


def test_stop_discards_pending_jobs_and_rejects_new_enqueues():
    getter = RecordingGetter()
    getter.blocked_ips.add("8.8.8.8")
    worker = IPReputationWorker(reputation_getter=getter)

    worker.start()

    try:
        assert worker.enqueue("8.8.8.8") == ENQUEUE_QUEUED
        assert wait_until(lambda: len(getter.calls) == 1)
        assert worker.enqueue("1.1.1.1") == ENQUEUE_QUEUED
        assert worker.status()["queue_size"] == 1

        assert worker.stop(timeout=0.05) is False
        assert worker.enqueue("9.9.9.9") == ENQUEUE_NOT_RUNNING
        assert worker.status()["queue_size"] == 0

        getter.release_event.set()

        assert wait_until(
            lambda: worker.status()["thread_alive"] is False
        )
        assert worker.stop(timeout=2) is True
        assert worker.status()["tracked_count"] == 0
        assert worker.status()["running"] is False
        assert [call[0] for call in getter.calls] == ["8.8.8.8"]
    finally:
        getter.release_event.set()
        worker.stop(timeout=2)


def test_stop_before_start_and_repeated_stop_are_safe():
    worker = IPReputationWorker()

    assert worker.stop() is True
    assert worker.stop() is True
    assert worker.start() is True
    assert worker.stop() is True
    assert worker.stop() is True

    status = worker.status()

    assert status["running"] is False
    assert status["thread_alive"] is False
    assert status["thread_name"] is None
    assert status["tracked_count"] == 0


def test_session_is_closed_after_success_and_failure():
    getter = RecordingGetter()
    factory = FakeSessionFactory()
    worker = IPReputationWorker(
        session_factory=factory,
        reputation_getter=getter
    )

    with RunningWorker(worker, getter):
        assert worker.enqueue("8.8.8.8") == ENQUEUE_QUEUED
        assert wait_until(lambda: len(getter.calls) == 1)
        assert wait_until(lambda: factory.sessions[0].closed)

        getter.errors["1.1.1.1"] = RuntimeError("processing boom")

        assert worker.enqueue("1.1.1.1") == ENQUEUE_QUEUED
        assert wait_until(lambda: len(getter.calls) == 2)
        assert wait_until(lambda: factory.sessions[1].closed)
        assert len(factory.sessions) == 2
        assert all(session.closed for session in factory.sessions)
        assert worker.is_running()


def test_session_factory_failure_does_not_kill_worker():
    getter = RecordingGetter()
    factory = FakeSessionFactory()
    factory.error = RuntimeError("session boom")
    worker = IPReputationWorker(
        session_factory=factory,
        reputation_getter=getter
    )

    with RunningWorker(worker, getter):
        assert worker.enqueue("8.8.8.8") == ENQUEUE_QUEUED
        assert wait_until(
            lambda: worker.status()["tracked_count"] == 0
        )
        assert getter.calls == []
        assert worker.is_running()

        factory.error = None

        assert worker.enqueue("1.1.1.1") == ENQUEUE_QUEUED
        assert wait_until(lambda: len(getter.calls) == 1)

    assert getter.calls[0][0] == "1.1.1.1"


def test_process_checks_feature_flag_before_creating_session(
    monkeypatch
):
    getter = RecordingGetter()
    factory = FakeSessionFactory()
    worker = IPReputationWorker(
        session_factory=factory,
        reputation_getter=getter
    )

    monkeypatch.setattr(settings, "IP_REPUTATION_ENABLED", False)

    worker._process("8.8.8.8")

    assert getter.calls == []
    assert factory.sessions == []


def test_processing_error_details_are_not_logged_or_exposed(caplog):
    secret = "super-secret-provider-token"
    getter = RecordingGetter()
    getter.errors["8.8.8.8"] = RuntimeError(secret)
    worker = IPReputationWorker(reputation_getter=getter)

    with caplog.at_level(logging.DEBUG):
        with RunningWorker(worker, getter):
            assert worker.enqueue("8.8.8.8") == ENQUEUE_QUEUED
            assert wait_until(
                lambda: worker.status()["tracked_count"] == 0
            )

    assert secret not in caplog.text
    assert secret not in str(worker.status())
    assert secret not in repr(worker.status())
