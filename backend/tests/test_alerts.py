import logging

import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.core.database import Base
from app.models.alert import Alert
from app.services import alerts as alerts_module
from app.services.ip_reputation_worker import (
    ENQUEUE_DISABLED,
    ENQUEUE_DUPLICATE,
    ENQUEUE_FULL,
    ENQUEUE_NOT_RUNNING,
    ENQUEUE_QUEUED,
    IPReputationWorker,
)


class FakeWorker:
    def __init__(self):
        self.calls = []
        self.status = ENQUEUE_QUEUED
        self.error = None
        self.on_enqueue = None

    def enqueue(self, ip_address):
        if self.on_enqueue is not None:
            self.on_enqueue(ip_address)

        self.calls.append(ip_address)

        if self.error is not None:
            raise self.error

        return self.status


def port_scan_result(source_ip="8.8.8.8", **overrides):
    result = {
        "is_port_scan": True,
        "source_ip": source_ip,
        "scan_type": "rapid_port_scan",
        "severity": "HIGH",
        "unique_ports_detected": 10,
    }

    result.update(overrides)

    return result


def traffic_spike_result(source_ip="8.8.8.8", **overrides):
    result = {
        "is_traffic_spike": True,
        "source_ip": source_ip,
        "event_type": "traffic_spike",
        "severity": "MEDIUM",
        "packet_count": 100,
        "window_seconds": 5,
    }

    result.update(overrides)

    return result


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )

    Base.metadata.create_all(bind=engine)

    TestingSession = sessionmaker(
        bind=engine,
        autoflush=False,
        autocommit=False
    )

    session = TestingSession()

    yield session

    session.close()
    Base.metadata.drop_all(bind=engine)
    engine.dispose()


@pytest.fixture
def worker(monkeypatch):
    fake_worker = FakeWorker()
    monkeypatch.setattr(
        alerts_module,
        "ip_reputation_worker",
        fake_worker
    )

    return fake_worker


@pytest.fixture
def events(monkeypatch):
    captured = []

    def fake_emit_event(event_type, data, **extra):
        captured.append({
            "type": event_type,
            "data": data,
            "extra": extra,
        })

    monkeypatch.setattr(
        alerts_module,
        "emit_event",
        fake_emit_event
    )

    return captured


def test_new_alert_enqueues_source_ip_once(db, worker, events):
    alert = alerts_module.create_security_alert(
        db,
        port_scan_result("8.8.8.8")
    )

    assert alert is not None
    assert alert.source_ip == "8.8.8.8"
    assert worker.calls == ["8.8.8.8"]
    assert len(events) == 1
    assert events[0]["type"] == "alert.created"
    assert events[0]["data"]["source_ip"] == "8.8.8.8"
    assert db.query(Alert).count() == 1


def test_duplicate_alert_does_not_enqueue_again(db, worker, events):
    first_alert = alerts_module.create_security_alert(
        db,
        port_scan_result("8.8.8.8")
    )

    worker.calls.clear()
    events.clear()

    second_alert = alerts_module.create_security_alert(
        db,
        port_scan_result("8.8.8.8")
    )

    assert second_alert.id == first_alert.id
    assert worker.calls == []
    assert events == []
    assert db.query(Alert).count() == 1


def test_resolved_alert_allows_new_alert_and_enqueue(db, worker):
    first_alert = alerts_module.create_security_alert(
        db,
        port_scan_result("8.8.8.8")
    )

    first_alert.status = "RESOLVED"
    db.commit()

    worker.calls.clear()

    second_alert = alerts_module.create_security_alert(
        db,
        port_scan_result("8.8.8.8")
    )

    assert second_alert.id != first_alert.id
    assert worker.calls == ["8.8.8.8"]
    assert db.query(Alert).count() == 2


@pytest.mark.parametrize(
    "enqueue_status",
    [
        ENQUEUE_DISABLED,
        ENQUEUE_FULL,
        ENQUEUE_NOT_RUNNING,
        ENQUEUE_DUPLICATE,
    ]
)
def test_non_queued_status_does_not_break_alert_creation(
    db,
    worker,
    events,
    enqueue_status
):
    worker.status = enqueue_status

    alert = alerts_module.create_security_alert(
        db,
        port_scan_result("8.8.8.8")
    )

    assert alert is not None
    assert worker.calls == ["8.8.8.8"]
    assert len(events) == 1
    assert db.query(Alert).count() == 1


def test_disabled_feature_does_not_break_alert_creation(
    db,
    events,
    monkeypatch
):
    reputation_worker = IPReputationWorker()

    monkeypatch.setattr(
        alerts_module,
        "ip_reputation_worker",
        reputation_worker
    )
    monkeypatch.setattr(
        settings,
        "IP_REPUTATION_ENABLED",
        False
    )

    alert = alerts_module.create_security_alert(
        db,
        port_scan_result("8.8.8.8")
    )

    assert alert is not None
    assert len(events) == 1
    assert db.query(Alert).count() == 1
    assert reputation_worker.status()["queue_size"] == 0


@pytest.mark.parametrize(
    "source_ip",
    [
        "192.168.1.1",
        "10.0.0.1",
        "127.0.0.1",
        "2001:db8::1",
        "not-an-ip",
    ]
)
def test_invalid_or_non_public_ip_does_not_break_alert_creation(
    db,
    events,
    monkeypatch,
    caplog,
    source_ip
):
    reputation_worker = IPReputationWorker()

    monkeypatch.setattr(
        alerts_module,
        "ip_reputation_worker",
        reputation_worker
    )
    monkeypatch.setattr(
        settings,
        "IP_REPUTATION_ENABLED",
        True
    )

    with caplog.at_level(logging.WARNING):
        alert = alerts_module.create_security_alert(
            db,
            port_scan_result(source_ip)
        )

    assert alert is not None
    assert alert.source_ip == source_ip
    assert len(events) == 1
    assert db.query(Alert).count() == 1
    assert reputation_worker.status()["queue_size"] == 0
    assert "Failed to enqueue alert source IP" in caplog.text
    assert source_ip not in caplog.text


def test_enqueue_exception_does_not_break_alert_creation(
    db,
    worker,
    events,
    caplog
):
    secret = "super-secret-provider-token"
    worker.error = RuntimeError(
        f"provider failed with {secret} and raw response"
    )

    with caplog.at_level(logging.WARNING):
        alert = alerts_module.create_security_alert(
            db,
            port_scan_result("8.8.8.8")
        )

    assert alert is not None
    assert worker.calls == ["8.8.8.8"]
    assert len(events) == 1
    assert db.query(Alert).count() == 1
    assert "Failed to enqueue alert source IP" in caplog.text
    assert secret not in caplog.text
    assert "provider failed" not in caplog.text
    assert "raw response" not in caplog.text


def test_enqueue_occurs_after_commit(db, worker, monkeypatch):
    order = []
    original_commit = db.commit

    def tracked_commit():
        original_commit()
        order.append("commit")

    def tracked_enqueue(ip_address):
        order.append("enqueue")

    monkeypatch.setattr(db, "commit", tracked_commit)
    worker.on_enqueue = tracked_enqueue

    alert = alerts_module.create_security_alert(
        db,
        port_scan_result("8.8.8.8")
    )

    assert alert is not None
    assert order == ["commit", "enqueue"]


def test_commit_failure_prevents_enqueue(
    db,
    worker,
    events,
    monkeypatch
):
    def failing_commit():
        raise RuntimeError("commit failed")

    monkeypatch.setattr(db, "commit", failing_commit)

    with pytest.raises(RuntimeError, match="commit failed"):
        alerts_module.create_security_alert(
            db,
            port_scan_result("8.8.8.8")
        )

    assert worker.calls == []
    assert events == []

    db.rollback()

    assert db.query(Alert).count() == 0


def test_existing_port_scan_alert_behavior_is_preserved(
    db,
    worker,
    events
):
    alert = alerts_module.create_security_alert(
        db,
        port_scan_result("8.8.8.8")
    )

    assert alert.status == "NEW"
    assert alert.severity == "HIGH"
    assert alert.alert_type == "rapid_port_scan"
    assert alert.description == (
        "Rapid Port Scan detected from 8.8.8.8. "
        "10 unique destination ports were accessed."
    )
    assert alert.timestamp is not None
    assert worker.calls == ["8.8.8.8"]

    event = events[0]

    assert event["type"] == "alert.created"
    assert event["extra"] == {}
    assert event["data"]["id"] == alert.id
    assert event["data"]["source_ip"] == "8.8.8.8"
    assert event["data"]["alert_type"] == "rapid_port_scan"
    assert event["data"]["severity"] == "HIGH"
    assert event["data"]["status"] == "NEW"
    assert event["data"]["description"] == alert.description
    assert event["data"]["timestamp"].endswith("Z")


def test_existing_traffic_spike_alert_behavior_is_preserved(
    db,
    worker,
    events
):
    alert = alerts_module.create_security_alert(
        db,
        traffic_spike_result("8.8.8.8")
    )

    assert alert.status == "NEW"
    assert alert.severity == "MEDIUM"
    assert alert.alert_type == "traffic_spike"
    assert alert.description == (
        "Traffic spike detected from 8.8.8.8. "
        "100 packets received within 5 seconds."
    )
    assert worker.calls == ["8.8.8.8"]
    assert len(events) == 1


def test_no_detection_does_not_create_alert_or_enqueue(
    db,
    worker,
    events
):
    result = alerts_module.create_security_alert(
        db,
        {
            "is_port_scan": False,
            "is_traffic_spike": False,
        }
    )

    assert result is None
    assert worker.calls == []
    assert events == []
    assert db.query(Alert).count() == 0


def test_alert_service_uses_shared_worker_singleton():
    from app.main import ip_reputation_worker as app_worker
    from app.services.ip_reputation_runtime import (
        ip_reputation_worker as runtime_worker,
    )

    assert alerts_module.ip_reputation_worker is runtime_worker
    assert app_worker is runtime_worker
