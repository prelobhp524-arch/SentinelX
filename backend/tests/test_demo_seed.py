from datetime import datetime, timedelta, timezone

import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.analytics import (
    get_alerts_by_severity,
    get_analytics_summary,
    get_top_source_ips,
    get_traffic_by_protocol,
)
from app.core.database import Base
from app.models.alert import Alert
from app.models.demo_seed import DemoSeedRun
from app.models.traffic import Traffic
from app.services.demo_seed import (
    DEMO_DESCRIPTION_PREFIX,
    DEMO_PERIOD_DAYS,
    seed_demo_data,
)


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


def utc_naive(year, month, day, hour=12, minute=0):
    return datetime(
        year,
        month,
        day,
        hour,
        minute,
        tzinfo=timezone.utc
    ).replace(tzinfo=None)


def test_seed_creates_realistic_dashboard_data(db):
    anchor = utc_naive(2026, 11, 20)

    result = seed_demo_data(db, now=anchor)

    assert result["seeded"] is True
    assert result["reason"] == "created"
    assert result["traffic_created"] > 100
    assert result["alerts_created"] >= 10
    assert result["traffic_total"] == result["traffic_created"]
    assert result["alerts_total"] == result["alerts_created"]

    traffic = db.query(Traffic).all()
    alerts = db.query(Alert).all()

    assert {record.protocol for record in traffic} >= {
        "TCP",
        "UDP",
        "ICMP",
    }
    assert {record.status for record in traffic} == {
        "normal",
        "suspicious",
    }
    assert {record.direction for record in traffic} == {
        "INBOUND",
        "OUTBOUND",
        "UNKNOWN",
    }

    assert {alert.severity for alert in alerts} == {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }
    assert {alert.status for alert in alerts} == {
        "NEW",
        "ACKNOWLEDGED",
        "RESOLVED",
    }
    assert all(
        alert.description.startswith(DEMO_DESCRIPTION_PREFIX)
        for alert in alerts
    )

    oldest_allowed = anchor - timedelta(days=DEMO_PERIOD_DAYS)

    assert all(
        oldest_allowed <= record.timestamp <= anchor
        for record in traffic
    )
    assert all(
        oldest_allowed <= alert.timestamp <= anchor
        for alert in alerts
    )

    assert any(
        record.source_ip.startswith(("10.", "172.", "192.168."))
        for record in traffic
    )
    assert any(
        record.source_ip.startswith(("198.51.100.", "203.0.113."))
        for record in traffic
    )


def test_repeated_seed_is_idempotent(db):
    first = seed_demo_data(db)

    traffic_count = db.query(Traffic).count()
    alert_count = db.query(Alert).count()

    second = seed_demo_data(db)

    assert first["seeded"] is True
    assert second["seeded"] is False
    assert second["reason"] == "already_seeded"
    assert second["traffic_created"] == 0
    assert second["alerts_created"] == 0
    assert db.query(Traffic).count() == traffic_count
    assert db.query(Alert).count() == alert_count
    assert db.query(DemoSeedRun).count() == 1


def test_seed_preserves_existing_records(db):
    existing_traffic = Traffic(
        source_ip="10.99.99.99",
        destination_ip="10.0.0.5",
        protocol="TCP",
        source_port=51000,
        destination_port=443,
        packet_size=777,
        timestamp=utc_naive(2026, 11, 1),
        status="normal",
        direction="OUTBOUND",
    )
    existing_alert = Alert(
        source_ip="203.0.113.250",
        alert_type="existing_real_alert",
        severity="LOW",
        description="Existing record that must not be modified.",
        timestamp=utc_naive(2026, 11, 1),
        status="ACKNOWLEDGED",
    )

    db.add_all([existing_traffic, existing_alert])
    db.commit()

    traffic_id = existing_traffic.id
    alert_id = existing_alert.id

    result = seed_demo_data(db)

    assert result["seeded"] is True

    preserved_traffic = db.get(Traffic, traffic_id)
    preserved_alert = db.get(Alert, alert_id)

    assert preserved_traffic is not None
    assert preserved_traffic.source_ip == "10.99.99.99"
    assert preserved_traffic.packet_size == 777
    assert preserved_traffic.status == "normal"

    assert preserved_alert is not None
    assert preserved_alert.alert_type == "existing_real_alert"
    assert preserved_alert.description == (
        "Existing record that must not be modified."
    )
    assert preserved_alert.status == "ACKNOWLEDGED"

    assert db.query(Traffic).count() == result["traffic_total"]
    assert db.query(Alert).count() == result["alerts_total"]


def test_analytics_endpoints_use_seeded_records(db):
    seed_demo_data(db)

    summary = get_analytics_summary(db)

    assert summary["total_traffic"] == db.query(Traffic).count()
    assert summary["total_alerts"] == db.query(Alert).count()
    assert (
        summary["normal_traffic"] + summary["suspicious_traffic"]
        == summary["total_traffic"]
    )
    assert (
        summary["new_alerts"]
        + summary["acknowledged_alerts"]
        + summary["resolved_alerts"]
        == summary["total_alerts"]
    )

    protocol_data = get_traffic_by_protocol(db)

    assert sum(row["total"] for row in protocol_data) == (
        summary["total_traffic"]
    )
    assert {row["protocol"] for row in protocol_data} >= {
        "TCP",
        "UDP",
        "ICMP",
    }

    severity_data = get_alerts_by_severity(db)

    assert sum(row["total"] for row in severity_data) == (
        summary["total_alerts"]
    )
    assert {row["severity"] for row in severity_data} == {
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    }

    top_ips = get_top_source_ips(limit=5, db=db)

    assert len(top_ips) == 5
    assert all(row["total_traffic"] > 0 for row in top_ips)
    assert any(row["suspicious_traffic"] > 0 for row in top_ips)


def test_seed_marker_records_dataset_metadata(db):
    anchor = utc_naive(2026, 11, 20, 8, 30)

    result = seed_demo_data(db, now=anchor)

    marker = db.query(DemoSeedRun).one()

    assert marker.seed_key == result["seed_key"]
    assert marker.dataset_version == result["dataset_version"]
    assert marker.anchor_at == anchor
    assert marker.traffic_count == result["traffic_created"]
    assert marker.alert_count == result["alerts_created"]


def test_cli_refuses_non_sqlite_target_without_confirmation(
    monkeypatch,
    capsys
):
    from app import seed_demo

    secret = "postgres-secret-password"

    monkeypatch.setattr(
        seed_demo,
        "initialization_database_url",
        lambda: f"postgresql://user:{secret}@example.test/sentinelx"
    )

    exit_code = seed_demo.main([])

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "--yes" in captured.out
    assert secret not in captured.out
    assert secret not in captured.err
