from datetime import datetime, timedelta, timezone

import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models.traffic import Traffic
from app.services.detection import detect_port_scan, detect_traffic_spike


# Create an isolated in-memory test database
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


# Helper function to insert test traffic
def add_traffic(db, source_ip, destination_port, seconds_ago=10):

    record = Traffic(
        source_ip=source_ip,
        destination_ip="192.168.1.1",
        protocol="TCP",
        source_port=50000,
        destination_port=destination_port,
        packet_size=1200,
        status="normal",
        timestamp=datetime.now(timezone.utc).replace(tzinfo=None)
        - timedelta(seconds=seconds_ago)
    )

    db.add(record)
    db.commit()


# Test 1: Normal traffic
def test_normal_traffic(db):

    add_traffic(db, "192.168.1.10", 443)

    result = detect_port_scan(db, "192.168.1.10")

    assert result["is_port_scan"] is False
    assert result["severity"] == "LOW"


# Test 2: Rapid port scan
def test_rapid_port_scan(db):

    for port in range(20, 30):
        add_traffic(db, "192.168.1.20", port, seconds_ago=10)

    result = detect_port_scan(db, "192.168.1.20")

    assert result["is_port_scan"] is True
    assert result["scan_type"] == "rapid_port_scan"
    assert result["severity"] == "HIGH"


# Test 3: Slow port scan
def test_slow_port_scan(db):

    add_traffic(db, "192.168.1.30", 20, seconds_ago=100)

    for port in range(21, 30):
        add_traffic(db, "192.168.1.30", port, seconds_ago=10)

    result = detect_port_scan(db, "192.168.1.30")

    assert result["is_port_scan"] is True
    assert result["scan_type"] == "slow_port_scan"
    assert result["severity"] == "MEDIUM"
    assert result["rapid_window_ports"] == 9
    assert result["slow_window_ports"] == 10


# Test 4: Different source IPs
def test_independent_source_ips(db):

    for port in range(20, 29):
        add_traffic(db, "192.168.1.40", port)

    add_traffic(db, "192.168.1.41", 443)

    result = detect_port_scan(db, "192.168.1.41")

    assert result["is_port_scan"] is False
    assert result["unique_ports_detected"] == 1


# Test 5: Repeated attempts to the same port
def test_repeated_same_port(db):

    for _ in range(10):
        add_traffic(db, "192.168.1.50", 443)

    result = detect_port_scan(db, "192.168.1.50")

    assert result["is_port_scan"] is False
    assert result["unique_ports_detected"] == 1
def test_traffic_spike_detected(db):
    for _ in range(100):
        add_traffic(
            db,
            "192.168.1.60",
            443,
            seconds_ago=10
        )

    result = detect_traffic_spike(db, "192.168.1.60")

    assert result["is_traffic_spike"] is True
    assert result["severity"] == "HIGH"
    assert result["packet_count"] == 100


def test_normal_traffic_volume(db):
    for _ in range(99):
        add_traffic(
            db,
            "192.168.1.61",
            443,
            seconds_ago=10
        )

    result = detect_traffic_spike(db, "192.168.1.61")

    assert result["is_traffic_spike"] is False
    assert result["severity"] == "LOW"
    assert result["packet_count"] == 99