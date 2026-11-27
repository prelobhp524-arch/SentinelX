"""Idempotent generation of simulated dashboard data.

The seed command is intentionally separate from application startup. It uses
the existing Traffic and Alert models so analytics queries keep working without
schema changes to the dashboard-facing tables. A dedicated demo_seed_runs table
records completed seed runs so repeated invocations cannot insert duplicates.
"""

import random

from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.demo_seed import DemoSeedRun
from app.models.traffic import Traffic


DEMO_SEED_KEY = "sentinelx-public-demo-v1"
DEMO_DATASET_VERSION = "1"
DEMO_DESCRIPTION_PREFIX = "[SIMULATED]"
DEMO_PERIOD_DAYS = 7
DEMO_MIN_AGE_SECONDS = 5 * 60

NORMAL_TRAFFIC_COUNT = 140

PRIVATE_SOURCE_IPS = [
    "10.0.12.15",
    "10.0.24.8",
    "10.20.30.40",
    "172.16.4.5",
    "172.16.8.20",
    "192.168.0.50",
    "192.168.1.10",
    "192.168.1.25",
    "192.168.10.33",
]

PUBLIC_SOURCE_IPS = [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "151.101.1.69",
    "104.16.132.229",
]

PUBLIC_DESTINATIONS = [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "151.101.1.69",
    "104.16.132.229",
]

LOCAL_SERVERS = [
    "10.0.0.5",
    "10.0.0.10",
    "192.168.1.1",
    "172.16.0.10",
]

TCP_DESTINATION_PORTS = [
    22, 25, 53, 80, 110, 143, 443, 445, 993, 3306, 3389, 5432, 8080, 8443
]

UDP_DESTINATION_PORTS = [53, 67, 123, 161, 443, 5353]

EPHEMERAL_PORT_RANGE = (32768, 65535)


def utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _random_age(rng: random.Random) -> timedelta:
    max_age_seconds = DEMO_PERIOD_DAYS * 24 * 60 * 60

    return timedelta(
        seconds=rng.uniform(
            DEMO_MIN_AGE_SECONDS,
            max_age_seconds
        )
    )


def _normal_traffic_record(rng: random.Random, anchor_at: datetime) -> Traffic:
    protocol = rng.choices(
        ["TCP", "UDP", "ICMP", "47"],
        weights=[65, 20, 10, 5],
        k=1
    )[0]

    direction = rng.choices(
        ["OUTBOUND", "INBOUND", "UNKNOWN"],
        weights=[45, 35, 20],
        k=1
    )[0]

    source_port = None
    destination_port = None

    if direction == "OUTBOUND":
        source_ip = rng.choice(PRIVATE_SOURCE_IPS)
        destination_ip = rng.choice(PUBLIC_DESTINATIONS)
    elif direction == "INBOUND":
        source_ip = rng.choice(PUBLIC_SOURCE_IPS)
        destination_ip = rng.choice(LOCAL_SERVERS)
    else:
        source_ip = rng.choice(PRIVATE_SOURCE_IPS)
        destination_ip = rng.choice(LOCAL_SERVERS + PRIVATE_SOURCE_IPS)

    if protocol == "TCP":
        source_port = rng.randint(*EPHEMERAL_PORT_RANGE)
        destination_port = rng.choice(TCP_DESTINATION_PORTS)
        packet_size = rng.randint(64, 1500)
    elif protocol == "UDP":
        source_port = rng.randint(*EPHEMERAL_PORT_RANGE)
        destination_port = rng.choice(UDP_DESTINATION_PORTS)
        packet_size = rng.randint(64, 1472)
    elif protocol == "ICMP":
        packet_size = rng.randint(64, 1200)
    else:
        packet_size = rng.randint(64, 1400)

    return Traffic(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
        packet_size=packet_size,
        timestamp=anchor_at - _random_age(rng),
        status="normal",
        direction=direction
    )


def _traffic(
    source_ip,
    destination_ip,
    protocol,
    source_port,
    destination_port,
    packet_size,
    timestamp,
    status,
    direction
) -> Traffic:
    return Traffic(
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
        packet_size=packet_size,
        timestamp=timestamp,
        status=status,
        direction=direction
    )


def _alert(
    source_ip,
    alert_type,
    severity,
    description,
    timestamp,
    status
) -> Alert:
    return Alert(
        source_ip=source_ip,
        alert_type=alert_type,
        severity=severity,
        description=f"{DEMO_DESCRIPTION_PREFIX} {description}",
        timestamp=timestamp,
        status=status
    )


def build_demo_dataset(anchor_at: datetime):
    rng = random.Random(DEMO_SEED_KEY)

    traffic = [
        _normal_traffic_record(rng, anchor_at)
        for _ in range(NORMAL_TRAFFIC_COUNT)
    ]

    alerts = []

    # Rapid port scan: 12 unique destination ports inside 60 seconds.
    rapid_scan_start = anchor_at - timedelta(hours=2)
    rapid_scan_ports = [20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445]

    for index, destination_port in enumerate(rapid_scan_ports):
        traffic.append(
            _traffic(
                source_ip="198.51.100.23",
                destination_ip="10.0.0.5",
                protocol="TCP",
                source_port=rng.randint(*EPHEMERAL_PORT_RANGE),
                destination_port=destination_port,
                packet_size=rng.randint(40, 80),
                timestamp=rapid_scan_start + timedelta(seconds=index * 4),
                status="suspicious",
                direction="INBOUND"
            )
        )

    alerts.append(
        _alert(
            source_ip="198.51.100.23",
            alert_type="rapid_port_scan",
            severity="HIGH",
            description=(
                "Rapid port scan detected from 198.51.100.23. "
                "12 unique destination ports were accessed within "
                "60 seconds."
            ),
            timestamp=rapid_scan_start + timedelta(minutes=1),
            status="NEW"
        )
    )

    # Slow port scan: 10 unique destination ports across roughly 90 seconds.
    slow_scan_start = anchor_at - timedelta(days=3)
    slow_scan_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 8080]

    for index, destination_port in enumerate(slow_scan_ports):
        traffic.append(
            _traffic(
                source_ip="203.0.113.45",
                destination_ip="192.168.1.1",
                protocol="TCP",
                source_port=rng.randint(*EPHEMERAL_PORT_RANGE),
                destination_port=destination_port,
                packet_size=rng.randint(40, 90),
                timestamp=slow_scan_start + timedelta(seconds=index * 10),
                status="suspicious",
                direction="INBOUND"
            )
        )

    alerts.append(
        _alert(
            source_ip="203.0.113.45",
            alert_type="slow_port_scan",
            severity="MEDIUM",
            description=(
                "Slow port scan detected from 203.0.113.45. "
                "10 unique destination ports were accessed within "
                "120 seconds."
            ),
            timestamp=slow_scan_start + timedelta(minutes=2),
            status="ACKNOWLEDGED"
        )
    )

    # Traffic spike: 105 packets from one source inside 60 seconds.
    spike_start = anchor_at - timedelta(hours=5)

    for index in range(105):
        traffic.append(
            _traffic(
                source_ip="203.0.113.199",
                destination_ip="10.0.0.5",
                protocol="TCP",
                source_port=rng.randint(*EPHEMERAL_PORT_RANGE),
                destination_port=443,
                packet_size=rng.randint(500, 1500),
                timestamp=spike_start + timedelta(seconds=index * 0.5),
                status="suspicious",
                direction="INBOUND"
            )
        )

    alerts.append(
        _alert(
            source_ip="203.0.113.199",
            alert_type="traffic_spike",
            severity="HIGH",
            description=(
                "Traffic spike detected from 203.0.113.199. "
                "105 packets were received within 60 seconds."
            ),
            timestamp=spike_start + timedelta(minutes=1),
            status="NEW"
        )
    )

    # Suspicious outbound connections from an internal host.
    outbound_start = anchor_at - timedelta(hours=6)
    outbound_destinations = [
        ("198.51.100.66", 4444),
        ("203.0.113.88", 8443),
        ("198.51.100.90", 9001),
        ("203.0.113.120", 4444),
        ("198.51.100.66", 9001),
        ("203.0.113.88", 4444),
    ]

    for index, (destination_ip, destination_port) in enumerate(
        outbound_destinations
    ):
        traffic.append(
            _traffic(
                source_ip="192.168.1.25",
                destination_ip=destination_ip,
                protocol="TCP",
                source_port=rng.randint(*EPHEMERAL_PORT_RANGE),
                destination_port=destination_port,
                packet_size=rng.randint(80, 600),
                timestamp=outbound_start + timedelta(seconds=index * 30),
                status="suspicious",
                direction="OUTBOUND"
            )
        )

    alerts.append(
        _alert(
            source_ip="192.168.1.25",
            alert_type="suspicious_outbound",
            severity="CRITICAL",
            description=(
                "Repeated outbound connections to uncommon destination "
                "ports were detected from 192.168.1.25."
            ),
            timestamp=outbound_start + timedelta(minutes=4),
            status="NEW"
        )
    )

    # ICMP flood: 25 echo requests inside 50 seconds.
    icmp_start = anchor_at - timedelta(days=1)

    for index in range(25):
        traffic.append(
            _traffic(
                source_ip="198.51.100.77",
                destination_ip="10.0.0.10",
                protocol="ICMP",
                source_port=None,
                destination_port=None,
                packet_size=rng.randint(64, 512),
                timestamp=icmp_start + timedelta(seconds=index * 2),
                status="suspicious",
                direction="INBOUND"
            )
        )

    alerts.append(
        _alert(
            source_ip="198.51.100.77",
            alert_type="icmp_flood",
            severity="MEDIUM",
            description=(
                "ICMP flood detected from 198.51.100.77. "
                "25 echo requests were received within 50 seconds."
            ),
            timestamp=icmp_start + timedelta(minutes=1),
            status="RESOLVED"
        )
    )

    # Repeated SSH authentication attempts behind the brute-force alert.
    brute_force_start = anchor_at - timedelta(days=4)

    for index in range(8):
        traffic.append(
            _traffic(
                source_ip="198.51.100.200",
                destination_ip="10.0.0.5",
                protocol="TCP",
                source_port=rng.randint(*EPHEMERAL_PORT_RANGE),
                destination_port=22,
                packet_size=rng.randint(60, 120),
                timestamp=brute_force_start + timedelta(seconds=index * 15),
                status="suspicious",
                direction="INBOUND"
            )
        )

    # Port scan behind the historical port_scan alert.
    historical_scan_start = anchor_at - timedelta(days=6)
    historical_scan_ports = [21, 22, 23, 25, 80, 110, 139, 443, 445, 8080]

    for index, destination_port in enumerate(historical_scan_ports):
        traffic.append(
            _traffic(
                source_ip="192.0.2.77",
                destination_ip="192.168.1.1",
                protocol="TCP",
                source_port=rng.randint(*EPHEMERAL_PORT_RANGE),
                destination_port=destination_port,
                packet_size=rng.randint(40, 90),
                timestamp=(
                    historical_scan_start + timedelta(seconds=index * 5)
                ),
                status="suspicious",
                direction="INBOUND"
            )
        )

    alerts.extend(
        [
            _alert(
                source_ip="10.0.12.15",
                alert_type="malware_beacon",
                severity="CRITICAL",
                description=(
                    "Periodic beaconing to an external command-and-control "
                    "endpoint was detected from 10.0.12.15."
                ),
                timestamp=anchor_at - timedelta(days=2),
                status="ACKNOWLEDGED"
            ),
            _alert(
                source_ip="198.51.100.200",
                alert_type="brute_force_attempt",
                severity="HIGH",
                description=(
                    "Multiple failed SSH authentication attempts were "
                    "detected from 198.51.100.200."
                ),
                timestamp=anchor_at - timedelta(days=4),
                status="RESOLVED"
            ),
            _alert(
                source_ip="192.168.10.33",
                alert_type="policy_violation",
                severity="LOW",
                description=(
                    "A host used an unapproved application protocol. "
                    "Source host: 192.168.10.33."
                ),
                timestamp=anchor_at - timedelta(days=5),
                status="RESOLVED"
            ),
            _alert(
                source_ip="203.0.113.45",
                alert_type="tls_certificate_anomaly",
                severity="LOW",
                description=(
                    "A TLS certificate with an unexpected issuer was "
                    "observed from 203.0.113.45."
                ),
                timestamp=anchor_at - timedelta(days=1),
                status="ACKNOWLEDGED"
            ),
            _alert(
                source_ip="10.0.24.8",
                alert_type="dns_tunneling",
                severity="CRITICAL",
                description=(
                    "High-volume encoded DNS queries consistent with "
                    "tunneling were detected from 10.0.24.8."
                ),
                timestamp=anchor_at - timedelta(hours=8),
                status="NEW"
            ),
            _alert(
                source_ip="172.16.4.5",
                alert_type="lateral_movement",
                severity="HIGH",
                description=(
                    "Sequential internal connection attempts were detected "
                    "from 172.16.4.5."
                ),
                timestamp=anchor_at - timedelta(days=2, hours=12),
                status="ACKNOWLEDGED"
            ),
            _alert(
                source_ip="192.0.2.77",
                alert_type="port_scan",
                severity="MEDIUM",
                description=(
                    "A port scan was detected from 192.0.2.77 against a "
                    "local service."
                ),
                timestamp=anchor_at - timedelta(days=6),
                status="RESOLVED"
            ),
            _alert(
                source_ip="198.51.100.23",
                alert_type="repeated_auth_failure",
                severity="LOW",
                description=(
                    "Repeated authentication failures were detected from "
                    "198.51.100.23."
                ),
                timestamp=anchor_at - timedelta(hours=3),
                status="NEW"
            ),
            _alert(
                source_ip="10.20.30.40",
                alert_type="data_exfiltration",
                severity="CRITICAL",
                description=(
                    "Anomalous outbound transfer volume was detected from "
                    "10.20.30.40."
                ),
                timestamp=anchor_at - timedelta(days=5, hours=12),
                status="RESOLVED"
            ),
            _alert(
                source_ip="203.0.113.199",
                alert_type="traffic_spike",
                severity="HIGH",
                description=(
                    "A previous traffic spike from 203.0.113.199 was "
                    "reviewed and resolved."
                ),
                timestamp=anchor_at - timedelta(hours=5, minutes=30),
                status="RESOLVED"
            ),
            _alert(
                source_ip="10.0.24.8",
                alert_type="suspicious_dns_query",
                severity="LOW",
                description=(
                    "A suspicious DNS query pattern was observed from "
                    "10.0.24.8."
                ),
                timestamp=anchor_at - timedelta(hours=4),
                status="ACKNOWLEDGED"
            ),
        ]
    )

    return traffic, alerts


def _seed_result(
    seeded,
    reason,
    seed_key,
    dataset_version,
    traffic_created,
    alert_created,
    traffic_total,
    alert_total,
    marker=None
):
    return {
        "seeded": seeded,
        "reason": reason,
        "seed_key": seed_key,
        "dataset_version": dataset_version,
        "traffic_created": traffic_created,
        "alerts_created": alert_created,
        "traffic_total": traffic_total,
        "alerts_total": alert_total,
        "anchor_at": marker.anchor_at if marker is not None else None,
    }


def seed_demo_data(
    db: Session,
    *,
    seed_key: str = DEMO_SEED_KEY,
    dataset_version: str = DEMO_DATASET_VERSION,
    now: datetime | None = None
):
    existing = db.query(DemoSeedRun).filter(
        DemoSeedRun.seed_key == seed_key
    ).first()

    if existing is not None:
        return _seed_result(
            seeded=False,
            reason="already_seeded",
            seed_key=seed_key,
            dataset_version=existing.dataset_version,
            traffic_created=0,
            alert_created=0,
            traffic_total=db.query(Traffic).count(),
            alert_total=db.query(Alert).count(),
            marker=existing
        )

    anchor_at = now or utcnow_naive()

    traffic_records, alert_records = build_demo_dataset(anchor_at)

    marker = DemoSeedRun(
        seed_key=seed_key,
        dataset_version=dataset_version,
        anchor_at=anchor_at,
        traffic_count=len(traffic_records),
        alert_count=len(alert_records)
    )

    try:
        db.add_all(traffic_records)
        db.add_all(alert_records)
        db.add(marker)
        db.commit()
    except IntegrityError:
        db.rollback()

        existing = db.query(DemoSeedRun).filter(
            DemoSeedRun.seed_key == seed_key
        ).first()

        return _seed_result(
            seeded=False,
            reason="already_seeded",
            seed_key=seed_key,
            dataset_version=(
                existing.dataset_version
                if existing is not None
                else dataset_version
            ),
            traffic_created=0,
            alert_created=0,
            traffic_total=db.query(Traffic).count(),
            alert_total=db.query(Alert).count(),
            marker=existing
        )
    except Exception:
        db.rollback()
        raise

    return _seed_result(
        seeded=True,
        reason="created",
        seed_key=seed_key,
        dataset_version=dataset_version,
        traffic_created=len(traffic_records),
        alert_created=len(alert_records),
        traffic_total=db.query(Traffic).count(),
        alert_total=db.query(Alert).count(),
        marker=marker
    )
