from datetime import datetime, timezone, timedelta

from sqlalchemy.orm import Session

from app.models.traffic import Traffic


# Detection configuration
PORT_SCAN_THRESHOLD = 10

RAPID_SCAN_WINDOW = 60
SLOW_SCAN_WINDOW = 120
TRAFFIC_SPIKE_THRESHOLD = 100
TRAFFIC_SPIKE_WINDOW = 60

def detect_port_scan(db: Session, source_ip: str):

    # Current time
    current_time = datetime.now(timezone.utc).replace(tzinfo=None)

    # Calculate time windows
    rapid_window_start = current_time - timedelta(
        seconds=RAPID_SCAN_WINDOW
    )

    slow_window_start = current_time - timedelta(
        seconds=SLOW_SCAN_WINDOW
    )

    # Retrieve traffic from the last 120 seconds
    recent_traffic = db.query(Traffic).filter(
        Traffic.source_ip == source_ip,
        Traffic.timestamp >= slow_window_start,
        Traffic.destination_port.isnot(None)
    ).all()

    # Count unique destination ports in each window
    rapid_ports = {
        record.destination_port
        for record in recent_traffic
        if record.timestamp >= rapid_window_start
    }

    slow_ports = {
        record.destination_port
        for record in recent_traffic
    }

    # Default classification
    scan_detected = False
    scan_type = "normal"
    severity = "LOW"
    detected_ports = slow_ports

    # Check rapid scanning first
    if len(rapid_ports) >= PORT_SCAN_THRESHOLD:

        scan_detected = True
        scan_type = "rapid_port_scan"
        severity = "HIGH"
        detected_ports = rapid_ports

    # Check slow scanning
    elif len(slow_ports) >= PORT_SCAN_THRESHOLD:

        scan_detected = True
        scan_type = "slow_port_scan"
        severity = "MEDIUM"
        detected_ports = slow_ports

    return {
        "is_port_scan": scan_detected,
        "scan_type": scan_type,
        "severity": severity,
        "source_ip": source_ip,
        "unique_ports_detected": len(detected_ports),
        "rapid_window_ports": len(rapid_ports),
        "slow_window_ports": len(slow_ports),
        "threshold": PORT_SCAN_THRESHOLD,
        "rapid_window_seconds": RAPID_SCAN_WINDOW,
        "slow_window_seconds": SLOW_SCAN_WINDOW,
        "detected_ports": sorted(detected_ports)
    }
def detect_traffic_spike(db: Session, source_ip: str):
    current_time = datetime.now(timezone.utc).replace(tzinfo=None)

    window_start = current_time - timedelta(
        seconds=TRAFFIC_SPIKE_WINDOW
    )

    recent_traffic = db.query(Traffic).filter(
        Traffic.source_ip == source_ip,
        Traffic.timestamp >= window_start
    )

    packet_count = recent_traffic.count()

    spike_detected = packet_count >= TRAFFIC_SPIKE_THRESHOLD

    return {
        "is_traffic_spike": spike_detected,
        "event_type": "traffic_spike" if spike_detected else "normal",
        "severity": "HIGH" if spike_detected else "LOW",
        "source_ip": source_ip,
        "packet_count": packet_count,
        "threshold": TRAFFIC_SPIKE_THRESHOLD,
        "window_seconds": TRAFFIC_SPIKE_WINDOW
    }