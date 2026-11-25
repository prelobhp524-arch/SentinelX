import logging

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.services.ip_reputation_runtime import ip_reputation_worker
from app.services.ip_reputation_worker import (
    ENQUEUE_FULL,
    ENQUEUE_NOT_RUNNING,
)
from app.services.websocket_events import emit_event, serialize_alert


logger = logging.getLogger(__name__)


def enqueue_alert_source_ip(source_ip):
    try:
        status = ip_reputation_worker.enqueue(source_ip)
    except Exception:
        logger.warning(
            "Failed to enqueue alert source IP for reputation check"
        )
        return

    if status in (ENQUEUE_FULL, ENQUEUE_NOT_RUNNING):
        logger.warning(
            "IP reputation enqueue skipped for alert source IP: %s",
            status
        )


def create_security_alert(db: Session, detection_result: dict):

    # Check whether a threat was detected
    if not (
        detection_result.get("is_port_scan")
        or detection_result.get("is_traffic_spike")
    ):
        return None

    source_ip = detection_result["source_ip"]

    # Identify the attack type
    alert_type = (
        detection_result.get("scan_type")
        or detection_result.get("event_type")
    )

    severity = detection_result["severity"]

    # Prevent duplicate active alerts
    existing_alert = db.query(Alert).filter(
        Alert.source_ip == source_ip,
        Alert.alert_type == alert_type,
        Alert.status.in_(["NEW", "ACKNOWLEDGED"])
    ).first()

    if existing_alert:
        return existing_alert

    # Prepare attack description
    if detection_result.get("is_port_scan"):
        description = (
            f"{alert_type.replace('_', ' ').title()} detected from "
            f"{source_ip}. "
            f"{detection_result['unique_ports_detected']} unique "
            f"destination ports were accessed."
        )

    else:
        description = (
            f"Traffic spike detected from {source_ip}. "
            f"{detection_result['packet_count']} packets received "
            f"within {detection_result['window_seconds']} seconds."
        )

    # Create security alert
    alert = Alert(
        source_ip=source_ip,
        alert_type=alert_type,
        severity=severity,
        description=description,
        status="NEW"
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    emit_event(
        "alert.created",
        serialize_alert(alert)
    )

    enqueue_alert_source_ip(alert.source_ip)

    return alert
