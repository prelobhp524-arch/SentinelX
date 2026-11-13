from sqlalchemy.orm import Session

from app.models.alert import Alert


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

    return alert