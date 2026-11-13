from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.models.traffic import Traffic
from app.models.alert import Alert

from app.services.detection import (
    detect_port_scan,
    detect_traffic_spike
)

from app.services.alerts import create_security_alert
from app.services.websocket_events import emit_event, serialize_traffic


router = APIRouter(
    prefix="/api/traffic",
    tags=["Network Traffic"]
)


class TrafficCreate(BaseModel):
    source_ip: str
    destination_ip: str
    protocol: str
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    packet_size: int = Field(gt=0)
    status: str = "normal"


@router.post("/")
def create_traffic(
    traffic: TrafficCreate,
    db: Session = Depends(get_db)
):
    # Save incoming traffic
    new_traffic = Traffic(**traffic.model_dump())

    db.add(new_traffic)
    db.commit()
    db.refresh(new_traffic)

    source_ip = new_traffic.source_ip

    # Run detection engines
    port_scan_result = detect_port_scan(db, source_ip)
    traffic_spike_result = detect_traffic_spike(db, source_ip)

    alerts = []

    # Port scan detection
    if port_scan_result["is_port_scan"]:
        new_traffic.status = "suspicious"

        alert = create_security_alert(db, port_scan_result)

        if alert:
            alerts.append(alert)

    # Traffic spike detection
    if traffic_spike_result["is_traffic_spike"]:
        new_traffic.status = "suspicious"

        alert = create_security_alert(db, traffic_spike_result)

        if alert:
            alerts.append(alert)

    # Update traffic record
    db.commit()
    db.refresh(new_traffic)

    emit_event(
        "traffic.created",
        serialize_traffic(new_traffic)
    )

    # Convert alerts into dictionaries
    alert_data = []

    for alert in alerts:
        alert_data.append({
            "id": alert.id,
            "source_ip": alert.source_ip,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "description": alert.description,
            "timestamp": alert.timestamp,
            "status": alert.status
        })

    return {
        "message": "Traffic analysed and saved successfully",
        "data": new_traffic,
        "detections": {
            "port_scan": port_scan_result,
            "traffic_spike": traffic_spike_result
        },
        "alerts": alert_data
    }


@router.get("/")
def get_all_traffic(db: Session = Depends(get_db)):
    return db.query(Traffic).order_by(
        Traffic.id.desc()
    ).all()


@router.get("/{traffic_id}")
def get_traffic(
    traffic_id: int,
    db: Session = Depends(get_db)
):
    traffic = db.query(Traffic).filter(
        Traffic.id == traffic_id
    ).first()

    if not traffic:
        raise HTTPException(
            status_code=404,
            detail="Traffic record not found"
        )

    return traffic