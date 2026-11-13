from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.core.database import get_db
from app.models.alert import Alert
from app.services.websocket_events import emit_event, serialize_alert


router = APIRouter(prefix="/api/alerts", tags=["Security Alerts"])


class AlertStatusUpdate(BaseModel):
    status: str


@router.get("/")
def get_all_alerts(db: Session = Depends(get_db)):
    return db.query(Alert).order_by(Alert.id.desc()).all()


@router.get("/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Security alert not found"
        )

    return alert


@router.patch("/{alert_id}/status")
def update_alert_status(
    alert_id: int,
    update: AlertStatusUpdate,
    db: Session = Depends(get_db)
):
    allowed_statuses = ["NEW", "ACKNOWLEDGED", "RESOLVED"]

    if update.status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Choose from: {allowed_statuses}"
        )

    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Security alert not found"
        )

    previous_status = alert.status

    alert.status = update.status

    db.commit()
    db.refresh(alert)

    if previous_status != alert.status:
        emit_event(
            "alert.updated",
            serialize_alert(alert),
            previous_status=previous_status
        )

    return {
        "message": "Alert status updated successfully",
        "data": alert
    }