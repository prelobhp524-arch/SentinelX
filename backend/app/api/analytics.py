from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, case

from app.core.database import get_db
from app.models.traffic import Traffic
from app.models.alert import Alert


router = APIRouter(
    prefix="/api/analytics",
    tags=["Traffic Analytics"]
)


# 1. Overall system statistics
@router.get("/summary")
def get_analytics_summary(db: Session = Depends(get_db)):

    total_traffic = db.query(Traffic).count()

    normal_traffic = db.query(Traffic).filter(
        Traffic.status == "normal"
    ).count()

    suspicious_traffic = db.query(Traffic).filter(
        Traffic.status == "suspicious"
    ).count()

    total_alerts = db.query(Alert).count()

    new_alerts = db.query(Alert).filter(
        Alert.status == "NEW"
    ).count()

    acknowledged_alerts = db.query(Alert).filter(
        Alert.status == "ACKNOWLEDGED"
    ).count()

    resolved_alerts = db.query(Alert).filter(
        Alert.status == "RESOLVED"
    ).count()

    return {
        "total_traffic": total_traffic,
        "normal_traffic": normal_traffic,
        "suspicious_traffic": suspicious_traffic,
        "total_alerts": total_alerts,
        "new_alerts": new_alerts,
        "acknowledged_alerts": acknowledged_alerts,
        "resolved_alerts": resolved_alerts
    }


# 2. Traffic grouped by protocol
@router.get("/traffic-by-protocol")
def get_traffic_by_protocol(db: Session = Depends(get_db)):

    results = db.query(
        Traffic.protocol,
        func.count(Traffic.id).label("total")
    ).group_by(
        Traffic.protocol
    ).all()

    return [
        {
            "protocol": result.protocol,
            "total": result.total
        }
        for result in results
    ]


# 3. Alerts grouped by severity
@router.get("/alerts-by-severity")
def get_alerts_by_severity(db: Session = Depends(get_db)):

    results = db.query(
        Alert.severity,
        func.count(Alert.id).label("total")
    ).group_by(
        Alert.severity
    ).all()

    return [
        {
            "severity": result.severity,
            "total": result.total
        }
        for result in results
    ]


# 4. Top source IP addresses
@router.get("/top-source-ips")
def get_top_source_ips(
    limit: int = Query(default=5, ge=1, le=50),
    db: Session = Depends(get_db)
):

    results = db.query(
        Traffic.source_ip,
        func.count(Traffic.id).label("total_traffic"),
        func.sum(
            case(
                (Traffic.status == "suspicious", 1),
                else_=0
            )
        ).label("suspicious_traffic")
    ).group_by(
        Traffic.source_ip
    ).order_by(
        func.count(Traffic.id).desc()
    ).limit(limit).all()

    return [
        {
            "source_ip": result.source_ip,
            "total_traffic": result.total_traffic,
            "suspicious_traffic": result.suspicious_traffic
        }
        for result in results
    ]