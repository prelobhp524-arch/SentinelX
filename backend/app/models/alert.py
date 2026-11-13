from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.sql import func

from app.core.database import Base


class Alert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)

    source_ip = Column(String(45), nullable=False)

    alert_type = Column(String(50), nullable=False)

    severity = Column(String(20), nullable=False)

    description = Column(Text, nullable=False)

    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    status = Column(
        String(20),
        default="NEW",
        nullable=False
    )