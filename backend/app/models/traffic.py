from sqlalchemy import Column, Integer, String, DateTime
from sqlalchemy.sql import func

from app.core.database import Base


class Traffic(Base):
    __tablename__ = "network_traffic"

    id = Column(Integer, primary_key=True, index=True)

    source_ip = Column(String(45), nullable=False)
    destination_ip = Column(String(45), nullable=False)

    protocol = Column(String(20), nullable=False)

    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)

    packet_size = Column(Integer, nullable=False)

    timestamp = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    status = Column(String(20), default="normal")

    direction = Column(
        String(20),
        nullable=False,
        default="UNKNOWN",
        server_default="UNKNOWN"
    )