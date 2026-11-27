from sqlalchemy import Column, Integer, String
from sqlalchemy.sql import func

from app.core.database import Base
from app.core.types import UTCDateTime


class DemoSeedRun(Base):
    __tablename__ = "demo_seed_runs"

    id = Column(Integer, primary_key=True, index=True)

    seed_key = Column(
        String(100),
        nullable=False,
        unique=True,
        index=True
    )

    dataset_version = Column(String(20), nullable=False)

    anchor_at = Column(UTCDateTime, nullable=False)

    traffic_count = Column(Integer, nullable=False, default=0)

    alert_count = Column(Integer, nullable=False, default=0)

    seeded_at = Column(
        UTCDateTime,
        server_default=func.now(),
        nullable=False
    )
