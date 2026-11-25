from sqlalchemy import Boolean, Column, DateTime, Integer, String
from sqlalchemy.sql import func

from app.core.database import Base


class IPReputationCache(Base):
    __tablename__ = "ip_reputation_cache"

    id = Column(Integer, primary_key=True, index=True)

    ip_address = Column(String(45), nullable=False, unique=True, index=True)

    provider = Column(
        String(20),
        nullable=False,
        default="AbuseIPDB",
        server_default="AbuseIPDB"
    )

    abuse_confidence_score = Column(Integer, nullable=True)
    total_reports = Column(Integer, nullable=True)
    num_distinct_users = Column(Integer, nullable=True)

    last_reported_at = Column(DateTime(timezone=True), nullable=True)

    isp = Column(String(255), nullable=True)
    domain = Column(String(255), nullable=True)
    country_code = Column(String(2), nullable=True)
    usage_type = Column(String(100), nullable=True)

    is_public = Column(Boolean, nullable=True)
    is_whitelisted = Column(Boolean, nullable=True)
    is_tor = Column(Boolean, nullable=True)

    checked_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )

    expires_at = Column(
        DateTime(timezone=True),
        nullable=False,
        index=True
    )
