from sqlalchemy import Column, Integer, String, DateTime
from datetime import datetime, timezone

from app.database.database import Base


class IOC(Base):

    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)

    indicator_type = Column(String)

    value = Column(String)

    normalized_value = Column(String)

    source = Column(String)

    threat_type = Column(String)

    confidence = Column(Integer)

    severity = Column(String)

    tags = Column(String)

    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc)
    )