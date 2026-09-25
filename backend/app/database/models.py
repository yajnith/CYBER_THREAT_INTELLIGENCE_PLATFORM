from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    JSON,
    UniqueConstraint,
    ForeignKey,
    Index,
)
from datetime import datetime, timezone

from app.database.database import Base


class IOC(Base):

    __tablename__ = "iocs"

    __table_args__ = (
        UniqueConstraint(
            "indicator_type",
            "normalized_value",
            name="uq_ioc_type_normalized_value"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)

    indicator_type = Column(String)

    value = Column(String)

    normalized_value = Column(String)

    source = Column(String)

    threat_type = Column(String)

    confidence = Column(Integer)

    severity = Column(String)

    tags = Column(JSON)

    first_seen = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    last_seen = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc)
    )

    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc)
    )


class IOCObservation(Base):

    __tablename__ = "ioc_observations"

    __table_args__ = (
        Index(
            "ix_ioc_observations_ioc_id",
            "ioc_id",
        ),
        Index(
            "ix_ioc_observations_source",
            "source",
        ),
    )

    id = Column(
    Integer,
    primary_key=True,
    )

    ioc_id = Column(
        Integer,
        ForeignKey("iocs.id", ondelete="CASCADE"),
        nullable=False,
    )

    source = Column(
        String,
        nullable=False,
    )

    observed_at = Column(
        DateTime,
        nullable=False,
    )