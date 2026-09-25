from app.database.database import SessionLocal
from app.database.models import IOC, IOCObservation
from app.services.ioc_correlation import get_ioc_correlation


def test_ioc_correlation_counts_sources_and_threat_types():
    db = SessionLocal()

    try:
        ioc = IOC(
            indicator_type="domain",
            value="pytest-correlation.example",
            normalized_value="pytest-correlation.example",
            source="correlation_feed_a",
            threat_type="malware",
            confidence=80,
            severity="high",
            tags=["pytest"],
        )

        db.add(ioc)
        db.commit()
        db.refresh(ioc)

        db.add_all(
            [
                IOCObservation(
                    ioc_id=ioc.id,
                    source="correlation_feed_a",
                    observed_at=ioc.created_at,
                ),
                IOCObservation(
                    ioc_id=ioc.id,
                    source="correlation_feed_b",
                    observed_at=ioc.created_at,
                ),
                IOCObservation(
                    ioc_id=ioc.id,
                    source="correlation_feed_a",
                    observed_at=ioc.created_at,
                ),
            ]
        )

        db.commit()

        result = get_ioc_correlation(ioc.id, db)

        assert result["ioc_id"] == ioc.id
        assert result["source_count"] == 2
        assert result["observation_count"] == 3
        assert result["sources"] == [
            "correlation_feed_a",
            "correlation_feed_b",
        ]
        assert result["threat_type_count"] == 1
        assert result["threat_types"] == ["malware"]

    finally:
        test_ioc = (
            db.query(IOC)
            .filter(
                IOC.indicator_type == "domain",
                IOC.normalized_value == "pytest-correlation.example",
            )
            .first()
        )

        if test_ioc:
            db.query(IOCObservation).filter(
                IOCObservation.ioc_id == test_ioc.id
            ).delete()

            db.delete(test_ioc)
            db.commit()

        db.close()