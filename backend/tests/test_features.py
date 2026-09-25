from app.database.database import SessionLocal
from app.database.models import IOC, IOCObservation
from app.features.ioc_features import build_ioc_features


def test_ioc_feature_vector():
    db = SessionLocal()

    try:
        ioc = IOC(
            indicator_type="domain",
            value="pytest-features.example",
            normalized_value="pytest-features.example",
            source="feature_feed_a",
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
                    source="feature_feed_a",
                    observed_at=ioc.created_at,
                ),
                IOCObservation(
                    ioc_id=ioc.id,
                    source="feature_feed_b",
                    observed_at=ioc.created_at,
                ),
            ]
        )

        db.commit()

        result = build_ioc_features(
            ioc.id,
            db,
        )

        assert result["confidence"] == 80
        assert result["severity_score"] == 75
        assert result["deterministic_risk_score"] == 77
        assert result["source_count"] == 2
        assert result["observation_count"] == 2
        assert result["threat_type_count"] == 1
        assert result["length"] == len(
            "pytest-features.example"
        )
        assert result["has_digits"] == 0
        assert result["has_special_characters"] == 1

    finally:
        test_ioc = (
            db.query(IOC)
            .filter(
                IOC.indicator_type == "domain",
                IOC.normalized_value == "pytest-features.example",
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