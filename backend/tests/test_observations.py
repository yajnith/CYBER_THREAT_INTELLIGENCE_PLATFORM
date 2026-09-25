from app.database.database import SessionLocal
from app.database.models import IOC, IOCObservation
from app.schemas.ioc import IOCCreate, IndicatorType, Severity
from app.services.ioc_service import process_ioc


def test_ioc_creates_observation():
    db = SessionLocal()

    try:
        ioc = IOCCreate(
            indicator_type=IndicatorType.DOMAIN,
            value="pytest-observation.example",
            source="pytest_feed",
            threat_type="test",
            confidence=80,
            severity=Severity.HIGH,
            tags=["pytest"],
        )

        existing_ioc = (
            db.query(IOC)
            .filter(
                IOC.indicator_type == ioc.indicator_type,
                IOC.normalized_value == ioc.value,
            )
            .first()
        )

        if existing_ioc:
            db.query(IOCObservation).filter(
                IOCObservation.ioc_id == existing_ioc.id
            ).delete()

            db.delete(existing_ioc)
            db.commit()

        result = process_ioc(ioc, db)

        observations = (
            db.query(IOCObservation)
            .filter(
                IOCObservation.ioc_id == result["ioc"].id
            )
            .all()
        )

        assert len(observations) == 1
        assert observations[0].source == "pytest_feed"
        assert observations[0].ioc_id == result["ioc"].id

    finally:
        test_ioc = (
            db.query(IOC)
            .filter(
                IOC.indicator_type == IndicatorType.DOMAIN,
                IOC.normalized_value == "pytest-observation.example",
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