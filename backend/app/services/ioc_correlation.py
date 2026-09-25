from sqlalchemy.orm import Session

from app.database.models import IOC, IOCObservation


def get_ioc_correlation(
    ioc_id: int,
    db: Session,
) -> dict:
    observations = (
        db.query(IOCObservation)
        .filter(IOCObservation.ioc_id == ioc_id)
        .order_by(IOCObservation.observed_at.desc())
        .all()
    )

    sources = sorted(
        {
            observation.source
            for observation in observations
        }
    )

    ioc = (
        db.query(IOC)
        .filter(IOC.id == ioc_id)
        .first()
    )

    threat_types = []

    if ioc and ioc.threat_type:
        threat_types = [ioc.threat_type]

    return {
        "ioc_id": ioc_id,
        "source_count": len(sources),
        "sources": sources,
        "observation_count": len(observations),
        "threat_type_count": len(threat_types),
        "threat_types": threat_types,
    }