from sqlalchemy.orm import Session

from app.database.models import IOCObservation


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

    return {
        "ioc_id": ioc_id,
        "source_count": len(sources),
        "sources": sources,
        "observation_count": len(observations),
    }