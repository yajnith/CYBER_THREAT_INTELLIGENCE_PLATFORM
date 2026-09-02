from app.enrichment.ioc_enricher import enrich_ioc

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import IOC
from app.normalization.ioc_normalizer import normalize_ioc
from app.scoring.risk_scorer import calculate_risk_score, get_risk_level
from app.schemas.ioc import IOCCreate

router = APIRouter(
    prefix="/api/v1/iocs",
    tags=["Threat Intelligence - IOCs"]
)


@router.post("")
def create_ioc(
    ioc: IOCCreate,
    db: Session = Depends(get_db)
):
    normalized = normalize_ioc(ioc)

    enrichment = enrich_ioc(
        ioc.indicator_type.value,
        normalized["normalized_value"]
    )

    risk_score = calculate_risk_score(
        ioc.severity.value,
        ioc.confidence
    )

    risk_level = get_risk_level(risk_score)

    now = datetime.now(timezone.utc)

    existing = (
        db.query(IOC)
        .filter(
            IOC.indicator_type == normalized["indicator_type"],
            IOC.normalized_value == normalized["normalized_value"]
        )
        .first()
    )

    if existing:
        existing.last_seen = now

        db.commit()
        db.refresh(existing)

        return {
            "ioc": existing,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "enrichment": enrichment
        }

    record = IOC(
        **normalized,
        first_seen=now,
        last_seen=now,
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    return {
        "ioc": record,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "enrichment": enrichment
    }