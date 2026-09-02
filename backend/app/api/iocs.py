from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import IOC
from app.enrichment.ioc_enricher import enrich_ioc
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


@router.get("")
def get_iocs(
    db: Session = Depends(get_db)
):
    records = (
        db.query(IOC)
        .order_by(IOC.id.desc())
        .all()
    )

    return {
        "count": len(records),
        "data": records
    }

@router.get("/search")
def search_iocs(
    indicator_type: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    source: str | None = Query(default=None),
    threat_type: str | None = Query(default=None),
    db: Session = Depends(get_db)
):
    query = db.query(IOC)

    if indicator_type:
        query = query.filter(
            IOC.indicator_type == indicator_type
        )

    if severity:
        query = query.filter(
            IOC.severity == severity
        )

    if source:
        query = query.filter(
            IOC.source == source
        )

    if threat_type:
        query = query.filter(
            IOC.threat_type == threat_type
        )

    records = (
        query
        .order_by(IOC.id.desc())
        .all()
    )

    return {
        "count": len(records),
        "data": records
    }

@router.get("/{ioc_id}")
def get_ioc(
    ioc_id: int,
    db: Session = Depends(get_db)
):
    record = (
        db.query(IOC)
        .filter(IOC.id == ioc_id)
        .first()
    )

    if not record:
        raise HTTPException(
            status_code=404,
            detail="IOC not found"
        )

    return record