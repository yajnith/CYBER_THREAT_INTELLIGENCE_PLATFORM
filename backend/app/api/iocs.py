from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import IOC, IOCObservation
from app.enrichment.ioc_enricher import enrich_ioc
from app.schemas.ioc import IOCCreate
from app.scoring.risk_scorer import (
    calculate_risk_score,
    get_risk_level,
)
from app.services.ioc_correlation import get_ioc_correlation
from app.services.ioc_service import process_ioc


router = APIRouter(
    prefix="/api/v1/iocs",
    tags=["Threat Intelligence - IOCs"],
)


@router.post("")
def create_ioc(
    ioc: IOCCreate,
    db: Session = Depends(get_db),
):
    return process_ioc(ioc, db)


@router.get("")
def get_iocs(
    db: Session = Depends(get_db),
):
    records = (
        db.query(IOC)
        .order_by(IOC.id.desc())
        .all()
    )

    return {
        "count": len(records),
        "data": records,
    }


@router.get("/search")
def search_iocs(
    indicator_type: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    source: str | None = Query(default=None),
    threat_type: str | None = Query(default=None),
    db: Session = Depends(get_db),
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
        "data": records,
    }


@router.get("/{ioc_id}")
def get_ioc(
    ioc_id: int,
    db: Session = Depends(get_db),
):
    record = (
        db.query(IOC)
        .filter(IOC.id == ioc_id)
        .first()
    )

    if not record:
        raise HTTPException(
            status_code=404,
            detail="IOC not found",
        )

    observations = (
        db.query(IOCObservation)
        .filter(IOCObservation.ioc_id == record.id)
        .order_by(IOCObservation.observed_at.desc())
        .all()
    )

    correlation = get_ioc_correlation(
        record.id,
        db,
    )

    enrichment = enrich_ioc(
        record.indicator_type,
        record.normalized_value,
    )

    risk_score = calculate_risk_score(
        record.severity,
        record.confidence,
    )

    risk_level = get_risk_level(risk_score)

    return {
        "ioc": record,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "enrichment": enrichment,
        "observations": observations,
        "correlation": correlation,
    }