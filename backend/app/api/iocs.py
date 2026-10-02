from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.database.models import IOC, IOCObservation
from app.enrichment.ioc_enricher import enrich_ioc
from app.schemas.ioc import IOCCreate
from app.scoring.risk_scorer import (
    calculate_risk_score,
    explain_risk_score,
    get_risk_level,
)
from app.services.ioc_correlation import get_ioc_correlation
from app.services.ioc_service import process_ioc
from app.services.attack_context import map_attack_style_context
from app.services.cve_context import build_cve_context
from app.services.recommendations import generate_mitigation_recommendations
from app.api.research import build_investigation_research_context


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

    data = []
    all_sources = set()
    for record in records:
        correlation = get_ioc_correlation(record.id, db)
        all_sources.update(correlation["sources"])
        risk = explain_risk_score(record.severity, record.confidence)
        data.append({
            "id": record.id,
            "indicator_type": record.indicator_type,
            "value": record.value,
            "normalized_value": record.normalized_value,
            "source": record.source,
            "threat_type": record.threat_type,
            "confidence": record.confidence,
            "severity": record.severity,
            "tags": record.tags,
            "first_seen": record.first_seen,
            "last_seen": record.last_seen,
            "created_at": record.created_at,
            "sources": correlation["sources"],
            "source_count": correlation["source_count"],
            "observation_count": correlation["observation_count"],
            "risk_score": risk["final_deterministic_score"],
            "risk_level": risk["risk_level"],
        })

    return {
        "count": len(records),
        "source_count": len(all_sources),
        "data": data,
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
    risk_explanation = explain_risk_score(
        record.severity,
        record.confidence,
    )
    threat_type = getattr(record, "threat_type", None)
    tags = getattr(record, "tags", None) or []
    attack_context = map_attack_style_context(threat_type, tags)
    cve_context = (
        build_cve_context(record.normalized_value)
        if record.indicator_type == "cve"
        else None
    )
    recommendations = generate_mitigation_recommendations(
        record.indicator_type,
        record.normalized_value,
        threat_type=threat_type,
        severity=record.severity,
        confidence=record.confidence,
        risk_level=risk_level,
        risk_score=risk_score,
        tags=tags,
        enrichment=enrichment,
        source_count=correlation["source_count"],
    )

    return {
        "ioc": record,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_explanation": risk_explanation,
        "source_count": correlation["source_count"],
        "sources": correlation["sources"],
        "enrichment": enrichment,
        "observations": observations,
        "correlation": correlation,
        "attack_context": attack_context,
        "cve_context": cve_context,
        "mitigation_recommendations": recommendations,
        "research_context": build_investigation_research_context(),
    }
