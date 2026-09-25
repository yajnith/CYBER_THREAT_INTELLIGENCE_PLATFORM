from sqlalchemy.orm import Session

from app.database.models import IOC
from app.enrichment.ioc_enricher import enrich_ioc
from app.scoring.risk_scorer import (
    SEVERITY_SCORES,
    calculate_risk_score,
)
from app.services.ioc_correlation import get_ioc_correlation


def build_ioc_features(
    ioc_id: int,
    db: Session,
) -> dict:
    ioc = (
        db.query(IOC)
        .filter(IOC.id == ioc_id)
        .first()
    )

    if not ioc:
        raise ValueError("IOC not found")

    correlation = get_ioc_correlation(
        ioc_id,
        db,
    )

    enrichment = enrich_ioc(
        ioc.indicator_type,
        ioc.normalized_value,
    )

    severity_score = SEVERITY_SCORES.get(
        ioc.severity.lower(),
        50,
    )

    deterministic_risk_score = calculate_risk_score(
        ioc.severity,
        ioc.confidence,
    )

    return {
        "confidence": ioc.confidence,
        "severity_score": severity_score,
        "deterministic_risk_score": deterministic_risk_score,
        "source_count": correlation["source_count"],
        "observation_count": correlation["observation_count"],
        "threat_type_count": correlation["threat_type_count"],
        "length": enrichment["length"],
        "has_digits": int(enrichment["has_digits"]),
        "has_special_characters": int(
            enrichment["has_special_characters"]
        ),
    }