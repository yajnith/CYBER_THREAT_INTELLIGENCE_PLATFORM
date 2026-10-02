from app.enrichment.ioc_enricher import enrich_ioc
from app.scoring.risk_scorer import (
    calculate_risk_score,
    explain_risk_score,
    get_risk_level,
)


def test_critical_risk_score():
    score = calculate_risk_score("critical", 90)

    assert score == 96
    assert get_risk_level(score) == "critical"


def test_high_risk_score():
    score = calculate_risk_score("high", 80)

    assert score == 77
    assert get_risk_level(score) == "high"


def test_risk_explanation_matches_deterministic_formula():
    result = explain_risk_score("high", 80)

    assert result == {
        "severity_score": 75,
        "severity_contribution": 45.0,
        "confidence_contribution": 32.0,
        "final_deterministic_score": 77,
        "risk_level": "high",
    }


def test_medium_risk_score():
    score = calculate_risk_score("medium", 50)

    assert score == 50
    assert get_risk_level(score) == "medium"


def test_low_risk_score():
    score = calculate_risk_score("low", 20)

    assert score == 23
    assert get_risk_level(score) == "low"


def test_domain_enrichment():
    result = enrich_ioc(
        "domain",
        "evil-example.com"
    )

    assert result["tld"] == ".com"
    assert result["has_subdomain"] is False
    assert result["label_count"] == 2


def test_url_enrichment():
    result = enrich_ioc(
        "url",
        "https://evil-example.com/login?id=123"
    )

    assert result["scheme"] == "https"
    assert result["hostname"] == "evil-example.com"
    assert result["has_path"] is True
    assert result["has_query"] is True


def test_hash_enrichment():
    result = enrich_ioc(
        "hash_sha256",
        "a" * 64
    )

    assert result["hash_length"] == 64


def test_email_enrichment():
    result = enrich_ioc(
        "email",
        "attacker@example.com"
    )

    assert result["username"] == "attacker"
    assert result["domain"] == "example.com"
