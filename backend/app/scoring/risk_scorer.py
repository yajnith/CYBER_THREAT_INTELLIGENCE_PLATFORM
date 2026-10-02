SEVERITY_SCORES = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 100,
}


def calculate_risk_score(severity: str, confidence: int) -> int:
    return explain_risk_score(severity, confidence)[
        "final_deterministic_score"
    ]


def explain_risk_score(severity: str, confidence: int) -> dict:
    """Return the deterministic score and its weighted components."""
    severity_score = SEVERITY_SCORES.get(severity.lower(), 50)
    severity_contribution = severity_score * 0.6
    confidence_contribution = confidence * 0.4
    final_score = round(severity_contribution + confidence_contribution)

    return {
        "severity_score": severity_score,
        "severity_contribution": severity_contribution,
        "confidence_contribution": confidence_contribution,
        "final_deterministic_score": final_score,
        "risk_level": get_risk_level(final_score),
    }


def get_risk_level(score: int) -> str:
    if score >= 90:
        return "critical"

    if score >= 70:
        return "high"

    if score >= 40:
        return "medium"

    return "low"
