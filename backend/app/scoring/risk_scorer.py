SEVERITY_SCORES = {
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 100,
}


def calculate_risk_score(severity: str, confidence: int) -> int:
    severity_score = SEVERITY_SCORES.get(
        severity.lower(),
        50
    )

    score = (
        severity_score * 0.6
        + confidence * 0.4
    )

    return round(score)


def get_risk_level(score: int) -> str:
    if score >= 90:
        return "critical"

    if score >= 70:
        return "high"

    if score >= 40:
        return "medium"

    return "low"