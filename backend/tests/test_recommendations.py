from app.services.recommendations import generate_mitigation_recommendations


def test_hash_recommendations_use_context_and_are_advisory():
    recommendations = generate_mitigation_recommendations(
        "hash_sha256", "not interpolated", threat_type="malware",
        severity="critical", confidence=95, risk_level="critical", risk_score=98,
        source_count=2,
    )
    assert recommendations
    assert recommendations[0]["priority"] == "high"
    assert "hash" in recommendations[0]["reason"].lower()
    assert all("recommendation" in item and "reason" in item for item in recommendations)
    assert all("not interpolated" not in item["reason"] for item in recommendations)


def test_low_confidence_adds_validation_guidance():
    recommendations = generate_mitigation_recommendations(
        "ipv4", "192.0.2.1", confidence=20,
    )
    assert any("additional evidence" in item["recommendation"] for item in recommendations)
