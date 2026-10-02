from types import SimpleNamespace

from app.database.database import SessionLocal
from app.database.models import IOC, IOCObservation
from app.api import iocs as ioc_api
from app.api.iocs import get_ioc
from app.services.ioc_correlation import get_ioc_correlation


def test_dashboard_ioc_list_includes_actual_observation_count(monkeypatch):
    record = SimpleNamespace(
        id=91,
        indicator_type="url",
        value="https://dashboard-count.example/path",
        normalized_value="https://dashboard-count.example/path",
        source="URLhaus",
        threat_type="malware_download",
        confidence=50,
        severity="medium",
        tags=["test-tag"],
        first_seen=None,
        last_seen=None,
        created_at=None,
    )

    class FakeQuery:
        def order_by(self, *_args):
            return self

        def all(self):
            return [record]

    class FakeDB:
        def query(self, *_args):
            return FakeQuery()

    monkeypatch.setattr(ioc_api, "get_ioc_correlation", lambda *_args: {
        "sources": ["URLhaus"],
        "source_count": 1,
        "observation_count": 3,
    })

    result = ioc_api.get_iocs(FakeDB())

    assert result["count"] == 1
    assert result["data"][0]["sources"] == ["URLhaus"]
    assert result["data"][0]["observation_count"] == 3


def test_ioc_correlation_counts_sources_and_threat_types():
    db = SessionLocal()

    try:
        ioc = IOC(
            indicator_type="domain",
            value="pytest-correlation.example",
            normalized_value="pytest-correlation.example",
            source="correlation_feed_a",
            threat_type="malware",
            confidence=80,
            severity="high",
            tags=["pytest"],
        )

        db.add(ioc)
        db.commit()
        db.refresh(ioc)

        db.add_all(
            [
                IOCObservation(
                    ioc_id=ioc.id,
                    source="correlation_feed_a",
                    observed_at=ioc.created_at,
                ),
                IOCObservation(
                    ioc_id=ioc.id,
                    source="correlation_feed_b",
                    observed_at=ioc.created_at,
                ),
                IOCObservation(
                    ioc_id=ioc.id,
                    source="correlation_feed_a",
                    observed_at=ioc.created_at,
                ),
            ]
        )

        db.commit()

        result = get_ioc_correlation(ioc.id, db)

        assert result["ioc_id"] == ioc.id
        assert result["source_count"] == 2
        assert result["observation_count"] == 3
        assert result["sources"] == [
            "correlation_feed_a",
            "correlation_feed_b",
        ]
        assert result["threat_type_count"] == 1
        assert result["threat_types"] == ["malware"]

    finally:
        test_ioc = (
            db.query(IOC)
            .filter(
                IOC.indicator_type == "domain",
                IOC.normalized_value == "pytest-correlation.example",
            )
            .first()
        )

        if test_ioc:
            db.query(IOCObservation).filter(
                IOCObservation.ioc_id == test_ioc.id
            ).delete()

            db.delete(test_ioc)
            db.commit()

        db.close()


def test_ioc_detail_returns_observation_derived_sources_and_risk_explanation():
    db = SessionLocal()

    try:
        ioc = IOC(
            indicator_type="domain",
            value="pytest-detail-sources.example",
            normalized_value="pytest-detail-sources.example",
            source="detail_feed_a",
            threat_type="malware",
            confidence=80,
            severity="high",
            tags=["pytest"],
        )
        db.add(ioc)
        db.commit()
        db.refresh(ioc)
        db.add_all([
            IOCObservation(ioc_id=ioc.id, source="detail_feed_a", observed_at=ioc.created_at),
            IOCObservation(ioc_id=ioc.id, source="detail_feed_b", observed_at=ioc.created_at),
            IOCObservation(ioc_id=ioc.id, source="detail_feed_b", observed_at=ioc.created_at),
        ])
        db.commit()

        result = get_ioc(ioc.id, db)

        assert result["source_count"] == 2
        assert result["sources"] == ["detail_feed_a", "detail_feed_b"]
        assert result["correlation"]["source_count"] == 2
        assert result["correlation"]["sources"] == result["sources"]
        assert result["risk_score"] == 77
        assert result["risk_level"] == "high"
        assert result["risk_explanation"] == {
            "severity_score": 75,
            "severity_contribution": 45.0,
            "confidence_contribution": 32.0,
            "final_deterministic_score": 77,
            "risk_level": "high",
        }
        assert result["research_context"]["production_ml_enabled"] is False
        assert result["research_context"]["real_labeled_model_available"] is False
        assert result["attack_context"]["mapping_type"] == "rule-based ATT&CK-style context mapping"
        assert result["cve_context"] is None
        assert result["mitigation_recommendations"]
        assert all("reason" in item for item in result["mitigation_recommendations"])
        assert "prediction" not in result
        assert "model_score" not in result
    finally:
        test_ioc = db.query(IOC).filter(
            IOC.indicator_type == "domain",
            IOC.normalized_value == "pytest-detail-sources.example",
        ).first()
        if test_ioc:
            db.query(IOCObservation).filter(IOCObservation.ioc_id == test_ioc.id).delete()
            db.delete(test_ioc)
            db.commit()
        db.close()
