import json
from types import SimpleNamespace

from app.api import research
from app.api import iocs as ioc_api


def _write_json(root, relative_path, value):
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def _write_overview_artifacts(root):
    _write_json(root, "urlhaus/metadata.json", {
        "dataset": "URLhaus",
        "normalized_record_count": 14354,
        "threat_distribution": {"malware_download": 14354},
        "url_status_distribution": {"offline": 12624, "online": 1730},
    })
    _write_json(root, "features/urlhaus_feature_profile.json", {
        "statistics": {"feature_row_count": 14354, "feature_column_count": 44,
                       "rows_with_assigned_target": 0},
    })
    _write_json(root, "experiments/urlhaus_experiment_profile.json", {
        "statistics": {
            "experiment_feature_counts": {"A": 20, "B": 28, "C": 44},
            "experiment_row_counts": {"A": 14354, "B": 14354, "C": 14354},
            "feature_source_row_coverage": {"urlhaus": 14354},
            "labeled_count_per_experiment": {"A": 0, "B": 0, "C": 0},
            "input_target_row_count": 0,
        },
    })
    _write_json(root, "ml/synthetic_baseline_results.json", {
        "metadata": {
            "result_type": "SYNTHETIC BENCHMARK RESULT",
            "dataset_type": "controlled_synthetic_benchmark",
            "synthetic": True,
            "real_world_ground_truth": False,
            "benchmark_size": 600,
            "class_counts": {"positive": 300, "negative": 300},
            "random_seed": 8137,
            "split_seed": 2026,
            "split_strategy": "75/25",
            "models": ["LogisticRegression", "GaussianNaiveBayes"],
        },
        "experiments": {
            experiment_id: {
                "feature_count": count,
                "models": {"LogisticRegression": {"result_type": "SYNTHETIC BENCHMARK RESULT",
                                                      "metrics": {"accuracy": 0.9}}},
            }
            for experiment_id, count in {"A": 20, "B": 28, "C": 44}.items()
        },
    })
    _write_json(root, "ml/explainability/synthetic_explanations.json", {
        "metadata": {
            "dataset_type": "controlled_synthetic_benchmark",
            "models": ["LogisticRegression"],
            "model_feature_importance_is_causal": False,
        },
        "experiments": {
            "C": {
                "models": {
                    "LogisticRegression": {
                        "global_model_feature_contribution": {
                            "features_ranked_by_mean_absolute_contribution": [
                                {"feature": "tag_count", "mean_absolute_contribution": 0.42},
                                {"feature": "value_length", "mean_absolute_contribution": 0.21},
                            ],
                        },
                    },
                },
            },
        },
    })
    _write_json(root, "urlhaus/urlhaus_normalized.json", [
        {"tags": ["alpha", "shared"]},
        {"tags": ["shared", "beta"]},
        {"tags": []},
    ])
    _write_json(root, "threatfox/metadata.json", {"status": "not_collected"})


def test_research_overview_endpoint_reads_artifacts_and_reports_limitations(tmp_path, monkeypatch):
    _write_overview_artifacts(tmp_path)
    monkeypatch.setattr(research, "RESEARCH_DATA_DIR", tmp_path)

    overview = research.get_research_overview()
    route = next(route for route in research.router.routes if route.path == "/api/v1/research/overview")
    assert "GET" in route.methods
    assert overview["real_dataset"]["records"] == 14354
    assert overview["real_dataset"]["supervised_labels"] == 0
    assert overview["real_dataset"]["target_status"] == "unavailable / unknown"
    assert overview["feature_engineering"] == {"rows": 14354, "total_features": 44}
    assert [experiment["feature_count"] for experiment in overview["experiments"]] == [20, 28, 44]
    assert overview["benchmark"]["result_label"] == "SYNTHETIC BENCHMARK RESULT"
    assert overview["benchmark"]["samples"] == 600
    assert overview["real_dataset"]["url_status_distribution"] == {
        "offline": 12624, "online": 1730,
    }
    assert overview["real_dataset"]["top_tags"] == [
        {"label": "shared", "value": 2},
        {"label": "alpha", "value": 1},
        {"label": "beta", "value": 1},
    ]
    assert overview["explainability"]["global_feature_contributions"]["C"]["LogisticRegression"] == [
        {"feature": "tag_count", "mean_absolute_contribution": 0.42},
        {"feature": "value_length", "mean_absolute_contribution": 0.21},
    ]
    assert overview["explainability"]["global_feature_contributions_available"] is True
    assert overview["experiments"][2]["models"]["LogisticRegression"]["metrics"]["accuracy"] == 0.9
    assert overview["explainability"]["available"] is True
    assert overview["threatfox"]["real_data_collected"] is False
    assert any("Production CTIP risk scoring remains deterministic." in item for item in overview["limitations"])


def test_research_overview_endpoint_survives_missing_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr(research, "RESEARCH_DATA_DIR", tmp_path)

    overview = research.get_research_overview()
    assert overview["artifacts_available"] is False
    assert overview["real_dataset"]["records"] is None
    assert overview["benchmark"]["available"] is False
    assert set(overview["artifacts"].values()) == {"unavailable"}


def test_research_overview_marks_malformed_artifacts_invalid(tmp_path, monkeypatch):
    (tmp_path / "urlhaus").mkdir()
    (tmp_path / "urlhaus/metadata.json").write_text("{broken json", encoding="utf-8")
    monkeypatch.setattr(research, "RESEARCH_DATA_DIR", tmp_path)

    overview = research.get_research_overview()

    assert overview["artifacts"]["urlhaus_metadata"] == "invalid"
    assert overview["real_dataset"]["records"] is None


def test_investigation_research_context_uses_artifacts_without_labels(tmp_path, monkeypatch):
    _write_overview_artifacts(tmp_path)
    monkeypatch.setattr(research, "RESEARCH_DATA_DIR", tmp_path)

    context = research.build_investigation_research_context()

    assert context == {
        "available": True,
        "real_labeled_model_available": False,
        "real_supervised_label_count": 0,
        "research_dataset": "URLhaus",
        "research_records": 14354,
        "feature_count": 44,
        "experiment_configurations": ["A", "B", "C"],
        "synthetic_benchmark_available": True,
        "synthetic_benchmark_label": "Controlled synthetic dataset",
        "production_ml_enabled": False,
    }


def test_investigation_remains_deterministic_when_research_artifacts_are_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(research, "RESEARCH_DATA_DIR", tmp_path)
    record = SimpleNamespace(
        id=12,
        indicator_type="domain",
        normalized_value="example.test",
        severity="high",
        confidence=80,
    )

    class FakeQuery:
        def filter(self, *_args):
            return self

        def first(self):
            return record

        def order_by(self, *_args):
            return self

        def all(self):
            return []

    class FakeDB:
        def query(self, *_args):
            return FakeQuery()

    monkeypatch.setattr(ioc_api, "get_ioc_correlation", lambda *_args: {
        "source_count": 2,
        "sources": ["feed_a", "feed_b"],
        "observation_count": 2,
    })
    monkeypatch.setattr(ioc_api, "enrich_ioc", lambda *_args: {})
    monkeypatch.setattr(ioc_api, "calculate_risk_score", lambda *_args: 77)
    monkeypatch.setattr(ioc_api, "get_risk_level", lambda _score: "high")
    monkeypatch.setattr(ioc_api, "explain_risk_score", lambda *_args: {
        "severity_score": 75,
        "severity_contribution": 45.0,
        "confidence_contribution": 32.0,
        "final_deterministic_score": 77,
        "risk_level": "high",
    })

    result = ioc_api.get_ioc(12, FakeDB())

    assert result["risk_score"] == 77
    assert result["risk_level"] == "high"
    assert result["risk_explanation"]["final_deterministic_score"] == 77
    assert result["research_context"]["available"] is False
    assert result["research_context"]["production_ml_enabled"] is False
    assert result["research_context"]["synthetic_benchmark_available"] is False
    assert "prediction" not in result
    assert "model_score" not in result
