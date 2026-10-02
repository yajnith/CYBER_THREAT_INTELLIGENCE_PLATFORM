import json

from research_data.correlation import correlate_entity
from research_data.features.build_features import (
    FEATURE_COLUMNS,
    build_feature_row,
    summarize_feature_rows,
)
from research_data.unified.schema import SourceObservation, UnifiedResearchRecord


def _summary(ioc_type="url", value="https://example.test/a", observations=None):
    observations = observations or [
        SourceObservation(
            source="urlhaus",
            source_record_id="uh-1",
            source_reference="https://urlhaus.example/1",
            reporter="reporter-a",
            source_ioc_value=value,
            threat_type="malware_download",
            tags=["elf", "linux"],
        )
    ]
    return correlate_entity(UnifiedResearchRecord(
        ioc_value=value,
        normalized_ioc_value=value,
        ioc_type=ioc_type,
        source_observations=observations,
    ))


def test_feature_row_is_deterministic_and_preserves_input_provenance():
    summary = _summary(observations=[
        SourceObservation(
            source="urlhaus", source_record_id="uh-1",
            source_reference="https://urlhaus.example/1", reporter="same-reporter",
            threat_type="malware_download", tags=["elf"],
        ),
        SourceObservation(
            source="threatfox", source_record_id="tf-2",
            source_reference="https://threatfox.example/2", reporter="same-reporter",
            threat_type="botnet_cc", malware_family="FamilyX", confidence=80,
            tags=["c2"], first_seen="2026-01-01T00:00:00Z",
            last_seen="2026-01-03T00:00:00Z",
        ),
    ])
    original_entity = summary.entity.model_dump(mode="json")

    row_a = build_feature_row(summary)
    row_b = build_feature_row(summary)

    assert row_a == row_b
    assert row_a["features"]["observation_count"] == 2
    assert row_a["features"]["distinct_source_count"] == 2
    assert row_a["features"]["multi_source"] is True
    assert row_a["features"]["repeated_observation"] is False
    assert row_a["features"]["distinct_threat_type_count"] == 2
    assert row_a["features"]["distinct_malware_family_count"] == 1
    assert row_a["features"]["threat_context_available"] is True
    assert row_a["features"]["tag_count"] == 2
    assert row_a["features"]["distinct_tag_count"] == 2
    assert row_a["features"]["confidence_min"] == 80
    assert row_a["features"]["confidence_max"] == 80
    assert row_a["features"]["confidence_mean"] == 80
    assert row_a["features"]["confidence_source_count"] == 1
    assert row_a["features"]["earliest_observation_timestamp"] == "2026-01-01T00:00:00Z"
    assert row_a["features"]["latest_observation_timestamp"] == "2026-01-03T00:00:00Z"
    assert row_a["features"]["temporal_span_seconds"] == 172800
    assert row_a["features"]["temporal_coverage"] is True
    assert [item["source_record_id"] for item in row_a["source_provenance"]] == ["uh-1", "tf-2"]
    assert row_a["raw_context_assertions"][1]["malware_family"] == "FamilyX"
    assert summary.entity.model_dump(mode="json") == original_entity
    assert set(row_a["features"]) == set(FEATURE_COLUMNS)


def test_single_source_missing_optional_context_is_safe_and_target_is_unassigned():
    row = build_feature_row(_summary(observations=[
        SourceObservation(source="urlhaus", source_record_id="u-1")
    ]))
    features = row["features"]

    assert features["observation_count"] == 1
    assert features["distinct_source_count"] == 1
    assert features["multi_source"] is False
    assert features["repeated_observation"] is False
    assert features["threat_context_available"] is False
    assert features["confidence_available"] is False
    assert features["confidence_min"] is None
    assert features["confidence_max"] is None
    assert features["confidence_mean"] is None
    assert features["temporal_coverage"] is False
    assert features["earliest_observation_timestamp"] is None
    assert row["target"] is None
    assert not any("label" in key or "risk_score" in key for key in features)


def test_type_indicators_distinguish_same_text_with_different_ioc_types():
    url_row = build_feature_row(_summary("url", "same-value"))
    domain_row = build_feature_row(_summary("domain", "same-value"))

    assert url_row["entity_identity"]["normalized_ioc_value"] == domain_row["entity_identity"]["normalized_ioc_value"]
    assert url_row["features"]["ioc_type"] == "url"
    assert url_row["features"]["type_url"] is True
    assert url_row["features"]["type_domain"] is False
    assert domain_row["features"]["type_domain"] is True
    assert domain_row["features"]["type_url"] is False


def test_repeated_source_observations_confidence_and_reporters_are_aggregated():
    summary = _summary(observations=[
        SourceObservation(source="urlhaus", source_record_id="u-1", reporter="reporter-a", confidence=20),
        SourceObservation(source="urlhaus", source_record_id="u-2", reporter="reporter-b", confidence=60),
    ])
    features = build_feature_row(summary)["features"]

    assert features["observation_count"] == 2
    assert features["distinct_source_count"] == 1
    assert features["repeated_observation"] is True
    assert features["source_diversity_ratio"] == 0.5
    assert features["distinct_reporter_count"] == 2
    assert features["confidence_min"] == 20
    assert features["confidence_max"] == 60
    assert features["confidence_mean"] == 40
    assert features["confidence_source_count"] == 1


def test_summary_reports_missing_values_and_does_not_create_a_target():
    rows = [build_feature_row(_summary(observations=[SourceObservation(source="urlhaus")]))]
    profile = summarize_feature_rows(rows)

    assert profile["feature_row_count"] == 1
    assert profile["feature_column_count"] == len(FEATURE_COLUMNS)
    assert profile["missing_value_count_by_feature"]["confidence_min"] == 1
    assert profile["missing_value_count_by_feature"]["earliest_observation_timestamp"] == 1
    assert profile["target_defined"] is False
    assert profile["rows_with_assigned_target"] == 0
    assert profile["rows_with_risk_score_feature"] == 0


def test_machine_readable_schema_declares_no_target():
    with open("research_data/features/feature_schema.json", encoding="utf-8") as file:
        schema = json.load(file)
    assert schema["target_policy"]["target_defined"] is False
    assert schema["target_policy"]["urlhaus_threat_is_target"] is False
    assert schema["target_policy"]["deterministic_risk_score_included"] is False
    assert len(schema["feature_columns"]) == len(FEATURE_COLUMNS)
