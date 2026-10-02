import json

import pytest

from research_data.pipeline.run_urlhaus import (
    process_normalized_records,
    process_source_records,
    run_urlhaus_pipeline,
)


def test_process_normalized_records_runs_all_research_stages():
    records = [
        {
            "urlhaus_id": "synthetic-urlhaus-1",
            "url": "https://one.example/path",
            "date_added": "2026-01-01 00:00:00 UTC",
            "url_status": "online",
            "last_online": None,
            "threat": "malware_download",
            "tags": ["synthetic-tag"],
            "urlhaus_link": "https://source.example/1",
            "reporter": "synthetic-reporter",
        },
        {
            "urlhaus_id": "synthetic-urlhaus-2",
            "url": "https://one.example/path",
            "date_added": "2026-01-02 00:00:00 UTC",
            "url_status": "offline",
            "last_online": "2026-01-03 00:00:00 UTC",
            "threat": "malware_download",
            "tags": [],
            "urlhaus_link": "https://source.example/2",
            "reporter": "synthetic-reporter",
        },
    ]

    entities, summaries, statistics = process_normalized_records(records)

    assert len(entities) == 1
    assert len(summaries) == 1
    assert statistics["normalized_input_record_count"] == 2
    assert statistics["adapted_record_count"] == 2
    assert statistics["resolved_entity_count"] == 1
    assert statistics["observation_count"] == 2
    assert statistics["source_count"] == 1
    assert statistics["multi_source_entity_count"] == 0
    assert statistics["threat_context_coverage"]["observations_with_context"] == 2
    assert statistics["tag_coverage"]["observations_with_tags"] == 1
    assert statistics["confidence_coverage"]["observations_with_confidence"] == 0
    assert statistics["temporal_coverage"]["observations_with_seen_timestamp_fields"] == 0
    assert [item.source_record_id for item in entities[0].source_observations] == [
        "synthetic-urlhaus-1",
        "synthetic-urlhaus-2",
    ]
    assert entities[0].source_observations[0].urlhaus.date_added == "2026-01-01 00:00:00 UTC"
    assert entities[0].source_observations[1].urlhaus.last_online == "2026-01-03 00:00:00 UTC"


def test_run_pipeline_writes_provenance_preserving_results_and_metadata(tmp_path):
    source = tmp_path / "normalized.json"
    source.write_text(json.dumps([{
        "urlhaus_id": "synthetic-1",
        "url": "https://example.test/",
        "threat": "malware_download",
        "tags": ["synthetic-tag"],
        "urlhaus_link": "https://source.example/1",
        "reporter": "synthetic-reporter",
    }]), encoding="utf-8")
    source_metadata = tmp_path / "source_metadata.json"
    source_metadata.write_text(json.dumps({
        "source": "synthetic fixture source",
        "collection_timestamp": "2026-01-01T00:00:00Z",
    }), encoding="utf-8")
    threatfox_metadata = tmp_path / "threatfox_metadata.json"
    threatfox_metadata.write_text(json.dumps({"status": "not_collected"}), encoding="utf-8")
    output = tmp_path / "pipeline_results.json"
    metadata = tmp_path / "pipeline_metadata.json"

    # No real source data is needed to validate the orchestration and
    # serialization contract.
    profile = run_urlhaus_pipeline(
        input_file=source,
        threatfox_file=tmp_path / "not_collected.json",
        output_file=output,
        metadata_file=metadata,
        source_metadata_file=source_metadata,
        threatfox_metadata_file=threatfox_metadata,
    )

    result = json.loads(output.read_text(encoding="utf-8"))[0]
    assert result["entity"]["source_observations"][0]["source_record_id"] == "synthetic-1"
    assert result["entity"]["source_observations"][0]["source_reference"] == "https://source.example/1"
    assert result["entity"]["source_observations"][0]["urlhaus"]["reporter"] == "synthetic-reporter"
    assert profile["statistics"]["resolved_entity_count"] == 1
    assert profile["threatfox_status"] == "not_collected"
    assert profile["empirical_cross_source_results_available"] is False
    assert json.loads(metadata.read_text(encoding="utf-8"))["status"] == "completed"


@pytest.mark.parametrize("invalid", [None, {}, ["not a record"]])
def test_process_rejects_invalid_normalized_input(invalid):
    with pytest.raises(ValueError):
        process_normalized_records(invalid)


def _urlhaus(url, record_id="u-1", threat="malware_download", tags=None):
    return {
        "urlhaus_id": record_id,
        "url": url,
        "date_added": "2026-01-01 00:00:00 UTC",
        "url_status": "online",
        "last_online": None,
        "threat": threat,
        "tags": tags or [],
        "urlhaus_link": f"https://urlhaus.example/{record_id}",
        "reporter": "urlhaus-reporter",
    }


def _threatfox(ioc, ioc_type="url", record_id="t-1", threat="botnet_cc", family="FamilyA"):
    from research_data.threatfox.normalize import normalize_ioc_value

    return {
        "source_dataset": "ThreatFox",
        "threatfox_id": record_id,
        "ioc": ioc,
        "normalized_ioc": normalize_ioc_value(ioc_type, ioc),
        "ioc_type": ioc_type,
        "ioc_type_description": "synthetic test fixture",
        "threat_type": threat,
        "threat_type_description": None,
        "malware_family": family,
        "malware_printable": family,
        "malware_alias": None,
        "malware_malpedia": None,
        "confidence_level": 85,
        "first_seen": "2026-01-02T00:00:00Z",
        "last_seen": "2026-01-03T00:00:00Z",
        "reporter": "threatfox-reporter",
        "reference": "https://threatfox.example/record/" + record_id,
        "tags": ["tf-tag"],
        "additional_fields": {"fixture_note": "synthetic only"},
    }


def test_source_pipeline_accepts_threatfox_only_and_preserves_observation():
    _, summaries, stats = process_source_records({
        "threatfox": [_threatfox("example.test", ioc_type="domain")],
    })

    assert len(summaries) == 1
    observation = summaries[0].entity.source_observations[0]
    assert observation.source == "threatfox"
    assert observation.source_record_id == "t-1"
    assert observation.source_reference.endswith("t-1")
    assert observation.threatfox.additional_fields["fixture_note"] == "synthetic only"
    assert stats["normalized_records_by_source"] == {"threatfox": 1}


def test_shared_typed_ioc_resolves_cross_source_without_losing_provenance():
    _, summaries, stats = process_source_records({
        "urlhaus": [_urlhaus("https://shared.example/path", record_id="u-shared")],
        "threatfox": [_threatfox("https://shared.example/path", record_id="t-shared")],
    })

    assert len(summaries) == 1
    summary = summaries[0]
    assert summary.multi_source is True
    assert summary.source_names == ["threatfox", "urlhaus"]
    assert {item.source_record_id for item in summary.entity.source_observations} == {"u-shared", "t-shared"}
    assert summary.entity.source_observations[0].urlhaus.urlhaus_id == "u-shared"
    assert summary.entity.source_observations[1].threatfox.threatfox_id == "t-shared"
    assert stats["multi_source_entity_count"] == 1
    assert stats["source_count"] == 2


def test_same_text_with_different_ioc_types_stays_separate():
    _, summaries, _ = process_source_records({
        "urlhaus": [_urlhaus("same-value", record_id="u-same")],
        "threatfox": [_threatfox("same-value", ioc_type="domain", record_id="t-same")],
    })

    assert len(summaries) == 2
    assert {(item.ioc_type, item.normalized_ioc_value) for item in summaries} == {
        ("url", "same-value"),
        ("domain", "same-value"),
    }
    assert all(not item.multi_source for item in summaries)


def test_conflicting_assertions_and_repeated_same_source_records_are_preserved():
    _, summaries, stats = process_source_records({
        "urlhaus": [
            _urlhaus("https://conflict.example/", record_id="u-one", threat="malware_download", tags=["uh-tag"]),
            _urlhaus("https://conflict.example/", record_id="u-two", threat="phishing", tags=["other-tag"]),
        ],
        "threatfox": [_threatfox(
            "https://conflict.example/", record_id="t-one", threat="botnet_cc", family="FamilyB"
        )],
    })

    assert len(summaries) == 1
    summary = summaries[0]
    assert summary.observation_count == 3
    assert summary.threat_types == ["botnet_cc", "malware_download", "phishing"]
    assert summary.malware_families == ["FamilyB"]
    assert summary.threat_type_agreement is False
    assert {item.source_record_id for item in summary.entity.source_observations} == {"u-one", "u-two", "t-one"}
    assert summary.aggregated_tags == ["other-tag", "tf-tag", "uh-tag"]
    assert stats["observation_count"] == 3
    assert stats["source_context_coverage"]["threatfox"]["context_field_coverage"]["confidence"] == 1


def test_missing_optional_context_is_valid_and_counted():
    minimal = _urlhaus("https://minimal.example", record_id="u-minimal")
    minimal.update({"threat": None, "tags": [], "reporter": None, "urlhaus_link": None})
    _, summaries, stats = process_source_records({"urlhaus": [minimal]})

    assert summaries[0].source_count == 1
    assert summaries[0].threat_types == []
    assert summaries[0].entity.source_observations[0].urlhaus.urlhaus_link is None
    assert stats["threat_context_coverage"]["observations_with_context"] == 0


def test_invalid_threatfox_type_fails_clearly_in_multi_source_pipeline():
    record = _threatfox("value", ioc_type="unknown-kind")
    with pytest.raises(ValueError, match="Unsupported ThreatFox IOC type"):
        process_source_records({"threatfox": [record]})
