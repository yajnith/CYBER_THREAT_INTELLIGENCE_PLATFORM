import pytest

from research_data.correlation import correlate_entity
from research_data.unified.schema import SourceObservation, UnifiedResearchRecord


def make_entity(observations):
    return UnifiedResearchRecord(
        ioc_value="https://example.test/a",
        normalized_ioc_value="https://example.test/a",
        ioc_type="url",
        source_observations=observations,
    )


def observation(
    source="urlhaus",
    *,
    record_id="record-1",
    threat_type=None,
    malware_family=None,
    confidence=None,
    tags=None,
    first_seen=None,
    last_seen=None,
    observation_timestamp=None,
    urlhaus=None,
    threatfox=None,
):
    return SourceObservation(
        source=source,
        source_record_id=record_id,
        threat_type=threat_type,
        malware_family=malware_family,
        confidence=confidence,
        tags=tags,
        first_seen=first_seen,
        last_seen=last_seen,
        observation_timestamp=observation_timestamp,
        urlhaus=urlhaus,
        threatfox=threatfox,
    )


def test_one_observation_from_one_source_has_expected_base_features():
    entity = make_entity([observation(threat_type="malware_download")])

    summary = correlate_entity(entity)

    assert summary.ioc_type == "url"
    assert summary.normalized_ioc_value == "https://example.test/a"
    assert summary.observation_count == 1
    assert summary.source_record_count == 1
    assert summary.source_count == 1
    assert summary.source_names == ["urlhaus"]
    assert summary.multi_source is False
    assert summary.threat_types == ["malware_download"]
    assert summary.context_dimensions == ["threat_type"]
    assert summary.context_richness == 1


def test_same_ioc_with_two_sources_is_marked_multi_source():
    summary = correlate_entity(make_entity([
        observation(record_id="u1"),
        observation("threatfox", record_id="t1"),
    ]))

    assert summary.source_names == ["threatfox", "urlhaus"]
    assert summary.source_count == 2
    assert summary.multi_source is True
    assert summary.context_richness == 1
    assert [item.source_record_id for item in summary.entity.source_observations] == [
        "u1",
        "t1",
    ]


def test_agreeing_threat_context_is_reported_without_flattening_observations():
    summary = correlate_entity(make_entity([
        observation(threat_type="malware_download", tags=["loader", "elf"]),
        observation(
            "threatfox",
            threat_type="malware_download",
            tags=["elf", "linux"],
        ),
    ]))

    assert summary.threat_types == ["malware_download"]
    assert summary.threat_type_agreement is True
    assert summary.aggregated_tags == ["elf", "linux", "loader"]
    assert summary.shared_tags == ["elf"]
    assert len(summary.entity.source_observations) == 2
    assert [item.tags for item in summary.entity.source_observations] == [
        ["loader", "elf"],
        ["elf", "linux"],
    ]


def test_conflicting_threat_context_is_explicit_and_preserved():
    summary = correlate_entity(make_entity([
        observation(
            threat_type="malware_download",
            malware_family="Family A",
            confidence=70,
            tags=["tag-a"],
        ),
        observation(
            "threatfox",
            threat_type="botnet_cc",
            malware_family="Family B",
            confidence=90,
            tags=["tag-b"],
        ),
    ]))

    assert summary.threat_types == ["botnet_cc", "malware_download"]
    assert summary.threat_type_count == 2
    assert summary.threat_type_agreement is False
    assert summary.malware_families == ["Family A", "Family B"]
    assert summary.malware_family_agreement is False
    assert summary.confidence_agreement is False
    assert summary.aggregated_tags == ["tag-a", "tag-b"]
    assert summary.shared_tags == []
    assert [item.threat_type for item in summary.entity.source_observations] == [
        "malware_download",
        "botnet_cc",
    ]


def test_multiple_malware_families_are_counted():
    summary = correlate_entity(make_entity([
        observation(malware_family="Family A"),
        observation("threatfox", malware_family="Family B"),
    ]))

    assert summary.malware_families == ["Family A", "Family B"]
    assert summary.malware_family_count == 2


def test_missing_optional_context_has_empty_aggregates():
    summary = correlate_entity(make_entity([
        observation(record_id=None, urlhaus={"url": "https://example.test/a"}),
    ]))

    assert summary.source_record_count == 0
    assert summary.observations_without_record_id == 1
    assert summary.threat_types == []
    assert summary.malware_families == []
    assert summary.aggregated_tags == []
    assert summary.confidence_mean is None
    assert summary.observations_with_threat_context == 0
    assert summary.context_richness == 0
    assert summary.entity.source_observations[0].urlhaus.url == "https://example.test/a"


def test_timestamp_bounds_and_span_use_available_temporal_fields():
    summary = correlate_entity(make_entity([
        observation(first_seen="2026-01-01T00:00:00Z"),
        observation(
            "threatfox",
            observation_timestamp="2026-01-01T00:01:30Z",
            last_seen="2026-01-01T00:02:00Z",
        ),
    ]))

    assert summary.earliest_timestamp == "2026-01-01T00:00:00Z"
    assert summary.latest_timestamp == "2026-01-01T00:02:00Z"
    assert summary.temporal_span_seconds == 120.0
    assert summary.observations_with_timestamps == 2
    assert summary.unparseable_timestamp_count == 0
    assert "temporal" in summary.context_dimensions
    assert summary.context_richness == 2  # temporal plus source diversity


def test_confidence_is_aggregated_by_source_and_across_observations():
    summary = correlate_entity(make_entity([
        observation(confidence=40),
        observation(record_id="record-2", confidence=80),
        observation("threatfox", confidence=100),
    ]))

    assert summary.confidence_by_source == {
        "threatfox": [100],
        "urlhaus": [40, 80],
    }
    assert summary.confidence_observation_count == 3
    assert summary.confidence_min == 40
    assert summary.confidence_max == 100
    assert summary.confidence_mean == 73.33
    assert summary.confidence_agreement is False


def test_timestamp_timezone_mixture_does_not_claim_a_span():
    summary = correlate_entity(make_entity([
        observation(first_seen="2026-01-01T00:00:00Z"),
        observation("threatfox", first_seen="2026-01-01T00:00:00"),
    ]))

    assert summary.timestamp_timezone_conflict is True
    assert summary.earliest_timestamp is None
    assert summary.latest_timestamp is None
    assert summary.temporal_span_seconds is None


def test_invalid_entity_input_fails_clearly():
    with pytest.raises(ValueError, match="expects a UnifiedResearchRecord"):
        correlate_entity({"ioc_type": "url"})
