import pytest

from research_data.entity_resolution import resolve_entities
from research_data.unified.schema import (
    SourceObservation,
    UnifiedResearchRecord,
)


def make_record(
    *,
    ioc_type="domain",
    value="Example.test",
    normalized="example.test",
    source="urlhaus",
    source_record_id="record-1",
    threat_type="malware_download",
    malware_family=None,
    confidence=None,
    tags=None,
    first_seen=None,
    additional_fields=None,
):
    source_fields = {}
    if source == "urlhaus":
        source_fields["urlhaus"] = {"urlhaus_id": source_record_id}
    elif source == "threatfox":
        source_fields["threatfox"] = {"threatfox_id": source_record_id}

    observation = SourceObservation(
        source=source,
        source_record_id=source_record_id,
        source_reference=f"https://source.test/{source_record_id}",
        reporter=f"reporter-{source}",
        source_ioc_value=value,
        threat_type=threat_type,
        malware_family=malware_family,
        confidence=confidence,
        tags=tags,
        first_seen=first_seen,
        additional_fields=additional_fields or {},
        **source_fields,
    )
    return UnifiedResearchRecord(
        ioc_value=value,
        normalized_ioc_value=normalized,
        ioc_type=ioc_type,
        source_observations=[observation],
    )


def test_same_typed_ioc_from_different_sources_resolves_to_one_entity():
    records = [
        make_record(source="urlhaus", source_record_id="u-1"),
        make_record(source="threatfox", source_record_id="t-1"),
    ]

    [entity] = resolve_entities(records)

    assert (entity.ioc_type, entity.normalized_ioc_value) == (
        "domain",
        "example.test",
    )
    assert [observation.source for observation in entity.source_observations] == [
        "urlhaus",
        "threatfox",
    ]
    assert [observation.source_record_id for observation in entity.source_observations] == [
        "u-1",
        "t-1",
    ]
    assert [observation.source_reference for observation in entity.source_observations] == [
        "https://source.test/u-1",
        "https://source.test/t-1",
    ]
    assert [observation.reporter for observation in entity.source_observations] == [
        "reporter-urlhaus",
        "reporter-threatfox",
    ]


def test_same_text_with_different_ioc_types_stays_separate():
    records = [
        make_record(ioc_type="domain", value="example.test", normalized="example.test"),
        make_record(ioc_type="url", value="example.test", normalized="example.test"),
    ]

    entities = resolve_entities(records)

    assert len(entities) == 2
    assert {entity.ioc_type for entity in entities} == {"domain", "url"}


def test_repeated_same_source_observations_with_distinct_ids_are_preserved():
    records = [
        make_record(source_record_id="u-1", first_seen="2026-01-01"),
        make_record(source_record_id="u-2", first_seen="2026-01-02"),
    ]

    [entity] = resolve_entities(records)

    assert len(entity.source_observations) == 2
    assert [observation.source_record_id for observation in entity.source_observations] == [
        "u-1",
        "u-2",
    ]
    assert [observation.first_seen for observation in entity.source_observations] == [
        "2026-01-01",
        "2026-01-02",
    ]


def test_different_normalized_values_resolve_to_separate_entities():
    records = [
        make_record(normalized="one.example"),
        make_record(normalized="two.example", source_record_id="u-2"),
    ]

    entities = resolve_entities(records)

    assert len(entities) == 2
    assert {entity.normalized_ioc_value for entity in entities} == {
        "one.example",
        "two.example",
    }


def test_conflicting_context_and_provenance_remain_on_separate_assertions():
    records = [
        make_record(
            source="urlhaus",
            source_record_id="u-1",
            threat_type="malware_download",
            tags=["tag-a"],
            additional_fields={"status_note": "first"},
        ),
        make_record(
            source="threatfox",
            source_record_id="t-1",
            threat_type="botnet_cc",
            malware_family="Family B",
            confidence=92,
            tags=["tag-b"],
            first_seen="2026-02-01",
            additional_fields={"source_note": "second"},
        ),
        make_record(
            source="threatfox",
            source_record_id="t-2",
            threat_type="botnet_cc",
            malware_family="Family C",
            confidence=55,
            tags=["tag-c"],
            first_seen="2026-02-02",
            additional_fields={"source_note": "third"},
        ),
    ]

    [entity] = resolve_entities(records)

    first, second, third = entity.source_observations
    assert first.threat_type == "malware_download"
    assert first.tags == ["tag-a"]
    assert first.additional_fields == {"status_note": "first"}
    assert first.urlhaus.urlhaus_id == "u-1"
    assert second.threat_type == "botnet_cc"
    assert second.malware_family == "Family B"
    assert second.confidence == 92
    assert second.tags == ["tag-b"]
    assert second.first_seen == "2026-02-01"
    assert second.source_record_id == "t-1"
    assert second.additional_fields == {"source_note": "second"}
    assert second.threatfox.threatfox_id == "t-1"
    assert third.threat_type == "botnet_cc"
    assert third.malware_family == "Family C"
    assert third.confidence == 55
    assert third.tags == ["tag-c"]
    assert third.first_seen == "2026-02-02"
    assert third.source_record_id == "t-2"
    assert third.additional_fields == {"source_note": "third"}


def test_unsupported_ioc_type_fails_clearly():
    invalid = UnifiedResearchRecord.model_construct(
        ioc_value="example.test",
        normalized_ioc_value="example.test",
        ioc_type="unsupported-type",
        source_observations=[SourceObservation(source="urlhaus")],
    )

    with pytest.raises(ValueError, match="(?s)Invalid unified research record.*ioc_type"):
        resolve_entities([invalid])


def test_non_unified_input_fails_clearly():
    with pytest.raises(ValueError, match="expects UnifiedResearchRecord"):
        resolve_entities([{"ioc_type": "domain"}])
