import pytest
from pydantic import ValidationError

from research_data.sources import ThreatFoxAdapter, URLhausAdapter
from research_data.threatfox.normalize import normalize_record as normalize_threatfox
from research_data.urlhaus.normalize import normalize_record as normalize_urlhaus


def test_urlhaus_adapter_maps_normalized_record_and_preserves_provenance():
    normalized = normalize_urlhaus(
        "123456",
        {
            "url": " HTTPS://Example.test/Path ",
            "dateadded": "2026-09-25 12:00:00 UTC",
            "url_status": "online",
            "last_online": "2026-09-26 12:00:00 UTC",
            "threat": "malware_download",
            "tags": ["test-tag"],
            "urlhaus_link": "https://urlhaus.abuse.ch/url/123456/",
            "reporter": "researcher-x",
        },
    )

    mapped = URLhausAdapter().adapt(normalized)
    observation = mapped.source_observations[0]

    assert mapped.ioc_type == "url"
    assert mapped.ioc_value == "HTTPS://Example.test/Path"
    assert mapped.normalized_ioc_value == "HTTPS://Example.test/Path"
    assert observation.source == "urlhaus"
    assert observation.source_record_id == "123456"
    assert observation.source_reference == "https://urlhaus.abuse.ch/url/123456/"
    assert observation.reporter == "researcher-x"
    assert observation.threat_type == "malware_download"
    assert observation.tags == ["test-tag"]
    assert observation.urlhaus.url == mapped.ioc_value
    assert observation.urlhaus.date_added == "2026-09-25 12:00:00 UTC"
    assert observation.urlhaus.last_online == "2026-09-26 12:00:00 UTC"
    assert observation.first_seen is None
    assert observation.last_seen is None
    assert observation.confidence is None
    assert len(mapped.source_observations) == 1


def test_urlhaus_optional_fields_and_unknown_fields_are_preserved():
    normalized = normalize_urlhaus("42", {"url": "https://example.test/"})
    normalized["source_extension"] = {"evidence": "preserved"}

    observation = URLhausAdapter().adapt(normalized).source_observations[0]

    assert observation.reporter is None
    assert observation.threat_type is None
    assert observation.tags == []
    assert observation.urlhaus.date_added is None
    assert observation.additional_fields == {
        "source_extension": {"evidence": "preserved"}
    }


def test_threatfox_adapter_maps_normalized_record_and_preserves_context():
    normalized = normalize_threatfox({
        "id": 987,
        "ioc": "Example.Test",
        "ioc_type": "DOMAIN",
        "ioc_type_desc": "domain",
        "threat_type": "botnet_cc",
        "threat_type_desc": "Botnet C&C",
        "malware": "ExampleFamily",
        "malware_printable": "Example Family",
        "malware_alias": "Alias",
        "malware_malpedia": "malpedia-entry",
        "confidence_level": 85,
        "first_seen": "2026-09-20 00:00:00 UTC",
        "last_seen": "2026-09-21 00:00:00 UTC",
        "reporter": "researcher-y",
        "reference": "https://example.test/reference",
        "tags": ["tag-a", "tag-b"],
        "new_source_field": "preserved",
    })

    mapped = ThreatFoxAdapter().adapt(normalized)
    observation = mapped.source_observations[0]

    assert mapped.ioc_type == "domain"
    assert mapped.ioc_value == "Example.Test"
    assert mapped.normalized_ioc_value == "example.test"
    assert observation.source == "threatfox"
    assert observation.source_record_id == "987"
    assert observation.source_reference == "https://example.test/reference"
    assert observation.reporter == "researcher-y"
    assert observation.threat_type == "botnet_cc"
    assert observation.malware_family == "ExampleFamily"
    assert observation.confidence == 85
    assert observation.first_seen == "2026-09-20 00:00:00 UTC"
    assert observation.last_seen == "2026-09-21 00:00:00 UTC"
    assert observation.tags == ["tag-a", "tag-b"]
    assert observation.threatfox.malware_alias == "Alias"
    assert observation.threatfox.malware_malpedia == "malpedia-entry"
    assert observation.threatfox.additional_fields["new_source_field"] == "preserved"
    assert len(mapped.source_observations) == 1


def test_threatfox_hash_type_maps_to_unified_type_using_source_normalizer():
    normalized = normalize_threatfox({
        "id": 3,
        "ioc": " ABCD ",
        "ioc_type": "md5_hash",
    })

    mapped = ThreatFoxAdapter().adapt(normalized)

    assert mapped.ioc_type == "hash_md5"
    assert mapped.normalized_ioc_value == "abcd"


def test_threatfox_missing_optional_context_stays_missing():
    normalized = normalize_threatfox({
        "ioc": "203.0.113.7",
        "ioc_type": "ipv4",
    })

    observation = ThreatFoxAdapter().adapt(normalized).source_observations[0]

    assert observation.source_record_id is None
    assert observation.source_reference is None
    assert observation.reporter is None
    assert observation.threat_type is None
    assert observation.malware_family is None
    assert observation.confidence is None
    assert observation.tags == []
    assert observation.first_seen is None
    assert observation.last_seen is None


@pytest.mark.parametrize(
    "adapter,record,message",
    [
        (URLhausAdapter(), [], "must be a JSON object"),
        (URLhausAdapter(), {"url": " "}, "non-empty 'url'"),
        (
            ThreatFoxAdapter(),
            {"ioc": "x", "ioc_type": "unknown", "normalized_ioc": "x"},
            "Unsupported ThreatFox IOC type",
        ),
        (
            ThreatFoxAdapter(),
            {"ioc": "Example.Test", "ioc_type": "domain", "normalized_ioc": "Example.Test"},
            "does not match",
        ),
    ],
)
def test_invalid_records_fail_clearly(adapter, record, message):
    with pytest.raises((ValueError, ValidationError), match=message):
        adapter.adapt(record)
