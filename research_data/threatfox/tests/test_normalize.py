import json

from research_data.threatfox.normalize import normalize_file, normalize_records
from research_data.threatfox.profile import build_profile


def test_normalization_preserves_context_and_tracks_quality():
    source_records = [
        {
            "id": "1001",
            "ioc": " Example.COM ",
            "ioc_type": "domain",
            "ioc_type_desc": "Domain IOC",
            "threat_type": "botnet_cc",
            "threat_type_desc": "Botnet command and control",
            "malware": "win.examplefamily",
            "malware_printable": "Example Family",
            "malware_alias": None,
            "malware_malpedia": "https://example.test/malware",
            "confidence_level": 85,
            "first_seen": "2026-09-20 10:00:00 UTC",
            "last_seen": None,
            "reporter": "researcher_a",
            "reference": "https://example.test/report",
            "tags": [" botnet ", "c2"],
            "malware_samples": [{"sha256_hash": "abc123"}],
        },
        {
            "id": "1001",
            "ioc": "example.com",
            "ioc_type": "domain",
            "threat_type": "botnet_cc",
            "reporter": "researcher_a",
        },
        {
            "ioc": "suspicious-value",
            "ioc_type": "vendor_new_type",
            "threat_type": "unknown_context",
        },
        "malformed record",
    ]

    normalized, quality = normalize_records(
        source_records,
        known_ioc_types={"domain", "url"},
    )

    assert len(normalized) == 3
    assert normalized[0]["threatfox_id"] == "1001"
    assert normalized[0]["ioc"] == "Example.COM"
    assert normalized[0]["normalized_ioc"] == "example.com"
    assert normalized[0]["ioc_type_description"] == "Domain IOC"
    assert normalized[0]["malware_family"] == "win.examplefamily"
    assert normalized[0]["confidence_level"] == 85
    assert normalized[0]["first_seen"] == "2026-09-20 10:00:00 UTC"
    assert normalized[0]["last_seen"] is None
    assert normalized[0]["reporter"] == "researcher_a"
    assert normalized[0]["reference"] == "https://example.test/report"
    assert normalized[0]["tags"] == ["botnet", "c2"]
    assert normalized[0]["additional_fields"]["malware_samples"] == [
        {"sha256_hash": "abc123"}
    ]
    assert quality["duplicate_identifier_count"] == 1
    assert quality["duplicate_ioc_count"] == 1
    assert quality["missing_identifier_count"] == 1
    assert quality["unknown_ioc_types"] == [
        {
            "index": 2,
            "ioc_type": "vendor_new_type",
            "threatfox_id": None,
        }
    ]
    assert quality["malformed_records"] == [
        {"index": 3, "reason": "Record must be a JSON object."}
    ]
    assert quality["normalization_consistency_failures"] == 0


def test_file_normalization_and_profile_are_provenance_aware(tmp_path):
    records = [
        {
            "id": "2001",
            "ioc": "192.0.2.10",
            "ioc_type": "ip:port",
            "threat_type": "payload_delivery",
            "malware": "win.sample",
            "confidence_level": 70,
            "first_seen": "2026-09-21 12:00:00 UTC",
            "reporter": "researcher_b",
            "tags": None,
        }
    ]
    raw_file = tmp_path / "raw.json"
    types_file = tmp_path / "types.json"
    normalized_file = tmp_path / "normalized.json"
    raw_file.write_text(
        json.dumps({"query_status": "ok", "data": records}),
        encoding="utf-8",
    )
    types_file.write_text(
        json.dumps({
            "query_status": "ok",
            "data": {"1": {"ioc_type": "ip:port"}},
        }),
        encoding="utf-8",
    )

    normalized, quality = normalize_file(
        raw_file=raw_file,
        output_file=normalized_file,
        types_file=types_file,
    )
    profile = build_profile(
        {"data": records},
        normalized,
        quality,
        collection_timestamp="2026-09-22T00:00:00+00:00",
        days_requested=7,
    )

    assert json.loads(normalized_file.read_text(encoding="utf-8")) == normalized
    assert profile["collection_timestamp"] == "2026-09-22T00:00:00+00:00"
    assert profile["raw_record_count"] == 1
    assert profile["normalized_record_count"] == 1
    assert profile["ioc_type_distribution"] == {"ip:port": 1}
    assert profile["threat_type_distribution"] == {"payload_delivery": 1}
    assert profile["malware_family_distribution"] == {"win.sample": 1}
    assert profile["reporter_distribution"] == {"researcher_b": 1}
    assert profile["missing_value_counts"]["last_seen"] == 1
    assert profile["missing_value_counts"]["reference"] == 1
    assert profile["duplicate_counts"]["duplicate_iocs"] == 0
    assert profile["unknown_ioc_type_count"] == 0
    assert profile["ioc_type_catalog_available"] is True
