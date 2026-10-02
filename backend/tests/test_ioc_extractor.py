import pytest

from app.services.ioc_extractor import extract_iocs


def test_extracts_supported_types_with_exact_positions_and_method():
    text = (
        "Visit https://bad.example/path, email ops@evil.example; "
        "IP 192.0.2.4 hash " + "a" * 32 + " " + "b" * 40 + " " + "c" * 64
        + " CVE-2024-12345 and domain malware.example"
    )
    candidates = extract_iocs(text)
    assert {item["indicator_type"] for item in candidates} == {
        "url", "email", "ipv4", "hash_md5", "hash_sha1", "hash_sha256", "cve", "domain"
    }
    for item in candidates:
        assert text[item["start"]:item["end"]] == item["value"]
        assert item["extraction_method"] == "rule-based IOC extraction"
    assert not any(item["value"] == "bad.example" for item in candidates)
    assert not any(item["value"] == "evil.example" for item in candidates)


def test_invalid_ipv4_is_not_returned_and_urls_trim_sentence_punctuation():
    found = extract_iocs("Bad 999.1.1.1; use https://host.example/path.")
    assert not any(item["indicator_type"] == "ipv4" for item in found)
    url = next(item for item in found if item["indicator_type"] == "url")
    assert url["value"] == "https://host.example/path"


def test_extraction_requires_text():
    with pytest.raises(TypeError, match="input must be text"):
        extract_iocs(None)
