import pytest
from pydantic import ValidationError

from app.api.analysis import ExtractionRequest, extract_iocs_from_text


def test_extraction_api_returns_method_count_and_candidates():
    result = extract_iocs_from_text(
        ExtractionRequest(text="See https://malware.example/a and CVE-2024-12345")
    )
    assert result["method"] == "rule-based IOC extraction"
    assert result["count"] == len(result["candidates"]) == 2
    assert {item["indicator_type"] for item in result["candidates"]} == {"url", "cve"}


def test_extraction_api_limits_empty_and_oversized_text():
    with pytest.raises(ValidationError):
        ExtractionRequest(text="")
    with pytest.raises(ValidationError):
        ExtractionRequest(text="x" * 100001)
