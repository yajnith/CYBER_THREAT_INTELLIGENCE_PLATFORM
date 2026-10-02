import pytest
from pydantic import ValidationError

from research_data.unified.schema import UnifiedResearchRecord


def test_common_identity_and_provenance_fields_validate_and_are_preserved():
    record = UnifiedResearchRecord.model_validate({
        "ioc_value": "example.test",
        "normalized_ioc_value": "example.test",
        "ioc_type": "domain",
        "source_observations": [
            {
                "source": "urlhaus",
                "source_record_id": "synthetic-urlhaus-id-1",
                "source_reference": "https://example.test/source-reference",
                "reporter": "synthetic-reporter",
                "source_ioc_value": "example.test",
                "threat_type": "malware_download",
                "tags": ["synthetic-tag"],
                "urlhaus": {
                    "urlhaus_id": "synthetic-urlhaus-id-1",
                    "url": "example.test",
                    "date_added": "2026-01-01 00:00:00 UTC",
                },
            }
        ],
    })

    observation = record.source_observations[0]
    assert record.ioc_type == "domain"
    assert observation.source_record_id == "synthetic-urlhaus-id-1"
    assert observation.source_reference == "https://example.test/source-reference"
    assert observation.reporter == "synthetic-reporter"
    assert observation.urlhaus.date_added == "2026-01-01 00:00:00 UTC"


def test_source_specific_optional_context_can_be_missing():
    record = UnifiedResearchRecord.model_validate({
        "ioc_value": "https://example.test/path",
        "normalized_ioc_value": "https://example.test/path",
        "ioc_type": "url",
        "source_observations": [
            {"source": "urlhaus"},
            {"source": "threatfox"},
        ],
    })

    assert record.source_observations[0].confidence is None
    assert record.source_observations[0].threat_type is None
    assert record.source_observations[0].urlhaus is None
    assert record.source_observations[1].threatfox is None


def test_threatfox_specific_context_is_optional_and_preserved():
    record = UnifiedResearchRecord.model_validate({
        "ioc_value": "203.0.113.10:443",
        "normalized_ioc_value": "203.0.113.10:443",
        "ioc_type": "ip:port",
        "source_observations": [
            {
                "source": "threatfox",
                "source_record_id": "synthetic-threatfox-id-1",
                "threatfox": {
                    "threatfox_id": "synthetic-threatfox-id-1",
                    "ioc": "203.0.113.10:443",
                    "ioc_type": "ip:port",
                    "malware_family": "synthetic-family",
                    "additional_fields": {"synthetic_context": "preserved"},
                },
            }
        ],
    })

    threatfox = record.source_observations[0].threatfox
    assert threatfox.ioc_type == "ip:port"
    assert threatfox.malware_family == "synthetic-family"
    assert threatfox.additional_fields == {"synthetic_context": "preserved"}


def test_invalid_ioc_type_is_rejected():
    with pytest.raises(ValidationError):
        UnifiedResearchRecord.model_validate({
            "ioc_value": "example.test",
            "normalized_ioc_value": "example.test",
            "ioc_type": "invented_type",
            "source_observations": [{"source": "urlhaus"}],
        })
