"""Adapter for the existing normalized ThreatFox record format."""

from typing import Any

from research_data.sources.base import SourceAdapter
from research_data.threatfox.normalize import normalize_ioc_value
from research_data.unified.schema import (
    SourceObservation,
    ThreatFoxFields,
    UnifiedResearchRecord,
)


THREATFOX_TYPE_MAP = {
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "domain": "domain",
    "url": "url",
    "md5_hash": "hash_md5",
    "sha1_hash": "hash_sha1",
    "sha256_hash": "hash_sha256",
    "cve": "cve",
    "email": "email",
    "ip:port": "ip:port",
}


class ThreatFoxAdapter(SourceAdapter):
    source_name = "threatfox"

    def adapt(self, record: dict[str, Any]) -> UnifiedResearchRecord:
        record = self.require_mapping(record, self.source_name)
        ioc = record.get("ioc")
        if not isinstance(ioc, str) or not ioc.strip():
            raise ValueError("ThreatFox record requires a non-empty 'ioc'.")

        source_type = record.get("ioc_type")
        if not isinstance(source_type, str) or not source_type.strip():
            raise ValueError("ThreatFox record requires a non-empty 'ioc_type'.")
        source_type = source_type.strip().lower()
        unified_type = THREATFOX_TYPE_MAP.get(source_type)
        if unified_type is None:
            raise ValueError(
                f"Unsupported ThreatFox IOC type: {source_type!r}. "
                "Review the source type catalogue before adding a mapping."
            )

        expected_normalized = normalize_ioc_value(source_type, ioc)
        normalized_value = record.get("normalized_ioc")
        if not isinstance(normalized_value, str) or not normalized_value:
            raise ValueError(
                "ThreatFox normalized record requires a non-empty 'normalized_ioc'."
            )
        if normalized_value != expected_normalized:
            raise ValueError(
                "ThreatFox 'normalized_ioc' does not match the existing "
                "source normalizer output."
            )

        known_fields = set(ThreatFoxFields.model_fields)
        source_fields = {
            field: record[field]
            for field in known_fields
            if field in record
        }
        fields = ThreatFoxFields.model_validate(source_fields)
        additional_fields = dict(fields.additional_fields)
        additional_fields.update({
            key: value
            for key, value in record.items()
            if key not in known_fields
            and key not in {"source_dataset", "normalized_ioc"}
        })
        # Keep the source-provided additional_fields map intact, while unknown
        # top-level source properties remain visible in the same extension map.
        fields = fields.model_copy(update={"additional_fields": additional_fields})

        observation = SourceObservation(
            source=self.source_name,
            source_record_id=fields.threatfox_id,
            source_reference=fields.reference,
            reporter=fields.reporter,
            source_ioc_value=ioc,
            threat_type=fields.threat_type,
            malware_family=fields.malware_family,
            confidence=fields.confidence_level,
            tags=fields.tags,
            first_seen=fields.first_seen,
            last_seen=fields.last_seen,
            threatfox=fields,
        )

        return UnifiedResearchRecord(
            ioc_value=ioc,
            normalized_ioc_value=normalized_value,
            ioc_type=unified_type,
            source_observations=[observation],
        )
