"""Build provenance-aware quality profiles for local ThreatFox exports."""

import json
from collections import Counter
from pathlib import Path
from typing import Any

from research_data.threatfox.normalize import (
    METADATA_FILE,
    NORMALIZED_FILE,
    RAW_FILE,
    TYPES_FILE,
    PREPROCESSING_OPERATIONS,
    normalize_file,
)


SOURCE_URL = "https://threatfox-api.abuse.ch/api/v1/"
ACCESS_METHOD = (
    "Official ThreatFox Community API: HTTPS POST query=get_iocs with days=1..7; "
    "IOC-type validation uses the documented query=types response. Auth-Key is required."
)


def distribution(records: list[dict[str, Any]], field: str) -> dict[str, int]:
    counts = Counter(
        str(record[field])
        for record in records
        if record.get(field) not in (None, "")
    )
    return dict(sorted(counts.items()))


def build_profile(
    raw_response: dict[str, Any],
    normalized: list[dict[str, Any]],
    quality: dict[str, Any],
    collection_timestamp: str | None = None,
    days_requested: int | None = None,
) -> dict[str, Any]:
    raw_records = raw_response.get("data") or []
    if not isinstance(raw_records, list):
        raw_records = []

    missing_fields = [
        "threatfox_id",
        "ioc",
        "ioc_type",
        "ioc_type_description",
        "threat_type",
        "threat_type_description",
        "malware_family",
        "malware_printable",
        "malware_alias",
        "malware_malpedia",
        "confidence_level",
        "first_seen",
        "last_seen",
        "reporter",
        "reference",
        "tags",
    ]
    missing_values = {
        field: sum(
            record.get(field) is None
            or record.get(field) == ""
            or record.get(field) == []
            for record in normalized
        )
        for field in missing_fields
    }
    reporter_counts = distribution(normalized, "reporter")
    tag_counts = Counter(
        tag for record in normalized for tag in record.get("tags", [])
    )

    return {
        "dataset": "ThreatFox",
        "source": "ThreatFox Community API",
        "source_url": SOURCE_URL,
        "access_method": ACCESS_METHOD,
        "authentication_required": True,
        "collection_timestamp": collection_timestamp,
        "days_requested": days_requested,
        "status": "profiled" if collection_timestamp else "profiled_local_data",
        "raw_record_count": len(raw_records),
        "normalized_record_count": len(normalized),
        "malformed_record_count": len(quality["malformed_records"]),
        "ioc_type_distribution": distribution(normalized, "ioc_type"),
        "threat_type_distribution": distribution(normalized, "threat_type"),
        "malware_family_distribution": distribution(normalized, "malware_family"),
        "reporter_distribution": reporter_counts,
        "unique_reporter_count": len(reporter_counts),
        "tag_distribution": dict(tag_counts.most_common()),
        "missing_value_counts": missing_values,
        "duplicate_counts": {
            "duplicate_identifiers": quality["duplicate_identifier_count"],
            "duplicate_iocs": quality["duplicate_ioc_count"],
        },
        "missing_identifier_count": quality["missing_identifier_count"],
        "missing_ioc_count": quality["missing_ioc_count"],
        "missing_ioc_type_count": quality["missing_ioc_type_count"],
        "unknown_ioc_type_count": len(quality["unknown_ioc_types"]),
        "ioc_type_catalog_available": quality[
            "ioc_type_validation_performed"
        ],
        "unknown_ioc_types": quality["unknown_ioc_types"],
        "normalization_consistency_failures": quality[
            "normalization_consistency_failures"
        ],
        "preprocessing": PREPROCESSING_OPERATIONS,
        "data_quality": {
            "malformed_records": quality["malformed_records"],
            "missing_identifiers": quality["missing_identifier_count"],
            "unknown_ioc_types": quality["unknown_ioc_types"],
            "normalization_consistency_failures": quality[
                "normalization_consistency_failures"
            ],
        },
    }


def write_profile(
    raw_file: Path = RAW_FILE,
    types_file: Path = TYPES_FILE,
    normalized_file: Path = NORMALIZED_FILE,
    metadata_file: Path = METADATA_FILE,
) -> dict[str, Any]:
    if not raw_file.exists():
        raise FileNotFoundError(
            f"ThreatFox raw export not found: {raw_file}. Run fetch.py first."
        )

    with raw_file.open("r", encoding="utf-8") as file:
        raw_response = json.load(file)
    previous_metadata = {}
    if metadata_file.exists():
        with metadata_file.open("r", encoding="utf-8") as file:
            previous_metadata = json.load(file)

    normalized, quality = normalize_file(
        raw_file=raw_file,
        output_file=normalized_file,
        types_file=types_file,
    )
    profile = build_profile(
        raw_response,
        normalized,
        quality,
        collection_timestamp=previous_metadata.get("collection_timestamp"),
        days_requested=previous_metadata.get("days_requested"),
    )
    metadata_file.parent.mkdir(parents=True, exist_ok=True)
    with metadata_file.open("w", encoding="utf-8") as file:
        json.dump(profile, file, indent=2, ensure_ascii=False)
    return profile


def main() -> None:
    profile = write_profile()
    print(f"ThreatFox raw records: {profile['raw_record_count']}")
    print(f"ThreatFox normalized records: {profile['normalized_record_count']}")
    print(f"ThreatFox duplicate IOCs: {profile['duplicate_counts']['duplicate_iocs']}")


if __name__ == "__main__":
    main()
