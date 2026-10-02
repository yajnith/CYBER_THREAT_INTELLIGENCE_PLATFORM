"""Normalize documented ThreatFox Community API IOC records."""

import json
from pathlib import Path
from typing import Any, Iterable


DATA_DIR = Path(__file__).parent
RAW_FILE = DATA_DIR / "threatfox_raw.json"
TYPES_FILE = DATA_DIR / "threatfox_types.json"
NORMALIZED_FILE = DATA_DIR / "threatfox_normalized.json"
METADATA_FILE = DATA_DIR / "metadata.json"

NORMALIZED_FIELDS = {
    "id",
    "ioc",
    "ioc_type",
    "ioc_type_desc",
    "threat_type",
    "threat_type_desc",
    "malware",
    "malware_printable",
    "malware_alias",
    "malware_malpedia",
    "confidence_level",
    "first_seen",
    "last_seen",
    "reporter",
    "reference",
    "tags",
}

PREPROCESSING_OPERATIONS = [
    "Validated the API data array and retained malformed-record diagnostics.",
    "Trimmed IOC values and normalized IOC type names to lowercase.",
    "Lowercased domain IOCs and hash IOCs; retained other IOC value casing.",
    "Normalized null, scalar, and list tags to a list of trimmed strings.",
    "Mapped documented API fields to a stable schema; preserved unrecognized source fields in additional_fields.",
    "Kept source timestamps and references verbatim to preserve provenance.",
    "Counted duplicate IOC/type pairs without deleting records from the normalized output.",
]


def normalize_tags(tags: Any) -> list[str]:
    if tags is None:
        return []
    if isinstance(tags, list):
        values: Iterable[Any] = tags
    elif isinstance(tags, str):
        values = tags.split(",")
    else:
        values = [tags]
    return [str(tag).strip() for tag in values if str(tag).strip()]


def normalize_ioc_value(ioc_type: str, value: Any) -> str:
    normalized = str(value or "").strip()
    if ioc_type == "domain" or ioc_type in {
        "md5_hash",
        "sha1_hash",
        "sha256_hash",
    }:
        return normalized.lower()
    return normalized


def normalize_record(record: dict[str, Any]) -> dict[str, Any]:
    ioc_type = str(record.get("ioc_type") or "").strip().lower()
    ioc = str(record.get("ioc") or "").strip()
    return {
        "source_dataset": "ThreatFox",
        "threatfox_id": (
            str(record["id"]).strip()
            if record.get("id") not in (None, "")
            else None
        ),
        "ioc": ioc,
        "normalized_ioc": normalize_ioc_value(ioc_type, ioc),
        "ioc_type": ioc_type or None,
        "ioc_type_description": record.get("ioc_type_desc"),
        "threat_type": record.get("threat_type"),
        "threat_type_description": record.get("threat_type_desc"),
        "malware_family": record.get("malware"),
        "malware_printable": record.get("malware_printable"),
        "malware_alias": record.get("malware_alias"),
        "malware_malpedia": record.get("malware_malpedia"),
        "confidence_level": record.get("confidence_level"),
        "first_seen": record.get("first_seen"),
        "last_seen": record.get("last_seen"),
        "reporter": record.get("reporter"),
        "reference": record.get("reference"),
        "tags": normalize_tags(record.get("tags")),
        "additional_fields": {
            key: value
            for key, value in record.items()
            if key not in NORMALIZED_FIELDS
        },
    }


def normalize_records(
    records: Any,
    known_ioc_types: set[str] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if not isinstance(records, list):
        raise ValueError("ThreatFox API data must be a JSON array.")

    normalized: list[dict[str, Any]] = []
    malformed_records: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_iocs: set[tuple[str, str]] = set()
    duplicate_id_count = 0
    duplicate_ioc_count = 0
    unknown_ioc_types: list[dict[str, Any]] = []

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            malformed_records.append({
                "index": index,
                "reason": "Record must be a JSON object.",
            })
            continue

        item = normalize_record(record)
        normalized.append(item)

        identifier = item["threatfox_id"]
        if identifier:
            if identifier in seen_ids:
                duplicate_id_count += 1
            seen_ids.add(identifier)

        ioc_type = item["ioc_type"]
        normalized_ioc = item["normalized_ioc"]
        if known_ioc_types is not None and ioc_type and ioc_type not in known_ioc_types:
            unknown_ioc_types.append({
                "index": index,
                "ioc_type": ioc_type,
                "threatfox_id": identifier,
            })

        if ioc_type and normalized_ioc:
            ioc_key = (ioc_type, normalized_ioc)
            if ioc_key in seen_iocs:
                duplicate_ioc_count += 1
            seen_iocs.add(ioc_key)

    quality = {
        "malformed_records": malformed_records,
        "missing_identifier_count": sum(
            record.get("threatfox_id") is None for record in normalized
        ),
        "missing_ioc_count": sum(
            not record.get("ioc") for record in normalized
        ),
        "missing_ioc_type_count": sum(
            not record.get("ioc_type") for record in normalized
        ),
        "duplicate_identifier_count": duplicate_id_count,
        "duplicate_ioc_count": duplicate_ioc_count,
        "unknown_ioc_types": unknown_ioc_types,
        "ioc_type_validation_performed": known_ioc_types is not None,
        "normalization_consistency_failures": sum(
            record["normalized_ioc"]
            != normalize_ioc_value(record["ioc_type"] or "", record["ioc"])
            for record in normalized
        ),
    }
    return normalized, quality


def load_known_ioc_types(types_response: Any) -> set[str] | None:
    if not isinstance(types_response, dict):
        return None
    entries = types_response.get("data")
    if isinstance(entries, dict):
        candidates = entries.values()
    elif isinstance(entries, list):
        candidates = entries
    else:
        return None
    return {
        str(entry["ioc_type"]).strip().lower()
        for entry in candidates
        if isinstance(entry, dict) and entry.get("ioc_type")
    }


def normalize_file(
    raw_file: Path = RAW_FILE,
    output_file: Path = NORMALIZED_FILE,
    types_file: Path = TYPES_FILE,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    with raw_file.open("r", encoding="utf-8") as file:
        response = json.load(file)
    if not isinstance(response, dict) or response.get("query_status") not in {
        "ok",
        "no_result",
    }:
        raise ValueError("Raw file is not a successful ThreatFox API response.")

    types_response = None
    if types_file.exists():
        with types_file.open("r", encoding="utf-8") as file:
            types_response = json.load(file)
    known_types = load_known_ioc_types(types_response)
    raw_records = response.get("data") or []
    records, quality = normalize_records(raw_records, known_types)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with output_file.open("w", encoding="utf-8") as file:
        json.dump(records, file, indent=2, ensure_ascii=False)
    return records, quality
