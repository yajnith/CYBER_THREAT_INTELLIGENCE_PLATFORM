"""Run available normalized CTI sources through the research pipeline.

The historical module name and URLhaus-only wrapper are retained for callers
of the first pipeline milestone. The default execution now also reads a real
normalized ThreatFox file when one exists; absence is recorded explicitly.
"""

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from research_data.correlation import CorrelationSummary, correlate_entities
from research_data.entity_resolution import resolve_entities
from research_data.sources.threatfox import ThreatFoxAdapter
from research_data.sources.urlhaus import URLhausAdapter
from research_data.unified.schema import UnifiedResearchRecord


RESEARCH_DATA_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = Path(__file__).resolve().parents[2]
URLHAUS_DIR = RESEARCH_DATA_DIR / "urlhaus"
THREATFOX_DIR = RESEARCH_DATA_DIR / "threatfox"
THREATFOX_METADATA = THREATFOX_DIR / "metadata.json"
DEFAULT_INPUT = URLHAUS_DIR / "urlhaus_normalized.json"
DEFAULT_THREATFOX_INPUT = THREATFOX_DIR / "threatfox_normalized.json"
DEFAULT_OUTPUT = RESEARCH_DATA_DIR / "unified" / "research_pipeline_results.json"
DEFAULT_METADATA = Path(__file__).with_name("urlhaus_pipeline_metadata.json")
DEFAULT_SOURCE_METADATA = URLHAUS_DIR / "metadata.json"

ADAPTERS = {
    "urlhaus": URLhausAdapter,
    "threatfox": ThreatFoxAdapter,
}


def process_source_records(
    source_records: dict[str, list[dict[str, Any]]],
) -> tuple[list[UnifiedResearchRecord], list[CorrelationSummary], dict[str, Any]]:
    """Adapt, resolve, and correlate normalized records from named sources.

    Source input order and record order are retained. Repeated source records
    are passed through unchanged so the resolver preserves every observation.
    """

    if not isinstance(source_records, dict) or not source_records:
        raise ValueError("Source records must be a non-empty source-to-records mapping.")

    adapted_records: list[UnifiedResearchRecord] = []
    normalized_counts: dict[str, int] = {}
    for source_name, records in source_records.items():
        if source_name not in ADAPTERS:
            raise ValueError(f"Unsupported research source: {source_name!r}.")
        if not isinstance(records, list):
            raise ValueError(f"Normalized {source_name} input must be a JSON array.")
        normalized_counts[source_name] = len(records)
        adapter = ADAPTERS[source_name]()
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                raise ValueError(
                    f"Normalized {source_name} record at index {index} must be an object."
                )
            adapted_records.append(adapter.adapt(record))

    resolved_entities = resolve_entities(adapted_records)
    summaries = correlate_entities(resolved_entities)
    statistics = build_statistics(
        normalized_counts, adapted_records, resolved_entities, summaries
    )
    return resolved_entities, summaries, statistics


def process_normalized_records(
    records: list[dict[str, Any]],
) -> tuple[list[UnifiedResearchRecord], list[CorrelationSummary], dict[str, Any]]:
    """Compatibility wrapper for the earlier URLhaus-only pipeline API."""

    return process_source_records({"urlhaus": records})


def build_statistics(
    normalized_counts: dict[str, int],
    adapted_records: list[UnifiedResearchRecord],
    resolved_entities: list[UnifiedResearchRecord],
    summaries: list[CorrelationSummary],
) -> dict[str, Any]:
    """Produce source-aware deterministic coverage and correlation statistics."""

    observations = [
        observation
        for entity in resolved_entities
        for observation in entity.source_observations
    ]
    threat_counts = Counter(
        observation.threat_type
        for observation in observations
        if observation.threat_type
    )
    malware_counts = Counter(
        observation.malware_family
        for observation in observations
        if observation.malware_family
    )
    source_names = sorted({observation.source for observation in observations})
    source_record_ids = sum(
        observation.source_record_id is not None for observation in observations
    )
    references = sum(
        observation.source_reference is not None for observation in observations
    )
    reporters = {observation.reporter for observation in observations if observation.reporter}
    observations_with_context = sum(
        summary.observations_with_threat_context for summary in summaries
    )
    observations_with_tags = sum(bool(observation.tags) for observation in observations)
    observations_with_confidence = sum(
        observation.confidence is not None for observation in observations
    )
    observations_with_seen_fields = sum(
        bool(observation.first_seen or observation.last_seen or observation.observation_timestamp)
        for observation in observations
    )
    source_specific_time_fields: dict[str, dict[str, int]] = {}
    source_context: dict[str, dict[str, Any]] = {}
    for source in source_names:
        source_observations = [item for item in observations if item.source == source]
        if source == "urlhaus":
            timestamp_fields = {
                "date_added": sum(bool(item.urlhaus and item.urlhaus.date_added) for item in source_observations),
                "last_online": sum(bool(item.urlhaus and item.urlhaus.last_online) for item in source_observations),
            }
            context_fields = {
                "threat_type": sum(bool(item.threat_type) for item in source_observations),
                "tags": sum(bool(item.tags) for item in source_observations),
                "date_added": timestamp_fields["date_added"],
                "last_online": timestamp_fields["last_online"],
                "url_status": sum(bool(item.urlhaus and item.urlhaus.url_status) for item in source_observations),
            }
        else:
            timestamp_fields = {
                "first_seen": sum(bool(item.threatfox and item.threatfox.first_seen) for item in source_observations),
                "last_seen": sum(bool(item.threatfox and item.threatfox.last_seen) for item in source_observations),
            }
            context_fields = {
                "threat_type": sum(bool(item.threat_type) for item in source_observations),
                "malware_family": sum(bool(item.malware_family) for item in source_observations),
                "confidence": sum(item.confidence is not None for item in source_observations),
                "tags": sum(bool(item.tags) for item in source_observations),
                "first_seen": timestamp_fields["first_seen"],
                "last_seen": timestamp_fields["last_seen"],
            }
        source_specific_time_fields[source] = timestamp_fields
        source_context[source] = {
            "observation_count": len(source_observations),
            "observations_with_record_id": sum(item.source_record_id is not None for item in source_observations),
            "observations_with_reference": sum(item.source_reference is not None for item in source_observations),
            "observations_with_reporter": sum(item.reporter is not None for item in source_observations),
            "context_field_coverage": context_fields,
            "source_specific_timestamp_coverage": timestamp_fields,
        }

    richness_counts = Counter(summary.context_richness for summary in summaries)
    identity_keys = {(entity.ioc_type, entity.normalized_ioc_value) for entity in resolved_entities}
    return {
        "normalized_input_record_count": sum(normalized_counts.values()),
        "normalized_records_by_source": dict(sorted(normalized_counts.items())),
        "adapted_record_count": len(adapted_records),
        "resolved_entity_count": len(resolved_entities),
        "unique_ioc_type_identity_count": len(identity_keys),
        "observation_count": len(observations),
        "source_record_count": len(observations),
        "source_count": len(source_names),
        "source_names": source_names,
        "single_source_entity_count": sum(summary.source_count == 1 for summary in summaries),
        "multi_source_entity_count": sum(summary.multi_source for summary in summaries),
        "source_record_id_coverage": {
            "observations_with_record_id": source_record_ids,
            "observations_without_record_id": len(observations) - source_record_ids,
        },
        "source_reference_coverage": {
            "observations_with_reference": references,
            "observations_without_reference": len(observations) - references,
        },
        "reporter_coverage": {
            "observations_with_reporter": sum(observation.reporter is not None for observation in observations),
            "distinct_reporter_count": len(reporters),
        },
        "threat_context_coverage": {
            "observations_with_context": observations_with_context,
            "observations_without_context": len(observations) - observations_with_context,
            "entities_with_context": sum(summary.observations_with_threat_context > 0 for summary in summaries),
            "threat_type_distribution": dict(sorted(threat_counts.items())),
            "distinct_threat_type_count": len(threat_counts),
            "malware_family_distribution": dict(sorted(malware_counts.items())),
            "distinct_malware_family_count": len(malware_counts),
        },
        "tag_coverage": {
            "observations_with_tags": observations_with_tags,
            "observations_without_tags": len(observations) - observations_with_tags,
            "entities_with_tags": sum(bool(summary.aggregated_tags) for summary in summaries),
            "distinct_tag_count": len({tag for observation in observations for tag in (observation.tags or [])}),
        },
        "confidence_coverage": {
            "observations_with_confidence": observations_with_confidence,
            "observations_without_confidence": len(observations) - observations_with_confidence,
            "entities_with_confidence": sum(summary.confidence_observation_count > 0 for summary in summaries),
            "minimum": min((item.confidence for item in observations if item.confidence is not None), default=None),
            "maximum": max((item.confidence for item in observations if item.confidence is not None), default=None),
            "mean": round(sum(item.confidence for item in observations if item.confidence is not None) / observations_with_confidence, 2) if observations_with_confidence else None,
        },
        "temporal_coverage": {
            "observations_with_seen_timestamp_fields": observations_with_seen_fields,
            "entities_with_correlation_temporal_bounds": sum(summary.earliest_timestamp is not None for summary in summaries),
            "source_specific_timestamp_coverage": source_specific_time_fields,
            "urlhaus_observations_with_date_added": source_specific_time_fields.get("urlhaus", {}).get("date_added", 0),
            "urlhaus_observations_with_last_online": source_specific_time_fields.get("urlhaus", {}).get("last_online", 0),
        },
        "source_context_coverage": source_context,
        "context_richness_distribution": {str(value): richness_counts[value] for value in sorted(richness_counts)},
    }


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as file:
        return json.load(file)


def _metadata_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(path)


def _write_result_records(path: Path, summaries: list[CorrelationSummary]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as file:
        file.write("[\n")
        for index, summary in enumerate(summaries):
            if index:
                file.write(",\n")
            json.dump(summary.model_dump(mode="json"), file, ensure_ascii=False)
        file.write("\n]\n")


def run_multi_source_pipeline(
    urlhaus_file: Path = DEFAULT_INPUT,
    threatfox_file: Path = DEFAULT_THREATFOX_INPUT,
    output_file: Path = DEFAULT_OUTPUT,
    metadata_file: Path = DEFAULT_METADATA,
    urlhaus_metadata_file: Path = DEFAULT_SOURCE_METADATA,
    threatfox_metadata_file: Path = THREATFOX_METADATA,
) -> dict[str, Any]:
    """Run URLhaus and any locally available normalized ThreatFox records."""

    urlhaus_file = Path(urlhaus_file)
    threatfox_file = Path(threatfox_file)
    if not urlhaus_file.is_file():
        raise FileNotFoundError(f"Normalized URLhaus dataset not found: {urlhaus_file}")
    urlhaus_records = _load_json(urlhaus_file)
    if not isinstance(urlhaus_records, list):
        raise ValueError("Normalized URLhaus input must be a JSON array.")

    threatfox_metadata = _load_json(Path(threatfox_metadata_file)) if Path(threatfox_metadata_file).is_file() else {}
    source_records: dict[str, list[dict[str, Any]]] = {"urlhaus": urlhaus_records}
    source_status: dict[str, dict[str, Any]] = {
        "urlhaus": {"status": "processed", "normalized_record_count": len(urlhaus_records), "input_file": _metadata_path(urlhaus_file)}
    }
    if threatfox_file.is_file():
        threatfox_records = _load_json(threatfox_file)
        if not isinstance(threatfox_records, list):
            raise ValueError("Normalized ThreatFox input must be a JSON array.")
        source_records["threatfox"] = threatfox_records
        source_status["threatfox"] = {
            "status": "processed",
            "normalized_record_count": len(threatfox_records),
            "input_file": _metadata_path(threatfox_file),
        }
    else:
        source_status["threatfox"] = {
            "status": threatfox_metadata.get("status", "not_collected"),
            "normalized_record_count": 0,
            "input_file": None,
            "note": "No normalized ThreatFox dataset file was present; no ThreatFox records were used.",
        }

    resolved, summaries, statistics = process_source_records(source_records)
    output_file = Path(output_file)
    metadata_file = Path(metadata_file)
    source_metadata = _load_json(Path(urlhaus_metadata_file)) if Path(urlhaus_metadata_file).is_file() else {}
    _write_result_records(output_file, summaries)

    multiple_source_datasets = sum(bool(records) for records in source_records.values()) > 1
    metadata = {
        "pipeline": "multi-source research adapters, typed entity resolution, and correlation",
        "status": "completed",
        "pipeline_run_timestamp": datetime.now(timezone.utc).isoformat(),
        "included_sources": statistics["source_names"],
        "source_status": source_status,
        "source_collection_timestamps": {
            "urlhaus": source_metadata.get("collection_timestamp"),
            "threatfox": threatfox_metadata.get("collection_timestamp"),
        },
        "input_files": {source: details["input_file"] for source, details in source_status.items()},
        "input_sha256": {
            source: hashlib.sha256(Path(details["input_file"]).read_bytes()).hexdigest()
            for source, details in source_status.items()
            if details["input_file"] is not None
        },
        "output_file": _metadata_path(output_file),
        "output_format": "JSON array of correlation summaries with embedded unified entities and source observations",
        "identity_rule": ["ioc_type", "normalized_ioc_value"],
        "threatfox_status": source_status["threatfox"]["status"],
        "multiple_source_datasets_included": multiple_source_datasets,
        "empirical_cross_source_results_available": multiple_source_datasets,
        "statistics": statistics,
        "interpretation": (
            "URLhaus and ThreatFox normalized datasets were processed. Cross-source results are based only on the records actually loaded."
            if multiple_source_datasets
            else "URLhaus-only execution. ThreatFox is not collected or unavailable; no cross-source results are claimed."
        ),
    }
    metadata_file.parent.mkdir(parents=True, exist_ok=True)
    temporary_metadata = metadata_file.with_suffix(metadata_file.suffix + ".tmp")
    with temporary_metadata.open("w", encoding="utf-8") as file:
        json.dump(metadata, file, indent=2, ensure_ascii=False)
        file.write("\n")
    temporary_metadata.replace(metadata_file)
    return metadata


def run_urlhaus_pipeline(
    input_file: Path = DEFAULT_INPUT,
    output_file: Path = DEFAULT_OUTPUT,
    metadata_file: Path = DEFAULT_METADATA,
    source_metadata_file: Path = DEFAULT_SOURCE_METADATA,
    threatfox_file: Path = DEFAULT_THREATFOX_INPUT,
    threatfox_metadata_file: Path = THREATFOX_METADATA,
) -> dict[str, Any]:
    """Compatibility wrapper; defaults still discover optional ThreatFox data."""

    return run_multi_source_pipeline(
        urlhaus_file=input_file,
        threatfox_file=threatfox_file,
        output_file=output_file,
        metadata_file=metadata_file,
        urlhaus_metadata_file=source_metadata_file,
        threatfox_metadata_file=threatfox_metadata_file,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run available normalized CTI datasets through the research pipeline."
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="normalized URLhaus JSON")
    parser.add_argument("--threatfox-input", type=Path, default=DEFAULT_THREATFOX_INPUT, help="optional normalized ThreatFox JSON")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--metadata", type=Path, default=DEFAULT_METADATA)
    args = parser.parse_args()

    metadata = run_multi_source_pipeline(
        urlhaus_file=args.input,
        threatfox_file=args.threatfox_input,
        output_file=args.output,
        metadata_file=args.metadata,
    )
    print(json.dumps(metadata["statistics"], indent=2))
    print(f"Pipeline metadata: {args.metadata}")
    print(f"Pipeline results: {args.output}")


if __name__ == "__main__":
    main()
