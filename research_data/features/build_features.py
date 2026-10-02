"""Build deterministic research features from correlated CTI entities.

The module does not create labels, predictions, or risk scores. Raw IOC values
are preserved only as entity identity; model-facing identity features use type,
length, and character-shape counts. Full source-specific details remain in the
input correlation artifact, while rows retain source lineage and raw assertions.
"""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from statistics import mean
from typing import Any

from research_data.correlation import CorrelationSummary


RESEARCH_DATA_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = Path(__file__).resolve().parents[2]
FEATURE_DIR = Path(__file__).resolve().parent
FEATURE_SCHEMA_FILE = FEATURE_DIR / "feature_schema.json"
DEFAULT_INPUT = RESEARCH_DATA_DIR / "unified" / "research_pipeline_results.json"
DEFAULT_OUTPUT = RESEARCH_DATA_DIR / "urlhaus" / "urlhaus_research_features.json"
DEFAULT_PROFILE = FEATURE_DIR / "urlhaus_feature_profile.json"

FEATURE_SCHEMA = json.loads(FEATURE_SCHEMA_FILE.read_text(encoding="utf-8"))
FEATURE_COLUMNS = tuple(FEATURE_SCHEMA["feature_columns"])
IOC_TYPES = (
    "ipv4", "ipv6", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256",
    "cve", "email", "ip:port",
)


def build_feature_row(summary: CorrelationSummary) -> dict[str, Any]:
    """Return one row without modifying or flattening its underlying entity."""

    if not isinstance(summary, CorrelationSummary):
        raise ValueError("Feature generation expects a CorrelationSummary object.")
    entity = summary.entity
    value = entity.normalized_ioc_value
    observations = entity.source_observations
    sources = set(summary.source_names)
    reporters = {item.reporter for item in observations if item.reporter}
    tag_count = sum(len(item.tags or []) for item in observations)
    confidence_available = summary.confidence_observation_count > 0
    temporal_coverage = (
        summary.earliest_timestamp is not None
        and summary.latest_timestamp is not None
    )

    features: dict[str, Any] = {
        "ioc_type": summary.ioc_type,
        "value_length": len(value),
        "character_alpha_count": sum(character.isalpha() for character in value),
        "character_digit_count": sum(character.isdigit() for character in value),
        "character_non_alphanumeric_count": sum(not character.isalnum() for character in value),
        "has_dot": "." in value,
        "has_slash": "/" in value,
        "has_colon": ":" in value,
        "has_hyphen": "-" in value,
        "has_at_sign": "@" in value,
        "observation_count": summary.observation_count,
        "distinct_source_count": summary.source_count,
        "multi_source": summary.multi_source,
        "source_diversity_ratio": round(summary.source_count / summary.observation_count, 6) if summary.observation_count else 0.0,
        "repeated_observation": summary.observation_count > summary.source_count,
        "source_urlhaus": "urlhaus" in sources,
        "source_threatfox": "threatfox" in sources,
        "distinct_reporter_count": len(reporters),
        "distinct_threat_type_count": summary.threat_type_count,
        "distinct_malware_family_count": summary.malware_family_count,
        "threat_context_available": summary.observations_with_threat_context > 0,
        "context_richness": summary.context_richness,
        "tag_count": tag_count,
        "distinct_tag_count": len(summary.aggregated_tags),
        "confidence_available": confidence_available,
        "confidence_min": summary.confidence_min,
        "confidence_max": summary.confidence_max,
        "confidence_mean": summary.confidence_mean,
        "confidence_source_count": len(summary.confidence_by_source),
        "earliest_observation_timestamp": summary.earliest_timestamp,
        "latest_observation_timestamp": summary.latest_timestamp,
        "temporal_span_seconds": summary.temporal_span_seconds,
        "temporal_coverage": temporal_coverage,
        "observations_with_timestamps": summary.observations_with_timestamps,
    }
    # Explicit boolean indicators for each schema IOC type.
    for ioc_type in IOC_TYPES:
        column = f"type_{ioc_type.replace(':', '_')}"
        features[column] = summary.ioc_type == ioc_type

    # Keep schema order stable even if implementation dictionary order changes.
    features = {column: features[column] for column in FEATURE_COLUMNS}
    source_provenance = [
        {
            "source": observation.source,
            "source_record_id": observation.source_record_id,
            "source_reference": observation.source_reference,
            "reporter": observation.reporter,
        }
        for observation in observations
    ]
    raw_context_assertions = [
        {
            "source": observation.source,
            "source_record_id": observation.source_record_id,
            "threat_type": observation.threat_type,
            "malware_family": observation.malware_family,
            "confidence": observation.confidence,
            "tags": list(observation.tags or []),
        }
        for observation in observations
    ]
    return {
        "entity_identity": {
            "ioc_type": entity.ioc_type,
            "normalized_ioc_value": entity.normalized_ioc_value,
        },
        "features": features,
        "source_provenance": source_provenance,
        "raw_context_assertions": raw_context_assertions,
        "target": None,
    }


def build_feature_rows(
    summaries: list[CorrelationSummary],
) -> list[dict[str, Any]]:
    """Build rows in the same order as the correlation summaries."""

    if not isinstance(summaries, list):
        raise ValueError("Correlation summaries must be provided as a list.")
    return [build_feature_row(summary) for summary in summaries]


def summarize_feature_rows(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate row/column counts, missingness, and descriptive distributions."""

    missing_values = {
        column: sum(row["features"][column] is None for row in rows)
        for column in FEATURE_COLUMNS
    }
    categorical_distributions: dict[str, dict[str, int]] = {}
    for column in ("ioc_type", "multi_source", "repeated_observation", "source_urlhaus", "source_threatfox", "threat_context_available", "confidence_available", "temporal_coverage"):
        counts = Counter(str(row["features"][column]) for row in rows)
        categorical_distributions[column] = dict(sorted(counts.items()))

    numeric_distributions: dict[str, dict[str, int | float | None]] = {}
    for column, spec in FEATURE_SCHEMA["feature_columns"].items():
        if spec["type"] not in {"integer", "number"}:
            continue
        values = [row["features"][column] for row in rows if row["features"][column] is not None]
        numeric_distributions[column] = {
            "available_count": len(values),
            "missing_count": len(rows) - len(values),
            "minimum": min(values) if values else None,
            "maximum": max(values) if values else None,
            "mean": round(mean(values), 6) if values else None,
        }

    return {
        "feature_row_count": len(rows),
        "feature_column_count": len(FEATURE_COLUMNS),
        "feature_columns": list(FEATURE_COLUMNS),
        "missing_value_count_by_feature": missing_values,
        "categorical_distributions": categorical_distributions,
        "numeric_distributions": numeric_distributions,
        "target_defined": False,
        "rows_with_assigned_target": sum(row.get("target") is not None for row in rows),
        "rows_with_risk_score_feature": sum("risk_score" in row["features"] for row in rows),
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _path_label(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def run_feature_pipeline(
    input_file: Path = DEFAULT_INPUT,
    output_file: Path = DEFAULT_OUTPUT,
    profile_file: Path = DEFAULT_PROFILE,
) -> dict[str, Any]:
    """Generate deterministic feature rows from the correlation JSON artifact."""

    input_file, output_file, profile_file = map(Path, (input_file, output_file, profile_file))
    if not input_file.is_file():
        raise FileNotFoundError(f"Correlated research input not found: {input_file}")
    with input_file.open("r", encoding="utf-8-sig") as file:
        payload = json.load(file)
    if not isinstance(payload, list):
        raise ValueError("Correlated research input must be a JSON array.")
    summaries: list[CorrelationSummary] = []
    for index, item in enumerate(payload):
        try:
            summaries.append(CorrelationSummary.model_validate(item))
        except Exception as error:
            raise ValueError(f"Invalid correlation summary at index {index}: {error}") from error

    rows = build_feature_rows(summaries)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    temporary_output = output_file.with_suffix(output_file.suffix + ".tmp")
    with temporary_output.open("w", encoding="utf-8", newline="\n") as file:
        file.write("[\n")
        for index, row in enumerate(rows):
            if index:
                file.write(",\n")
            json.dump(row, file, ensure_ascii=False, separators=(",", ":"))
        file.write("\n]\n")
    temporary_output.replace(output_file)

    profile = {
        "status": "completed",
        "input_file": _path_label(input_file),
        "input_sha256": _sha256_file(input_file),
        "output_file": _path_label(output_file),
        "output_sha256": _sha256_file(output_file),
        "feature_schema_file": _path_label(FEATURE_SCHEMA_FILE),
        "identity_rule": ["ioc_type", "normalized_ioc_value"],
        "target_defined": False,
        "urlhaus_threat_used_as_target": False,
        "risk_score_included": False,
        "statistics": summarize_feature_rows(rows),
        "interpretation": (
            "Feature preparation only. No target, model, prediction, or performance result was generated."
        ),
    }
    profile_file.parent.mkdir(parents=True, exist_ok=True)
    temporary_profile = profile_file.with_suffix(profile_file.suffix + ".tmp")
    temporary_profile.write_text(json.dumps(profile, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary_profile.replace(profile_file)
    return profile


def main() -> None:
    parser = argparse.ArgumentParser(description="Build leakage-conscious CTI research features.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    args = parser.parse_args()
    profile = run_feature_pipeline(args.input, args.output, args.profile)
    print(json.dumps(profile["statistics"], indent=2))
    print(f"Feature profile: {args.profile}")
    print(f"Feature rows: {args.output}")


if __name__ == "__main__":
    main()
