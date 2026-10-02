"""Join engineered feature rows to independent target rows for A/B/C experiments.

The join key is exactly ``(ioc_type, normalized_ioc_value)``. A missing target
row becomes ``unknown``; no label is inferred. Target evidence and source
provenance are retained outside the model-facing ``features`` dictionary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
RESEARCH_DATA = ROOT / "research_data"
FEATURE_DIR = RESEARCH_DATA / "features"
FEATURE_SCHEMA_PATH = FEATURE_DIR / "feature_schema.json"
SPEC_PATH = FEATURE_DIR / "experiment_spec.json"
TARGET_SCHEMA_PATH = RESEARCH_DATA / "targets" / "target_schema.json"
DATASET_SCHEMA_PATH = Path(__file__).resolve().parent / "experiment_dataset_schema.json"
DEFAULT_FEATURES = RESEARCH_DATA / "urlhaus" / "urlhaus_research_features.json"
DEFAULT_TARGETS = RESEARCH_DATA / "targets" / "urlhaus_target_rows.json"
DEFAULT_OUTPUT_DIR = RESEARCH_DATA / "urlhaus"
DEFAULT_PROFILE = Path(__file__).resolve().parent / "urlhaus_experiment_profile.json"

IOC_TYPES = {
    "ipv4", "ipv6", "domain", "url", "hash_md5", "hash_sha1",
    "hash_sha256", "cve", "email", "ip:port",
}
EXPERIMENT_IDS = ("A", "B", "C")
TARGET_VALUES = {"positive", "negative", "unknown"}


def _identity(row: dict[str, Any], label: str) -> tuple[str, str]:
    identity = row.get("entity_identity")
    if not isinstance(identity, dict):
        raise ValueError(f"{label} row must contain entity_identity.")
    ioc_type = identity.get("ioc_type")
    value = identity.get("normalized_ioc_value")
    if ioc_type not in IOC_TYPES:
        raise ValueError(f"{label} row has unsupported IOC type: {ioc_type!r}.")
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} row has an empty normalized_ioc_value.")
    return ioc_type, value


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _index_rows(rows: list[dict[str, Any]], label: str) -> dict[tuple[str, str], dict[str, Any]]:
    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{label} row at index {index} must be an object.")
        key = _identity(row, label)
        if key in indexed:
            if _canonical_json(indexed[key]) != _canonical_json(row):
                raise ValueError(
                    f"Conflicting duplicate {label} rows for typed identity {key!r}."
                )
            # Exact duplicate rows are safely collapsed. Conflicting duplicates
            # fail rather than selecting a label or feature row arbitrarily.
            continue
        indexed[key] = row
    return indexed


def _feature_columns_by_experiment(feature_schema: dict[str, Any]) -> dict[str, list[str]]:
    columns = feature_schema.get("feature_columns")
    if not isinstance(columns, dict) or not columns:
        raise ValueError("Feature schema must declare feature_columns.")
    groups = {name: value.get("group") for name, value in columns.items()}
    if any(group not in {"A", "B", "C"} for group in groups.values()):
        raise ValueError("Every feature column must belong to group A, B, or C.")
    return {
        "A": [name for name, group in groups.items() if group == "A"],
        "B": [name for name, group in groups.items() if group in {"A", "B"}],
        "C": [name for name, group in groups.items() if group in {"A", "B", "C"}],
    }


def _validate_target(row: dict[str, Any], key: tuple[str, str]) -> None:
    if row.get("target") not in TARGET_VALUES:
        raise ValueError(f"Target row for {key!r} must have positive, negative, or unknown target.")
    if row.get("entity_identity") != {
        "ioc_type": key[0], "normalized_ioc_value": key[1]
    }:
        raise ValueError(f"Target row identity does not match typed identity {key!r}.")


def build_experiment_datasets(
    feature_rows: list[dict[str, Any]],
    target_rows: list[dict[str, Any]] | None = None,
    *,
    feature_schema: dict[str, Any] | None = None,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    """Build identical-entity A/B/C row sets with experiment-specific inputs.

    Exact duplicate input rows collapse deterministically. Conflicting rows for
    the same typed identity are rejected, preventing arbitrary label selection.
    Unmatched feature rows get an unknown target and empty outcome evidence.
    """

    if not isinstance(feature_rows, list):
        raise ValueError("feature_rows must be a list.")
    target_rows = [] if target_rows is None else target_rows
    if not isinstance(target_rows, list):
        raise ValueError("target_rows must be a list.")
    if feature_schema is None:
        feature_schema = json.loads(FEATURE_SCHEMA_PATH.read_text(encoding="utf-8"))
    columns = _feature_columns_by_experiment(feature_schema)
    expected = set(feature_schema["feature_columns"])

    feature_index = _index_rows(feature_rows, "feature")
    target_index = _index_rows(target_rows, "target")
    for key, row in feature_index.items():
        features = row.get("features")
        if not isinstance(features, dict) or set(features) != expected:
            raise ValueError(f"Feature row for {key!r} does not match the feature schema columns.")
        if row.get("target") not in (None, "unknown"):
            raise ValueError("Feature rows may not carry assigned targets; use target_rows separately.")
    for key, row in target_index.items():
        _validate_target(row, key)

    datasets: dict[str, list[dict[str, Any]]] = {name: [] for name in EXPERIMENT_IDS}
    target_counts: Counter[str] = Counter()
    source_row_counts: Counter[str] = Counter()
    source_observation_counts: Counter[str] = Counter()
    unmatched_targets = sorted(set(target_index) - set(feature_index))
    for key in sorted(feature_index):
        feature_row = feature_index[key]
        row_sources = {
            item.get("source")
            for item in feature_row.get("source_provenance", [])
            if isinstance(item, dict) and isinstance(item.get("source"), str) and item["source"]
        }
        source_row_counts.update(row_sources)
        source_observation_counts.update(
            item["source"]
            for item in feature_row.get("source_provenance", [])
            if isinstance(item, dict) and isinstance(item.get("source"), str) and item["source"]
        )
        target_row = target_index.get(key)
        if target_row is None:
            target_value = "unknown"
            target_reason = "no_target_row_for_typed_identity"
            prediction_window = None
            evidence = []
        else:
            target_value = target_row["target"]
            target_reason = target_row.get("target_reason", "")
            prediction_window = target_row.get("prediction_window")
            evidence = target_row.get("outcome_evidence", [])
            if not isinstance(evidence, list):
                raise ValueError(f"outcome_evidence for {key!r} must be a list.")
            feature_sources = {
                item.get("source")
                for item in feature_row.get("source_provenance", [])
                if isinstance(item, dict) and isinstance(item.get("source"), str)
            }
            target_sources = {
                item.get("source")
                for item in evidence
                if isinstance(item, dict) and isinstance(item.get("source"), str)
            }
            overlapping_sources = feature_sources & target_sources
            if overlapping_sources:
                raise ValueError(
                    f"Target source(s) {sorted(overlapping_sources)!r} also occur in feature provenance "
                    f"for {key!r}; rebuild inputs without target-source evidence before assembling experiments."
                )
        target_counts[target_value] += 1
        common = {
            "schema_version": "1.0",
            "entity_identity": {
                "ioc_type": key[0],
                "normalized_ioc_value": key[1],
            },
            "target": target_value,
            "target_metadata": {
                "reason": target_reason,
                "prediction_window": prediction_window,
                "outcome_evidence": evidence,
            },
            "source_provenance": feature_row.get("source_provenance", []),
            "raw_context_assertions": feature_row.get("raw_context_assertions", []),
        }
        for experiment_id in EXPERIMENT_IDS:
            selected = {name: feature_row["features"][name] for name in columns[experiment_id]}
            datasets[experiment_id].append({
                **common,
                "experiment_id": experiment_id,
                "features": selected,
            })

    summary = {
        "entity_identity": ["ioc_type", "normalized_ioc_value"],
        "input_feature_row_count": len(feature_rows),
        "unique_feature_identity_count": len(feature_index),
        "input_target_row_count": len(target_rows),
        "unique_target_identity_count": len(target_index),
        "unmatched_target_identity_count": len(unmatched_targets),
        "unmatched_target_identities": [
            {"ioc_type": item[0], "normalized_ioc_value": item[1]}
            for item in unmatched_targets
        ],
        "experiment_feature_counts": {name: len(columns[name]) for name in EXPERIMENT_IDS},
        "experiment_row_counts": {name: len(datasets[name]) for name in EXPERIMENT_IDS},
        "feature_source_row_coverage": dict(sorted(source_row_counts.items())),
        "feature_source_observation_coverage": dict(sorted(source_observation_counts.items())),
        "target_counts_per_experiment": {
            name: {target: target_counts[target] for target in ("positive", "negative", "unknown")}
            for name in EXPERIMENT_IDS
        },
        "labeled_count_per_experiment": {
            name: target_counts["positive"] + target_counts["negative"]
            for name in EXPERIMENT_IDS
        },
        "unlabeled_count_per_experiment": {
            name: target_counts["unknown"] for name in EXPERIMENT_IDS
        },
        "class_balance_per_experiment": {
            name: {
                "positive": target_counts["positive"],
                "negative": target_counts["negative"],
                "unknown": target_counts["unknown"],
                "labeled_positive_fraction": (
                    round(target_counts["positive"] / (target_counts["positive"] + target_counts["negative"]), 6)
                    if target_counts["positive"] + target_counts["negative"] else None
                ),
            }
            for name in EXPERIMENT_IDS
        },
        "feature_source_record_count": len(feature_rows),
        "target_source_record_count": len(target_rows),
        "model_trained": False,
        "metrics_calculated": False,
    }
    return datasets, summary


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json_array(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("[\n")
        for index, row in enumerate(rows):
            if index:
                handle.write(",\n")
            json.dump(row, handle, ensure_ascii=False, separators=(",", ":"))
        handle.write("\n]\n")
    temporary.replace(path)


def run_experiment_dataset_pipeline(
    feature_file: Path = DEFAULT_FEATURES,
    target_file: Path | None = None,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    profile_file: Path = DEFAULT_PROFILE,
) -> dict[str, Any]:
    """Run the dataset join. If no target file exists, rows remain unknown."""

    feature_file = Path(feature_file)
    target_file = Path(target_file) if target_file is not None else DEFAULT_TARGETS
    output_dir, profile_file = Path(output_dir), Path(profile_file)
    if not feature_file.is_file():
        raise FileNotFoundError(f"Feature rows not found: {feature_file}")
    feature_rows = json.loads(feature_file.read_text(encoding="utf-8-sig"))
    if not isinstance(feature_rows, list):
        raise ValueError("Feature input must be a JSON array.")
    targets_available = target_file.is_file()
    target_rows = json.loads(target_file.read_text(encoding="utf-8-sig")) if targets_available else []
    if not isinstance(target_rows, list):
        raise ValueError("Target input must be a JSON array.")
    datasets, summary = build_experiment_datasets(feature_rows, target_rows)

    output_hashes: dict[str, str] = {}
    output_names: dict[str, str] = {}
    for experiment_id, rows in datasets.items():
        output = output_dir / f"urlhaus_experiment_{experiment_id}.json"
        _write_json_array(output, rows)
        output_names[experiment_id] = output.relative_to(ROOT).as_posix() if output.is_relative_to(ROOT) else str(output)
        output_hashes[experiment_id] = _sha256(output)

    def label(path: Path) -> str:
        return path.relative_to(ROOT).as_posix() if path.is_relative_to(ROOT) else str(path)

    profile = {
        "status": "completed",
        "dataset_scope": "URLhaus feature snapshot joined to independent target rows when present",
        "feature_input": label(feature_file),
        "feature_input_sha256": _sha256(feature_file),
        "target_input": label(target_file) if targets_available else None,
        "target_input_sha256": _sha256(target_file) if targets_available else None,
        "target_input_available": targets_available,
        "feature_schema": label(FEATURE_SCHEMA_PATH),
        "experiment_spec": label(SPEC_PATH),
        "target_schema": label(TARGET_SCHEMA_PATH),
        "dataset_schema": label(DATASET_SCHEMA_PATH),
        "outputs": {
            key: {"path": output_names[key], "sha256": output_hashes[key]}
            for key in EXPERIMENT_IDS
        },
        "statistics": summary,
        "interpretation": (
            "Dataset assembly only. Unknown means no qualifying target row was supplied; "
            "it is not a negative label. No model or performance result was generated."
        ),
    }
    profile_file.parent.mkdir(parents=True, exist_ok=True)
    temp_profile = profile_file.with_suffix(profile_file.suffix + ".tmp")
    temp_profile.write_text(json.dumps(profile, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp_profile.replace(profile_file)
    return profile


def main() -> None:
    parser = argparse.ArgumentParser(description="Assemble leakage-conscious CTIP A/B/C experiment datasets.")
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    parser.add_argument("--targets", type=Path, default=None, help="Optional output of research_data.targets.build_targets.")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    args = parser.parse_args()
    profile = run_experiment_dataset_pipeline(args.features, args.targets, args.output_dir, args.profile)
    print(json.dumps(profile["statistics"], indent=2))
    print(f"Experiment profile: {args.profile}")


if __name__ == "__main__":
    main()
