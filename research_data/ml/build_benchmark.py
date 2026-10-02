"""Generate a deterministic controlled synthetic benchmark in CTIP feature space.

These rows are synthetic pipeline fixtures, not observed CTI and not ground
truth. Labels come from a hidden balanced latent class; features are noisy,
overlapping class-conditional draws. No rule-based CTIP risk score is used.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
FEATURE_SCHEMA_PATH = ROOT / "research_data" / "features" / "feature_schema.json"
DEFAULT_OUTPUT = Path(__file__).resolve().parent / "controlled_benchmark.json"
DEFAULT_SEED = 8137
DEFAULT_ROWS_PER_CLASS = 300
IOC_TYPE_VALUES = ("url", "domain", "ipv4", "hash_sha256")
IOC_TYPES = ("ipv4", "ipv6", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "cve", "email", "ip:port")


def _clip_int(value: float, low: int, high: int) -> int:
    return max(low, min(high, int(round(value))))


def _generate_features(rng: random.Random, positive: bool) -> dict[str, Any]:
    """Draw plausible, internally related features with class overlap."""

    positive_type_weights = (0.52, 0.24, 0.14, 0.10)
    negative_type_weights = (0.40, 0.30, 0.18, 0.12)
    ioc_type = rng.choices(
        IOC_TYPE_VALUES,
        weights=positive_type_weights if positive else negative_type_weights,
        k=1,
    )[0]
    mean_length = 48 if positive else 37
    value_length = _clip_int(rng.gauss(mean_length, 17), 16, 180)
    alpha_count = _clip_int(value_length * rng.uniform(0.42, 0.78), 0, value_length)
    digit_count = _clip_int(value_length * rng.uniform(0.04, 0.28), 0, value_length - alpha_count)
    other_count = value_length - alpha_count - digit_count

    # Synthetic correlation sources are only a schema/pipeline exercise. They
    # make no assertion that ThreatFox is locally acquired or observed here.
    source_count = rng.choices((1, 2), weights=(0.64, 0.36) if positive else (0.82, 0.18), k=1)[0]
    observation_count = source_count + rng.choices((0, 1, 2, 3), weights=(0.22, 0.42, 0.24, 0.12) if positive else (0.48, 0.32, 0.14, 0.06), k=1)[0]
    reporter_count = _clip_int(rng.gauss(2.2 if positive else 1.5, 1.0), 1, 6)

    threat_type_count = rng.choices((0, 1, 2, 3), weights=(0.10, 0.53, 0.29, 0.08) if positive else (0.38, 0.48, 0.12, 0.02), k=1)[0]
    malware_family_count = rng.choices((0, 1, 2), weights=(0.36, 0.50, 0.14) if positive else (0.78, 0.20, 0.02), k=1)[0]
    tag_count = _clip_int(rng.gauss(3.2 if positive else 1.5, 1.5), 0, 10)
    distinct_tag_count = min(tag_count, _clip_int(rng.gauss(tag_count * 0.78, 0.8), 0, 8))
    confidence_available = rng.random() < (0.80 if positive else 0.47)
    if confidence_available:
        confidence_min = _clip_int(rng.gauss(39 if positive else 31, 18), 0, 100)
        confidence_max = _clip_int(rng.gauss(78 if positive else 63, 16), confidence_min, 100)
        confidence_mean = round(rng.uniform(confidence_min, confidence_max), 3)
        confidence_source_count = rng.randint(1, source_count)
    else:
        confidence_min = confidence_max = confidence_mean = None
        confidence_source_count = 0

    threat_context_available = threat_type_count > 0 or malware_family_count > 0 or tag_count > 0 or confidence_available
    context_richness = sum((threat_type_count > 0, malware_family_count > 0, tag_count > 0, confidence_available))
    is_url = ioc_type == "url"
    has_dot = ioc_type in {"url", "domain", "email"}
    has_slash = is_url
    has_colon = is_url or ioc_type == "ip:port"
    has_hyphen = rng.random() < 0.31
    has_at_sign = ioc_type == "email"

    features: dict[str, Any] = {
        "ioc_type": ioc_type,
        "value_length": value_length,
        "character_alpha_count": alpha_count,
        "character_digit_count": digit_count,
        "character_non_alphanumeric_count": other_count,
        "has_dot": has_dot,
        "has_slash": has_slash,
        "has_colon": has_colon,
        "has_hyphen": has_hyphen,
        "has_at_sign": has_at_sign,
        "observation_count": observation_count,
        "distinct_source_count": source_count,
        "multi_source": source_count > 1,
        "source_diversity_ratio": round(source_count / observation_count, 6),
        "repeated_observation": observation_count > source_count,
        "source_urlhaus": True,
        "source_threatfox": source_count > 1,
        "distinct_reporter_count": reporter_count,
        "distinct_threat_type_count": threat_type_count,
        "distinct_malware_family_count": malware_family_count,
        "threat_context_available": threat_context_available,
        "context_richness": context_richness,
        "tag_count": tag_count,
        "distinct_tag_count": distinct_tag_count,
        "confidence_available": confidence_available,
        "confidence_min": confidence_min,
        "confidence_max": confidence_max,
        "confidence_mean": confidence_mean,
        "confidence_source_count": confidence_source_count,
        # Synthetic benchmark has no chronological event history. Keep absolute
        # timestamps missing rather than inventing temporal observations.
        "earliest_observation_timestamp": None,
        "latest_observation_timestamp": None,
        "temporal_span_seconds": None,
        "temporal_coverage": False,
        "observations_with_timestamps": 0,
    }
    for supported_type in IOC_TYPES:
        features[f"type_{supported_type.replace(':', '_')}"] = ioc_type == supported_type
    return features


def build_benchmark(
    *,
    seed: int = DEFAULT_SEED,
    rows_per_class: int = DEFAULT_ROWS_PER_CLASS,
    feature_schema: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a balanced benchmark, deterministic for a fixed seed and size."""

    if not isinstance(seed, int) or isinstance(seed, bool):
        raise ValueError("seed must be an integer.")
    if not isinstance(rows_per_class, int) or isinstance(rows_per_class, bool) or rows_per_class < 2:
        raise ValueError("rows_per_class must be an integer of at least 2.")
    if feature_schema is None:
        feature_schema = json.loads(FEATURE_SCHEMA_PATH.read_text(encoding="utf-8"))
    expected = set(feature_schema["feature_columns"])
    rng = random.Random(seed)
    latent_labels = ["positive"] * rows_per_class + ["negative"] * rows_per_class
    rng.shuffle(latent_labels)
    rows = []
    for index, latent_class in enumerate(latent_labels):
        features = _generate_features(rng, latent_class == "positive")
        if set(features) != expected:
            raise ValueError("Synthetic feature generator does not match feature_schema.json.")
        rows.append({
            "benchmark_row_id": f"SYN-{index + 1:05d}",
            "features": features,
            "target": latent_class,
        })
    return {
        "dataset_metadata": {
            "dataset_type": "controlled_synthetic_benchmark",
            "synthetic": True,
            "real_world_ground_truth": False,
            "derived_from_human_validated_urlhaus_labels": False,
            "purpose": "Validate feature selection, splitting, baseline fitting, and metric calculation only.",
            "random_seed": seed,
            "rows_per_class": rows_per_class,
            "row_count": len(rows),
            "class_counts": {"positive": rows_per_class, "negative": rows_per_class},
            "generation_logic": (
                "A seeded balanced latent binary class controls overlapping, noisy distributions for existing IOC, "
                "observation/correlation, and context columns. No risk_score threshold or label flag is used as a feature."
            ),
            "feature_schema": "research_data/features/feature_schema.json",
            "experiment_spec": "research_data/features/experiment_spec.json",
        },
        "rows": rows,
    }


def write_benchmark(output_path: Path = DEFAULT_OUTPUT, *, seed: int = DEFAULT_SEED, rows_per_class: int = DEFAULT_ROWS_PER_CLASS) -> dict[str, Any]:
    benchmark = build_benchmark(seed=seed, rows_per_class=rows_per_class)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary.write_text(json.dumps(benchmark, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    temporary.replace(output_path)
    return benchmark


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the controlled synthetic CTIP benchmark.")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--rows-per-class", type=int, default=DEFAULT_ROWS_PER_CLASS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    benchmark = write_benchmark(args.output, seed=args.seed, rows_per_class=args.rows_per_class)
    print(json.dumps(benchmark["dataset_metadata"], indent=2))
    print(f"Synthetic benchmark: {args.output}")


if __name__ == "__main__":
    main()
