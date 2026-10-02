"""Deterministic model-specific feature contributions for synthetic baselines.

Logistic Regression contributions are encoded_value * coefficient and sum with
the intercept to the model log-odds. Gaussian Naive Bayes contributions are
per-column Gaussian log-likelihood ratios (positive class vs negative class)
and sum with log prior odds to the model log-odds. These describe model
behavior on the controlled synthetic set; they are not causal explanations.
"""

from __future__ import annotations

import argparse
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

from research_data.ml.build_benchmark import DEFAULT_OUTPUT as DEFAULT_BENCHMARK
from research_data.ml.train_baselines import (
    DEFAULT_RESULTS,
    EXPERIMENT_IDS,
    FeatureEncoder,
    GaussianNaiveBayesBaseline,
    LogisticRegressionBaseline,
    experiment_columns,
    stratified_split_indices,
)


ROOT = Path(__file__).resolve().parents[3]
FEATURE_SCHEMA_PATH = ROOT / "research_data" / "features" / "feature_schema.json"
DEFAULT_OUTPUT = Path(__file__).resolve().parent / "synthetic_explanations.json"
EXPLANATION_VERSION = "ctip_feature_contributions_v1"
MAX_LOCAL_FEATURES_PER_DIRECTION = 8
SOURCE_FEATURES = {"source_urlhaus", "source_threatfox", "distinct_reporter_count", "confidence_source_count"}
OBSERVATION_FEATURES = {"observation_count", "repeated_observation", "observations_with_timestamps"}
CORRELATION_FEATURES = {"distinct_source_count", "multi_source", "source_diversity_ratio"}


def _sigmoid(value: float) -> float:
    if value >= 0:
        exp_value = math.exp(-min(value, 700))
        return 1.0 / (1.0 + exp_value)
    exp_value = math.exp(max(value, -700))
    return exp_value / (1.0 + exp_value)


def _encoded_names(encoder: FeatureEncoder) -> list[tuple[str, str]]:
    """Return (encoded column, original feature) in exact matrix order."""

    names: list[tuple[str, str]] = []
    for feature in encoder.columns:
        if feature in encoder.categories:
            names.extend((f"{feature}={category}", feature) for category in encoder.categories[feature])
        else:
            names.append((feature, feature))
    return names


def _feature_group(feature: str, feature_specs: dict[str, Any]) -> str:
    if feature_specs[feature].get("group") == "A":
        return "ioc_intrinsic"
    if feature in OBSERVATION_FEATURES:
        return "observation"
    if feature in CORRELATION_FEATURES:
        return "correlation"
    if feature in SOURCE_FEATURES:
        return "provenance_source"
    return "threat_context"


def _model_attribution(
    model: LogisticRegressionBaseline | GaussianNaiveBayesBaseline,
    matrix_row: list[float],
) -> tuple[float, list[float], float]:
    if isinstance(model, LogisticRegressionBaseline):
        contributions = [value * coefficient for value, coefficient in zip(matrix_row, model.weights)]
        base = model.intercept
        log_odds = base + sum(contributions)
        return base, contributions, _sigmoid(log_odds)
    prior_zero, means_zero, variances_zero = model.class_stats[0]
    prior_one, means_one, variances_one = model.class_stats[1]
    base = math.log(prior_one / prior_zero)
    contributions = []
    for value, mean_zero, variance_zero, mean_one, variance_one in zip(
        matrix_row, means_zero, variances_zero, means_one, variances_one
    ):
        # Difference of Gaussian log densities. The shared log(2*pi) term cancels.
        contribution = (
            -0.5 * math.log(variance_one / variance_zero)
            -0.5 * ((value - mean_one) ** 2 / variance_one - (value - mean_zero) ** 2 / variance_zero)
        )
        contributions.append(contribution)
    log_odds = base + sum(contributions)
    return base, contributions, _sigmoid(log_odds)


def _ranked_local_contributions(
    encoded_names: list[tuple[str, str]],
    matrix_row: list[float],
    contributions: list[float],
    feature_groups: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, dict[str, float]]]:
    entries = [
        {
            "feature": encoded_name,
            "source_feature": raw_name,
            "feature_group": group,
            "encoded_feature_value": round(value, 9),
            "contribution": round(contribution, 9),
        }
        for (encoded_name, raw_name), value, contribution, group in zip(
            encoded_names, matrix_row, contributions, feature_groups
        )
    ]
    positive = sorted((item for item in entries if item["contribution"] > 0), key=lambda item: (-item["contribution"], item["feature"]))
    negative = sorted((item for item in entries if item["contribution"] < 0), key=lambda item: (item["contribution"], item["feature"]))
    grouped: dict[str, dict[str, float]] = defaultdict(lambda: {"signed_sum": 0.0, "absolute_sum": 0.0})
    for item in entries:
        grouped[item["feature_group"]]["signed_sum"] += item["contribution"]
        grouped[item["feature_group"]]["absolute_sum"] += abs(item["contribution"])
    grouped_output = {
        name: {key: round(value, 9) for key, value in sorted(metrics.items())}
        for name, metrics in sorted(grouped.items())
    }
    return positive[:MAX_LOCAL_FEATURES_PER_DIRECTION], negative[:MAX_LOCAL_FEATURES_PER_DIRECTION], grouped_output


def _global_summaries(
    encoded_names: list[tuple[str, str]],
    test_matrix: list[list[float]],
    all_contributions: list[list[float]],
    feature_groups: list[str],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    row_count = len(all_contributions)
    feature_rows = []
    for index, (encoded_name, raw_name) in enumerate(encoded_names):
        values = [row[index] for row in all_contributions]
        feature_rows.append({
            "feature": encoded_name,
            "source_feature": raw_name,
            "feature_group": feature_groups[index],
            "aggregate_absolute_contribution": round(sum(abs(value) for value in values), 9),
            "mean_absolute_contribution": round(sum(abs(value) for value in values) / row_count, 9),
            "mean_signed_contribution": round(sum(values) / row_count, 9),
        })
    feature_rows.sort(key=lambda item: (-item["mean_absolute_contribution"], item["feature"]))

    group_indices: dict[str, list[int]] = defaultdict(list)
    for index, group in enumerate(feature_groups):
        group_indices[group].append(index)
    group_summaries = {}
    for group, indices in sorted(group_indices.items()):
        absolute_per_row = [sum(abs(row[index]) for index in indices) for row in all_contributions]
        signed_per_row = [sum(row[index] for index in indices) for row in all_contributions]
        mean_absolute = sum(absolute_per_row) / row_count
        group_summaries[group] = {
            "encoded_feature_count": len(indices),
            "mean_absolute_contribution_per_example": round(mean_absolute, 9),
            "mean_absolute_contribution_per_feature_per_example": round(mean_absolute / len(indices), 9),
            "mean_signed_contribution_per_example": round(sum(signed_per_row) / row_count, 9),
        }
    return feature_rows, group_summaries


def build_explanations(
    benchmark: dict[str, Any],
    *,
    feature_schema: dict[str, Any] | None = None,
    split_seed: int = 2026,
    local_example_count_per_class: int = 1,
) -> dict[str, Any]:
    """Fit the existing baselines and explain the deterministic test partition."""

    metadata = benchmark.get("dataset_metadata", {})
    if not (
        metadata.get("dataset_type") == "controlled_synthetic_benchmark"
        and metadata.get("synthetic") is True
        and metadata.get("real_world_ground_truth") is False
        and metadata.get("derived_from_human_validated_urlhaus_labels") is False
    ):
        raise ValueError("Explanations are restricted to the explicitly marked controlled synthetic benchmark.")
    rows = benchmark.get("rows")
    if not isinstance(rows, list) or not rows or any(row.get("target") not in {"positive", "negative"} for row in rows):
        raise ValueError("Synthetic explanation rows must have positive/negative targets only.")
    if feature_schema is None:
        feature_schema = json.loads(FEATURE_SCHEMA_PATH.read_text(encoding="utf-8"))
    groups = experiment_columns(feature_schema)
    feature_specs = feature_schema["feature_columns"]
    labels = [row["target"] for row in rows]
    train_indices, test_indices = stratified_split_indices(labels, seed=split_seed)
    experiments: dict[str, Any] = {}
    for experiment_id in EXPERIMENT_IDS:
        columns = groups[experiment_id]
        encoder = FeatureEncoder(feature_specs, columns).fit([rows[index]["features"] for index in train_indices])
        encoded_names = _encoded_names(encoder)
        test_matrix = encoder.transform([rows[index]["features"] for index in test_indices])
        feature_groups = [_feature_group(raw_name, feature_specs) for _, raw_name in encoded_names]
        train_matrix = encoder.transform([rows[index]["features"] for index in train_indices])
        train_labels = [1 if rows[index]["target"] == "positive" else 0 for index in train_indices]
        models = {
            "LogisticRegression": LogisticRegressionBaseline().fit(train_matrix, train_labels),
            "GaussianNaiveBayes": GaussianNaiveBayesBaseline().fit(train_matrix, train_labels),
        }
        model_artifacts: dict[str, Any] = {}
        for model_name, model in models.items():
            scores = model.predict_proba(test_matrix)
            decisions: list[tuple[int, float, list[float], float]] = []
            for test_index, (matrix_row, score) in enumerate(zip(test_matrix, scores)):
                base, contributions, reconstructed_score = _model_attribution(model, matrix_row)
                if abs(reconstructed_score - score) > 1e-9:
                    raise ValueError(f"Attribution contributions do not reconstruct {model_name} prediction.")
                decisions.append((test_index, score, contributions, base))
            all_contributions = [item[2] for item in decisions]
            global_features, global_groups = _global_summaries(encoded_names, test_matrix, all_contributions, feature_groups)

            # Selection is mechanical: lowest original generated row ID in the
            # sorted held-out indices for each predicted class, regardless of
            # whether the prediction is correct. No metric-based cherry-picking.
            local_examples = []
            for predicted_class in ("positive", "negative"):
                chosen = []
                for test_index, score, contributions, base in decisions:
                    predicted = "positive" if score >= 0.5 else "negative"
                    if predicted == predicted_class:
                        chosen.append((test_index, score, contributions, base))
                    if len(chosen) >= local_example_count_per_class:
                        break
                for test_index, score, contributions, base in chosen:
                    benchmark_index = test_indices[test_index]
                    positive, negative, local_groups = _ranked_local_contributions(
                        encoded_names, test_matrix[test_index], contributions, feature_groups
                    )
                    local_examples.append({
                        "benchmark_row_id": rows[benchmark_index]["benchmark_row_id"],
                        "actual_target": labels[benchmark_index],
                        "predicted_class": predicted_class,
                        "positive_class_probability": round(score, 9),
                        "base_log_odds": round(base, 9),
                        "sum_feature_contributions": round(sum(contributions), 9),
                        "reconstructed_log_odds": round(base + sum(contributions), 9),
                        "top_positive_contributing_features": positive,
                        "top_negative_contributing_features": negative,
                        "feature_group_contributions": local_groups,
                    })
            model_artifacts[model_name] = {
                "attribution_method": (
                    "encoded feature value × learned coefficient; local contributions add to the intercept in log-odds space"
                    if isinstance(model, LogisticRegressionBaseline)
                    else "per-feature Gaussian log-likelihood ratio log p(x_j|positive) - log p(x_j|negative); contributions add to log prior odds"
                ),
                "contribution_direction": "positive values push toward the positive class; negative values push toward the negative class",
                "local_explanations": local_examples,
                "global_model_feature_contribution": {
                    "aggregation": "mean and sum of absolute per-example log-odds contribution; signed mean is also reported",
                    "features_ranked_by_mean_absolute_contribution": global_features,
                },
                "feature_group_contribution": {
                    "aggregation": "mean absolute and signed sum of feature log-odds contributions per held-out example; also normalized by encoded group width",
                    "groups": global_groups,
                },
            }
        experiments[experiment_id] = {
            "name": {"A": "IOC-only", "B": "IOC + observation/correlation", "C": "IOC + correlation + threat context"}[experiment_id],
            "feature_count": len(columns),
            "encoded_feature_count": len(encoded_names),
            "feature_groups_included": sorted(set(feature_groups)),
            "models": model_artifacts,
        }

    return {
        "metadata": {
            "artifact_type": "SYNTHETIC BENCHMARK EXPLANATION",
            "explanation_version": EXPLANATION_VERSION,
            "dataset_type": metadata["dataset_type"],
            "synthetic": True,
            "real_world_ground_truth": False,
            "derived_from_human_validated_urlhaus_labels": False,
            "benchmark_size": len(rows),
            "class_counts": metadata["class_counts"],
            "benchmark_seed": metadata["random_seed"],
            "split_seed": split_seed,
            "split_strategy": "same deterministic stratified 75/25 split as train_baselines.py",
            "train_size": len(train_indices),
            "test_size": len(test_indices),
            "models": ["LogisticRegression", "GaussianNaiveBayes"],
            "feature_values_are_encoded": True,
            "model_feature_importance_is_causal": False,
            "real_urlhaus_rows_explained": False,
            "local_example_selection": (
                "For each experiment/model, take the first held-out row in deterministic split order for each predicted class; "
                "selection does not depend on correctness or contribution magnitude."
            ),
            "interpretation": (
                "Explanations describe model behavior on this controlled synthetic benchmark only. They do not establish "
                "causal relationships or real-world threat attribution."
            ),
        },
        "experiments": experiments,
    }


def run_explanation_pipeline(
    benchmark_path: Path = DEFAULT_BENCHMARK,
    output_path: Path = DEFAULT_OUTPUT,
) -> dict[str, Any]:
    benchmark = json.loads(Path(benchmark_path).read_text(encoding="utf-8"))
    artifact = build_explanations(benchmark)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix(output_path.suffix + ".tmp")
    temporary.write_text(json.dumps(artifact, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(output_path)
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(description="Explain synthetic baseline experiments with model-derived contributions.")
    parser.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    artifact = run_explanation_pipeline(args.benchmark, args.output)
    print(json.dumps(artifact["metadata"], indent=2))
    print(f"Synthetic explanation artifact: {args.output}")


if __name__ == "__main__":
    main()
