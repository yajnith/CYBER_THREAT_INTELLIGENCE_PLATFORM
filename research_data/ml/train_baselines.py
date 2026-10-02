"""Train deterministic baseline classifiers on the controlled synthetic set.

This module intentionally refuses real CTI data. Its small dependency-free
Logistic Regression and Gaussian Naive Bayes implementations exist only to
exercise the CTIP A/B/C experiment path when scikit-learn is unavailable.
"""

from __future__ import annotations

import argparse
import json
import math
import platform
import random
import statistics
from pathlib import Path
from typing import Any

from research_data.ml.build_benchmark import DEFAULT_OUTPUT as DEFAULT_BENCHMARK
from research_data.ml.build_benchmark import build_benchmark


ROOT = Path(__file__).resolve().parents[2]
FEATURE_SCHEMA_PATH = ROOT / "research_data" / "features" / "feature_schema.json"
EXPERIMENT_SPEC_PATH = ROOT / "research_data" / "features" / "experiment_spec.json"
DEFAULT_RESULTS = Path(__file__).resolve().parent / "synthetic_baseline_results.json"
SPLIT_SEED = 2026
TEST_FRACTION = 0.25
EXPERIMENT_IDS = ("A", "B", "C")


def experiment_columns(feature_schema: dict[str, Any] | None = None) -> dict[str, list[str]]:
    if feature_schema is None:
        feature_schema = json.loads(FEATURE_SCHEMA_PATH.read_text(encoding="utf-8"))
    columns = feature_schema.get("feature_columns", {})
    groups = {name: item.get("group") for name, item in columns.items()}
    return {
        "A": [name for name, group in groups.items() if group == "A"],
        "B": [name for name, group in groups.items() if group in {"A", "B"}],
        "C": [name for name, group in groups.items() if group in {"A", "B", "C"}],
    }


def stratified_split_indices(labels: list[str], *, test_fraction: float = TEST_FRACTION, seed: int = SPLIT_SEED) -> tuple[list[int], list[int]]:
    if not 0 < test_fraction < 1:
        raise ValueError("test_fraction must be between 0 and 1.")
    by_class: dict[str, list[int]] = {}
    for index, label in enumerate(labels):
        if label not in {"positive", "negative"}:
            raise ValueError("Training labels must be positive or negative; unknown rows are not trainable.")
        by_class.setdefault(label, []).append(index)
    if set(by_class) != {"positive", "negative"} or any(len(items) < 2 for items in by_class.values()):
        raise ValueError("A stratified split requires at least two examples of each class.")
    rng = random.Random(seed)
    train_indices: list[int] = []
    test_indices: list[int] = []
    for label in sorted(by_class):
        members = by_class[label][:]
        rng.shuffle(members)
        test_count = max(1, min(len(members) - 1, int(round(len(members) * test_fraction))))
        test_indices.extend(members[:test_count])
        train_indices.extend(members[test_count:])
    return sorted(train_indices), sorted(test_indices)


class FeatureEncoder:
    """Fit medians, scaling, and one-hot vocabularies on training rows only."""

    def __init__(self, feature_specs: dict[str, Any], columns: list[str]):
        self.feature_specs = feature_specs
        self.columns = columns
        self.numeric: dict[str, tuple[float, float, float]] = {}
        self.categories: dict[str, list[str]] = {}

    def fit(self, rows: list[dict[str, Any]]) -> "FeatureEncoder":
        for name in self.columns:
            spec = self.feature_specs[name]
            values = [row.get(name) for row in rows if row.get(name) is not None]
            value_type = spec.get("type")
            if value_type in {"categorical", "string"}:
                vocab = sorted({str(value) for value in values})
                if any(row.get(name) is None for row in rows):
                    vocab.append("__missing__")
                self.categories[name] = vocab
                continue
            numeric = [float(value) for value in values]
            median = statistics.median(numeric) if numeric else 0.0
            imputed = [float(value) if value is not None else median for value in (row.get(name) for row in rows)]
            center = statistics.fmean(imputed) if imputed else 0.0
            scale = math.sqrt(statistics.fmean((value - center) ** 2 for value in imputed)) if imputed else 1.0
            self.numeric[name] = (median, center, scale if scale > 1e-12 else 1.0)
        return self

    def transform(self, rows: list[dict[str, Any]]) -> list[list[float]]:
        matrix: list[list[float]] = []
        for row in rows:
            encoded: list[float] = []
            for name in self.columns:
                if name in self.categories:
                    vocab = self.categories[name]
                    value = "__missing__" if row.get(name) is None else str(row.get(name))
                    encoded.extend(1.0 if value == category else 0.0 for category in vocab)
                else:
                    median, center, scale = self.numeric[name]
                    raw = row.get(name)
                    value = median if raw is None else float(raw)
                    encoded.append((value - center) / scale)
            matrix.append(encoded)
        return matrix


class LogisticRegressionBaseline:
    """Binary logistic regression using deterministic full-batch gradient descent."""

    def __init__(self, *, learning_rate: float = 0.15, iterations: int = 250, l2: float = 0.002):
        self.learning_rate = learning_rate
        self.iterations = iterations
        self.l2 = l2
        self.weights: list[float] = []
        self.intercept = 0.0

    @staticmethod
    def _sigmoid(value: float) -> float:
        if value >= 0:
            exp_value = math.exp(-min(value, 700))
            return 1.0 / (1.0 + exp_value)
        exp_value = math.exp(max(value, -700))
        return exp_value / (1.0 + exp_value)

    def fit(self, matrix: list[list[float]], labels: list[int]) -> "LogisticRegressionBaseline":
        if not matrix or len(matrix) != len(labels):
            raise ValueError("Logistic regression requires a non-empty aligned matrix and labels.")
        dimensions = len(matrix[0])
        self.weights = [0.0] * dimensions
        self.intercept = 0.0
        row_count = len(matrix)
        for _ in range(self.iterations):
            gradients = [0.0] * dimensions
            intercept_gradient = 0.0
            for features, label in zip(matrix, labels):
                probability = self._sigmoid(self.intercept + sum(weight * value for weight, value in zip(self.weights, features)))
                error = probability - label
                intercept_gradient += error
                for column, value in enumerate(features):
                    gradients[column] += error * value
            self.intercept -= self.learning_rate * intercept_gradient / row_count
            for column in range(dimensions):
                gradient = gradients[column] / row_count + self.l2 * self.weights[column]
                self.weights[column] -= self.learning_rate * gradient
        return self

    def predict_proba(self, matrix: list[list[float]]) -> list[float]:
        return [self._sigmoid(self.intercept + sum(weight * value for weight, value in zip(self.weights, row))) for row in matrix]


class GaussianNaiveBayesBaseline:
    """Small Gaussian Naive Bayes reference model with variance smoothing."""

    def __init__(self, variance_smoothing: float = 1e-6):
        self.variance_smoothing = variance_smoothing
        self.class_stats: dict[int, tuple[float, list[float], list[float]]] = {}

    def fit(self, matrix: list[list[float]], labels: list[int]) -> "GaussianNaiveBayesBaseline":
        if not matrix or len(matrix) != len(labels):
            raise ValueError("Gaussian Naive Bayes requires a non-empty aligned matrix and labels.")
        dimensions = len(matrix[0])
        for class_value in (0, 1):
            class_rows = [row for row, label in zip(matrix, labels) if label == class_value]
            if not class_rows:
                raise ValueError("Both classes are required for Gaussian Naive Bayes.")
            means = [statistics.fmean(row[column] for row in class_rows) for column in range(dimensions)]
            variances = [
                max(statistics.fmean((row[column] - means[column]) ** 2 for row in class_rows), self.variance_smoothing)
                for column in range(dimensions)
            ]
            self.class_stats[class_value] = (len(class_rows) / len(matrix), means, variances)
        return self

    def predict_proba(self, matrix: list[list[float]]) -> list[float]:
        output = []
        for row in matrix:
            log_probabilities = []
            for class_value in (0, 1):
                prior, means, variances = self.class_stats[class_value]
                log_probability = math.log(prior)
                for value, center, variance in zip(row, means, variances):
                    log_probability -= 0.5 * (math.log(2 * math.pi * variance) + ((value - center) ** 2 / variance))
                log_probabilities.append(log_probability)
            difference = log_probabilities[1] - log_probabilities[0]
            if difference >= 0:
                probability = 1.0 / (1.0 + math.exp(-min(difference, 700)))
            else:
                exp_difference = math.exp(max(difference, -700))
                probability = exp_difference / (1.0 + exp_difference)
            output.append(probability)
        return output


def _roc_auc(labels: list[int], scores: list[float]) -> float:
    positive = [score for score, label in zip(scores, labels) if label == 1]
    negative = [score for score, label in zip(scores, labels) if label == 0]
    if not positive or not negative:
        raise ValueError("ROC-AUC requires both classes in the test split.")
    wins = sum(1.0 if pos > neg else 0.5 if pos == neg else 0.0 for pos in positive for neg in negative)
    return wins / (len(positive) * len(negative))


def _metrics(labels: list[int], scores: list[float]) -> dict[str, float]:
    predictions = [1 if score >= 0.5 else 0 for score in scores]
    true_positive = sum(actual == 1 and predicted == 1 for actual, predicted in zip(labels, predictions))
    false_positive = sum(actual == 0 and predicted == 1 for actual, predicted in zip(labels, predictions))
    false_negative = sum(actual == 1 and predicted == 0 for actual, predicted in zip(labels, predictions))
    accuracy = sum(actual == predicted for actual, predicted in zip(labels, predictions)) / len(labels)
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "accuracy": round(accuracy, 6),
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "roc_auc": round(_roc_auc(labels, scores), 6),
    }


def _validate_synthetic_dataset(dataset: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    metadata = dataset.get("dataset_metadata") if isinstance(dataset, dict) else None
    if not isinstance(metadata, dict):
        raise ValueError("Dataset metadata is required; refusing unprovenanced training data.")
    if metadata.get("dataset_type") == "real_urlhaus_experiment" or metadata.get("real_world_ground_truth") is True:
        raise ValueError("Real URLhaus experiment data has no validated labeled targets; supervised training is refused.")
    if not (
        metadata.get("dataset_type") == "controlled_synthetic_benchmark"
        and metadata.get("synthetic") is True
        and metadata.get("real_world_ground_truth") is False
        and metadata.get("derived_from_human_validated_urlhaus_labels") is False
    ):
        raise ValueError("Training is allowed only for the explicitly marked controlled synthetic benchmark.")
    rows = dataset.get("rows")
    if not isinstance(rows, list) or not rows:
        raise ValueError("Synthetic benchmark must contain rows.")
    labels = [row.get("target") for row in rows if isinstance(row, dict)]
    if len(labels) != len(rows) or any(label not in {"positive", "negative"} for label in labels):
        raise ValueError("Synthetic training rows must have only positive or negative targets; unknown is not trainable.")
    if set(labels) != {"positive", "negative"}:
        raise ValueError("Synthetic benchmark must contain both target classes.")
    return rows, metadata


def train_baselines(dataset: dict[str, Any], *, split_seed: int = SPLIT_SEED, feature_schema: dict[str, Any] | None = None) -> dict[str, Any]:
    """Train two deterministic baselines for each existing feature group."""

    rows, dataset_metadata = _validate_synthetic_dataset(dataset)
    if feature_schema is None:
        feature_schema = json.loads(FEATURE_SCHEMA_PATH.read_text(encoding="utf-8"))
    groups = experiment_columns(feature_schema)
    train_indices, test_indices = stratified_split_indices([row["target"] for row in rows], seed=split_seed)
    train_labels = [1 if rows[index]["target"] == "positive" else 0 for index in train_indices]
    test_labels = [1 if rows[index]["target"] == "positive" else 0 for index in test_indices]
    specs = feature_schema["feature_columns"]
    experiments: dict[str, Any] = {}
    for experiment_id in EXPERIMENT_IDS:
        columns = groups[experiment_id]
        encoder = FeatureEncoder(specs, columns)
        train_features = [rows[index]["features"] for index in train_indices]
        test_features = [rows[index]["features"] for index in test_indices]
        encoder.fit(train_features)
        train_matrix = encoder.transform(train_features)
        test_matrix = encoder.transform(test_features)
        models = {
            "LogisticRegression": LogisticRegressionBaseline().fit(train_matrix, train_labels),
            "GaussianNaiveBayes": GaussianNaiveBayesBaseline().fit(train_matrix, train_labels),
        }
        model_results = {}
        for model_name, model in models.items():
            scores = model.predict_proba(test_matrix)
            model_results[model_name] = {
                "result_type": "SYNTHETIC BENCHMARK RESULT",
                "metrics": _metrics(test_labels, scores),
            }
        experiments[experiment_id] = {
            "name": {"A": "IOC-only", "B": "IOC + observation/correlation", "C": "IOC + correlation + threat context"}[experiment_id],
            "feature_groups": {"A": ["A_ioc_only"], "B": ["A_ioc_only", "B_ioc_plus_observation_correlation"], "C": ["A_ioc_only", "B_ioc_plus_observation_correlation", "C_ioc_correlation_and_threat_context"]}[experiment_id],
            "feature_count": len(columns),
            "encoded_model_column_count": len(train_matrix[0]),
            "models": model_results,
        }

    class_counts: dict[str, int] = {
        target: sum(row["target"] == target for row in rows)
        for target in ("positive", "negative")
    }
    return {
        "metadata": {
            "result_type": "SYNTHETIC BENCHMARK RESULT",
            "dataset_type": dataset_metadata["dataset_type"],
            "synthetic": True,
            "real_world_ground_truth": False,
            "derived_from_human_validated_urlhaus_labels": False,
            "random_seed": dataset_metadata["random_seed"],
            "split_seed": split_seed,
            "split_strategy": "StratifiedShuffleSplit equivalent; 75% train / 25% test within each class.",
            "model_implementation": "Dependency-free reference baselines; scikit-learn unavailable.",
            "implementation_version": "ctip_reference_baselines_v1",
            "python_version": platform.python_version(),
            "scikit_learn_available": False,
            "benchmark_size": len(rows),
            "class_counts": class_counts,
            "train_size": len(train_indices),
            "test_size": len(test_indices),
            "train_class_counts": {
                "positive": sum(label == 1 for label in train_labels),
                "negative": sum(label == 0 for label in train_labels),
            },
            "test_class_counts": {
                "positive": sum(label == 1 for label in test_labels),
                "negative": sum(label == 0 for label in test_labels),
            },
            "models": ["LogisticRegression", "GaussianNaiveBayes"],
        },
        "experiments": experiments,
        "limitations": [
            "All reported metrics measure a controlled synthetic benchmark only.",
            "They are not URLhaus performance, real-world threat detection performance, or evidence of improved CTI prioritization.",
            "No real URLhaus target labels were used; all real URLhaus rows remain unknown.",
        ],
    }


def run_pipeline(benchmark_file: Path = DEFAULT_BENCHMARK, results_file: Path = DEFAULT_RESULTS) -> dict[str, Any]:
    dataset = json.loads(Path(benchmark_file).read_text(encoding="utf-8"))
    results = train_baselines(dataset)
    output = Path(results_file)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(results, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(output)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Run controlled synthetic A/B/C CTIP baselines.")
    parser.add_argument("--benchmark", type=Path, default=DEFAULT_BENCHMARK)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    args = parser.parse_args()
    results = run_pipeline(args.benchmark, args.results)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
