import json
import math
import unittest
from pathlib import Path

from research_data.ml.build_benchmark import DEFAULT_SEED, build_benchmark
from research_data.ml.train_baselines import (
    experiment_columns,
    stratified_split_indices,
    train_baselines,
)


ROOT = Path(__file__).resolve().parents[3]
REAL_PROFILE = ROOT / "research_data" / "experiments" / "urlhaus_experiment_profile.json"


class SyntheticBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.benchmark = build_benchmark()

    def test_benchmark_generation_is_deterministic_and_balanced(self):
        repeated = build_benchmark()
        self.assertEqual(self.benchmark, repeated)
        metadata = self.benchmark["dataset_metadata"]
        self.assertEqual(metadata["random_seed"], DEFAULT_SEED)
        self.assertEqual(metadata["row_count"], 600)
        self.assertEqual(metadata["class_counts"], {"positive": 300, "negative": 300})

    def test_benchmark_is_explicitly_synthetic_not_ground_truth(self):
        metadata = self.benchmark["dataset_metadata"]
        self.assertEqual(metadata["dataset_type"], "controlled_synthetic_benchmark")
        self.assertTrue(metadata["synthetic"])
        self.assertFalse(metadata["real_world_ground_truth"])
        self.assertFalse(metadata["derived_from_human_validated_urlhaus_labels"])
        self.assertIn("latent", metadata["generation_logic"].lower())
        self.assertIn("overlapping", metadata["generation_logic"].lower())

    def test_target_and_generation_metadata_are_not_features(self):
        for row in self.benchmark["rows"]:
            self.assertEqual(set(row["features"]), set(self.benchmark["rows"][0]["features"]))
            self.assertNotIn("target", row["features"])
            self.assertNotIn("synthetic", row["features"])
            self.assertNotIn("label_generation_flag", row["features"])
            self.assertNotIn("risk_score", row["features"])

    def test_experiment_groups_match_existing_feature_schema(self):
        columns = experiment_columns()
        self.assertEqual([len(columns[name]) for name in ("A", "B", "C")], [20, 28, 44])
        self.assertTrue(set(columns["A"]).issubset(columns["B"]))
        self.assertTrue(set(columns["B"]).issubset(columns["C"]))
        self.assertEqual(set(self.benchmark["rows"][0]["features"]), set(columns["C"]))

    def test_stratified_split_is_deterministic_and_preserves_classes(self):
        labels = [row["target"] for row in self.benchmark["rows"]]
        first = stratified_split_indices(labels, seed=27)
        self.assertEqual(first, stratified_split_indices(labels, seed=27))
        train, test = first
        self.assertEqual((len(train), len(test)), (450, 150))
        for indices in (train, test):
            self.assertEqual({labels[index] for index in indices}, {"positive", "negative"})

    def test_two_baselines_train_and_metrics_are_generated_for_all_experiments(self):
        results = train_baselines(self.benchmark)
        self.assertEqual(set(results["experiments"]), {"A", "B", "C"})
        self.assertEqual(results["metadata"]["models"], ["LogisticRegression", "GaussianNaiveBayes"])
        self.assertEqual((results["metadata"]["train_size"], results["metadata"]["test_size"]), (450, 150))
        for experiment in results["experiments"].values():
            self.assertEqual(set(experiment["models"]), {"LogisticRegression", "GaussianNaiveBayes"})
            for model in experiment["models"].values():
                self.assertEqual(model["result_type"], "SYNTHETIC BENCHMARK RESULT")
                self.assertEqual(set(model["metrics"]), {"accuracy", "precision", "recall", "f1", "roc_auc"})
                self.assertTrue(all(0 <= value <= 1 and math.isfinite(value) for value in model["metrics"].values()))

    def test_training_results_repeat_exactly(self):
        self.assertEqual(train_baselines(self.benchmark), train_baselines(self.benchmark))

    def test_real_urlhaus_profile_has_no_labels_and_real_training_is_refused(self):
        profile = json.loads(REAL_PROFILE.read_text(encoding="utf-8"))
        self.assertEqual(profile["statistics"]["input_target_row_count"], 0)
        self.assertEqual(profile["statistics"]["labeled_count_per_experiment"]["A"], 0)
        real_rows = [{"features": {}, "target": "unknown"}]
        real_data = {
            "dataset_metadata": {
                "dataset_type": "real_urlhaus_experiment",
                "synthetic": False,
                "real_world_ground_truth": False,
                "derived_from_human_validated_urlhaus_labels": False,
            },
            "rows": real_rows,
        }
        with self.assertRaisesRegex(ValueError, "no validated labeled targets"):
            train_baselines(real_data)

    def test_unknown_targets_cannot_be_trained(self):
        invalid = {
            "dataset_metadata": self.benchmark["dataset_metadata"],
            "rows": [dict(self.benchmark["rows"][0], target="unknown")],
        }
        with self.assertRaisesRegex(ValueError, "unknown is not trainable"):
            train_baselines(invalid)


if __name__ == "__main__":
    unittest.main()
