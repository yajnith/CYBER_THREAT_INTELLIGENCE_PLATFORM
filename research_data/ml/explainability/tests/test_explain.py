import json
import math
import unittest
from pathlib import Path

from research_data.ml.build_benchmark import build_benchmark
from research_data.ml.explainability.explain import (
    _model_attribution,
    _encoded_names,
    _feature_group,
    _ranked_local_contributions,
    build_explanations,
)
from research_data.ml.train_baselines import (
    FeatureEncoder,
    GaussianNaiveBayesBaseline,
    LogisticRegressionBaseline,
    experiment_columns,
    stratified_split_indices,
)


class ExplanationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.benchmark = build_benchmark()
        cls.artifact = build_explanations(cls.benchmark)

    def test_explanations_repeat_deterministically(self):
        self.assertEqual(self.artifact, build_explanations(self.benchmark))

    def test_contribution_dimensions_match_encoded_model_features(self):
        for experiment in self.artifact["experiments"].values():
            for model in experiment["models"].values():
                local = model["local_explanations"][0]
                contributions = local["top_positive_contributing_features"] + local["top_negative_contributing_features"]
                # Full dimensions are exposed in the global summary, even though
                # local output intentionally keeps only the requested top items.
                self.assertEqual(experiment["encoded_feature_count"], len(model["global_model_feature_contribution"]["features_ranked_by_mean_absolute_contribution"]))
                self.assertLessEqual(len(contributions), 16)

    def _fit_one(self, experiment_id, model_type):
        schema = json.loads(Path("research_data/features/feature_schema.json").read_text(encoding="utf-8"))
        rows = self.benchmark["rows"]
        columns = experiment_columns(schema)[experiment_id]
        train_indices, test_indices = stratified_split_indices([row["target"] for row in rows])
        encoder = FeatureEncoder(schema["feature_columns"], columns).fit([rows[index]["features"] for index in train_indices])
        train = encoder.transform([rows[index]["features"] for index in train_indices])
        test = encoder.transform([rows[index]["features"] for index in test_indices])
        labels = [1 if rows[index]["target"] == "positive" else 0 for index in train_indices]
        model = model_type().fit(train, labels)
        return schema, encoder, test[0], model

    def test_logistic_contribution_is_encoded_value_times_coefficient_and_preserves_sign(self):
        schema, encoder, sample, model = self._fit_one("A", LogisticRegressionBaseline)
        base, contributions, score = _model_attribution(model, sample)
        self.assertEqual(len(contributions), len(model.weights))
        for value, coefficient, contribution in zip(sample, model.weights, contributions):
            self.assertAlmostEqual(contribution, value * coefficient, places=12)
        self.assertAlmostEqual(score, model.predict_proba([sample])[0], places=12)
        self.assertTrue(any(value > 0 for value in contributions))
        self.assertTrue(any(value < 0 for value in contributions))

    def test_gaussian_naive_bayes_decomposition_reconstructs_class_score(self):
        _, _, sample, model = self._fit_one("C", GaussianNaiveBayesBaseline)
        base, contributions, score = _model_attribution(model, sample)
        prior_zero, means_zero, variances_zero = model.class_stats[0]
        prior_one, means_one, variances_one = model.class_stats[1]
        self.assertAlmostEqual(base, math.log(prior_one / prior_zero), places=12)
        self.assertEqual(len(contributions), len(means_zero))
        log_odds = base + sum(contributions)
        reconstructed = 1 / (1 + math.exp(-log_odds)) if log_odds >= 0 else math.exp(log_odds) / (1 + math.exp(log_odds))
        self.assertAlmostEqual(score, reconstructed, places=10)
        self.assertAlmostEqual(score, model.predict_proba([sample])[0], places=10)

    def test_local_positive_and_negative_lists_preserve_contribution_sign(self):
        for experiment in self.artifact["experiments"].values():
            for model in experiment["models"].values():
                for local in model["local_explanations"]:
                    self.assertTrue(local["top_positive_contributing_features"])
                    self.assertTrue(local["top_negative_contributing_features"])
                    self.assertTrue(all(item["contribution"] > 0 for item in local["top_positive_contributing_features"]))
                    self.assertTrue(all(item["contribution"] < 0 for item in local["top_negative_contributing_features"]))

    def test_global_feature_contribution_is_ranked_and_deterministic(self):
        for experiment in self.artifact["experiments"].values():
            for model in experiment["models"].values():
                values = model["global_model_feature_contribution"]["features_ranked_by_mean_absolute_contribution"]
                scores = [item["mean_absolute_contribution"] for item in values]
                self.assertEqual(scores, sorted(scores, reverse=True))
                self.assertTrue(all(value >= 0 for value in scores))

    def test_feature_group_aggregation_and_experiment_scope(self):
        a = self.artifact["experiments"]["A"]
        b = self.artifact["experiments"]["B"]
        c = self.artifact["experiments"]["C"]
        for experiment in (a, b, c):
            for model in experiment["models"].values():
                self.assertIn("ioc_intrinsic", model["feature_group_contribution"]["groups"])
        for model in a["models"].values():
            groups = model["feature_group_contribution"]["groups"]
            self.assertNotIn("correlation", groups)
            self.assertNotIn("threat_context", groups)
        for model in b["models"].values():
            groups = model["feature_group_contribution"]["groups"]
            self.assertIn("observation", groups)
            self.assertIn("correlation", groups)
            self.assertNotIn("threat_context", groups)
        for model in c["models"].values():
            groups = model["feature_group_contribution"]["groups"]
            self.assertIn("correlation", groups)
            self.assertIn("threat_context", groups)

    def test_local_group_totals_equal_the_sum_of_their_feature_contributions(self):
        schema, encoder, sample, model = self._fit_one("C", LogisticRegressionBaseline)
        _, contributions, _ = _model_attribution(model, sample)
        encoded_names = _encoded_names(encoder)
        groups = [_feature_group(raw_name, schema["feature_columns"]) for _, raw_name in encoded_names]
        _, _, aggregate = _ranked_local_contributions(encoded_names, sample, contributions, groups)
        expected = {}
        for group, contribution in zip(groups, contributions):
            current = expected.setdefault(group, {"signed_sum": 0.0, "absolute_sum": 0.0})
            current["signed_sum"] += contribution
            current["absolute_sum"] += abs(contribution)
        self.assertEqual(set(aggregate), set(expected))
        for group in expected:
            self.assertAlmostEqual(aggregate[group]["signed_sum"], expected[group]["signed_sum"], places=8)
            self.assertAlmostEqual(aggregate[group]["absolute_sum"], expected[group]["absolute_sum"], places=8)

    def test_no_target_or_generation_flag_is_explained_as_a_feature(self):
        for experiment in self.artifact["experiments"].values():
            for model in experiment["models"].values():
                names = [item["feature"] for item in model["global_model_feature_contribution"]["features_ranked_by_mean_absolute_contribution"]]
                self.assertFalse(any("target" in name or "generation" in name or "synthetic" in name for name in names))

    def test_metadata_labels_explanations_as_synthetic_and_noncausal(self):
        metadata = self.artifact["metadata"]
        self.assertEqual(metadata["artifact_type"], "SYNTHETIC BENCHMARK EXPLANATION")
        self.assertTrue(metadata["synthetic"])
        self.assertFalse(metadata["real_world_ground_truth"])
        self.assertFalse(metadata["model_feature_importance_is_causal"])
        self.assertFalse(metadata["real_urlhaus_rows_explained"])
        self.assertIn("do not establish causal", metadata["interpretation"])

    def test_local_example_selection_is_prediction_class_based_not_correctness_based(self):
        self.assertIn("does not depend on correctness", self.artifact["metadata"]["local_example_selection"])
        for experiment in self.artifact["experiments"].values():
            for model in experiment["models"].values():
                self.assertEqual({item["predicted_class"] for item in model["local_explanations"]}, {"positive", "negative"})


if __name__ == "__main__":
    unittest.main()
