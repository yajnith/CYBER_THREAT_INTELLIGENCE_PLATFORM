import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
SPEC_FILE = ROOT / "research_data" / "features" / "experiment_spec.json"
FEATURE_SCHEMA_FILE = ROOT / "research_data" / "features" / "feature_schema.json"
FEATURE_ROWS_FILE = ROOT / "research_data" / "urlhaus" / "urlhaus_research_features.json"


class ExperimentSpecificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = json.loads(SPEC_FILE.read_text(encoding="utf-8"))
        cls.feature_schema = json.loads(FEATURE_SCHEMA_FILE.read_text(encoding="utf-8"))

    def test_target_is_explicitly_unavailable_and_not_selected(self):
        current = self.spec["current_target"]
        self.assertEqual(current["status"], "unavailable")
        self.assertEqual(current["statement"], "Target not currently available.")
        self.assertIsNone(current["selected_strategy"])
        self.assertIsNone(current["preferred_future_strategy"])
        self.assertEqual(current["target_builder_status"], "implemented_infrastructure_only_not_run_on_real_entities")
        self.assertTrue(self.spec["results"]["target_builder_implemented"])
        self.assertFalse(self.spec["results"]["real_target_rows_generated"])

    def test_no_strategy_promotes_rule_score_or_single_class_to_ground_truth(self):
        candidates = {item["id"]: item for item in self.spec["target_candidates"]}
        self.assertEqual(candidates["source_reported_threat_type"]["supervised_suitability"], "unsuitable_as_current_multiclass_target")
        self.assertEqual(candidates["deterministic_ctip_risk_level"]["supervised_suitability"], "not_ground_truth")
        self.assertFalse(self.feature_schema["target_policy"]["urlhaus_threat_is_target"])
        self.assertFalse(self.feature_schema["target_policy"]["deterministic_risk_score_included"])

    def test_current_feature_dataset_rows_remain_unlabeled(self):
        self.assertTrue(FEATURE_ROWS_FILE.is_file(), "Generate the current feature artifact before running this test.")
        rows = json.loads(FEATURE_ROWS_FILE.read_text(encoding="utf-8"))
        self.assertEqual(len(rows), 14354)
        self.assertTrue(all(row.get("target") is None for row in rows))
        self.assertTrue(all("risk_score" not in row["features"] for row in rows))

    def test_a_b_c_experiments_reference_defined_feature_groups(self):
        experiments = self.spec["experiments"]
        self.assertEqual(set(experiments), {"A", "B", "C"})
        defined_groups = set(self.feature_schema["feature_groups"])
        for experiment in experiments.values():
            self.assertTrue(experiment["feature_groups"])
            self.assertTrue(set(experiment["leakage_controls"]))
            self.assertIn("target_requirement", experiment)
        self.assertTrue(set(experiments["A"]["feature_groups"]).issubset(defined_groups))
        self.assertTrue(set(experiments["B"]["feature_groups"]).issubset(defined_groups))
        self.assertTrue(set(experiments["C"]["feature_groups"]).issubset(defined_groups))

    def test_leakage_and_grouped_temporal_split_controls_are_present(self):
        policy = self.spec["leakage_policy"]
        self.assertIn("always_exclude", policy)
        self.assertGreaterEqual(len(policy["always_exclude"]), 5)
        self.assertIn("source_reported_label_policy", policy)
        protocol = self.spec["evaluation_protocol"]
        self.assertIn("chronological", protocol["primary_split"].lower())
        self.assertIn("(ioc_type, normalized_ioc_value)", protocol["entity_grouping"])
        self.assertEqual(protocol["prediction_horizon_days"], 7)
        self.assertIn("embargo", protocol)
        self.assertTrue(self.spec["results"]["model_trained"])
        self.assertTrue(self.spec["results"]["performance_metrics_calculated"])
        self.assertFalse(self.spec["results"]["real_urlhaus_model_trained"])
        self.assertFalse(self.spec["results"]["real_world_performance_metrics_calculated"])


if __name__ == "__main__":
    unittest.main()
