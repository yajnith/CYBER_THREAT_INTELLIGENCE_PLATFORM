import unittest

from research_data.experiments.build_datasets import build_experiment_datasets


def _schema():
    return {
        "feature_columns": {
            "ioc_type": {"group": "A"},
            "shape": {"group": "A"},
            "source_count": {"group": "B"},
            "threat_count": {"group": "C"},
        }
    }


def _feature(ioc_type="url", value="https://a.test/x", **overrides):
    row = {
        "entity_identity": {"ioc_type": ioc_type, "normalized_ioc_value": value},
        "features": {
            "ioc_type": ioc_type,
            "shape": 4,
            "source_count": 1,
            "threat_count": 1,
            "risk_score": 99,
        },
        "source_provenance": [{"source": "urlhaus", "source_record_id": "u1", "reporter": "r"}],
        "raw_context_assertions": [{"source": "urlhaus", "threat_type": "malware_download"}],
        "target": None,
    }
    row["features"].pop("risk_score")
    row.update(overrides)
    return row


def _target(ioc_type="url", value="https://a.test/x", target="positive", reason="fixture"):
    return {
        "schema_version": "1.0",
        "entity_identity": {"ioc_type": ioc_type, "normalized_ioc_value": value},
        "target": target,
        "target_reason": reason,
        "prediction_window": {"cutoff_at": "t0", "horizon_days": 7},
        "outcome_evidence": [{"source": "independent-fixture", "assertion_id": "a1"}],
    }


class ExperimentDatasetTests(unittest.TestCase):
    def test_exact_typed_identity_matching_and_unmatched_as_unknown(self):
        features = [_feature(), _feature("domain", "https://a.test/x")]
        targets = [_target()]
        datasets, summary = build_experiment_datasets(features, targets, feature_schema=_schema())
        a_rows = {row["entity_identity"]["ioc_type"]: row for row in datasets["A"]}
        self.assertEqual(len(a_rows), 2)
        self.assertEqual(a_rows["url"]["target"], "positive")
        self.assertEqual(a_rows["domain"]["target"], "unknown")
        self.assertEqual(a_rows["domain"]["target_metadata"]["reason"], "no_target_row_for_typed_identity")
        self.assertEqual(summary["target_counts_per_experiment"]["A"], {"positive": 1, "negative": 0, "unknown": 1})

    def test_a_b_c_columns_are_nested_subsets_and_metadata_is_not_feature_input(self):
        datasets, summary = build_experiment_datasets([_feature()], feature_schema=_schema())
        feature_sets = {key: set(rows[0]["features"]) for key, rows in datasets.items()}
        self.assertEqual(feature_sets["A"], {"ioc_type", "shape"})
        self.assertEqual(feature_sets["B"], feature_sets["A"] | {"source_count"})
        self.assertEqual(feature_sets["C"], feature_sets["B"] | {"threat_count"})
        for row in datasets["C"]:
            self.assertNotIn("risk_score", row["features"])
            self.assertNotIn("outcome_evidence", row["features"])
            self.assertIn("source_provenance", row)
            self.assertIn("raw_context_assertions", row)
        self.assertEqual(summary["experiment_feature_counts"], {"A": 2, "B": 3, "C": 4})
        self.assertEqual(summary["feature_source_row_coverage"], {"urlhaus": 1})
        self.assertEqual(summary["feature_source_observation_coverage"], {"urlhaus": 1})
        self.assertIsNone(summary["class_balance_per_experiment"]["A"]["labeled_positive_fraction"])

    def test_target_evidence_is_retained_outside_features(self):
        target = _target()
        datasets, _ = build_experiment_datasets([_feature()], [target], feature_schema=_schema())
        row = datasets["C"][0]
        self.assertEqual(row["target_metadata"]["outcome_evidence"], target["outcome_evidence"])
        self.assertEqual(row["target_metadata"]["prediction_window"], target["prediction_window"])
        self.assertNotIn("source", row["features"])

    def test_target_source_overlap_with_feature_provenance_is_rejected(self):
        target = _target()
        target["outcome_evidence"] = [{"source": "urlhaus", "assertion_id": "a1"}]
        with self.assertRaisesRegex(ValueError, "also occur in feature provenance"):
            build_experiment_datasets([_feature()], [target], feature_schema=_schema())

    def test_feature_row_target_cannot_assign_a_label(self):
        with self.assertRaisesRegex(ValueError, "may not carry assigned targets"):
            build_experiment_datasets([_feature(target="negative")], feature_schema=_schema())

    def test_wrong_or_unsupported_identity_fails(self):
        with self.assertRaisesRegex(ValueError, "unsupported IOC type"):
            build_experiment_datasets([_feature("unknown", "x")], feature_schema=_schema())
        bad_target = _target("domain", "https://a.test/x")
        # Target-only identities are reported deterministically, not attached by value alone.
        _, summary = build_experiment_datasets([_feature()], [bad_target], feature_schema=_schema())
        self.assertEqual(summary["unmatched_target_identity_count"], 1)

    def test_exact_duplicates_collapse_and_conflicting_duplicates_fail(self):
        feature = _feature()
        identical, summary = build_experiment_datasets([feature, feature], feature_schema=_schema())
        self.assertEqual(len(identical["A"]), 1)
        self.assertEqual(summary["input_feature_row_count"], 2)
        conflicting = _feature()
        conflicting["features"]["shape"] = 5
        with self.assertRaisesRegex(ValueError, "Conflicting duplicate feature"):
            build_experiment_datasets([feature, conflicting], feature_schema=_schema())

        target = _target()
        duplicate_target, _ = build_experiment_datasets([feature], [target, target], feature_schema=_schema())
        self.assertEqual(len(duplicate_target["A"]), 1)
        other_target = _target(target="negative", reason="different")
        with self.assertRaisesRegex(ValueError, "Conflicting duplicate target"):
            build_experiment_datasets([feature], [target, other_target], feature_schema=_schema())

    def test_output_order_is_stable(self):
        rows = [_feature("ipv4", "192.0.2.1"), _feature("domain", "example.org")]
        first, _ = build_experiment_datasets(rows, feature_schema=_schema())
        second, _ = build_experiment_datasets(list(reversed(rows)), feature_schema=_schema())
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
