import json
import unittest
from pathlib import Path

from research_data.targets.build_targets import OutcomeAssertion, build_targets


CUTOFF = "2026-01-01T00:00:00Z"
HORIZON_END = "2026-01-08T00:00:00Z"
IDENTITY = {"ioc_type": "url", "normalized_ioc_value": "https://sample.test/ioc"}


def harmful(assertion_id, timestamp, **overrides):
    record = {
        "assertion_id": assertion_id,
        **IDENTITY,
        "outcome_status": "confirmed_harmful",
        "independent_validation": True,
        "source": "independent-lab",
        "source_record_id": f"record-{assertion_id}",
        "source_reference": f"https://evidence.example/{assertion_id}",
        "confirmation_timestamp": timestamp,
        "adjudication_timestamp": None,
        "coverage_through": None,
        "supersedes_assertion_ids": [],
    }
    record.update(overrides)
    return record


def non_harmful(assertion_id, adjudicated_at, coverage_through=None, **overrides):
    record = {
        "assertion_id": assertion_id,
        **IDENTITY,
        "outcome_status": "adjudicated_non_harmful",
        "independent_validation": True,
        "source": "independent-lab",
        "source_record_id": f"record-{assertion_id}",
        "source_reference": f"https://evidence.example/{assertion_id}",
        "confirmation_timestamp": None,
        "adjudication_timestamp": adjudicated_at,
        "coverage_through": coverage_through,
        "supersedes_assertion_ids": [],
    }
    record.update(overrides)
    return record


class FutureOutcomeTargetTests(unittest.TestCase):
    def make_target(self, assertions, entities=None):
        return build_targets(entities or [IDENTITY], assertions, CUTOFF)

    def test_positive_confirmation_inside_seven_day_horizon(self):
        row = self.make_target([harmful("h1", "2026-01-04T10:00:00Z")])[0]
        self.assertEqual(row["target"], "positive")
        self.assertEqual(row["prediction_window"]["horizon_end"], HORIZON_END)
        self.assertEqual(row["target_reason"], "independent_harmful_confirmation_in_future_horizon")

    def test_no_outcome_is_unknown_not_negative(self):
        row = self.make_target([])[0]
        self.assertEqual(row["target"], "unknown")
        self.assertNotEqual(row["target"], "negative")

    def test_explicit_non_harmful_with_complete_coverage_is_negative(self):
        row = self.make_target([non_harmful("n1", CUTOFF, HORIZON_END)])[0]
        self.assertEqual(row["target"], "negative")

    def test_incomplete_negative_coverage_remains_unknown(self):
        row = self.make_target([non_harmful("n1", CUTOFF, "2026-01-05T00:00:00Z")])[0]
        self.assertEqual(row["target"], "unknown")
        self.assertEqual(row["target_reason"], "negative_assertion_without_full_horizon_coverage")

    def test_confirmation_before_cutoff_is_not_a_future_positive(self):
        row = self.make_target([harmful("old", "2025-12-31T23:59:59Z")])[0]
        self.assertEqual(row["target"], "unknown")
        self.assertEqual(row["outcome_evidence"][0]["decision_reason"], "confirmation_at_or_before_cutoff")

    def test_confirmation_exactly_at_cutoff_is_not_a_future_positive(self):
        row = self.make_target([harmful("at-cutoff", CUTOFF)])[0]
        self.assertEqual(row["target"], "unknown")
        self.assertEqual(row["outcome_evidence"][0]["decision_reason"], "confirmation_at_or_before_cutoff")

    def test_confirmation_after_horizon_does_not_label_entity(self):
        row = self.make_target([harmful("late", "2026-01-08T00:00:01Z")])[0]
        self.assertEqual(row["target"], "unknown")
        self.assertEqual(row["outcome_evidence"][0]["decision_reason"], "confirmation_after_horizon")

    def test_horizon_end_is_inclusive(self):
        row = self.make_target([harmful("end", HORIZON_END)])[0]
        self.assertEqual(row["target"], "positive")

    def test_duplicate_entity_observations_produce_one_label(self):
        rows = self.make_target(
            [harmful("h1", "2026-01-02T00:00:00Z")],
            entities=[IDENTITY, dict(IDENTITY)],
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["evidence_count"], 1)

    def test_multiple_confirmations_preserve_all_provenance_deterministically(self):
        assertions = [
            harmful("h2", "2026-01-05T00:00:00Z"),
            harmful("h1", "2026-01-03T00:00:00Z"),
        ]
        first = self.make_target(assertions)[0]
        second = self.make_target(list(reversed(assertions)))[0]
        self.assertEqual(first, second)
        self.assertEqual(first["target"], "positive")
        self.assertEqual(first["evidence_count"], 2)
        self.assertEqual([e["assertion_id"] for e in first["outcome_evidence"]], ["h1", "h2"])
        self.assertEqual(first["outcome_evidence"][0]["source_reference"], "https://evidence.example/h1")

    def test_conflicting_assertions_are_unknown_and_both_preserved(self):
        row = self.make_target([
            harmful("h1", "2026-01-03T00:00:00Z"),
            non_harmful("n1", "2026-01-04T00:00:00Z", HORIZON_END),
        ])[0]
        self.assertEqual(row["target"], "unknown")
        self.assertTrue(row["assertion_conflict_detected"])
        self.assertEqual(row["conflict_resolution"], "unresolved")
        self.assertEqual(row["evidence_count"], 2)

    def test_explicit_supersession_resolves_conflict_and_keeps_evidence(self):
        row = self.make_target([
            harmful("h1", "2026-01-03T00:00:00Z"),
            non_harmful(
                "n1", "2026-01-04T00:00:00Z", HORIZON_END,
                supersedes_assertion_ids=["h1"],
            ),
        ])[0]
        self.assertEqual(row["target"], "negative")
        self.assertTrue(row["assertion_conflict_detected"])
        self.assertEqual(row["conflict_resolution"], "explicit_supersession")
        self.assertEqual(row["evidence_count"], 2)
        self.assertTrue(row["outcome_evidence"][0]["superseded_by_explicit_adjudication"])

    def test_same_text_different_ioc_types_get_separate_targets(self):
        url_entity = {"ioc_type": "url", "normalized_ioc_value": "same-value"}
        domain_entity = {"ioc_type": "domain", "normalized_ioc_value": "same-value"}
        assertion = harmful(
            "h1", "2026-01-02T00:00:00Z",
            normalized_ioc_value="same-value",
        )
        rows = self.make_target([assertion], entities=[domain_entity, url_entity])
        by_type = {row["entity_identity"]["ioc_type"]: row["target"] for row in rows}
        self.assertEqual(by_type, {"domain": "unknown", "url": "positive"})

    def test_non_independent_assertion_cannot_create_target(self):
        row = self.make_target([
            harmful("unverified", "2026-01-02T00:00:00Z", independent_validation=False)
        ])[0]
        self.assertEqual(row["target"], "unknown")
        self.assertEqual(row["outcome_evidence"][0]["decision_reason"], "not_independently_validated")

    def test_output_separates_target_from_features_and_preserves_typed_identity(self):
        row = self.make_target([harmful("h1", "2026-01-02T00:00:00Z")])[0]
        self.assertEqual(row["entity_identity"], IDENTITY)
        self.assertNotIn("features", row)
        self.assertNotIn("risk_score", row)

    def test_machine_readable_schema_matches_builder_contract(self):
        schema_path = Path(__file__).resolve().parents[1] / "target_schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        assertion_schema = schema["outcome_assertion"]
        row_schema = schema["target_row"]

        self.assertEqual(schema["prediction_horizon_days"], 7)
        self.assertEqual(schema["identity_key"], ["ioc_type", "normalized_ioc_value"])
        self.assertEqual(schema["oneOf"], [{"$ref": "#/outcome_assertion"}, {"$ref": "#/target_row"}])
        self.assertIn("confirmation_timestamp", assertion_schema["properties"])
        self.assertIn("adjudication_timestamp", assertion_schema["properties"])
        self.assertIn("coverage_through", assertion_schema["properties"])
        self.assertEqual(row_schema["properties"]["target"]["enum"], ["positive", "negative", "unknown"])
        evidence_schema = row_schema["properties"]["outcome_evidence"]["items"]
        self.assertIn("considered_for_target", evidence_schema["properties"])
        self.assertIn("source_reference", evidence_schema["properties"])
        valid = OutcomeAssertion.model_validate(harmful("schema-check", "2026-01-02T00:00:00Z"))
        self.assertEqual(valid.outcome_status, "confirmed_harmful")
        row = self.make_target([harmful("schema-row", "2026-01-02T00:00:00Z")])[0]
        self.assertEqual(set(row), set(row_schema["properties"]))
        self.assertTrue(set(row["outcome_evidence"][0]).issubset(set(evidence_schema["properties"])))

    def test_timezone_naive_cutoff_or_assertion_is_rejected(self):
        with self.assertRaises(ValueError):
            build_targets([IDENTITY], [], "2026-01-01T00:00:00")
        with self.assertRaises(ValueError):
            OutcomeAssertion.model_validate(harmful("naive", "2026-01-02T00:00:00"))


if __name__ == "__main__":
    unittest.main()
