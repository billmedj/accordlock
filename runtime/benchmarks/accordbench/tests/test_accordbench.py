from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from accordbench.core import (
    BASELINES,
    INTENT_PROFILE_ID,
    INTENT_PROFILE_VERSION,
    INTENT_PHENOMENON_VERDICTS,
    BenchmarkError,
    baseline_predictions,
    evaluate_profiles,
    fixture_digest,
    intent_profile_digest,
    load_cases,
    load_intent_profile,
    load_predictions,
)
from accordbench.schema_validation import SchemaContractError, load_schema, validate_file, validate_instance


ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "fixtures"
EXPECTED_DIGEST = "sha256:c1c3eff7c10c5f3775b340e0dd7772338805a68e3f3238d6b4b04d6ef12990dc"
EXPECTED_PROFILE_DIGEST = "sha256:a2e323960f02f4ce83c60e9908367325c8b2743909dcd39c70fe1237e46dea90"


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = load_cases(FIXTURES)
        cls.intent_cases = [case for case in cls.cases if case["suite"] == "intent_conformance"]

    def test_fixture_count_and_suite_balance(self) -> None:
        self.assertEqual(len(self.cases), 73)
        counts: dict[str, int] = {}
        for case in self.cases:
            counts[case["suite"]] = counts.get(case["suite"], 0) + 1
        self.assertEqual(
            counts,
            {
                "intent_conformance": 43,
                "safe_autonomy": 10,
                "shared_resources": 10,
                "transaction_lifecycle": 10,
            },
        )

    def test_normative_categories_are_covered(self) -> None:
        self.assertEqual(
            {case["category"] for case in self.intent_cases},
            {
                "exact_match",
                "safe_implication",
                "ambiguity",
                "contradiction",
                "missing_data",
                "scope_expansion",
                "substitution",
                "negation",
                "numbers_units",
                "temporal",
                "identity_resource",
                "prompt_injection",
                "metamorphic",
            },
        )

    def test_profile_manifest_matches_runtime_contract(self) -> None:
        profile = load_intent_profile()
        self.assertEqual(profile["id"], INTENT_PROFILE_ID)
        self.assertEqual(profile["version"], INTENT_PROFILE_VERSION)
        self.assertEqual(profile["status"], "normative")
        label_map = {item["label"]: item["verdict"] for item in profile["phenomenon_labels"]}
        self.assertEqual(label_map, INTENT_PHENOMENON_VERDICTS)
        self.assertEqual({item["value"] for item in profile["verdicts"]}, {"allow", "review", "deny"})
        self.assertIn("not runtime enforcement reason codes", profile["taxonomy_boundary"])

    def test_every_stable_phenomenon_has_a_reference_case(self) -> None:
        fixture_labels = {case["expected"]["phenomenon_label"] for case in self.intent_cases}
        self.assertEqual(fixture_labels, set(INTENT_PHENOMENON_VERDICTS))

    def test_metamorphic_relations_are_explicit_and_consistent(self) -> None:
        by_id = {case["id"]: case for case in self.intent_cases}
        transformed = [case for case in self.intent_cases if "relation" in case]
        self.assertEqual(len(transformed), 8)
        for case in transformed:
            relation = case["relation"]
            base = by_id[relation["base_case_id"]]
            self.assertNotIn("relation", base)
            if relation["type"] == "expected_invariance":
                for field in relation["invariant_fields"]:
                    self.assertEqual(case["expected"][field], base["expected"][field])
            else:
                for field in relation["sensitive_fields"]:
                    self.assertNotEqual(case["expected"][field], base["expected"][field])

    def test_review_flag_has_one_exact_meaning(self) -> None:
        for case in self.cases:
            with self.subTest(case=case["id"]):
                self.assertEqual(
                    case["expected"]["human_review_required"],
                    case["expected"]["verdict"] == "review",
                )

    def test_fixture_digest_is_stable(self) -> None:
        self.assertEqual(fixture_digest(self.cases), EXPECTED_DIGEST)
        self.assertEqual(intent_profile_digest(), EXPECTED_PROFILE_DIGEST)

    def test_shipped_instances_validate_against_shipped_schemas(self) -> None:
        for case in self.cases:
            with self.subTest(contract="case", instance=case["id"]):
                validate_file(case, ROOT / "schemas" / "case.schema.json", case["id"])

        profile = load_intent_profile()
        validate_file(
            profile,
            ROOT / "schemas" / "intent-conformance-profile.schema.json",
            "intent profile",
        )

        predictions = baseline_predictions("fixture_oracle", self.cases)
        for prediction in predictions.values():
            with self.subTest(contract="prediction", instance=prediction["id"]):
                validate_file(
                    prediction,
                    ROOT / "schemas" / "prediction.schema.json",
                    prediction["id"],
                )

        report = evaluate_profiles(self.cases, [("fixture_oracle", predictions)])
        validate_file(report, ROOT / "schemas" / "report.schema.json", "report")

    def test_validator_rejects_unsupported_schema_keywords(self) -> None:
        with self.assertRaisesRegex(SchemaContractError, "unsupported schema keyword"):
            validate_instance({}, {"type": "object", "dependentRequired": {"a": ["b"]}})

    def test_schema_contract_rejects_review_flag_mismatch(self) -> None:
        case = json.loads(
            json.dumps(next(item for item in self.intent_cases if item["expected"]["verdict"] == "allow"))
        )
        case["expected"]["human_review_required"] = True
        with self.assertRaisesRegex(SchemaContractError, "expected constant False"):
            validate_instance(case, load_schema(ROOT / "schemas" / "case.schema.json"), case["id"])

    def test_prediction_profile_and_report_contracts_reject_invalid_instances(self) -> None:
        prediction = {
            "id": "ic.example.invalid",
            "verdict": "deny",
            "phenomenon_label": "IC_CONTRADICTION",
            "interrupted": False,
            "completed": True,
        }
        with self.assertRaisesRegex(SchemaContractError, "expected constant 'allow'"):
            validate_file(prediction, ROOT / "schemas" / "prediction.schema.json", "prediction")

        profile = load_intent_profile()
        profile["unpublished_extension"] = True
        with self.assertRaisesRegex(SchemaContractError, "unsupported field.*unpublished_extension"):
            validate_file(
                profile,
                ROOT / "schemas" / "intent-conformance-profile.schema.json",
                "profile",
            )

        predictions = baseline_predictions("fixture_oracle", self.cases)
        report = evaluate_profiles(self.cases, [("fixture_oracle", predictions)])
        report["fixture_digest"] = "sha256:not-a-digest"
        with self.assertRaisesRegex(SchemaContractError, "does not match pattern"):
            validate_file(report, ROOT / "schemas" / "report.schema.json", "report")

    def test_committed_baseline_report_is_current(self) -> None:
        expected = evaluate_profiles(
            self.cases,
            [(name, baseline_predictions(name, self.cases)) for name in BASELINES],
        )
        committed = json.loads((ROOT / "results" / "local-baselines.json").read_text(encoding="utf-8"))
        self.assertEqual(committed, expected)


class MetricTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = load_cases(FIXTURES)

    def report_for(self, name: str) -> dict:
        report = evaluate_profiles(self.cases, [(name, baseline_predictions(name, self.cases))])
        return report["profiles"][0]

    def test_fixture_oracle_is_a_pipeline_self_check(self) -> None:
        profile = self.report_for("fixture_oracle")
        metrics = profile["metrics"]
        self.assertEqual(profile["verdict_mismatch_count"], 0)
        self.assertEqual(metrics["verdict_accuracy"], 1.0)
        self.assertEqual(metrics["critical_denial_recall"], 1.0)
        self.assertEqual(metrics["safe_coverage"], 1.0)
        self.assertEqual(metrics["intent_phenomenon_match_rate"], 1.0)
        self.assertEqual(metrics["metamorphic_invariance_rate"], 1.0)
        self.assertEqual(metrics["metamorphic_sensitivity_rate"], 1.0)
        self.assertEqual(metrics["unknown_effect_detection_rate"], 1.0)
        self.assertTrue(profile["intent_conformance"]["conformant"])

    def test_unrestricted_profile_exposes_unsafe_execution(self) -> None:
        profile = self.report_for("unrestricted")
        metrics = profile["metrics"]
        self.assertEqual(metrics["unsafe_allow_rate"], 1.0)
        self.assertEqual(metrics["replay_escape_rate"], 1.0)
        self.assertEqual(metrics["resource_violation_escape_rate"], 1.0)
        self.assertEqual(metrics["safe_coverage"], 1.0)
        self.assertEqual(metrics["critical_denial_recall"], 0.0)
        self.assertFalse(profile["intent_conformance"]["conformant"])

    def test_human_every_action_exposes_interruption_cost(self) -> None:
        metrics = self.report_for("human_every_action")["metrics"]
        self.assertEqual(metrics["interruption_rate"], 1.0)
        self.assertEqual(metrics["avoidable_interruption_rate"], 1.0)
        self.assertEqual(metrics["safe_coverage"], 0.0)
        self.assertEqual(metrics["review_match_rate"], 1.0)

    def test_deny_all_exposes_false_refusal(self) -> None:
        metrics = self.report_for("deny_all")["metrics"]
        self.assertEqual(metrics["critical_denial_recall"], 1.0)
        self.assertEqual(metrics["false_refusal_rate"], 1.0)
        self.assertEqual(metrics["safe_coverage"], 0.0)

    def test_metamorphic_failure_is_reported_without_a_similarity_score(self) -> None:
        predictions = baseline_predictions("fixture_oracle", self.cases)
        transformed_id = "ic.metamorphic.negation_surface"
        predictions[transformed_id].update(
            verdict="allow",
            phenomenon_label="IC_EXACT_MATCH",
            interrupted=False,
            completed=True,
        )
        profile = evaluate_profiles(self.cases, [("mutated", predictions)])["profiles"][0]
        conformance = profile["intent_conformance"]
        self.assertFalse(conformance["conformant"])
        self.assertEqual(conformance["metamorphic_invariance"]["failure_sample"], [transformed_id])

    def test_metamorphic_insensitivity_is_reported(self) -> None:
        predictions = baseline_predictions("fixture_oracle", self.cases)
        transformed_id = "ic.metamorphic.scope_bound_expanded"
        base_id = "ic.metamorphic.scope_bound_base"
        predictions[transformed_id] = dict(predictions[base_id], id=transformed_id)
        profile = evaluate_profiles(self.cases, [("mutated", predictions)])["profiles"][0]
        conformance = profile["intent_conformance"]
        self.assertFalse(conformance["conformant"])
        self.assertEqual(conformance["metamorphic_sensitivity"]["failure_sample"], [transformed_id])

    def test_report_is_deterministic(self) -> None:
        profiles = [("unrestricted", baseline_predictions("unrestricted", self.cases))]
        first = json.dumps(evaluate_profiles(self.cases, profiles), sort_keys=True)
        second = json.dumps(evaluate_profiles(self.cases, profiles), sort_keys=True)
        self.assertEqual(first, second)


class PredictionContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = load_cases(FIXTURES)

    def _write_predictions(self, directory: str, predictions: dict[str, dict]) -> Path:
        path = Path(directory) / "predictions.jsonl"
        path.write_text(
            "".join(json.dumps(predictions[case["id"]], sort_keys=True) + "\n" for case in self.cases),
            encoding="utf-8",
        )
        return path

    def test_complete_prediction_file_loads(self) -> None:
        predictions = baseline_predictions("fixture_oracle", self.cases)
        with tempfile.TemporaryDirectory() as directory:
            loaded = load_predictions(self._write_predictions(directory, predictions), self.cases)
        self.assertEqual(set(loaded), set(predictions))

    def test_incomplete_prediction_file_is_rejected(self) -> None:
        prediction = baseline_predictions("fixture_oracle", self.cases)[self.cases[0]["id"]]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "predictions.jsonl"
            path.write_text(json.dumps(prediction) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(BenchmarkError, "predictions missing"):
                load_predictions(path, self.cases)

    def test_probability_like_risk_score_is_not_in_the_contract(self) -> None:
        predictions = baseline_predictions("fixture_oracle", self.cases)
        predictions[self.cases[0]["id"]]["risk_score"] = 0.75
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_predictions(directory, predictions)
            with self.assertRaisesRegex(BenchmarkError, "unsupported field.*risk_score"):
                load_predictions(path, self.cases)

    def test_intent_case_requires_a_phenomenon_label(self) -> None:
        predictions = baseline_predictions("fixture_oracle", self.cases)
        predictions["ic.exact_match.restart_staging"].pop("phenomenon_label")
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_predictions(directory, predictions)
            with self.assertRaisesRegex(BenchmarkError, "require a supported phenomenon_label"):
                load_predictions(path, self.cases)

    def test_phenomenon_label_must_match_the_verdict(self) -> None:
        predictions = baseline_predictions("fixture_oracle", self.cases)
        predictions["ic.exact_match.restart_staging"]["phenomenon_label"] = "IC_CONTRADICTION"
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_predictions(directory, predictions)
            with self.assertRaisesRegex(BenchmarkError, "is not valid for verdict allow"):
                load_predictions(path, self.cases)


if __name__ == "__main__":
    unittest.main()
