import io
import json
import sys
import unittest
from pathlib import Path

from accordlock_demos.accordbench import (
    AccordBenchCase,
    AccordBenchContractError,
    AccordLockSystemAdapter,
    run_jsonl,
)


def fake_report(system_authorized: bool) -> dict:
    return {
        "report_kind": "OFFLINE_DETERMINISTIC_SECURITY_DEMO",
        "production_ready": False,
        "benchmark": False,
        "execution_profile": {"network_access": "NOT_ACCESSED"},
        "scenarios": [
            {
                "scenario_id": "DP-102",
                "baseline": {"allow": True},
                "accordlock": {
                    "evaluation_outcome": "DENY",
                    "evaluation_reasons": ["REVIEW_NOT_APPROVED"],
                    "authorization": {"status": "NOT_REACHED", "reason": "EVALUATION_DENIED"},
                    "consumption": {"status": "REJECTED", "reason": "AUTHORITY_MISMATCH"},
                    "post_admission_projection": {"status": "NOT_REACHED", "reason": "NO_CONSUMPTION"},
                    "final_effect_authorized": system_authorized,
                },
            }
        ],
    }


class AccordBenchContractTests(unittest.TestCase):
    def test_rejects_oracle_and_expected_fields(self) -> None:
        for forbidden in ("oracle", "expected", "baseline", "label"):
            value = {
                "schema_version": 1,
                "case_id": "case-1",
                "driver": "accordlock_offline_native",
                "scenario_id": "DP-102",
                forbidden: "DENY",
            }
            with self.assertRaises(AccordBenchContractError):
                AccordBenchCase.parse(value)

    def test_uses_native_system_output_not_reference_baseline(self) -> None:
        adapter = AccordLockSystemAdapter(
            Path(sys.executable), runner=lambda _binary, _scenario: fake_report(False)
        )
        result = adapter.evaluate(AccordBenchCase("case-1", "DP-102"))
        self.assertEqual(result["decision"], "DENY")
        self.assertIn("AUTHORITY_MISMATCH", result["reason_codes"])
        self.assertNotIn("baseline", result)
        self.assertFalse(result["metadata"]["oracle_or_reference_baseline_consumed"])

    def test_jsonl_rejects_duplicate_case_ids(self) -> None:
        line = json.dumps(
            {
                "schema_version": 1,
                "case_id": "duplicate",
                "driver": "accordlock_offline_native",
                "scenario_id": "DP-102",
            }
        )
        adapter = AccordLockSystemAdapter(
            Path(sys.executable), runner=lambda _binary, _scenario: fake_report(False)
        )
        destination = io.StringIO()
        self.assertEqual(run_jsonl(io.StringIO(f"{line}\n{line}\n"), destination, adapter), 2)
        self.assertEqual(len(destination.getvalue().splitlines()), 1)


if __name__ == "__main__":
    unittest.main()
