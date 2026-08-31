from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, TextIO

from .process import binary_version, file_sha256, run_offline_scenarios

ADAPTER_SCHEMA_VERSION = 1
ALLOWED_SCENARIOS = {"DP-000", "DP-101", "DP-102", "DP-103"}
CASE_FIELDS = {"schema_version", "case_id", "driver", "scenario_id"}


class AccordBenchContractError(ValueError):
    pass


@dataclass(frozen=True)
class AccordBenchCase:
    case_id: str
    scenario_id: str

    @classmethod
    def parse(cls, value: Any) -> "AccordBenchCase":
        if not isinstance(value, dict) or set(value) != CASE_FIELDS:
            raise AccordBenchContractError(
                "case must contain exactly schema_version, case_id, driver, and scenario_id"
            )
        if value["schema_version"] != ADAPTER_SCHEMA_VERSION:
            raise AccordBenchContractError("unsupported case schema_version")
        if value["driver"] != "accordlock_offline_native":
            raise AccordBenchContractError("unsupported system driver")
        case_id = value["case_id"]
        scenario_id = value["scenario_id"]
        if (
            not isinstance(case_id, str)
            or not case_id
            or len(case_id) > 128
            or case_id.strip() != case_id
            or any(character.isspace() for character in case_id)
        ):
            raise AccordBenchContractError("case_id is outside the bounded profile")
        if scenario_id not in ALLOWED_SCENARIOS:
            raise AccordBenchContractError("scenario_id is not implemented by the native CLI")
        return cls(case_id, scenario_id)


class AccordLockSystemAdapter:
    def __init__(
        self,
        cli_binary: Path,
        runner: Callable[[Path, str], dict[str, Any]] = run_offline_scenarios,
    ) -> None:
        self.cli_binary = cli_binary.resolve(strict=True)
        self.runner = runner
        self._reports: dict[str, dict[str, Any]] = {}

    def evaluate(self, case: AccordBenchCase) -> dict[str, Any]:
        report = self._reports.get(case.scenario_id)
        if report is None:
            report = self.runner(self.cli_binary, case.scenario_id)
            self._reports[case.scenario_id] = report
        system_output = _system_output(report, case.scenario_id)
        authorized = system_output.get("final_effect_authorized")
        decision = "ALLOW" if authorized is True else "DENY" if authorized is False else "INDETERMINATE"
        return {
            "schema_version": ADAPTER_SCHEMA_VERSION,
            "case_id": case.case_id,
            "adapter": "accordlock_offline_native_v1",
            "decision": decision,
            "reason_codes": _reason_codes(system_output, decision),
            "system_output": system_output,
            "metadata": {
                "system_under_test_executed": True,
                "decision_source": "native report scenarios[].accordlock",
                "oracle_or_reference_baseline_consumed": False,
                "provider": "NONE",
                "network_access": report.get("execution_profile", {}).get("network_access"),
                "production_ready": report.get("production_ready"),
                "benchmark": report.get("benchmark"),
                "binary_version": binary_version(self.cli_binary),
                "binary_sha256": file_sha256(self.cli_binary),
            },
        }


def run_jsonl(
    source: TextIO, destination: TextIO, adapter: AccordLockSystemAdapter
) -> int:
    seen: set[str] = set()
    for line_number, line in enumerate(source, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
            case = AccordBenchCase.parse(value)
            if case.case_id in seen:
                raise AccordBenchContractError("case_id must be unique within one adapter run")
            seen.add(case.case_id)
            result = adapter.evaluate(case)
        except (json.JSONDecodeError, AccordBenchContractError) as error:
            print(f"line {line_number}: {error}", file=sys.stderr)
            return 2
        destination.write(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")
        destination.flush()
    return 0


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Run AccordBench cases against real AccordLock native decisions."
    )
    command.add_argument(
        "--cli-binary",
        type=Path,
        default=os.environ.get("ACCORDLOCK_CLI_BIN"),
        required="ACCORDLOCK_CLI_BIN" not in os.environ,
        help="Path to the real AccordLock CLI binary.",
    )
    command.add_argument(
        "cases",
        nargs="?",
        type=Path,
        help="JSONL case file. Standard input is used when omitted.",
    )
    return command


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        adapter = AccordLockSystemAdapter(Path(arguments.cli_binary))
        if arguments.cases is None:
            return run_jsonl(sys.stdin, sys.stdout, adapter)
        with arguments.cases.open("r", encoding="utf-8") as source:
            return run_jsonl(source, sys.stdout, adapter)
    except Exception as error:
        print(f"AccordBench adapter failed: {error}", file=sys.stderr)
        return 2


def _system_output(report: dict[str, Any], scenario_id: str) -> dict[str, Any]:
    if report.get("report_kind") != "OFFLINE_DETERMINISTIC_SECURITY_DEMO":
        raise AccordBenchContractError("native CLI returned an unexpected report kind")
    scenarios = report.get("scenarios")
    if not isinstance(scenarios, list):
        raise AccordBenchContractError("native CLI report has no scenario list")
    for scenario in scenarios:
        if isinstance(scenario, dict) and scenario.get("scenario_id") == scenario_id:
            output = scenario.get("accordlock")
            if not isinstance(output, dict):
                break
            return output
    raise AccordBenchContractError("native CLI did not return the requested system output")


def _reason_codes(system_output: dict[str, Any], decision: str) -> list[str]:
    if decision == "INDETERMINATE":
        return ["SYSTEM_OUTPUT_INDETERMINATE"]
    reasons: list[str] = []
    for value in system_output.get("evaluation_reasons", []):
        if (
            isinstance(value, str)
            and not (decision == "DENY" and value == "ALLOWED")
            and value not in reasons
        ):
            reasons.append(value)
    if decision == "DENY":
        for field in ("authorization", "consumption", "post_admission_projection"):
            value = system_output.get(field)
            reason = value.get("reason") if isinstance(value, dict) else None
            if isinstance(reason, str) and reason not in {"NO_AUTHORIZATION", "NO_CONSUMPTION"}:
                if reason not in reasons:
                    reasons.append(reason)
    return reasons or (["ALLOWED"] if decision == "ALLOW" else ["DENIED"])
