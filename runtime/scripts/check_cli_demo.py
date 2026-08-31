#!/usr/bin/env python3
"""Execute the synthetic CLI twice and reject nondeterministic or inflated output."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


EXPECTED_SCENARIOS = ["DP-000", "DP-101", "DP-102", "DP-103"]


def execute(cargo: str, root: Path) -> bytes:
    command = [
        cargo,
        "run",
        "--locked",
        "--quiet",
        "-p",
        "accordlock-cli",
        "--",
        "demo",
        "--scenario",
        "all",
    ]
    environment = os.environ.copy()
    inherited_rustflags = environment.get("RUSTFLAGS", "").strip()
    environment["RUSTFLAGS"] = " ".join(
        value for value in (inherited_rustflags, "-A linker_messages") if value
    )
    result = subprocess.run(
        command,
        cwd=root,
        env=environment,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        sys.stderr.buffer.write(result.stderr)
        raise RuntimeError(f"CLI exited with code {result.returncode}")
    if result.stderr:
        sys.stderr.buffer.write(result.stderr)
        raise RuntimeError("CLI emitted stderr during a successful run")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    try:
        first = execute(args.cargo, args.root)
        second = execute(args.cargo, args.root)
        if first != second:
            raise RuntimeError("two fresh CLI invocations produced different bytes")
        report = json.loads(first)
        if report.get("schema_version") != 2:
            raise RuntimeError("CLI report schema_version boundary is absent or changed")
        if report.get("report_kind") != "OFFLINE_DETERMINISTIC_SECURITY_DEMO":
            raise RuntimeError("CLI report_kind boundary is absent or changed")
        if report.get("production_ready") is not False:
            raise RuntimeError("offline CLI output must declare production_ready=false")
        if report.get("benchmark") is not False:
            raise RuntimeError("synthetic CLI output must declare benchmark=false")
        execution_profile = report.get("execution_profile")
        if not isinstance(execution_profile, dict):
            raise RuntimeError("offline CLI execution_profile is absent")
        if execution_profile.get("network_access") != "NOT_ACCESSED":
            raise RuntimeError("offline CLI must declare that it did not access the network")
        if execution_profile.get("external_mutation") != "NONE":
            raise RuntimeError("offline CLI must declare that it made no external mutation")
        scenarios = report.get("scenarios")
        identifiers = [item.get("scenario_id") for item in scenarios] if isinstance(scenarios, list) else []
        if identifiers != EXPECTED_SCENARIOS:
            raise RuntimeError(f"unexpected ordered scenario set: {identifiers}")
        if not all(item.get("synthetic") is True for item in scenarios):
            raise RuntimeError("every CLI scenario must declare synthetic=true")
        coverage = report.get("coverage")
        live_gates = coverage.get("live_gates") if isinstance(coverage, dict) else None
        if not isinstance(live_gates, list) or len(live_gates) != 3:
            raise RuntimeError("offline CLI must expose exactly three live-production checks")
        if any(item.get("satisfied") is not False for item in live_gates):
            raise RuntimeError("offline execution cannot satisfy a live-production check")
    except (OSError, RuntimeError, json.JSONDecodeError) as error:
        print(f"FAIL cli_synthetic_demo: {error}", file=sys.stderr)
        return 1
    print(
        "PASS cli_synthetic_demo deterministic_runs=2 scenarios=4 "
        "production_ready=false benchmark=false live_gates=3"
    )
    print(
        "BOUNDARY deterministic offline execution only; no network, external mutation, "
        "G0, benchmark, or independent-validation claim"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
