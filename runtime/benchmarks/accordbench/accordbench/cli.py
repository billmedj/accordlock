"""Command-line interface for AccordBench."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import (
    BASELINES,
    BenchmarkError,
    baseline_predictions,
    evaluate_profiles,
    load_cases,
    load_predictions,
)


PACKAGE_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FIXTURES = PACKAGE_ROOT / "fixtures"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="accordbench",
        description="Run deterministic safety and intent-conformance evaluations for autonomous agents.",
    )
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES, help="Directory containing JSONL cases.")
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--predictions", type=Path, help="Complete candidate prediction JSONL file.")
    source.add_argument("--baseline", choices=BASELINES, help="Run one built-in comparison profile.")
    parser.add_argument("--name", help="Profile name used with --predictions.")
    parser.add_argument("--output", type=Path, help="Write the report to this path instead of standard output.")
    parser.add_argument("--compact", action="store_true", help="Emit compact JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        cases = load_cases(args.fixtures)
        if args.predictions:
            name = args.name or args.predictions.stem
            profiles = [(name, load_predictions(args.predictions, cases))]
        elif args.baseline:
            profiles = [(args.baseline, baseline_predictions(args.baseline, cases))]
        else:
            profiles = [(name, baseline_predictions(name, cases)) for name in BASELINES]
        report = evaluate_profiles(cases, profiles)
    except BenchmarkError as exc:
        print(f"accordbench: {exc}", file=sys.stderr)
        return 2

    indent = None if args.compact else 2
    rendered = json.dumps(report, indent=indent, sort_keys=True, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(rendered)
    return 0
