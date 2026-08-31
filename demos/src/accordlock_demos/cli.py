from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .report import write_reports
from .suite import run_adversarial_suite


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description="Run AccordLock's provider-free adversarial demonstration."
    )
    command.add_argument(
        "--cli-binary",
        type=Path,
        default=os.environ.get("ACCORDLOCK_CLI_BIN"),
        required="ACCORDLOCK_CLI_BIN" not in os.environ,
        help="Path to the real AccordLock CLI binary.",
    )
    command.add_argument(
        "--runtime-binary",
        type=Path,
        default=os.environ.get("ACCORDLOCK_RUNTIME_BIN"),
        required="ACCORDLOCK_RUNTIME_BIN" not in os.environ,
        help="Path to the real accordlock-agent-runtime binary.",
    )
    command.add_argument(
        "--output-directory",
        type=Path,
        default=Path("artifacts"),
        help="Directory for JSON and Markdown reports.",
    )
    return command


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    output = arguments.output_directory.resolve()
    run_parent = output.parent / ".demo-runs"
    try:
        report = run_adversarial_suite(
            Path(arguments.cli_binary), Path(arguments.runtime_binary), run_parent
        )
        json_path, markdown_path = write_reports(report, output)
    except Exception as error:
        print(f"AccordLock demo failed: {error}", file=sys.stderr)
        return 2
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")
    return 0 if report["status"] == "PASS" else 1
