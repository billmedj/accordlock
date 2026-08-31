"""Command-line interface for assurance traceability validation."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .linter import ManifestLoadError, verify_manifest


def _default_root() -> Path:
    # This package lives at <repository>/assurance, so the parent is the
    # repository root. An independently packaged copy should pass --root explicitly.
    return Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="accordlock-assurance",
        description=(
            "Validate that assurance claims reference existing Lean theorems, "
            "configured TLA+ invariants, Rust sources, and Rust tests."
        ),
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=_default_root(),
        help="monorepo root (default: parent of the assurance package)",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "claims.yaml",
        help="claims manifest (default: claims.yaml beside this package)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="emit a stable JSON report",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = verify_manifest(args.manifest, args.root)
    except ManifestLoadError as error:
        if args.as_json:
            print(
                json.dumps(
                    {
                        "schema_version": 1,
                        "ok": False,
                        "claims_checked": 0,
                        "findings": [
                            {
                                "code": "manifest.load",
                                "location": str(args.manifest),
                                "message": str(error),
                            }
                        ],
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        else:
            print(f"ERROR manifest.load {args.manifest}: {error}", file=sys.stderr)
        return 1

    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    elif report.ok:
        print(
            "Assurance traceability verified: "
            f"{report.claims_checked} claims, "
            f"{report.references_checked} references."
        )
    else:
        for finding in report.findings:
            print(
                f"ERROR {finding.code} {finding.location}: {finding.message}",
                file=sys.stderr,
            )
        print(
            f"Assurance traceability failed with {len(report.findings)} finding(s).",
            file=sys.stderr,
        )
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
