#!/usr/bin/env python3
"""Verify that imported component trees match the public provenance record."""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "SOURCE_PROVENANCE.json"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
COMPONENT_KEYS = {
    "path",
    "sourceRepository",
    "upstreamRepository",
    "commit",
    "tree",
    "assembledTree",
    "trackedTreeExclusions",
    "postImportAdjustments",
}


class ProvenanceError(RuntimeError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProvenanceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_manifest() -> dict[str, Any]:
    if MANIFEST.stat().st_size > 1_048_576:
        raise ProvenanceError("SOURCE_PROVENANCE.json exceeds 1 MiB")
    try:
        value = json.loads(
            MANIFEST.read_text(encoding="utf-8"), object_pairs_hook=_unique_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProvenanceError(f"cannot load provenance manifest: {error}") from error
    if not isinstance(value, dict) or value.get("schemaVersion") != "1.0":
        raise ProvenanceError("unsupported provenance schema")
    components = value.get("components")
    if not isinstance(components, list) or not components:
        raise ProvenanceError("provenance components must be a non-empty list")
    return value


def _safe_relative(raw: Any, label: str) -> PurePosixPath:
    if not isinstance(raw, str) or not raw or "\\" in raw:
        raise ProvenanceError(f"{label} must be a non-empty forward-slash path")
    path = PurePosixPath(raw.rstrip("/"))
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ProvenanceError(f"{label} is not a normalized repository-relative path")
    return path


def _git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )
    if result.returncode != 0:
        diagnostic = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        raise ProvenanceError(f"git {' '.join(arguments)} failed: {diagnostic}")
    return result.stdout.strip()


def _require_hex(value: Any, label: str) -> str:
    if not isinstance(value, str) or not HEX40.fullmatch(value):
        raise ProvenanceError(f"{label} must be a lowercase 40-character Git object id")
    return value


def verify() -> tuple[int, int, int]:
    manifest = _load_manifest()
    seen: set[str] = set()
    exclusions_checked = 0
    adjustments_checked = 0

    for index, raw_component in enumerate(manifest["components"]):
        label = f"components[{index}]"
        if not isinstance(raw_component, dict):
            raise ProvenanceError(f"{label} must be an object")
        unknown = set(raw_component) - COMPONENT_KEYS
        required = {
            "path",
            "sourceRepository",
            "commit",
            "tree",
            "assembledTree",
            "trackedTreeExclusions",
            "postImportAdjustments",
        }
        missing = required - set(raw_component)
        if unknown or missing:
            raise ProvenanceError(
                f"{label} schema mismatch: unknown={sorted(unknown)} missing={sorted(missing)}"
            )
        component_path = _safe_relative(raw_component["path"], f"{label}.path")
        component = component_path.as_posix()
        if component in seen:
            raise ProvenanceError(f"duplicate component path: {component}")
        seen.add(component)
        if not (ROOT / component).is_dir():
            raise ProvenanceError(f"component directory does not exist: {component}")

        repository = raw_component["sourceRepository"]
        if not isinstance(repository, str) or not repository.startswith("https://github.com/"):
            raise ProvenanceError(f"{label}.sourceRepository must be an HTTPS GitHub URL")
        _require_hex(raw_component["commit"], f"{label}.commit")
        _require_hex(raw_component["tree"], f"{label}.tree")
        expected = _require_hex(raw_component["assembledTree"], f"{label}.assembledTree")
        observed = _git("rev-parse", f"HEAD:{component}")
        if observed != expected:
            raise ProvenanceError(
                f"assembled tree drift for {component}: expected={expected} observed={observed}"
            )

        exclusions = raw_component["trackedTreeExclusions"]
        if not isinstance(exclusions, list):
            raise ProvenanceError(f"{label}.trackedTreeExclusions must be a list")
        for exclusion_index, exclusion in enumerate(exclusions):
            if not isinstance(exclusion, dict) or set(exclusion) != {
                "path",
                "trackedEntries",
                "blobBytes",
                "reason",
            }:
                raise ProvenanceError(
                    f"{label}.trackedTreeExclusions[{exclusion_index}] has an invalid schema"
                )
            excluded = _safe_relative(
                exclusion["path"], f"{label}.trackedTreeExclusions[{exclusion_index}].path"
            )
            if (ROOT / component / Path(*excluded.parts)).exists():
                raise ProvenanceError(
                    f"declared excluded path is present in assembled tree: {component}/{excluded}"
                )
            if not isinstance(exclusion["trackedEntries"], int) or exclusion["trackedEntries"] < 1:
                raise ProvenanceError("trackedEntries must be a positive integer")
            if not isinstance(exclusion["blobBytes"], int) or exclusion["blobBytes"] < 1:
                raise ProvenanceError("blobBytes must be a positive integer")
            if not isinstance(exclusion["reason"], str) or not exclusion["reason"].strip():
                raise ProvenanceError("exclusion reason must be a non-empty string")
            exclusions_checked += 1

        adjustments = raw_component["postImportAdjustments"]
        if not isinstance(adjustments, list):
            raise ProvenanceError(f"{label}.postImportAdjustments must be a list")
        for adjustment_index, adjustment in enumerate(adjustments):
            if not isinstance(adjustment, dict) or set(adjustment) != {"path", "reason"}:
                raise ProvenanceError(
                    f"{label}.postImportAdjustments[{adjustment_index}] has an invalid schema"
                )
            adjusted = _safe_relative(
                adjustment["path"], f"{label}.postImportAdjustments[{adjustment_index}].path"
            )
            if not (ROOT / component / Path(*adjusted.parts)).is_file():
                raise ProvenanceError(
                    f"post-import adjustment path is missing: {component}/{adjusted}"
                )
            if not isinstance(adjustment["reason"], str) or not adjustment["reason"].strip():
                raise ProvenanceError("adjustment reason must be a non-empty string")
            adjustments_checked += 1

    return len(seen), exclusions_checked, adjustments_checked


def main() -> int:
    try:
        components, exclusions, adjustments = verify()
    except (OSError, ProvenanceError, subprocess.SubprocessError) as error:
        print(f"FAIL source_provenance: {error}", file=sys.stderr)
        return 1
    print(
        "PASS source_provenance "
        f"components={components} exclusions={exclusions} adjustments={adjustments}"
    )
    print(
        "BOUNDARY source provenance validates assembled component trees committed at HEAD; "
        "it does not fetch or authenticate external origin history"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
