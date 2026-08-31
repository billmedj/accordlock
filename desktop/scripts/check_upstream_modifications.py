#!/usr/bin/env python3
"""Audit modified Goose files against AccordLock's pinned upstream tree.

The audit is deliberately network-free. ``GOOSE_UPSTREAM_MANIFEST.txt`` records
every blob and mode in the exact upstream commit, including the two upstream
subtrees intentionally omitted from this distribution. The current Git index
is compared with that manifest, and ``MODIFICATIONS.md`` must be an exact,
deterministically rendered inventory of the result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "GOOSE_UPSTREAM_MANIFEST.txt"
REPORT_PATH = ROOT / "MODIFICATIONS.md"

UPSTREAM_PROJECT = "https://github.com/aaif-goose/goose"
UPSTREAM_VERSION = "v1.47.0"
UPSTREAM_REVISION = "f9c7aaccde4834810dfd13d5efa8f0d39ba28a20"
UPSTREAM_TREE = "a640469c0b798464250561cca0238c4cabfbf5c1"
NOTICE_TEXT = "Modified by AccordLock contributors; see UPSTREAM.md."

EXCLUDED_PREFIXES = (
    "documentation/",
    "services/ask-ai-bot/",
)

# These files cannot safely carry a source comment. The explanation is emitted
# verbatim into MODIFICATIONS.md, making each exception explicit and reviewable.
NOTICE_EXCEPTIONS = {
    "Cargo.lock": (
        "Cargo-generated lockfile; manual comments are not stable under "
        "regeneration."
    ),
    "ui/desktop/src/built-in-extensions.json": (
        "Strict JSON array consumed as extension data; no schema-neutral comment "
        "or metadata location exists."
    ),
    "ui/desktop/src/components/settings/extensions/bundled-extensions.json": (
        "Strict JSON array consumed as extension data; no schema-neutral comment "
        "or metadata location exists."
    ),
    "ui/desktop/src/i18n/messages/en.json": (
        "Strict message-catalog JSON; an extra key changes the compiled catalog "
        "rather than recording inert metadata."
    ),
    "crates/goose/src/agents/snapshots/goose__agents__prompt_manager__tests__all_platform_extensions.snap": (
        "Insta-generated prompt snapshot; an in-file comment would change the "
        "asserted prompt or invalidate the snapshot metadata header."
    ),
    "ui/desktop/src/images/icon-512.png": "Binary PNG application asset.",
    "ui/desktop/src/images/icon-light.icns": "Binary Apple icon asset.",
    "ui/desktop/src/images/icon-light.png": "Binary PNG application asset.",
    "ui/desktop/src/images/icon.icns": "Binary Apple icon asset.",
    "ui/desktop/src/images/icon.ico": "Binary Windows icon asset.",
    "ui/desktop/src/images/icon.png": "Binary PNG application asset.",
    "ui/desktop/src/images/icon@2x.png": "Binary PNG application asset.",
    "ui/desktop/src/images/iconTemplate.png": "Binary PNG tray asset.",
    "ui/desktop/src/images/iconTemplate@2x.png": "Binary PNG tray asset.",
    "ui/desktop/src/images/iconTemplateUpdate.png": "Binary PNG tray asset.",
    "ui/desktop/src/images/iconTemplateUpdate@2x.png": "Binary PNG tray asset.",
    "ui/pnpm-lock.yaml": (
        "pnpm-generated lockfile; manual comments are not stable under "
        "regeneration."
    ),
}

# These values describe the final audited baseline. Changing an inherited file,
# restoring an omitted subtree, or changing provenance requires an explicit
# review and baseline update; a same-count substitution is still caught because
# MODIFICATIONS.md contains the exact path sets.
EXPECTED_UPSTREAM_FILES = 2369
EXPECTED_INCLUDED_UPSTREAM_FILES = 1514
EXPECTED_EXCLUDED_UPSTREAM_FILES = 855
EXPECTED_MODIFIED_FILES = 368
EXPECTED_UNCHANGED_FILES = 1109
EXPECTED_REMOVED_FILES = 37
EXPECTED_ADDED_FILES = 214
EXPECTED_MANIFEST_SHA256 = "92274f915d061559f6f42a067bfbfe2ff49eedb5d453afd6900ca8c5220220d8"
EXPECTED_PATH_SET_SHA256 = {
    "modified": "6667f78e9ea506dc8d3caf18ec712cb48e5e5eb76d7d40dde49d50a168e2b1ff",
    "unchanged": "2a267d6ba28bc8b7c53523180d7a8eb0f7c3a48e1fa2d3610e0f3a3c39af4282",
    "added": "22d3036da31c39f0f08cd3bdcec472b61a174114bb7f723b92b1be751a5336b3",
    "removed": "fdb0c15a2cbf18f484b3c71f72ab9698374ac174d902a0a3e2d9f8d9274bf739",
    "excluded": "e151bf44b2acf79b34a680f7173a7fed91d9f532ff8897d3f931cda27822eb83",
}


class AuditError(RuntimeError):
    """Raised when provenance or the working tree cannot be audited safely."""


@dataclass(frozen=True)
class Entry:
    mode: str
    object_id: str


@dataclass(frozen=True)
class Inventory:
    included_upstream: dict[str, Entry]
    excluded_upstream: dict[str, Entry]
    current: dict[str, Entry]
    modified: tuple[str, ...]
    unchanged: tuple[str, ...]
    added: tuple[str, ...]
    removed: tuple[str, ...]


def _run_git(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _parse_manifest(path: Path = MANIFEST_PATH) -> tuple[dict[str, Entry], dict[str, Entry]]:
    included: dict[str, Entry] = {}
    excluded: dict[str, Entry] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise AuditError(f"unable to read {path.name}: {error}") from error

    for line_number, line in enumerate(lines, start=1):
        if not line or line.startswith("#"):
            continue
        fields = line.split("\t", 3)
        if len(fields) != 4:
            raise AuditError(f"{path.name}:{line_number}: malformed manifest entry")
        disposition, mode, object_id, relative_path = fields
        if disposition not in {"included", "excluded"}:
            raise AuditError(
                f"{path.name}:{line_number}: invalid disposition {disposition!r}"
            )
        if not re.fullmatch(r"[0-7]{6}", mode):
            raise AuditError(f"{path.name}:{line_number}: invalid Git mode {mode!r}")
        if not re.fullmatch(r"[0-9a-f]{40}", object_id):
            raise AuditError(
                f"{path.name}:{line_number}: invalid Git object {object_id!r}"
            )
        if not relative_path or "\\" in relative_path:
            raise AuditError(f"{path.name}:{line_number}: invalid repository path")
        target = included if disposition == "included" else excluded
        if relative_path in included or relative_path in excluded:
            raise AuditError(f"{path.name}:{line_number}: duplicate path {relative_path}")
        target[relative_path] = Entry(mode, object_id)

    return included, excluded


def _current_index() -> dict[str, Entry]:
    result = _run_git("ls-files", "-s", "-z", "--", ".")
    entries: dict[str, Entry] = {}
    for raw_entry in result.stdout.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, object_id, stage = metadata.decode("ascii").split(" ")
            relative_path = raw_path.decode("utf-8", errors="strict").replace("\\", "/")
        except (UnicodeError, ValueError) as error:
            raise AuditError("git ls-files returned an unparseable index entry") from error
        if stage != "0":
            raise AuditError(f"unmerged index entry cannot be audited: {relative_path}")
        entries[relative_path] = Entry(mode, object_id)
    return entries


def analyze() -> Inventory:
    included, excluded = _parse_manifest()
    current = _current_index()

    invalid_exclusions = tuple(
        sorted(path for path in excluded if not path.startswith(EXCLUDED_PREFIXES))
    )
    if invalid_exclusions:
        raise AuditError(
            "manifest marks paths outside the approved exclusions: "
            + ", ".join(invalid_exclusions[:5])
        )
    misclassified_inclusions = tuple(
        sorted(path for path in included if path.startswith(EXCLUDED_PREFIXES))
    )
    if misclassified_inclusions:
        raise AuditError(
            "manifest includes paths from an excluded subtree: "
            + ", ".join(misclassified_inclusions[:5])
        )
    restored_exclusions = tuple(sorted(set(current) & set(excluded)))
    if restored_exclusions:
        raise AuditError(
            "an intentionally omitted upstream path was restored without provenance review: "
            + ", ".join(restored_exclusions[:5])
        )

    shared = set(current) & set(included)
    modified = tuple(sorted(path for path in shared if current[path] != included[path]))
    unchanged = tuple(sorted(path for path in shared if current[path] == included[path]))
    added = tuple(sorted(set(current) - set(included) - set(excluded)))
    removed = tuple(sorted(set(included) - set(current)))
    return Inventory(
        included_upstream=included,
        excluded_upstream=excluded,
        current=current,
        modified=modified,
        unchanged=unchanged,
        added=added,
        removed=removed,
    )


def _path_set_digest(paths: tuple[str, ...] | list[str]) -> str:
    payload = ("\0".join(paths) + "\0").encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _check_baseline(inventory: Inventory) -> list[str]:
    actual = {
        "upstream files": len(inventory.included_upstream)
        + len(inventory.excluded_upstream),
        "included upstream files": len(inventory.included_upstream),
        "excluded upstream files": len(inventory.excluded_upstream),
        "modified shared files": len(inventory.modified),
        "unchanged shared files": len(inventory.unchanged),
        "removed upstream files": len(inventory.removed),
        "AccordLock-only files": len(inventory.added),
    }
    expected = {
        "upstream files": EXPECTED_UPSTREAM_FILES,
        "included upstream files": EXPECTED_INCLUDED_UPSTREAM_FILES,
        "excluded upstream files": EXPECTED_EXCLUDED_UPSTREAM_FILES,
        "modified shared files": EXPECTED_MODIFIED_FILES,
        "unchanged shared files": EXPECTED_UNCHANGED_FILES,
        "removed upstream files": EXPECTED_REMOVED_FILES,
        "AccordLock-only files": EXPECTED_ADDED_FILES,
    }
    errors = [
        f"baseline mismatch for {label}: expected {expected[label]}, got {value}"
        for label, value in actual.items()
        if value != expected[label]
    ]

    manifest_lines = tuple(
        line
        for line in MANIFEST_PATH.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    )
    manifest_digest = _path_set_digest(manifest_lines)
    if manifest_digest != EXPECTED_MANIFEST_SHA256:
        errors.append(
            "pinned upstream manifest digest mismatch: "
            f"expected {EXPECTED_MANIFEST_SHA256}, got {manifest_digest}"
        )

    path_sets = {
        "modified": inventory.modified,
        "unchanged": inventory.unchanged,
        "added": inventory.added,
        "removed": inventory.removed,
        "excluded": tuple(sorted(inventory.excluded_upstream)),
    }
    for label, paths in path_sets.items():
        digest = _path_set_digest(paths)
        if digest != EXPECTED_PATH_SET_SHA256[label]:
            errors.append(
                f"exact {label} path-set digest mismatch: "
                f"expected {EXPECTED_PATH_SET_SHA256[label]}, got {digest}"
            )
    return errors


def _check_notices(inventory: Inventory) -> list[str]:
    errors: list[str] = []
    modified = set(inventory.modified)
    stale_exceptions = sorted(set(NOTICE_EXCEPTIONS) - modified)
    if stale_exceptions:
        errors.append(
            "notice exceptions are not modified upstream files: "
            + ", ".join(stale_exceptions)
        )

    for relative_path in inventory.modified:
        if relative_path in NOTICE_EXCEPTIONS:
            continue
        path = ROOT / relative_path
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(
                f"{relative_path}: modified non-UTF-8 file lacks an explicit notice exception"
            )
            continue
        except OSError as error:
            errors.append(f"{relative_path}: unable to read modified file: {error}")
            continue
        first_lines = "\n".join(content.splitlines()[:12])
        if NOTICE_TEXT not in first_lines:
            errors.append(f"{relative_path}: missing prominent modification notice")

        lines = content.splitlines()
        if Path(relative_path).suffix in {".cjs", ".js", ".mjs", ".ts", ".tsx"} and (
            f"// {NOTICE_TEXT}" not in lines[:12]
        ):
            errors.append(
                f"{relative_path}: JavaScript-family notices must use an inert // comment"
            )
        if inventory.current[relative_path].mode == "100755" and (
            not lines or not lines[0].startswith("#!")
        ):
            errors.append(f"{relative_path}: executable shebang is not byte-leading")
        if relative_path.endswith(".html") and (
            not lines or not lines[0].lower().startswith("<!doctype")
        ):
            errors.append(f"{relative_path}: HTML doctype is not leading")
        if relative_path.endswith(".plist") and (
            not lines or not lines[0].startswith("<?xml")
        ):
            errors.append(f"{relative_path}: XML declaration is not leading")
        if relative_path == "Dockerfile" and (
            not lines or not lines[0].startswith("# syntax=")
        ):
            errors.append(f"{relative_path}: Docker syntax directive is not leading")
        if relative_path in {
            ".github/ISSUE_TEMPLATE/bug_report.md",
            ".github/ISSUE_TEMPLATE/feature_request.md",
        } and (not lines or lines[0] != "---"):
            errors.append(f"{relative_path}: GitHub front matter is not leading")
        if relative_path == "crates/goose/src/prompts/system.md" and (
            not lines or lines[0] != f"{{# {NOTICE_TEXT} #}}"
        ):
            errors.append(f"{relative_path}: notice must remain an inert Tera comment")
        if relative_path in {"ui/package.json", "ui/desktop/package.json"}:
            try:
                package_metadata = json.loads(content)
            except json.JSONDecodeError as error:
                errors.append(f"{relative_path}: invalid package JSON: {error}")
            else:
                if package_metadata.get("accordlockModificationNotice") != NOTICE_TEXT:
                    errors.append(
                        f"{relative_path}: missing schema-neutral modification metadata"
                    )
    return errors


def render_report(inventory: Inventory) -> str:
    notice_paths = tuple(
        path for path in inventory.modified if path not in NOTICE_EXCEPTIONS
    )
    lines = [
        "# Modifications from Goose",
        "",
        "This file is the exact, machine-checked change inventory for AccordLock Desktop.",
        "It implements the modified-file notice boundary for the Apache License 2.0",
        "without placing invalid comments inside strict data formats or binary assets.",
        "",
        "## Pinned upstream",
        "",
        f"- Project: [{UPSTREAM_PROJECT}]({UPSTREAM_PROJECT})",
        f"- Version: `{UPSTREAM_VERSION}`",
        f"- Commit: `{UPSTREAM_REVISION}`",
        f"- Tree: `{UPSTREAM_TREE}`",
        "- Manifest: `GOOSE_UPSTREAM_MANIFEST.txt`",
        "- Intentionally omitted upstream subtrees: `documentation/` and "
        "`services/ask-ai-bot/`",
        "",
        "## Audited result",
        "",
        f"- {len(inventory.included_upstream) + len(inventory.excluded_upstream)} files in the pinned upstream tree",
        f"- {len(inventory.excluded_upstream)} upstream files under the two explicit exclusions",
        f"- {len(inventory.modified)} inherited files modified and distributed",
        f"- {len(notice_paths)} modified text/source files with an in-file notice",
        f"- {len(NOTICE_EXCEPTIONS)} modified generated, strict-data, or binary files documented as exceptions",
        f"- {len(inventory.unchanged)} inherited files distributed unchanged",
        f"- {len(inventory.added)} AccordLock-only files",
        f"- {len(inventory.removed)} other upstream files omitted from this distribution",
        "",
        "The standard in-file notice is:",
        "",
        f"> {NOTICE_TEXT}",
        "",
        "Comments are placed after shebangs, XML declarations, Docker syntax",
        "directives, and other required leading syntax. The runtime system-prompt",
        "notice uses a Tera comment and is removed before model input. Package JSON",
        "uses a schema-neutral top-level metadata field.",
        "",
        "## Modified inherited files with in-file notices",
        "",
    ]
    lines.extend(f"- `{path}`" for path in notice_paths)
    lines.extend(
        [
            "",
            "## Modified inherited files documented out of band",
            "",
            "These files are still modified-file exceptions, not untracked changes. Adding",
            "a comment would corrupt a strict format, alter a binary payload, or be erased",
            "by the owning generator. Their upstream and current Git object identities are",
            "recorded by the manifest and the repository history.",
            "",
            "| File | Why an in-file notice is unsafe |",
            "| --- | --- |",
        ]
    )
    for path in sorted(NOTICE_EXCEPTIONS):
        lines.append(f"| `{path}` | {NOTICE_EXCEPTIONS[path]} |")
    lines.extend(
        [
            "",
            "## Compliance note",
            "",
            "Apache-2.0 section 4(b) requires modified files to carry prominent change",
            "notices. Source files do so directly. For the listed strict-data, generated,",
            "and binary exceptions, AccordLock uses this adjacent exact inventory plus Git",
            "object provenance because an in-file comment is technically unsafe. This is a",
            "documented engineering compromise, not legal advice; release counsel should",
            "confirm that the out-of-band handling is sufficient for the intended distribution.",
            "",
            "## AccordLock-only files",
            "",
        ]
    )
    lines.extend(f"- `{path}`" for path in inventory.added)
    lines.extend(
        [
            "",
            "## Other omitted upstream files",
            "",
            "The two excluded subtrees are represented in the pinned manifest and are not",
            "repeated here. The following additional upstream files are not distributed:",
            "",
        ]
    )
    lines.extend(f"- `{path}`" for path in inventory.removed)
    lines.extend(
        [
            "",
            "## Reproduce the audit",
            "",
            "From `desktop/`:",
            "",
            "```console",
            "python scripts/check_upstream_modifications.py",
            "python -m unittest scripts.tests.test_upstream_modifications -v",
            "```",
            "",
            "The check is network-free. It fails if the pinned manifest, exact path sets,",
            "file counts, exception list, in-file notices, or this report drift.",
            "",
        ]
    )
    return "\n".join(lines)


def audit() -> tuple[Inventory, list[str]]:
    inventory = analyze()
    errors = _check_baseline(inventory)
    errors.extend(_check_notices(inventory))
    expected_report = render_report(inventory)
    try:
        actual_report = REPORT_PATH.read_text(encoding="utf-8")
    except OSError as error:
        errors.append(f"unable to read {REPORT_PATH.name}: {error}")
    else:
        if actual_report != expected_report:
            errors.append(
                f"{REPORT_PATH.name} is stale; regenerate it from the audited inventory"
            )
    return inventory, errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--print-report",
        action="store_true",
        help="print the deterministic MODIFICATIONS.md body",
    )
    arguments = parser.parse_args()

    try:
        inventory = analyze()
        if arguments.print_report:
            sys.stdout.write(render_report(inventory))
            return 0
        inventory, errors = audit()
    except (AuditError, OSError, subprocess.SubprocessError) as error:
        print(f"Upstream modification audit: FAIL\n- {error}", file=sys.stderr)
        return 1

    if errors:
        print("Upstream modification audit: FAIL", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        "Upstream modification audit: PASS "
        f"({len(inventory.modified)} modified, "
        f"{len(inventory.unchanged)} unchanged, "
        f"{len(inventory.added)} AccordLock-only, "
        f"{len(inventory.removed)} omitted outside explicit subtrees)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
