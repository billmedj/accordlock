from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
import tomllib
from pathlib import Path
from typing import Any


RUSTSEC_REMOTE = "https://github.com/RustSec/advisory-db.git"
HEX_COMMIT = re.compile(r"[0-9a-f]{40}")
REQUIRED_INFORMATIONAL_WARNINGS = {"notice", "unmaintained", "unsound"}


class RustSecAuditError(RuntimeError):
    pass


def _run(command: list[str], *, cwd: Path | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RustSecAuditError(
            f"command failed with {completed.returncode}: {command[0]}: {detail}"
        )
    return completed.stdout.strip()


def _git(git: str, database: Path, *arguments: str) -> str:
    return _run(
        [
            git,
            "-c",
            f"safe.directory={database}",
            "-C",
            str(database),
            *arguments,
        ]
    )


def _git_is_ancestor(git: str, database: Path, ancestor: str, descendant: str) -> bool:
    completed = subprocess.run(
        [
            git,
            "-c",
            f"safe.directory={database}",
            "-C",
            str(database),
            "merge-base",
            "--is-ancestor",
            ancestor,
            descendant,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode not in (0, 1):
        raise RustSecAuditError(
            f"git ancestry check failed with {completed.returncode}: {completed.stderr.strip()}"
        )
    return completed.returncode == 0


def inspect_database(git: str, database: Path) -> dict[str, Any]:
    database = database.resolve()
    if not (database / ".git").exists():
        raise RustSecAuditError("RustSec database is not a Git checkout")
    head = _git(git, database, "rev-parse", "--verify", "HEAD^{commit}")
    origin_main_ref = "refs/remotes/origin/main^{commit}"
    return {
        "remote": _git(git, database, "remote", "get-url", "origin"),
        "head": head,
        "origin_main": _git(
            git,
            database,
            "rev-parse",
            "--verify",
            origin_main_ref,
        ),
        "head_is_ancestor_of_origin_main": _git_is_ancestor(
            git, database, head, origin_main_ref
        ),
        "commit_time": int(_git(git, database, "show", "-s", "--format=%ct", "HEAD")),
        "status": _git(git, database, "status", "--porcelain=v1", "--untracked-files=all"),
    }


def validate_database_snapshot(
    snapshot: dict[str, Any], *, now: int, max_age_days: int, expected_commit: str
) -> dict[str, Any]:
    if max_age_days <= 0:
        raise RustSecAuditError("maximum database age must be positive")
    remote = snapshot.get("remote")
    head = snapshot.get("head")
    origin_main = snapshot.get("origin_main")
    head_is_ancestor = snapshot.get("head_is_ancestor_of_origin_main")
    commit_time = snapshot.get("commit_time")
    status = snapshot.get("status")
    if remote != RUSTSEC_REMOTE:
        raise RustSecAuditError(f"unexpected RustSec remote: {remote}")
    if not isinstance(head, str) or HEX_COMMIT.fullmatch(head) is None:
        raise RustSecAuditError("RustSec HEAD is not a full Git commit")
    if HEX_COMMIT.fullmatch(expected_commit) is None:
        raise RustSecAuditError("pinned RustSec commit is malformed")
    if head != expected_commit:
        raise RustSecAuditError("RustSec HEAD differs from the repository-pinned commit")
    if not isinstance(origin_main, str) or HEX_COMMIT.fullmatch(origin_main) is None:
        raise RustSecAuditError("RustSec origin/main is not a full Git commit")
    if head_is_ancestor is not True:
        raise RustSecAuditError("pinned RustSec commit is not in fetched origin/main history")
    if status != "":
        raise RustSecAuditError("RustSec checkout has local or untracked changes")
    if not isinstance(commit_time, int):
        raise RustSecAuditError("RustSec commit time is missing")
    if commit_time > now + 300:
        raise RustSecAuditError("RustSec commit time is in the future")
    maximum_age_seconds = max_age_days * 24 * 60 * 60
    age_seconds = now - commit_time
    if age_seconds > maximum_age_seconds:
        raise RustSecAuditError(
            f"RustSec database is stale: age_seconds={age_seconds} maximum={maximum_age_seconds}"
        )
    return {
        "commit": head,
        "remote": remote,
        "age_seconds": age_seconds,
        "maximum_age_days": max_age_days,
        "worktree_clean": True,
        "repository_pin_matched": True,
        "fetched_origin_history_contains_pin": True,
    }


def _expected_lock_packages(lock_path: Path) -> int:
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock.get("package")
    if not isinstance(packages, list) or not packages:
        raise RustSecAuditError("Cargo.lock package set is empty or malformed")
    return len(packages)


def validate_audit_report(
    report: dict[str, Any], *, expected_lock_packages: int
) -> dict[str, Any]:
    database = report.get("database")
    lockfile = report.get("lockfile")
    settings = report.get("settings")
    vulnerabilities = report.get("vulnerabilities")
    warnings = report.get("warnings")
    if not all(
        isinstance(value, dict)
        for value in (database, lockfile, settings, vulnerabilities, warnings)
    ):
        raise RustSecAuditError("cargo-audit JSON has an unexpected shape")

    advisory_count = database.get("advisory-count")
    if not isinstance(advisory_count, int) or advisory_count < 1_000:
        raise RustSecAuditError("RustSec advisory set is unexpectedly small")
    dependency_count = lockfile.get("dependency-count")
    if dependency_count != expected_lock_packages:
        raise RustSecAuditError(
            "cargo-audit did not inspect the complete lockfile: "
            f"observed={dependency_count} expected={expected_lock_packages}"
        )

    if settings.get("target_arch") != [] or settings.get("target_os") != []:
        raise RustSecAuditError("cargo-audit target filtering is forbidden")
    if settings.get("severity") is not None:
        raise RustSecAuditError("cargo-audit severity filtering is forbidden")
    if settings.get("ignore") != []:
        raise RustSecAuditError("cargo-audit advisory ignores are forbidden")
    informational = settings.get("informational_warnings")
    if not isinstance(informational, list) or not REQUIRED_INFORMATIONAL_WARNINGS.issubset(
        set(informational)
    ):
        raise RustSecAuditError("cargo-audit informational warnings are incomplete")

    if vulnerabilities.get("found") is not False:
        raise RustSecAuditError("RustSec vulnerabilities were reported")
    if vulnerabilities.get("count") != 0 or vulnerabilities.get("list") != []:
        raise RustSecAuditError("RustSec vulnerability result is inconsistent")
    if warnings != {}:
        raise RustSecAuditError("RustSec warnings were reported")

    return {
        "advisories_loaded": advisory_count,
        "dependencies_scanned": dependency_count,
        "advisory_ignores": 0,
        "target_filters": 0,
        "vulnerabilities": 0,
        "warnings": 0,
        "yanked_checked": False,
    }


def run_audit(
    cargo_audit: Path, database: Path, lock_path: Path
) -> tuple[int, dict[str, Any], str]:
    completed = subprocess.run(
        [
            str(cargo_audit),
            "audit",
            "--db",
            str(database),
            "--no-fetch",
            "--no-yanked",
            "--file",
            str(lock_path),
            "--deny",
            "warnings",
            "--json",
            "--color",
            "never",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RustSecAuditError(f"cargo-audit returned invalid JSON: {detail}") from error
    if not isinstance(report, dict):
        raise RustSecAuditError("cargo-audit JSON root is not an object")
    return completed.returncode, report, completed.stderr.strip()


def validate(
    *,
    cargo_audit: Path,
    git: str,
    database: Path,
    lock_path: Path,
    expected_commit_path: Path,
    max_age_days: int,
) -> dict[str, Any]:
    expected_commit = expected_commit_path.read_text(encoding="utf-8").strip()
    database_result = validate_database_snapshot(
        inspect_database(git, database),
        now=int(time.time()),
        max_age_days=max_age_days,
        expected_commit=expected_commit,
    )
    expected = _expected_lock_packages(lock_path)
    return_code, report, stderr = run_audit(cargo_audit, database, lock_path)
    audit_result = validate_audit_report(report, expected_lock_packages=expected)
    if return_code != 0:
        raise RustSecAuditError(
            f"cargo-audit exited with {return_code} after JSON validation: {stderr}"
        )
    return {"database": database_result, "audit": audit_result}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo-audit", type=Path, required=True)
    parser.add_argument("--git", default="git")
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--expected-commit-file", type=Path, required=True)
    parser.add_argument("--max-age-days", type=int, default=14)
    args = parser.parse_args()
    try:
        result = validate(
            cargo_audit=args.cargo_audit.resolve(),
            git=args.git,
            database=args.db.resolve(),
            lock_path=args.lock.resolve(),
            expected_commit_path=args.expected_commit_file.resolve(),
            max_age_days=args.max_age_days,
        )
    except (OSError, ValueError, RustSecAuditError, subprocess.SubprocessError) as error:
        print(f"FAIL rustsec_audit {error}")
        return 1
    print("PASS rustsec_audit " + json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
