from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = REPOSITORY_ROOT / "scripts" / "check_rustsec_audit.py"
SPEC = importlib.util.spec_from_file_location("accordlock_rustsec_audit", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load checker from {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class RustSecAuditTests(unittest.TestCase):
    @staticmethod
    def _safe_report() -> dict[str, object]:
        return {
            "database": {
                "advisory-count": 1_200,
                "last-commit": None,
                "last-updated": None,
            },
            "lockfile": {"dependency-count": 10},
            "settings": {
                "target_arch": [],
                "target_os": [],
                "severity": None,
                "ignore": [],
                "informational_warnings": ["unmaintained", "unsound", "notice"],
            },
            "vulnerabilities": {"found": False, "count": 0, "list": []},
            "warnings": {},
        }

    def test_safe_complete_report_passes(self) -> None:
        result = CHECKER.validate_audit_report(
            self._safe_report(), expected_lock_packages=10
        )
        self.assertEqual(result["vulnerabilities"], 0)

    def test_advisory_ignore_fails_closed(self) -> None:
        report = self._safe_report()
        report["settings"]["ignore"] = ["RUSTSEC-2099-0001"]
        with self.assertRaises(CHECKER.RustSecAuditError):
            CHECKER.validate_audit_report(report, expected_lock_packages=10)

    def test_severity_or_target_filter_fails_closed(self) -> None:
        for key, value in (("severity", "high"), ("target_arch", ["x86_64"])):
            report = self._safe_report()
            report["settings"][key] = value
            with self.subTest(key=key), self.assertRaises(CHECKER.RustSecAuditError):
                CHECKER.validate_audit_report(report, expected_lock_packages=10)

    def test_incomplete_warning_classes_fail_closed(self) -> None:
        report = self._safe_report()
        report["settings"]["informational_warnings"] = ["unsound"]
        with self.assertRaises(CHECKER.RustSecAuditError):
            CHECKER.validate_audit_report(report, expected_lock_packages=10)

    def test_vulnerability_or_warning_fails_closed(self) -> None:
        vulnerable = self._safe_report()
        vulnerable["vulnerabilities"] = {
            "found": True,
            "count": 1,
            "list": [{"advisory": {"id": "RUSTSEC-2099-0001"}}],
        }
        warning = copy.deepcopy(self._safe_report())
        warning["warnings"] = {"unmaintained": [{"package": {"name": "old"}}]}
        for report in (vulnerable, warning):
            with self.assertRaises(CHECKER.RustSecAuditError):
                CHECKER.validate_audit_report(report, expected_lock_packages=10)

    def test_database_snapshot_requires_fresh_clean_origin_main(self) -> None:
        now = 2_000_000
        safe = {
            "remote": CHECKER.RUSTSEC_REMOTE,
            "head": "a" * 40,
            "origin_main": "a" * 40,
            "head_is_ancestor_of_origin_main": True,
            "commit_time": now - 60,
            "status": "",
        }
        CHECKER.validate_database_snapshot(
            safe, now=now, max_age_days=14, expected_commit="a" * 40
        )
        for key, value in (
            ("remote", "https://example.invalid/advisory-db.git"),
            ("head_is_ancestor_of_origin_main", False),
            ("status", " M crates/foo.md"),
            ("commit_time", now - 15 * 24 * 60 * 60),
        ):
            snapshot = dict(safe)
            snapshot[key] = value
            with self.subTest(key=key), self.assertRaises(CHECKER.RustSecAuditError):
                CHECKER.validate_database_snapshot(
                    snapshot,
                    now=now,
                    max_age_days=14,
                    expected_commit="a" * 40,
                )

    def test_database_snapshot_must_match_repository_pin(self) -> None:
        snapshot = {
            "remote": CHECKER.RUSTSEC_REMOTE,
            "head": "a" * 40,
            "origin_main": "a" * 40,
            "head_is_ancestor_of_origin_main": True,
            "commit_time": 1_999_900,
            "status": "",
        }
        with self.assertRaises(CHECKER.RustSecAuditError):
            CHECKER.validate_database_snapshot(
                snapshot,
                now=2_000_000,
                max_age_days=14,
                expected_commit="b" * 40,
            )


if __name__ == "__main__":
    unittest.main()
