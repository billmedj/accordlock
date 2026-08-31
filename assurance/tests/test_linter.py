from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from accordlock_assurance.linter import ManifestLoadError, verify_manifest


class AssuranceLinterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.root = base / "repository"
        self.package = base / "assurance"
        self.root.mkdir()
        self.package.mkdir()

        self._write(
            self.root / "formal" / "Sample.lean",
            "namespace Sample\n\ntheorem exact_binding : True := by trivial\n\nend Sample\n",
        )
        self._write(
            self.root / "models" / "Sample.tla",
            "---- MODULE Sample ----\nInit == TRUE\nNext == FALSE\nSafe == TRUE\n====\n",
        )
        self._write(
            self.root / "models" / "Sample.cfg",
            "SPECIFICATION Spec\n\nINVARIANTS\n    Safe\n",
        )
        self._write(
            self.root / "crates" / "sample" / "src" / "lib.rs",
            "pub const AUDIT_VERSION: u16 = 6;\n\n#[test]\nfn exact_binding_test() {}\n\nfn helper_only() {}\n",
        )
        self._write(self.package / "README.md", "The contract is audit v6.\n")
        self.manifest = self.package / "claims.yaml"
        self.valid = {
            "schema_version": 1,
            "metadata": {
                "name": "Test claims",
                "purpose": "Exercise the linter.",
                "assurance_levels": ["Abstract proof and implementation traceability."],
                "source_versions": [
                    {
                        "name": "audit",
                        "path": "crates/sample/src/lib.rs",
                        "constant": "AUDIT_VERSION",
                        "expected": 6,
                        "documents": ["README.md", "claims.yaml"],
                    }
                ],
            },
            "claims": [
                {
                    "id": "authorization.exact-binding",
                    "title": "Exact binding",
                    "statement": "Authority is exact.",
                    "scope": "The sample model.",
                    "lean": [
                        {
                            "path": "formal/Sample.lean",
                            "theorems": ["exact_binding"],
                        }
                    ],
                    "tla": [
                        {
                            "model": "models/Sample.tla",
                            "config": "models/Sample.cfg",
                            "invariants": ["Safe"],
                        }
                    ],
                    "runtime": [
                        {
                            "path": "crates/sample/src/lib.rs",
                            "description": "Implements the sample boundary.",
                        }
                    ],
                    "tests": [
                        {
                            "path": "crates/sample/src/lib.rs",
                            "name": "exact_binding_test",
                        }
                    ],
                    "limitations": ["This is a fixture, not a production proof."],
                }
            ],
        }
        self._save(self.valid)

    @staticmethod
    def _write(path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _save(self, manifest: dict[str, object]) -> None:
        self.manifest.write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )

    def _codes(self) -> set[str]:
        return {finding.code for finding in verify_manifest(self.manifest, self.root).findings}

    def test_valid_manifest_passes(self) -> None:
        report = verify_manifest(self.manifest, self.root)
        self.assertTrue(report.ok, report.findings)
        self.assertEqual(report.claims_checked, 1)
        self.assertGreaterEqual(report.references_checked, 10)

    def test_duplicate_json_key_is_rejected(self) -> None:
        self.manifest.write_text(
            '{"schema_version":1,"schema_version":1,"metadata":{},"claims":[]}',
            encoding="utf-8",
        )
        with self.assertRaises(ManifestLoadError):
            verify_manifest(self.manifest, self.root)

    def test_missing_lean_theorem_fails(self) -> None:
        changed = deepcopy(self.valid)
        changed["claims"][0]["lean"][0]["theorems"] = ["renamed_theorem"]
        self._save(changed)
        self.assertIn("lean.theorem_missing", self._codes())

    def test_tla_invariant_must_be_selected_by_config(self) -> None:
        self._write(
            self.root / "models" / "Sample.tla",
            "---- MODULE Sample ----\nSafe == TRUE\nDefinedButNotChecked == TRUE\n====\n",
        )
        changed = deepcopy(self.valid)
        changed["claims"][0]["tla"][0]["invariants"] = ["DefinedButNotChecked"]
        self._save(changed)
        self.assertIn("tla.invariant_unconfigured", self._codes())

    def test_rust_function_without_test_attribute_is_not_evidence(self) -> None:
        changed = deepcopy(self.valid)
        changed["claims"][0]["tests"][0]["name"] = "helper_only"
        self._save(changed)
        self.assertIn("rust_test.missing", self._codes())

    def test_repository_path_escape_is_rejected(self) -> None:
        changed = deepcopy(self.valid)
        changed["claims"][0]["runtime"][0]["path"] = "../escape.rs"
        self._save(changed)
        self.assertIn("path.unsafe", self._codes())

    def test_unknown_schema_field_fails_closed(self) -> None:
        changed = deepcopy(self.valid)
        changed["claims"][0]["marketing_status"] = "complete"
        self._save(changed)
        self.assertIn("schema.unknown_key", self._codes())

    def test_stale_version_wording_is_detected(self) -> None:
        self._write(self.package / "README.md", "The contract is audit v5.\n")
        self.assertIn("source_version.stale_wording", self._codes())

    def test_source_version_change_requires_manifest_update(self) -> None:
        self._write(
            self.root / "crates" / "sample" / "src" / "lib.rs",
            "pub const AUDIT_VERSION: u16 = 7;\n\n#[test]\nfn exact_binding_test() {}\n",
        )
        self.assertIn("source_version.stale_expected", self._codes())


if __name__ == "__main__":
    unittest.main()
