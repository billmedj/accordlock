from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_source_provenance.py"
SPEC = importlib.util.spec_from_file_location("accordlock_source_provenance", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT}")
PROVENANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROVENANCE)


def git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


class SourceProvenanceChangeSetTests(unittest.TestCase):
    def _repository(self, root: Path) -> tuple[str, str]:
        git(root, "init", "--quiet")
        git(root, "config", "user.name", "AccordLock Test")
        git(root, "config", "user.email", "test@example.invalid")
        component = root / "component"
        component.mkdir()
        (component / "modified.txt").write_text("before\n", encoding="utf-8")
        (component / "removed.txt").write_text("removed\n", encoding="utf-8")
        git(root, "add", "component")
        git(root, "commit", "--quiet", "-m", "base")
        base_tree = git(root, "rev-parse", "HEAD:component")

        (component / "modified.txt").write_text("after\n", encoding="utf-8")
        (component / "removed.txt").unlink()
        (component / "added.txt").write_text("added\n", encoding="utf-8")
        git(root, "add", "-A", "component")
        git(root, "commit", "--quiet", "-m", "result")
        result_tree = git(root, "rev-parse", "HEAD:component")
        return base_tree, result_tree

    @staticmethod
    def _manifest(base_tree: str, result_tree: str) -> dict[str, object]:
        return {
            "schemaVersion": "1.1",
            "components": [
                {
                    "path": "component",
                    "sourceRepository": "https://github.com/example/component.git",
                    "commit": "0" * 40,
                    "tree": "1" * 40,
                    "assembledTree": result_tree,
                    "trackedTreeExclusions": [],
                    "postImportAdjustments": [
                        {"path": "modified.txt", "reason": "test fixture"}
                    ],
                    "postImportChangeSets": [
                        {
                            "baseTree": base_tree,
                            "resultTree": result_tree,
                            "changes": [
                                {
                                    "path": "added.txt",
                                    "effect": "added",
                                    "reason": "test addition",
                                },
                                {
                                    "path": "modified.txt",
                                    "effect": "modified",
                                    "reason": "test modification",
                                },
                                {
                                    "path": "removed.txt",
                                    "effect": "removed",
                                    "reason": "test removal",
                                },
                            ],
                        }
                    ],
                }
            ],
        }

    def test_exact_git_delta_accepts_added_modified_and_removed_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            base_tree, result_tree = self._repository(root)
            manifest_path = root / "SOURCE_PROVENANCE.json"
            manifest_path.write_text(
                json.dumps(self._manifest(base_tree, result_tree)), encoding="utf-8"
            )
            with patch.object(PROVENANCE, "ROOT", root), patch.object(
                PROVENANCE, "MANIFEST", manifest_path
            ):
                self.assertEqual(PROVENANCE.verify(), (1, 0, 1, 1, 3))

    def test_omitted_change_fails_the_exact_delta_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            base_tree, result_tree = self._repository(root)
            manifest = self._manifest(base_tree, result_tree)
            changes = manifest["components"][0]["postImportChangeSets"][0]["changes"]
            changes.pop()
            manifest_path = root / "SOURCE_PROVENANCE.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with patch.object(PROVENANCE, "ROOT", root), patch.object(
                PROVENANCE, "MANIFEST", manifest_path
            ):
                with self.assertRaisesRegex(
                    PROVENANCE.ProvenanceError, "does not exactly describe its Git delta"
                ):
                    PROVENANCE.verify()


if __name__ == "__main__":
    unittest.main()
