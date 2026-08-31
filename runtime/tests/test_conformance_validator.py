from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = REPOSITORY_ROOT / "conformance" / "validate.py"
SPEC = importlib.util.spec_from_file_location("accordlock_conformance_validator", VALIDATOR_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load validator from {VALIDATOR_PATH}")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class ConformanceValidatorTests(unittest.TestCase):
    def _copy_repository(self) -> tuple[tempfile.TemporaryDirectory[str], Path]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        shutil.copytree(REPOSITORY_ROOT / "conformance", root / "conformance")
        return temporary, root

    def _mutate_json(self, root: Path, relative: str, mutate) -> None:
        path = root / "conformance" / relative
        value = json.loads(path.read_text(encoding="utf-8"))
        mutate(value)
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def _assert_invalid(self, root: Path) -> None:
        with self.assertRaises(VALIDATOR.ValidationError):
            VALIDATOR.validate_repository(root)

    def test_frozen_corpus_is_valid(self) -> None:
        self.assertEqual(
            VALIDATOR.validate_repository(REPOSITORY_ROOT),
            {"scenario_manifests": 7},
        )

    def test_unknown_scenario_field_fails_closed(self) -> None:
        temporary, root = self._copy_repository()
        self.addCleanup(temporary.cleanup)
        self._mutate_json(root, "scenarios/DP-000.json", lambda value: value.__setitem__("attested", True))
        self._assert_invalid(root)

    def test_unknown_action_security_field_fails_closed(self) -> None:
        temporary, root = self._copy_repository()
        self.addCleanup(temporary.cleanup)
        self._mutate_json(root, "scenarios/DP-000.json", lambda value: value["action_proposal"].__setitem__("grade", 4))
        self._assert_invalid(root)

    def test_duplicate_json_key_fails_closed(self) -> None:
        temporary, root = self._copy_repository()
        self.addCleanup(temporary.cleanup)
        path = root / "conformance" / "scenarios" / "DP-000.json"
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace('"id": "DP-000",', '"id": "DP-000",\n  "id": "DP-999",', 1), encoding="utf-8")
        self._assert_invalid(root)

    def test_declared_count_mismatch_is_rejected(self) -> None:
        temporary, root = self._copy_repository()
        self.addCleanup(temporary.cleanup)
        self._mutate_json(root, "corpus.json", lambda value: value["declared_counts"].__setitem__("scenario_manifests_total", 8))
        self._assert_invalid(root)

    def test_broken_repair_link_is_rejected(self) -> None:
        temporary, root = self._copy_repository()
        self.addCleanup(temporary.cleanup)
        self._mutate_json(root, "scenarios/DP-101R.json", lambda value: value.__setitem__("repairs", "DP-102"))
        self._assert_invalid(root)

    def test_outcome_drift_is_rejected(self) -> None:
        temporary, root = self._copy_repository()
        self.addCleanup(temporary.cleanup)
        self._mutate_json(root, "scenarios/DP-101.json", lambda value: value["expected"]["accordlock"].__setitem__("decision", "ALLOW"))
        self._assert_invalid(root)

if __name__ == "__main__":
    unittest.main()
