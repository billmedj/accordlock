from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check_upstream_modifications.py"
SPEC = importlib.util.spec_from_file_location("upstream_modifications", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load {SCRIPT}")
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)


class UpstreamModificationAuditTests(unittest.TestCase):
    def test_exact_pinned_upstream_classification_and_notices(self) -> None:
        inventory, errors = AUDIT.audit()

        self.assertEqual(errors, [])
        self.assertEqual(
            len(inventory.included_upstream) + len(inventory.excluded_upstream),
            AUDIT.EXPECTED_UPSTREAM_FILES,
        )
        self.assertEqual(len(inventory.modified), AUDIT.EXPECTED_MODIFIED_FILES)
        self.assertEqual(len(inventory.unchanged), AUDIT.EXPECTED_UNCHANGED_FILES)
        self.assertEqual(len(inventory.removed), AUDIT.EXPECTED_REMOVED_FILES)

    def test_report_is_a_deterministic_render_of_the_exact_path_sets(self) -> None:
        inventory = AUDIT.analyze()

        self.assertEqual(
            AUDIT.REPORT_PATH.read_text(encoding="utf-8"),
            AUDIT.render_report(inventory),
        )


if __name__ == "__main__":
    unittest.main()
