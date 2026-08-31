import os
import tempfile
import unittest
from pathlib import Path

from accordlock_demos.suite import run_adversarial_suite


@unittest.skipUnless(
    os.environ.get("ACCORDLOCK_CLI_BIN") and os.environ.get("ACCORDLOCK_RUNTIME_BIN"),
    "set both real AccordLock binary paths to run the integration test",
)
class RealBinaryIntegrationTests(unittest.TestCase):
    def test_provider_free_suite_passes_against_real_entrypoints(self) -> None:
        with tempfile.TemporaryDirectory(prefix="accordlock-demo-test-") as temporary:
            report = run_adversarial_suite(
                Path(os.environ["ACCORDLOCK_CLI_BIN"]),
                Path(os.environ["ACCORDLOCK_RUNTIME_BIN"]),
                Path(temporary),
            )
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(all(case["status"] == "PASS" for case in report["cases"]))
        self.assertFalse(report["execution_profile"]["oracle_baseline_used_for_system_decisions"])


if __name__ == "__main__":
    unittest.main()
