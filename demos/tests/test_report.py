import unittest

from accordlock_demos.report import render_markdown


class MarkdownReportTests(unittest.TestCase):
    def test_renders_decisions_evidence_and_limitations(self) -> None:
        report = {
            "status": "PASS",
            "cases": [
                {
                    "case_id": "case-1",
                    "claim": "Exact scope is enforced",
                    "status": "PASS",
                    "observed": {"reason_code": "PROTECTED_PATH"},
                    "interpretation": "The request was denied.",
                }
            ],
            "execution_profile": {"model_provider": "NONE"},
            "limitations": ["Not a production-readiness claim."],
        }
        rendered = render_markdown(report)
        self.assertIn("PROTECTED_PATH", rendered)
        self.assertIn('"model_provider": "NONE"', rendered)
        self.assertIn("Not a production-readiness claim.", rendered)


if __name__ == "__main__":
    unittest.main()
