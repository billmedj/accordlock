from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from scripts.check_publication import (
    check_generated_files,
    validate_workflow_text,
)


class PublicationGuardTests(unittest.TestCase):
    def test_accepts_sha_pinned_read_only_action(self) -> None:
        workflow = """
permissions:
  contents: read
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
"""
        self.assertEqual(validate_workflow_text("ci.yml", workflow), [])

    def test_rejects_moving_action_reference(self) -> None:
        workflow = "steps:\n  - uses: actions/checkout@main\n"
        findings = validate_workflow_text("ci.yml", workflow)
        self.assertEqual([finding.check for finding in findings], ["unpinned-action"])

    def test_rejects_release_write_path(self) -> None:
        workflow = """
permissions:
  contents: write
steps:
  - run: gh release create v0.1.0
"""
        checks = {finding.check for finding in validate_workflow_text("release.yml", workflow)}
        self.assertEqual(checks, {"contents-write-permission", "release-publication-step"})

    def test_rejects_generated_and_packaged_files(self) -> None:
        findings = check_generated_files(
            ["runtime/target/debug/tool", "release/AccordLock.msi", "src/main.rs"]
        )
        self.assertEqual(
            {finding.check for finding in findings},
            {"generated-file", "packaged-binary"},
        )


if __name__ == "__main__":
    unittest.main()
