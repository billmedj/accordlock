from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from scripts.check_publication import (
    check_generated_files,
    validate_brand_mark,
    validate_public_copy_text,
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

    def test_accepts_clear_public_copy(self) -> None:
        text = "The runtime checks one action before dispatch.\n"
        self.assertEqual(validate_public_copy_text("README.md", text), [])

    def test_rejects_promotional_public_copy(self) -> None:
        findings = validate_public_copy_text(
            "README.md",
            "A revolutionary and world-class runtime.\n",
        )
        self.assertEqual(
            [finding.check for finding in findings],
            ["promotional-copy"],
        )

    def test_rejects_formulaic_public_copy(self) -> None:
        findings = validate_public_copy_text(
            "ROADMAP.md",
            "At its core, this is more than just a tool.\n",
        )
        self.assertEqual(
            [finding.check for finding in findings],
            ["formulaic-copy"],
        )

    def test_rejects_non_ascii_public_copy(self) -> None:
        findings = validate_public_copy_text(
            "README.md",
            "The runtime checks the action - then records it.\u00a0\n",
        )
        self.assertEqual(
            [finding.check for finding in findings],
            ["public-copy-non-ascii"],
        )

    def test_language_guide_can_name_prohibited_copy(self) -> None:
        self.assertEqual(
            validate_public_copy_text(
                "LANGUAGE.md",
                "Do not use revolutionary or more than just.\n",
            ),
            [],
        )

    def test_public_mark_must_match_desktop_mark(self) -> None:
        self.assertEqual(validate_brand_mark(b"same", b"same"), [])
        findings = validate_brand_mark(b"public", b"desktop")
        self.assertEqual(
            [finding.check for finding in findings],
            ["brand-asset-mismatch"],
        )


if __name__ == "__main__":
    unittest.main()
