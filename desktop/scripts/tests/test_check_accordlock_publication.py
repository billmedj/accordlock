from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check_accordlock_publication.py"
SPEC = importlib.util.spec_from_file_location("accordlock_publication", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Unable to load {SCRIPT}")
PUBLICATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PUBLICATION)


def git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


class AccordLockPublicationGuardTests(unittest.TestCase):
    def test_upstream_telemetry_ingestion_keys_are_rejected(self) -> None:
        candidate = "phc_" + ("A" * 40)
        self.assertTrue(
            any(pattern.search(candidate) for pattern in PUBLICATION.SECRET_PATTERNS)
        )

    def test_personal_home_paths_are_detected_without_naming_a_developer(self) -> None:
        self.assertTrue(
            any(
                pattern.search("/home/alice/private.json")
                for pattern in PUBLICATION.PERSONAL_PATH_PATTERNS
            )
        )
        self.assertFalse(
            any(
                pattern.search("/home/scanner/.config/goose")
                for pattern in PUBLICATION.PERSONAL_PATH_PATTERNS
            )
        )

    def test_untracked_publication_input_fails_until_it_is_staged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            git(root, "init", "--quiet")
            (root / ".gitignore").write_text("ignored.rs\n", encoding="utf-8")
            tracked = root / "ui" / "desktop" / "src" / "accordlockTracked.ts"
            tracked.parent.mkdir(parents=True)
            tracked.write_text("export const tracked = true;\n", encoding="utf-8")
            draft = root / "crates" / "goose" / "src" / "agents" / "accordlock_draft.rs"
            draft.parent.mkdir(parents=True)
            draft.write_text("pub const DRAFT: bool = true;\n", encoding="utf-8")
            (root / "ignored.rs").write_text("ignored\n", encoding="utf-8")
            git(root, "add", ".gitignore", tracked.relative_to(root).as_posix())

            errors: list[str] = []
            PUBLICATION.check_repository_hygiene(errors, root)

            self.assertIn(
                "crates/goose/src/agents/accordlock_draft.rs: untracked publication input; "
                "stage it or ignore it explicitly",
                errors,
            )
            self.assertFalse(any(error.startswith("ignored.rs:") for error in errors))

            git(root, "add", draft.relative_to(root).as_posix())
            errors = []
            PUBLICATION.check_repository_hygiene(errors, root)

            self.assertFalse(
                any("untracked publication input" in error for error in errors)
            )


if __name__ == "__main__":
    unittest.main()
