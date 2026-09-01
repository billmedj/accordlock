from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


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
            any(pattern.search(candidate) for pattern in PUBLICATION.GLOBAL_SECRET_PATTERNS)
        )

    def test_secret_in_non_owned_upstream_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            git(root, "init", "--quiet")
            fixture = root / "vendor" / "upstream" / "fixture.txt"
            fixture.parent.mkdir(parents=True)
            fixture.write_text("token=" + "phc_" + ("B" * 40) + "\n", encoding="utf-8")
            git(root, "add", fixture.relative_to(root).as_posix())

            errors: list[str] = []
            PUBLICATION.check_repository_hygiene(errors, root)

            self.assertEqual(
                errors,
                [
                    "vendor/upstream/fixture.txt:1: possible committed secret is forbidden"
                ],
            )

    def test_runtime_helpers_are_offline_and_uv_build_fetch_is_pinned(self) -> None:
        errors: list[str] = []
        PUBLICATION.check_extension_helper_supply_chain(errors)

        self.assertEqual(errors, [])
        self.assertNotIn(
            PUBLICATION.PINNED_UV_BUILD_SURFACE,
            PUBLICATION.EXTENSION_HELPER_SURFACES,
        )
        build_helper = (PUBLICATION.ROOT / PUBLICATION.PINNED_UV_BUILD_SURFACE).read_text(
            encoding="utf-8"
        )
        self.assertIn("https://", build_helper)

    def test_macos_disk_image_uses_the_native_verified_pipeline(self) -> None:
        errors: list[str] = []
        PUBLICATION.check_macos_packaging_supply_chain(errors)

        self.assertEqual(errors, [])

    def test_vulnerable_macos_packaging_dependency_is_rejected(self) -> None:
        original_read = PUBLICATION.read

        def read_with_vulnerable_package(relative_path: str) -> str:
            content = original_read(relative_path)
            if relative_path == "ui/pnpm-lock.yaml":
                return content + "\n  image-size@0.7.5:\n"
            return content

        errors: list[str] = []
        with patch.object(PUBLICATION, "read", side_effect=read_with_vulnerable_package):
            PUBLICATION.check_macos_packaging_supply_chain(errors)

        self.assertIn(
            "ui/pnpm-lock.yaml: forbidden vulnerable packaging dependency: image-size@",
            errors,
        )

    def test_unsupported_electron_packager_override_is_rejected(self) -> None:
        original_read = PUBLICATION.read

        def read_with_packager_override(relative_path: str) -> str:
            content = original_read(relative_path)
            if relative_path == "ui/pnpm-workspace.yaml":
                return content.replace(
                    "overrides:\n",
                    "overrides:\n  '@electron/packager': 20.3.0\n",
                    1,
                )
            return content

        errors: list[str] = []
        with patch.object(PUBLICATION, "read", side_effect=read_with_packager_override):
            PUBLICATION.check_macos_packaging_supply_chain(errors)

        self.assertIn(
            "ui/pnpm-workspace.yaml: Electron Packager must stay within Forge's supported range",
            errors,
        )

    def test_macos_disk_image_requires_signature_verification_after_stapling(self) -> None:
        original_read = PUBLICATION.read

        def read_without_final_signature_check(relative_path: str) -> str:
            content = original_read(relative_path)
            if relative_path == "scripts/build-macos.ps1":
                return content.replace(
                    "The final DMG code signature is invalid after stapling.",
                    "The DMG code signature is invalid.",
                )
            return content

        errors: list[str] = []
        with patch.object(PUBLICATION, "read", side_effect=read_without_final_signature_check):
            PUBLICATION.check_macos_packaging_supply_chain(errors)

        self.assertTrue(
            any(
                "final DMG signature verification must run after stapling" in error
                for error in errors
            )
        )

    def test_archived_macos_app_requires_its_own_notarization_ticket(self) -> None:
        original_read = PUBLICATION.read

        def read_without_archived_ticket_check(relative_path: str) -> str:
            content = original_read(relative_path)
            if relative_path == "scripts/build-macos.ps1":
                return content.replace("'stapler', 'validate', '-v', $AppRoot", "'verify'")
            return content

        errors: list[str] = []
        with patch.object(PUBLICATION, "read", side_effect=read_without_archived_ticket_check):
            PUBLICATION.check_macos_packaging_supply_chain(errors)

        self.assertTrue(any("native DMG pipeline is missing" in error for error in errors))

    def test_macos_output_cleanup_requires_real_non_link_ancestors(self) -> None:
        original_read = PUBLICATION.read

        def read_with_lexical_cleanup(relative_path: str) -> str:
            content = original_read(relative_path)
            if relative_path == "scripts/build-macos.ps1":
                return content.replace(
                    "Remove-ControlledDirectoryTree -Boundary $outputPlatformRoot -Directory $outputRoot",
                    "Remove-Item -LiteralPath $outputRoot -Recurse -Force",
                )
            return content

        errors: list[str] = []
        with patch.object(PUBLICATION, "read", side_effect=read_with_lexical_cleanup):
            PUBLICATION.check_macos_packaging_supply_chain(errors)

        self.assertIn(
            "scripts/build-macos.ps1: output cleanup must validate real non-link ancestors",
            errors,
        )

    def test_retired_pctx_dependency_is_rejected(self) -> None:
        original_read = PUBLICATION.read

        def read_with_retired_package(relative_path: str) -> str:
            content = original_read(relative_path)
            if relative_path == "Cargo.lock":
                return (
                    content
                    + '\n[[package]]\nname = "pctx_code_mode"\nversion = "0.1.0"\n'
                )
            return content

        errors: list[str] = []
        with patch.object(PUBLICATION, "read", side_effect=read_with_retired_package):
            PUBLICATION.check_retired_code_mode_surface(errors)

        self.assertIn(
            "Cargo.lock: retired PCTX package is forbidden: pctx_code_mode",
            errors,
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
