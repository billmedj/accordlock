from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = REPOSITORY_ROOT / "scripts" / "check_supply_chain.py"
SPEC = importlib.util.spec_from_file_location("accordlock_supply_chain", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load checker from {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class SupplyChainTests(unittest.TestCase):
    def _repository(self, source: str = CHECKER.CRATES_IO_SOURCE, checksum: str = "a" * 64):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        local = root / "local"
        (local / "src").mkdir(parents=True)
        (local / "Cargo.toml").write_text(
            '[package]\nname = "local"\nversion = "0.1.0"\n', encoding="utf-8"
        )
        (local / "src" / "lib.rs").write_text("", encoding="utf-8")
        (root / "Cargo.lock").write_text(
            "\n".join(
                (
                    "version = 4",
                    "",
                    "[[package]]",
                    'name = "external"',
                    'version = "1.0.0"',
                    f'source = "{source}"',
                    f'checksum = "{checksum}"',
                    "",
                    "[[package]]",
                    'name = "local"',
                    'version = "0.1.0"',
                    "",
                )
            ),
            encoding="utf-8",
        )
        return root

    @staticmethod
    def _metadata(
        root: Path,
        source: str = CHECKER.CRATES_IO_SOURCE,
        license_expression: str = "MIT",
    ):
        local_id = "path+file:///workspace#local@0.1.0"
        return {
            "workspace_members": [local_id],
            "packages": [
                {
                    "id": local_id,
                    "name": "local",
                    "version": "0.1.0",
                    "source": None,
                    "manifest_path": str(root / "local" / "Cargo.toml"),
                    "license": None,
                    "targets": [{"src_path": str(root / "local" / "src" / "lib.rs")}],
                },
                {
                    "id": "registry+external",
                    "name": "external",
                    "version": "1.0.0",
                    "source": source,
                    "license": license_expression,
                }
            ],
        }

    def test_valid_locked_registry_dependency_passes(self) -> None:
        root = self._repository()
        with mock.patch.object(CHECKER, "_metadata", return_value=self._metadata(root)):
            result = CHECKER.validate(root, "cargo")
        self.assertEqual(result["checksums_present"], 1)

    def test_git_dependency_fails_closed(self) -> None:
        source = "git+https://example.invalid/dependency"
        root = self._repository(source=source)
        with mock.patch.object(
            CHECKER, "_metadata", return_value=self._metadata(root, source=source)
        ):
            with self.assertRaises(CHECKER.SupplyChainError):
                CHECKER.validate(root, "cargo")

    def test_missing_lock_checksum_fails_closed(self) -> None:
        root = self._repository(checksum="short")
        with mock.patch.object(CHECKER, "_metadata", return_value=self._metadata(root)):
            with self.assertRaises(CHECKER.SupplyChainError):
                CHECKER.validate(root, "cargo")

    def test_missing_license_metadata_fails_closed(self) -> None:
        root = self._repository()
        with mock.patch.object(
            CHECKER,
            "_metadata",
            return_value=self._metadata(root, license_expression=""),
        ):
            with self.assertRaises(CHECKER.SupplyChainError):
                CHECKER.validate(root, "cargo")

    def test_license_expression_is_recorded_not_legally_classified(self) -> None:
        root = self._repository()
        expression = "AGPL-3.0-only AND (MIT OR Apache-2.0)"
        with mock.patch.object(
            CHECKER,
            "_metadata",
            return_value=self._metadata(root, license_expression=expression),
        ):
            result = CHECKER.validate(root, "cargo")
        self.assertFalse(result["license_policy_evaluated"])

    def test_source_less_package_outside_workspace_fails_closed(self) -> None:
        root = self._repository()
        metadata = self._metadata(root)
        metadata["packages"].append(
            {
                "id": "path+file:///outside#replacement@1.0.0",
                "name": "replacement",
                "version": "1.0.0",
                "source": None,
                "manifest_path": str(root.parent / "replacement" / "Cargo.toml"),
                "license": "MIT",
                "targets": [{"src_path": str(root.parent / "replacement" / "src" / "lib.rs")}],
            }
        )
        with mock.patch.object(CHECKER, "_metadata", return_value=metadata):
            with self.assertRaises(CHECKER.SupplyChainError):
                CHECKER.validate(root, "cargo")

    def test_workspace_target_outside_repository_fails_closed(self) -> None:
        root = self._repository()
        metadata = self._metadata(root)
        metadata["packages"][0]["targets"] = [
            {"src_path": str(root.parent / "outside.rs")}
        ]
        with mock.patch.object(CHECKER, "_metadata", return_value=metadata):
            with self.assertRaises(CHECKER.SupplyChainError):
                CHECKER.validate(root, "cargo")

    def test_unknown_source_less_lock_record_fails_closed(self) -> None:
        root = self._repository()
        with (root / "Cargo.lock").open("a", encoding="utf-8") as lock:
            lock.write(
                '\n[[package]]\nname = "replacement"\nversion = "1.0.0"\n'
            )
        with mock.patch.object(CHECKER, "_metadata", return_value=self._metadata(root)):
            with self.assertRaises(CHECKER.SupplyChainError):
                CHECKER.validate(root, "cargo")


if __name__ == "__main__":
    unittest.main()
