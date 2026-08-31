from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = REPOSITORY_ROOT / "scripts" / "validate_repository.py"
SPEC = importlib.util.spec_from_file_location("accordlock_repository_validator", VALIDATOR_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load validator from {VALIDATOR_PATH}")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class RepositoryValidatorTlaTests(unittest.TestCase):
    def setUp(self) -> None:
        models = REPOSITORY_ROOT / "models"
        self.canonical_cfg = (models / "DurableDispatchAcquisition.cfg").read_text(
            encoding="utf-8"
        )
        self.bounded_max2_cfg = (
            models / "DurableDispatchAcquisitionBoundedMax2.cfg"
        ).read_text(encoding="utf-8")
        self.smoke_cfg = (
            models / "DurableDispatchAcquisitionSmoke.cfg"
        ).read_text(encoding="utf-8")
        self.model = (models / "DurableDispatchAcquisition.tla").read_text(
            encoding="utf-8"
        )

    def test_final_dda_configs_and_model_are_valid(self) -> None:
        for label, source in (
            ("canonical DDA config", self.canonical_cfg),
            ("bounded Max2 DDA config", self.bounded_max2_cfg),
            ("smoke DDA config", self.smoke_cfg),
        ):
            VALIDATOR.validate_dda_config_directives(source, label)
        VALIDATOR.validate_dda_model_contract(self.model)

    def test_constants_parser_stops_at_view(self) -> None:
        source = """SPECIFICATION Spec

CONSTANTS
    Bound = 3

VIEW SafetyView
    SmuggledConstant = 4

INVARIANTS
    TypeOK
"""
        self.assertEqual(
            VALIDATOR.tla_config_constants(source, "test config"),
            {"Bound": "3"},
        )

    def test_view_must_be_unique_and_symmetry_is_forbidden(self) -> None:
        mutations = (
            (
                "wrong view",
                self.canonical_cfg.replace("VIEW SafetyView", "VIEW OtherView", 1),
            ),
            (
                "duplicate view",
                self.canonical_cfg.replace(
                    "VIEW SafetyView", "VIEW SafetyView\nVIEW SafetyView", 1
                ),
            ),
            (
                "symmetry directive",
                self.canonical_cfg.replace(
                    "VIEW SafetyView",
                    "SYMMETRY SymmetryPermutations\n\nVIEW SafetyView",
                    1,
                ),
            ),
        )
        for label, source in mutations:
            with self.subTest(label=label), self.assertRaises(
                VALIDATOR.ValidationError
            ):
                VALIDATOR.validate_dda_config_directives(source, "test config")

    def test_model_requires_alpha_canonicalization_and_fail_closed_view(self) -> None:
        mutations = (
            (
                "alpha canonicalization",
                self.model.replace(
                    "CanonicalFreshRequestId(requestId) ==", "Removed ==", 1
                ),
            ),
            ("fail-closed view", self.model.replace("    IF TypeOK", "    IF TRUE", 1)),
        )
        for label, source in mutations:
            with self.subTest(label=label), self.assertRaises(
                VALIDATOR.ValidationError
            ):
                VALIDATOR.validate_dda_model_contract(source)


class RepositoryPublicationHygieneTests(unittest.TestCase):
    def make_public_tree(self, root: Path) -> list[Path]:
        for relative in VALIDATOR.PUBLICATION_REQUIRED_FILES:
            path = root / relative
            path.write_text(f"# {relative}\n", encoding="utf-8")
        guide = root / "docs" / "guide.md"
        guide.parent.mkdir()
        guide.write_text("# Guide\n", encoding="utf-8")
        (root / "README.md").write_text(
            "[Guide](docs/guide.md#usage)\n[Website](https://example.com)\n",
            encoding="utf-8",
        )
        return sorted(path for path in root.rglob("*") if path.is_file())

    def test_complete_public_tree_has_no_legacy_brand_or_broken_link(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            paths = self.make_public_tree(root)
            file_count, link_count = VALIDATOR.validate_publication_hygiene(root, paths)
            self.assertEqual(file_count, len(paths))
            self.assertEqual(link_count, 1)

    def test_archive_fallback_excludes_generated_dependency_trees(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            source = root / "src" / "lib.rs"
            source.parent.mkdir()
            source.write_text("pub fn checked_source() {}\n", encoding="utf-8")
            for relative in (
                ".lake/build/ir/private.setup.json",
                ".local/tools/tool.jar",
                "__pycache__/module.pyc",
                "node_modules/package/index.js",
                "models/states/19-0/states_0",
                "target/debug/build-record.json",
            ):
                generated = root / relative
                generated.parent.mkdir(parents=True, exist_ok=True)
                generated.write_text("generated\n", encoding="utf-8")

            visible = VALIDATOR.git_visible_files(root)

            self.assertEqual(visible, [source])

    def test_legacy_brand_is_rejected_in_path_and_content(self) -> None:
        legacy = "sig" + "net"
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            paths = self.make_public_tree(root)
            branded_path = root / f"{legacy}-notes.md"
            branded_path.write_text("neutral\n", encoding="utf-8")
            with self.assertRaises(VALIDATOR.ValidationError):
                VALIDATOR.validate_no_legacy_brand(root, paths + [branded_path])

            content_path = root / "neutral.md"
            content_path.write_text(legacy.upper(), encoding="utf-8")
            with self.assertRaises(VALIDATOR.ValidationError):
                VALIDATOR.validate_no_legacy_brand(root, paths + [content_path])

    def test_broken_relative_and_absolute_local_links_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            paths = self.make_public_tree(root)
            readme = root / "README.md"
            for source in (
                "[Missing](docs/missing.md)\n",
                "[Local](/tmp/private.txt)\n",
                "[Windows](C:\\private\\notes.txt)\n",
            ):
                with self.subTest(source=source):
                    readme.write_text(source, encoding="utf-8")
                    with self.assertRaises(VALIDATOR.ValidationError):
                        VALIDATOR.validate_markdown_links(root, paths)

    def test_missing_public_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            paths = self.make_public_tree(root)
            security = root / "SECURITY.md"
            security.unlink()
            with self.assertRaises(VALIDATOR.ValidationError):
                VALIDATOR.validate_publication_hygiene(
                    root, [path for path in paths if path != security]
                )

    def test_internal_terms_non_english_copy_and_private_paths_are_rejected(self) -> None:
        forbidden_sources = (
            "cr" + "cs policy\n",
            "binding" + " gate\n",
            "seman" + "tic meter\n",
            "mis" + "sion_id = 1\n",
            "bien" + "venue dans AccordLock\n",
            "C:" + "\\Users\\alice\\private.txt\n",
        )
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            paths = self.make_public_tree(root)
            candidate = root / "docs" / "candidate.txt"
            for source in forbidden_sources:
                with self.subTest(source=source):
                    candidate.write_text(source, encoding="utf-8")
                    with self.assertRaises(VALIDATOR.ValidationError):
                        VALIDATOR.validate_publication_hygiene(root, paths + [candidate])

    def test_runtime_artifacts_and_realistic_credentials_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            paths = self.make_public_tree(root)

            environment = root / ".env"
            environment.write_text("TOKEN=value\n", encoding="utf-8")
            with self.assertRaises(VALIDATOR.ValidationError):
                VALIDATOR.validate_publication_hygiene(root, paths + [environment])

            credential = root / "docs" / "credential.txt"
            credential.write_text("AKIA" + "ABCD" * 4 + "\n", encoding="utf-8")
            with self.assertRaises(VALIDATOR.ValidationError):
                VALIDATOR.validate_publication_hygiene(root, paths + [credential])

    def test_explicit_synthetic_credential_fixture_and_legal_attribution_are_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root).resolve()
            paths = self.make_public_tree(root)
            fixture = root / "tests" / "fixtures" / "credential.txt"
            fixture.parent.mkdir(parents=True)
            fixture.write_text(
                "AKIA" + "A" * 16 + " # publication-safe-test-vector\n",
                encoding="utf-8",
            )
            notice = root / "NOTICE"
            notice.write_text("Bilal" + " Medjani\n", encoding="utf-8")
            VALIDATOR.validate_publication_hygiene(root, paths + [fixture])


class RepositoryPostgresIdentifierTests(unittest.TestCase):
    def test_repository_identifiers_fit_postgres_limit(self) -> None:
        count, maximum = VALIDATOR.validate_postgres_identifier_lengths(
            REPOSITORY_ROOT / "migrations"
        )
        self.assertGreater(count, 0)
        self.assertLessEqual(maximum, VALIDATOR.POSTGRES_IDENTIFIER_MAX_BYTES)

    def test_overlong_identifier_is_rejected_by_utf8_byte_length(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            migrations = Path(raw_root)
            overlong = "accordlock_" + ("x" * 53)
            self.assertEqual(len(overlong.encode("utf-8")), 64)
            (migrations / "0001_overlong.sql").write_text(
                f"CREATE TABLE public.{overlong} (id bigint);\n",
                encoding="utf-8",
            )
            with self.assertRaises(VALIDATOR.ValidationError):
                VALIDATOR.validate_postgres_identifier_lengths(migrations)

    def test_broker_secret_prefix_and_length_are_derived_consistently(self) -> None:
        prefix, length = VALIDATOR.validate_broker_secret_name_contract(
            REPOSITORY_ROOT
        )
        self.assertEqual(prefix, "accordlock-")
        self.assertEqual(length, len(prefix.encode("utf-8")) + 32)


if __name__ == "__main__":
    unittest.main()
