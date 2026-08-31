from __future__ import annotations

import importlib.util
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = REPOSITORY_ROOT / "scripts" / "check_profiled_rustsec_audit.py"
SPEC = importlib.util.spec_from_file_location("accordlock_profiled_rustsec", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load checker from {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class ProfiledRustSecAuditTests(unittest.TestCase):
    @staticmethod
    def _package(name: str, version: str, checksum: str) -> dict[str, object]:
        return {
            "name": name,
            "version": version,
            "source": CHECKER.CRATES_IO_SOURCE,
            "checksum": checksum,
        }

    @classmethod
    def _finding(
        cls, advisory: str, name: str, version: str, checksum: str
    ) -> dict[str, object]:
        return {
            "advisory": {"id": advisory},
            "package": cls._package(name, version, checksum),
        }

    @staticmethod
    def _report() -> dict[str, object]:
        return {
            "database": {"advisory-count": 1_200},
            "lockfile": {"dependency-count": 2},
            "settings": {
                "target_arch": [],
                "target_os": [],
                "severity": None,
                "ignore": [],
                "informational_warnings": ["notice", "unmaintained", "unsound"],
            },
            "vulnerabilities": {"found": False, "count": 0, "list": []},
            "warnings": {},
        }

    def setUp(self) -> None:
        self.safe_checksum = "a" * 64
        self.off_profile_checksum = "b" * 64
        self.safe_identity = ("safe", "1.0.0", CHECKER.CRATES_IO_SOURCE)
        self.off_profile_identity = ("unused", "2.0.0", CHECKER.CRATES_IO_SOURCE)
        self.lock_index = {
            self.safe_identity: self._package("safe", "1.0.0", self.safe_checksum),
            self.off_profile_identity: self._package(
                "unused", "2.0.0", self.off_profile_checksum
            ),
        }
        self.profile_targets = {self.safe_identity: {"x86_64-pc-windows-msvc"}}

    def test_off_profile_findings_remain_visible_but_do_not_fail(self) -> None:
        report = self._report()
        report["vulnerabilities"] = {
            "found": True,
            "count": 1,
            "list": [
                self._finding(
                    "RUSTSEC-2099-0001",
                    "unused",
                    "2.0.0",
                    self.off_profile_checksum,
                )
            ],
        }
        warning = self._finding(
            "RUSTSEC-2099-0002", "unused", "2.0.0", self.off_profile_checksum
        )
        warning["kind"] = "unmaintained"
        report["warnings"] = {"unmaintained": [warning]}

        result = CHECKER.validate_profile_findings(
            report,
            expected_lock_packages=2,
            lock_index=self.lock_index,
            profile_targets=self.profile_targets,
        )

        self.assertEqual(result["profileFindings"], 0)
        self.assertEqual(result["wholeLockFindings"], 2)
        self.assertEqual(len(result["excludedOffProfileFindings"]), 2)

    def test_any_reachable_vulnerability_or_warning_fails(self) -> None:
        reports = []
        vulnerable = self._report()
        vulnerable["vulnerabilities"] = {
            "found": True,
            "count": 1,
            "list": [
                self._finding(
                    "RUSTSEC-2099-0001", "safe", "1.0.0", self.safe_checksum
                )
            ],
        }
        reports.append(vulnerable)
        warning = self._report()
        warning_item = self._finding(
            "RUSTSEC-2099-0002", "safe", "1.0.0", self.safe_checksum
        )
        warning_item["kind"] = "unsound"
        warning["warnings"] = {"unsound": [warning_item]}
        reports.append(warning)

        for report in reports:
            with self.subTest(report=report), self.assertRaises(
                CHECKER.ProfiledRustSecError
            ):
                CHECKER.validate_profile_findings(
                    report,
                    expected_lock_packages=2,
                    lock_index=self.lock_index,
                    profile_targets=self.profile_targets,
                )

    def test_filters_ignores_and_incomplete_lock_scan_fail_closed(self) -> None:
        mutations = (
            ("ignore", ["RUSTSEC-2099-0001"]),
            ("target_os", ["windows"]),
            ("severity", "high"),
            ("informational_warnings", ["unsound"]),
        )
        for key, value in mutations:
            report = self._report()
            report["settings"][key] = value
            with self.subTest(key=key), self.assertRaises(
                CHECKER.ProfiledRustSecError
            ):
                CHECKER.validate_profile_findings(
                    report,
                    expected_lock_packages=2,
                    lock_index=self.lock_index,
                    profile_targets=self.profile_targets,
                )
        incomplete = self._report()
        incomplete["lockfile"]["dependency-count"] = 1
        with self.assertRaises(CHECKER.ProfiledRustSecError):
            CHECKER.validate_profile_findings(
                incomplete,
                expected_lock_packages=2,
                lock_index=self.lock_index,
                profile_targets=self.profile_targets,
            )

    def test_finding_must_match_exact_lock_source_and_checksum(self) -> None:
        for mutation in ("source", "checksum"):
            report = self._report()
            item = self._finding(
                "RUSTSEC-2099-0001", "unused", "2.0.0", self.off_profile_checksum
            )
            if mutation == "source":
                item["package"]["source"] = "registry+https://example.invalid/index"
            else:
                item["package"]["checksum"] = "c" * 64
            report["vulnerabilities"] = {
                "found": True,
                "count": 1,
                "list": [item],
            }
            with self.subTest(mutation=mutation), self.assertRaises(
                CHECKER.ProfiledRustSecError
            ):
                CHECKER.validate_profile_findings(
                    report,
                    expected_lock_packages=2,
                    lock_index=self.lock_index,
                    profile_targets=self.profile_targets,
                )

    def test_tree_parser_requires_exact_root_features_and_known_output(self) -> None:
        output = "\n".join(
            (
                CHECKER.TREE_MARKER
                + "goose-cli v1.47.0 (workspace)\t"
                + "accordlock-distribution,disable-update,rustls-tls,system-keyring",
                CHECKER.TREE_MARKER + "serde v1.0.0\tderive,std",
                CHECKER.TREE_MARKER + "serde v1.0.0\tderive,std (*)",
            )
        )
        expected = (
            "accordlock-distribution",
            "disable-update",
            "rustls-tls",
            "system-keyring",
        )
        parsed = CHECKER.parse_tree(
            output, package="goose-cli", expected_root_features=expected
        )
        self.assertEqual(set(parsed), {("goose-cli", "1.47.0"), ("serde", "1.0.0")})

        with self.assertRaises(CHECKER.ProfiledRustSecError):
            CHECKER.parse_tree(
                output.replace(",system-keyring", "", 1),
                package="goose-cli",
                expected_root_features=expected,
            )
        with self.assertRaises(CHECKER.ProfiledRustSecError):
            CHECKER.parse_tree(
                output + "\nunexpected",
                package="goose-cli",
                expected_root_features=expected,
            )

    @staticmethod
    def _packaging_fixture(workspace: Path) -> tuple[Path, dict[str, object]]:
        scripts = workspace / "scripts"
        scripts.mkdir()
        features = "accordlock-distribution,rustls-tls,system-keyring"
        windows = (
            '$windowsTargetTriple = "x86_64-pc-windows-msvc"\n'
            "$requiredWindowsArchitecture = [System.Runtime.InteropServices.Architecture]::X64\n"
            "[System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(\n"
            "[System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne $requiredWindowsArchitecture\n"
            "[System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne $requiredWindowsArchitecture\n"
            "Windows packaging requires an x86-64 Windows host and x86-64 PowerShell process\n"
            "function Invoke-AccordLockCargoBuild {\n"
            "param([string[]]$Arguments, [string]$TargetDirectory)\n"
            "$localTargetDirectory = [IO.Path]::GetFullPath($TargetDirectory)\n"
            "& cargo clean --target-dir $localTargetDirectory -p $package\n"
            "$effectiveArguments = @($Arguments) + @('--target-dir', $localTargetDirectory)\n"
            "& cargo @effectiveArguments\n"
            "}\n"
            "function Next-WindowsFunction { }\n"
            "function Assert-AccordLockReleaseSourceIdentity { }\n"
            "Assert-AccordLockReleaseSourceIdentity\n"
            "Assert-AccordLockReleaseSourceIdentity\n"
            "Assert-AccordLockReleaseSourceIdentity\n"
            "Assert-AccordLockReleaseSourceIdentity\n"
            "$gooseCargoTargetDirectory = if ($Release) {\n"
            "New-AccordLockCargoTargetDirectory -SourceRoot $gooseSourceRoot\n}\n"
            '$gooseBinary = Join-Path $gooseCargoTargetDirectory "$windowsTargetTriple\\$profileName\\goose.exe"\n'
            "if ($Release -and $gooseCargoTargetDirectory) {\n"
            "Remove-AccordLockCargoTargetDirectory -Directory $gooseCargoTargetDirectory\n}\n"
            "$gooseCargoArguments = @(\n"
            '"build", "--locked", "--release", "--target", $windowsTargetTriple, '
            '"-p", "goose-cli", "--bin", "goose", "--no-default-features", '
            f'"--features", "{features}"\n)\n'
            "$gooseBuildExitCode = 1\n"
            "        Invoke-AccordLockCargoBuild `\n"
            "    -Arguments $gooseCargoArguments `\n"
            "    -SourceRoot $gooseSourceRoot `\n"
            "    -TargetDirectory $gooseCargoTargetDirectory `\n"
            "    -NativePackagesToClean @('aws-lc-sys') `\n"
            "    -ExitCode ([ref]$gooseBuildExitCode)\n"
        )
        macos = (
            "$targetTriple = if ($Architecture -ceq 'arm64') { "
            "'aarch64-apple-darwin' } else { 'x86_64-apple-darwin' }\n"
            "$rustcVerboseVersion = @(& rustc -vV)\n"
            "if ($rustcHostLines.Count -ne 1) { throw 'bad host output' }\n"
            "if ($rustcHost -cne $targetTriple) { throw 'macOS packaging requires a "
            "native host/target pair' }\n"
            "function Invoke-ReleaseCargoBuild {\n"
            "param([string[]]$Arguments, [string]$TargetDirectory)\n"
            "$resolvedTargetDirectory = [IO.Path]::GetFullPath($TargetDirectory)\n"
            "& cargo @Arguments --target-dir $resolvedTargetDirectory\n"
            "}\n"
            "function Next-MacFunction { }\n"
            "function Assert-ReleaseSourceIdentity { }\n"
            "Assert-ReleaseSourceIdentity\n"
            "Assert-ReleaseSourceIdentity\n"
            "Assert-ReleaseSourceIdentity\n"
            "Assert-ReleaseSourceIdentity\n"
            "$gooseCargoTargetDirectory = if ($Release) {\n"
            "New-AccordLockCargoTargetDirectory -SourceRoot $GooseRoot\n}\n"
            '$gooseBinary = Join-Path $gooseCargoTargetDirectory "$targetTriple/release/goose"\n'
            "if ($Release -and $gooseCargoTargetDirectory) {\n"
            "Remove-AccordLockCargoTargetDirectory -Directory $gooseCargoTargetDirectory\n}\n"
            "Invoke-ReleaseCargoBuild `\n-SourceRoot $root `\n-TargetDirectory $gooseCargoTargetDirectory `\n-Arguments @(\n"
            "'build', '--locked', '--release', '--target', $targetTriple, "
            "'-p', 'goose-cli', '--bin', 'goose', '--no-default-features', "
            f"'--features', '{features}'\n)\n"
            "Invoke-ReleaseCargoBuild `\n-SourceRoot $runtime `\n-TargetDirectory $runtimeCargoTargetDirectory `\n-Arguments @(\n"
            "'build', '--locked', '--release', '--target', $targetTriple, "
            "'-p', 'accordlock-agent-runtime', '--bin', "
            "'accordlock-agent-runtime'\n)\n"
        )
        windows_path = scripts / "build-windows.ps1"
        macos_path = scripts / "build-macos.ps1"
        windows_path.write_text(windows, encoding="utf-8")
        macos_path.write_text(macos, encoding="utf-8")
        profile_path = workspace / "profile.json"
        profile_path.write_text("{}", encoding="utf-8")
        profile: dict[str, object] = {
            "binary": "goose",
            "buildScripts": {
                "macos": {
                    "path": "scripts/build-macos.ps1",
                    "sha256": hashlib.sha256(macos_path.read_bytes()).hexdigest(),
                },
                "windows": {
                    "path": "scripts/build-windows.ps1",
                    "sha256": hashlib.sha256(windows_path.read_bytes()).hexdigest(),
                },
            },
            "features": [
                "accordlock-distribution",
                "rustls-tls",
                "system-keyring",
            ],
            "package": "goose-cli",
        }
        return profile_path, profile

    @staticmethod
    def _repin_script(profile: dict[str, object], platform: str, path: Path) -> None:
        profile["buildScripts"][platform]["sha256"] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()

    def test_packaging_commands_are_bound_to_the_profile(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            workspace = Path(raw_directory)
            profile_path, profile = self._packaging_fixture(workspace)
            CHECKER.validate_packaging_commands(profile_path, profile)

            windows_path = workspace / "scripts" / "build-windows.ps1"
            windows_path.write_text(
                windows_path.read_text(encoding="utf-8") + "# unreviewed change\n",
                encoding="utf-8",
            )
            with self.assertRaises(CHECKER.ProfiledRustSecError):
                CHECKER.validate_packaging_commands(profile_path, profile)

    def test_argument_mutation_fails_even_when_script_digest_is_repinned(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            workspace = Path(raw_directory)
            profile_path, profile = self._packaging_fixture(workspace)
            windows_path = workspace / "scripts" / "build-windows.ps1"
            source = windows_path.read_text(encoding="utf-8").replace(
                "$gooseBuildExitCode = 1",
                "$gooseCargoArguments += @('--all-features')\n$gooseBuildExitCode = 1",
            )
            windows_path.write_text(source, encoding="utf-8")
            self._repin_script(profile, "windows", windows_path)
            with self.assertRaises(CHECKER.ProfiledRustSecError):
                CHECKER.validate_packaging_commands(profile_path, profile)

    def test_nonexecuted_decoy_command_cannot_validate_a_different_call(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            workspace = Path(raw_directory)
            profile_path, profile = self._packaging_fixture(workspace)
            windows_path = workspace / "scripts" / "build-windows.ps1"
            source = windows_path.read_text(encoding="utf-8")
            source = source.replace(
                "$gooseCargoArguments = @(",
                "if ($false) {\n$gooseCargoArguments = @(",
                1,
            ).replace(
                ")\n$gooseBuildExitCode = 1",
                ")\n}\n$gooseCargoArguments = @('build', '--all-features')\n"
                "$gooseBuildExitCode = 1",
                1,
            )
            windows_path.write_text(source, encoding="utf-8")
            self._repin_script(profile, "windows", windows_path)
            with self.assertRaises(CHECKER.ProfiledRustSecError):
                CHECKER.validate_packaging_commands(profile_path, profile)

    def test_removed_native_host_guard_fails_even_when_script_digest_is_repinned(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            workspace = Path(raw_directory)
            profile_path, profile = self._packaging_fixture(workspace)
            macos_path = workspace / "scripts" / "build-macos.ps1"
            source = macos_path.read_text(encoding="utf-8").replace(
                "$rustcHost -cne $targetTriple",
                "$rustcHost -cne 'some-other-target'",
            )
            macos_path.write_text(source, encoding="utf-8")
            self._repin_script(profile, "macos", macos_path)
            with self.assertRaises(CHECKER.ProfiledRustSecError):
                CHECKER.validate_packaging_commands(profile_path, profile)

    def test_windows_wrapper_mutations_fail_even_when_repinned(self) -> None:
        mutations = (
            ("param([string[]]$Arguments, [string]$TargetDirectory)", "param([string[]]$Arguments, [string]$TargetDirectory)\n$Arguments += '--all-features'"),
            ("& cargo @effectiveArguments", "& cargo @effectiveArguments\n$effectiveArguments += '--all-features'"),
            ("& cargo @effectiveArguments", "& cargo @effectiveArguments\n& cargo @Arguments --all-features"),
        )
        for anchor, mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw_directory:
                workspace = Path(raw_directory)
                profile_path, profile = self._packaging_fixture(workspace)
                path = workspace / "scripts" / "build-windows.ps1"
                path.write_text(
                    path.read_text(encoding="utf-8").replace(anchor, mutation, 1),
                    encoding="utf-8",
                )
                self._repin_script(profile, "windows", path)
                with self.assertRaises(CHECKER.ProfiledRustSecError):
                    CHECKER.validate_packaging_commands(profile_path, profile)

    def test_macos_wrapper_mutations_and_decoy_fail_even_when_repinned(self) -> None:
        command = "& cargo @Arguments --target-dir $resolvedTargetDirectory"
        mutations = (
            ("param([string[]]$Arguments, [string]$TargetDirectory)", "param([string[]]$Arguments, [string]$TargetDirectory)\n$Arguments += '--all-features'"),
            (command, command + "\n$Arguments = @('build', '--all-features')"),
            (command, "if ($false) { & cargo build --all-features }\n" + command),
        )
        for anchor, mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw_directory:
                workspace = Path(raw_directory)
                profile_path, profile = self._packaging_fixture(workspace)
                path = workspace / "scripts" / "build-macos.ps1"
                path.write_text(
                    path.read_text(encoding="utf-8").replace(anchor, mutation, 1),
                    encoding="utf-8",
                )
                self._repin_script(profile, "macos", path)
                with self.assertRaises(CHECKER.ProfiledRustSecError):
                    CHECKER.validate_packaging_commands(profile_path, profile)

    def test_release_target_cannot_be_persistent_bypassed_or_left_behind(self) -> None:
        cases = (
            (
                "windows",
                "New-AccordLockCargoTargetDirectory -SourceRoot $gooseSourceRoot",
                "[IO.Path]::GetFullPath((Join-Path $gooseSourceRoot 'target'))",
            ),
            (
                "windows",
                "-TargetDirectory $gooseCargoTargetDirectory",
                "-TargetDirectory (Join-Path $gooseSourceRoot 'target')",
            ),
            ("windows", "-Directory $gooseCargoTargetDirectory", "-Directory $null"),
            (
                "macos",
                "New-AccordLockCargoTargetDirectory -SourceRoot $GooseRoot",
                "[IO.Path]::GetFullPath((Join-Path $GooseRoot 'target'))",
            ),
            (
                "macos",
                "-TargetDirectory $gooseCargoTargetDirectory",
                "-TargetDirectory (Join-Path $GooseRoot 'target')",
            ),
            ("macos", "-Directory $gooseCargoTargetDirectory", "-Directory $null"),
        )
        for platform, old, new in cases:
            with self.subTest(platform=platform, mutation=new), tempfile.TemporaryDirectory() as raw_directory:
                workspace = Path(raw_directory)
                profile_path, profile = self._packaging_fixture(workspace)
                path = workspace / "scripts" / f"build-{platform}.ps1"
                source = path.read_text(encoding="utf-8")
                self.assertIn(old, source)
                path.write_text(source.replace(old, new, 1), encoding="utf-8")
                self._repin_script(profile, platform, path)
                with self.assertRaises(CHECKER.ProfiledRustSecError):
                    CHECKER.validate_packaging_commands(profile_path, profile)

    def test_release_source_revalidation_cannot_be_removed_when_repinned(self) -> None:
        for platform, assertion in (
            ("windows", "Assert-AccordLockReleaseSourceIdentity\n"),
            ("macos", "Assert-ReleaseSourceIdentity\n"),
        ):
            with self.subTest(platform=platform), tempfile.TemporaryDirectory() as raw_directory:
                workspace = Path(raw_directory)
                profile_path, profile = self._packaging_fixture(workspace)
                path = workspace / "scripts" / f"build-{platform}.ps1"
                source = path.read_text(encoding="utf-8")
                path.write_text(source.replace(assertion, "", 1), encoding="utf-8")
                self._repin_script(profile, platform, path)
                with self.assertRaises(CHECKER.ProfiledRustSecError):
                    CHECKER.validate_packaging_commands(profile_path, profile)

    def test_ci_matrix_contains_every_native_host_target_pair(self) -> None:
        profile = {
            "hostTargets": [
                {"host": host, "target": target, "runner": runner}
                for host, target, runner in sorted(CHECKER.ALLOWED_HOST_TARGET_RUNNERS)
            ]
        }
        matrix = CHECKER.ci_matrix(profile)
        observed = {
            (item["host"], item["target"], item["runner"])
            for item in matrix["include"]
        }
        self.assertEqual(observed, CHECKER.ALLOWED_HOST_TARGET_RUNNERS)
        with self.assertRaises(CHECKER.ProfiledRustSecError):
            CHECKER.select_host_target(
                profile,
                expected_host="x86_64-unknown-linux-gnu",
                target="aarch64-apple-darwin",
            )


if __name__ == "__main__":
    unittest.main()
