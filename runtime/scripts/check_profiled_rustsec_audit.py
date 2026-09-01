#!/usr/bin/env python3
"""Audit the exact Rust package graph compiled into the desktop sidecar.

``cargo audit`` intentionally audits every package record in a lockfile.  A
workspace lockfile can also contain packages that are reachable only through
disabled features or unrelated workspace members.  This checker keeps the
full-lock audit (with no advisory ignores or target/severity filters), derives
the released graph independently with Cargo's own resolver, and fails when any
reported vulnerability or warning belongs to that graph.

The reviewed profile pins a stable SHA-256 digest for each release target.  A
dependency, source, checksum, or activated-feature change therefore requires
an explicit profile update instead of silently changing the audit boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import time
import tomllib
from pathlib import Path
from typing import Any


SCRIPT_DIRECTORY = Path(__file__).resolve().parent
BASE_CHECKER_PATH = SCRIPT_DIRECTORY / "check_rustsec_audit.py"
BASE_SPEC = importlib.util.spec_from_file_location(
    "accordlock_complete_lock_rustsec_audit", BASE_CHECKER_PATH
)
if BASE_SPEC is None or BASE_SPEC.loader is None:
    raise RuntimeError(f"cannot load RustSec checker from {BASE_CHECKER_PATH}")
BASE = importlib.util.module_from_spec(BASE_SPEC)
sys.modules[BASE_SPEC.name] = BASE
BASE_SPEC.loader.exec_module(BASE)


PROFILE_SCHEMA_VERSION = 2
TREE_MARKER = "__ACCORDLOCK_PROFILE_PACKAGE__"
CRATES_IO_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SOURCE = re.compile(r"git\+https://[^#]+#[0-9a-f]{40}")
PACKAGE_DISPLAY = re.compile(
    r"(?P<name>[A-Za-z0-9_-]+) v(?P<version>[^\s]+)(?:\s.*)?"
)
FEATURE_NAME = re.compile(r"[A-Za-z0-9_.+/-]+")
ADVISORY_ID = re.compile(r"RUSTSEC-[0-9]{4}-[0-9]{4}")
TARGET_TRIPLE = re.compile(r"[A-Za-z0-9_]+(?:-[A-Za-z0-9_]+){2,}")
ALLOWED_WARNING_KINDS = frozenset(BASE.REQUIRED_INFORMATIONAL_WARNINGS)
ALLOWED_HOST_TARGET_RUNNERS = frozenset(
    {
        ("aarch64-apple-darwin", "aarch64-apple-darwin", "macos-15"),
        ("x86_64-apple-darwin", "x86_64-apple-darwin", "macos-15-intel"),
        ("x86_64-pc-windows-msvc", "x86_64-pc-windows-msvc", "windows-2025"),
    }
)


class ProfiledRustSecError(RuntimeError):
    """The released dependency graph or its audit could not be proven safe."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProfiledRustSecError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ProfiledRustSecError(
            f"{label} keys differ: missing={missing} extra={extra}"
        )


def _relative_file(workspace: Path, raw: object, label: str) -> Path:
    if not isinstance(raw, str) or not raw or "\\" in raw:
        raise ProfiledRustSecError(f"{label} must be a non-empty POSIX path")
    relative = Path(raw)
    if relative.is_absolute() or ".." in relative.parts:
        raise ProfiledRustSecError(f"{label} escapes the profile workspace")
    resolved = (workspace / relative).resolve()
    if not resolved.is_relative_to(workspace) or not resolved.is_file():
        raise ProfiledRustSecError(f"{label} is missing or outside the workspace")
    return resolved


def _string_list(raw: object, label: str) -> tuple[str, ...]:
    if not isinstance(raw, list) or not raw or not all(
        isinstance(item, str) and FEATURE_NAME.fullmatch(item) for item in raw
    ):
        raise ProfiledRustSecError(f"{label} must contain valid non-empty names")
    values = tuple(raw)
    if len(set(values)) != len(values) or list(values) != sorted(values):
        raise ProfiledRustSecError(f"{label} must be unique and sorted")
    return values


def load_profile(profile_path: Path) -> dict[str, Any]:
    profile_path = profile_path.resolve()
    try:
        profile = json.loads(
            profile_path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProfiledRustSecError(f"cannot read profile: {error}") from error
    if not isinstance(profile, dict):
        raise ProfiledRustSecError("profile root must be an object")
    _require_exact_keys(
        profile,
        {
            "binary",
            "buildScripts",
            "defaultFeatures",
            "edgeKinds",
            "expectedRootFeatures",
            "features",
            "lockPath",
            "manifestPath",
            "package",
            "schemaVersion",
            "hostTargets",
        },
        "profile",
    )
    if profile.get("schemaVersion") != PROFILE_SCHEMA_VERSION:
        raise ProfiledRustSecError("unsupported profile schema version")
    if profile.get("defaultFeatures") is not False:
        raise ProfiledRustSecError("the distribution profile must disable default features")
    if profile.get("package") != "goose-cli" or profile.get("binary") != "goose":
        raise ProfiledRustSecError("the distribution root must be goose-cli/goose")
    features = _string_list(profile.get("features"), "features")
    expected_root_features = _string_list(
        profile.get("expectedRootFeatures"), "expectedRootFeatures"
    )
    if not set(features).issubset(expected_root_features):
        raise ProfiledRustSecError("requested features are absent from expected root features")
    if profile.get("edgeKinds") != ["normal", "build"]:
        raise ProfiledRustSecError("only normal and build dependency edges are auditable")

    host_targets = profile.get("hostTargets")
    if not isinstance(host_targets, list) or not host_targets:
        raise ProfiledRustSecError("hostTargets must be a non-empty array")
    observed_pairs: set[tuple[str, str, str]] = set()
    for index, expectation in enumerate(host_targets):
        if not isinstance(expectation, dict):
            raise ProfiledRustSecError(f"hostTargets[{index}] is not an object")
        _require_exact_keys(
            expectation,
            {"graphSha256", "host", "packageCount", "runner", "target"},
            f"hostTargets[{index}]",
        )
        host = expectation.get("host")
        target = expectation.get("target")
        runner = expectation.get("runner")
        if not isinstance(host, str) or TARGET_TRIPLE.fullmatch(host) is None:
            raise ProfiledRustSecError(f"invalid Rust host triple: {host!r}")
        if not isinstance(target, str) or TARGET_TRIPLE.fullmatch(target) is None:
            raise ProfiledRustSecError(f"invalid Rust target triple: {target!r}")
        if not isinstance(runner, str):
            raise ProfiledRustSecError(f"invalid CI runner for {host}->{target}")
        pair = (host, target, runner)
        if pair not in ALLOWED_HOST_TARGET_RUNNERS:
            raise ProfiledRustSecError(f"unsupported host/target runner: {pair}")
        if pair in observed_pairs:
            raise ProfiledRustSecError(f"duplicate host/target runner: {pair}")
        observed_pairs.add(pair)
        if not isinstance(expectation.get("packageCount"), int) or expectation[
            "packageCount"
        ] <= 0:
            raise ProfiledRustSecError(f"invalid package count for {host}->{target}")
        digest = expectation.get("graphSha256")
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            raise ProfiledRustSecError(f"invalid graph digest for {host}->{target}")
    if observed_pairs != ALLOWED_HOST_TARGET_RUNNERS:
        missing = sorted(ALLOWED_HOST_TARGET_RUNNERS - observed_pairs)
        raise ProfiledRustSecError(f"required native host/target pairs are missing: {missing}")

    scripts = profile.get("buildScripts")
    if not isinstance(scripts, dict):
        raise ProfiledRustSecError("buildScripts must be an object")
    _require_exact_keys(scripts, {"macos", "windows"}, "buildScripts")
    for platform, script in scripts.items():
        if not isinstance(script, dict):
            raise ProfiledRustSecError(f"buildScripts.{platform} must be an object")
        _require_exact_keys(script, {"path", "sha256"}, f"buildScripts.{platform}")
        digest = script.get("sha256")
        if not isinstance(digest, str) or SHA256.fullmatch(digest) is None:
            raise ProfiledRustSecError(f"buildScripts.{platform}.sha256 is malformed")

    workspace = profile_path.parent
    _relative_file(workspace, profile.get("manifestPath"), "manifestPath")
    _relative_file(workspace, profile.get("lockPath"), "lockPath")
    _relative_file(workspace, scripts["windows"].get("path"), "Windows build script")
    _relative_file(workspace, scripts["macos"].get("path"), "macOS build script")
    return profile


def _quoted_powershell_tokens(body: str) -> tuple[str, ...]:
    token_pattern = re.compile(r"(?P<quote>['\"])(?P<value>[^'\"\r\n]+)(?P=quote)")
    return tuple(match.group("value") for match in token_pattern.finditer(body))


def _powershell_function(source: str, name: str) -> str:
    matches = re.findall(
        rf"(?ms)^function\s+{re.escape(name)}\s*\{{.*?(?=^function\s+[A-Za-z0-9_-]+\s*\{{|\Z)",
        source,
    )
    if len(matches) != 1:
        raise ProfiledRustSecError(f"PowerShell function {name} is missing or duplicated")
    return matches[0]


def _variable_uses(source: str, variable: str) -> int:
    return len(re.findall(
        rf"(?i)(?<![A-Za-z0-9_])\${re.escape(variable)}(?![A-Za-z0-9_])", source
    ))


def _assert_only_array_syntax(body: str, *, allowed_variable: str | None) -> None:
    scrubbed = re.sub(r"(?P<quote>['\"])[^'\"\r\n]+(?P=quote)", "", body)
    if allowed_variable is not None:
        if scrubbed.count(allowed_variable) != 1:
            raise ProfiledRustSecError(
                f"packaging command must contain exactly one {allowed_variable}"
            )
        scrubbed = scrubbed.replace(allowed_variable, "")
    scrubbed = re.sub(r"[\s,]", "", scrubbed)
    if scrubbed:
        raise ProfiledRustSecError(
            f"packaging command contains unreviewed PowerShell input: {scrubbed!r}"
        )


def validate_packaging_commands(profile_path: Path, profile: dict[str, Any]) -> None:
    workspace = profile_path.resolve().parent
    scripts = profile["buildScripts"]
    features = ",".join(profile["features"])
    common = (
        "build",
        "--locked",
        "--release",
        "-p",
        profile["package"],
        "--bin",
        profile["binary"],
        "--no-default-features",
        "--features",
        features,
    )

    windows_path = _relative_file(
        workspace, scripts["windows"]["path"], "Windows build script"
    )
    windows_digest = hashlib.sha256(windows_path.read_bytes()).hexdigest()
    if windows_digest != scripts["windows"]["sha256"]:
        raise ProfiledRustSecError("Windows build script digest differs from the profile")
    windows_source = windows_path.read_text(encoding="utf-8")
    windows_target = "x86_64-pc-windows-msvc"
    target_assignments = re.findall(
        r"(?mi)^\$windowsTargetTriple\s*=\s*['\"]([^'\"]+)['\"]\s*$",
        windows_source,
    )
    if target_assignments != [windows_target]:
        raise ProfiledRustSecError("Windows packaging target assignment is not exact")
    for required_host_guard in (
        "$requiredWindowsArchitecture = [System.Runtime.InteropServices.Architecture]::X64",
        "[System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(",
        "[System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne $requiredWindowsArchitecture",
        "[System.Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture -ne $requiredWindowsArchitecture",
        "Windows packaging requires an x86-64 Windows host and x86-64 PowerShell process",
    ):
        if windows_source.count(required_host_guard) != 1:
            raise ProfiledRustSecError(
                f"Windows native host/target guard is missing: {required_host_guard}"
            )
    windows_match = re.search(
        r"\$gooseCargoArguments\s*=\s*@\((?P<body>.*?)\)\s*\r?\n",
        windows_source,
        re.DOTALL,
    )
    if windows_match is None:
        raise ProfiledRustSecError("Windows Goose build argument array is missing")
    windows_body = windows_match.group("body")
    _assert_only_array_syntax(windows_body, allowed_variable="$windowsTargetTriple")
    windows_expected = common[:3] + ("--target",) + common[3:]
    if _quoted_powershell_tokens(windows_body) != windows_expected:
        raise ProfiledRustSecError("Windows Goose build command differs from the profile")
    goose_argument_uses = re.findall(
        r"(?i)(?<![A-Za-z0-9_])\$gooseCargoArguments(?![A-Za-z0-9_])",
        windows_source,
    )
    if len(goose_argument_uses) != 2:
        raise ProfiledRustSecError(
            "Windows Goose arguments must have one definition and one productive use"
        )
    productive_calls = re.findall(
        r"(?ms)^[ \t]*Invoke-AccordLockCargoBuild\s+`\s*\r?\n"
        r"\s*-Arguments\s+\$gooseCargoArguments\s+`\s*\r?\n"
        r"\s*-SourceRoot\s+\$gooseSourceRoot\s+`\s*\r?\n"
        r"\s*-TargetDirectory\s+\$gooseCargoTargetDirectory\s+`\s*\r?\n"
        r"\s*-NativePackagesToClean\s+@\('aws-lc-sys'\)\s+`\s*\r?\n"
        r"\s*-ExitCode\s+\(\[ref\]\$gooseBuildExitCode\)\s*$",
        windows_source,
    )
    if len(productive_calls) != 1:
        raise ProfiledRustSecError("Windows profiled Cargo invocation is missing or duplicated")
    windows_wrapper = _powershell_function(windows_source, "Invoke-AccordLockCargoBuild")
    if windows_wrapper.count(
        "$localTargetDirectory = [IO.Path]::GetFullPath($TargetDirectory)"
    ) != 1 or _variable_uses(windows_wrapper, "TargetDirectory") != 2:
        raise ProfiledRustSecError("Windows Cargo target is not passed through exactly")
    if windows_wrapper.count(
        "$effectiveArguments = @($Arguments) + @('--target-dir', $localTargetDirectory)"
    ) != 1 or windows_wrapper.count("& cargo @effectiveArguments") != 1:
        raise ProfiledRustSecError("Windows Cargo wrapper mutates or bypasses profiled arguments")
    if _variable_uses(windows_wrapper, "Arguments") != 2:
        raise ProfiledRustSecError("Windows Cargo wrapper mutates its Arguments parameter")
    if _variable_uses(windows_wrapper, "effectiveArguments") != 1 or len(
        re.findall(r"(?i)(?<![A-Za-z0-9_])@effectiveArguments(?![A-Za-z0-9_])", windows_wrapper)
    ) != 1:
        raise ProfiledRustSecError("Windows effective Cargo arguments are mutable or reused")
    if len(re.findall(r"(?i)&\s*cargo(?:\.exe)?\b", windows_source)) != 2:
        raise ProfiledRustSecError("Windows packaging has an unexpected direct Cargo execution")
    for required_release_target in (
        "$gooseCargoTargetDirectory = if ($Release) {",
        "New-AccordLockCargoTargetDirectory -SourceRoot $gooseSourceRoot",
        '$gooseBinary = Join-Path $gooseCargoTargetDirectory "$windowsTargetTriple\\$profileName\\goose.exe"',
        "if ($Release -and $gooseCargoTargetDirectory) {",
        "-Directory $gooseCargoTargetDirectory",
    ):
        if windows_source.count(required_release_target) != 1:
            raise ProfiledRustSecError(
                f"Windows ephemeral release target invariant is missing: {required_release_target}"
            )
    if windows_source.count("Assert-AccordLockReleaseSourceIdentity") != 5:
        raise ProfiledRustSecError("Windows release source revalidation is incomplete")

    macos_path = _relative_file(
        workspace, scripts["macos"]["path"], "macOS build script"
    )
    macos_digest = hashlib.sha256(macos_path.read_bytes()).hexdigest()
    if macos_digest != scripts["macos"]["sha256"]:
        raise ProfiledRustSecError("macOS build script digest differs from the profile")
    macos_source = macos_path.read_text(encoding="utf-8")
    macos_target_assignment = (
        "$targetTriple = if ($Architecture -ceq 'arm64') { "
        "'aarch64-apple-darwin' } else { 'x86_64-apple-darwin' }"
    )
    if macos_source.count(macos_target_assignment) != 1:
        raise ProfiledRustSecError("macOS architecture-to-target mapping is not exact")
    for required_host_guard in (
        "$rustcVerboseVersion = @(& rustc -vV)",
        "$rustcHostLines.Count -ne 1",
        "$rustcHost -cne $targetTriple",
        "macOS packaging requires a native host/target pair",
    ):
        if macos_source.count(required_host_guard) != 1:
            raise ProfiledRustSecError(
                f"macOS native host/target guard is missing: {required_host_guard}"
            )
    macos_wrapper = _powershell_function(macos_source, "Invoke-ReleaseCargoBuild")
    if macos_wrapper.count("& cargo @Arguments --target-dir $resolvedTargetDirectory") != 1:
        raise ProfiledRustSecError("macOS Cargo wrapper bypasses the supplied arguments")
    if macos_wrapper.count(
        "$resolvedTargetDirectory = [IO.Path]::GetFullPath($TargetDirectory)"
    ) != 1 or _variable_uses(macos_wrapper, "TargetDirectory") != 2:
        raise ProfiledRustSecError("macOS Cargo target is not passed through exactly")
    if _variable_uses(macos_wrapper, "Arguments") != 1 or len(
        re.findall(r"(?i)(?<![A-Za-z0-9_])@Arguments(?![A-Za-z0-9_])", macos_wrapper)
    ) != 1:
        raise ProfiledRustSecError("macOS Cargo wrapper mutates its Arguments parameter")
    if len(re.findall(r"(?i)&\s*cargo\b", macos_source)) != 1:
        raise ProfiledRustSecError("macOS packaging has an unexpected direct Cargo execution")
    for required_release_target in (
        "$gooseCargoTargetDirectory = if ($Release) {",
        "New-AccordLockCargoTargetDirectory -SourceRoot $GooseRoot",
        '$gooseBinary = Join-Path $gooseCargoTargetDirectory "$targetTriple/release/goose"',
        "if ($Release -and $gooseCargoTargetDirectory) {",
        "-Directory $gooseCargoTargetDirectory",
    ):
        if macos_source.count(required_release_target) != 1:
            raise ProfiledRustSecError(
                f"macOS ephemeral release target invariant is missing: {required_release_target}"
            )
    if macos_source.count("Assert-ReleaseSourceIdentity") != 5:
        raise ProfiledRustSecError("macOS release source revalidation is incomplete")
    candidate_matches = list(re.finditer(
        r"Invoke-ReleaseCargoBuild\s+`?\s*\r?\n?"
        r"\s*-SourceRoot\s+[^\r\n]+\s+`?\s*\r?\n"
        r"\s*-TargetDirectory\s+(?P<target>[^\r\n]+?)\s+`?\s*\r?\n"
        r"\s*-Arguments\s+@\((?P<body>.*?)\)",
        macos_source,
        re.DOTALL,
    ))
    if len(candidate_matches) != 2:
        raise ProfiledRustSecError("macOS packaging must contain exactly two Cargo invocations")
    goose_candidates = [
        match for match in candidate_matches
        if profile["package"] in _quoted_powershell_tokens(match.group("body"))
    ]
    if len(goose_candidates) != 1:
        raise ProfiledRustSecError("macOS must contain one profiled Goose build command")
    if goose_candidates[0].group("target").strip() != "$gooseCargoTargetDirectory":
        raise ProfiledRustSecError("macOS Goose build bypasses its ephemeral target")
    other_candidates = [match for match in candidate_matches if match not in goose_candidates]
    if other_candidates[0].group("target").strip() != "$runtimeCargoTargetDirectory":
        raise ProfiledRustSecError("macOS runtime build bypasses its ephemeral target")
    macos_body = goose_candidates[0].group("body")
    _assert_only_array_syntax(macos_body, allowed_variable="$targetTriple")
    macos_expected = common[:3] + ("--target",) + common[3:]
    if _quoted_powershell_tokens(macos_body) != macos_expected:
        raise ProfiledRustSecError("macOS Goose build command differs from the profile")


def _run(command: list[str], *, cwd: Path, timeout: int = 600) -> str:
    completed = subprocess.run(
        command,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=timeout,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ProfiledRustSecError(
            f"command failed with {completed.returncode}: {command[0]}: {detail}"
        )
    return completed.stdout


def run_audit(
    cargo_audit: Path, database: Path, lock_path: Path
) -> tuple[int, dict[str, Any], str]:
    completed = subprocess.run(
        [
            str(cargo_audit),
            "audit",
            "--db",
            str(database),
            "--no-fetch",
            "--no-yanked",
            "--file",
            str(lock_path),
            "--deny",
            "warnings",
            "--json",
            "--color",
            "never",
        ],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=300,
    )
    try:
        report = json.loads(
            completed.stdout, object_pairs_hook=_reject_duplicate_keys
        )
    except json.JSONDecodeError as error:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ProfiledRustSecError(
            f"cargo-audit returned invalid JSON: {detail}"
        ) from error
    if not isinstance(report, dict):
        raise ProfiledRustSecError("cargo-audit JSON root is not an object")
    return completed.returncode, report, completed.stderr.strip()


def _cargo_arguments(profile: dict[str, Any]) -> list[str]:
    arguments = ["--locked", "--manifest-path", profile["manifestPath"]]
    if profile["defaultFeatures"] is False:
        arguments.append("--no-default-features")
    arguments.extend(["--features", ",".join(profile["features"])])
    return arguments


def rustc_host(rustc: str, workspace: Path) -> str:
    output = _run([rustc, "-vV"], cwd=workspace, timeout=60)
    hosts = [
        line.split(":", 1)[1].strip()
        for line in output.splitlines()
        if line.startswith("host:")
    ]
    if len(hosts) != 1 or TARGET_TRIPLE.fullmatch(hosts[0]) is None:
        raise ProfiledRustSecError("rustc did not report one valid host triple")
    return hosts[0]


def select_host_target(
    profile: dict[str, Any], *, expected_host: str, target: str
) -> dict[str, Any]:
    matches = [
        entry
        for entry in profile["hostTargets"]
        if entry["host"] == expected_host and entry["target"] == target
    ]
    if len(matches) != 1:
        raise ProfiledRustSecError(
            f"profile does not contain exactly one native pair: {expected_host}->{target}"
        )
    return matches[0]


def ci_matrix(profile: dict[str, Any]) -> dict[str, Any]:
    return {
        "include": [
            {
                "cargoAudit": (
                    ".local/tools/cargo-audit/bin/cargo-audit.exe"
                    if entry["runner"].startswith("windows-")
                    else ".local/tools/cargo-audit/bin/cargo-audit"
                ),
                "host": entry["host"],
                "python": (
                    "python" if entry["runner"].startswith("windows-") else "python3"
                ),
                "runner": entry["runner"],
                "target": entry["target"],
            }
            for entry in sorted(
                profile["hostTargets"],
                key=lambda item: (item["runner"], item["host"], item["target"]),
            )
        ]
    }


def cargo_metadata(
    cargo: str, workspace: Path, profile: dict[str, Any], target: str
) -> dict[str, Any]:
    # Keep metadata unfiltered: Cargo can compile host-side build dependencies
    # whose cfg does not match the cross-compilation target. ``cargo tree``
    # below performs the exact target selection; metadata is only the identity
    # and source catalogue used to map that tree back to Cargo.lock.
    output = _run(
        [
            cargo,
            "metadata",
            "--format-version",
            "1",
            *_cargo_arguments(profile),
        ],
        cwd=workspace,
    )
    try:
        metadata = json.loads(output, object_pairs_hook=_reject_duplicate_keys)
    except json.JSONDecodeError as error:
        raise ProfiledRustSecError(f"cargo metadata returned invalid JSON: {error}") from error
    if not isinstance(metadata, dict):
        raise ProfiledRustSecError("cargo metadata root is not an object")
    return metadata


def cargo_tree(
    cargo: str, workspace: Path, profile: dict[str, Any], target: str
) -> str:
    return _run(
        [
            cargo,
            "tree",
            *_cargo_arguments(profile),
            "-p",
            profile["package"],
            "--target",
            target,
            "--edges",
            ",".join(profile["edgeKinds"]),
            "--prefix",
            "none",
            "--format",
            f"{TREE_MARKER}{{p}}\t{{f}}",
        ],
        cwd=workspace,
    )


def parse_tree(
    output: str, *, package: str, expected_root_features: tuple[str, ...]
) -> dict[tuple[str, str], set[tuple[str, ...]]]:
    packages: dict[tuple[str, str], set[tuple[str, ...]]] = {}
    root: tuple[str, str] | None = None
    root_features: tuple[str, ...] | None = None
    for line_number, raw_line in enumerate(output.splitlines(), start=1):
        if not raw_line:
            continue
        if not raw_line.startswith(TREE_MARKER):
            raise ProfiledRustSecError(
                f"unexpected cargo tree output at line {line_number}: {raw_line!r}"
            )
        payload = raw_line[len(TREE_MARKER) :]
        if payload.count("\t") != 1:
            raise ProfiledRustSecError(f"malformed cargo tree line {line_number}")
        display, raw_features = payload.split("\t", 1)
        if raw_features.endswith(" (*)"):
            raw_features = raw_features[:-4]
        match = PACKAGE_DISPLAY.fullmatch(display)
        if match is None:
            raise ProfiledRustSecError(
                f"unrecognized Cargo package display at line {line_number}: {display!r}"
            )
        key = (match.group("name"), match.group("version"))
        feature_tuple = tuple(sorted(filter(None, raw_features.split(","))))
        if len(set(feature_tuple)) != len(feature_tuple) or any(
            FEATURE_NAME.fullmatch(feature) is None for feature in feature_tuple
        ):
            raise ProfiledRustSecError(f"malformed feature set at line {line_number}")
        if root is None:
            root = key
            root_features = feature_tuple
        packages.setdefault(key, set()).add(feature_tuple)
    if root is None or root[0] != package:
        raise ProfiledRustSecError("cargo tree root differs from the distribution package")
    if root_features != expected_root_features:
        raise ProfiledRustSecError(
            "resolved root features differ from the reviewed profile: "
            f"observed={list(root_features or ())} expected={list(expected_root_features)}"
        )
    return packages


def _lock_index(lock_path: Path) -> tuple[dict[tuple[str, str, str | None], dict[str, Any]], int]:
    try:
        lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ProfiledRustSecError(f"cannot parse Cargo.lock: {error}") from error
    records = lock.get("package")
    if not isinstance(records, list) or not records:
        raise ProfiledRustSecError("Cargo.lock package list is empty or malformed")
    index: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise ProfiledRustSecError("Cargo.lock contains a non-object package")
        name = record.get("name")
        version = record.get("version")
        source = record.get("source")
        if not isinstance(name, str) or not isinstance(version, str) or (
            source is not None and not isinstance(source, str)
        ):
            raise ProfiledRustSecError("Cargo.lock contains a malformed package identity")
        key = (name, version, source)
        if key in index:
            raise ProfiledRustSecError(f"duplicate Cargo.lock package identity: {key}")
        index[key] = record
    return index, len(records)


def _canonical_package(
    package: dict[str, Any],
    feature_sets: set[tuple[str, ...]],
    *,
    workspace: Path,
    lock_index: dict[tuple[str, str, str | None], dict[str, Any]],
) -> tuple[tuple[str, str, str | None], dict[str, Any]]:
    name = package.get("name")
    version = package.get("version")
    source = package.get("source")
    checksum = package.get("checksum")
    manifest_path = package.get("manifest_path")
    if not isinstance(name, str) or not isinstance(version, str) or (
        source is not None and not isinstance(source, str)
    ):
        raise ProfiledRustSecError("cargo metadata package identity is malformed")
    identity = (name, version, source)
    lock_record = lock_index.get(identity)
    if lock_record is None:
        raise ProfiledRustSecError(f"resolved package is absent from Cargo.lock: {identity}")

    if source is None:
        if checksum is not None or not isinstance(manifest_path, str):
            raise ProfiledRustSecError(f"local package metadata is malformed: {name} {version}")
        resolved_manifest = Path(manifest_path).resolve()
        if not resolved_manifest.is_relative_to(workspace) or not resolved_manifest.is_file():
            raise ProfiledRustSecError(
                f"local package manifest escapes the workspace: {resolved_manifest}"
            )
        canonical_source = "path+" + resolved_manifest.relative_to(workspace).as_posix()
        canonical_checksum = None
    elif source == CRATES_IO_SOURCE:
        lock_checksum = lock_record.get("checksum")
        if (
            not isinstance(lock_checksum, str)
            or SHA256.fullmatch(lock_checksum) is None
            or (checksum is not None and checksum != lock_checksum)
        ):
            raise ProfiledRustSecError(
                f"registry checksum mismatch: {name} {version}"
            )
        canonical_source = source
        canonical_checksum = lock_checksum
    elif GIT_SOURCE.fullmatch(source) is not None:
        if checksum is not None or lock_record.get("checksum") is not None:
            raise ProfiledRustSecError(f"Git package unexpectedly has a checksum: {identity}")
        canonical_source = source
        canonical_checksum = None
    else:
        raise ProfiledRustSecError(f"unapproved package source: {identity}")

    return identity, {
        "checksum": canonical_checksum,
        "featureSets": [list(features) for features in sorted(feature_sets)],
        "name": name,
        "source": canonical_source,
        "version": version,
    }


def resolve_target_graph(
    *,
    cargo: str,
    workspace: Path,
    profile: dict[str, Any],
    target: str,
    lock_index: dict[tuple[str, str, str | None], dict[str, Any]],
) -> dict[str, Any]:
    metadata = cargo_metadata(cargo, workspace, profile, target)
    raw_packages = metadata.get("packages")
    resolve = metadata.get("resolve")
    if not isinstance(raw_packages, list) or not isinstance(resolve, dict):
        raise ProfiledRustSecError("cargo metadata has an unexpected shape")
    metadata_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    metadata_by_id: dict[str, dict[str, Any]] = {}
    for package in raw_packages:
        if not isinstance(package, dict):
            raise ProfiledRustSecError("cargo metadata contains a non-object package")
        name = package.get("name")
        version = package.get("version")
        package_id = package.get("id")
        if not all(isinstance(value, str) for value in (name, version, package_id)):
            raise ProfiledRustSecError("cargo metadata package key is malformed")
        metadata_by_key.setdefault((name, version), []).append(package)
        metadata_by_id[package_id] = package

    root_id = resolve.get("root")
    root_package = metadata_by_id.get(root_id) if isinstance(root_id, str) else None
    if root_package is None or root_package.get("name") != profile["package"]:
        raise ProfiledRustSecError("cargo metadata root differs from the profile package")
    root_targets = root_package.get("targets")
    if not isinstance(root_targets, list) or not any(
        isinstance(item, dict)
        and item.get("name") == profile["binary"]
        and isinstance(item.get("kind"), list)
        and "bin" in item["kind"]
        for item in root_targets
    ):
        raise ProfiledRustSecError("profile binary is absent from the root package")

    expected_root_features = tuple(profile["expectedRootFeatures"])
    tree_packages = parse_tree(
        cargo_tree(cargo, workspace, profile, target),
        package=profile["package"],
        expected_root_features=expected_root_features,
    )
    canonical_packages: list[dict[str, Any]] = []
    identities: set[tuple[str, str, str | None]] = set()
    for key, feature_sets in sorted(tree_packages.items()):
        candidates = metadata_by_key.get(key, [])
        if len(candidates) != 1:
            raise ProfiledRustSecError(
                "cargo tree package does not map to exactly one metadata package: "
                f"{key} candidates={len(candidates)}"
            )
        identity, canonical = _canonical_package(
            candidates[0], feature_sets, workspace=workspace, lock_index=lock_index
        )
        identities.add(identity)
        canonical_packages.append(canonical)

    graph_document = {
        "binary": profile["binary"],
        "defaultFeatures": profile["defaultFeatures"],
        "edgeKinds": profile["edgeKinds"],
        "features": profile["features"],
        "package": profile["package"],
        "packages": canonical_packages,
        "target": target,
    }
    encoded = json.dumps(
        graph_document, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    return {
        "digest": hashlib.sha256(encoded).hexdigest(),
        "identities": identities,
        "package_count": len(canonical_packages),
    }


def _validate_audit_envelope(
    report: dict[str, Any], *, expected_lock_packages: int
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    database = report.get("database")
    lockfile = report.get("lockfile")
    settings = report.get("settings")
    vulnerabilities = report.get("vulnerabilities")
    warnings = report.get("warnings")
    if not all(
        isinstance(value, dict)
        for value in (database, lockfile, settings, vulnerabilities, warnings)
    ):
        raise ProfiledRustSecError("cargo-audit JSON has an unexpected shape")
    advisory_count = database.get("advisory-count")
    if not isinstance(advisory_count, int) or advisory_count < 1_000:
        raise ProfiledRustSecError("RustSec advisory set is unexpectedly small")
    if lockfile.get("dependency-count") != expected_lock_packages:
        raise ProfiledRustSecError(
            "cargo-audit did not inspect the complete lockfile: "
            f"observed={lockfile.get('dependency-count')} expected={expected_lock_packages}"
        )
    if settings.get("target_arch") != [] or settings.get("target_os") != []:
        raise ProfiledRustSecError("cargo-audit target filtering is forbidden")
    if settings.get("severity") is not None:
        raise ProfiledRustSecError("cargo-audit severity filtering is forbidden")
    if settings.get("ignore") != []:
        raise ProfiledRustSecError("cargo-audit advisory ignores are forbidden")
    informational = settings.get("informational_warnings")
    if not isinstance(informational, list) or set(informational) != ALLOWED_WARNING_KINDS:
        raise ProfiledRustSecError("cargo-audit warning classes differ from the full policy")

    found = vulnerabilities.get("found")
    count = vulnerabilities.get("count")
    vulnerability_list = vulnerabilities.get("list")
    if not isinstance(found, bool) or not isinstance(count, int) or not isinstance(
        vulnerability_list, list
    ):
        raise ProfiledRustSecError("cargo-audit vulnerability result is malformed")
    if count != len(vulnerability_list) or found != (count > 0) or not all(
        isinstance(item, dict) for item in vulnerability_list
    ):
        raise ProfiledRustSecError("cargo-audit vulnerability result is inconsistent")

    typed_warnings: dict[str, list[dict[str, Any]]] = {}
    for kind, items in warnings.items():
        if kind not in ALLOWED_WARNING_KINDS or not isinstance(items, list) or not all(
            isinstance(item, dict) for item in items
        ):
            raise ProfiledRustSecError(f"cargo-audit warning result is malformed: {kind}")
        typed_warnings[kind] = items
    return vulnerability_list, typed_warnings


def _finding_identity(
    finding: dict[str, Any],
    *,
    lock_index: dict[tuple[str, str, str | None], dict[str, Any]],
) -> tuple[str, tuple[str, str, str | None]]:
    advisory = finding.get("advisory")
    package = finding.get("package")
    if not isinstance(advisory, dict) or not isinstance(package, dict):
        raise ProfiledRustSecError("cargo-audit finding lacks advisory or package data")
    advisory_id = advisory.get("id")
    name = package.get("name")
    version = package.get("version")
    source = package.get("source")
    checksum = package.get("checksum")
    if not isinstance(advisory_id, str) or ADVISORY_ID.fullmatch(advisory_id) is None:
        raise ProfiledRustSecError("cargo-audit finding has an invalid advisory ID")
    if not isinstance(name, str) or not isinstance(version, str) or (
        source is not None and not isinstance(source, str)
    ):
        raise ProfiledRustSecError("cargo-audit finding has a malformed package identity")
    identity = (name, version, source)
    lock_record = lock_index.get(identity)
    if lock_record is None:
        raise ProfiledRustSecError(
            f"cargo-audit finding does not map to Cargo.lock: {identity}"
        )
    if checksum != lock_record.get("checksum"):
        raise ProfiledRustSecError(
            f"cargo-audit finding checksum differs from Cargo.lock: {identity}"
        )
    return advisory_id, identity


def validate_profile_findings(
    report: dict[str, Any],
    *,
    expected_lock_packages: int,
    lock_index: dict[tuple[str, str, str | None], dict[str, Any]],
    profile_targets: dict[tuple[str, str, str | None], set[str]],
) -> dict[str, Any]:
    vulnerabilities, warnings = _validate_audit_envelope(
        report, expected_lock_packages=expected_lock_packages
    )
    findings: list[tuple[str, str, tuple[str, str, str | None]]] = []
    for item in vulnerabilities:
        advisory_id, identity = _finding_identity(item, lock_index=lock_index)
        findings.append(("vulnerability", advisory_id, identity))
    for kind, items in sorted(warnings.items()):
        for item in items:
            if item.get("kind") != kind:
                raise ProfiledRustSecError("cargo-audit warning kind is inconsistent")
            advisory_id, identity = _finding_identity(item, lock_index=lock_index)
            findings.append((kind, advisory_id, identity))
    if len(set(findings)) != len(findings):
        raise ProfiledRustSecError("cargo-audit contains duplicate findings")

    reachable = [finding for finding in findings if finding[2] in profile_targets]
    if reachable:
        details = []
        for kind, advisory_id, identity in sorted(reachable):
            targets = ",".join(sorted(profile_targets[identity]))
            details.append(
                f"{advisory_id}:{kind}:{identity[0]}@{identity[1]}:{targets}"
            )
        raise ProfiledRustSecError(
            "RustSec findings are reachable from the distributed graph: "
            + "; ".join(details)
        )
    return {
        "excludedOffProfileFindings": [
            {
                "advisory": advisory_id,
                "kind": kind,
                "package": f"{identity[0]}@{identity[1]}",
            }
            for kind, advisory_id, identity in sorted(findings)
        ],
        "profileFindings": 0,
        "wholeLockFindings": len(findings),
    }


def validate(
    *,
    cargo: str,
    rustc: str,
    cargo_audit: Path,
    git: str,
    database: Path,
    profile_path: Path,
    expected_commit_path: Path,
    max_age_days: int,
    expected_host: str,
    target: str,
) -> dict[str, Any]:
    profile_path = profile_path.resolve()
    profile = load_profile(profile_path)
    validate_packaging_commands(profile_path, profile)
    workspace = profile_path.parent
    lock_path = _relative_file(workspace, profile["lockPath"], "lockPath")
    lock_index, lock_count = _lock_index(lock_path)
    actual_host = rustc_host(rustc, workspace)
    if actual_host != expected_host:
        raise ProfiledRustSecError(
            f"native host differs from CI declaration: observed={actual_host} "
            f"expected={expected_host}"
        )
    expectation = select_host_target(
        profile, expected_host=expected_host, target=target
    )
    profile_targets: dict[tuple[str, str, str | None], set[str]] = {}
    graph = resolve_target_graph(
        cargo=cargo,
        workspace=workspace,
        profile=profile,
        target=target,
        lock_index=lock_index,
    )
    if graph["digest"] != expectation["graphSha256"] or graph[
        "package_count"
    ] != expectation["packageCount"]:
        raise ProfiledRustSecError(
            "distribution graph differs from the reviewed native profile: "
            f"host={actual_host} target={target} "
            f"observed={graph['digest']}/{graph['package_count']} "
            f"expected={expectation['graphSha256']}/{expectation['packageCount']}"
        )
    pair_label = f"{actual_host}->{target}"
    for identity in graph["identities"]:
        profile_targets.setdefault(identity, set()).add(pair_label)

    expected_commit = expected_commit_path.read_text(encoding="utf-8").strip()
    database_result = BASE.validate_database_snapshot(
        BASE.inspect_database(git, database.resolve()),
        now=int(time.time()),
        max_age_days=max_age_days,
        expected_commit=expected_commit,
    )
    return_code, report, stderr = run_audit(
        cargo_audit.resolve(), database.resolve(), lock_path
    )
    findings_result = validate_profile_findings(
        report,
        expected_lock_packages=lock_count,
        lock_index=lock_index,
        profile_targets=profile_targets,
    )
    expected_exit = 1 if findings_result["wholeLockFindings"] else 0
    if return_code != expected_exit:
        raise ProfiledRustSecError(
            "cargo-audit exit code is inconsistent with its validated report: "
            f"observed={return_code} expected={expected_exit} stderr={stderr}"
        )
    return {
        "audit": {
            **findings_result,
            "advisoryIgnores": 0,
            "dependenciesScanned": lock_count,
            "severityFilters": 0,
            "targetFilters": 0,
        },
        "database": database_result,
        "profile": {
            "defaultFeatures": False,
            "edgeKinds": profile["edgeKinds"],
            "features": profile["features"],
            "host": actual_host,
            "package": profile["package"],
            "profilePackages": len(profile_targets),
            "runner": expectation["runner"],
            "target": target,
            "graphSha256": graph["digest"],
            "packageCount": graph["package_count"],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--rustc", default="rustc")
    parser.add_argument("--cargo-audit", type=Path)
    parser.add_argument("--git", default="git")
    parser.add_argument("--db", type=Path)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--expected-commit-file", type=Path)
    parser.add_argument("--max-age-days", type=int, default=14)
    parser.add_argument("--expected-host")
    parser.add_argument("--target")
    parser.add_argument("--emit-ci-matrix", action="store_true")
    args = parser.parse_args()
    try:
        if args.emit_ci_matrix:
            if any(
                value is not None
                for value in (
                    args.cargo_audit,
                    args.db,
                    args.expected_commit_file,
                    args.expected_host,
                    args.target,
                )
            ):
                raise ProfiledRustSecError(
                    "--emit-ci-matrix cannot be combined with audit arguments"
                )
            profile = load_profile(args.profile)
            # Matrix generation is the first CI consumer of the profile. Refuse
            # to schedule jobs from a manifest that is not bound to the exact
            # productive packaging scripts.
            validate_packaging_commands(args.profile, profile)
            print(
                json.dumps(
                    ci_matrix(profile),
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
            return 0
        if any(
            value is None
            for value in (
                args.cargo_audit,
                args.db,
                args.expected_commit_file,
                args.expected_host,
                args.target,
            )
        ):
            raise ProfiledRustSecError(
                "audit mode requires cargo-audit, db, expected-commit-file, "
                "expected-host, and target"
            )
        result = validate(
            cargo=args.cargo,
            rustc=args.rustc,
            cargo_audit=args.cargo_audit,
            git=args.git,
            database=args.db,
            profile_path=args.profile,
            expected_commit_path=args.expected_commit_file,
            max_age_days=args.max_age_days,
            expected_host=args.expected_host,
            target=args.target,
        )
    except (
        OSError,
        ValueError,
        ProfiledRustSecError,
        BASE.RustSecAuditError,
        subprocess.SubprocessError,
    ) as error:
        print(f"FAIL profiled_rustsec_audit {error}")
        return 1
    print(
        "PASS profiled_rustsec_audit "
        + json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
