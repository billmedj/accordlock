#!/usr/bin/env python3
"""Build and run AccordLock's provider-free native demonstration."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "runtime"
DEMO_ENTRYPOINT = ROOT / "demos" / "run_demo.py"
DEMO_SOURCE = ROOT / "demos" / "src"
REPORT_NAMES = ("adversarial-demo.json", "adversarial-demo.md")
MAX_REPORT_BYTES = 4 * 1024 * 1024


class DemoFailure(RuntimeError):
    """A fail-closed launcher error with a user-facing diagnostic."""


def _arguments(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build the two native AccordLock entrypoints and run the provider-free "
            "security demonstration. No model provider, account, or external request is used."
        )
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="pass --offline to Cargo so dependency resolution cannot use the network",
    )
    parser.add_argument(
        "--output-directory",
        type=Path,
        help=(
            "copy the full JSON and Markdown reports to this directory; by default "
            "all report artifacts are temporary"
        ),
    )
    parser.add_argument(
        "--display",
        choices=("json", "markdown"),
        help="print a concise JSON or Markdown result after the demonstration passes",
    )
    return parser.parse_args(argv)


def _locate_cargo(environment: dict[str, str]) -> str:
    configured = environment.get("ACCORDLOCK_CARGO")
    if configured:
        candidate = Path(os.path.abspath(os.path.expanduser(configured)))
        if not candidate.is_file():
            raise DemoFailure(f"ACCORDLOCK_CARGO is not a regular file: {candidate}")
        return str(candidate)

    discovered = shutil.which("cargo", path=environment.get("PATH"))
    if discovered:
        return discovered

    if os.name == "nt" and environment.get("USERPROFILE"):
        candidate = Path(environment["USERPROFILE"]) / ".cargo" / "bin" / "cargo.exe"
        if candidate.is_file():
            # Rustup tool proxies rely on argv[0] to select Cargo. Resolving the
            # cargo.exe link to rustup.exe would invoke the wrong command.
            return str(candidate.absolute())

    raise DemoFailure(
        "Cargo is unavailable. Install the Rust toolchain declared in "
        "runtime/rust-toolchain.toml or set ACCORDLOCK_CARGO to the cargo executable."
    )


def _selected_environment(source: dict[str, str], names: set[str]) -> dict[str, str]:
    selected = {name.upper() for name in names}
    return {key: value for key, value in source.items() if key.upper() in selected}


def _cargo_environment(source: dict[str, str], offline: bool) -> dict[str, str]:
    environment = _selected_environment(
        source,
        {
            "APPDATA",
            "CARGO_HOME",
            "COMSPEC",
            "HOME",
            "HOMEDRIVE",
            "HOMEPATH",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "LOCALAPPDATA",
            "PATH",
            "PATHEXT",
            "PROCESSOR_ARCHITECTURE",
            "PROGRAMFILES",
            "PROGRAMFILES(X86)",
            "PROGRAMW6432",
            "RUSTUP_HOME",
            "SSL_CERT_DIR",
            "SSL_CERT_FILE",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "TMPDIR",
            "USERPROFILE",
            "WINDIR",
        },
    )
    environment["CARGO_INCREMENTAL"] = "0"
    environment["CARGO_TERM_COLOR"] = "never"
    if offline:
        environment["CARGO_NET_OFFLINE"] = "true"
    return environment


def _windows_msvc_environment(
    source: dict[str, str], environment: dict[str, str]
) -> dict[str, str]:
    if os.name != "nt" or shutil.which("link.exe", path=environment.get("PATH")):
        return environment

    candidates: list[Path] = []
    program_files_x86 = source.get("PROGRAMFILES(X86)") or source.get("ProgramFiles(x86)")
    if program_files_x86:
        vswhere = (
            Path(program_files_x86)
            / "Microsoft Visual Studio"
            / "Installer"
            / "vswhere.exe"
        )
        if vswhere.is_file():
            try:
                discovered = subprocess.run(
                    [str(vswhere), "-all", "-products", "*", "-format", "json"],
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=10.0,
                    check=False,
                    shell=False,
                )
                if discovered.returncode == 0 and len(discovered.stdout) <= 1024 * 1024:
                    installations = json.loads(discovered.stdout)
                    if isinstance(installations, list):
                        for installation in installations:
                            if isinstance(installation, dict) and isinstance(
                                installation.get("installationPath"), str
                            ):
                                candidates.append(
                                    Path(installation["installationPath"])
                                    / "VC"
                                    / "Auxiliary"
                                    / "Build"
                                    / "vcvarsall.bat"
                                )
            except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
                pass

        visual_studio = Path(program_files_x86) / "Microsoft Visual Studio"
        if visual_studio.is_dir():
            candidates.extend(
                visual_studio.glob("*/*/VC/Auxiliary/Build/vcvarsall.bat")
            )

    system_root = source.get("SYSTEMROOT") or source.get("SystemRoot")
    command_processor = (
        Path(system_root) / "System32" / "cmd.exe" if system_root else Path("cmd.exe")
    )
    machine = platform.machine().upper()
    architecture = "arm64" if machine in {"ARM64", "AARCH64"} else "x64"
    seen: set[Path] = set()
    for candidate in sorted(candidates, reverse=True):
        candidate = candidate.absolute()
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        try:
            prepared = subprocess.run(
                [
                    str(command_processor),
                    "/d",
                    "/s",
                    "/c",
                    f'call "{candidate}" {architecture} >nul && set',
                ],
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30.0,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if prepared.returncode != 0:
            continue
        updated = environment.copy()
        for line in prepared.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                if key:
                    updated[key] = value
        if shutil.which("link.exe", path=updated.get("PATH")):
            return updated

    raise DemoFailure(
        "the Windows MSVC linker environment is unavailable; install Visual Studio "
        "Build Tools with the Desktop development with C++ workload"
    )


def _demo_environment(source: dict[str, str]) -> dict[str, str]:
    environment = _selected_environment(
        source,
        {
            "COMSPEC",
            "HOME",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "TEMP",
            "TMP",
            "TMPDIR",
            "TZ",
            "USERPROFILE",
            "WINDIR",
        },
    )
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(DEMO_SOURCE)
    return environment


def _diagnostic(completed: subprocess.CompletedProcess[str]) -> str:
    stderr = completed.stderr.strip()
    if stderr:
        return stderr[-4096:]
    rendered: list[str] = []
    for line in completed.stdout.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict) or message.get("reason") != "compiler-message":
            continue
        detail = message.get("message")
        if isinstance(detail, dict) and isinstance(detail.get("rendered"), str):
            rendered.append(detail["rendered"].strip())
    if rendered:
        return "\n".join(rendered)[-4096:]
    stdout = completed.stdout.strip()
    return stdout[-4096:] if stdout else "no diagnostic"


def _run_command(
    label: str,
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: float,
) -> subprocess.CompletedProcess[str]:
    print(f"RUN {label}", flush=True)
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as error:
        raise DemoFailure(f"{label} exceeded {timeout_seconds:g} seconds") from error
    except OSError as error:
        raise DemoFailure(f"{label} could not start: {error}") from error
    if completed.returncode != 0:
        raise DemoFailure(
            f"{label} exited with status {completed.returncode}: {_diagnostic(completed)}"
        )
    print(f"PASS {label}", flush=True)
    return completed


def _built_binaries(build_output: str) -> tuple[Path, Path]:
    executables: dict[str, Path] = {}
    for line in build_output.splitlines():
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict) or message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target")
        executable = message.get("executable")
        if not isinstance(target, dict) or not isinstance(executable, str):
            continue
        name = target.get("name")
        kinds = target.get("kind")
        if name not in {"accordlock", "accordlock-agent-runtime"} or kinds != ["bin"]:
            continue
        path = Path(executable).resolve()
        previous = executables.get(name)
        if previous is not None and previous != path:
            raise DemoFailure(f"Cargo reported multiple executables for {name}")
        executables[name] = path

    missing = sorted({"accordlock", "accordlock-agent-runtime"} - executables.keys())
    if missing:
        raise DemoFailure(f"Cargo did not report the required executable(s): {', '.join(missing)}")
    for name, path in executables.items():
        if not path.is_file():
            raise DemoFailure(f"Cargo reported a missing {name} executable: {path}")
    return executables["accordlock"], executables["accordlock-agent-runtime"]


def _json_object(raw: str, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise DemoFailure(f"{label} did not emit one JSON document") from error
    if not isinstance(value, dict):
        raise DemoFailure(f"{label} JSON root is not an object")
    return value


def _verify_offline_proof(raw: str) -> None:
    proof = _json_object(raw, "native offline proof")
    profile = proof.get("execution_profile")
    if (
        proof.get("schema_version") != 2
        or proof.get("report_kind") != "OFFLINE_DETERMINISTIC_SECURITY_DEMO"
        or proof.get("production_ready") is not False
        or not isinstance(profile, dict)
        or profile.get("mode") != "OFFLINE_DETERMINISTIC_NO_NETWORK"
        or profile.get("network_access") != "NOT_ACCESSED"
        or profile.get("external_mutation") != "NONE"
    ):
        raise DemoFailure("native offline proof crossed or omitted its declared safety boundary")


def _read_report(path: Path) -> str:
    if not path.is_file():
        raise DemoFailure(f"demonstration report is missing: {path.name}")
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise DemoFailure(f"demonstration report exceeds {MAX_REPORT_BYTES} bytes: {path.name}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise DemoFailure(f"demonstration report is unreadable: {path.name}") from error


def _verify_demo_report(report_directory: Path) -> dict[str, Any]:
    report = _json_object(
        _read_report(report_directory / "adversarial-demo.json"),
        "adversarial demonstration",
    )
    _read_report(report_directory / "adversarial-demo.md")
    cases = report.get("cases")
    profile = report.get("execution_profile")
    if (
        report.get("status") != "PASS"
        or not isinstance(cases, list)
        or not cases
        or any(not isinstance(case, dict) or case.get("status") != "PASS" for case in cases)
        or not isinstance(profile, dict)
        or profile.get("model_provider") != "NONE"
        or profile.get("external_accounts") != "NONE"
        or profile.get("internet_transport") != "NOT_ATTEMPTED"
        or profile.get("external_mutation") != "NONE"
    ):
        raise DemoFailure("adversarial demonstration did not satisfy its provider-free contract")
    return report


def _copy_reports(source: Path, requested: Path) -> Path:
    destination = requested.expanduser().resolve()
    if destination.exists() and not destination.is_dir():
        raise DemoFailure(f"output path is not a directory: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    existing = [name for name in REPORT_NAMES if (destination / name).exists()]
    if existing:
        raise DemoFailure(
            "refusing to replace existing report file(s): " + ", ".join(existing)
        )
    for name in REPORT_NAMES:
        shutil.copy2(source / name, destination / name)
    return destination


def _concise_result(report: dict[str, Any]) -> dict[str, Any]:
    profile = report["execution_profile"]
    return {
        "schema_version": 1,
        "result": report["status"],
        "cases": [
            {"id": case.get("case_id", "unknown"), "result": case["status"]}
            for case in report["cases"]
        ],
        "execution": {
            "model_provider": profile["model_provider"],
            "external_accounts": profile["external_accounts"],
            "internet_transport": profile["internet_transport"],
            "external_mutation": profile["external_mutation"],
        },
    }


def _display_result(report: dict[str, Any], display: str) -> None:
    concise = _concise_result(report)
    if display == "json":
        print(json.dumps(concise, indent=2, sort_keys=True))
        return
    print("# AccordLock provider-free demonstration")
    print()
    print(f"**Result:** {concise['result']}")
    print()
    for case in concise["cases"]:
        print(f"- `{case['id']}`: {case['result']}")
    print()
    print("No model provider, external account, internet transport, or external mutation was used.")


def run(arguments: argparse.Namespace) -> dict[str, Any]:
    source_environment = os.environ.copy()
    cargo = _locate_cargo(source_environment)
    cargo_environment = _cargo_environment(source_environment, arguments.offline)
    cargo_environment = _windows_msvc_environment(source_environment, cargo_environment)
    build_command = [
        cargo,
        "build",
        "--locked",
    ]
    if arguments.offline:
        build_command.append("--offline")
    build_command.extend(
        [
            "--message-format=json-render-diagnostics",
            "-p",
            "accordlock-cli",
            "-p",
            "accordlock-agent-runtime",
        ]
    )
    build = _run_command(
        "native-build",
        build_command,
        cwd=RUNTIME,
        environment=cargo_environment,
        timeout_seconds=1800.0,
    )
    cli_binary, runtime_binary = _built_binaries(build.stdout)

    child_environment = _demo_environment(source_environment)
    proof = _run_command(
        "native-offline-proof",
        [str(cli_binary), "offline", "--compact"],
        cwd=RUNTIME,
        environment=child_environment,
        timeout_seconds=120.0,
    )
    _verify_offline_proof(proof.stdout)

    with tempfile.TemporaryDirectory(prefix="accordlock-provider-free-demo-") as temporary:
        report_directory = Path(temporary) / "reports"
        _run_command(
            "native-adversarial-demo",
            [
                sys.executable,
                str(DEMO_ENTRYPOINT),
                "--cli-binary",
                str(cli_binary),
                "--runtime-binary",
                str(runtime_binary),
                "--output-directory",
                str(report_directory),
            ],
            cwd=ROOT / "demos",
            environment=child_environment,
            timeout_seconds=180.0,
        )
        report = _verify_demo_report(report_directory)
        persisted = None
        if arguments.output_directory is not None:
            persisted = _copy_reports(report_directory, arguments.output_directory)

    if persisted is not None:
        print(f"REPORTS {persisted}")
    print(
        "PASS provider_free_demo "
        f"cases={len(report['cases'])} provider=NONE network=NOT_ATTEMPTED",
        flush=True,
    )
    if arguments.display:
        _display_result(report, arguments.display)
    return report


def main(argv: list[str] | None = None) -> int:
    try:
        run(_arguments(argv))
    except (DemoFailure, OSError, subprocess.SubprocessError) as error:
        print(f"FAIL provider_free_demo: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
