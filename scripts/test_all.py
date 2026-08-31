#!/usr/bin/env python3
"""Run explicit, layered AccordLock checks from the monorepo root."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "runtime"
DESKTOP = ROOT / "desktop"


class CheckFailure(RuntimeError):
    pass


def _program(name: str) -> str:
    configured = os.environ.get(f"ACCORDLOCK_{name.upper().replace('-', '_')}")
    if configured:
        path = Path(configured).expanduser().resolve()
        if not path.is_file():
            raise CheckFailure(f"configured {name} path is not a regular file: {path}")
        return str(path)
    resolved = shutil.which(name)
    if resolved:
        return resolved
    if os.name == "nt" and name == "cargo":
        profile = os.environ.get("USERPROFILE")
        if profile:
            candidate = Path(profile) / ".cargo" / "bin" / "cargo.exe"
            if candidate.is_file():
                return str(candidate)
    raise CheckFailure(f"required program is unavailable: {name}")


def _run(label: str, command: list[str], cwd: Path = ROOT, env: dict[str, str] | None = None) -> None:
    print(f"RUN {label}", flush=True)
    result = subprocess.run(command, cwd=cwd, env=env, check=False)
    if result.returncode != 0:
        raise CheckFailure(f"{label} exited with status {result.returncode}")
    print(f"PASS {label}", flush=True)


def _base_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def run_source_checks() -> None:
    python = sys.executable
    environment = _base_environment()
    _run("publication", [python, "scripts/check_publication.py"], env=environment)
    _run("publication-tests", [python, "-m", "unittest", "discover", "-s", "tests", "-v"], env=environment)
    _run(
        "assurance-tests",
        [python, "-m", "unittest", "discover", "-s", "assurance/tests", "-t", "assurance", "-v"],
        env=environment,
    )
    demo_environment = environment.copy()
    demo_environment["PYTHONPATH"] = str(ROOT / "demos" / "src")
    _run(
        "provider-free-demo-tests",
        [python, "-W", "error::ResourceWarning", "-m", "unittest", "discover", "-s", "demos/tests", "-v"],
        env=demo_environment,
    )


def run_runtime_checks() -> None:
    cargo = _program("cargo")
    python = sys.executable
    environment = _base_environment()
    environment["CARGO_INCREMENTAL"] = "0"
    _run("runtime-format", [cargo, "fmt", "--all", "--", "--check"], RUNTIME, environment)
    _run("runtime-tests", [cargo, "test", "--workspace", "--locked"], RUNTIME, environment)
    _run(
        "runtime-contract-tests",
        [python, "-m", "unittest", "discover", "-s", "tests", "-v"],
        RUNTIME,
        environment,
    )
    _run(
        "native-demo-build",
        [cargo, "build", "--locked", "-p", "accordlock-cli", "-p", "accordlock-agent-runtime"],
        RUNTIME,
        environment,
    )
    _run(
        "native-provider-free-proof",
        [cargo, "run", "--locked", "-q", "-p", "accordlock-cli", "--", "offline", "--compact"],
        RUNTIME,
        environment,
    )
    suffix = ".exe" if os.name == "nt" else ""
    demo_environment = environment.copy()
    demo_environment["PYTHONPATH"] = str(ROOT / "demos" / "src")
    demo_environment["ACCORDLOCK_CLI_BIN"] = str(RUNTIME / "target" / "debug" / f"accordlock{suffix}")
    demo_environment["ACCORDLOCK_RUNTIME_BIN"] = str(
        RUNTIME / "target" / "debug" / f"accordlock-agent-runtime{suffix}"
    )
    _run(
        "native-adversarial-demo-tests",
        [python, "-W", "error::ResourceWarning", "-m", "unittest", "discover", "-s", "demos/tests", "-v"],
        ROOT,
        demo_environment,
    )


def _lake_program() -> str:
    configured = os.environ.get("ACCORDLOCK_LAKE")
    if configured:
        path = Path(configured).expanduser().resolve()
        if not path.is_file():
            raise CheckFailure("ACCORDLOCK_LAKE does not name a regular file")
        return str(path)
    discovered = shutil.which("lake")
    if discovered:
        return discovered
    if os.name == "nt":
        profile = os.environ.get("USERPROFILE")
        if profile:
            toolchain = (RUNTIME / "formal" / "lean-toolchain").read_text(encoding="utf-8").strip()
            directory = toolchain.replace("/", "--").replace(":", "---")
            candidate = Path(profile) / ".elan" / "toolchains" / directory / "bin" / "lake.exe"
            if candidate.is_file():
                return str(candidate)
    raise CheckFailure("lake is unavailable; install the toolchain from runtime/formal/lean-toolchain")


def run_formal_checks(tla_jar: Path) -> None:
    environment = _base_environment()
    _run("lean-source-policy", [sys.executable, "scripts/check_lean_sources.py"], env=environment)
    _run("lean-build", [_lake_program(), "build"], RUNTIME / "formal", environment)
    jar = tla_jar.expanduser().resolve()
    if not jar.is_file():
        raise CheckFailure(
            f"TLC jar is unavailable: {jar}. Fetch it explicitly with runtime/scripts/fetch_tla2tools.py"
        )
    if os.name == "nt":
        _run(
            "tla-smoke",
            [_program("pwsh"), "-NoProfile", "-File", "scripts/run-tla-smoke.ps1", "-Jar", str(jar)],
            RUNTIME,
            environment,
        )
    else:
        _run("tla-smoke", [_program("sh"), "scripts/run-tla-smoke.sh", str(jar)], RUNTIME, environment)


def run_desktop_checks() -> None:
    cargo = _program("cargo")
    pnpm = _program("pnpm")
    environment = _base_environment()
    environment["CARGO_INCREMENTAL"] = "0"
    environment["CARGO_BUILD_JOBS"] = "2"
    _run(
        "desktop-publication",
        [sys.executable, "scripts/check_accordlock_publication.py"],
        DESKTOP,
        environment,
    )
    _run("desktop-format", [cargo, "fmt", "--all", "--", "--check"], DESKTOP, environment)
    _run(
        "desktop-backend-tests",
        [cargo, "test", "--locked", "-p", "goose", "--features", "accordlock-distribution", "--lib", "accordlock_"],
        DESKTOP,
        environment,
    )
    _run(
        "desktop-backend-build",
        [
            cargo,
            "build",
            "--locked",
            "--release",
            "-p",
            "goose-cli",
            "--bin",
            "goose",
            "--no-default-features",
            "--features",
            "accordlock-distribution,rustls-tls,system-keyring",
        ],
        DESKTOP,
        environment,
    )
    _run("desktop-dependencies", [pnpm, "install", "--frozen-lockfile"], DESKTOP / "ui", environment)
    _run("desktop-interface-checks", [pnpm, "run", "lint:check"], DESKTOP / "ui" / "desktop", environment)
    _run("desktop-unit-tests", [pnpm, "run", "test:run"], DESKTOP / "ui" / "desktop", environment)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the fast public source gates, with explicit opt-in for heavier layers."
    )
    parser.add_argument("--runtime", action="store_true", help="also run the native runtime suite")
    parser.add_argument("--formal", action="store_true", help="also build Lean and run the TLC smoke suite")
    parser.add_argument("--desktop", action="store_true", help="also run the desktop source suite")
    parser.add_argument("--all", action="store_true", help="run source, runtime, formal, and desktop layers")
    parser.add_argument(
        "--tla-jar",
        type=Path,
        default=RUNTIME / ".local" / "tools" / "tla2tools.jar",
        help="path to the checksum-pinned TLC jar used by --formal",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        run_source_checks()
        if arguments.runtime or arguments.all:
            run_runtime_checks()
        if arguments.formal or arguments.all:
            run_formal_checks(arguments.tla_jar)
        if arguments.desktop or arguments.all:
            run_desktop_checks()
    except (CheckFailure, OSError, subprocess.SubprocessError) as error:
        print(f"FAIL test_all: {error}", file=sys.stderr)
        return 1
    selected = ["source"]
    selected.extend(
        name
        for enabled, name in (
            (arguments.runtime or arguments.all, "runtime"),
            (arguments.formal or arguments.all, "formal"),
            (arguments.desktop or arguments.all, "desktop"),
        )
        if enabled
    )
    print(f"PASS test_all layers={','.join(selected)}")
    print("BOUNDARY PostgreSQL, live providers, signed packaging, clean-machine acceptance, and independent review run separately")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
