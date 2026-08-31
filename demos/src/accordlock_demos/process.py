from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any


class ProductEntrypointError(RuntimeError):
    pass


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def run_json_command(command: list[str], timeout_seconds: float = 30.0) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
        check=False,
        env=_minimal_child_environment(),
    )
    if completed.returncode != 0:
        error = completed.stderr[:4096].decode("utf-8", errors="replace").strip()
        raise ProductEntrypointError(
            f"product entrypoint exited {completed.returncode}: {error or 'no diagnostic'}"
        )
    try:
        value = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProductEntrypointError("product entrypoint did not emit one JSON document") from error
    if not isinstance(value, dict):
        raise ProductEntrypointError("product entrypoint JSON root must be an object")
    return value


def run_offline_scenarios(cli_binary: Path, scenario: str = "all") -> dict[str, Any]:
    return run_json_command(
        [str(cli_binary), "offline", "--scenario", scenario, "--compact"],
        timeout_seconds=60.0,
    )


def binary_version(cli_binary: Path) -> str:
    completed = subprocess.run(
        [str(cli_binary), "--version"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5.0,
        check=False,
        env=_minimal_child_environment(),
    )
    if completed.returncode != 0:
        return "UNAVAILABLE"
    value = completed.stdout.decode("utf-8", errors="replace").strip()
    return value if value and len(value) <= 256 else "UNAVAILABLE"


def _minimal_child_environment() -> dict[str, str]:
    allowed = {
        "SystemRoot",
        "WINDIR",
        "TEMP",
        "TMP",
        "TMPDIR",
        "PATH",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
    }
    allowed_casefolded = {key.upper() for key in allowed}
    return {
        key: value
        for key, value in os.environ.items()
        if key.upper() in allowed_casefolded
    }
