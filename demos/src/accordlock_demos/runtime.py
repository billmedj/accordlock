from __future__ import annotations

import json
import os
import queue
import secrets
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Callable

from .canonical import (
    canonical_json_bytes,
    json_digest,
    length_prefixed_domain_digest,
    sha256_digest,
)
from .process import ProductEntrypointError, _minimal_child_environment

CONTROL_MAGIC = b"ALC1"
CONTROL_MAX_BYTES = 256 * 1024
TASK_POLICY_DOMAIN = b"accordlock:v2:task-policy"
FILESYSTEM_PATH = "/api/v2/execution/filesystem/authorize-and-execute"
NETWORK_PATH = "/api/v2/execution/network/authorize-and-execute"
MAX_HTTP_RESPONSE_BYTES = 1024 * 1024


def canonical_workspace(path: Path) -> str:
    resolved = str(path.resolve(strict=True))
    if os.name == "nt" and not resolved.startswith("\\\\?\\"):
        if resolved.startswith("\\\\"):
            return "\\\\?\\UNC\\" + resolved[2:]
        return "\\\\?\\" + resolved
    return resolved


def build_task_policy(objective: str) -> dict[str, Any]:
    policy = {
        "schema_version": 2,
        "task_objective_hash": sha256_digest(objective.encode("utf-8")),
        "preauthorized_capabilities": [
            {"extension_id": "developer", "tool_name": "read"},
        ],
        "protected_paths": [".env", ".git", ".ssh", "credentials"],
    }
    return policy


def build_approved_session(workspace_root: str, now: int) -> dict[str, Any]:
    objective = "Inspect the approved workspace and create one explicitly approved demo file."
    policy = build_task_policy(objective)
    return {
        "schema_version": 3,
        "task_id": str(uuid.uuid4()),
        "session_id": f"demo-session-{uuid.uuid4()}",
        "run_id": sha256_digest(secrets.token_bytes(32)),
        "workspace_root": workspace_root,
        "policy_epoch": 1,
        "task_policy": policy,
        "task_policy_hash": length_prefixed_domain_digest(TASK_POLICY_DOMAIN, policy),
        "task_objective": objective,
        "capabilities": [
            {"extension_id": "accordlock_network", "tool_name": "https_request"},
            {"extension_id": "developer", "tool_name": "read"},
            {"extension_id": "developer", "tool_name": "write"},
        ],
        "approved_at": now - 1,
        "expires_at": now + 600,
    }


def build_proposal(
    session: dict[str, Any],
    *,
    extension_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    checkpoint_text: str,
    tool_call_id: str | None = None,
    recorded_at: int | None = None,
) -> dict[str, Any]:
    call_id = tool_call_id or str(uuid.uuid4())
    arguments_sha256 = json_digest(arguments)
    material = {
        "text": [checkpoint_text],
        "tool_requests": [
            {
                "id": call_id,
                "name": f"{extension_id}__{tool_name}",
                "arguments_sha256": arguments_sha256,
            }
        ],
    }
    checkpoint = {
        "schema_version": 1,
        "session_id": session["session_id"],
        "run_id": session["run_id"],
        "tool_call_id": call_id,
        "material": material,
        "material_sha256": json_digest(material),
        "recorded_at": recorded_at or int(time.time()),
    }
    return {
        "schema_version": 3,
        "session_id": session["session_id"],
        "run_id": session["run_id"],
        "tool_call_id": call_id,
        "workspace_root": session["workspace_root"],
        "extension_id": extension_id,
        "tool_name": tool_name,
        "arguments": arguments,
        "arguments_sha256": arguments_sha256,
        "agent_plan_checkpoint": checkpoint,
    }


def build_action_approval(
    approval_request: dict[str, Any], approval_request_hash: str, now: int
) -> dict[str, Any]:
    copied = {
        key: approval_request[key]
        for key in (
            "task_id",
            "session_id",
            "run_id",
            "tool_call_id",
            "proposal_digest",
            "task_policy_hash",
            "prestate_hash",
            "task_requirement",
            "transformation_step",
            "policy_decision",
            "policy_decision_hash",
        )
    }
    return {
        "schema_version": 2,
        "approval_id": str(uuid.uuid4()),
        **copied,
        "approval_request_hash": approval_request_hash,
        "decision": "APPROVED",
        "approval_evidence_hash": sha256_digest(
            b"provider-free demo: exact action reviewed once"
        ),
        "decided_at": now,
        "expires_at": now + 120,
    }


@dataclass
class RuntimeHarness:
    binary: Path
    data_directory: Path
    process: subprocess.Popen[bytes]
    runtime_url: str
    token: str

    @classmethod
    def start(
        cls,
        binary: Path,
        data_directory: Path,
        *,
        https_domains: tuple[str, ...] = ("allowed.example",),
    ) -> "RuntimeHarness":
        binary = binary.resolve(strict=True)
        data_directory.mkdir(parents=True, exist_ok=False)
        token = secrets.token_urlsafe(48)
        environment = _minimal_child_environment()
        environment["ACCORDLOCK_RUNTIME_TOKEN"] = token
        environment["ACCORDLOCK_RUNTIME_DATA_DIR"] = str(data_directory.resolve())
        command = [
            str(binary),
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--ready-line",
            "--control-stdio",
        ]
        for domain in https_domains:
            command.extend(["--https-domain", domain])
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=environment,
            creationflags=creation_flags,
        )
        if process.stdin is None or process.stdout is None or process.stderr is None:
            process.kill()
            raise ProductEntrypointError("runtime did not expose inherited control pipes")
        try:
            ready_line = _read_with_timeout(process.stdout.readline, 10.0)
            prefix = b"ACCORDLOCK_RUNTIME_READY="
            if not ready_line.startswith(prefix):
                raise ProductEntrypointError("runtime did not emit its authenticated ready record")
            ready = json.loads(ready_line[len(prefix) :].decode("utf-8"))
            if (
                not isinstance(ready, dict)
                or ready.get("schema_version") != 2
                or not isinstance(ready.get("url"), str)
                or not ready["url"].startswith("http://127.0.0.1:")
            ):
                raise ProductEntrypointError("runtime ready record is outside the v2 loopback profile")
            harness = cls(binary, data_directory, process, ready["url"], token)
            harness.health()
            return harness
        except Exception as error:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=5.0)
            diagnostic = process.stderr.read(4096).decode("utf-8", errors="replace").strip()
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()
            if diagnostic:
                raise ProductEntrypointError(
                    f"runtime startup failed: {diagnostic}"
                ) from error
            raise

    def health(self) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{self.runtime_url}/api/v2/health",
            method="GET",
            headers={"Authorization": f"Bearer {self.token}", "Cache-Control": "no-store"},
        )
        return self._open_json(request)

    def control(self, method: str, field: str, value: dict[str, Any]) -> dict[str, Any]:
        if self.process.stdin is None or self.process.stdout is None:
            raise ProductEntrypointError("runtime control channel is closed")
        request_id = str(uuid.uuid4())
        payload = canonical_json_bytes(
            {
                "schema_version": 2,
                "request_id": request_id,
                "method": method,
                field: value,
            }
        )
        if len(payload) > CONTROL_MAX_BYTES:
            raise ProductEntrypointError("control request exceeds the runtime limit")
        self.process.stdin.write(CONTROL_MAGIC + len(payload).to_bytes(4, "big") + payload)
        self.process.stdin.flush()
        header = _read_exact_with_timeout(self.process.stdout, 8, 10.0)
        if header[:4] != CONTROL_MAGIC:
            raise ProductEntrypointError("runtime control response has an invalid frame header")
        size = int.from_bytes(header[4:], "big")
        if size <= 0 or size > CONTROL_MAX_BYTES:
            raise ProductEntrypointError("runtime control response exceeds the bounded profile")
        response = json.loads(_read_exact_with_timeout(self.process.stdout, size, 10.0))
        if not isinstance(response, dict) or response.get("request_id") != request_id:
            raise ProductEntrypointError("runtime control response is not bound to the request")
        return response

    def approve_session(self, session: dict[str, Any]) -> dict[str, Any]:
        return self.control("APPROVE_SESSION", "approved_session", session)

    def register_action_approval(self, approval: dict[str, Any]) -> dict[str, Any]:
        return self.control("REGISTER_ACTION_APPROVAL", "action_approval", approval)

    def execute_filesystem(self, proposal: dict[str, Any]) -> dict[str, Any]:
        return self.post(FILESYSTEM_PATH, {"schema_version": 3, "proposal": proposal})

    def execute_network(self, proposal: dict[str, Any]) -> dict[str, Any]:
        return self.post(NETWORK_PATH, {"schema_version": 3, "proposal": proposal})

    def post(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{self.runtime_url}{path}",
            data=canonical_json_bytes(body),
            method="POST",
            headers={
                "Authorization": f"Bearer {self.token}",
                "Cache-Control": "no-store",
                "Content-Type": "application/json",
            },
        )
        return self._open_json(request)

    def _open_json(self, request: urllib.request.Request) -> dict[str, Any]:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=10.0) as response:
                declared = response.headers.get("Content-Length")
                if declared is not None and int(declared) > MAX_HTTP_RESPONSE_BYTES:
                    raise ProductEntrypointError("runtime HTTP response exceeds the bound")
                body = response.read(MAX_HTTP_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            detail = error.read(4096).decode("utf-8", errors="replace")
            raise ProductEntrypointError(
                f"runtime HTTP route returned {error.code}: {detail or 'no diagnostic'}"
            ) from error
        except urllib.error.URLError as error:
            raise ProductEntrypointError("runtime loopback transport is unavailable") from error
        if len(body) > MAX_HTTP_RESPONSE_BYTES:
            raise ProductEntrypointError("runtime HTTP response exceeds the bound")
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProductEntrypointError("runtime HTTP response is not JSON") from error
        if not isinstance(value, dict):
            raise ProductEntrypointError("runtime HTTP response root must be an object")
        return value

    def close(self) -> None:
        if self.process.stdin is not None and not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5.0)
        diagnostic = b""
        if self.process.returncode not in (0, None) and self.process.stderr is not None:
            diagnostic = self.process.stderr.read(4096)
        if self.process.stdout is not None:
            self.process.stdout.close()
        if self.process.stderr is not None:
            self.process.stderr.close()
        if self.process.returncode not in (0, None):
            raise ProductEntrypointError(
                "runtime stopped unexpectedly: "
                + diagnostic.decode("utf-8", errors="replace").strip()
            )

    def __enter__(self) -> "RuntimeHarness":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        try:
            self.close()
        except ProductEntrypointError:
            if exc is None:
                raise


def _read_with_timeout(reader: Callable[[], bytes], timeout_seconds: float) -> bytes:
    results: queue.Queue[bytes | BaseException] = queue.Queue(maxsize=1)

    def run() -> None:
        try:
            results.put(reader())
        except BaseException as error:
            results.put(error)

    threading.Thread(target=run, daemon=True).start()
    try:
        result = results.get(timeout=timeout_seconds)
    except queue.Empty as error:
        raise ProductEntrypointError("runtime pipe response timed out") from error
    if isinstance(result, BaseException):
        raise ProductEntrypointError("runtime pipe read failed") from result
    if not result:
        raise ProductEntrypointError("runtime pipe closed before a complete response")
    return result


def _read_exact_with_timeout(stream: BinaryIO, size: int, timeout_seconds: float) -> bytes:
    def read() -> bytes:
        body = bytearray()
        while len(body) < size:
            chunk = stream.read(size - len(body))
            if not chunk:
                break
            body.extend(chunk)
        return bytes(body)

    value = _read_with_timeout(read, timeout_seconds)
    if len(value) != size:
        raise ProductEntrypointError("runtime pipe returned a truncated frame")
    return value
