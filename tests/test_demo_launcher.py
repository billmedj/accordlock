from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import run_demo


def _proof(*, production_ready: bool = False) -> str:
    return json.dumps(
        {
            "schema_version": 2,
            "report_kind": "OFFLINE_DETERMINISTIC_SECURITY_DEMO",
            "production_ready": production_ready,
            "execution_profile": {
                "mode": "OFFLINE_DETERMINISTIC_NO_NETWORK",
                "network_access": "NOT_ACCESSED",
                "external_mutation": "NONE",
            },
        }
    )


def _report(*, status: str = "PASS") -> dict[str, object]:
    return {
        "status": status,
        "cases": [
            {"case_id": "protected-effect", "status": "PASS"},
            {"case_id": "replay", "status": "PASS"},
        ],
        "execution_profile": {
            "model_provider": "NONE",
            "external_accounts": "NONE",
            "internet_transport": "NOT_ATTEMPTED",
            "external_mutation": "NONE",
        },
    }


class DemoLauncherTests(unittest.TestCase):
    def test_configured_cargo_keeps_the_tool_proxy_name(self) -> None:
        with tempfile.TemporaryDirectory(prefix="accordlock-launcher-test-") as temporary:
            root = Path(temporary)
            rustup = root / "rustup"
            cargo = root / "cargo"
            rustup.touch()
            try:
                cargo.symlink_to(rustup)
            except OSError:
                self.skipTest("this filesystem cannot create a test tool-proxy symlink")
            located = run_demo._locate_cargo({"ACCORDLOCK_CARGO": str(cargo)})
            self.assertEqual(Path(located), cargo.absolute())
            self.assertNotEqual(Path(located), rustup.absolute())

    def test_run_builds_only_locked_native_packages_and_uses_exact_artifacts(self) -> None:
        with tempfile.TemporaryDirectory(prefix="accordlock-launcher-test-") as temporary:
            root = Path(temporary)
            cli = root / ("accordlock.exe" if os.name == "nt" else "accordlock")
            runtime = root / (
                "accordlock-agent-runtime.exe" if os.name == "nt" else "accordlock-agent-runtime"
            )
            cli.write_bytes(b"cli")
            runtime.write_bytes(b"runtime")
            build_stdout = "\n".join(
                [
                    json.dumps(
                        {
                            "reason": "compiler-artifact",
                            "target": {"name": "accordlock", "kind": ["bin"]},
                            "executable": str(cli),
                        }
                    ),
                    json.dumps(
                        {
                            "reason": "compiler-artifact",
                            "target": {
                                "name": "accordlock-agent-runtime",
                                "kind": ["bin"],
                            },
                            "executable": str(runtime),
                        }
                    ),
                ]
            )
            output = root / "requested-reports"
            calls: list[tuple[str, list[str], dict[str, str]]] = []

            def fake_run(
                label: str,
                command: list[str],
                *,
                cwd: Path,
                environment: dict[str, str],
                timeout_seconds: float,
            ) -> subprocess.CompletedProcess[str]:
                del cwd, timeout_seconds
                calls.append((label, command, environment))
                if label == "native-build":
                    return subprocess.CompletedProcess(command, 0, build_stdout, "")
                if label == "native-offline-proof":
                    return subprocess.CompletedProcess(command, 0, _proof(), "")
                report_directory = Path(command[command.index("--output-directory") + 1])
                report_directory.mkdir(parents=True)
                (report_directory / "adversarial-demo.json").write_text(
                    json.dumps(_report()), encoding="utf-8"
                )
                (report_directory / "adversarial-demo.md").write_text(
                    "# PASS\n", encoding="utf-8"
                )
                return subprocess.CompletedProcess(command, 0, "", "")

            arguments = argparse.Namespace(
                offline=True,
                output_directory=output,
                display=None,
            )
            with (
                mock.patch.object(run_demo, "_locate_cargo", return_value="cargo-test"),
                mock.patch.object(
                    run_demo,
                    "_windows_msvc_environment",
                    side_effect=lambda _source, environment: environment,
                ),
                mock.patch.object(run_demo, "_run_command", side_effect=fake_run),
                mock.patch.dict(
                    os.environ,
                    {
                        "PATH": os.environ.get("PATH", ""),
                        "OPENAI_API_KEY": "must-not-reach-a-child",
                    },
                    clear=True,
                ),
                redirect_stdout(io.StringIO()),
            ):
                report = run_demo.run(arguments)

            self.assertEqual(report["status"], "PASS")
            self.assertEqual([label for label, _, _ in calls], [
                "native-build",
                "native-offline-proof",
                "native-adversarial-demo",
            ])
            build = calls[0][1]
            self.assertEqual(
                build,
                [
                    "cargo-test",
                    "build",
                    "--locked",
                    "--offline",
                    "--message-format=json-render-diagnostics",
                    "-p",
                    "accordlock-cli",
                    "-p",
                    "accordlock-agent-runtime",
                ],
            )
            self.assertEqual(calls[1][1], [str(cli.resolve()), "offline", "--compact"])
            self.assertEqual(
                calls[2][1][calls[2][1].index("--cli-binary") + 1],
                str(cli.resolve()),
            )
            self.assertEqual(
                calls[2][1][calls[2][1].index("--runtime-binary") + 1],
                str(runtime.resolve()),
            )
            for _, _, environment in calls:
                self.assertNotIn("OPENAI_API_KEY", environment)
            self.assertEqual(calls[2][2]["PYTHONPATH"], str(run_demo.DEMO_SOURCE))
            self.assertTrue((output / "adversarial-demo.json").is_file())
            self.assertTrue((output / "adversarial-demo.md").is_file())

    def test_default_reports_are_removed_with_the_temporary_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="accordlock-launcher-test-") as temporary:
            root = Path(temporary)
            cli = root / "accordlock"
            runtime = root / "accordlock-agent-runtime"
            cli.touch()
            runtime.touch()
            build_output = "\n".join(
                json.dumps(
                    {
                        "reason": "compiler-artifact",
                        "target": {"name": name, "kind": ["bin"]},
                        "executable": str(path),
                    }
                )
                for name, path in (
                    ("accordlock", cli),
                    ("accordlock-agent-runtime", runtime),
                )
            )
            observed_report_directory: Path | None = None

            def fake_run(
                label: str,
                command: list[str],
                **_: object,
            ) -> subprocess.CompletedProcess[str]:
                nonlocal observed_report_directory
                if label == "native-build":
                    return subprocess.CompletedProcess(command, 0, build_output, "")
                if label == "native-offline-proof":
                    return subprocess.CompletedProcess(command, 0, _proof(), "")
                observed_report_directory = Path(
                    command[command.index("--output-directory") + 1]
                )
                observed_report_directory.mkdir(parents=True)
                (observed_report_directory / "adversarial-demo.json").write_text(
                    json.dumps(_report()), encoding="utf-8"
                )
                (observed_report_directory / "adversarial-demo.md").write_text(
                    "# PASS\n", encoding="utf-8"
                )
                return subprocess.CompletedProcess(command, 0, "", "")

            arguments = argparse.Namespace(offline=False, output_directory=None, display=None)
            with (
                mock.patch.object(run_demo, "_locate_cargo", return_value="cargo-test"),
                mock.patch.object(
                    run_demo,
                    "_windows_msvc_environment",
                    side_effect=lambda _source, environment: environment,
                ),
                mock.patch.object(run_demo, "_run_command", side_effect=fake_run),
                redirect_stdout(io.StringIO()),
            ):
                run_demo.run(arguments)

            self.assertIsNotNone(observed_report_directory)
            self.assertFalse(observed_report_directory.exists())

    def test_command_runner_never_uses_a_shell(self) -> None:
        completed = subprocess.CompletedProcess(["tool"], 0, "ok", "")
        with (
            mock.patch("scripts.run_demo.subprocess.run", return_value=completed) as invoked,
            redirect_stdout(io.StringIO()),
        ):
            result = run_demo._run_command(
                "test",
                ["tool", "literal argument"],
                cwd=run_demo.ROOT,
                environment={"PATH": "test"},
                timeout_seconds=1.0,
            )
        self.assertIs(result, completed)
        self.assertIs(invoked.call_args.kwargs["shell"], False)
        self.assertEqual(invoked.call_args.args[0], ["tool", "literal argument"])

    def test_failure_diagnostic_prioritizes_stderr_over_cargo_json(self) -> None:
        completed = subprocess.CompletedProcess(
            ["cargo"],
            1,
            '{"reason":"compiler-artifact","large":"' + ("x" * 5000) + '"}',
            "the actionable compiler failure",
        )
        self.assertEqual(
            run_demo._diagnostic(completed),
            "the actionable compiler failure",
        )

    def test_offline_proof_must_keep_production_and_network_claims_false(self) -> None:
        with self.assertRaisesRegex(run_demo.DemoFailure, "safety boundary"):
            run_demo._verify_offline_proof(_proof(production_ready=True))

        changed = json.loads(_proof())
        changed["execution_profile"]["network_access"] = "ACCESSED"
        with self.assertRaisesRegex(run_demo.DemoFailure, "safety boundary"):
            run_demo._verify_offline_proof(json.dumps(changed))

    def test_demo_report_must_pass_every_case_without_external_authority(self) -> None:
        with tempfile.TemporaryDirectory(prefix="accordlock-launcher-test-") as temporary:
            directory = Path(temporary)
            report = _report()
            report["execution_profile"]["model_provider"] = "CONNECTED"
            (directory / "adversarial-demo.json").write_text(
                json.dumps(report), encoding="utf-8"
            )
            (directory / "adversarial-demo.md").write_text("# FAIL\n", encoding="utf-8")
            with self.assertRaisesRegex(run_demo.DemoFailure, "provider-free contract"):
                run_demo._verify_demo_report(directory)

    def test_existing_report_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory(prefix="accordlock-launcher-test-") as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            source.mkdir()
            destination.mkdir()
            for name in run_demo.REPORT_NAMES:
                (source / name).write_text("new", encoding="utf-8")
            existing = destination / "adversarial-demo.json"
            existing.write_text("keep", encoding="utf-8")
            with self.assertRaisesRegex(run_demo.DemoFailure, "refusing to replace"):
                run_demo._copy_reports(source, destination)
            self.assertEqual(existing.read_text(encoding="utf-8"), "keep")
            self.assertFalse((destination / "adversarial-demo.md").exists())

    def test_main_fails_closed_with_one_diagnostic(self) -> None:
        stderr = io.StringIO()
        with (
            mock.patch.object(
                run_demo,
                "_locate_cargo",
                side_effect=run_demo.DemoFailure("Cargo is unavailable"),
            ),
            redirect_stderr(stderr),
        ):
            result = run_demo.main([])
        self.assertEqual(result, 1)
        self.assertEqual(
            stderr.getvalue().strip(),
            "FAIL provider_free_demo: Cargo is unavailable",
        )

    def test_concise_json_and_markdown_are_opt_in(self) -> None:
        json_output = io.StringIO()
        with redirect_stdout(json_output):
            run_demo._display_result(_report(), "json")
        parsed = json.loads(json_output.getvalue())
        self.assertEqual(parsed["result"], "PASS")
        self.assertEqual(parsed["execution"]["model_provider"], "NONE")

        markdown_output = io.StringIO()
        with redirect_stdout(markdown_output):
            run_demo._display_result(_report(), "markdown")
        self.assertIn("**Result:** PASS", markdown_output.getvalue())
        self.assertIn("No model provider", markdown_output.getvalue())


if __name__ == "__main__":
    unittest.main()
