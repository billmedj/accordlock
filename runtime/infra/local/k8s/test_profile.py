#!/usr/bin/env python3
"""Static lock-alignment tests for the account-free Kubernetes exhibit."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
SHA256 = r"[0-9a-f]{64}"


def _read(name: str) -> str:
    return (HERE / name).read_text(encoding="utf-8")


def _powershell_assignment(source: str, name: str) -> str:
    match = re.search(rf"^\${re.escape(name)}\s*=\s*'([^']+)'\s*$", source, re.MULTILINE)
    if match is None:
        raise AssertionError(f"missing unambiguous PowerShell assignment: ${name}")
    return match.group(1)


class LocalProfileTests(unittest.TestCase):
    def test_kind_binary_pin_is_consistent(self) -> None:
        installer = _read("install-kind.ps1")
        runner = _read("run-live.ps1")
        readme = _read("README.md")

        installed_version = _powershell_assignment(installer, "Version")
        required_version = _powershell_assignment(runner, "KindVersion")
        checksum = _powershell_assignment(installer, "ExpectedSha256")

        self.assertEqual(installed_version, "v0.32.0")
        self.assertEqual(required_version, installed_version)
        self.assertRegex(checksum, rf"^{SHA256}$")
        self.assertIn(f"kind {installed_version}", readme)
        self.assertIn(checksum, readme)
        self.assertIn(
            'https://github.com/kubernetes-sigs/kind/releases/download/$Version/kind-windows-amd64',
            installer,
        )

    def test_image_commitments_are_consistent(self) -> None:
        runner = _read("run-live.ps1")
        locks = _read("IMAGE_LOCKS.txt")
        deployment = _read("deployment.yaml")

        node_image = _powershell_assignment(runner, "NodeImage")
        new_image = _powershell_assignment(runner, "NewImage")
        prior_image = _powershell_assignment(runner, "PriorImage")

        self.assertRegex(node_image, rf"^kindest/node:v1\.35\.0@sha256:{SHA256}$")
        self.assertRegex(new_image, rf"^docker\.io/library/nginx@sha256:{SHA256}$")
        self.assertRegex(prior_image, rf"^docker\.io/library/nginx@sha256:{SHA256}$")
        self.assertNotEqual(new_image, prior_image)
        self.assertIn(node_image, locks)
        self.assertIn(new_image.split("@", 1)[1], locks)
        self.assertIn(prior_image.split("@", 1)[1], locks)
        self.assertIn(f"image: {prior_image}", deployment)

    def test_fixed_profile_scope_is_aligned(self) -> None:
        runner = _read("run-live.ps1")
        namespace = _read("namespace.yaml")
        deployment = _read("deployment.yaml")
        kind_config = _read("kind-config.yaml")

        profile = _powershell_assignment(runner, "ProfileLabel")
        namespace_name = _powershell_assignment(runner, "Namespace")
        deployment_name = _powershell_assignment(runner, "Deployment")
        cluster_name = _powershell_assignment(runner, "ClusterName")

        self.assertIn(f"name: {namespace_name}", namespace)
        self.assertIn(f"accordlock.io/profile: {profile}", namespace)
        self.assertIn(f"namespace: {namespace_name}", deployment)
        self.assertIn(f"name: {deployment_name}", deployment)
        self.assertGreaterEqual(deployment.count(f"accordlock.io/profile: {profile}"), 2)
        self.assertIn("automountServiceAccountToken: false", deployment)
        self.assertIn(f"name: {cluster_name}", kind_config)
        self.assertEqual(kind_config.count("role: control-plane"), 1)

    def test_timeout_scaling_stays_bounded_and_auditable(self) -> None:
        runner = _read("run-live.ps1")
        readme = _read("README.md")

        self.assertIn("[ValidateRange(1, 6)]", runner)
        self.assertIn("[int]$TimeoutScale = 1", runner)
        self.assertIn(
            "$EffectiveTimeoutSeconds = [Math]::Min(1800, $TimeoutSeconds * $TimeoutScale)",
            runner,
        )
        self.assertGreaterEqual(runner.count("timeout_scale = $TimeoutScale"), 3)
        self.assertIn("-TimeoutScale 2", readme)
        self.assertIn("-TimeoutScale 6", readme)


if __name__ == "__main__":
    unittest.main()
