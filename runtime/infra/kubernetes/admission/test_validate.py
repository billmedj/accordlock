#!/usr/bin/env python3
"""Static regression tests for the fail-closed admission preflight."""

from __future__ import annotations

import base64
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import validate


HERE = Path(__file__).resolve().parent
TEST_CA = base64.b64encode(
    b"-----BEGIN CERTIFICATE-----\n"
    b"MIIBHjCB0aADAgECAhQytqIVxb4Q7nvh0fsYVeqTpPDqZTAFBgMrZXAwHjEcMBoG\n"
    b"A1UEAwwTc2lnbmV0LXdlYmhvb2sudGVzdDAeFw0yNjA4MTYwMzEzNThaFw0yNjA4\n"
    b"MTcwMzEzNThaMB4xHDAaBgNVBAMME3NpZ25ldC13ZWJob29rLnRlc3QwKjAFBgMr\n"
    b"ZXADIQCrIFGa7zB0LEJmoTOql2C5uuPsGuJj+4xNNkcqmxFLAKMhMB8wHQYDVR0O\n"
    b"BBYEFGp9MSXOP6MafSNCADCx3tDoSybzMAUGAytlcANBAKqvbXhynR+BfL8gbOSC\n"
    b"60j5gSgri1gQIHcHzieG5gPcJRjCcx/obfAY1ErL65GKjX5TJxCvurXgGT1D6aHm\n"
    b"4Qk=\n"
    b"-----END CERTIFICATE-----\n"
).decode("ascii")


class CandidateValidationTests(unittest.TestCase):
    def copy_candidate(self) -> Path:
        temporary = Path(tempfile.mkdtemp(prefix="accordlock-admission-static-"))
        self.addCleanup(shutil.rmtree, temporary, True)
        candidate = temporary / "admission"
        shutil.copytree(HERE, candidate, ignore=shutil.ignore_patterns("__pycache__"))
        return candidate

    @staticmethod
    def load(path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def save(path: Path, value: dict) -> None:
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    def materialize_reviewable_candidate(self, candidate: Path) -> None:
        deployment_path = candidate / "deployment.json"
        deployment = self.load(deployment_path)
        deployment["spec"]["template"]["spec"]["containers"][0]["image"] = (
            "registry.example.com/security/accordlock-webhook@sha256:" + "1" * 64
        )
        self.save(deployment_path, deployment)

        webhook_path = candidate / "validating-webhook-configuration.json"
        webhook = self.load(webhook_path)
        webhook["webhooks"][0]["clientConfig"]["caBundle"] = TEST_CA
        self.save(webhook_path, webhook)

        config_path = candidate / "config-map.json"
        config = self.load(config_path)
        replacements = {
            "ACCORDLOCK_WEBHOOK_OBSERVER_IDENTITY": "urn:accordlock:observer:eks-prod-a",
            "ACCORDLOCK_WEBHOOK_TENANT": "example-tenant",
            "ACCORDLOCK_WEBHOOK_CLUSTER_TRUST_DOMAIN": "spiffe://example.com/eks/prod-a",
            "ACCORDLOCK_WEBHOOK_API_SERVER_IDENTITY": "sha256:" + "a" * 64,
            "ACCORDLOCK_WEBHOOK_CLUSTER_IDENTITY": "arn:aws:eks:eu-west-1:111122223333:cluster/prod-a",
            "ACCORDLOCK_WEBHOOK_EXECUTOR_USERNAME": "system:serviceaccount:accordlock-executor:executor",
            "ACCORDLOCK_WEBHOOK_EXECUTOR_GROUPS_JSON": (
                "[\"system:authenticated\",\"system:serviceaccounts\","
                "\"system:serviceaccounts:accordlock-executor\"]"
            ),
            "ACCORDLOCK_STATE_POSTGRES_SERVER_NAME": "db.internal.example.com",
        }
        config["data"].update(replacements)
        self.save(config_path, config)

        deployment = self.load(deployment_path)
        deployment["spec"]["template"]["metadata"]["annotations"] = {
            "accordlock.io/config-revision": "config-r1",
            "accordlock.io/server-tls-revision": "server-tls-r1",
            "accordlock.io/postgres-auth-revision": "postgres-auth-r1",
            "accordlock.io/postgres-ca-revision": "postgres-ca-r1",
        }
        self.save(deployment_path, deployment)

    def test_repository_candidate_is_intentionally_refused(self) -> None:
        errors = validate.validate(HERE)
        joined = "\n".join(errors)
        self.assertIn("example.invalid", joined)
        self.assertIn("caBundle", joined)
        self.assertIn("unresolved configuration placeholder", joined)

    def test_materialized_nonsecret_candidate_passes(self) -> None:
        candidate = self.copy_candidate()
        self.materialize_reviewable_candidate(candidate)
        self.assertEqual(validate.validate(candidate), [])

    def test_mutable_tag_is_refused(self) -> None:
        candidate = self.copy_candidate()
        self.materialize_reviewable_candidate(candidate)
        path = candidate / "deployment.json"
        deployment = self.load(path)
        deployment["spec"]["template"]["spec"]["containers"][0]["image"] = (
            "registry.example.com/security/accordlock-webhook:latest"
        )
        self.save(path, deployment)
        self.assertTrue(any("digest-only" in error for error in validate.validate(candidate)))

    def test_tag_plus_digest_is_refused(self) -> None:
        candidate = self.copy_candidate()
        self.materialize_reviewable_candidate(candidate)
        path = candidate / "deployment.json"
        deployment = self.load(path)
        deployment["spec"]["template"]["spec"]["containers"][0]["image"] = (
            "registry.example.com/security/accordlock-webhook:v1@sha256:" + "2" * 64
        )
        self.save(path, deployment)
        errors = validate.validate(candidate)
        self.assertTrue(any("digest-only" in error or "mutable image tags" in error for error in errors))

    def test_all_zero_digest_is_refused(self) -> None:
        candidate = self.copy_candidate()
        self.materialize_reviewable_candidate(candidate)
        path = candidate / "deployment.json"
        deployment = self.load(path)
        deployment["spec"]["template"]["spec"]["containers"][0]["image"] = (
            "registry.example.com/security/accordlock-webhook@sha256:" + "0" * 64
        )
        self.save(path, deployment)
        self.assertIn(
            "the all-zero image digest sentinel is forbidden",
            validate.validate(candidate),
        )

    def test_garbage_pem_ca_bundle_is_refused(self) -> None:
        candidate = self.copy_candidate()
        self.materialize_reviewable_candidate(candidate)
        path = candidate / "validating-webhook-configuration.json"
        webhook = self.load(path)
        webhook["webhooks"][0]["clientConfig"]["caBundle"] = base64.b64encode(
            b"-----BEGIN CERTIFICATE-----\nZmFrZS10ZXN0LWNh\n-----END CERTIFICATE-----\n"
        ).decode("ascii")
        self.save(path, webhook)
        self.assertTrue(any("caBundle" in error for error in validate.validate(candidate)))

    def test_literal_secret_resource_is_refused(self) -> None:
        candidate = self.copy_candidate()
        self.materialize_reviewable_candidate(candidate)
        secret_path = candidate / "literal-secret.json"
        self.save(
            secret_path,
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": "forbidden", "namespace": "accordlock-system"},
                "stringData": {"password": "plaintext"},
            },
        )
        with (candidate / "kustomization.yaml").open("a", encoding="utf-8") as handle:
            handle.write("  - literal-secret.json\n")
        joined = "\n".join(validate.validate(candidate))
        self.assertIn("resource set differs", joined)
        self.assertIn("Secret resources are forbidden", joined)

    def test_selector_scope_drift_is_refused(self) -> None:
        candidate = self.copy_candidate()
        self.materialize_reviewable_candidate(candidate)
        path = candidate / "validating-webhook-configuration.json"
        webhook = self.load(path)
        webhook["webhooks"][0]["objectSelector"] = {}
        webhook["webhooks"][0]["rules"][0]["operations"].append("CREATE")
        self.save(path, webhook)
        joined = "\n".join(validate.validate(candidate))
        self.assertIn("object selector", joined)
        self.assertIn("exactly UPDATE", joined)

    def test_pod_privilege_and_host_path_drift_are_refused(self) -> None:
        candidate = self.copy_candidate()
        self.materialize_reviewable_candidate(candidate)
        path = candidate / "deployment.json"
        deployment = self.load(path)
        pod = deployment["spec"]["template"]["spec"]
        pod["containers"][0]["securityContext"]["allowPrivilegeEscalation"] = True
        pod["volumes"].append(
            {"name": "host", "hostPath": {"path": "/", "type": "Directory"}}
        )
        self.save(path, deployment)
        joined = "\n".join(validate.validate(candidate))
        self.assertIn("disable privilege escalation", joined)
        self.assertIn("only reviewed Secret volumes", joined)

    def test_api_version_downgrade_is_refused(self) -> None:
        candidate = self.copy_candidate()
        self.materialize_reviewable_candidate(candidate)
        path = candidate / "validating-webhook-configuration.json"
        webhook = self.load(path)
        webhook["apiVersion"] = "admissionregistration.k8s.io/v1beta1"
        self.save(path, webhook)
        self.assertTrue(
            any("admissionregistration.k8s.io/v1" in error for error in validate.validate(candidate))
        )

    def test_ambiguous_observer_identity_is_refused(self) -> None:
        candidate = self.copy_candidate()
        self.materialize_reviewable_candidate(candidate)
        path = candidate / "config-map.json"
        config = self.load(path)
        config["data"]["ACCORDLOCK_WEBHOOK_OBSERVER_IDENTITY"] = (
            "urn:accordlock:observer:EKS Prod A"
        )
        self.save(path, config)
        self.assertIn(
            "webhook observer identity is not canonical",
            validate.validate(candidate),
        )

    def test_base_omits_optional_client_certificate(self) -> None:
        candidate = self.copy_candidate()
        self.materialize_reviewable_candidate(candidate)
        deployment = self.load(candidate / "deployment.json")
        text = json.dumps(deployment)
        self.assertNotIn("accordlock-postgres-client-tls", text)
        self.assertNotIn("ACCORDLOCK_STATE_POSTGRES_CLIENT_CERT_PATH", text)
        self.assertNotIn("ACCORDLOCK_STATE_POSTGRES_CLIENT_KEY_PATH", text)
        self.assertEqual(validate.validate(candidate), [])


if __name__ == "__main__":
    unittest.main()
