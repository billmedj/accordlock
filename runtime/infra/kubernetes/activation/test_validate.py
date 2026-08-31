#!/usr/bin/env python3
"""Adversarial tests for the offline EKS activation evidence gate."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("accordlock_activation_validate", HERE / "validate.py")
assert SPEC is not None and SPEC.loader is not None
validate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validate
SPEC.loader.exec_module(validate)

NOW = datetime(2026, 8, 16, 12, 0, 0, tzinfo=timezone.utc)


def stamp(offset_seconds: int) -> str:
    return (NOW + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def commitment(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def valid_bundle() -> dict:
    cluster = "arn:aws:eks:eu-west-1:111122223333:cluster/prod-a"
    sa_uid = "11111111-2222-4333-8444-555555555555"
    token_authorization_id = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    admission_uid = "12345678-1234-4234-8234-123456789abc"
    token_commitment = commitment("bearer-token")
    request_commitment = commitment("canonical-provider-request")
    profile = {
        "cluster_identity": cluster,
        "cluster_trust_domain": "spiffe://corp.internal/eks/prod-a",
        "api_server_identity": commitment("eks-api-server-identity"),
        "api_dns_name": "a1b2c3d4.gr7.eu-west-1.eks.amazonaws.com",
        "api_url": "https://a1b2c3d4.gr7.eu-west-1.eks.amazonaws.com:443",
        "resolved_sockets": [
            {"ip": "10.0.10.12", "port": 443},
            {"ip": "10.0.20.12", "port": 443},
        ],
        "api_ca_commitment": commitment("eks-api-ca"),
        "kubernetes_audience": "https://kubernetes.default.svc",
        "namespace": "accordlock-target",
        "service_account_name": "accordlock-executor",
        "service_account_uid": sa_uid,
        "bound_secret_name": "accordlock-bound-credential",
        "deployment_name": "target-app",
    }
    route_commitment = validate.canonical_commitment("accordlock.eks.route-profile.v1", profile)
    context = {
        "tenant": "example-tenant",
        "environment": "production",
        "cluster_identity": cluster,
        "release_digest": commitment("release-image"),
        "route_commitment": route_commitment,
    }
    context_commitment = validate.canonical_commitment(
        "accordlock.eks.activation-context.v1", context
    )

    evidence: list[dict] = []

    def add(
        evidence_id: str,
        kind: str,
        offset: int,
        claims: dict,
        source: str | None = None,
        max_age: int = 120,
    ) -> None:
        observed = NOW + timedelta(seconds=offset)
        evidence.append(
            {
                "id": evidence_id,
                "kind": kind,
                "observed_at": observed.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source_identity": source or f"urn:accordlock:evidence-source:{evidence_id}",
                "activation_context_commitment": context_commitment,
                "command_commitment": commitment(f"command:{evidence_id}"),
                "response_commitment": commitment(f"response:{evidence_id}"),
                "freshness": {
                    "max_age_seconds": max_age,
                    "valid_until": (observed + timedelta(seconds=max_age)).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                },
                "claims": claims,
            }
        )

    add(
        "server.version",
        "server_version",
        -60,
        {
            "git_version": "v1.32.7-eks-1234567",
            "major": 1,
            "minor": 32,
            "service_account_token_authorization_id": "ga_enabled",
        },
    )
    add(
        "route.profile",
        "route_profile",
        -59,
        {"profile": profile, "route_commitment": route_commitment},
    )
    add(
        "token.request",
        "token_request",
        -50,
        {
            "route_commitment": route_commitment,
            "namespace": profile["namespace"],
            "service_account_name": profile["service_account_name"],
            "service_account_uid": sa_uid,
            "audience": profile["kubernetes_audience"],
            "token_authorization_id": token_authorization_id,
            "credential_id": f"AUTHORIZATION_ID={token_authorization_id}",
            "token_commitment": token_commitment,
            "issued_at": stamp(-51),
            "not_before": stamp(-60),
            "expires_at": stamp(900),
            "result": "issued",
        },
    )
    add(
        "token.review",
        "token_review",
        -45,
        {
            "route_commitment": route_commitment,
            "token_commitment": token_commitment,
            "token_authorization_id": token_authorization_id,
            "credential_id": f"AUTHORIZATION_ID={token_authorization_id}",
            "service_account_uid": sa_uid,
            "username": "system:serviceaccount:accordlock-target:accordlock-executor",
            "groups": [
                "system:authenticated",
                "system:serviceaccounts",
                "system:serviceaccounts:accordlock-target",
            ],
            "audience": profile["kubernetes_audience"],
            "reviewed_at": stamp(-45),
            "result": "authenticated",
        },
    )
    add(
        "get.authenticated",
        "authenticated_get",
        -40,
        {
            "route_commitment": route_commitment,
            "token_commitment": token_commitment,
            "credential_id": f"AUTHORIZATION_ID={token_authorization_id}",
            "audience": profile["kubernetes_audience"],
            "api_dns_name": profile["api_dns_name"],
            "resource_path": "/apis/apps/v1/namespaces/accordlock-target/deployments/target-app",
            "result": "authenticated_200",
        },
    )
    identities = {
        "secret_lifecycle": "system:serviceaccount:accordlock-system:secret-lifecycle",
        "service_account_token": "system:serviceaccount:accordlock-system:token-issuer",
        "token_review": "system:serviceaccount:accordlock-system:token-reviewer",
        "executor": "system:serviceaccount:accordlock-target:accordlock-executor",
        "webhook": "system:serviceaccount:accordlock-system:accordlock-webhook",
        "activation_operator": "arn:aws:iam::111122223333:role/accordlock-activation-operator",
    }
    management_claims = {
        "route_commitment": route_commitment,
        "identities": identities,
        "credential_bindings": {
            "secret_lifecycle": {
                "mode": "present",
                "credential_commitment": commitment("secret-management-credential"),
            },
            "service_account_token": {
                "mode": "present",
                "credential_commitment": commitment("token-request-management-credential"),
            },
            "token_review": {
                "mode": "present",
                "credential_commitment": commitment("token-review-management-credential"),
            },
            "executor": {
                "mode": "present",
                "credential_commitment": token_commitment,
            },
            "webhook": {
                "mode": "absent",
                "credential_commitment": "absent",
            },
        },
        "rbac_commitments": {
            role: commitment(f"temporary-rbac:{role}")
            for role in (
                "secret_lifecycle",
                "service_account_token",
                "token_review",
            )
        },
        "separation": "pairwise_distinct_subjects_rbac_and_credentials",
    }
    add(
        "identities.management",
        "management_identities",
        -55,
        management_claims,
    )
    matrix = sorted(validate.EXPECTED_SAR_MATRIX)
    for index, (role, verb, api_group, resource, decision) in enumerate(matrix):
        resource_name = (
            "target-app"
            if resource == "deployments"
            else "accordlock-executor"
            if resource == "serviceaccounts/token"
            else "not_applicable"
            if resource == "tokenreviews"
            else "accordlock-bound-credential"
        )
        namespace = "cluster_scope" if resource == "tokenreviews" else profile["namespace"]
        add(
            f"sar.cell-{index:02d}",
            "subject_access_review",
            -54 + index,
            {
                "route_commitment": route_commitment,
                "role": role,
                "subject_identity": identities[role],
                "verb": verb,
                "api_group": api_group,
                "resource": resource,
                "namespace": namespace,
                "resource_name": resource_name,
                "decision": decision,
                "decision_reason_commitment": commitment(f"sar-reason:{index}"),
            },
        )
    graph_rules = {
        "secret_lifecycle": [
            {
                "api_groups": [""],
                "resources": ["secrets"],
                "verbs": ["create", "delete", "get"],
                "scope": "namespaced",
                "namespace": profile["namespace"],
                "resource_names": [],
            }
        ],
        "service_account_token": [
            {
                "api_groups": [""],
                "resources": ["serviceaccounts/token"],
                "verbs": ["create"],
                "scope": "namespaced",
                "namespace": profile["namespace"],
                "resource_names": [profile["service_account_name"]],
            }
        ],
        "token_review": [
            {
                "api_groups": ["authentication.k8s.io"],
                "resources": ["tokenreviews"],
                "verbs": ["create"],
                "scope": "cluster",
                "namespace": "cluster_scope",
                "resource_names": [],
            }
        ],
    }
    for index, role in enumerate(
        ("secret_lifecycle", "service_account_token", "token_review")
    ):
        cluster_scoped = role == "token_review"
        auth_name = f"accordlock-{role.replace('_', '-')}"
        graph = {
            "enumeration_result": "complete_normalized_graph",
            "source_snapshots": {
                "roles": commitment(f"snapshot:roles:{role}"),
                "cluster_roles": commitment(f"snapshot:cluster-roles:{role}"),
                "role_bindings": commitment(f"snapshot:role-bindings:{role}"),
                "cluster_role_bindings": commitment(
                    f"snapshot:cluster-role-bindings:{role}"
                ),
                "eks_access_entries": commitment(f"snapshot:eks-access:{role}"),
                "aws_auth_configmap": commitment(f"snapshot:aws-auth:{role}"),
            },
            "authorization_objects": [
                {
                    "kind": "ClusterRole" if cluster_scoped else "Role",
                    "namespace": "cluster_scope" if cluster_scoped else profile["namespace"],
                    "name": auth_name,
                    "object_commitment": commitment(f"authorization-object:{role}"),
                    "aggregation_rule": "absent",
                    "aggregate_labels": [],
                }
            ],
            "bindings": [
                {
                    "kind": "ClusterRoleBinding" if cluster_scoped else "RoleBinding",
                    "namespace": "cluster_scope" if cluster_scoped else profile["namespace"],
                    "name": f"{auth_name}-binding",
                    "role_ref_kind": "ClusterRole" if cluster_scoped else "Role",
                    "role_ref_name": auth_name,
                    "subjects": [identities[role]],
                    "object_commitment": commitment(f"authorization-binding:{role}"),
                }
            ],
            "eks_access_entries": [],
            "aws_auth_mappings": [],
            "effective_rules": graph_rules[role],
            "aggregation_rules": [],
            "impersonation_edges": [],
        }
        rbac_commitment = validate.canonical_commitment(
            "accordlock.eks.effective-rbac-graph.v1", graph
        )
        management_claims["rbac_commitments"][role] = rbac_commitment
        add(
            f"rbac.graph-{role}",
            "effective_rbac_graph",
            -20 + index,
            {
                "route_commitment": route_commitment,
                "role": role,
                "subject_identity": identities[role],
                "credential_commitment": management_claims["credential_bindings"][role][
                    "credential_commitment"
                ],
                "rbac_commitment": rbac_commitment,
                "normalized_graph": graph,
                "result": "closed_allowlist_only",
            },
        )
    add(
        "vwc.exact",
        "vwc_configuration",
        -56,
        {
            "failure_policy": "Fail",
            "match_policy": "Equivalent",
            "side_effects": "NoneOnDryRun",
            "timeout_seconds": 2,
            "operations": ["UPDATE"],
            "api_groups": ["apps"],
            "api_versions": ["v1"],
            "resources": ["deployments"],
            "scope": "Namespaced",
            "namespace_selector": {"matchLabels": {"accordlock.io/enabled": "true"}},
            "object_selector": {"matchLabels": {"accordlock.io/protected": "true"}},
            "service_dns": "accordlock-webhook.accordlock-system.svc",
            "ca_bundle_commitment": commitment("webhook-ca"),
        },
    )
    add(
        "certificate.chain",
        "certificate_chain",
        -55,
        {
            "service_dns": "accordlock-webhook.accordlock-system.svc",
            "ca_commitment": commitment("webhook-ca"),
            "leaf_commitment": commitment("webhook-leaf"),
            "chain_commitment": commitment("webhook-chain"),
            "dns_sans": [
                "accordlock-webhook.accordlock-system.svc",
                "accordlock-webhook.accordlock-system.svc.cluster.local",
            ],
            "issuer_identity": "urn:accordlock:issuer:admission-webhook-prod",
            "not_before": stamp(-86400),
            "not_after": stamp(86400),
            "validated_at": stamp(-55),
            "validation_result": "valid_chain_and_dns",
        },
    )
    add(
        "mutator.inventory",
        "deployment_mutator_inventory",
        -35,
        {
            "route_commitment": route_commitment,
            "namespace": profile["namespace"],
            "deployment_name": profile["deployment_name"],
            "executor_identity": identities["executor"],
            "authorized_mutator_identities": [identities["executor"]],
            "alternate_mutator_credentials": [],
            "active_bearer_commitments": [token_commitment],
            "rbac_snapshot_commitment": commitment("rbac-snapshot"),
            "eks_access_snapshot_commitment": commitment("eks-access-snapshot"),
            "iam_snapshot_commitment": commitment("iam-snapshot"),
            "admission_exemption_snapshot_commitment": commitment("admission-exemptions"),
            "break_glass_path": "disabled",
            "result": "executor_only_no_alternate_credential",
        },
    )
    add(
        "provider.request",
        "provider_request",
        -30,
        {
            "admission_review_uid": admission_uid,
            "route_commitment": route_commitment,
            "token_commitment": token_commitment,
            "expected_request_commitment": request_commitment,
            "sent_request_commitment": request_commitment,
            "sent_at": stamp(-30),
            "result": "sent_once",
        },
    )
    add(
        "webhook.control-plane",
        "webhook_control_plane_call",
        -29,
        {
            "boundary_mode": "eks_customer_routed_network",
            "caller_origin": "eks_control_plane",
            "transport_result": "accepted",
            "admission_review_uid": admission_uid,
            "webhook_response_uid": admission_uid,
            "provider_request_commitment": request_commitment,
            "network_enforcement_commitment": commitment("network-enforcement"),
            "control_plane_path_commitment": commitment("control-plane-path"),
            "routing_snapshot_commitment": commitment("routing-snapshot"),
        },
        source="urn:accordlock:source:eks-control-plane-prod-a",
    )
    for index, zone in enumerate(["workload-a", "workload-b"]):
        add(
            f"probe.{zone}",
            "workload_probe",
            -25 + index,
            {
                "boundary_mode": "eks_customer_routed_network",
                "zone": zone,
                "caller_origin": "ordinary_workload",
                "transport_result": "connection_blocked",
                "admission_review_uid": f"0000000{index + 1}-0000-4000-8000-00000000000{index + 1}",
                "webhook_response": "none",
                "raw_admission_review_commitment": commitment(f"raw-probe:{zone}"),
            },
            source=f"urn:accordlock:source:{zone}",
        )
    add(
        "admission.consumption",
        "admission_uid_consumption",
        -28,
        {
            "admission_review_uid": admission_uid,
            "credential_id": f"AUTHORIZATION_ID={token_authorization_id}",
            "token_commitment": token_commitment,
            "durable_state_commitment": commitment("durable-consumption-row"),
            "consumption_count": 1,
            "result": "consumed_once",
        },
    )
    return {
        "schema_version": 1,
        "capture_id": "urn:uuid:99999999-9999-4999-8999-999999999999",
        "generated_at": stamp(-61),
        "activation_context": context,
        "activation_context_commitment": context_commitment,
        "workload_zones": ["workload-a", "workload-b"],
        "evidence": evidence,
    }


def one(bundle: dict, kind: str) -> dict:
    return next(item for item in bundle["evidence"] if item["kind"] == kind)


def rbac_graph(bundle: dict, role: str) -> dict:
    return next(
        item
        for item in bundle["evidence"]
        if item["kind"] == "effective_rbac_graph" and item["claims"]["role"] == role
    )


class ActivationGateTests(unittest.TestCase):
    def assert_refused(self, bundle: dict, needle: str) -> None:
        joined = "\n".join(validate.validate(bundle, NOW))
        self.assertIn(needle, joined, joined)

    def test_complete_bundle_passes(self) -> None:
        self.assertEqual(validate.validate(valid_bundle(), NOW), [])

    def test_checked_in_example_is_intentionally_refused(self) -> None:
        example = json.loads((HERE / "example.refused.json").read_text(encoding="utf-8"))
        errors = validate.validate(example, NOW)
        self.assertTrue(errors)
        self.assertTrue(any("placeholder" in error or "sentinel" in error for error in errors))

    def test_duplicate_json_key_is_refused_before_payload_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text(
                '{"schema_version":1,"activation_context":'
                '{"tenant":"example-tenant","tenant":"attacker"}}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON key: tenant"):
                validate._load(path)

    def test_oversized_bundle_is_refused_before_json_allocation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.json"
            path.write_bytes(b" " * (validate.MAX_BUNDLE_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "bundle size"):
                validate._load(path)

    def test_schema_is_json_and_names_the_normative_validator(self) -> None:
        schema = json.loads((HERE / "bundle.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertIn("validate.py", schema["description"])

    def test_naked_boolean_is_refused(self) -> None:
        bundle = valid_bundle()
        one(bundle, "server_version")["claims"]["service_account_token_authorization_id"] = True
        self.assert_refused(bundle, "naked boolean")

    def test_kubernetes_131_is_refused(self) -> None:
        bundle = valid_bundle()
        claims = one(bundle, "server_version")["claims"]
        claims["git_version"] = "v1.31.9-eks-123"
        claims["minor"] = 31
        self.assert_refused(bundle, "Kubernetes server >= 1.32")

    def test_authorization_id_feature_not_ga_enabled_is_refused(self) -> None:
        bundle = valid_bundle()
        one(bundle, "server_version")["claims"]["service_account_token_authorization_id"] = "disabled"
        self.assert_refused(bundle, "ga_enabled")

    def test_noncanonical_credential_id_is_refused(self) -> None:
        bundle = valid_bundle()
        one(bundle, "token_request")["claims"]["credential_id"] = "AUTHORIZATION_ID=wrong"
        self.assert_refused(bundle, "credential_id must exactly encode")

    def test_token_review_authorization_id_swap_is_refused(self) -> None:
        bundle = valid_bundle()
        one(bundle, "token_review")["claims"]["token_authorization_id"] = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
        self.assert_refused(bundle, "does not exactly bind")

    def test_service_account_uid_swap_is_refused(self) -> None:
        bundle = valid_bundle()
        one(bundle, "token_review")["claims"]["service_account_uid"] = (
            "22222222-2222-4222-8222-222222222222"
        )
        self.assert_refused(bundle, "service_account_uid does not exactly bind")

    def test_get_with_wrong_audience_is_refused(self) -> None:
        bundle = valid_bundle()
        one(bundle, "authenticated_get")["claims"]["audience"] = "https://sts.amazonaws.com"
        self.assert_refused(bundle, "authenticated GET audience")

    def test_route_socket_drift_without_recommit_is_refused(self) -> None:
        bundle = valid_bundle()
        one(bundle, "route_profile")["claims"]["profile"]["resolved_sockets"][0]["ip"] = "10.0.10.99"
        self.assert_refused(bundle, "route_commitment does not match")

    def test_management_identity_collision_is_refused(self) -> None:
        bundle = valid_bundle()
        identities = one(bundle, "management_identities")["claims"]["identities"]
        identities["secret_lifecycle"] = identities["executor"]
        self.assert_refused(bundle, "pairwise distinct")

    def test_management_credential_byte_reuse_is_refused(self) -> None:
        bundle = valid_bundle()
        bindings = one(bundle, "management_identities")["claims"]["credential_bindings"]
        bindings["secret_lifecycle"]["credential_commitment"] = bindings[
            "service_account_token"
        ]["credential_commitment"]
        self.assert_refused(bundle, "reuse the same credential bytes")

    def test_broker_management_rbac_commitment_reuse_is_refused(self) -> None:
        bundle = valid_bundle()
        bindings = one(bundle, "management_identities")["claims"]["rbac_commitments"]
        bindings["secret_lifecycle"] = bindings["token_review"]
        self.assert_refused(bundle, "reuse the same RBAC closure commitment")

    def test_missing_segmented_rbac_graph_is_refused(self) -> None:
        bundle = valid_bundle()
        removed = rbac_graph(bundle, "token_review")
        bundle["evidence"].remove(removed)
        self.assert_refused(bundle, "exactly one graph for each segmented")

    def test_rbac_wildcard_is_refused(self) -> None:
        bundle = valid_bundle()
        graph = rbac_graph(bundle, "secret_lifecycle")["claims"]["normalized_graph"]
        graph["effective_rules"][0]["resources"] = ["*"]
        self.assert_refused(bundle, "contains a wildcard")

    def test_aggregated_cluster_role_is_refused(self) -> None:
        bundle = valid_bundle()
        graph = rbac_graph(bundle, "token_review")["claims"]["normalized_graph"]
        graph["aggregation_rules"] = [commitment("aggregate-selector")]
        self.assert_refused(bundle, "contains aggregation")

    def test_escalate_bind_impersonate_verb_is_refused(self) -> None:
        bundle = valid_bundle()
        graph = rbac_graph(bundle, "token_review")["claims"]["normalized_graph"]
        graph["effective_rules"][0]["verbs"].append("impersonate")
        self.assert_refused(bundle, "contains escalate/bind/impersonate")

    def test_alternate_eks_access_entry_is_refused(self) -> None:
        bundle = valid_bundle()
        graph = rbac_graph(bundle, "service_account_token")["claims"]["normalized_graph"]
        graph["eks_access_entries"] = [commitment("alternate-eks-principal")]
        self.assert_refused(bundle, "alternate EKS IAM/aws-auth authorization path")

    def test_permission_outside_graph_allowlist_is_refused(self) -> None:
        bundle = valid_bundle()
        graph = rbac_graph(bundle, "secret_lifecycle")["claims"]["normalized_graph"]
        graph["effective_rules"].append(
            {
                "api_groups": [""],
                "resources": ["pods"],
                "verbs": ["get"],
                "scope": "namespaced",
                "namespace": "accordlock-target",
                "resource_names": [],
            }
        )
        self.assert_refused(bundle, "effective permissions differ from the exact allowlist")

    def test_legacy_single_broker_authority_is_refused(self) -> None:
        bundle = valid_bundle()
        claims = one(bundle, "management_identities")["claims"]
        claims["identities"] = {
            "broker": "system:serviceaccount:accordlock-system:broker",
            "executor": claims["identities"]["executor"],
            "webhook": claims["identities"]["webhook"],
            "activation_operator": claims["identities"]["activation_operator"],
        }
        self.assert_refused(bundle, "management identities keys differ")

    def test_cross_operation_sar_subject_substitution_is_refused(self) -> None:
        bundle = valid_bundle()
        sar = next(
            item
            for item in bundle["evidence"]
            if item["kind"] == "subject_access_review"
            and item["claims"]["role"] == "secret_lifecycle"
            and item["claims"]["resource"] == "deployments"
        )
        sar["claims"]["subject_identity"] = one(bundle, "management_identities")["claims"][
            "identities"
        ]["executor"]
        self.assert_refused(bundle, "subject does not match the secret_lifecycle identity")

    def test_token_request_sar_for_wrong_service_account_name_is_refused(self) -> None:
        bundle = valid_bundle()
        sar = next(
            item
            for item in bundle["evidence"]
            if item["kind"] == "subject_access_review"
            and item["claims"]["role"] == "service_account_token"
            and item["claims"]["decision"] == "allow"
        )
        sar["claims"]["resource_name"] = "different-service-account"
        self.assert_refused(bundle, "resource_name differs from the exact operation")

    def test_token_review_sar_must_be_cluster_scoped(self) -> None:
        bundle = valid_bundle()
        sar = next(
            item
            for item in bundle["evidence"]
            if item["kind"] == "subject_access_review"
            and item["claims"]["role"] == "token_review"
            and item["claims"]["decision"] == "allow"
        )
        sar["claims"]["namespace"] = "accordlock-target"
        self.assert_refused(bundle, "namespace/scope differs from the exact operation")

    def test_sar_allow_instead_of_required_deny_is_refused(self) -> None:
        bundle = valid_bundle()
        sar = next(
            item
            for item in bundle["evidence"]
            if item["kind"] == "subject_access_review"
            and item["claims"]["role"] == "executor"
            and item["claims"]["resource"] == "secrets"
        )
        sar["claims"]["decision"] = "allow"
        self.assert_refused(bundle, "allow/deny matrix differs")

    def test_missing_sar_cell_is_refused(self) -> None:
        bundle = valid_bundle()
        index = next(i for i, item in enumerate(bundle["evidence"]) if item["kind"] == "subject_access_review")
        bundle["evidence"].pop(index)
        self.assert_refused(bundle, "allow/deny matrix differs")

    def test_missing_workload_zone_probe_is_refused(self) -> None:
        bundle = valid_bundle()
        bundle["evidence"] = [
            item
            for item in bundle["evidence"]
            if not (item["kind"] == "workload_probe" and item["claims"]["zone"] == "workload-b")
        ]
        self.assert_refused(bundle, "do not exactly cover every workload zone")

    def test_workload_probe_that_reaches_webhook_is_refused(self) -> None:
        bundle = valid_bundle()
        probe = one(bundle, "workload_probe")
        probe["claims"]["transport_result"] = "accepted"
        probe["claims"]["webhook_response"] = "denied"
        self.assert_refused(bundle, "did not prove a negative caller boundary")

    def test_control_plane_origin_substitution_is_refused(self) -> None:
        bundle = valid_bundle()
        one(bundle, "webhook_control_plane_call")["claims"]["caller_origin"] = "ordinary_workload"
        self.assert_refused(bundle, "must be observed from the EKS control plane")

    def test_configurable_apiserver_mtls_profile_passes_claim_validation(self) -> None:
        bundle = valid_bundle()
        positive = one(bundle, "webhook_control_plane_call")["claims"]
        for key in (
            "network_enforcement_commitment",
            "control_plane_path_commitment",
            "routing_snapshot_commitment",
        ):
            positive.pop(key)
        positive.update(
            {
                "boundary_mode": "apiserver_mtls",
                "client_certificate_commitment": commitment("apiserver-client-certificate"),
                "platform_configuration_commitment": commitment("mtls-platform-configuration"),
            }
        )
        for probe in (item for item in bundle["evidence"] if item["kind"] == "workload_probe"):
            probe["claims"]["boundary_mode"] = "apiserver_mtls"
            probe["claims"]["transport_result"] = "client_auth_rejected"
        self.assertEqual(validate.validate(bundle, NOW), [])

    def test_apiserver_mtls_without_platform_commitment_is_refused(self) -> None:
        bundle = valid_bundle()
        positive = one(bundle, "webhook_control_plane_call")["claims"]
        for key in (
            "network_enforcement_commitment",
            "control_plane_path_commitment",
            "routing_snapshot_commitment",
        ):
            positive.pop(key)
        positive.update(
            {
                "boundary_mode": "apiserver_mtls",
                "client_certificate_commitment": commitment("apiserver-client-certificate"),
                "platform_configuration_commitment": "sha256:" + "0" * 64,
            }
        )
        for probe in (item for item in bundle["evidence"] if item["kind"] == "workload_probe"):
            probe["claims"]["boundary_mode"] = "apiserver_mtls"
            probe["claims"]["transport_result"] = "client_auth_rejected"
        self.assert_refused(bundle, "platform_configuration_commitment is missing or sentinel")

    def test_mixed_caller_boundary_modes_are_refused(self) -> None:
        bundle = valid_bundle()
        one(bundle, "workload_probe")["claims"]["boundary_mode"] = "apiserver_mtls"
        self.assert_refused(bundle, "different caller boundary mode")

    def test_vwc_failure_policy_downgrade_is_refused(self) -> None:
        bundle = valid_bundle()
        one(bundle, "vwc_configuration")["claims"]["failure_policy"] = "Ignore"
        self.assert_refused(bundle, "VWC failure_policy")

    def test_vwc_selector_broadening_is_refused(self) -> None:
        bundle = valid_bundle()
        one(bundle, "vwc_configuration")["claims"]["object_selector"] = {}
        self.assert_refused(bundle, "VWC object_selector")

    def test_certificate_ca_substitution_is_refused(self) -> None:
        bundle = valid_bundle()
        one(bundle, "certificate_chain")["claims"]["ca_commitment"] = commitment("attacker-ca")
        self.assert_refused(bundle, "differs from the VWC caBundle")

    def test_alternate_mutator_credential_is_refused(self) -> None:
        bundle = valid_bundle()
        inventory = one(bundle, "deployment_mutator_inventory")["claims"]
        inventory["alternate_mutator_credentials"] = [commitment("admin-token")]
        self.assert_refused(bundle, "alternate_mutator_credentials differs")

    def test_admission_uid_double_consumption_is_refused(self) -> None:
        bundle = valid_bundle()
        one(bundle, "admission_uid_consumption")["claims"]["consumption_count"] = 2
        self.assert_refused(bundle, "consumption_count differs")

    def test_provider_request_commitment_substitution_is_refused(self) -> None:
        bundle = valid_bundle()
        one(bundle, "provider_request")["claims"]["sent_request_commitment"] = commitment(
            "different-request"
        )
        self.assert_refused(bundle, "does not exactly match")

    def test_expired_provider_bearer_is_refused(self) -> None:
        bundle = valid_bundle()
        one(bundle, "provider_request")["claims"]["sent_at"] = stamp(901)
        self.assert_refused(bundle, "token validity window")

    def test_stale_evidence_is_refused(self) -> None:
        bundle = valid_bundle()
        server = one(bundle, "server_version")
        server["observed_at"] = stamp(-500)
        server["freshness"] = {"max_age_seconds": 120, "valid_until": stamp(-380)}
        self.assert_refused(bundle, "is stale")

    def test_context_mix_and_match_is_refused(self) -> None:
        bundle = valid_bundle()
        one(bundle, "route_profile")["activation_context_commitment"] = commitment("other-context")
        self.assert_refused(bundle, "not bound to the activation context")

    def test_zero_command_commitment_is_refused(self) -> None:
        bundle = valid_bundle()
        one(bundle, "token_review")["command_commitment"] = "sha256:" + "0" * 64
        self.assert_refused(bundle, "command_commitment is missing or sentinel")


if __name__ == "__main__":
    unittest.main()
