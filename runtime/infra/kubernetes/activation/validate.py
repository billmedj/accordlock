#!/usr/bin/env python3
"""Offline, fail-closed activation gate for captured EKS evidence bundles.

The gate validates evidence *claims and their bindings*.  It never contacts a
cluster, executes a captured command, or treats a commitment as proof that the
committed bytes are true.  Raw command/response artifacts must be retained and
independently reviewable by the operator.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit


SCHEMA_VERSION = 1
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
ID_RE = re.compile(r"^[a-z][a-z0-9._:-]{2,127}$")
DNS_RE = re.compile(
    r"^(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
ARN_RE = re.compile(
    r"^arn:aws(?:-[a-z]+)?:eks:[a-z0-9-]+:[0-9]{12}:cluster/"
    r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}$"
)
RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
PLACEHOLDER_RE = re.compile(
    r"(?:REPLACE(?:_WITH)?|CHANGEME|TODO|example\.invalid|<[^>]+>)",
    re.IGNORECASE,
)
MAX_FUTURE_SKEW = timedelta(minutes=5)
MAX_BUNDLE_BYTES = 2 * 1024 * 1024

REQUIRED_SINGLE_KINDS = {
    "server_version",
    "route_profile",
    "token_request",
    "token_review",
    "authenticated_get",
    "management_identities",
    "webhook_control_plane_call",
    "vwc_configuration",
    "certificate_chain",
    "deployment_mutator_inventory",
    "admission_uid_consumption",
    "provider_request",
}
REPEATABLE_KINDS = {"effective_rbac_graph", "subject_access_review", "workload_probe"}
ALLOWED_KINDS = REQUIRED_SINGLE_KINDS | REPEATABLE_KINDS
FRESHNESS_CAP_SECONDS = {
    "server_version": 3600,
    "route_profile": 900,
    "token_request": 300,
    "token_review": 300,
    "authenticated_get": 300,
    "management_identities": 900,
    "effective_rbac_graph": 900,
    "subject_access_review": 900,
    "webhook_control_plane_call": 300,
    "workload_probe": 900,
    "vwc_configuration": 900,
    "certificate_chain": 900,
    "deployment_mutator_inventory": 900,
    "admission_uid_consumption": 300,
    "provider_request": 300,
}

EXPECTED_SAR_MATRIX = {
    ("secret_lifecycle", "create", "", "secrets", "allow"),
    ("secret_lifecycle", "get", "", "secrets", "allow"),
    ("secret_lifecycle", "delete", "", "secrets", "allow"),
    ("secret_lifecycle", "create", "", "serviceaccounts/token", "deny"),
    ("secret_lifecycle", "create", "authentication.k8s.io", "tokenreviews", "deny"),
    ("secret_lifecycle", "patch", "apps", "deployments", "deny"),
    ("service_account_token", "create", "", "serviceaccounts/token", "allow"),
    ("service_account_token", "create", "", "secrets", "deny"),
    ("service_account_token", "get", "", "secrets", "deny"),
    ("service_account_token", "delete", "", "secrets", "deny"),
    ("service_account_token", "create", "authentication.k8s.io", "tokenreviews", "deny"),
    ("service_account_token", "patch", "apps", "deployments", "deny"),
    ("token_review", "create", "authentication.k8s.io", "tokenreviews", "allow"),
    ("token_review", "create", "", "secrets", "deny"),
    ("token_review", "get", "", "secrets", "deny"),
    ("token_review", "delete", "", "secrets", "deny"),
    ("token_review", "create", "", "serviceaccounts/token", "deny"),
    ("token_review", "patch", "apps", "deployments", "deny"),
    ("executor", "get", "apps", "deployments", "allow"),
    ("executor", "patch", "apps", "deployments", "allow"),
    ("executor", "create", "", "secrets", "deny"),
    ("executor", "get", "", "secrets", "deny"),
    ("executor", "delete", "", "secrets", "deny"),
    ("executor", "create", "", "serviceaccounts/token", "deny"),
    ("executor", "create", "authentication.k8s.io", "tokenreviews", "deny"),
    ("webhook", "create", "", "secrets", "deny"),
    ("webhook", "patch", "apps", "deployments", "deny"),
    ("webhook", "get", "apps", "deployments", "deny"),
    ("webhook", "get", "", "secrets", "deny"),
    ("webhook", "delete", "", "secrets", "deny"),
    ("webhook", "create", "", "serviceaccounts/token", "deny"),
    ("webhook", "create", "authentication.k8s.io", "tokenreviews", "deny"),
}


class DuplicateJsonKeyError(ValueError):
    """Raised when an object contains two lexical occurrences of one key."""


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical_commitment(domain: str, value: Any) -> str:
    """Return the gate's domain-separated canonical JSON commitment."""
    encoded = json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    digest = hashlib.sha256(domain.encode("ascii") + b"\x00" + encoded).hexdigest()
    return f"sha256:{digest}"


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or RFC3339_RE.fullmatch(value) is None:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _is_commitment(value: Any) -> bool:
    return (
        isinstance(value, str)
        and SHA256_RE.fullmatch(value) is not None
        and value != "sha256:" + "0" * 64
    )


def _canonical_uuid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except (ValueError, AttributeError):
        return False


def _exact_keys(value: Any, expected: set[str], location: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{location} must be an object")
        return False
    keys = set(value)
    if keys != expected:
        errors.append(
            f"{location} keys differ: missing={sorted(expected - keys)!r}, "
            f"unexpected={sorted(keys - expected)!r}"
        )
        return False
    return True


def _walk_forbidden(value: Any, location: str, errors: list[str]) -> None:
    if isinstance(value, bool):
        errors.append(f"naked boolean is forbidden at {location}; use an explicit result enum")
    elif isinstance(value, float) and (value != value or abs(value) == float("inf")):
        errors.append(f"non-finite number is forbidden at {location}")
    elif isinstance(value, str) and PLACEHOLDER_RE.search(value):
        errors.append(f"unresolved sentinel or placeholder at {location}")
    elif isinstance(value, dict):
        for key, nested in value.items():
            _walk_forbidden(nested, f"{location}.{key}", errors)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _walk_forbidden(nested, f"{location}[{index}]", errors)


def _require_text(value: Any, location: str, errors: list[str]) -> str | None:
    if not isinstance(value, str) or not value or value.strip() != value or any(c.isspace() for c in value):
        errors.append(f"{location} must be non-empty canonical text without whitespace")
        return None
    return value


def _claims(evidence: dict[str, Any], keys: set[str], errors: list[str]) -> dict[str, Any]:
    claims = evidence.get("claims")
    _exact_keys(claims, keys, f"{evidence.get('id', 'evidence')}.claims", errors)
    return claims if isinstance(claims, dict) else {}


def _index(evidence: list[dict[str, Any]], kind: str) -> list[dict[str, Any]]:
    return [item for item in evidence if item.get("kind") == kind]


def _one(evidence: list[dict[str, Any]], kind: str, errors: list[str]) -> dict[str, Any]:
    matches = _index(evidence, kind)
    if len(matches) != 1:
        errors.append(f"expected exactly one {kind} evidence item, found {len(matches)}")
        return {}
    return matches[0]


def _validate_server(item: dict[str, Any], errors: list[str]) -> None:
    claims = _claims(
        item,
        {"git_version", "major", "minor", "service_account_token_authorization_id"},
        errors,
    )
    major, minor = claims.get("major"), claims.get("minor")
    if not isinstance(major, int) or isinstance(major, bool) or major < 1:
        errors.append("server_version major must be an integer >= 1")
    if not isinstance(minor, int) or isinstance(minor, bool) or minor < 0:
        errors.append("server_version minor must be a non-negative integer")
    version = claims.get("git_version")
    match = re.match(r"^v(\d+)\.(\d+)(?:\.\d+)?(?:[-+][0-9A-Za-z.-]+)?$", version or "")
    if match is None or (major, minor) != (int(match.group(1)), int(match.group(2))):
        errors.append("server_version git_version does not exactly match major/minor")
    if not isinstance(major, int) or not isinstance(minor, int) or (major, minor) < (1, 32):
        errors.append("Kubernetes server >= 1.32 is required for the AUTHORIZATION_ID activation profile")
    if claims.get("service_account_token_authorization_id") != "ga_enabled":
        errors.append("ServiceAccountTokenAUTHORIZATION_ID must be captured as ga_enabled")


def _validate_route(
    item: dict[str, Any], context: dict[str, Any], errors: list[str]
) -> dict[str, Any]:
    claims = _claims(item, {"profile", "route_commitment"}, errors)
    profile_keys = {
        "cluster_identity",
        "cluster_trust_domain",
        "api_server_identity",
        "api_dns_name",
        "api_url",
        "resolved_sockets",
        "api_ca_commitment",
        "kubernetes_audience",
        "namespace",
        "service_account_name",
        "service_account_uid",
        "bound_secret_name",
        "deployment_name",
    }
    profile = claims.get("profile")
    _exact_keys(profile, profile_keys, "route_profile.claims.profile", errors)
    if not isinstance(profile, dict):
        return {}
    cluster = profile.get("cluster_identity")
    if not isinstance(cluster, str) or ARN_RE.fullmatch(cluster) is None:
        errors.append("route cluster_identity must be an exact EKS cluster ARN")
    if cluster != context.get("cluster_identity"):
        errors.append("route cluster_identity differs from activation context")
    trust_domain = profile.get("cluster_trust_domain")
    parsed_trust = urlsplit(trust_domain) if isinstance(trust_domain, str) else None
    if (
        parsed_trust is None
        or parsed_trust.scheme != "spiffe"
        or not parsed_trust.hostname
        or parsed_trust.query
        or parsed_trust.fragment
    ):
        errors.append("route cluster_trust_domain must be an exact spiffe URI")
    if not _is_commitment(profile.get("api_server_identity")):
        errors.append("route api_server_identity must be a non-sentinel sha256 commitment")
    dns = profile.get("api_dns_name")
    if not isinstance(dns, str) or DNS_RE.fullmatch(dns) is None:
        errors.append("route api_dns_name must be a canonical DNS name")
    api_url = profile.get("api_url")
    parsed_url = urlsplit(api_url) if isinstance(api_url, str) else None
    try:
        url_port = parsed_url.port if parsed_url is not None else None
    except ValueError:
        url_port = None
    if (
        parsed_url is None
        or parsed_url.scheme != "https"
        or parsed_url.hostname != dns
        or url_port != 443
        or parsed_url.path not in ("", "/")
        or parsed_url.query
        or parsed_url.fragment
        or parsed_url.username is not None
    ):
        errors.append("route api_url must exactly bind https, api_dns_name, and port 443")
    sockets = profile.get("resolved_sockets")
    socket_tuples: list[tuple[str, int]] = []
    if not isinstance(sockets, list) or not sockets:
        errors.append("route resolved_sockets must be a non-empty exact socket set")
    else:
        for index, socket in enumerate(sockets):
            if not _exact_keys(socket, {"ip", "port"}, f"route socket[{index}]", errors):
                continue
            try:
                ip = str(ipaddress.ip_address(socket.get("ip")))
            except ValueError:
                errors.append(f"route socket[{index}] has a non-canonical IP address")
                continue
            if ip != socket.get("ip") or socket.get("port") != 443:
                errors.append(f"route socket[{index}] must have canonical IP text and port 443")
            socket_tuples.append((ip, socket.get("port")))
        if socket_tuples != sorted(set(socket_tuples)):
            errors.append("route resolved_sockets must be unique and canonically sorted")
    if not _is_commitment(profile.get("api_ca_commitment")):
        errors.append("route api_ca_commitment must be a non-sentinel sha256 commitment")
    audience = profile.get("kubernetes_audience")
    parsed_audience = urlsplit(audience) if isinstance(audience, str) else None
    if (
        parsed_audience is None
        or parsed_audience.scheme != "https"
        or not parsed_audience.hostname
        or parsed_audience.query
        or parsed_audience.fragment
    ):
        errors.append("route kubernetes_audience must be the captured real HTTPS audience")
    for field in ("namespace", "service_account_name", "bound_secret_name", "deployment_name"):
        value = profile.get(field)
        if not isinstance(value, str) or re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", value) is None:
            errors.append(f"route {field} is not a canonical Kubernetes name")
    if not _canonical_uuid(profile.get("service_account_uid")):
        errors.append("route service_account_uid must be a canonical UUID")
    expected = canonical_commitment("accordlock.eks.route-profile.v1", profile)
    if claims.get("route_commitment") != expected:
        errors.append("route_commitment does not match the exact canonical route profile")
    if claims.get("route_commitment") != context.get("route_commitment"):
        errors.append("route_commitment differs from activation context")
    return profile


def _validate_token_chain(
    evidence: list[dict[str, Any]], profile: dict[str, Any], errors: list[str]
) -> dict[str, Any]:
    request = _one(evidence, "token_request", errors)
    review = _one(evidence, "token_review", errors)
    request_keys = {
        "route_commitment",
        "namespace",
        "service_account_name",
        "service_account_uid",
        "audience",
        "token_authorization_id",
        "credential_id",
        "token_commitment",
        "issued_at",
        "not_before",
        "expires_at",
        "result",
    }
    req = _claims(request, request_keys, errors)
    review_keys = {
        "route_commitment",
        "token_commitment",
        "token_authorization_id",
        "credential_id",
        "service_account_uid",
        "username",
        "groups",
        "audience",
        "reviewed_at",
        "result",
    }
    rev = _claims(review, review_keys, errors)
    bindings = {
        "namespace": "namespace",
        "service_account_name": "service_account_name",
        "service_account_uid": "service_account_uid",
        "audience": "kubernetes_audience",
    }
    expected_route_commitment = canonical_commitment("accordlock.eks.route-profile.v1", profile)
    if req.get("route_commitment") != expected_route_commitment:
        errors.append("TokenRequest route_commitment differs from exact route profile")
    for claim_field, route_field in bindings.items():
        if req.get(claim_field) != profile.get(route_field):
            errors.append(f"TokenRequest {claim_field} differs from exact route profile")
    if req.get("result") != "issued":
        errors.append("TokenRequest result must be issued")
    if not _canonical_uuid(req.get("token_authorization_id")):
        errors.append("TokenRequest token_authorization_id must be a canonical UUID")
    if req.get("credential_id") != f"AUTHORIZATION_ID={req.get('token_authorization_id')}":
        errors.append("TokenRequest credential_id must exactly encode its AUTHORIZATION_ID")
    if not _is_commitment(req.get("token_commitment")):
        errors.append("TokenRequest token_commitment is missing or sentinel")
    issued = _parse_time(req.get("issued_at"))
    not_before = _parse_time(req.get("not_before"))
    expires = _parse_time(req.get("expires_at"))
    if None in (issued, not_before, expires) or not (not_before <= issued < expires):
        errors.append("TokenRequest times must be canonical and satisfy not_before <= issued_at < expires_at")
    for field in (
        "route_commitment",
        "token_commitment",
        "token_authorization_id",
        "credential_id",
        "service_account_uid",
        "audience",
    ):
        request_field = "audience" if field == "audience" else field
        if rev.get(field) != req.get(request_field):
            errors.append(f"TokenReview {field} does not exactly bind the TokenRequest")
    expected_username = (
        f"system:serviceaccount:{profile.get('namespace')}:{profile.get('service_account_name')}"
    )
    if rev.get("username") != expected_username:
        errors.append("TokenReview username differs from the bound ServiceAccount")
    expected_groups = sorted(
        [
            "system:authenticated",
            "system:serviceaccounts",
            f"system:serviceaccounts:{profile.get('namespace')}",
        ]
    )
    if rev.get("groups") != expected_groups:
        errors.append("TokenReview groups must exactly match the modern ServiceAccount profile")
    if rev.get("result") != "authenticated":
        errors.append("TokenReview result must be authenticated")
    reviewed = _parse_time(rev.get("reviewed_at"))
    if reviewed is None or issued is None or expires is None or not (issued <= reviewed < expires):
        errors.append("TokenReview reviewed_at must fall inside the token validity window")
    req_observed = _parse_time(request.get("observed_at"))
    rev_observed = _parse_time(review.get("observed_at"))
    if req_observed is not None and rev_observed is not None and req_observed > rev_observed:
        errors.append("TokenReview evidence precedes TokenRequest evidence")
    return req


def _validate_authenticated_get(
    item: dict[str, Any], profile: dict[str, Any], token: dict[str, Any], errors: list[str]
) -> None:
    claims = _claims(
        item,
        {
            "route_commitment",
            "token_commitment",
            "credential_id",
            "audience",
            "api_dns_name",
            "resource_path",
            "result",
        },
        errors,
    )
    expected_path = (
        f"/apis/apps/v1/namespaces/{profile.get('namespace')}/deployments/"
        f"{profile.get('deployment_name')}"
    )
    expected = {
        "route_commitment": token.get("route_commitment"),
        "token_commitment": token.get("token_commitment"),
        "credential_id": token.get("credential_id"),
        "audience": profile.get("kubernetes_audience"),
        "api_dns_name": profile.get("api_dns_name"),
        "resource_path": expected_path,
        "result": "authenticated_200",
    }
    for field, value in expected.items():
        if claims.get(field) != value:
            errors.append(f"authenticated GET {field} differs from its exact bound value")


def _validate_identities_and_sars(
    evidence: list[dict[str, Any]],
    profile: dict[str, Any],
    token: dict[str, Any],
    errors: list[str],
) -> dict[str, str]:
    identity_item = _one(evidence, "management_identities", errors)
    claims = _claims(
        identity_item,
        {
            "route_commitment",
            "identities",
            "credential_bindings",
            "rbac_commitments",
            "separation",
        },
        errors,
    )
    identities = claims.get("identities")
    roles = {
        "secret_lifecycle",
        "service_account_token",
        "token_review",
        "executor",
        "webhook",
        "activation_operator",
    }
    _exact_keys(identities, roles, "management identities", errors)
    if not isinstance(identities, dict):
        identities = {}
    for role in sorted(roles):
        _require_text(identities.get(role), f"management identity {role}", errors)
    if len(set(identities.values())) != len(roles):
        errors.append("management identities must be pairwise distinct")
    if claims.get("separation") != "pairwise_distinct_subjects_rbac_and_credentials":
        errors.append(
            "management separation must be pairwise_distinct_subjects_rbac_and_credentials"
        )
    credential_bindings = claims.get("credential_bindings")
    runtime_roles = {
        "secret_lifecycle",
        "service_account_token",
        "token_review",
        "executor",
        "webhook",
    }
    _exact_keys(
        credential_bindings,
        runtime_roles,
        "management credential_bindings",
        errors,
    )
    if not isinstance(credential_bindings, dict):
        credential_bindings = {}
    for role in sorted(runtime_roles):
        _exact_keys(
            credential_bindings.get(role),
            {"mode", "credential_commitment"},
            f"management credential binding {role}",
            errors,
        )
    secret_binding = credential_bindings.get("secret_lifecycle", {})
    token_request_binding = credential_bindings.get("service_account_token", {})
    token_review_binding = credential_bindings.get("token_review", {})
    executor_binding = credential_bindings.get("executor", {})
    webhook_binding = credential_bindings.get("webhook", {})
    management_bindings = {
        "secret_lifecycle": secret_binding,
        "service_account_token": token_request_binding,
        "token_review": token_review_binding,
    }
    for role, binding in management_bindings.items():
        if binding.get("mode") != "present" or not _is_commitment(
            binding.get("credential_commitment")
        ):
            errors.append(f"{role} management credential must be present and committed")
    if (
        executor_binding.get("mode") != "present"
        or executor_binding.get("credential_commitment") != token.get("token_commitment")
    ):
        errors.append("executor management credential must exactly bind the reviewed bearer")
    if webhook_binding != {"mode": "absent", "credential_commitment": "absent"}:
        errors.append("webhook Kubernetes API credential must be explicitly absent")
    present_commitments = [
        binding.get("credential_commitment")
        for binding in (*management_bindings.values(), executor_binding)
        if binding.get("mode") == "present"
    ]
    if len(present_commitments) != len(set(present_commitments)):
        errors.append("management/executor roles reuse the same credential bytes")
    rbac_commitments = claims.get("rbac_commitments")
    management_roles = {"secret_lifecycle", "service_account_token", "token_review"}
    _exact_keys(
        rbac_commitments,
        management_roles,
        "management rbac_commitments",
        errors,
    )
    if not isinstance(rbac_commitments, dict):
        rbac_commitments = {}
    for role in sorted(management_roles):
        if not _is_commitment(rbac_commitments.get(role)):
            errors.append(f"{role} effective RBAC closure commitment is missing or sentinel")
    management_rbac = [
        rbac_commitments.get(role)
        for role in ("secret_lifecycle", "service_account_token", "token_review")
    ]
    if len(management_rbac) != len(set(management_rbac)):
        errors.append("broker management authorities reuse the same RBAC closure commitment")
    route_commitment = canonical_commitment("accordlock.eks.route-profile.v1", profile) if profile else None
    if claims.get("route_commitment") != route_commitment:
        errors.append("management identities are not bound to the exact route")

    actual: set[tuple[str, str, str, str, str]] = set()
    sars = _index(evidence, "subject_access_review")
    for item in sars:
        sar = _claims(
            item,
            {
                "route_commitment",
                "role",
                "subject_identity",
                "verb",
                "api_group",
                "resource",
                "namespace",
                "resource_name",
                "decision",
                "decision_reason_commitment",
            },
            errors,
        )
        role = sar.get("role")
        if role not in runtime_roles:
            errors.append("SubjectAccessReview role is outside the exact reviewed matrix")
        elif sar.get("subject_identity") != identities.get(role):
            errors.append(f"SubjectAccessReview subject does not match the {role} identity")
        if sar.get("route_commitment") != route_commitment:
            errors.append("SubjectAccessReview is not bound to the exact route")
        if sar.get("resource") == "tokenreviews":
            expected_namespace = "cluster_scope"
            expected_resource_name = "not_applicable"
        elif sar.get("resource") == "serviceaccounts/token":
            expected_namespace = profile.get("namespace")
            expected_resource_name = profile.get("service_account_name")
        elif sar.get("resource") == "secrets":
            expected_namespace = profile.get("namespace")
            expected_resource_name = profile.get("bound_secret_name")
        else:
            expected_namespace = profile.get("namespace")
            expected_resource_name = profile.get("deployment_name")
        if sar.get("namespace") != expected_namespace:
            errors.append("SubjectAccessReview namespace/scope differs from the exact operation")
        if sar.get("resource_name") != expected_resource_name:
            errors.append("SubjectAccessReview resource_name differs from the exact operation")
        if not _is_commitment(sar.get("decision_reason_commitment")):
            errors.append("SubjectAccessReview decision reason commitment is missing or sentinel")
        key = (
            sar.get("role"),
            sar.get("verb"),
            sar.get("api_group"),
            sar.get("resource"),
            sar.get("decision"),
        )
        if key in actual:
            errors.append(f"duplicate SubjectAccessReview matrix cell: {key!r}")
        actual.add(key)
    if actual != EXPECTED_SAR_MATRIX:
        errors.append(
            "SubjectAccessReview allow/deny matrix differs from the exact reviewed matrix: "
            f"missing={sorted(EXPECTED_SAR_MATRIX - actual)!r}, "
            f"unexpected={sorted(actual - EXPECTED_SAR_MATRIX)!r}"
        )
    _validate_effective_rbac_graphs(
        evidence,
        profile,
        identities,
        credential_bindings,
        rbac_commitments,
        errors,
    )
    return identities


def _contains_wildcard(value: Any) -> bool:
    if isinstance(value, str):
        return value == "*"
    if isinstance(value, dict):
        return any(_contains_wildcard(nested) for nested in value.values())
    if isinstance(value, list):
        return any(_contains_wildcard(nested) for nested in value)
    return False


def _validate_effective_rbac_graphs(
    evidence: list[dict[str, Any]],
    profile: dict[str, Any],
    identities: dict[str, str],
    credential_bindings: dict[str, Any],
    rbac_commitments: dict[str, Any],
    errors: list[str],
) -> None:
    management_roles = {"secret_lifecycle", "service_account_token", "token_review"}
    graphs = _index(evidence, "effective_rbac_graph")
    graph_roles = [
        item.get("claims", {}).get("role")
        for item in graphs
        if isinstance(item.get("claims"), dict)
    ]
    if set(graph_roles) != management_roles or len(graph_roles) != len(management_roles):
        errors.append(
            "effective RBAC graphs must contain exactly one graph for each segmented "
            "broker management authority"
        )
    route_commitment = canonical_commitment("accordlock.eks.route-profile.v1", profile) if profile else None
    expected_rules = {
        "secret_lifecycle": [
            {
                "api_groups": [""],
                "resources": ["secrets"],
                "verbs": ["create", "delete", "get"],
                "scope": "namespaced",
                "namespace": profile.get("namespace"),
                "resource_names": [],
            }
        ],
        "service_account_token": [
            {
                "api_groups": [""],
                "resources": ["serviceaccounts/token"],
                "verbs": ["create"],
                "scope": "namespaced",
                "namespace": profile.get("namespace"),
                "resource_names": [profile.get("service_account_name")],
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
    graph_keys = {
        "enumeration_result",
        "source_snapshots",
        "authorization_objects",
        "bindings",
        "eks_access_entries",
        "aws_auth_mappings",
        "effective_rules",
        "aggregation_rules",
        "impersonation_edges",
    }
    snapshot_keys = {
        "roles",
        "cluster_roles",
        "role_bindings",
        "cluster_role_bindings",
        "eks_access_entries",
        "aws_auth_configmap",
    }
    forbidden_verbs = {"escalate", "bind", "impersonate"}
    forbidden_resources = {
        "roles",
        "clusterroles",
        "rolebindings",
        "clusterrolebindings",
        "pods/exec",
        "pods/attach",
        "serviceaccounts/impersonate",
        "users",
        "groups",
    }
    for item in graphs:
        claims = _claims(
            item,
            {
                "route_commitment",
                "role",
                "subject_identity",
                "credential_commitment",
                "rbac_commitment",
                "normalized_graph",
                "result",
            },
            errors,
        )
        role = claims.get("role")
        if role not in management_roles:
            errors.append("effective RBAC graph role is not a segmented broker authority")
            continue
        if claims.get("route_commitment") != route_commitment:
            errors.append(f"{role} effective RBAC graph is not bound to the exact route")
        if claims.get("subject_identity") != identities.get(role):
            errors.append(f"{role} effective RBAC graph subject does not match management identity")
        expected_credential = credential_bindings.get(role, {}).get("credential_commitment")
        if claims.get("credential_commitment") != expected_credential:
            errors.append(f"{role} effective RBAC graph does not bind its actual credential")
        graph = claims.get("normalized_graph")
        _exact_keys(graph, graph_keys, f"{role} normalized RBAC graph", errors)
        if not isinstance(graph, dict):
            continue
        if graph.get("enumeration_result") != "complete_normalized_graph":
            errors.append(f"{role} RBAC enumeration is not declared complete")
        snapshots = graph.get("source_snapshots")
        _exact_keys(snapshots, snapshot_keys, f"{role} RBAC source snapshots", errors)
        if isinstance(snapshots, dict):
            for name in sorted(snapshot_keys):
                if not _is_commitment(snapshots.get(name)):
                    errors.append(f"{role} RBAC source snapshot {name} is missing or sentinel")
        if _contains_wildcard(graph):
            errors.append(f"{role} effective RBAC graph contains a wildcard")
        if graph.get("aggregation_rules") != []:
            errors.append(f"{role} effective RBAC graph contains aggregation")
        if graph.get("impersonation_edges") != []:
            errors.append(f"{role} effective RBAC graph contains impersonation")
        if graph.get("eks_access_entries") != [] or graph.get("aws_auth_mappings") != []:
            errors.append(f"{role} has an alternate EKS IAM/aws-auth authorization path")

        expected_kind = "ClusterRole" if role == "token_review" else "Role"
        expected_binding_kind = "ClusterRoleBinding" if role == "token_review" else "RoleBinding"
        expected_namespace = "cluster_scope" if role == "token_review" else profile.get("namespace")
        objects = graph.get("authorization_objects")
        if not isinstance(objects, list) or len(objects) != 1:
            errors.append(f"{role} must have exactly one normalized authorization object")
            objects = []
        object_name = None
        for auth_object in objects:
            _exact_keys(
                auth_object,
                {
                    "kind",
                    "namespace",
                    "name",
                    "object_commitment",
                    "aggregation_rule",
                    "aggregate_labels",
                },
                f"{role} authorization object",
                errors,
            )
            if auth_object.get("kind") != expected_kind or auth_object.get("namespace") != expected_namespace:
                errors.append(f"{role} authorization object kind/scope is not exact")
            object_name = _require_text(
                auth_object.get("name"), f"{role} authorization object name", errors
            )
            if not _is_commitment(auth_object.get("object_commitment")):
                errors.append(f"{role} authorization object commitment is missing or sentinel")
            if auth_object.get("aggregation_rule") != "absent" or auth_object.get("aggregate_labels") != []:
                errors.append(f"{role} authorization object enables aggregation")

        bindings = graph.get("bindings")
        if not isinstance(bindings, list) or len(bindings) != 1:
            errors.append(f"{role} must have exactly one normalized authorization binding")
            bindings = []
        for binding in bindings:
            _exact_keys(
                binding,
                {
                    "kind",
                    "namespace",
                    "name",
                    "role_ref_kind",
                    "role_ref_name",
                    "subjects",
                    "object_commitment",
                },
                f"{role} authorization binding",
                errors,
            )
            if binding.get("kind") != expected_binding_kind or binding.get("namespace") != expected_namespace:
                errors.append(f"{role} authorization binding kind/scope is not exact")
            _require_text(binding.get("name"), f"{role} authorization binding name", errors)
            if binding.get("role_ref_kind") != expected_kind or binding.get("role_ref_name") != object_name:
                errors.append(f"{role} authorization binding roleRef is not exact")
            if binding.get("subjects") != [identities.get(role)]:
                errors.append(f"{role} authorization binding subjects are not exact")
            if not _is_commitment(binding.get("object_commitment")):
                errors.append(f"{role} authorization binding commitment is missing or sentinel")

        rules = graph.get("effective_rules")
        if rules != expected_rules[role]:
            errors.append(f"{role} effective permissions differ from the exact allowlist")
        if isinstance(rules, list):
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                verbs = rule.get("verbs") if isinstance(rule.get("verbs"), list) else []
                resources = rule.get("resources") if isinstance(rule.get("resources"), list) else []
                if forbidden_verbs & set(verbs):
                    errors.append(f"{role} effective RBAC graph contains escalate/bind/impersonate")
                if forbidden_resources & set(resources):
                    errors.append(f"{role} effective RBAC graph contains a forbidden resource")

        expected_commitment = canonical_commitment(
            "accordlock.eks.effective-rbac-graph.v1", graph
        )
        if claims.get("rbac_commitment") != expected_commitment:
            errors.append(f"{role} RBAC commitment does not match normalized graph")
        if rbac_commitments.get(role) != expected_commitment:
            errors.append(f"{role} normalized graph does not match configured RBAC commitment")
        if claims.get("result") != "closed_allowlist_only":
            errors.append(f"{role} effective RBAC graph result is not closed_allowlist_only")


def _validate_vwc(item: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    claims = _claims(
        item,
        {
            "failure_policy",
            "match_policy",
            "side_effects",
            "timeout_seconds",
            "operations",
            "api_groups",
            "api_versions",
            "resources",
            "scope",
            "namespace_selector",
            "object_selector",
            "service_dns",
            "ca_bundle_commitment",
        },
        errors,
    )
    expected = {
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
    }
    for field, value in expected.items():
        if claims.get(field) != value:
            errors.append(f"VWC {field} differs from the exact fail-closed selector profile")
    service_dns = claims.get("service_dns")
    if not isinstance(service_dns, str) or DNS_RE.fullmatch(service_dns) is None:
        errors.append("VWC service_dns is not canonical")
    if not _is_commitment(claims.get("ca_bundle_commitment")):
        errors.append("VWC ca_bundle_commitment is missing or sentinel")
    return claims


def _validate_certificate(
    item: dict[str, Any], vwc: dict[str, Any], now: datetime, errors: list[str]
) -> None:
    claims = _claims(
        item,
        {
            "service_dns",
            "ca_commitment",
            "leaf_commitment",
            "chain_commitment",
            "dns_sans",
            "issuer_identity",
            "not_before",
            "not_after",
            "validated_at",
            "validation_result",
        },
        errors,
    )
    if claims.get("service_dns") != vwc.get("service_dns"):
        errors.append("certificate service DNS differs from VWC service DNS")
    if claims.get("ca_commitment") != vwc.get("ca_bundle_commitment"):
        errors.append("certificate CA commitment differs from the VWC caBundle commitment")
    for field in ("ca_commitment", "leaf_commitment", "chain_commitment"):
        if not _is_commitment(claims.get(field)):
            errors.append(f"certificate {field} is missing or sentinel")
    sans = claims.get("dns_sans")
    if not isinstance(sans, list) or sans != sorted(set(sans)) or claims.get("service_dns") not in sans:
        errors.append("certificate DNS SANs must be unique, sorted, and contain VWC service DNS")
    _require_text(claims.get("issuer_identity"), "certificate issuer_identity", errors)
    not_before = _parse_time(claims.get("not_before"))
    not_after = _parse_time(claims.get("not_after"))
    validated = _parse_time(claims.get("validated_at"))
    if None in (not_before, not_after, validated) or not (not_before <= validated < not_after):
        errors.append("certificate chain times are invalid or validation was outside validity")
    elif not (not_before <= now < not_after):
        errors.append("certificate chain is not valid at gate evaluation time")
    if claims.get("validation_result") != "valid_chain_and_dns":
        errors.append("certificate validation_result must be valid_chain_and_dns")


def _validate_caller_boundary(
    evidence: list[dict[str, Any]], zones: list[str], errors: list[str]
) -> str | None:
    positive = _one(evidence, "webhook_control_plane_call", errors)
    base_keys = {
        "boundary_mode",
        "caller_origin",
        "transport_result",
        "admission_review_uid",
        "webhook_response_uid",
        "provider_request_commitment",
    }
    claims = positive.get("claims") if isinstance(positive.get("claims"), dict) else {}
    mode = claims.get("boundary_mode")
    mode_keys: set[str]
    if mode == "apiserver_mtls":
        mode_keys = {"client_certificate_commitment", "platform_configuration_commitment"}
    elif mode == "eks_customer_routed_network":
        mode_keys = {
            "network_enforcement_commitment",
            "control_plane_path_commitment",
            "routing_snapshot_commitment",
        }
    else:
        mode_keys = set()
        errors.append("caller boundary mode must be apiserver_mtls or eks_customer_routed_network")
    _claims(positive, base_keys | mode_keys, errors)
    if claims.get("caller_origin") != "eks_control_plane":
        errors.append("positive webhook call must be observed from the EKS control plane")
    if claims.get("transport_result") != "accepted":
        errors.append("positive control-plane webhook call was not accepted")
    uid = claims.get("admission_review_uid")
    if not _canonical_uuid(uid) or claims.get("webhook_response_uid") != uid:
        errors.append("positive webhook call must bind the same canonical AdmissionReview UID")
    if not _is_commitment(claims.get("provider_request_commitment")):
        errors.append("positive webhook call lacks a provider request commitment")
    for field in sorted(mode_keys):
        if not _is_commitment(claims.get(field)):
            errors.append(f"caller boundary {field} is missing or sentinel")

    probes = _index(evidence, "workload_probe")
    seen: set[str] = set()
    positive_source = positive.get("source_identity")
    for probe in probes:
        probe_claims = _claims(
            probe,
            {
                "boundary_mode",
                "zone",
                "caller_origin",
                "transport_result",
                "admission_review_uid",
                "webhook_response",
                "raw_admission_review_commitment",
            },
            errors,
        )
        zone = probe_claims.get("zone")
        if zone in seen:
            errors.append(f"duplicate workload-zone negative probe: {zone!r}")
        if isinstance(zone, str):
            seen.add(zone)
        if probe_claims.get("boundary_mode") != mode:
            errors.append(f"workload probe {zone!r} used a different caller boundary mode")
        if probe_claims.get("caller_origin") != "ordinary_workload":
            errors.append(f"workload probe {zone!r} did not originate from an ordinary workload")
        allowed_results = (
            {"client_auth_rejected"}
            if mode == "apiserver_mtls"
            else {"connection_blocked", "client_auth_rejected"}
        )
        if probe_claims.get("transport_result") not in allowed_results:
            errors.append(f"workload probe {zone!r} did not prove a negative caller boundary")
        if probe_claims.get("webhook_response") != "none":
            errors.append(f"workload probe {zone!r} reached an application response")
        if not _canonical_uuid(probe_claims.get("admission_review_uid")):
            errors.append(f"workload probe {zone!r} lacks a canonical unique AdmissionReview UID")
        if not _is_commitment(probe_claims.get("raw_admission_review_commitment")):
            errors.append(f"workload probe {zone!r} lacks the raw AdmissionReview commitment")
        if probe.get("source_identity") == positive_source:
            errors.append(f"workload probe {zone!r} reuses the control-plane source identity")
    if seen != set(zones):
        errors.append(
            "negative raw AdmissionReview probes do not exactly cover every workload zone: "
            f"missing={sorted(set(zones) - seen)!r}, unexpected={sorted(seen - set(zones))!r}"
        )
    probe_uids = [
        item.get("claims", {}).get("admission_review_uid")
        for item in probes
        if isinstance(item.get("claims"), dict)
    ]
    if len(probe_uids) != len(set(probe_uids)):
        errors.append("workload negative probes must use unique AdmissionReview UIDs")
    return mode


def _validate_mutator_inventory(
    item: dict[str, Any], profile: dict[str, Any], identities: dict[str, str], token: dict[str, Any], errors: list[str]
) -> None:
    claims = _claims(
        item,
        {
            "route_commitment",
            "namespace",
            "deployment_name",
            "executor_identity",
            "authorized_mutator_identities",
            "alternate_mutator_credentials",
            "active_bearer_commitments",
            "rbac_snapshot_commitment",
            "eks_access_snapshot_commitment",
            "iam_snapshot_commitment",
            "admission_exemption_snapshot_commitment",
            "break_glass_path",
            "result",
        },
        errors,
    )
    route_commitment = canonical_commitment("accordlock.eks.route-profile.v1", profile) if profile else None
    expected = {
        "route_commitment": route_commitment,
        "namespace": profile.get("namespace"),
        "deployment_name": profile.get("deployment_name"),
        "executor_identity": identities.get("executor"),
        "authorized_mutator_identities": [identities.get("executor")],
        "alternate_mutator_credentials": [],
        "active_bearer_commitments": [token.get("token_commitment")],
        "break_glass_path": "disabled",
        "result": "executor_only_no_alternate_credential",
    }
    for field, value in expected.items():
        if claims.get(field) != value:
            errors.append(f"deployment mutator inventory {field} differs from the closed profile")
    for field in (
        "rbac_snapshot_commitment",
        "eks_access_snapshot_commitment",
        "iam_snapshot_commitment",
        "admission_exemption_snapshot_commitment",
    ):
        if not _is_commitment(claims.get(field)):
            errors.append(f"deployment mutator inventory {field} is missing or sentinel")


def _validate_terminal_chain(
    evidence: list[dict[str, Any]], token: dict[str, Any], errors: list[str]
) -> None:
    positive = _one(evidence, "webhook_control_plane_call", errors)
    positive_claims = positive.get("claims") if isinstance(positive.get("claims"), dict) else {}
    uid = positive_claims.get("admission_review_uid")
    request_commitment = positive_claims.get("provider_request_commitment")

    consumption = _one(evidence, "admission_uid_consumption", errors)
    consumed = _claims(
        consumption,
        {
            "admission_review_uid",
            "credential_id",
            "token_commitment",
            "durable_state_commitment",
            "consumption_count",
            "result",
        },
        errors,
    )
    expected_consumed = {
        "admission_review_uid": uid,
        "credential_id": token.get("credential_id"),
        "token_commitment": token.get("token_commitment"),
        "consumption_count": 1,
        "result": "consumed_once",
    }
    for field, value in expected_consumed.items():
        if consumed.get(field) != value:
            errors.append(f"admission UID consumption {field} differs from the one-shot binding")
    if not _is_commitment(consumed.get("durable_state_commitment")):
        errors.append("admission UID consumption lacks a durable state commitment")

    provider = _one(evidence, "provider_request", errors)
    sent = _claims(
        provider,
        {
            "admission_review_uid",
            "route_commitment",
            "token_commitment",
            "expected_request_commitment",
            "sent_request_commitment",
            "sent_at",
            "result",
        },
        errors,
    )
    if sent.get("admission_review_uid") != uid:
        errors.append("provider request does not bind the consumed AdmissionReview UID")
    if sent.get("route_commitment") != token.get("route_commitment"):
        errors.append("provider request does not bind the exact route")
    if sent.get("token_commitment") != token.get("token_commitment"):
        errors.append("provider request does not bind the reviewed bearer")
    if (
        not _is_commitment(sent.get("expected_request_commitment"))
        or sent.get("sent_request_commitment") != sent.get("expected_request_commitment")
        or sent.get("sent_request_commitment") != request_commitment
    ):
        errors.append("provider request commitment does not exactly match expected and webhook-observed request")
    if sent.get("result") != "sent_once":
        errors.append("provider request result must be sent_once")
    sent_at = _parse_time(sent.get("sent_at"))
    not_before = _parse_time(token.get("not_before"))
    expires = _parse_time(token.get("expires_at"))
    if None in (sent_at, not_before, expires) or not (not_before <= sent_at < expires):
        errors.append("provider request was not sent inside the exact token validity window")
    get_item = _one(evidence, "authenticated_get", errors)
    get_observed = _parse_time(get_item.get("observed_at"))
    provider_observed = _parse_time(provider.get("observed_at"))
    positive_observed = _parse_time(positive.get("observed_at"))
    consumption_observed = _parse_time(consumption.get("observed_at"))
    if None not in (get_observed, provider_observed, positive_observed, consumption_observed):
        if not (get_observed <= provider_observed <= positive_observed <= consumption_observed):
            errors.append("GET, provider send, control-plane callback, and UID consumption are out of order")


def validate(bundle: Any, now: datetime | None = None) -> list[str]:
    """Return every candidate-claim error; this never authorizes activation."""
    errors: list[str] = []
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    now = now.astimezone(timezone.utc).replace(microsecond=0)
    _walk_forbidden(bundle, "bundle", errors)
    top_keys = {
        "schema_version",
        "capture_id",
        "generated_at",
        "activation_context",
        "activation_context_commitment",
        "workload_zones",
        "evidence",
    }
    if not _exact_keys(bundle, top_keys, "bundle", errors):
        if not isinstance(bundle, dict):
            return errors
    if bundle.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be exactly {SCHEMA_VERSION}")
    capture_id = bundle.get("capture_id")
    if not isinstance(capture_id, str) or not capture_id.startswith("urn:uuid:") or not _canonical_uuid(capture_id[9:]):
        errors.append("capture_id must be urn:uuid:<canonical UUID>")
    generated = _parse_time(bundle.get("generated_at"))
    if generated is None or generated > now + MAX_FUTURE_SKEW:
        errors.append("generated_at is invalid or too far in the future")

    context_keys = {"tenant", "environment", "cluster_identity", "release_digest", "route_commitment"}
    context = bundle.get("activation_context")
    _exact_keys(context, context_keys, "activation_context", errors)
    if not isinstance(context, dict):
        context = {}
    for field in ("tenant", "environment"):
        _require_text(context.get(field), f"activation_context.{field}", errors)
    if not isinstance(context.get("cluster_identity"), str) or ARN_RE.fullmatch(context.get("cluster_identity", "")) is None:
        errors.append("activation_context.cluster_identity must be an exact EKS cluster ARN")
    for field in ("release_digest", "route_commitment"):
        if not _is_commitment(context.get(field)):
            errors.append(f"activation_context.{field} must be a non-sentinel sha256 commitment")
    expected_context = canonical_commitment("accordlock.eks.activation-context.v1", context)
    if bundle.get("activation_context_commitment") != expected_context:
        errors.append("activation_context_commitment does not match the canonical context")

    zones = bundle.get("workload_zones")
    if (
        not isinstance(zones, list)
        or not zones
        or zones != sorted(set(zones))
        or any(not isinstance(zone, str) or ID_RE.fullmatch(zone) is None for zone in zones)
    ):
        errors.append("workload_zones must be a non-empty, unique, canonically sorted list")
        zones = zones if isinstance(zones, list) else []

    raw_evidence = bundle.get("evidence")
    if not isinstance(raw_evidence, list):
        errors.append("evidence must be an array")
        return errors
    evidence = [item for item in raw_evidence if isinstance(item, dict)]
    if len(evidence) != len(raw_evidence):
        errors.append("every evidence item must be an object")
    envelope_keys = {
        "id",
        "kind",
        "observed_at",
        "source_identity",
        "activation_context_commitment",
        "command_commitment",
        "response_commitment",
        "freshness",
        "claims",
    }
    seen_ids: set[str] = set()
    for index, item in enumerate(evidence):
        _exact_keys(item, envelope_keys, f"evidence[{index}]", errors)
        evidence_id = item.get("id")
        if not isinstance(evidence_id, str) or ID_RE.fullmatch(evidence_id) is None:
            errors.append(f"evidence[{index}].id is not canonical")
        elif evidence_id in seen_ids:
            errors.append(f"duplicate evidence id: {evidence_id}")
        else:
            seen_ids.add(evidence_id)
        kind = item.get("kind")
        if kind not in ALLOWED_KINDS:
            errors.append(f"evidence[{index}] has unsupported kind {kind!r}")
        _require_text(item.get("source_identity"), f"evidence[{index}].source_identity", errors)
        if item.get("activation_context_commitment") != expected_context:
            errors.append(f"evidence[{index}] is not bound to the activation context")
        for field in ("command_commitment", "response_commitment"):
            if not _is_commitment(item.get(field)):
                errors.append(f"evidence[{index}].{field} is missing or sentinel")
        observed = _parse_time(item.get("observed_at"))
        freshness = item.get("freshness")
        _exact_keys(freshness, {"max_age_seconds", "valid_until"}, f"evidence[{index}].freshness", errors)
        if not isinstance(freshness, dict):
            freshness = {}
        max_age = freshness.get("max_age_seconds")
        valid_until = _parse_time(freshness.get("valid_until"))
        cap = FRESHNESS_CAP_SECONDS.get(kind, 0)
        if not isinstance(max_age, int) or isinstance(max_age, bool) or not (1 <= max_age <= cap):
            errors.append(f"evidence[{index}] max_age_seconds exceeds the {kind!r} cap")
        if observed is None or valid_until is None:
            errors.append(f"evidence[{index}] freshness timestamps must be canonical UTC seconds")
        elif isinstance(max_age, int) and not isinstance(max_age, bool):
            if valid_until != observed + timedelta(seconds=max_age):
                errors.append(f"evidence[{index}] valid_until does not equal observed_at + max_age_seconds")
            if observed > now + MAX_FUTURE_SKEW:
                errors.append(f"evidence[{index}] observed_at is too far in the future")
            if now >= valid_until:
                errors.append(f"evidence[{index}] is stale")
        if not isinstance(item.get("claims"), dict):
            errors.append(f"evidence[{index}].claims must be an object")

    complete_singletons = True
    for kind in sorted(REQUIRED_SINGLE_KINDS):
        count = len(_index(evidence, kind))
        if count != 1:
            errors.append(f"expected exactly one {kind} evidence item, found {count}")
            complete_singletons = False
    if not _index(evidence, "subject_access_review"):
        errors.append("SubjectAccessReview evidence matrix is absent")
    if not _index(evidence, "workload_probe"):
        errors.append("workload-zone negative probe evidence is absent")
    if not complete_singletons:
        return errors

    server = _one(evidence, "server_version", errors)
    if server:
        _validate_server(server, errors)
    route = _one(evidence, "route_profile", errors)
    profile = _validate_route(route, context, errors) if route else {}
    token = _validate_token_chain(evidence, profile, errors)
    get_item = _one(evidence, "authenticated_get", errors)
    if get_item:
        _validate_authenticated_get(get_item, profile, token, errors)
    identities = _validate_identities_and_sars(evidence, profile, token, errors)
    vwc_item = _one(evidence, "vwc_configuration", errors)
    vwc = _validate_vwc(vwc_item, errors) if vwc_item else {}
    cert_item = _one(evidence, "certificate_chain", errors)
    if cert_item:
        _validate_certificate(cert_item, vwc, now, errors)
    _validate_caller_boundary(evidence, zones, errors)
    inventory = _one(evidence, "deployment_mutator_inventory", errors)
    if inventory:
        _validate_mutator_inventory(inventory, profile, identities, token, errors)
    _validate_terminal_chain(evidence, token, errors)
    return errors


def _load(path: Path) -> Any:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_BUNDLE_BYTES + 1)
        if not raw or len(raw) > MAX_BUNDLE_BYTES:
            raise ValueError(
                f"evidence bundle size must be within 1..{MAX_BUNDLE_BYTES} bytes"
            )
        return json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        DuplicateJsonKeyError,
        RecursionError,
    ) as error:
        raise ValueError(f"cannot read evidence bundle {path}: {error}") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="captured evidence bundle JSON")
    parser.add_argument(
        "--now",
        help="deterministic RFC3339 UTC evaluation time (tests/review only)",
    )
    args = parser.parse_args(argv)
    try:
        bundle = _load(args.bundle)
    except ValueError as error:
        print(f"REFUSED\n- {error}")
        return 2
    now = _parse_time(args.now) if args.now is not None else None
    if args.now is not None and now is None:
        print("REFUSED\n- --now must be RFC3339 UTC seconds, e.g. 2026-08-16T00:00:00Z")
        return 2
    errors = validate(bundle, now)
    if errors:
        print("REFUSED")
        for error in errors:
            print(f"- {error}")
        return 1
    print("CANDIDATE_EVIDENCE_CLAIMS_VALIDATED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
