#!/usr/bin/env python3
"""Fail-closed, standard-library-only preflight for the admission candidate.

This checker is deliberately stricter than Kubernetes schema validation.  It
does not contact a cluster and never applies resources.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


REQUIRED_RESOURCE_FILES = {
    "namespace.json",
    "service-account.json",
    "config-map.json",
    "deployment.json",
    "service.json",
    "pod-disruption-budget.json",
    "validating-webhook-configuration.json",
}
REQUIRED_CONFIG_KEYS = {
    "ACCORDLOCK_WEBHOOK_BIND_ADDR",
    "ACCORDLOCK_WEBHOOK_TLS_CERT_PATH",
    "ACCORDLOCK_WEBHOOK_TLS_KEY_PATH",
    "ACCORDLOCK_WEBHOOK_HANDLER_TIMEOUT_MS",
    "ACCORDLOCK_WEBHOOK_GRACEFUL_SHUTDOWN_MS",
    "ACCORDLOCK_WEBHOOK_MAX_IN_FLIGHT",
    "ACCORDLOCK_WEBHOOK_OBSERVER_IDENTITY",
    "ACCORDLOCK_WEBHOOK_TENANT",
    "ACCORDLOCK_WEBHOOK_ENVIRONMENT",
    "ACCORDLOCK_WEBHOOK_CLUSTER_TRUST_DOMAIN",
    "ACCORDLOCK_WEBHOOK_API_SERVER_IDENTITY",
    "ACCORDLOCK_WEBHOOK_CLUSTER_IDENTITY",
    "ACCORDLOCK_WEBHOOK_EXECUTOR_USERNAME",
    "ACCORDLOCK_WEBHOOK_EXECUTOR_GROUPS_JSON",
    "ACCORDLOCK_STATE_POSTGRES_SERVER_NAME",
    "ACCORDLOCK_STATE_POSTGRES_PORT",
    "ACCORDLOCK_STATE_POSTGRES_DATABASE",
    "ACCORDLOCK_STATE_POSTGRES_USER",
    "ACCORDLOCK_STATE_POSTGRES_PASSWORD_PATH",
    "ACCORDLOCK_STATE_POSTGRES_CA_PATH",
    "ACCORDLOCK_STATE_POSTGRES_CONNECT_TIMEOUT_MS",
}
EXPECTED_KINDS = {
    "Namespace",
    "ServiceAccount",
    "ConfigMap",
    "Deployment",
    "Service",
    "PodDisruptionBudget",
    "ValidatingWebhookConfiguration",
}
EXPECTED_API_VERSIONS = {
    "Namespace": "v1",
    "ServiceAccount": "v1",
    "ConfigMap": "v1",
    "Deployment": "apps/v1",
    "Service": "v1",
    "PodDisruptionBudget": "policy/v1",
    "ValidatingWebhookConfiguration": "admissionregistration.k8s.io/v1",
}
RBAC_KINDS = {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding"}
DIGEST_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]*/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$")
PLACEHOLDER_RE = re.compile(r"(?:REPLACE_(?:WITH_)?|CHANGEME|<[^>]+>)", re.IGNORECASE)
OBSERVER_IDENTITY_RE = re.compile(
    r"^urn:accordlock:observer:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?::[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)


def _resource_names(kustomization: Path) -> list[str]:
    try:
        lines = kustomization.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise ValueError(f"cannot read {kustomization.name}: {error}") from error

    resources: list[str] = []
    in_resources = False
    resources_indent = 0
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if line.strip() == "resources:":
            in_resources = True
            resources_indent = indent
            continue
        if in_resources and indent > resources_indent:
            match = re.fullmatch(r"\s*-\s+([A-Za-z0-9._/-]+)\s*", line)
            if not match:
                raise ValueError("kustomization resources must be plain relative paths")
            resources.append(match.group(1))
            continue
        if in_resources:
            break
    if not resources:
        raise ValueError("kustomization contains no resources")
    if len(resources) != len(set(resources)):
        raise ValueError("kustomization contains duplicate resources")
    return resources


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot parse {path.name}: {error}") from error


def _resolve_inside(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as error:
        raise ValueError(f"resource escapes candidate root: {relative}") from error
    if not candidate.is_file():
        raise ValueError(f"resource does not exist: {relative}")
    return candidate


def _one(resources: Iterable[dict[str, Any]], kind: str, errors: list[str]) -> dict[str, Any]:
    matches = [resource for resource in resources if resource.get("kind") == kind]
    if len(matches) != 1:
        errors.append(f"expected exactly one {kind}, found {len(matches)}")
        return {}
    return matches[0]


def _pem_ca_bundle(value: Any) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        return False
    begin = b"-----BEGIN CERTIFICATE-----\n"
    end = b"\n-----END CERTIFICATE-----"
    cursor = 0
    certificates = 0
    while cursor < len(decoded):
        if not decoded.startswith(begin, cursor):
            return False
        body_start = cursor + len(begin)
        body_end = decoded.find(end, body_start)
        if body_end < 0:
            return False
        lines = decoded[body_start:body_end].split(b"\n")
        if (
            not lines
            or any(not line or len(line) > 64 for line in lines)
            or any(len(line) != 64 for line in lines[:-1])
        ):
            return False
        try:
            certificate_der = base64.b64decode(b"".join(lines), validate=True)
        except (ValueError, binascii.Error):
            return False
        if not _x509_certificate_der(certificate_der):
            return False
        cursor = body_end + len(end)
        if cursor < len(decoded) and decoded[cursor : cursor + 1] == b"\n":
            cursor += 1
        certificates += 1
    return certificates > 0


def _der_element(data: bytes, offset: int) -> tuple[int, int, int] | None:
    """Return one canonical DER element as ``(tag, value_start, end)``."""
    if offset < 0 or offset + 2 > len(data):
        return None
    tag = data[offset]
    first_length = data[offset + 1]
    if first_length < 0x80:
        value_start = offset + 2
        length = first_length
    else:
        length_bytes = first_length & 0x7F
        if length_bytes == 0 or length_bytes > 4 or offset + 2 + length_bytes > len(data):
            return None
        encoded = data[offset + 2 : offset + 2 + length_bytes]
        if encoded[0] == 0:
            return None
        length = int.from_bytes(encoded, "big")
        if length < 0x80:
            return None
        value_start = offset + 2 + length_bytes
    end_offset = value_start + length
    if end_offset > len(data):
        return None
    return tag, value_start, end_offset


def _x509_certificate_der(data: bytes) -> bool:
    """Reject garbage PEM by checking the outer X.509 Certificate grammar.

    This is intentionally not certificate-path validation. Runtime TLS still
    performs trust and signature validation; this preflight only proves that
    every configured PEM block is a structurally canonical DER Certificate.
    """
    if len(data) < 128:
        return False
    outer = _der_element(data, 0)
    if outer is None or outer[0] != 0x30 or outer[2] != len(data):
        return False
    cursor = outer[1]
    children: list[tuple[int, int, int]] = []
    for _ in range(3):
        child = _der_element(data, cursor)
        if child is None:
            return False
        children.append(child)
        cursor = child[2]
    if cursor != outer[2] or [child[0] for child in children] != [0x30, 0x30, 0x03]:
        return False
    signature_value = data[children[2][1] : children[2][2]]
    return len(signature_value) > 1 and signature_value[0] <= 7


def _placeholder_locations(value: Any, location: str = "resource") -> Iterable[str]:
    if isinstance(value, str):
        if PLACEHOLDER_RE.search(value):
            yield location
    elif isinstance(value, dict):
        for key, nested in value.items():
            yield from _placeholder_locations(nested, f"{location}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _placeholder_locations(nested, f"{location}[{index}]")


def _validate_secret_contract(root: Path, deployment: dict[str, Any], errors: list[str]) -> None:
    contract_path = root / "secrets.contract.json"
    contract = _load_json(contract_path)
    if not isinstance(contract, dict) or contract.get("schemaVersion") != 1:
        errors.append("secrets.contract.json must use schemaVersion 1")
        return
    if contract.get("namespace") != "accordlock-system":
        errors.append("secret contracts must target accordlock-system")

    forbidden_fields = {"data", "stringData", "value", "literal", "secretValue"}

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if key in forbidden_fields:
                    errors.append(f"secret contract contains forbidden literal field: {key}")
                walk(nested)
        elif isinstance(value, list):
            for nested in value:
                walk(nested)

    walk(contract)
    required = contract.get("requiredSecrets")
    optional = contract.get("optionalSecrets")
    if not isinstance(required, list) or not isinstance(optional, list):
        errors.append("secret contract lists are malformed")
        return

    expected: dict[str, set[str]] = {}
    for entry in required:
        if not isinstance(entry, dict):
            errors.append("required secret contract entry is malformed")
            continue
        name = entry.get("name")
        keys = entry.get("requiredKeys")
        if not isinstance(name, str) or not isinstance(keys, list) or not keys:
            errors.append("required secret contract must have a name and requiredKeys")
            continue
        if not all(isinstance(key, str) and key for key in keys):
            errors.append(f"required secret keys are malformed for {name}")
            continue
        expected[name] = set(keys)

    try:
        volumes = deployment["spec"]["template"]["spec"]["volumes"]
    except (KeyError, TypeError):
        errors.append("deployment has no secret-volume contract")
        return
    actual: dict[str, set[str]] = {}
    for volume in volumes if isinstance(volumes, list) else []:
        secret = volume.get("secret") if isinstance(volume, dict) else None
        if not isinstance(secret, dict):
            continue
        name = secret.get("secretName")
        items = secret.get("items")
        if isinstance(name, str) and isinstance(items, list):
            actual[name] = {
                item.get("key")
                for item in items
                if isinstance(item, dict) and isinstance(item.get("key"), str)
            }
    if actual != expected:
        errors.append(f"deployment secret references {actual!r} do not match required contract {expected!r}")

    optional_names = {
        entry.get("name") for entry in optional if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }
    if actual.keys() & optional_names:
        errors.append("optional PostgreSQL client credentials must be absent from the base candidate")


def validate(root: Path) -> list[str]:
    """Return every preflight error for one materialized candidate directory."""
    root = root.resolve()
    errors: list[str] = []
    try:
        resource_names = _resource_names(root / "kustomization.yaml")
    except ValueError as error:
        return [str(error)]

    if set(resource_names) != REQUIRED_RESOURCE_FILES:
        errors.append(
            "kustomization resource set differs from the reviewed base: "
            f"{sorted(set(resource_names))!r}"
        )

    resources: list[dict[str, Any]] = []
    for name in resource_names:
        try:
            value = _load_json(_resolve_inside(root, name))
        except ValueError as error:
            errors.append(str(error))
            continue
        if not isinstance(value, dict):
            errors.append(f"resource is not a JSON object: {name}")
            continue
        for location in _placeholder_locations(value, name):
            errors.append(f"unresolved configuration placeholder: {location}")
        resources.append(value)

    kinds = {resource.get("kind") for resource in resources}
    unexpected = kinds - EXPECTED_KINDS
    missing = EXPECTED_KINDS - kinds
    if unexpected:
        errors.append(f"unexpected resource kinds: {sorted(str(kind) for kind in unexpected)!r}")
    if missing:
        errors.append(f"missing resource kinds: {sorted(missing)!r}")
    if kinds & RBAC_KINDS:
        errors.append("RBAC resources are forbidden: the webhook needs no Kubernetes API credential")
    for resource in resources:
        kind = resource.get("kind")
        if kind in EXPECTED_API_VERSIONS and resource.get("apiVersion") != EXPECTED_API_VERSIONS[kind]:
            errors.append(f"{kind} must use {EXPECTED_API_VERSIONS[kind]}")
        if resource.get("kind") == "Secret":
            errors.append("literal or empty Secret resources are forbidden; provision contracts out of band")

    namespace = _one(resources, "Namespace", errors)
    if namespace.get("metadata", {}).get("name") != "accordlock-system":
        errors.append("namespace must be accordlock-system")

    service_account = _one(resources, "ServiceAccount", errors)
    if service_account.get("metadata", {}).get("name") != "accordlock-webhook":
        errors.append("ServiceAccount must be named accordlock-webhook")
    if service_account.get("metadata", {}).get("namespace") != "accordlock-system":
        errors.append("ServiceAccount must remain in accordlock-system")
    if service_account.get("automountServiceAccountToken") is not False:
        errors.append("ServiceAccount must disable token automount")

    config_map = _one(resources, "ConfigMap", errors)
    if config_map.get("metadata", {}).get("name") != "accordlock-webhook-config":
        errors.append("runtime ConfigMap must be named accordlock-webhook-config")
    if config_map.get("metadata", {}).get("namespace") != "accordlock-system":
        errors.append("runtime ConfigMap must remain in accordlock-system")
    config_data = config_map.get("data") if isinstance(config_map.get("data"), dict) else {}
    if set(config_data) != REQUIRED_CONFIG_KEYS:
        errors.append("ConfigMap key set differs from the reviewed runtime contract")
    if "ACCORDLOCK_STATE_POSTGRES_URL" in config_data:
        errors.append("credential-bearing ACCORDLOCK_STATE_POSTGRES_URL is forbidden")
    for key, value in config_data.items():
        if not isinstance(value, str):
            errors.append(f"ConfigMap value is not text: {key}")
    observer_identity = config_data.get("ACCORDLOCK_WEBHOOK_OBSERVER_IDENTITY")
    if (
        not isinstance(observer_identity, str)
        or len(observer_identity) > 253
        or OBSERVER_IDENTITY_RE.fullmatch(observer_identity) is None
    ):
        errors.append("webhook observer identity is not canonical")
    for key in config_data:
        upper = key.upper()
        sensitive = any(word in upper for word in ("PASSWORD", "TOKEN", "SECRET", "PRIVATE_KEY"))
        if sensitive and not key.endswith("_PATH"):
            errors.append(f"secret-like ConfigMap key is forbidden: {key}")

    deployment = _one(resources, "Deployment", errors)
    if deployment.get("metadata", {}).get("name") != "accordlock-webhook":
        errors.append("Deployment must be named accordlock-webhook")
    if deployment.get("metadata", {}).get("namespace") != "accordlock-system":
        errors.append("Deployment must remain in accordlock-system")
    pod_spec = deployment.get("spec", {}).get("template", {}).get("spec", {})
    revision_annotations = (
        deployment.get("spec", {}).get("template", {}).get("metadata", {}).get("annotations", {})
    )
    if set(revision_annotations) != {
        "accordlock.io/config-revision",
        "accordlock.io/server-tls-revision",
        "accordlock.io/postgres-auth-revision",
        "accordlock.io/postgres-ca-revision",
    }:
        errors.append("pod template must carry every reviewed config/secret revision annotation")
    if deployment.get("spec", {}).get("replicas", 0) < 3:
        errors.append("deployment requires at least three replicas")
    selector = {"matchLabels": {"app.kubernetes.io/name": "accordlock-webhook"}}
    if deployment.get("spec", {}).get("selector") != selector:
        errors.append("Deployment selector differs from the reviewed label")
    pod_labels = deployment.get("spec", {}).get("template", {}).get("metadata", {}).get("labels", {})
    if pod_labels.get("app.kubernetes.io/name") != "accordlock-webhook":
        errors.append("pod template must carry the selected webhook label")
    if pod_spec.get("automountServiceAccountToken") is not False:
        errors.append("pod must disable service-account token automount")
    if pod_spec.get("serviceAccountName") != "accordlock-webhook":
        errors.append("deployment must use the inert accordlock-webhook ServiceAccount")
    for flag in ("hostIPC", "hostNetwork", "hostPID"):
        if pod_spec.get(flag) is not False:
            errors.append(f"pod must explicitly set {flag}=false")
    if pod_spec.get("enableServiceLinks") is not False:
        errors.append("pod must disable service-link environment injection")
    if "initContainers" in pod_spec:
        errors.append("init containers are forbidden in the reviewed base")
    pod_security = pod_spec.get("securityContext", {})
    if pod_security.get("runAsNonRoot") is not True:
        errors.append("pod must run as non-root")
    if pod_security.get("runAsUser") != 65532 or pod_security.get("runAsGroup") != 65532:
        errors.append("pod must use the reviewed unprivileged UID/GID 65532")
    if pod_security.get("fsGroup") != 65532:
        errors.append("pod secret reader fsGroup must be 65532")
    if pod_security.get("seccompProfile", {}).get("type") != "RuntimeDefault":
        errors.append("pod must use the RuntimeDefault seccomp profile")
    if "podAntiAffinity" not in pod_spec.get("affinity", {}):
        errors.append("pod anti-affinity is required")

    containers = pod_spec.get("containers")
    if not isinstance(containers, list) or len(containers) != 1:
        errors.append("deployment must contain exactly one reviewed container")
        containers = []
    for container in containers:
        if container.get("command") != ["/usr/local/bin/accordlock-webhookd"] or "args" in container:
            errors.append("container must execute only /usr/local/bin/accordlock-webhookd")
        if container.get("envFrom") != [{"configMapRef": {"name": "accordlock-webhook-config"}}]:
            errors.append("container environment must come only from accordlock-webhook-config")
        image = container.get("image")
        if not isinstance(image, str) or not DIGEST_RE.fullmatch(image):
            errors.append("container image must be digest-only with a lowercase sha256 digest")
        else:
            repository = image.split("@", 1)[0]
            digest = image.rsplit("@sha256:", 1)[1]
            if digest == "0" * 64:
                errors.append("the all-zero image digest sentinel is forbidden")
            if ":" in repository.rsplit("/", 1)[-1]:
                errors.append("mutable image tags are forbidden even when a digest is also present")
            if repository.split("/", 1)[0] == "example.invalid":
                errors.append("sentinel image registry example.invalid must be replaced")
        security = container.get("securityContext", {})
        if security.get("allowPrivilegeEscalation") is not False:
            errors.append("container must disable privilege escalation")
        if security.get("privileged") is not False:
            errors.append("container must explicitly disable privileged mode")
        if security.get("readOnlyRootFilesystem") is not True:
            errors.append("container root filesystem must be read-only")
        if security.get("capabilities", {}).get("drop") != ["ALL"]:
            errors.append("container must drop every Linux capability")
        expected_probe_paths = {
            "startupProbe": "/livez",
            "livenessProbe": "/livez",
            "readinessProbe": "/readyz",
        }
        for probe_name, expected_path in expected_probe_paths.items():
            probe = container.get(probe_name, {})
            http_get = probe.get("httpGet", {})
            if (
                http_get.get("scheme") != "HTTPS"
                or http_get.get("path") != expected_path
                or http_get.get("port") != "https"
            ):
                errors.append(f"{probe_name} must use the reviewed HTTPS endpoint")
        resources_block = container.get("resources", {})
        if not resources_block.get("requests") or not resources_block.get("limits"):
            errors.append("container resource requests and limits are required")
        for env in container.get("env", []):
            if not isinstance(env, dict):
                continue
            name = str(env.get("name", "")).upper()
            if any(word in name for word in ("PASSWORD", "TOKEN", "SECRET", "PRIVATE_KEY")) and "value" in env:
                errors.append(f"literal sensitive environment value is forbidden: {name}")

    try:
        _validate_secret_contract(root, deployment, errors)
    except ValueError as error:
        errors.append(str(error))

    for volume in pod_spec.get("volumes", []) if isinstance(pod_spec, dict) else []:
        secret = volume.get("secret") if isinstance(volume, dict) else None
        if not isinstance(volume, dict) or set(volume) != {"name", "secret"}:
            errors.append("only reviewed Secret volumes are authorized")
        if isinstance(secret, dict) and secret.get("defaultMode") != 0o440:
            errors.append("secret volumes must use mode 0440 for the non-root fsGroup reader")

    if isinstance(containers, list) and containers:
        expected_mounts = {
            ("server-tls", "/var/run/secrets/accordlock/server-tls", True),
            ("postgres-auth", "/var/run/secrets/accordlock/postgres-auth", True),
            ("postgres-ca", "/var/run/secrets/accordlock/postgres-ca", True),
        }
        actual_mounts = {
            (mount.get("name"), mount.get("mountPath"), mount.get("readOnly"))
            for mount in containers[0].get("volumeMounts", [])
            if isinstance(mount, dict)
        }
        if actual_mounts != expected_mounts:
            errors.append("container volume mounts differ from the reviewed read-only secret paths")

    service = _one(resources, "Service", errors)
    if service.get("metadata", {}).get("name") != "accordlock-webhook" or service.get("metadata", {}).get("namespace") != "accordlock-system":
        errors.append("webhook Service identity must remain accordlock-system/accordlock-webhook")
    if service.get("spec", {}).get("type") != "ClusterIP":
        errors.append("webhook Service must remain ClusterIP-only")
    if service.get("spec", {}).get("selector") != {"app.kubernetes.io/name": "accordlock-webhook"}:
        errors.append("webhook Service selector differs from the reviewed label")
    expected_service_port = {
        "name": "https",
        "protocol": "TCP",
        "port": 443,
        "targetPort": "https",
        "appProtocol": "https",
    }
    if service.get("spec", {}).get("ports") != [expected_service_port]:
        errors.append("webhook Service must expose only reviewed HTTPS port 443")

    pdb = _one(resources, "PodDisruptionBudget", errors)
    if pdb.get("apiVersion") != "policy/v1" or pdb.get("spec", {}).get("maxUnavailable") != 1:
        errors.append("PDB must use policy/v1 with maxUnavailable 1")
    if pdb.get("spec", {}).get("selector") != selector:
        errors.append("PDB selector differs from the reviewed webhook label")

    webhook_config = _one(resources, "ValidatingWebhookConfiguration", errors)
    webhooks = webhook_config.get("webhooks")
    if not isinstance(webhooks, list) or len(webhooks) != 1:
        errors.append("exactly one validating webhook is required")
        webhooks = []
    for webhook in webhooks:
        client = webhook.get("clientConfig", {})
        if not _pem_ca_bundle(client.get("caBundle")):
            errors.append("caBundle must be non-empty base64-encoded PEM certificate material")
        if webhook.get("admissionReviewVersions") != ["v1"]:
            errors.append("only AdmissionReview v1 is authorized")
        if webhook.get("failurePolicy") != "Fail":
            errors.append("failurePolicy must be Fail")
        if webhook.get("matchPolicy") != "Equivalent":
            errors.append("matchPolicy must be Equivalent")
        if webhook.get("sideEffects") != "NoneOnDryRun":
            errors.append("sideEffects must be NoneOnDryRun")
        timeout = webhook.get("timeoutSeconds")
        if not isinstance(timeout, int) or not 1 <= timeout <= 5:
            errors.append("webhook timeoutSeconds must be bounded to 1..5 seconds")
        try:
            handler_ms = int(config_data["ACCORDLOCK_WEBHOOK_HANDLER_TIMEOUT_MS"])
        except (KeyError, TypeError, ValueError):
            handler_ms = 0
        if isinstance(timeout, int) and not 0 < handler_ms < timeout * 1000:
            errors.append("handler timeout must be positive and strictly below API-server timeout")
        if webhook.get("namespaceSelector") != {
            "matchLabels": {"accordlock.io/enabled": "true"}
        }:
            errors.append("namespace selector must require accordlock.io/enabled=true")
        if webhook.get("objectSelector") != {
            "matchLabels": {"accordlock.io/protected": "true"}
        }:
            errors.append("object selector must require accordlock.io/protected=true")
        expected_rule = {
            "operations": ["UPDATE"],
            "apiGroups": ["apps"],
            "apiVersions": ["v1"],
            "resources": ["deployments"],
            "scope": "Namespaced",
        }
        if webhook.get("rules") != [expected_rule]:
            errors.append("webhook rules must be exactly UPDATE apps/v1 namespaced deployments")
        expected_service = {
            "namespace": "accordlock-system",
            "name": "accordlock-webhook",
            "path": "/validate",
            "port": 443,
        }
        if client.get("service") != expected_service:
            errors.append("webhook client service target differs from the reviewed endpoint")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=Path(__file__).resolve().parent,
        help="materialized candidate directory (defaults to this script's directory)",
    )
    args = parser.parse_args(argv)
    errors = validate(args.root)
    if errors:
        print("REFUSED: admission deployment candidate is not apply-ready", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("PASS: admission deployment candidate passed fail-closed static preflight")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
