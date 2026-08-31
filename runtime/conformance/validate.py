#!/usr/bin/env python3
"""Fail-closed structural and payload validation for the synthetic corpus.

This validates the manifests as test oracles. It does not execute the product,
turn synthetic fixtures into benchmark evidence, or establish a G0 result.
Only the standard library is used so the check can run before dependencies are
installed.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, NoReturn


class ValidationError(ValueError):
    """A deterministic corpus validation failure."""


def _fail(path: str, message: str) -> NoReturn:
    raise ValidationError(f"{path}: {message}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def strict_load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except (OSError, json.JSONDecodeError, UnicodeError, ValidationError) as error:
        raise ValidationError(f"{path}: {error}") from error
    if not isinstance(value, dict):
        _fail(str(path), "document root must be an object")
    return value


def _exact_keys(value: Any, expected: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(path, "must be an object")
    actual = set(value)
    if actual != expected:
        unknown = sorted(actual - expected)
        missing = sorted(expected - actual)
        _fail(path, f"object shape mismatch; unknown={unknown}, missing={missing}")
    return value


def _list(value: Any, path: str, *, nonempty: bool = False) -> list[Any]:
    if not isinstance(value, list) or (nonempty and not value):
        _fail(path, "must be a non-empty array" if nonempty else "must be an array")
    return value


def _string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value:
        _fail(path, "must be a non-empty string")
    return value


def _nonnegative_int(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail(path, "must be a non-negative integer")
    return value


def _walk_frozen_shape(value: Any, shapes: dict[str, set[str]], path: str = "") -> None:
    if isinstance(value, dict):
        if path not in shapes:
            _fail(path or "/", "object has no frozen shape")
        _exact_keys(value, shapes[path], path or "/")
        for key, child in value.items():
            _walk_frozen_shape(child, shapes, f"{path}/{key}")
    elif isinstance(value, list):
        for child in value:
            _walk_frozen_shape(child, shapes, f"{path}/*")


FIXTURE_SHAPES = {
    "": {"authority_state", "clock", "ecr", "fixture_id", "g0_evidence", "github", "github_actions", "identities", "kubernetes", "plain_policy_baseline", "schema_version", "scope", "accordlock_profile", "status"},
    "/authority_state": {"activation_ids", "capability_grant_holder", "capability_grant_id", "capability_grant_maximum_uses", "content_roots", "epoch_vector"},
    "/authority_state/activation_ids": {"connector_trust", "grant_registry", "kernel_configuration", "mediation_configuration", "office_act_registry", "policy", "principal_registry", "resource_and_destination_registry", "revocation", "signer_key", "workload_build_allowlist"},
    "/authority_state/content_roots": {"connector_trust", "grant_registry", "kernel_configuration", "mediation_configuration", "office_act_registry", "policy", "principal_registry", "resource_and_destination_registry", "revocation", "signer_key", "workload_build_allowlist"},
    "/authority_state/epoch_vector": {"connector_trust", "grant_registry", "kernel_configuration", "mediation_configuration", "office_act_registry", "policy", "principal_registry", "resource_and_destination_registry", "revocation", "signer_key", "workload_build_allowlist"},
    "/clock": {"bound_object_invalidation_propagation_bound_ms", "canonical_unit", "clock_uncertainty_ms", "maximum_dispatch_delay_ms", "minimum_credential_lifetime_at_release_ms", "authorization_maximum_lifetime_ms", "requested_token_lifetime_ms", "source_maximum_age_ms", "t0", "t0_ms", "token_lifetime_upper_bound_ms"},
    "/ecr": {"digest_a", "digest_a_state", "digest_b", "digest_b_state", "old_digest"},
    "/ecr/digest_a_state": {"deleted", "observed_at", "quarantined", "signature_valid", "state_version"},
    "/ecr/digest_b_state": {"deleted", "observed_at", "quarantined", "signature_valid", "state_version"},
    "/github": {"protected_branch", "pull_request", "repository", "required_approvals", "reviewed_commit_a", "unreviewed_commit_b"},
    "/github/pull_request": {"approved_observed_at", "approved_reviewers", "approved_state_version", "base", "dismissed_at", "dismissed_reviewer", "dismissed_state_version", "head_commit", "number"},
    "/github_actions": {"registered_workflow", "registered_workload_identity", "run_a", "run_b"},
    "/github_actions/run_a": {"commit", "conclusion", "observed_at", "output_digest", "run_id", "state_version", "test_status"},
    "/github_actions/run_b": {"commit", "conclusion", "observed_at", "output_digest", "run_id", "state_version", "test_status"},
    "/identities": {"actions_connector", "agent_workload", "credential_broker", "ecr_connector", "enforcement_node", "executor", "github_connector", "invoking_user", "kubernetes_connector", "signer_adapter"},
    "/kubernetes": {"authorized_projection_id", "generation", "initial_projection", "authorized_mutable_paths", "resource_version", "unauthorized_admission_mutation"},
    "/kubernetes/initial_projection": {"metadata", "spec"},
    "/kubernetes/initial_projection/metadata": {"annotations", "labels"},
    "/kubernetes/initial_projection/metadata/annotations": {"accordlock.io/operation-hash", "accordlock.io/authorization-id", "accordlock.io/transaction-id"},
    "/kubernetes/initial_projection/metadata/labels": {"app.kubernetes.io/name"},
    "/kubernetes/initial_projection/spec": {"replicas", "template"},
    "/kubernetes/initial_projection/spec/template": {"metadata", "spec"},
    "/kubernetes/initial_projection/spec/template/metadata": {"annotations", "labels"},
    "/kubernetes/initial_projection/spec/template/metadata/annotations": set(),
    "/kubernetes/initial_projection/spec/template/metadata/labels": {"app.kubernetes.io/name"},
    "/kubernetes/initial_projection/spec/template/spec": {"containers", "serviceAccountName", "volumes"},
    "/kubernetes/initial_projection/spec/template/spec/containers/*": {"env", "image", "name", "volumeMounts"},
    "/kubernetes/unauthorized_admission_mutation": {"add_sidecar", "replace_service_account_name"},
    "/kubernetes/unauthorized_admission_mutation/add_sidecar": {"image", "name", "path"},
    "/kubernetes/unauthorized_admission_mutation/replace_service_account_name": {"path", "value"},
    "/plain_policy_baseline": {"authenticated_inputs", "default_decision", "explicit_omissions", "interpretation", "profile_id"},
    "/scope": {"action_class", "api_server_identity", "audience", "cluster_trust_domain", "container_index", "container_name", "deployment_name", "deployment_uid", "ecr_repository", "environment_id", "namespace", "operation", "repository", "tenant_id"},
    "/accordlock_profile": {"adoption_enabled", "enforcement_mode", "exact_effect_profile", "grant_profile", "profile_id", "required_lineage", "source_refresh_phase"},
}


CORPUS_KEYS = {
    "schema_version", "corpus_id", "created_at", "status", "strict_json",
    "g0_evidence", "independent_validation", "benchmark_result",
    "current_implementation_claim", "scope", "fixture",
    "scenario_manifest_schema", "positive_controls",
    "primary_differential_scenarios", "repaired_twins",
    "declared_counts",
    "corpus_wide_pass_conditions", "non_claims",
}
CORPUS_SCOPE_KEYS = {"action", "path", "local_target", "profiles"}
CORPUS_COUNT_KEYS = {
    "positive_controls", "primary_differential_scenarios", "repaired_twins",
    "scenario_manifests_total",
}
COMMON_SCENARIO_KEYS = {
    "schema_version", "id", "title", "classification", "status", "g0_evidence",
    "fixture_ref", "requirements", "assumptions", "residual_limits",
    "action_proposal", "timeline", "expected", "forbidden_outputs",
}
ACTION_KEYS = {
    "tenant_id", "environment_id", "client_request_id", "api_idempotency_key",
    "grant_selector", "action_class", "operation", "repository", "commit", "image",
    "cluster", "namespace", "deployment_name", "deployment_uid", "container_name",
}
TIMELINE_KEYS = {"sequence", "at_ms", "barrier", "event"}
PROFILE_COUNT_KEYS = {
    "evaluations", "allow_decisions", "deny_decisions", "deny_receipts",
    "execution_authorizations_issued", "successful_authorization_consumptions",
    "rejected_authorization_consumptions", "bound_objects_created", "credentials_issued",
    "effect_releases", "credential_handoffs", "provider_patch_attempts",
    "stored_protected_effects", "automatic_patch_retries", "credential_retirements",
    "transactions_final",
}
BASELINE_KEYS = {"decision", "state_sequence", "terminal_state", "reason_codes", "counts", "final_resource"}
ACCORDLOCK_KEYS = {"decision", "state_sequence", "provider_terminal_state", "transaction_terminal_state", "reason_codes", "counts", "final_resource", "replay"}
FINAL_RESOURCE_KEYS = {
    "container_names", "deployment_uid", "image_digest", "lineage_matches_requested_commit",
    "required_review_current_at_provider_call", "reserved_annotation_count",
    "rollout_condition", "service_account_name", "unauthorized_projected_delta_count",
    "unchanged",
}
REPLAY_KEYS = {
    "agreement", "historical_decision", "historical_policy_decision",
    "historical_lifecycle_reason_codes", "historical_lifecycle_terminal_state",
    "historical_provider_terminal_state", "historical_reason_codes",
    "missing_object_count", "model_invocations", "required",
}

EXPECTED_OUTCOMES = {
    "DP-000": ("ALLOW", "ALLOW", "TRANSACTION_FINAL", ["ALLOW"]),
    "DP-101": ("ALLOW", "DENY", "EVALUATED_DENY", ["PROV_TRANSFORM_OUTPUT_MISMATCH"]),
    "DP-101R": ("ALLOW", "ALLOW", "TRANSACTION_FINAL", ["ALLOW"]),
    "DP-102": ("ALLOW", "ALLOW_AT_EVALUATION_NO_EXECUTION", "CONSUMPTION_REJECTED", ["SOURCE_STATE_CHANGED", "GITHUB_REQUIRED_REVIEW_DISMISSED"]),
    "DP-102R": ("ALLOW", "ALLOW", "TRANSACTION_FINAL", ["ALLOW"]),
    "DP-103": ("ALLOW", "ALLOW_EXACT_REQUEST_PROVIDER_REJECTED_EXPANSION", "TRANSACTION_FINAL", ["POST_MUTATION_DELTA_UNAUTHORIZED"]),
    "DP-103R": ("ALLOW", "ALLOW", "TRANSACTION_FINAL", ["ALLOW"]),
}


def _check_exact_or_optional_keys(value: Any, required: set[str], optional: set[str], path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(path, "must be an object")
    actual = set(value)
    unknown = actual - required - optional
    missing = required - actual
    if unknown or missing:
        _fail(path, f"object shape mismatch; unknown={sorted(unknown)}, missing={sorted(missing)}")
    return value


def _validate_fixture(fixture: dict[str, Any]) -> None:
    _walk_frozen_shape(fixture, FIXTURE_SHAPES)
    if fixture["schema_version"] != "accordlock.conformance.fixture.v0.1":
        _fail("common-fixture.json/schema_version", "unsupported schema")
    if fixture["fixture_id"] != "DEPLOY_FIXTURE_001":
        _fail("common-fixture.json/fixture_id", "unexpected fixture id")
    if fixture["status"] != "synthetic" or fixture["g0_evidence"] is not False:
        _fail("common-fixture.json", "fixture must remain explicitly synthetic and non-G0")
    if fixture["scope"]["operation"] != "DEPLOY_EKS_IMAGE_V1":
        _fail("common-fixture.json/scope/operation", "unexpected operation")


def _validate_counts(counts: Any, path: str) -> None:
    counts = _exact_keys(counts, PROFILE_COUNT_KEYS, path)
    for name, value in counts.items():
        _nonnegative_int(value, f"{path}/{name}")


def _validate_profile_objects(scenario: dict[str, Any], path: str) -> None:
    expected = _exact_keys(scenario["expected"], {"plain_policy", "accordlock"}, f"{path}/expected")
    baseline = expected["plain_policy"]
    accordlock = expected["accordlock"]
    baseline_optional = {"security_result"}
    accordlock_optional = {"authorization_postcondition", "credential_postcondition"}
    _check_exact_or_optional_keys(baseline, BASELINE_KEYS, baseline_optional, f"{path}/expected/plain_policy")
    _check_exact_or_optional_keys(accordlock, ACCORDLOCK_KEYS, accordlock_optional, f"{path}/expected/accordlock")
    _exact_keys(baseline["final_resource"], set(baseline["final_resource"]), f"{path}/expected/plain_policy/final_resource")
    unknown = set(baseline["final_resource"]) - FINAL_RESOURCE_KEYS
    if unknown:
        _fail(f"{path}/expected/plain_policy/final_resource", f"unknown fields: {sorted(unknown)}")
    unknown = set(accordlock["final_resource"]) - FINAL_RESOURCE_KEYS
    if unknown:
        _fail(f"{path}/expected/accordlock/final_resource", f"unknown fields: {sorted(unknown)}")
    _validate_counts(baseline["counts"], f"{path}/expected/plain_policy/counts")
    _validate_counts(accordlock["counts"], f"{path}/expected/accordlock/counts")
    replay = _check_exact_or_optional_keys(
        accordlock["replay"],
        {"required", "model_invocations", "agreement", "missing_object_count"},
        REPLAY_KEYS - {"required", "model_invocations", "agreement", "missing_object_count"},
        f"{path}/expected/accordlock/replay",
    )
    if replay["required"] is not True or replay["model_invocations"] != 0 or replay["agreement"] is not True or replay["missing_object_count"] != 0:
        _fail(f"{path}/expected/accordlock/replay", "replay must be required, model-free, complete, and agreeing")
    for profile_name, profile in (("plain_policy", baseline), ("accordlock", accordlock)):
        states = _list(profile["state_sequence"], f"{path}/expected/{profile_name}/state_sequence", nonempty=True)
        if any(not isinstance(state, str) or not state for state in states):
            _fail(f"{path}/expected/{profile_name}/state_sequence", "states must be non-empty strings")
        reasons = _list(profile["reason_codes"], f"{path}/expected/{profile_name}/reason_codes", nonempty=True)
        if len(reasons) != len(set(reasons)):
            _fail(f"{path}/expected/{profile_name}/reason_codes", "reason codes must be unique")
    if baseline["state_sequence"][-1] != baseline["terminal_state"]:
        _fail(f"{path}/expected/plain_policy/state_sequence", "last state must equal terminal_state")
    if accordlock["state_sequence"][-1] != accordlock["transaction_terminal_state"]:
        _fail(f"{path}/expected/accordlock/state_sequence", "last state must equal transaction_terminal_state")
    if "authorization_postcondition" in accordlock:
        _exact_keys(accordlock["authorization_postcondition"], {"new_envelope_required", "new_authorization_required", "old_authorization_id_executable", "old_authorization_id_may_be_rebound"}, f"{path}/expected/accordlock/authorization_postcondition")
    if "credential_postcondition" in accordlock:
        _exact_keys(accordlock["credential_postcondition"], {"bound_object_invalidation_required", "replacement_credential_before_safe_expiry", "resource_reservation_released_before_safe_expiry"}, f"{path}/expected/accordlock/credential_postcondition")


def _validate_scenario(scenario: dict[str, Any], filename: str, fixture: dict[str, Any]) -> None:
    path = f"scenarios/{filename}"
    classification = scenario.get("classification")
    if classification == "synthetic_positive_control":
        expected_keys = COMMON_SCENARIO_KEYS | {"repairs"}
    elif classification == "synthetic_primary_differential":
        expected_keys = COMMON_SCENARIO_KEYS | {"repaired_by", "falsifier"}
        if scenario.get("id") == "DP-103":
            expected_keys.add("admission_mutation")
    elif classification == "synthetic_repaired_twin":
        expected_keys = COMMON_SCENARIO_KEYS | {"repairs", "repair"}
    else:
        _fail(f"{path}/classification", "unknown classification")
    _exact_keys(scenario, expected_keys, path)
    scenario_id = _string(scenario["id"], f"{path}/id")
    if filename != f"{scenario_id}.json" or scenario_id not in EXPECTED_OUTCOMES:
        _fail(f"{path}/id", "id must match a frozen scenario filename")
    if scenario["schema_version"] != "accordlock.conformance.scenario.v0.1":
        _fail(f"{path}/schema_version", "unsupported schema")
    if scenario["status"] != "preimplementation_oracle" or scenario["g0_evidence"] is not False:
        _fail(path, "scenario must remain a preimplementation, non-G0 oracle")
    if scenario["fixture_ref"] != "../common-fixture.json#DEPLOY_FIXTURE_001":
        _fail(f"{path}/fixture_ref", "unexpected fixture reference")
    for key in ("requirements", "assumptions", "residual_limits", "forbidden_outputs"):
        values = _list(scenario[key], f"{path}/{key}", nonempty=True)
        if any(not isinstance(value, str) or not value for value in values):
            _fail(f"{path}/{key}", "entries must be non-empty strings")
    action = _exact_keys(scenario["action_proposal"], ACTION_KEYS, f"{path}/action_proposal")
    if action["operation"] != fixture["scope"]["operation"]:
        _fail(f"{path}/action_proposal/operation", "does not match fixture")
    for key in ("tenant_id", "environment_id", "repository", "namespace", "deployment_name", "deployment_uid", "container_name"):
        fixture_key = key
        if action[key] != fixture["scope"][fixture_key]:
            _fail(f"{path}/action_proposal/{key}", "does not match common fixture")
    image_match = re.fullmatch(r"([^@]+)@sha256:([0-9a-f]{64})", str(action["image"]))
    if image_match is None or image_match.group(1) != fixture["scope"]["ecr_repository"]:
        _fail(f"{path}/action_proposal/image", "must be the fixture repository plus a lowercase sha256 digest")
    if not re.fullmatch(r"[0-9a-f]{40}", str(action["commit"])):
        _fail(f"{path}/action_proposal/commit", "must be a lowercase 40-hex commit")
    timeline = _list(scenario["timeline"], f"{path}/timeline", nonempty=True)
    prior_time = -1
    for index, event in enumerate(timeline, start=1):
        event = _exact_keys(event, TIMELINE_KEYS, f"{path}/timeline/{index - 1}")
        if event["sequence"] != index:
            _fail(f"{path}/timeline/{index - 1}/sequence", "sequence must be contiguous and one-based")
        at_ms = _nonnegative_int(event["at_ms"], f"{path}/timeline/{index - 1}/at_ms")
        if at_ms < prior_time:
            _fail(f"{path}/timeline/{index - 1}/at_ms", "timeline must be monotonic")
        prior_time = at_ms
        _string(event["barrier"], f"{path}/timeline/{index - 1}/barrier")
        _string(event["event"], f"{path}/timeline/{index - 1}/event")
    _validate_profile_objects(scenario, path)
    baseline_decision, accordlock_decision, terminal, reasons = EXPECTED_OUTCOMES[scenario_id]
    baseline = scenario["expected"]["plain_policy"]
    accordlock = scenario["expected"]["accordlock"]
    actual = (baseline["decision"], accordlock["decision"], accordlock["transaction_terminal_state"], accordlock["reason_codes"])
    wanted = (baseline_decision, accordlock_decision, terminal, reasons)
    if actual != wanted:
        _fail(f"{path}/expected", f"frozen outcome mismatch; got={actual!r}, expected={wanted!r}")
    if baseline["counts"]["evaluations"] != 1 or baseline["counts"]["provider_patch_attempts"] != 1:
        _fail(f"{path}/expected/plain_policy/counts", "baseline requires exactly one evaluation and provider attempt")
    if classification in {"synthetic_positive_control", "synthetic_repaired_twin"}:
        for name in ("execution_authorizations_issued", "successful_authorization_consumptions", "provider_patch_attempts", "stored_protected_effects", "transactions_final"):
            if accordlock["counts"][name] != 1:
                _fail(f"{path}/expected/accordlock/counts/{name}", "positive path count must be exactly one")
    if "admission_mutation" in scenario:
        mutation = _exact_keys(scenario["admission_mutation"], {"mutator_id", "operations", "authorized_path_count", "unauthorized_path_count"}, f"{path}/admission_mutation")
        operations = _list(mutation["operations"], f"{path}/admission_mutation/operations", nonempty=True)
        for index, operation in enumerate(operations):
            operation = _exact_keys(operation, {"op", "path", "value"}, f"{path}/admission_mutation/operations/{index}")
            if operation["op"] not in {"add", "replace"}:
                _fail(f"{path}/admission_mutation/operations/{index}/op", "unsupported mutation")
            if isinstance(operation["value"], dict):
                _exact_keys(operation["value"], {"name", "image"}, f"{path}/admission_mutation/operations/{index}/value")


def _proposal_differences(left: dict[str, Any], right: dict[str, Any]) -> set[str]:
    return {key for key in ACTION_KEYS if left[key] != right[key]}


def _validate_repairs(scenarios: dict[str, dict[str, Any]]) -> None:
    for primary_id in ("DP-101", "DP-102", "DP-103"):
        primary = scenarios[primary_id]
        twin_id = f"{primary_id}R"
        twin = scenarios[twin_id]
        if primary["repaired_by"] != twin_id or twin["repairs"] != primary_id:
            _fail(primary_id, "repair links must be reciprocal")
        if twin["repair"].get("all_other_security_inputs_unchanged") is not True:
            _fail(twin_id, "repair must assert unchanged remaining security inputs")
        differences = _proposal_differences(primary["action_proposal"], twin["action_proposal"])
        authorized = {"client_request_id", "api_idempotency_key"}
        if primary_id == "DP-101":
            authorized.add("image")
            repair = _exact_keys(twin["repair"], {"changed_field", "old_value", "new_value", "all_other_security_inputs_unchanged"}, f"{twin_id}/repair")
            if repair["changed_field"] != "action_proposal.image" or repair["old_value"] != primary["action_proposal"]["image"] or repair["new_value"] != twin["action_proposal"]["image"]:
                _fail(f"{twin_id}/repair", "declared image repair does not match the manifests")
        elif primary_id == "DP-102":
            repair = _exact_keys(twin["repair"], {"removed_event", "github_object_version_at_evaluation", "github_object_version_at_consumption", "github_object_version_at_release", "all_other_security_inputs_unchanged"}, f"{twin_id}/repair")
            primary_barriers = {event["barrier"] for event in primary["timeline"]}
            twin_barriers = {event["barrier"] for event in twin["timeline"]}
            if repair["removed_event"] not in primary_barriers or repair["removed_event"] in twin_barriers:
                _fail(f"{twin_id}/repair/removed_event", "removed event must occur only in the primary")
        else:
            repair = _exact_keys(twin["repair"], {"removed_mutator", "authorized_post_mutation_paths", "unauthorized_post_mutation_path_count", "all_other_security_inputs_unchanged"}, f"{twin_id}/repair")
            if repair["removed_mutator"] != primary["admission_mutation"]["mutator_id"] or repair["unauthorized_post_mutation_path_count"] != 0:
                _fail(f"{twin_id}/repair", "admission repair does not remove the declared mutator")
        if differences != authorized:
            _fail(twin_id, f"unexpected proposal differences from primary: {sorted(differences ^ authorized)}")


def validate_repository(root: Path) -> dict[str, int]:
    root = root.resolve()
    conformance = root / "conformance"
    corpus = strict_load(conformance / "corpus.json")
    _exact_keys(corpus, CORPUS_KEYS, "corpus.json")
    _exact_keys(corpus["scope"], CORPUS_SCOPE_KEYS, "corpus.json/scope")
    declared = _exact_keys(corpus["declared_counts"], CORPUS_COUNT_KEYS, "corpus.json/declared_counts")
    if corpus["schema_version"] != "accordlock.conformance.corpus.v0.1" or corpus["strict_json"] is not True:
        _fail("corpus.json", "unsupported schema or strict_json is not true")
    for flag in ("g0_evidence", "independent_validation", "benchmark_result", "current_implementation_claim"):
        if corpus[flag] is not False:
            _fail(f"corpus.json/{flag}", "must remain false for this synthetic oracle")
    if corpus["fixture"] != "common-fixture.json":
        _fail("corpus.json", "unexpected fixture path")
    fixture = strict_load(conformance / corpus["fixture"])
    _validate_fixture(fixture)
    groups = {
        "positive_controls": corpus["positive_controls"],
        "primary_differential_scenarios": corpus["primary_differential_scenarios"],
        "repaired_twins": corpus["repaired_twins"],
    }
    all_paths: list[str] = []
    for name, paths in groups.items():
        paths = _list(paths, f"corpus.json/{name}", nonempty=True)
        if len(paths) != declared[name]:
            _fail(f"corpus.json/declared_counts/{name}", "does not equal indexed path count")
        all_paths.extend(paths)
    if len(all_paths) != len(set(all_paths)) or len(all_paths) != declared["scenario_manifests_total"]:
        _fail("corpus.json/declared_counts/scenario_manifests_total", "duplicate path or incorrect total")
    on_disk = {f"scenarios/{path.name}" for path in (conformance / "scenarios").glob("*.json")}
    if set(all_paths) != on_disk:
        _fail("corpus.json", f"index/on-disk mismatch; indexed_only={sorted(set(all_paths)-on_disk)}, disk_only={sorted(on_disk-set(all_paths))}")
    scenarios: dict[str, dict[str, Any]] = {}
    for relative in all_paths:
        if not re.fullmatch(r"scenarios/DP-[0-9]{3}R?\.json", relative):
            _fail("corpus.json", f"unsafe or malformed scenario path: {relative!r}")
        scenario = strict_load(conformance / relative)
        _validate_scenario(scenario, Path(relative).name, fixture)
        scenarios[scenario["id"]] = scenario
    if set(scenarios) != set(EXPECTED_OUTCOMES):
        _fail("corpus.json", "scenario id set does not match the frozen seven-case corpus")
    _validate_repairs(scenarios)
    return {"scenario_manifests": len(scenarios)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    arguments = parser.parse_args(argv)
    try:
        counts = validate_repository(arguments.root)
    except ValidationError as error:
        print(f"CONFORMANCE INVALID: {error}", file=sys.stderr)
        return 1
    print(
        "CONFORMANCE VALID: "
        f"{counts['scenario_manifests']} synthetic scenario manifests; "
        "no G0, benchmark, implementation, or independent-validation claim"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
