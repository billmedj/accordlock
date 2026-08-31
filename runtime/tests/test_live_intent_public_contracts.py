from __future__ import annotations

import copy
import hashlib
import json
import re
import unittest
import unicodedata
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
EXAMPLES = SCHEMAS / "examples"

CONTRACTS = {
    "agent-plan-checkpoint.schema.json": "agent-plan-checkpoint.v1.json",
    "tool-call-proposal-v3.schema.json": "tool-call-proposal.v3.json",
    "pre-execution-live-intent-bundle.schema.json": "pre-execution-live-intent-bundle.v1.json",
    "complete-live-intent-bundle.schema.json": "complete-live-intent-bundle.v1.json",
}


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path} must contain a JSON object")
    return value


ALL_SCHEMAS = {
    schema["$id"]: schema
    for schema in (
        load_json(SCHEMAS / "agent-plan-checkpoint.schema.json"),
        load_json(SCHEMAS / "tool-call-proposal-v3.schema.json"),
        load_json(SCHEMAS / "pre-execution-live-intent-bundle.schema.json"),
        load_json(SCHEMAS / "complete-live-intent-bundle.schema.json"),
        load_json(SCHEMAS / "intent-conformance-record.schema.json"),
    )
}


try:
    from jsonschema import Draft202012Validator, ValidationError
    from referencing import Registry, Resource

    _REGISTRY = Registry().with_resources(
        (identifier, Resource.from_contents(schema))
        for identifier, schema in ALL_SCHEMAS.items()
    )

    def check_schema(schema: Mapping[str, Any]) -> None:
        Draft202012Validator.check_schema(schema)

    def validate_schema(instance: Any, schema: Mapping[str, Any]) -> None:
        Draft202012Validator(schema, registry=_REGISTRY).validate(instance)

except ImportError:
    class ValidationError(ValueError):
        """Fallback error when the optional jsonschema package is unavailable."""

    def check_schema(schema: Mapping[str, Any]) -> None:
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise ValidationError("contract must declare JSON Schema Draft 2020-12")
        if not isinstance(schema.get("$id"), str):
            raise ValidationError("contract must declare a string $id")

    def _resolve(reference: str, root: Mapping[str, Any]) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        base, separator, fragment = reference.partition("#")
        target_root = root if not base else ALL_SCHEMAS.get(base)
        if target_root is None:
            raise ValidationError(f"unresolved schema reference: {reference}")
        current: Any = target_root
        if separator and fragment:
            if not fragment.startswith("/"):
                raise ValidationError(f"unsupported schema fragment: {reference}")
            for token in fragment[1:].split("/"):
                key = token.replace("~1", "/").replace("~0", "~")
                if not isinstance(current, Mapping) or key not in current:
                    raise ValidationError(f"unresolved schema reference: {reference}")
                current = current[key]
        if not isinstance(current, Mapping):
            raise ValidationError(f"schema reference is not an object: {reference}")
        return current, target_root

    def _type_matches(value: Any, declared: str) -> bool:
        return {
            "object": isinstance(value, dict),
            "array": isinstance(value, list),
            "string": isinstance(value, str),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": isinstance(value, (int, float)) and not isinstance(value, bool),
            "boolean": isinstance(value, bool),
            "null": value is None,
        }.get(declared, False)

    def _validate(instance: Any, schema: Mapping[str, Any], root: Mapping[str, Any], path: str) -> None:
        if "$ref" in schema:
            target, target_root = _resolve(schema["$ref"], root)
            _validate(instance, target, target_root, path)
        for child in schema.get("allOf", []):
            _validate(instance, child, root, path)
        if "oneOf" in schema:
            matches = 0
            for child in schema["oneOf"]:
                try:
                    _validate(instance, child, root, path)
                except ValidationError:
                    continue
                matches += 1
            if matches != 1:
                raise ValidationError(f"{path}: expected exactly one oneOf match")
        if "not" in schema:
            try:
                _validate(instance, schema["not"], root, path)
            except ValidationError:
                pass
            else:
                raise ValidationError(f"{path}: matched a forbidden schema")

        declared = schema.get("type")
        if declared is not None:
            choices = [declared] if isinstance(declared, str) else declared
            if not any(_type_matches(instance, choice) for choice in choices):
                raise ValidationError(f"{path}: wrong JSON type")
        if "const" in schema and instance != schema["const"]:
            raise ValidationError(f"{path}: wrong constant")
        if "enum" in schema and instance not in schema["enum"]:
            raise ValidationError(f"{path}: value is outside the enum")

        if isinstance(instance, str):
            if len(instance) < schema.get("minLength", 0):
                raise ValidationError(f"{path}: text below minLength")
            if "maxLength" in schema and len(instance) > schema["maxLength"]:
                raise ValidationError(f"{path}: text above maxLength")
            if "pattern" in schema and re.search(schema["pattern"], instance) is None:
                raise ValidationError(f"{path}: text does not match pattern")
        if isinstance(instance, (int, float)) and not isinstance(instance, bool):
            if "minimum" in schema and instance < schema["minimum"]:
                raise ValidationError(f"{path}: value below minimum")
            if "maximum" in schema and instance > schema["maximum"]:
                raise ValidationError(f"{path}: value above maximum")
        if isinstance(instance, list):
            if len(instance) < schema.get("minItems", 0):
                raise ValidationError(f"{path}: array below minItems")
            if "maxItems" in schema and len(instance) > schema["maxItems"]:
                raise ValidationError(f"{path}: array above maxItems")
            if schema.get("uniqueItems"):
                rendered = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in instance]
                if len(rendered) != len(set(rendered)):
                    raise ValidationError(f"{path}: array items are not unique")
            for index, child in enumerate(schema.get("prefixItems", [])):
                if index < len(instance):
                    _validate(instance[index], child, root, f"{path}[{index}]")
            if "items" in schema:
                start = len(schema.get("prefixItems", []))
                for index, item in enumerate(instance[start:], start=start):
                    _validate(item, schema["items"], root, f"{path}[{index}]")
        if isinstance(instance, dict):
            required = schema.get("required", [])
            missing = [key for key in required if key not in instance]
            if missing:
                raise ValidationError(f"{path}: missing {', '.join(missing)}")
            properties = schema.get("properties", {})
            for key, child in properties.items():
                if key in instance:
                    _validate(instance[key], child, root, f"{path}.{key}")
            if schema.get("additionalProperties") is False:
                extras = set(instance) - set(properties)
                if extras:
                    raise ValidationError(f"{path}: unknown fields {sorted(extras)}")

    def validate_schema(instance: Any, schema: Mapping[str, Any]) -> None:
        _validate(instance, schema, schema, "$")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def validate_text(value: str, maximum_bytes: int, field: str) -> None:
    if not value or len(value.encode("utf-8")) > maximum_bytes:
        raise ValueError(f"{field} is outside its UTF-8 byte limit")
    if value.strip() != value or any(unicodedata.category(char) == "Cc" for char in value):
        raise ValueError(f"{field} is not canonical text")


def inspect_arguments(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [0, 0]
    if depth > 64:
        raise ValueError("arguments exceed depth 64")
    budget[0] += 1
    if budget[0] > 16_384:
        raise ValueError("arguments exceed 16384 nodes")
    if isinstance(value, str):
        budget[1] += len(value.encode("utf-8"))
    elif isinstance(value, list):
        for item in value:
            inspect_arguments(item, depth + 1, budget)
    elif isinstance(value, dict):
        for key, item in value.items():
            key_bytes = len(key.encode("utf-8"))
            if key_bytes > 1024:
                raise ValueError("argument key exceeds 1024 UTF-8 bytes")
            budget[1] += key_bytes
            inspect_arguments(item, depth + 1, budget)
    if budget[1] > 262_144 or len(canonical_json(value)) > 262_144:
        raise ValueError("arguments exceed the canonical byte limit")


def validate_plan_bindings(checkpoint: Mapping[str, Any], proposal: Mapping[str, Any]) -> None:
    for key, limit in (("session_id", 256), ("run_id", 256), ("tool_call_id", 512)):
        validate_text(str(checkpoint[key]), limit, f"checkpoint.{key}")
        if checkpoint[key] != proposal[key]:
            raise ValueError(f"checkpoint {key} was substituted")
    material = checkpoint["material"]
    material_bytes = canonical_json(material)
    if len(material_bytes) > 512 * 1024:
        raise ValueError("plan material exceeds 524288 bytes")
    if checkpoint["material_sha256"] != "sha256:" + hashlib.sha256(material_bytes).hexdigest():
        raise ValueError("plan material digest mismatch")
    requests = material["tool_requests"]
    identifiers = [request["id"] for request in requests]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("plan tool request IDs are not unique")
    matches = [request for request in requests if request["id"] == proposal["tool_call_id"]]
    if len(matches) != 1:
        raise ValueError("plan does not contain exactly one target request")
    target = matches[0]
    accepted_names = {proposal["tool_name"], f"{proposal['extension_id']}__{proposal['tool_name']}"}
    if target["name"] not in accepted_names:
        raise ValueError("plan target name does not resolve to the proposal")
    if target["arguments_sha256"] != proposal["arguments_sha256"]:
        raise ValueError("plan target arguments were substituted")


def validate_proposal_bindings(proposal: Mapping[str, Any]) -> None:
    for key, limit in (
        ("session_id", 256),
        ("run_id", 256),
        ("tool_call_id", 512),
        ("workspace_root", 4096),
        ("extension_id", 256),
        ("tool_name", 256),
    ):
        validate_text(str(proposal[key]), limit, key)
    inspect_arguments(proposal["arguments"])
    if proposal["arguments_sha256"] != sha256(proposal["arguments"]):
        raise ValueError("arguments digest mismatch")
    validate_plan_bindings(proposal["agent_plan_checkpoint"], proposal)


def validate_bundle_bindings(
    bundle: Mapping[str, Any],
    proposal: Mapping[str, Any],
    expected_result_hash: str | None = None,
) -> None:
    trace = bundle.get("checkpoint", bundle.get("trace"))
    if not isinstance(trace, Mapping):
        raise ValueError("bundle has no typed trace")
    task_hash = trace["task_hash"]
    requirement = bundle["requirements"][0]
    requirement_hash = trace["requirement_hashes"][0]
    if requirement["task_hash"] != task_hash or requirement["statement_hash"] != trace["request_hash"]:
        raise ValueError("requirement scope was substituted")
    if trace["plan_hash"] != proposal["agent_plan_checkpoint"]["material_sha256"]:
        raise ValueError("trace plan does not match the model checkpoint")
    if trace["action_hash"] != sha256(proposal):
        raise ValueError("trace action does not match the proposal")
    if expected_result_hash is not None and trace.get("result_hash") != expected_result_hash:
        raise ValueError("trace result was substituted")

    stages = [("REQUEST", "PLAN"), ("PLAN", "ACTION")]
    if "trace" in bundle:
        stages.append(("ACTION", "RESULT"))
    expected_targets = [trace["plan_hash"], trace["action_hash"]]
    if "trace" in bundle:
        expected_targets.append(trace["result_hash"])
    previous_hash = trace["request_hash"]
    previous_time = 0
    for index, (step, stage_pair, target_hash) in enumerate(
        zip(bundle["transformations"], stages, expected_targets, strict=True)
    ):
        if step["task_hash"] != task_hash or (step["source_stage"], step["target_stage"]) != stage_pair:
            raise ValueError("transformation scope was substituted")
        if step["source_hash"] != previous_hash or step["target_hash"] != target_hash:
            raise ValueError("transformation chain was substituted")
        expected_parent = None if index == 0 else trace["transformation_step_hashes"][index - 1]
        if step["parent_step_hash"] != expected_parent or step["recorded_at"] < previous_time:
            raise ValueError("transformation parent or time was substituted")
        previous_hash = target_hash
        previous_time = step["recorded_at"]
    if trace["recorded_at"] != previous_time:
        raise ValueError("trace completion time does not match its terminal step")

    context = bundle["context"]
    snapshot = context["ledger_snapshot"]
    expectation = context["ledger_expectation"]
    trust_policy = context["trust_policy"]
    record = bundle["record"]
    if snapshot["task_hash"] != task_hash or snapshot["trace_id"] != trace["trace_id"]:
        raise ValueError("ledger snapshot scope was substituted")
    if snapshot["ledger_hash"] != expectation["ledger_hash"] or record["expected_ledger_hash"] != expectation["ledger_hash"]:
        raise ValueError("ledger identity was substituted")
    if snapshot["captured_at"] != expectation["evaluated_at"] or record["evaluated_at"] != expectation["evaluated_at"]:
        raise ValueError("evaluation time was substituted")
    if trust_policy["task_hash"] != task_hash or record["task_hash"] != task_hash:
        raise ValueError("evaluation task was substituted")
    if snapshot["epoch"] != expectation["minimum_epoch"] or trust_policy["policy_epoch"] != context["minimum_trust_policy_epoch"]:
        raise ValueError("evaluation epoch was substituted")
    if record["minimum_ledger_epoch"] != expectation["minimum_epoch"] or record["minimum_trust_policy_epoch"] != context["minimum_trust_policy_epoch"]:
        raise ValueError("record epoch was substituted")
    if any(finding["requirement_hash"] != requirement_hash for finding in record["findings"]):
        raise ValueError("record requirement was substituted")


class LiveIntentPublicContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schemas = {name: load_json(SCHEMAS / name) for name in CONTRACTS}
        cls.examples = {name: load_json(EXAMPLES / example) for name, example in CONTRACTS.items()}

    def test_schemas_and_examples_are_valid_draft_2020_12_contracts(self) -> None:
        for name, schema in self.schemas.items():
            with self.subTest(schema=name):
                check_schema(schema)
                validate_schema(self.examples[name], schema)

    def test_plan_and_proposal_examples_are_exactly_bound(self) -> None:
        proposal = self.examples["tool-call-proposal-v3.schema.json"]
        checkpoint = self.examples["agent-plan-checkpoint.schema.json"]
        validate_proposal_bindings(proposal)
        self.assertEqual(checkpoint, proposal["agent_plan_checkpoint"])

    def test_bundle_examples_connect_to_the_same_plan_action_and_result(self) -> None:
        proposal = self.examples["tool-call-proposal-v3.schema.json"]
        validate_bundle_bindings(
            self.examples["pre-execution-live-intent-bundle.schema.json"],
            proposal,
        )
        validate_bundle_bindings(
            self.examples["complete-live-intent-bundle.schema.json"],
            proposal,
            "sha256:c200b16f0aa0b47e9012aadf2e9f54026d263304b21c549aa6f7f64a1cc250f7",
        )

    def test_unknown_keys_are_rejected_at_every_public_root(self) -> None:
        for name, schema in self.schemas.items():
            mutated = copy.deepcopy(self.examples[name])
            mutated["unexpected"] = True
            with self.subTest(schema=name), self.assertRaises(ValidationError):
                validate_schema(mutated, schema)

        proposal = copy.deepcopy(self.examples["tool-call-proposal-v3.schema.json"])
        proposal["agent_plan_checkpoint"]["material"]["unexpected"] = True
        with self.assertRaises(ValidationError):
            validate_schema(proposal, self.schemas["tool-call-proposal-v3.schema.json"])

    def test_bad_digest_shapes_are_rejected(self) -> None:
        proposal = copy.deepcopy(self.examples["tool-call-proposal-v3.schema.json"])
        proposal["arguments_sha256"] = "sha256:ABC"
        with self.assertRaises(ValidationError):
            validate_schema(proposal, self.schemas["tool-call-proposal-v3.schema.json"])

        bundle = copy.deepcopy(self.examples["complete-live-intent-bundle.schema.json"])
        bundle["trace"]["result_hash"] = "not-a-digest"
        with self.assertRaises(ValidationError):
            validate_schema(bundle, self.schemas["complete-live-intent-bundle.schema.json"])

    def test_scope_and_payload_substitution_are_rejected(self) -> None:
        proposal = copy.deepcopy(self.examples["tool-call-proposal-v3.schema.json"])
        proposal["agent_plan_checkpoint"]["session_id"] = "another-session"
        validate_schema(proposal, self.schemas["tool-call-proposal-v3.schema.json"])
        with self.assertRaises(ValueError):
            validate_proposal_bindings(proposal)

        changed_arguments = copy.deepcopy(self.examples["tool-call-proposal-v3.schema.json"])
        changed_arguments["arguments"]["path"] = "Cargo.toml"
        with self.assertRaises(ValueError):
            validate_proposal_bindings(changed_arguments)

        changed_task = copy.deepcopy(self.examples["pre-execution-live-intent-bundle.schema.json"])
        changed_task["requirements"][0]["task_hash"] = "sha256:" + "ab" * 32
        validate_schema(changed_task, self.schemas["pre-execution-live-intent-bundle.schema.json"])
        with self.assertRaises(ValueError):
            validate_bundle_bindings(
                changed_task,
                self.examples["tool-call-proposal-v3.schema.json"],
            )

    def test_missing_provider_evidence_cannot_claim_automatic_allow(self) -> None:
        for name in (
            "pre-execution-live-intent-bundle.schema.json",
            "complete-live-intent-bundle.schema.json",
        ):
            bundle = copy.deepcopy(self.examples[name])
            self.assertEqual(bundle["evidence"], [])
            self.assertEqual(bundle["context"]["trust_policy"]["trusted_provenance_hashes"], [])
            bundle["record"]["decision"] = "ALLOW"
            with self.subTest(schema=name), self.assertRaises(ValidationError):
                validate_schema(bundle, self.schemas[name])

    def test_utf8_byte_limits_and_unique_plan_request_ids_are_enforced(self) -> None:
        oversized = copy.deepcopy(self.examples["tool-call-proposal-v3.schema.json"])
        oversized["session_id"] = "é" * 129
        oversized["agent_plan_checkpoint"]["session_id"] = oversized["session_id"]
        with self.assertRaises(ValueError):
            validate_proposal_bindings(oversized)

        duplicate = copy.deepcopy(self.examples["tool-call-proposal-v3.schema.json"])
        duplicate["agent_plan_checkpoint"]["material"]["tool_requests"].append(
            copy.deepcopy(duplicate["agent_plan_checkpoint"]["material"]["tool_requests"][0])
        )
        duplicate["agent_plan_checkpoint"]["material_sha256"] = sha256(
            duplicate["agent_plan_checkpoint"]["material"]
        )
        with self.assertRaises(ValueError):
            validate_proposal_bindings(duplicate)


if __name__ == "__main__":
    unittest.main()
