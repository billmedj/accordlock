from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_PACKAGE = ROOT / "benchmarks" / "accordbench"
if str(BENCHMARK_PACKAGE) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_PACKAGE))

from accordbench.schema_validation import (  # noqa: E402
    SchemaContractError,
    load_schema,
    validate_instance,
)


CONTRACTS = {
    "completed-execution-evidence.schema.json": "completed-execution-evidence.v4.json",
    "execution-lineage.schema.json": "execution-lineage.v2.json",
    "task-control-projection.schema.json": "task-control-projection.v2.json",
    "session-audit-page.schema.json": "session-audit-page.v6.json",
    "intent-conformance-record.schema.json": "intent-conformance-record.v2.json",
    "intent-evidence-request.schema.json": "intent-evidence-request.v2.json",
    "intent-evidence-response.schema.json": "intent-evidence-response.v2.json",
    "external-evidence-disclosure-grant.schema.json": "external-evidence-disclosure-grant.v1.json",
}

ADDITIONAL_EXAMPLES = (
    ("session-audit-page.schema.json", "session-audit-page.all-events.v6.json"),
)


def load_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


class PublicSchemaContractTests(unittest.TestCase):
    def available_contracts(self) -> list[tuple[str, dict[str, object], dict[str, object]]]:
        loaded = []
        for schema_name, example_name in CONTRACTS.items():
            schema_path = ROOT / "schemas" / schema_name
            example_path = ROOT / "schemas" / "examples" / example_name
            if not schema_path.exists() or not example_path.exists():
                continue
            schema = load_schema(schema_path)
            example = load_json(example_path)
            self.assertIsInstance(example, dict)
            loaded.append((schema_name, schema, example))
        return loaded

    def test_every_declared_contract_and_example_exists(self) -> None:
        for schema_name, example_name in CONTRACTS.items():
            with self.subTest(schema=schema_name):
                self.assertTrue((ROOT / "schemas" / schema_name).is_file())
                self.assertTrue((ROOT / "schemas" / "examples" / example_name).is_file())

    def test_rust_locked_examples_satisfy_public_contracts(self) -> None:
        for schema_name, schema, example in self.available_contracts():
            with self.subTest(schema=schema_name):
                validate_instance(example, schema, schema_name)
        for schema_name, example_name in ADDITIONAL_EXAMPLES:
            schema = load_schema(ROOT / "schemas" / schema_name)
            example = load_json(ROOT / "schemas" / "examples" / example_name)
            with self.subTest(schema=schema_name, example=example_name):
                validate_instance(example, schema, example_name)

    def test_required_fields_are_enforced(self) -> None:
        for schema_name, schema, example in self.available_contracts():
            required = schema.get("required")
            self.assertIsInstance(required, list)
            self.assertTrue(required)
            mutated = copy.deepcopy(example)
            mutated.pop(required[0])
            with self.subTest(schema=schema_name):
                with self.assertRaises(SchemaContractError):
                    validate_instance(mutated, schema, schema_name)

    def test_unknown_fields_are_rejected_at_root_and_nested_objects(self) -> None:
        for schema_name, schema, example in self.available_contracts():
            root_mutation = copy.deepcopy(example)
            root_mutation["unexpected"] = True
            with self.subTest(schema=schema_name, location="root"):
                with self.assertRaises(SchemaContractError):
                    validate_instance(root_mutation, schema, schema_name)

        completed_schema = load_schema(ROOT / "schemas" / "completed-execution-evidence.schema.json")
        completed = load_json(
            ROOT / "schemas" / "examples" / "completed-execution-evidence.v4.json"
        )
        completed["lineage"]["unexpected"] = True
        with self.assertRaises(SchemaContractError):
            validate_instance(completed, completed_schema, "completed execution nested field")

        task_control_schema = load_schema(ROOT / "schemas" / "task-control-projection.schema.json")
        task_control = load_json(
            ROOT / "schemas" / "examples" / "task-control-projection.v2.json"
        )
        task_control["unexpected"] = True
        with self.assertRaises(SchemaContractError):
            validate_instance(task_control, task_control_schema, "task control unknown field")

        audit_schema = load_schema(ROOT / "schemas" / "session-audit-page.schema.json")
        audit = load_json(ROOT / "schemas" / "examples" / "session-audit-page.v6.json")
        audit["events"][0]["unexpected"] = True
        with self.assertRaises(SchemaContractError):
            validate_instance(audit, audit_schema, "audit event nested field")

    def test_schema_versions_are_exact(self) -> None:
        for schema_name, schema, example in self.available_contracts():
            mutated = copy.deepcopy(example)
            mutated["schema_version"] += 1
            with self.subTest(schema=schema_name):
                with self.assertRaises(SchemaContractError):
                    validate_instance(mutated, schema, schema_name)

    def test_enums_and_tagged_variants_are_closed(self) -> None:
        audit_schema = load_schema(ROOT / "schemas" / "session-audit-page.schema.json")
        audit = load_json(ROOT / "schemas" / "examples" / "session-audit-page.v6.json")
        audit["events"][0]["type"] = "UNKNOWN_EVENT"
        with self.assertRaises(SchemaContractError):
            validate_instance(audit, audit_schema, "audit event type")

        for schema_name, example_name, path in (
            ("intent-conformance-record.schema.json", "intent-conformance-record.v2.json", ("outcome",)),
            ("intent-evidence-request.schema.json", "intent-evidence-request.v2.json", ("stage",)),
            (
                "intent-evidence-response.schema.json",
                "intent-evidence-response.v2.json",
                ("evidence", "method_kind"),
            ),
        ):
            schema_path = ROOT / "schemas" / schema_name
            example_path = ROOT / "schemas" / "examples" / example_name
            if not schema_path.exists() or not example_path.exists():
                continue
            schema = load_schema(schema_path)
            example = load_json(example_path)
            target = example
            for component in path[:-1]:
                target = target[component]
            target[path[-1]] = "UNKNOWN_ENUM_VALUE"
            with self.subTest(schema=schema_name):
                with self.assertRaises(SchemaContractError):
                    validate_instance(example, schema, schema_name)

    def test_audit_task_check_requires_qualified_nonempty_evidence(self) -> None:
        schema = load_schema(ROOT / "schemas" / "session-audit-page.schema.json")
        audit = load_json(
            ROOT / "schemas" / "examples" / "session-audit-page.all-events.v6.json"
        )
        started = next(event for event in audit["events"] if event["type"] == "ACTION_STARTED")
        started["intent_assessment"] = {
            "schema_version": 1,
            "profile": "PRE_EXECUTION",
            "status": "VERIFIED",
            "evidence_count": 0,
            "finding_reasons": ["SUPPORTED"],
        }
        with self.assertRaises(SchemaContractError):
            validate_instance(audit, schema, "zero-evidence task check")

    def test_nested_evidence_and_authentication_contracts_are_closed(self) -> None:
        request_schema = load_schema(ROOT / "schemas" / "intent-evidence-request.schema.json")
        request = load_json(ROOT / "schemas" / "examples" / "intent-evidence-request.v2.json")
        request["disclosure_policy"]["unexpected"] = True
        with self.assertRaises(SchemaContractError):
            validate_instance(request, request_schema, "request disclosure policy")

        incomplete_external = load_json(
            ROOT / "schemas" / "examples" / "intent-evidence-request.v2.json"
        )
        incomplete_external["disclosure_policy"] = {"mode": "ALLOWLISTED_EXTERNAL"}
        with self.assertRaises(SchemaContractError):
            validate_instance(incomplete_external, request_schema, "external disclosure policy")

        valid_external = load_json(
            ROOT / "schemas" / "examples" / "intent-evidence-request.v2.json"
        )
        valid_external["disclosure_policy"] = {
            "mode": "ALLOWLISTED_EXTERNAL",
            "provider_id_hash": "sha256:" + "15" * 32,
            "egress_policy_hash": "sha256:" + "16" * 32,
            "provider_trust_root": "sha256:" + "17" * 32,
            "egress_authority_root": "sha256:" + "18" * 32,
        }
        validate_instance(valid_external, request_schema, "valid external disclosure policy")

        missing_egress_authority = copy.deepcopy(valid_external)
        missing_egress_authority["disclosure_policy"].pop("egress_authority_root")
        with self.assertRaises(SchemaContractError):
            validate_instance(
                missing_egress_authority,
                request_schema,
                "external disclosure policy without authority root",
            )

        response_schema = load_schema(ROOT / "schemas" / "intent-evidence-response.schema.json")
        response = load_json(ROOT / "schemas" / "examples" / "intent-evidence-response.v2.json")
        response["evidence"].pop("payload_hash")
        with self.assertRaises(SchemaContractError):
            validate_instance(response, response_schema, "nested evidence required field")

        local_with_external_field = load_json(
            ROOT / "schemas" / "examples" / "intent-evidence-response.v2.json"
        )
        local_with_external_field["authentication"]["provider_key_id"] = "provider-v1"
        with self.assertRaises(SchemaContractError):
            validate_instance(local_with_external_field, response_schema, "local authentication")

        incomplete_external_auth = load_json(
            ROOT / "schemas" / "examples" / "intent-evidence-response.v2.json"
        )
        incomplete_external_auth["authentication"] = {
            "mode": "EXTERNAL",
            "provider_key_id": "provider-v1",
        }
        with self.assertRaises(SchemaContractError):
            validate_instance(incomplete_external_auth, response_schema, "external authentication")

        valid_external_auth = load_json(
            ROOT / "schemas" / "examples" / "intent-evidence-response.v2.json"
        )
        valid_external_auth["authentication"] = {
            "mode": "EXTERNAL",
            "provider_key_id": "provider-v1",
            "provider_trust_root": "sha256:" + "17" * 32,
            "challenge_hash": "sha256:" + "18" * 32,
            "issued_at": 1110,
            "valid_until": 1300,
            "cose_sign1": [132, 1, 2, 3],
        }
        validate_instance(valid_external_auth, response_schema, "valid external authentication")

    def test_external_disclosure_grant_shape_is_closed_and_bounded(self) -> None:
        schema = load_schema(
            ROOT / "schemas" / "external-evidence-disclosure-grant.schema.json"
        )
        grant = load_json(
            ROOT / "schemas" / "examples" / "external-evidence-disclosure-grant.v1.json"
        )

        for field in schema["required"]:
            mutated = copy.deepcopy(grant)
            mutated.pop(field)
            with self.subTest(required=field):
                with self.assertRaises(SchemaContractError):
                    validate_instance(mutated, schema, "external disclosure grant")

        for field, value in (
            ("evaluation_profile", "UNKNOWN_PROFILE"),
            ("stage", "UNKNOWN_STAGE"),
            ("source_request_hash", "sha256:" + "00" * 32),
            ("authority_key_id", " authority-v1"),
            ("issued_at", 0),
            ("cose_sign1", []),
            ("cose_sign1", [256]),
        ):
            mutated = copy.deepcopy(grant)
            mutated[field] = value
            with self.subTest(field=field, value=value):
                with self.assertRaises(SchemaContractError):
                    validate_instance(mutated, schema, "external disclosure grant mutation")

        oversized_key = copy.deepcopy(grant)
        oversized_key["authority_key_id"] = "a" * 257
        with self.assertRaises(SchemaContractError):
            validate_instance(oversized_key, schema, "oversized authority key identifier")

        oversized_cose = copy.deepcopy(grant)
        oversized_cose["cose_sign1"] = [0] * 1_048_577
        with self.assertRaises(SchemaContractError):
            validate_instance(oversized_cose, schema, "oversized COSE_Sign1")

    def test_pre_execution_profile_cannot_request_result_evidence(self) -> None:
        schema = load_schema(ROOT / "schemas" / "intent-evidence-request.schema.json")
        request = load_json(ROOT / "schemas" / "examples" / "intent-evidence-request.v2.json")
        request["stage"] = "RESULT"
        with self.assertRaises(SchemaContractError):
            validate_instance(request, schema, "pre-execution result request")


if __name__ == "__main__":
    unittest.main()
