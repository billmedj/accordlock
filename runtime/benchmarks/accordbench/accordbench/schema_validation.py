"""Small, dependency-free validator for AccordBench's shipped JSON Schemas.

This is deliberately not a general JSON Schema implementation.  It supports
the exact Draft 2020-12 assertion subset used by the contracts in ``schemas``
and rejects schema keywords outside that subset.  That keeps the executable
contract auditable instead of silently accepting constraints it cannot check.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping


ANNOTATION_KEYWORDS = {"$schema", "$id", "title", "description"}
ASSERTION_KEYWORDS = {
    "$ref",
    "type",
    "enum",
    "const",
    "pattern",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "required",
    "properties",
    "additionalProperties",
    "items",
    "minItems",
    "maxItems",
    "uniqueItems",
    "allOf",
    "oneOf",
    "if",
    "then",
    "else",
    "not",
    "$defs",
}
SUPPORTED_TYPES = {"object", "array", "string", "boolean", "integer", "number", "null"}


class SchemaContractError(ValueError):
    """Raised when a schema is unsupported or an instance violates it."""


def load_schema(path: Path | str) -> dict[str, Any]:
    schema_path = Path(path)
    try:
        value = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SchemaContractError(f"cannot load schema {schema_path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SchemaContractError(f"schema {schema_path} must be a JSON object")
    _assert_supported_schema(value, "$")
    return value


def validate_instance(instance: Any, schema: Mapping[str, Any], source: str = "instance") -> None:
    """Validate ``instance`` against the supported schema subset."""

    _assert_supported_schema(schema, "$")
    _validate(instance, schema, schema, source)


def validate_file(instance: Any, schema_path: Path | str, source: str = "instance") -> None:
    """Load a shipped schema and validate one instance against it."""

    validate_instance(instance, load_schema(schema_path), source)


def _assert_supported_schema(schema: Mapping[str, Any], location: str) -> None:
    if not isinstance(schema, Mapping):
        raise SchemaContractError(f"{location}: schemas must be objects")
    unsupported = sorted(set(schema) - ANNOTATION_KEYWORDS - ASSERTION_KEYWORDS)
    if unsupported:
        raise SchemaContractError(
            f"{location}: unsupported schema keyword(s): {', '.join(unsupported)}"
        )

    if "$ref" in schema and not isinstance(schema["$ref"], str):
        raise SchemaContractError(f"{location}.$ref: must be text")
    if "type" in schema:
        declared = schema["type"]
        declared_types = [declared] if isinstance(declared, str) else declared
        if (
            not isinstance(declared_types, list)
            or not declared_types
            or any(
                not isinstance(item, str) or item not in SUPPORTED_TYPES
                for item in declared_types
            )
            or len(declared_types) != len(set(declared_types))
        ):
            raise SchemaContractError(f"{location}.type: unsupported or duplicate type")
    if "enum" in schema and (not isinstance(schema["enum"], list) or not schema["enum"]):
        raise SchemaContractError(f"{location}.enum: must be a non-empty array")
    if "pattern" in schema:
        pattern = schema["pattern"]
        if not isinstance(pattern, str):
            raise SchemaContractError(f"{location}.pattern: must be text")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise SchemaContractError(f"{location}.pattern: invalid regular expression: {exc}") from exc
    if "required" in schema:
        required = schema["required"]
        if (
            not isinstance(required, list)
            or any(not isinstance(item, str) for item in required)
            or len(required) != len(set(required))
        ):
            raise SchemaContractError(f"{location}.required: must contain unique strings")
    for integer_keyword in ("minLength", "maxLength", "minItems", "maxItems"):
        if integer_keyword in schema:
            bound = schema[integer_keyword]
            if not isinstance(bound, int) or isinstance(bound, bool) or bound < 0:
                raise SchemaContractError(f"{location}.{integer_keyword}: must be a non-negative integer")
    for numeric_keyword in ("minimum", "maximum"):
        if numeric_keyword in schema:
            bound = schema[numeric_keyword]
            if not isinstance(bound, (int, float)) or isinstance(bound, bool):
                raise SchemaContractError(f"{location}.{numeric_keyword}: must be numeric")
    if "uniqueItems" in schema and not isinstance(schema["uniqueItems"], bool):
        raise SchemaContractError(f"{location}.uniqueItems: must be boolean")

    for container_key in ("properties", "$defs"):
        container = schema.get(container_key, {})
        if not isinstance(container, Mapping):
            raise SchemaContractError(f"{location}.{container_key}: must be an object")
        for name, child in container.items():
            _assert_supported_schema(child, f"{location}.{container_key}.{name}")

    additional = schema.get("additionalProperties")
    if isinstance(additional, Mapping):
        _assert_supported_schema(additional, f"{location}.additionalProperties")
    elif additional is not None and not isinstance(additional, bool):
        raise SchemaContractError(f"{location}.additionalProperties: must be boolean or schema")

    for child_key in ("items", "if", "then", "else", "not"):
        if child_key in schema:
            _assert_supported_schema(schema[child_key], f"{location}.{child_key}")
    for children_key in ("allOf", "oneOf"):
        if children_key in schema:
            children = schema[children_key]
            if not isinstance(children, list) or not children:
                raise SchemaContractError(f"{location}.{children_key}: must be a non-empty array")
            for index, child in enumerate(children):
                _assert_supported_schema(child, f"{location}.{children_key}[{index}]")


def _resolve_ref(root: Mapping[str, Any], reference: str) -> Mapping[str, Any]:
    if not reference.startswith("#/"):
        raise SchemaContractError(f"unsupported non-local schema reference: {reference}")
    current: Any = root
    for token in reference[2:].split("/"):
        key = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or key not in current:
            raise SchemaContractError(f"unresolved schema reference: {reference}")
        current = current[key]
    if not isinstance(current, Mapping):
        raise SchemaContractError(f"schema reference is not an object: {reference}")
    return current


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "null":
        return value is None
    raise SchemaContractError(f"unsupported schema type: {expected}")


def _is_valid(value: Any, schema: Mapping[str, Any], root: Mapping[str, Any]) -> bool:
    try:
        _validate(value, schema, root, "conditional")
    except SchemaContractError:
        return False
    return True


def _validate(value: Any, schema: Mapping[str, Any], root: Mapping[str, Any], location: str) -> None:
    if "$ref" in schema:
        reference = schema["$ref"]
        if not isinstance(reference, str):
            raise SchemaContractError(f"{location}: $ref must be text")
        _validate(value, _resolve_ref(root, reference), root, location)

    if "allOf" in schema:
        for child in schema["allOf"]:
            _validate(value, child, root, location)

    if "oneOf" in schema:
        matches = sum(_is_valid(value, child, root) for child in schema["oneOf"])
        if matches != 1:
            raise SchemaContractError(f"{location}: must match exactly one oneOf branch")

    if "not" in schema and _is_valid(value, schema["not"], root):
        raise SchemaContractError(f"{location}: matches a forbidden schema")

    if "if" in schema:
        branch = "then" if _is_valid(value, schema["if"], root) else "else"
        if branch in schema:
            _validate(value, schema[branch], root, location)

    expected_type = schema.get("type")
    if expected_type is not None:
        expected_types = [expected_type] if isinstance(expected_type, str) else expected_type
        if not isinstance(expected_types, list) or not expected_types:
            raise SchemaContractError(f"{location}: schema type must be text or a non-empty array")
        if not any(isinstance(item, str) and _type_matches(value, item) for item in expected_types):
            rendered = ", ".join(str(item) for item in expected_types)
            raise SchemaContractError(f"{location}: expected type {rendered}")

    if "const" in schema and value != schema["const"]:
        raise SchemaContractError(f"{location}: expected constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        raise SchemaContractError(f"{location}: value is not in the allowed set")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            raise SchemaContractError(f"{location}: text is shorter than minLength")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            raise SchemaContractError(f"{location}: text is longer than maxLength")
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            raise SchemaContractError(f"{location}: text does not match pattern")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise SchemaContractError(f"{location}: value is below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise SchemaContractError(f"{location}: value is above maximum")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            raise SchemaContractError(f"{location}: array is shorter than minItems")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise SchemaContractError(f"{location}: array is longer than maxItems")
        if schema.get("uniqueItems"):
            canonical = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            if len(canonical) != len(set(canonical)):
                raise SchemaContractError(f"{location}: array items must be unique")
        if "items" in schema:
            for index, item in enumerate(value):
                _validate(item, schema["items"], root, f"{location}[{index}]")

    if isinstance(value, dict):
        required = schema.get("required", [])
        missing = [key for key in required if key not in value]
        if missing:
            raise SchemaContractError(f"{location}: missing required field(s): {', '.join(missing)}")

        properties = schema.get("properties", {})
        for key, child in properties.items():
            if key in value:
                _validate(value[key], child, root, f"{location}.{key}")

        extra = sorted(set(value) - set(properties))
        additional = schema.get("additionalProperties", True)
        if additional is False and extra:
            raise SchemaContractError(f"{location}: unsupported field(s): {', '.join(extra)}")
        if isinstance(additional, Mapping):
            for key in extra:
                _validate(value[key], additional, root, f"{location}.{key}")
