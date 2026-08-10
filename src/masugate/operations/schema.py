"""The deliberately small JSON Schema subset used by operation packs."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import cast

from masugate.model import JsonValue

_SAFE_INTEGER_MIN = -9_007_199_254_740_991
_SAFE_INTEGER_MAX = 9_007_199_254_740_991
_IDENTIFIER_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/-")
_SECRET_MODEL_FIELD_PARTS = frozenset(
    {
        "credential",
        "credentials",
        "secret",
        "secrets",
        "token",
        "tokens",
        "password",
        "apikey",
        "privatekey",
        "accesskey",
    }
)
_SECRET_MODEL_FIELD_COMPOUNDS = frozenset({"api_key", "private_key", "access_key"})
_RESERVED_MODEL_FIELD_NAMES = frozenset(
    {
        "adapter",
        "adaptercapabilities",
        "adapterid",
        "agentid",
        "auditref",
        "authorization",
        "connectorid",
        "contractversion",
        "credential",
        "decision",
        "effect",
        "executionposition",
        "idempotencykey",
        "invocationid",
        "locator",
        "operationid",
        "pendingid",
        "policyid",
        "policyversion",
        "principal",
        "principalid",
        "principalref",
        "providerid",
        "receipt",
        "receiptref",
        "replayed",
        "retry",
        "retryauthority",
        "ruleid",
        "runid",
        "sessionid",
        "sessionkey",
        "sourceid",
        "sourceinvocation",
        "sourcenamespace",
        "stableid",
        "token",
        "toolcallid",
        "traceid",
    }
)


def canonical_json(value: JsonValue) -> str:
    """Canonical JSON shared by pack digests and deterministic compilation."""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def require_identifier(value: object, field: str, *, max_length: int = 256) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > max_length
        or any(character not in _IDENTIFIER_CHARS for character in value)
    ):
        raise ValueError(f"{field} must be a canonical identifier")
    return value


def require_digest(value: object, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def require_model_field(value: object, field: str) -> str:
    if type(value) is not str or len(value) > 256 or not value:
        raise ValueError(f"{field} must be a canonical model field")
    if value in {"__proto__", "prototype", "constructor"}:
        raise ValueError(f"{field} uses an unsafe object key")
    if value == "runtime" or value.startswith("model_"):
        raise ValueError(f"{field} uses a reserved generated-host name")
    if not ("a" <= value[0] <= "z"):
        raise ValueError(f"{field} must be lower_snake_case")
    for character in value:
        if not (
            character.isascii() and (character.islower() or character.isdigit() or character == "_")
        ):
            raise ValueError(f"{field} must be lower_snake_case")
    if "__" in value or value.endswith("_"):
        raise ValueError(f"{field} must be lower_snake_case")
    if value.replace("_", "") in _RESERVED_MODEL_FIELD_NAMES:
        raise ValueError(f"{field} uses a reserved trust-boundary name")
    parts = value.split("_")
    if any(part in _SECRET_MODEL_FIELD_PARTS for part in parts) or any(
        "_".join(parts[index : index + 2]) in _SECRET_MODEL_FIELD_COMPOUNDS
        for index in range(len(parts) - 1)
    ):
        raise ValueError(f"{field} cannot name secret or credential material")
    return value


def _record(value: object, field: str, *, max_entries: int | None = None) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    if max_entries is not None and len(value) > max_entries:
        raise ValueError(f"{field} must contain at most {max_entries} entries")
    if not all(type(key) is str for key in value):
        raise ValueError(f"{field} must be an object")
    return cast(Mapping[str, object], value)


def _integer(value: object, field: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer from {minimum} through {maximum}")
    return value


def _canonical_bytes(value: JsonValue) -> int:
    return len(canonical_json(value).encode("utf-8"))


class _SchemaByteBudget:
    """Incrementally account for the canonical bytes of one schema tree."""

    def __init__(self, limit: int, field: str) -> None:
        self.remaining = limit
        self.field = field

    def consume(self, amount: int) -> None:
        self.remaining -= amount
        if self.remaining < 0:
            raise ValueError(f"{self.field} canonical form exceeds configured limit")


def validate_bounded_schema(
    value: object,
    field: str,
    *,
    max_canonical_bytes: int,
    require_object_root: bool = False,
) -> dict[str, JsonValue]:
    """Validate and normalize one non-coercing, non-referencing schema.

    Supported nodes are objects, arrays, strings, JavaScript-safe integers and
    booleans.  Every string/array is explicitly bounded; every object closes
    its property set.  This gives hosts sufficient schema expressiveness
    without giving a deployment a JSON-Schema programming language.
    """

    if type(max_canonical_bytes) is not int or max_canonical_bytes <= 0:
        raise ValueError("schema canonical byte limit must be positive")
    budget = _SchemaByteBudget(max_canonical_bytes, field)

    def visit(raw: object, context: str, depth: int) -> dict[str, JsonValue]:
        if depth > 8:
            raise ValueError(f"{context} exceeds maximum schema nesting")
        schema = _record(raw, context, max_entries=5)
        schema_type = schema.get("type")
        if schema_type == "object":
            allowed = {"type", "properties", "required", "additionalProperties"}
            if set(schema) != allowed:
                raise ValueError(f"{context} object schemas must be closed and explicit")
            if schema["additionalProperties"] is not False:
                raise ValueError(f"{context}.additionalProperties must be false")
            properties = _record(schema["properties"], f"{context}.properties", max_entries=128)
            if not properties or len(properties) > 128:
                raise ValueError(f"{context}.properties must contain 1 through 128 fields")
            property_items = [
                (require_model_field(name, f"{context}.properties key"), child)
                for name, child in properties.items()
            ]
            property_names = {name for name, _child in property_items}
            required = schema["required"]
            if not isinstance(required, list | tuple):
                raise ValueError(f"{context}.required must be an array")
            if len(required) > len(property_items):
                raise ValueError(f"{context}.required must name unique declared properties")
            parsed_required: list[str] = []
            for index, name in enumerate(required):
                name = require_model_field(name, f"{context}.required[{index}]")
                if name not in property_names or name in parsed_required:
                    raise ValueError(f"{context}.required must be unique declared properties")
                parsed_required.append(name)
            parsed_required.sort()
            object_shell: dict[str, JsonValue] = {
                "type": "object",
                "properties": {},
                "required": cast(JsonValue, parsed_required),
                "additionalProperties": False,
            }
            budget.consume(
                _canonical_bytes(object_shell)
                + sum(_canonical_bytes(name) + 1 for name, _child in property_items)
                + len(property_items)
                - 1
            )
            parsed_properties: dict[str, JsonValue] = {
                name: visit(child, f"{context}.properties.{name}", depth + 1)
                for name, child in property_items
            }
            return {
                "type": "object",
                "properties": parsed_properties,
                "required": cast(JsonValue, parsed_required),
                "additionalProperties": False,
            }
        if schema_type == "array":
            if (
                set(schema) - {"type", "items", "minItems", "maxItems"}
                or "items" not in schema
                or "maxItems" not in schema
            ):
                raise ValueError(f"{context} array schemas permit only bounded items")
            maximum = _integer(schema["maxItems"], f"{context}.maxItems", minimum=0, maximum=1024)
            minimum = _integer(
                schema.get("minItems", 0), f"{context}.minItems", minimum=0, maximum=maximum
            )
            array_shell: dict[str, JsonValue] = {
                "type": "array",
                "items": None,
                "minItems": minimum,
                "maxItems": maximum,
            }
            budget.consume(_canonical_bytes(array_shell) - len("null"))
            return {
                "type": "array",
                "items": visit(schema["items"], f"{context}.items", depth + 1),
                "minItems": minimum,
                "maxItems": maximum,
            }
        if schema_type == "string":
            if set(schema) - {"type", "minLength", "maxLength"} or "maxLength" not in schema:
                raise ValueError(f"{context} strings must declare maxLength")
            maximum = _integer(
                schema["maxLength"], f"{context}.maxLength", minimum=0, maximum=65_536
            )
            minimum = _integer(
                schema.get("minLength", 0), f"{context}.minLength", minimum=0, maximum=maximum
            )
            string_schema: dict[str, JsonValue] = {
                "type": "string",
                "minLength": minimum,
                "maxLength": maximum,
            }
            budget.consume(_canonical_bytes(string_schema))
            return string_schema
        if schema_type == "integer":
            if set(schema) - {"type", "minimum", "maximum"}:
                raise ValueError(f"{context} integers permit only safe bounds")
            minimum = _integer(
                schema.get("minimum", _SAFE_INTEGER_MIN),
                f"{context}.minimum",
                minimum=_SAFE_INTEGER_MIN,
                maximum=_SAFE_INTEGER_MAX,
            )
            maximum = _integer(
                schema.get("maximum", _SAFE_INTEGER_MAX),
                f"{context}.maximum",
                minimum=minimum,
                maximum=_SAFE_INTEGER_MAX,
            )
            integer_schema: dict[str, JsonValue] = {
                "type": "integer",
                "minimum": minimum,
                "maximum": maximum,
            }
            budget.consume(_canonical_bytes(integer_schema))
            return integer_schema
        if schema_type == "boolean" and set(schema) == {"type"}:
            boolean_schema: dict[str, JsonValue] = {"type": "boolean"}
            budget.consume(_canonical_bytes(boolean_schema))
            return boolean_schema
        raise ValueError(f"{context}.type is unsupported")

    parsed = visit(value, field, 0)
    if require_object_root and parsed["type"] != "object":
        raise ValueError(f"{field} must be an object schema")
    if len(canonical_json(parsed).encode("utf-8")) > max_canonical_bytes:
        raise ValueError(f"{field} canonical form exceeds configured limit")
    return parsed
