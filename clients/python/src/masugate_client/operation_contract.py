"""Public validators for the additive governed-route-manifest v2 contract."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TypeAlias, cast

from .adapter_contract import (
    GOVERNED_ROUTE_MANIFEST_VERSION,
    GovernedRouteManifest,
    _canonical_json,
    _identifier,
    _record,
    require_adapter_argument_name,
    validate_governed_route_manifest,
)
from .models import JsonValue

GOVERNED_ROUTE_MANIFEST_V2_VERSION = "masugate.governed-route-manifest.v2"
DEFAULT_ROUTE_SCHEMA_CANONICAL_BYTES = 65_536
DEFAULT_ROUTE_MANIFEST_CANONICAL_BYTES = 1_048_576
MAX_GOVERNED_ROUTE_MANIFEST_ROUTES = 64
MAX_ROUTE_ARTIFACT_FIELDS = 128
MAX_ROUTE_CONNECTOR_CAPABILITIES = 64
GovernedRouteManifestV2: TypeAlias = dict[str, JsonValue]
AnyGovernedRouteManifest: TypeAlias = GovernedRouteManifest | GovernedRouteManifestV2
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


def _model_field(value: object, field: str) -> str:
    if type(value) is not str:
        raise ValueError(f"{field} must be a model field")
    parsed = require_adapter_argument_name(value)
    if parsed == "runtime" or parsed.startswith("model_"):
        raise ValueError(f"{field} uses a reserved generated-host name")
    parts = parsed.split("_")
    if any(part in _SECRET_MODEL_FIELD_PARTS for part in parts) or any(
        "_".join(parts[index : index + 2]) in _SECRET_MODEL_FIELD_COMPOUNDS
        for index in range(len(parts) - 1)
    ):
        raise ValueError(f"{field} cannot name secret or credential material")
    return parsed


def _exact(value: Mapping[str, object], allowed: set[str], field: str) -> None:
    if set(value) != allowed:
        raise ValueError(f"{field} must contain exactly: {', '.join(sorted(allowed))}")


def _digest(value: object, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _integer(value: object, field: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{field} has invalid integer bounds")
    return value


def _schema_record(value: object, field: str, *, max_entries: int) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object with string keys")
    if len(value) > max_entries:
        raise ValueError(f"{field} must contain at most {max_entries} entries")
    if not all(type(key) is str for key in value):
        raise ValueError(f"{field} must be an object with string keys")
    return cast(Mapping[str, object], value)


def _canonical_bytes(value: JsonValue) -> int:
    return len(_canonical_json(value).encode("utf-8"))


class _SchemaByteBudget:
    """Incrementally account for the canonical bytes of one schema tree."""

    def __init__(self, limit: int, field: str) -> None:
        self.remaining = limit
        self.field = field

    def consume(self, amount: int) -> None:
        self.remaining -= amount
        if self.remaining < 0:
            raise ValueError(f"{self.field} canonical form exceeds configured limit")


def _schema(
    value: object, field: str, *, limit: int, object_root: bool = False
) -> dict[str, JsonValue]:
    budget = _SchemaByteBudget(limit, field)

    def visit(raw: object, context: str, depth: int) -> dict[str, JsonValue]:
        if depth > 8:
            raise ValueError(f"{context} exceeds maximum schema nesting")
        record = _schema_record(raw, context, max_entries=5)
        kind = record.get("type")
        if kind == "object":
            _exact(record, {"type", "properties", "required", "additionalProperties"}, context)
            if record["additionalProperties"] is not False:
                raise ValueError(f"{context}.additionalProperties must be false")
            properties = _schema_record(
                record["properties"], f"{context}.properties", max_entries=128
            )
            if not properties or len(properties) > 128:
                raise ValueError(f"{context}.properties must contain 1 through 128 fields")
            property_items = [
                (_model_field(name, f"{context}.properties key"), child)
                for name, child in properties.items()
            ]
            property_names = {name for name, _child in property_items}
            required_raw = record["required"]
            if not isinstance(required_raw, list | tuple):
                raise ValueError(f"{context}.required must be an array")
            if len(required_raw) > len(property_items):
                raise ValueError(f"{context}.required must name unique declared properties")
            required: list[str] = []
            for index, name in enumerate(required_raw):
                parsed_name = _model_field(name, f"{context}.required[{index}]")
                if parsed_name not in property_names or parsed_name in required:
                    raise ValueError(f"{context}.required must name unique declared properties")
                required.append(parsed_name)
            required.sort()
            object_shell: dict[str, JsonValue] = {
                "type": "object",
                "properties": {},
                "required": cast(JsonValue, required),
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
                "required": cast(JsonValue, required),
                "additionalProperties": False,
            }
        if kind == "array":
            allowed = {"type", "items", "minItems", "maxItems"}
            if set(record) - allowed or "items" not in record or "maxItems" not in record:
                raise ValueError(f"{context} array schemas must be explicitly bounded")
            maximum = _integer(record["maxItems"], f"{context}.maxItems", 0, 1024)
            minimum = _integer(record.get("minItems", 0), f"{context}.minItems", 0, maximum)
            array_shell: dict[str, JsonValue] = {
                "type": "array",
                "items": None,
                "minItems": minimum,
                "maxItems": maximum,
            }
            budget.consume(_canonical_bytes(array_shell) - len("null"))
            return {
                "type": "array",
                "items": visit(record["items"], f"{context}.items", depth + 1),
                "minItems": minimum,
                "maxItems": maximum,
            }
        if kind == "string":
            if set(record) - {"type", "minLength", "maxLength"} or "maxLength" not in record:
                raise ValueError(f"{context} strings must declare maxLength")
            maximum = _integer(record["maxLength"], f"{context}.maxLength", 0, 65_536)
            minimum = _integer(record.get("minLength", 0), f"{context}.minLength", 0, maximum)
            string_schema: dict[str, JsonValue] = {
                "type": "string",
                "minLength": minimum,
                "maxLength": maximum,
            }
            budget.consume(_canonical_bytes(string_schema))
            return string_schema
        if kind == "integer":
            if set(record) - {"type", "minimum", "maximum"}:
                raise ValueError(f"{context} integers permit only safe bounds")
            minimum = _integer(
                record.get("minimum", -9_007_199_254_740_991),
                f"{context}.minimum",
                -9_007_199_254_740_991,
                9_007_199_254_740_991,
            )
            maximum = _integer(
                record.get("maximum", 9_007_199_254_740_991),
                f"{context}.maximum",
                minimum,
                9_007_199_254_740_991,
            )
            integer_schema: dict[str, JsonValue] = {
                "type": "integer",
                "minimum": minimum,
                "maximum": maximum,
            }
            budget.consume(_canonical_bytes(integer_schema))
            return integer_schema
        if kind == "boolean" and set(record) == {"type"}:
            boolean_schema: dict[str, JsonValue] = {"type": "boolean"}
            budget.consume(_canonical_bytes(boolean_schema))
            return boolean_schema
        raise ValueError(f"{context}.type is unsupported")

    parsed = visit(value, field, 0)
    if object_root and parsed["type"] != "object":
        raise ValueError(f"{field} must be an object schema")
    if len(_canonical_json(parsed).encode("utf-8")) > limit:
        raise ValueError(f"{field} canonical form exceeds configured limit")
    return parsed


def validate_governed_route_manifest_v2(
    value: object,
    *,
    max_schema_canonical_bytes: int = DEFAULT_ROUTE_SCHEMA_CANONICAL_BYTES,
    max_manifest_canonical_bytes: int = DEFAULT_ROUTE_MANIFEST_CANONICAL_BYTES,
) -> GovernedRouteManifestV2:
    """Validate a public v2 route projection without accepting deployment secrets."""

    if type(max_schema_canonical_bytes) is not int or max_schema_canonical_bytes <= 0:
        raise ValueError("schema canonical byte limit must be positive")
    if type(max_manifest_canonical_bytes) is not int or max_manifest_canonical_bytes <= 0:
        raise ValueError("route manifest canonical byte limit must be positive")
    manifest = _record(value, "governed route manifest v2")
    _exact(manifest, {"contract_version", "pack", "routes"}, "governed route manifest v2")
    if manifest["contract_version"] != GOVERNED_ROUTE_MANIFEST_V2_VERSION:
        raise ValueError("governed route manifest v2.contract_version is unsupported")
    pack = _record(manifest["pack"], "governed route manifest v2.pack")
    _exact(pack, {"id", "version", "digest"}, "governed route manifest v2.pack")
    parsed_pack: dict[str, JsonValue] = {
        "id": _identifier(pack["id"], "governed route manifest v2.pack.id"),
        "version": _identifier(pack["version"], "governed route manifest v2.pack.version"),
        "digest": _digest(pack["digest"], "governed route manifest v2.pack.digest"),
    }
    raw_routes = manifest["routes"]
    if not isinstance(raw_routes, list | tuple) or not raw_routes:
        raise ValueError("governed route manifest v2.routes must be a non-empty array")
    if len(raw_routes) > MAX_GOVERNED_ROUTE_MANIFEST_ROUTES:
        raise ValueError(
            "governed route manifest v2.routes must contain at most "
            f"{MAX_GOVERNED_ROUTE_MANIFEST_ROUTES} entries"
        )
    routes: list[dict[str, JsonValue]] = []
    seen_host_tools: set[str] = set()
    seen_actions: set[str] = set()
    for index, raw_route in enumerate(raw_routes):
        field = f"governed route manifest v2.routes[{index}]"
        route = _record(raw_route, field)
        _exact(
            route,
            {
                "host_tool",
                "action",
                "input_schema",
                "public_result_schema",
                "artifact_fields",
                "owner",
                "required_connector_capabilities",
                "maturity",
                "compatibility",
            },
            field,
        )
        host_tool = _identifier(route["host_tool"], f"{field}.host_tool")
        if host_tool in seen_host_tools:
            raise ValueError("governed route manifest v2.routes must not repeat host_tool")
        seen_host_tools.add(host_tool)
        action = _identifier(route["action"], f"{field}.action", max_length=255)
        if action in seen_actions:
            raise ValueError("governed route manifest v2.routes must not repeat action")
        seen_actions.add(action)
        owner_raw = _record(route["owner"], f"{field}.owner")
        position = owner_raw.get("position")
        if position == "transactional":
            _exact(owner_raw, {"provider_id", "position"}, f"{field}.owner")
            owner: dict[str, JsonValue] = {
                "provider_id": _identifier(owner_raw["provider_id"], f"{field}.owner.provider_id"),
                "position": "transactional",
            }
        elif position == "protected-external":
            _exact(owner_raw, {"provider_id", "position", "connector_id"}, f"{field}.owner")
            owner = {
                "provider_id": _identifier(owner_raw["provider_id"], f"{field}.owner.provider_id"),
                "position": "protected-external",
                "connector_id": _identifier(
                    owner_raw["connector_id"], f"{field}.owner.connector_id"
                ),
            }
        else:
            raise ValueError(f"{field}.owner.position is invalid")
        artifact_raw = route["artifact_fields"]
        capabilities_raw = route["required_connector_capabilities"]
        if not isinstance(artifact_raw, list | tuple) or not isinstance(
            capabilities_raw, list | tuple
        ):
            raise ValueError(f"{field} artifact fields and capabilities must be arrays")
        if len(artifact_raw) > MAX_ROUTE_ARTIFACT_FIELDS:
            raise ValueError(
                f"{field}.artifact_fields must contain at most {MAX_ROUTE_ARTIFACT_FIELDS} entries"
            )
        if len(capabilities_raw) > MAX_ROUTE_CONNECTOR_CAPABILITIES:
            raise ValueError(
                f"{field}.required_connector_capabilities must contain at most "
                f"{MAX_ROUTE_CONNECTOR_CAPABILITIES} entries"
            )
        artifacts = [_model_field(name, f"{field}.artifact_fields") for name in artifact_raw]
        capabilities = [
            _identifier(name, f"{field}.required_connector_capabilities")
            for name in capabilities_raw
        ]
        if len(set(artifacts)) != len(artifacts) or len(set(capabilities)) != len(capabilities):
            raise ValueError(f"{field} arrays must not contain duplicates")
        if position == "transactional" and capabilities:
            raise ValueError(f"{field} transactional route cannot require connector capabilities")
        maturity = route["maturity"]
        if maturity not in ("reference-effect", "production-profile"):
            raise ValueError(f"{field}.maturity is invalid")
        if maturity == "production-profile" and position != "protected-external":
            raise ValueError(f"{field}.production-profile requires protected-external position")
        compatibility = _record(route["compatibility"], f"{field}.compatibility")
        _exact(compatibility, {"route_manifest", "connector_contract"}, f"{field}.compatibility")
        if (
            compatibility["route_manifest"] != GOVERNED_ROUTE_MANIFEST_V2_VERSION
            or compatibility["connector_contract"] != "masugate.connector.v1"
        ):
            raise ValueError(f"{field}.compatibility is unsupported")
        input_schema = _schema(
            route["input_schema"],
            f"{field}.input_schema",
            limit=max_schema_canonical_bytes,
            object_root=True,
        )
        properties = cast(dict[str, JsonValue], input_schema["properties"])
        if any(name not in properties for name in artifacts):
            raise ValueError(f"{field}.artifact_fields must name input properties")
        if artifacts:
            if position != "protected-external":
                raise ValueError(f"{field}.artifact_fields require protected-external position")
            required = cast(list[str], input_schema["required"])
            for artifact in artifacts:
                property_schema = cast(dict[str, JsonValue], properties[artifact])
                if artifact not in required or property_schema.get("type") != "string":
                    raise ValueError(
                        f"{field}.artifact_fields must be required bounded string properties"
                    )
        routes.append(
            {
                "host_tool": host_tool,
                "action": action,
                "input_schema": input_schema,
                "public_result_schema": _schema(
                    route["public_result_schema"],
                    f"{field}.public_result_schema",
                    limit=max_schema_canonical_bytes,
                ),
                "artifact_fields": cast(JsonValue, artifacts),
                "owner": owner,
                "required_connector_capabilities": cast(JsonValue, capabilities),
                "maturity": cast(JsonValue, maturity),
                "compatibility": {
                    "route_manifest": GOVERNED_ROUTE_MANIFEST_V2_VERSION,
                    "connector_contract": "masugate.connector.v1",
                },
            }
        )
    routes.sort(key=lambda item: cast(str, item["host_tool"]))
    parsed: GovernedRouteManifestV2 = {
        "contract_version": GOVERNED_ROUTE_MANIFEST_V2_VERSION,
        "pack": parsed_pack,
        "routes": cast(JsonValue, routes),
    }
    if len(_canonical_json(parsed).encode("utf-8")) > max_manifest_canonical_bytes:
        raise ValueError("governed route manifest v2 canonical form exceeds configured limit")
    return parsed


def validate_any_governed_route_manifest(value: object) -> AnyGovernedRouteManifest:
    if (
        isinstance(value, Mapping)
        and value.get("contract_version") == GOVERNED_ROUTE_MANIFEST_VERSION
    ):
        return validate_governed_route_manifest(value)
    return validate_governed_route_manifest_v2(value)


def canonical_governed_route_manifest_v2(value: object) -> str:
    return _canonical_json(validate_governed_route_manifest_v2(value))


def canonical_any_governed_route_manifest(value: object) -> str:
    if (
        isinstance(value, Mapping)
        and value.get("contract_version") == GOVERNED_ROUTE_MANIFEST_VERSION
    ):
        from .adapter_contract import canonical_governed_route_manifest

        return canonical_governed_route_manifest(value)
    return canonical_governed_route_manifest_v2(value)
