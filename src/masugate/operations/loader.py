"""Strict loaders for the public operation-pack and private binding contracts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from masugate.model import JsonValue

from .schema import (
    canonical_json,
    require_digest,
    require_identifier,
    require_model_field,
    validate_bounded_schema,
)

OPERATION_PACK_VERSION = "masugate.operation-pack.v1"
OPERATION_DEPLOYMENT_BINDING_VERSION = "masugate.operation-deployment-binding.v1"
ROUTE_MANIFEST_V2_VERSION = "masugate.governed-route-manifest.v2"
CONNECTOR_CONTRACT_VERSION = "masugate.connector.v1"
DEFAULT_SCHEMA_CANONICAL_BYTES = 65_536
DEFAULT_OPERATION_PACK_CANONICAL_BYTES = 1_048_576
DEFAULT_ROUTE_MANIFEST_CANONICAL_BYTES = 1_048_576
MAX_OPERATION_PACK_ACTIONS = 64
MAX_OPERATION_ARTIFACT_FIELDS = 128
MAX_REQUIRED_CONNECTOR_CAPABILITIES = 64

Maturity = Literal["logical-only", "reference-effect", "production-profile"]
Position = Literal["transactional", "protected-external"]


def _record(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(type(key) is str for key in value):
        raise ValueError(f"{field} must be an object with string keys")
    return cast(Mapping[str, object], value)


def _exact(record: Mapping[str, object], fields: tuple[str, ...], field: str) -> None:
    unexpected = sorted(set(record) - set(fields))
    if unexpected:
        raise ValueError(f"{field} contains unsupported fields: {', '.join(unexpected)}")
    missing = sorted(set(fields) - set(record))
    if missing:
        raise ValueError(f"{field} is missing required fields: {', '.join(missing)}")


def _identifier_list(
    value: object,
    field: str,
    *,
    model_fields: bool = False,
    max_items: int | None = None,
) -> tuple[str, ...]:
    if not isinstance(value, list | tuple):
        raise ValueError(f"{field} must be an array")
    if max_items is not None and len(value) > max_items:
        raise ValueError(f"{field} must contain at most {max_items} entries")
    result: list[str] = []
    for index, item in enumerate(value):
        item_field = f"{field}[{index}]"
        parsed = (
            require_model_field(item, item_field)
            if model_fields
            else require_identifier(item, item_field)
        )
        if parsed in result:
            raise ValueError(f"{field} must not contain duplicates")
        result.append(parsed)
    return tuple(result)


@dataclass(frozen=True, slots=True)
class PackCompatibility:
    route_manifest: Literal["masugate.governed-route-manifest.v2"]
    connector_contract: Literal["masugate.connector.v1"]


@dataclass(frozen=True, slots=True)
class OperationAction:
    action: str
    input_schema: dict[str, JsonValue]
    public_result_schema: dict[str, JsonValue]
    artifact_fields: tuple[str, ...]
    owner_position: Position
    required_connector_capabilities: tuple[str, ...]
    maturity: Maturity


@dataclass(frozen=True, slots=True)
class OperationPack:
    pack_id: str
    version: str
    compatibility: PackCompatibility
    actions: tuple[OperationAction, ...]


@dataclass(frozen=True, slots=True)
class ProviderBinding:
    provider_id: str
    implementation_digest: str
    configuration_digest: str


@dataclass(frozen=True, slots=True)
class ConnectorBinding:
    connector_id: str
    version: str
    implementation_digest: str
    configuration_digest: str
    credential_refs: tuple[str, ...]
    allowed_destinations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DeploymentRouteBinding:
    action: str
    host_tool: str
    provider: ProviderBinding
    connector: ConnectorBinding | None


@dataclass(frozen=True, slots=True)
class OperationDeploymentBinding:
    pack_id: str
    pack_version: str
    pack_digest: str
    routes: tuple[DeploymentRouteBinding, ...]


def _compatibility(value: object) -> PackCompatibility:
    record = _record(value, "operation pack.compatibility")
    _exact(record, ("route_manifest", "connector_contract"), "operation pack.compatibility")
    if record["route_manifest"] != ROUTE_MANIFEST_V2_VERSION:
        raise ValueError("operation pack.compatibility.route_manifest is unsupported")
    if record["connector_contract"] != CONNECTOR_CONTRACT_VERSION:
        raise ValueError("operation pack.compatibility.connector_contract is unsupported")
    return PackCompatibility(
        route_manifest=cast(
            Literal["masugate.governed-route-manifest.v2"], ROUTE_MANIFEST_V2_VERSION
        ),
        connector_contract=cast(Literal["masugate.connector.v1"], CONNECTOR_CONTRACT_VERSION),
    )


def load_operation_pack(
    value: object,
    *,
    max_schema_canonical_bytes: int = DEFAULT_SCHEMA_CANONICAL_BYTES,
    max_pack_canonical_bytes: int = DEFAULT_OPERATION_PACK_CANONICAL_BYTES,
) -> OperationPack:
    """Parse a closed ``masugate.operation-pack.v1`` document.

    The caller supplies the trusted deployment path; this loader never follows
    references and intentionally accepts no extension or secret fields.
    """

    if type(max_schema_canonical_bytes) is not int or max_schema_canonical_bytes <= 0:
        raise ValueError("schema canonical byte limit must be positive")
    if type(max_pack_canonical_bytes) is not int or max_pack_canonical_bytes <= 0:
        raise ValueError("operation pack canonical byte limit must be positive")
    root = _record(value, "operation pack")
    _exact(
        root, ("contract_version", "id", "version", "compatibility", "actions"), "operation pack"
    )
    if root["contract_version"] != OPERATION_PACK_VERSION:
        raise ValueError("operation pack.contract_version is unsupported")
    pack_id = require_identifier(root["id"], "operation pack.id")
    version = require_identifier(root["version"], "operation pack.version")
    compatibility = _compatibility(root["compatibility"])
    raw_actions = root["actions"]
    if not isinstance(raw_actions, list | tuple) or not raw_actions:
        raise ValueError("operation pack.actions must be a non-empty array")
    if len(raw_actions) > MAX_OPERATION_PACK_ACTIONS:
        raise ValueError(
            f"operation pack.actions must contain at most {MAX_OPERATION_PACK_ACTIONS} entries"
        )
    actions: list[OperationAction] = []
    action_names: set[str] = set()
    for index, raw_action in enumerate(raw_actions):
        field = f"operation pack.actions[{index}]"
        action = _record(raw_action, field)
        _exact(
            action,
            (
                "action",
                "input_schema",
                "public_result_schema",
                "artifact_fields",
                "owner_position",
                "required_connector_capabilities",
                "maturity",
            ),
            field,
        )
        action_name = require_identifier(action["action"], f"{field}.action", max_length=255)
        if action_name in action_names:
            raise ValueError("operation pack.actions must not repeat action")
        action_names.add(action_name)
        input_schema = validate_bounded_schema(
            action["input_schema"],
            f"{field}.input_schema",
            max_canonical_bytes=max_schema_canonical_bytes,
            require_object_root=True,
        )
        result_schema = validate_bounded_schema(
            action["public_result_schema"],
            f"{field}.public_result_schema",
            max_canonical_bytes=max_schema_canonical_bytes,
        )
        artifact_fields = _identifier_list(
            action["artifact_fields"],
            f"{field}.artifact_fields",
            model_fields=True,
            max_items=MAX_OPERATION_ARTIFACT_FIELDS,
        )
        input_properties = cast(dict[str, JsonValue], input_schema["properties"])
        if any(name not in input_properties for name in artifact_fields):
            raise ValueError(f"{field}.artifact_fields must name input_schema properties")
        position = action["owner_position"]
        if position not in ("transactional", "protected-external"):
            raise ValueError(f"{field}.owner_position is invalid")
        capabilities = _identifier_list(
            action["required_connector_capabilities"],
            f"{field}.required_connector_capabilities",
            max_items=MAX_REQUIRED_CONNECTOR_CAPABILITIES,
        )
        if position == "transactional" and capabilities:
            raise ValueError(
                f"{field}.required_connector_capabilities requires protected-external position"
            )
        if artifact_fields:
            if position != "protected-external":
                raise ValueError(f"{field}.artifact_fields require protected-external position")
            required_fields = cast(list[str], input_schema["required"])
            for artifact_field in artifact_fields:
                property_schema = cast(dict[str, JsonValue], input_properties[artifact_field])
                if artifact_field not in required_fields or property_schema.get("type") != "string":
                    raise ValueError(
                        f"{field}.artifact_fields must be required bounded string properties"
                    )
        maturity = action["maturity"]
        if maturity not in ("logical-only", "reference-effect", "production-profile"):
            raise ValueError(f"{field}.maturity is invalid")
        if maturity == "production-profile" and position != "protected-external":
            raise ValueError(f"{field}.production-profile requires protected-external position")
        actions.append(
            OperationAction(
                action=action_name,
                input_schema=input_schema,
                public_result_schema=result_schema,
                artifact_fields=artifact_fields,
                owner_position=cast(Position, position),
                required_connector_capabilities=capabilities,
                maturity=cast(Maturity, maturity),
            )
        )
    actions.sort(key=lambda action: action.action)
    parsed = OperationPack(pack_id, version, compatibility, tuple(actions))
    if len(canonical_operation_pack(parsed).encode("utf-8")) > max_pack_canonical_bytes:
        raise ValueError("operation pack canonical form exceeds configured limit")
    return parsed


def load_deployment_binding(value: object) -> OperationDeploymentBinding:
    """Parse the server-only binding that may name credentials and destinations."""

    root = _record(value, "operation deployment binding")
    _exact(root, ("contract_version", "pack", "routes"), "operation deployment binding")
    if root["contract_version"] != OPERATION_DEPLOYMENT_BINDING_VERSION:
        raise ValueError("operation deployment binding.contract_version is unsupported")
    pack = _record(root["pack"], "operation deployment binding.pack")
    _exact(pack, ("id", "version", "digest"), "operation deployment binding.pack")
    raw_routes = root["routes"]
    if not isinstance(raw_routes, list | tuple) or not raw_routes:
        raise ValueError("operation deployment binding.routes must be a non-empty array")
    routes: list[DeploymentRouteBinding] = []
    action_names: set[str] = set()
    host_tools: set[str] = set()
    for index, raw_route in enumerate(raw_routes):
        field = f"operation deployment binding.routes[{index}]"
        route = _record(raw_route, field)
        if set(route) - {"action", "host_tool", "provider", "connector"}:
            raise ValueError(f"{field} contains unsupported fields")
        if not {"action", "host_tool", "provider"} <= set(route):
            raise ValueError(f"{field} is missing required fields")
        action = require_identifier(route["action"], f"{field}.action", max_length=255)
        host_tool = require_identifier(route["host_tool"], f"{field}.host_tool")
        if action in action_names or host_tool in host_tools:
            raise ValueError(
                "operation deployment binding routes must have unique action and host_tool"
            )
        action_names.add(action)
        host_tools.add(host_tool)
        provider = _record(route["provider"], f"{field}.provider")
        _exact(
            provider, ("id", "implementation_digest", "configuration_digest"), f"{field}.provider"
        )
        parsed_provider = ProviderBinding(
            provider_id=require_identifier(provider["id"], f"{field}.provider.id"),
            implementation_digest=require_digest(
                provider["implementation_digest"], f"{field}.provider.implementation_digest"
            ),
            configuration_digest=require_digest(
                provider["configuration_digest"], f"{field}.provider.configuration_digest"
            ),
        )
        parsed_connector: ConnectorBinding | None = None
        if "connector" in route:
            connector = _record(route["connector"], f"{field}.connector")
            _exact(
                connector,
                (
                    "id",
                    "version",
                    "implementation_digest",
                    "configuration_digest",
                    "credential_refs",
                    "allowed_destinations",
                ),
                f"{field}.connector",
            )
            parsed_connector = ConnectorBinding(
                connector_id=require_identifier(connector["id"], f"{field}.connector.id"),
                version=require_identifier(connector["version"], f"{field}.connector.version"),
                implementation_digest=require_digest(
                    connector["implementation_digest"], f"{field}.connector.implementation_digest"
                ),
                configuration_digest=require_digest(
                    connector["configuration_digest"], f"{field}.connector.configuration_digest"
                ),
                credential_refs=_identifier_list(
                    connector["credential_refs"], f"{field}.connector.credential_refs"
                ),
                allowed_destinations=_identifier_list(
                    connector["allowed_destinations"], f"{field}.connector.allowed_destinations"
                ),
            )
        routes.append(DeploymentRouteBinding(action, host_tool, parsed_provider, parsed_connector))
    routes.sort(key=lambda route: route.action)
    return OperationDeploymentBinding(
        pack_id=require_identifier(pack["id"], "operation deployment binding.pack.id"),
        pack_version=require_identifier(
            pack["version"], "operation deployment binding.pack.version"
        ),
        pack_digest=require_digest(pack["digest"], "operation deployment binding.pack.digest"),
        routes=tuple(routes),
    )


def _pack_json(pack: OperationPack) -> dict[str, JsonValue]:
    return {
        "contract_version": OPERATION_PACK_VERSION,
        "id": pack.pack_id,
        "version": pack.version,
        "compatibility": {
            "route_manifest": pack.compatibility.route_manifest,
            "connector_contract": pack.compatibility.connector_contract,
        },
        "actions": [
            {
                "action": action.action,
                "input_schema": action.input_schema,
                "public_result_schema": action.public_result_schema,
                "artifact_fields": list(action.artifact_fields),
                "owner_position": action.owner_position,
                "required_connector_capabilities": list(action.required_connector_capabilities),
                "maturity": action.maturity,
            }
            for action in pack.actions
        ],
    }


def canonical_operation_pack(value: OperationPack | object) -> str:
    pack = value if isinstance(value, OperationPack) else load_operation_pack(value)
    return canonical_json(_pack_json(pack))


def canonical_deployment_binding(value: OperationDeploymentBinding | object) -> str:
    binding = (
        value if isinstance(value, OperationDeploymentBinding) else load_deployment_binding(value)
    )
    return canonical_json(
        {
            "contract_version": OPERATION_DEPLOYMENT_BINDING_VERSION,
            "pack": {
                "id": binding.pack_id,
                "version": binding.pack_version,
                "digest": binding.pack_digest,
            },
            "routes": [
                {
                    "action": route.action,
                    "host_tool": route.host_tool,
                    "provider": {
                        "id": route.provider.provider_id,
                        "implementation_digest": route.provider.implementation_digest,
                        "configuration_digest": route.provider.configuration_digest,
                    },
                    **(
                        {}
                        if route.connector is None
                        else {
                            "connector": {
                                "id": route.connector.connector_id,
                                "version": route.connector.version,
                                "implementation_digest": route.connector.implementation_digest,
                                "configuration_digest": route.connector.configuration_digest,
                                "credential_refs": list(route.connector.credential_refs),
                                "allowed_destinations": list(route.connector.allowed_destinations),
                            }
                        }
                    ),
                }
                for route in binding.routes
            ],
        }
    )
