"""Compilation from a public operation pack plus private deployment binding."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from importlib import metadata
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, cast

from masugate_connector_sdk import (
    SDK_CONTRACT_VERSION,
    ConnectorCapabilities,
    ConnectorSDKError,
    OperationConnector,
    validate_operation_connector,
)

from masugate.errors import ContractError
from masugate.model import JsonValue
from masugate.provider_assembly import EffectExecutionPosition, ProviderAssembly

from .loader import (
    CONNECTOR_CONTRACT_VERSION,
    DEFAULT_ROUTE_MANIFEST_CANONICAL_BYTES,
    ROUTE_MANIFEST_V2_VERSION,
    ConnectorBinding,
    DeploymentRouteBinding,
    OperationDeploymentBinding,
    OperationPack,
    canonical_operation_pack,
)
from .schema import canonical_json, require_digest, require_identifier

if TYPE_CHECKING:
    from masugate.contracts import ProviderIdentity


def provider_identity_digests(identity: ProviderIdentity) -> tuple[str, str]:
    """Derive stable binding digests from the exact assembled provider identity."""

    return (
        sha256(
            canonical_json(
                {
                    "provider_id": identity.provider_id,
                    "implementation_version": identity.implementation_version,
                }
            ).encode("utf-8")
        ).hexdigest(),
        sha256(
            canonical_json(
                {
                    "provider_id": identity.provider_id,
                    "configuration_version": identity.configuration_version,
                }
            ).encode("utf-8")
        ).hexdigest(),
    )


@dataclass(frozen=True, slots=True)
class ConnectorRegistration:
    """Trusted runtime identity and capabilities of one installed connector."""

    connector_id: str
    version: str
    package_id: str
    package_version: str
    entry_point: str
    sdk_contract_version: str
    implementation_digest: str
    configuration_digest: str
    credential_refs: tuple[str, ...]
    allowed_destinations: tuple[str, ...]
    capabilities: frozenset[str]
    capability_profile: ConnectorCapabilities
    maturity: Literal["reference-effect", "production-profile"]

    def __post_init__(self) -> None:
        for field_name in (
            "connector_id",
            "version",
            "package_id",
            "package_version",
            "entry_point",
            "sdk_contract_version",
        ):
            require_identifier(getattr(self, field_name), f"connector registration {field_name}")
        require_digest(self.implementation_digest, "connector registration implementation digest")
        require_digest(self.configuration_digest, "connector registration configuration digest")
        for field_name in ("credential_refs", "allowed_destinations"):
            values = tuple(
                require_identifier(value, f"connector registration {field_name}", max_length=255)
                for value in getattr(self, field_name)
            )
            if len(set(values)) != len(values):
                raise ValueError(f"connector registration {field_name} must be unique")
            object.__setattr__(self, field_name, tuple(sorted(values)))
        if self.sdk_contract_version != SDK_CONTRACT_VERSION:
            raise ValueError("connector registration SDK contract version is unsupported")
        if type(self.capability_profile) is not ConnectorCapabilities:
            raise TypeError("connector registration needs ConnectorCapabilities")
        if self.capabilities != self.capability_profile.names:
            raise ValueError("connector registration labels do not match its capability profile")
        if self.maturity not in {"reference-effect", "production-profile"}:
            raise ValueError("connector registration maturity is invalid")


class ConnectorRegistry:
    """Closed registry used only by trusted startup composition."""

    def __init__(self, registrations: Iterable[ConnectorRegistration] = ()) -> None:
        registered: dict[str, ConnectorRegistration] = {}
        for registration in registrations:
            if not isinstance(registration, ConnectorRegistration):
                raise TypeError("connector registry values must be ConnectorRegistration")
            if registration.connector_id in registered:
                raise ValueError(f"connector registry repeats {registration.connector_id!r}")
            registered[registration.connector_id] = registration
        self._registrations = MappingProxyType(registered)

    def get(self, connector_id: str) -> ConnectorRegistration:
        try:
            return self._registrations[connector_id]
        except KeyError as exc:
            raise ContractError(
                f"operation route names an unregistered connector: {connector_id}"
            ) from exc


def _capability_profile(value: object, field: str) -> ConnectorCapabilities:
    if not isinstance(value, dict) or set(value) != {
        "idempotent_dispatch",
        "status_query",
        "cancellation",
        "fencing",
        "max_payload_bytes",
        "max_result_bytes",
        "ambiguity_handling",
    }:
        raise ValueError(f"{field} must be a closed capability profile")
    try:
        return ConnectorCapabilities(
            idempotent_dispatch=cast(bool, value["idempotent_dispatch"]),
            status_query=cast(bool, value["status_query"]),
            cancellation=cast(bool, value["cancellation"]),
            fencing=cast(bool, value["fencing"]),
            max_payload_bytes=cast(int, value["max_payload_bytes"]),
            max_result_bytes=cast(int, value["max_result_bytes"]),
            ambiguity_handling=cast(str | None, value["ambiguity_handling"]),
        )
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} is invalid") from exc


def load_connector_registry(value: object) -> ConnectorRegistry:
    """Load a closed server-side connector identity registry."""

    if not isinstance(value, dict) or set(value) != {"contract_version", "connectors"}:
        raise ValueError("connector registry must contain only contract_version and connectors")
    if value["contract_version"] != "masugate.connector-registry.v2":
        raise ValueError("connector registry.contract_version is unsupported")
    raw_connectors = value["connectors"]
    if not isinstance(raw_connectors, list):
        raise ValueError("connector registry.connectors must be an array")
    registrations: list[ConnectorRegistration] = []
    for index, raw_connector in enumerate(raw_connectors):
        field = f"connector registry.connectors[{index}]"
        if not isinstance(raw_connector, dict) or set(raw_connector) != {
            "id",
            "version",
            "package_id",
            "package_version",
            "entry_point",
            "sdk_contract_version",
            "implementation_digest",
            "configuration_digest",
            "credential_refs",
            "allowed_destinations",
            "capabilities",
            "capability_profile",
            "maturity",
        }:
            raise ValueError(f"{field} must be a closed connector registration")
        capabilities = raw_connector["capabilities"]
        if not isinstance(capabilities, list) or not all(
            type(item) is str for item in capabilities
        ):
            raise ValueError(f"{field}.capabilities must be an array of identifiers")
        parsed_capabilities = frozenset(
            require_identifier(item, f"{field}.capabilities") for item in capabilities
        )
        if len(parsed_capabilities) != len(capabilities):
            raise ValueError(f"{field}.capabilities must not contain duplicates")
        maturity = raw_connector["maturity"]
        if maturity not in ("reference-effect", "production-profile"):
            raise ValueError(f"{field}.maturity is invalid")
        profile = _capability_profile(raw_connector["capability_profile"], f"{field}.profile")
        registrations.append(
            ConnectorRegistration(
                connector_id=require_identifier(raw_connector["id"], f"{field}.id"),
                version=require_identifier(raw_connector["version"], f"{field}.version"),
                package_id=require_identifier(raw_connector["package_id"], f"{field}.package_id"),
                package_version=require_identifier(
                    raw_connector["package_version"], f"{field}.package_version"
                ),
                entry_point=require_identifier(
                    raw_connector["entry_point"], f"{field}.entry_point"
                ),
                sdk_contract_version=require_identifier(
                    raw_connector["sdk_contract_version"], f"{field}.sdk_contract_version"
                ),
                implementation_digest=require_digest(
                    raw_connector["implementation_digest"], f"{field}.implementation_digest"
                ),
                configuration_digest=require_digest(
                    raw_connector["configuration_digest"], f"{field}.configuration_digest"
                ),
                credential_refs=_identifier_tuple(
                    raw_connector["credential_refs"], f"{field}.credential_refs"
                ),
                allowed_destinations=_identifier_tuple(
                    raw_connector["allowed_destinations"], f"{field}.allowed_destinations"
                ),
                capabilities=parsed_capabilities,
                capability_profile=profile,
                maturity=cast(Literal["reference-effect", "production-profile"], maturity),
            )
        )
    return ConnectorRegistry(registrations)


def _identifier_tuple(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{field} must be an array of identifiers")
    parsed = tuple(require_identifier(item, field) for item in value)
    if len(set(parsed)) != len(parsed):
        raise ValueError(f"{field} must not contain duplicates")
    return tuple(sorted(parsed))


def load_registered_connector(
    registry: ConnectorRegistry,
    connector_id: str,
) -> OperationConnector:
    """Load exactly one deployment-selected external package entry point.

    This function receives only the closed server registry—not a host/module
    string—and checks distribution, entry-point, SDK, identity, and full
    capability profile before the worker can hold a secret or handoff.
    """

    if type(registry) is not ConnectorRegistry:
        raise TypeError("registered connector loader needs ConnectorRegistry")
    registration = registry.get(connector_id)
    try:
        distribution = metadata.distribution(registration.package_id)
    except metadata.PackageNotFoundError as exc:
        raise ContractError("registered connector package is not installed") from exc
    if (
        distribution.metadata.get("Name") != registration.package_id
        or distribution.version != registration.package_version
    ):
        raise ContractError("registered connector package identity drifted")
    if _distribution_implementation_digest(distribution) != registration.implementation_digest:
        raise ContractError("registered connector implementation digest drifted")
    matches = tuple(
        entry
        for entry in metadata.entry_points(
            group="masugate.connector", name=registration.entry_point
        )
        if entry.dist is not None
        and entry.dist.metadata.get("Name") == registration.package_id
        and entry.dist.version == registration.package_version
    )
    if len(matches) != 1:
        raise ContractError("registered connector entry point is absent or ambiguous")
    try:
        connector = validate_operation_connector(matches[0].load())
    except (ConnectorSDKError, ImportError, AttributeError, TypeError, ValueError) as exc:
        raise ContractError("registered connector entry point violates the SDK contract") from exc
    if connector.connector_id != registration.connector_id:
        raise ContractError("registered connector identity drifted")
    if connector.sdk_contract_version != registration.sdk_contract_version:
        raise ContractError("registered connector SDK contract drifted")
    if connector.capabilities != registration.capability_profile:
        raise ContractError("registered connector capability profile drifted")
    return connector


def _distribution_implementation_digest(distribution: metadata.Distribution) -> str:
    """Hash installed distribution members rather than trusting package metadata."""

    members: list[dict[str, str]] = []
    for member in sorted(distribution.files or (), key=str):
        # Installer bookkeeping must not alter the implementation identity.
        # Bind code and distribution metadata, but omit the files a package
        # installer can create or rewrite after the wheel has been verified.
        if str(member).endswith(
            (
                ".dist-info/RECORD",
                ".dist-info/INSTALLER",
                ".dist-info/REQUESTED",
                ".dist-info/direct_url.json",
            )
        ):
            continue
        location = Path(str(distribution.locate_file(member)))
        if not location.is_file():
            raise ContractError("registered connector distribution member is unavailable")
        members.append(
            {
                "path": str(member),
                "sha256": sha256(location.read_bytes()).hexdigest(),
            }
        )
    if not members:
        raise ContractError("registered connector distribution has no hashed members")
    return sha256(canonical_json(cast(JsonValue, members)).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class CompiledOperationRoutes:
    """Public adapter projection plus private trusted bindings.

    ``route_manifest`` is the only member an adapter or model host receives.
    The private binding retains deployment-only digest, credential-reference,
    and destination facts for startup/worker composition.
    """

    route_manifest: dict[str, JsonValue]
    deployment_binding: OperationDeploymentBinding
    operation_pack: OperationPack
    _canonical_route_manifest: str

    @property
    def canonical_route_manifest(self) -> str:
        """Return the compiler-certified manifest bytes, not a mutable projection."""

        return self._canonical_route_manifest


def _owner(
    route: DeploymentRouteBinding, position: Literal["transactional", "protected-external"]
) -> dict[str, JsonValue]:
    owner: dict[str, JsonValue] = {"provider_id": route.provider.provider_id, "position": position}
    if position == "protected-external":
        assert route.connector is not None
        owner["connector_id"] = route.connector.connector_id
    return owner


def compile_operation_pack(
    pack: OperationPack,
    binding: OperationDeploymentBinding,
    *,
    max_route_manifest_canonical_bytes: int = DEFAULT_ROUTE_MANIFEST_CANONICAL_BYTES,
) -> CompiledOperationRoutes:
    """Merge one exact pack/binding pair without leaking private configuration."""

    if (
        type(max_route_manifest_canonical_bytes) is not int
        or max_route_manifest_canonical_bytes <= 0
    ):
        raise ValueError("route manifest canonical byte limit must be positive")
    if binding.pack_id != pack.pack_id or binding.pack_version != pack.version:
        raise ContractError("operation deployment binding does not select the loaded pack version")
    actual_digest = sha256(canonical_operation_pack(pack).encode("utf-8")).hexdigest()
    if binding.pack_digest != actual_digest:
        raise ContractError("operation deployment binding pack digest does not match loaded pack")
    action_by_name = {action.action: action for action in pack.actions}
    binding_by_action = {route.action: route for route in binding.routes}
    if set(binding_by_action) != set(action_by_name):
        raise ContractError("operation deployment binding must bind every and only pack actions")
    routes: list[dict[str, JsonValue]] = []
    for action_name, action in action_by_name.items():
        route = binding_by_action[action_name]
        if action.maturity == "logical-only":
            raise ContractError(
                "logical-only operation actions cannot be compiled into agent tools"
            )
        if action.owner_position == "transactional":
            if route.connector is not None:
                raise ContractError(
                    f"transactional operation {action_name!r} cannot bind a connector"
                )
        elif route.connector is None:
            raise ContractError(f"protected operation {action_name!r} requires a connector binding")
        routes.append(
            {
                "host_tool": route.host_tool,
                "action": action_name,
                "input_schema": action.input_schema,
                "public_result_schema": action.public_result_schema,
                "artifact_fields": list(action.artifact_fields),
                "owner": _owner(route, action.owner_position),
                "required_connector_capabilities": list(action.required_connector_capabilities),
                "maturity": action.maturity,
                "compatibility": {
                    "route_manifest": ROUTE_MANIFEST_V2_VERSION,
                    "connector_contract": CONNECTOR_CONTRACT_VERSION,
                },
            }
        )
    routes.sort(key=lambda route: cast(str, route["host_tool"]))
    route_manifest: dict[str, JsonValue] = {
        "contract_version": ROUTE_MANIFEST_V2_VERSION,
        "pack": {"id": pack.pack_id, "version": pack.version, "digest": actual_digest},
        "routes": cast(JsonValue, routes),
    }
    canonical_route_manifest = canonical_json(route_manifest)
    if len(canonical_route_manifest.encode("utf-8")) > max_route_manifest_canonical_bytes:
        raise ContractError("compiled operation route manifest exceeds configured byte limit")
    return CompiledOperationRoutes(
        route_manifest=route_manifest,
        deployment_binding=binding,
        operation_pack=pack,
        _canonical_route_manifest=canonical_route_manifest,
    )


def _provider_for_action(assembly: ProviderAssembly, action: str) -> ProviderIdentity:
    assembled = assembly.action(action)
    module = next(
        module for module in assembly.modules if module.module_id == assembled.effect_owner
    )
    return module.identity


def _validate_connector(
    action: str,
    binding: ConnectorBinding,
    required_capabilities: tuple[str, ...],
    registry: ConnectorRegistry,
) -> None:
    registered = registry.get(binding.connector_id)
    if (
        registered.version != binding.version
        or registered.implementation_digest != binding.implementation_digest
        or registered.configuration_digest != binding.configuration_digest
        or registered.credential_refs != binding.credential_refs
        or registered.allowed_destinations != binding.allowed_destinations
    ):
        raise ContractError(f"operation route connector configuration drift: {action}")
    if not set(required_capabilities) <= registered.capabilities:
        raise ContractError(f"operation route connector lacks required capability: {action}")


def validate_compiled_operation_routes(
    compiled: CompiledOperationRoutes,
    assembly: ProviderAssembly,
    connector_registry: ConnectorRegistry,
) -> None:
    """Fail startup if public routes no longer match installed protected owners."""

    if canonical_json(compiled.route_manifest) != compiled.canonical_route_manifest:
        raise ContractError("compiled operation route manifest was modified after compilation")
    action_by_name = {action.action: action for action in compiled.operation_pack.actions}
    binding_by_action = {route.action: route for route in compiled.deployment_binding.routes}
    if set(action_by_name) != set(binding_by_action):  # pragma: no cover - compiler invariant
        raise ContractError("compiled operation routes no longer match the deployment binding")
    for action_name in sorted(action_by_name):
        action = action_by_name[action_name]
        binding = binding_by_action[action_name]
        assembled = assembly.action(action_name)
        expected_position = EffectExecutionPosition(action.owner_position)
        expected_connector_id = (
            None if binding.connector is None else binding.connector.connector_id
        )
        if (
            assembled.position is not expected_position
            or assembled.connector_id != expected_connector_id
        ):
            raise ContractError(f"operation route owner drift: {action_name}")
        identity = _provider_for_action(assembly, action_name)
        implementation_digest, configuration_digest = provider_identity_digests(identity)
        if (
            identity.provider_id != binding.provider.provider_id
            or binding.provider.implementation_digest != implementation_digest
            or binding.provider.configuration_digest != configuration_digest
        ):
            raise ContractError(f"operation route provider configuration drift: {action_name}")
        if expected_position is EffectExecutionPosition.PROTECTED_EXTERNAL:
            assert binding.connector is not None
            _validate_connector(
                action_name,
                binding.connector,
                action.required_connector_capabilities,
                connector_registry,
            )
            registered = connector_registry.get(binding.connector.connector_id)
            maturity_rank = {"reference-effect": 1, "production-profile": 2}
            if maturity_rank[action.maturity] > maturity_rank[registered.maturity]:
                raise ContractError(f"operation route maturity inflation: {action_name}")
