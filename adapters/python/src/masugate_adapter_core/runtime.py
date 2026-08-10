"""Host-neutral, replacement-only runtime over the public MasuGate Python SDK."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Protocol, cast

from masugate_client import (
    ActionResult,
    AdapterCancellationEnvelope,
    AdapterInvocation,
    AuditRecord,
    ExpectedActionOwner,
    JsonValue,
    OperationLocator,
    PendingLookup,
    Scalar,
    StagedArtifact,
    canonical_adapter_envelope,
    canonical_any_governed_route_manifest,
    create_adapter_invocation,
    operation_locator,
    validate_any_governed_route_manifest,
    validate_operation_locator,
)

_SAFE_INTEGER_MIN = -9_007_199_254_740_991
_SAFE_INTEGER_MAX = 9_007_199_254_740_991
_CAPABILITIES = frozenset({"cancellation", "locator", "pending-presentation", "receipt"})


class AdapterCoreError(ValueError):
    """Base error for a host binding's pre-admission validation failures."""


class AdapterModelArgumentsError(AdapterCoreError):
    """Model input did not exactly match the registered tool declaration."""


class ChangedInvocationConflictError(AdapterCoreError):
    """A trusted source identity was reused with changed canonical content."""


class PendingLocatorMismatchError(AdapterCoreError):
    """A pending read did not resolve the exact host-owned operation locator."""


class UnsupportedAdapterCapabilityError(AdapterCoreError):
    """The binding attempted a lifecycle operation it did not declare."""


class UnknownGovernedToolError(AdapterCoreError):
    """The host binding asked for a tool absent from its registered manifest."""


class GovernedActionClient(Protocol):
    """Public SDK operations needed by the replacement-only runtime."""

    async def execute(
        self,
        action: str,
        args: Mapping[str, Scalar],
        stable_id: str,
        trace_id: str | None = None,
        *,
        owner: ExpectedActionOwner | None = None,
        expected_principal: str | None = None,
        adapter_invocation: str | None = None,
    ) -> ActionResult: ...

    async def stage_artifact(
        self,
        *,
        action: str,
        field: str,
        content: bytes,
        media_type: str,
        stable_id: str,
        adapter_invocation: str,
    ) -> StagedArtifact: ...

    async def get_pending(self, pending_id: str) -> PendingLookup: ...

    async def cancel_pending(self, pending_id: str) -> AdapterCancellationEnvelope: ...

    async def get_audit(self, operation_id: str) -> AuditRecord: ...


@dataclass(frozen=True, slots=True)
class AdapterCapabilities:
    """Non-authoritative adapter provenance supplied by the host binding."""

    adapter_id: str
    capabilities: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.adapter_id) is not str or not self.adapter_id:
            raise AdapterCoreError("adapter_id must be non-empty")
        capabilities = tuple(self.capabilities)
        object.__setattr__(self, "capabilities", capabilities)
        if len(set(capabilities)) != len(capabilities):
            raise AdapterCoreError("adapter capabilities must not contain duplicates")
        if any(capability not in _CAPABILITIES for capability in capabilities):
            raise AdapterCoreError("adapter capabilities contain an unsupported value")

    def require(self, capability: str) -> None:
        if capability not in self.capabilities:
            raise UnsupportedAdapterCapabilityError(
                f"adapter does not declare required capability: {capability}"
            )


@dataclass(frozen=True, slots=True)
class TrustedInvocation:
    """Identity derived by a host, never accepted from model arguments."""

    principal_id: str
    source_namespace: str
    source_id: str
    adapter: AdapterCapabilities
    stable_id_override: str | None = None
    trace_id: str | None = None

    def __post_init__(self) -> None:
        if any(
            type(value) is not str or not value
            for value in (self.principal_id, self.source_namespace, self.source_id)
        ):
            raise AdapterCoreError("trusted principal and source values must be non-empty strings")
        if self.stable_id_override is not None and (
            type(self.stable_id_override) is not str or not self.stable_id_override
        ):
            raise AdapterCoreError("trusted stable_id_override must be a non-empty string")
        if self.trace_id is not None and (type(self.trace_id) is not str or not self.trace_id):
            raise AdapterCoreError("trusted trace_id must be a non-empty string")

    def adapter_invocation(
        self,
        spec: GovernedToolSpec,
        arguments: Mapping[str, Scalar],
    ) -> AdapterInvocation:
        return create_adapter_invocation(
            {
                "principal": {"id": self.principal_id},
                "source": {"namespace": self.source_namespace, "id": self.source_id},
                "adapter": {
                    "id": self.adapter.adapter_id,
                    "contract_version": "masugate.host-adapter.v1",
                    "capabilities": list(self.adapter.capabilities),
                },
                "action": {"name": spec.action, "arguments": dict(arguments)},
            }
        )

    @property
    def stable_id(self) -> str:
        if self.stable_id_override is not None:
            return self.stable_id_override
        return "adapter-core:v1:" + json.dumps(
            [self.principal_id, self.source_namespace, self.source_id],
            ensure_ascii=False,
            separators=(",", ":"),
        )

    @property
    def binding_key(self) -> tuple[str, str, str]:
        return (self.principal_id, self.source_namespace, self.source_id)


@dataclass(frozen=True, slots=True)
class GovernedToolSpec:
    """One registered model-visible tool and its server-certified owner."""

    host_tool: str
    action: str
    arguments: dict[str, Literal["string", "integer", "boolean"]] | None
    owner: ExpectedActionOwner
    input_schema: dict[str, JsonValue] | None = None
    public_result_schema: dict[str, JsonValue] | None = None
    artifact_fields: tuple[str, ...] = ()


class GovernedRouteParser:
    """Parses a manifest once and exposes only its declared tool routes."""

    def __init__(self, manifest: object) -> None:
        parsed = validate_any_governed_route_manifest(manifest)
        self._canonical_manifest = canonical_any_governed_route_manifest(parsed)
        self._routes: dict[str, GovernedToolSpec] = {}
        for raw_route in cast(list[dict[str, JsonValue]], parsed["routes"]):
            owner = cast(dict[str, str], raw_route["owner"])
            position = cast(Literal["transactional", "protected-external"], owner["position"])
            arguments: dict[str, Literal["string", "integer", "boolean"]] | None
            input_schema: dict[str, JsonValue] | None
            public_result_schema: dict[str, JsonValue] | None
            artifact_fields: tuple[str, ...]
            if parsed["contract_version"] == "masugate.governed-route-manifest.v1":
                arguments = {
                    name: cast(Literal["string", "integer", "boolean"], kind)
                    for name, kind in cast(dict[str, str], raw_route["arguments"]).items()
                }
                input_schema = None
                public_result_schema = None
                artifact_fields = ()
            else:
                arguments = None
                input_schema = cast(dict[str, JsonValue], raw_route["input_schema"])
                public_result_schema = cast(dict[str, JsonValue], raw_route["public_result_schema"])
                artifact_fields = tuple(cast(list[str], raw_route["artifact_fields"]))
            self._routes[cast(str, raw_route["host_tool"])] = GovernedToolSpec(
                host_tool=cast(str, raw_route["host_tool"]),
                action=cast(str, raw_route["action"]),
                arguments=arguments,
                owner=ExpectedActionOwner(
                    provider_id=owner["provider_id"],
                    position=position,
                    connector_id=owner.get("connector_id"),
                ),
                input_schema=input_schema,
                public_result_schema=public_result_schema,
                artifact_fields=artifact_fields,
            )

    @property
    def canonical_manifest(self) -> str:
        return self._canonical_manifest

    def select(self, host_tool: str) -> GovernedToolSpec:
        try:
            return self._routes[host_tool]
        except KeyError as exc:
            raise UnknownGovernedToolError(f"unknown governed tool: {host_tool}") from exc


@dataclass(frozen=True, slots=True)
class GovernedLifecycle:
    """Authoritative lifecycle returned to a host without native fallthrough."""

    status: Literal["committed", "denied", "pending", "in_progress", "outcome_unknown"]
    result: ActionResult
    locator: OperationLocator
    native_effect_permitted: Literal[False] = False
    retry_as_new_action: Literal[False] = False


@dataclass(frozen=True, slots=True)
class PendingPresentation:
    """Durable pending read returned when a host resumes an existing locator."""

    status: Literal["pending"]
    operation_id: str
    pending_id: str
    native_effect_permitted: Literal[False] = False
    retry_as_new_action: Literal[False] = False


def classify_lifecycle(result: ActionResult) -> GovernedLifecycle:
    """Classify all GAP outcomes without granting a host-native effect path."""

    return GovernedLifecycle(
        status=result.status,
        result=result,
        locator=operation_locator(
            {
                "operation_id": result.operation_id,
                "status": result.status,
                "pending_id": result.pending_id,
            }
        ),
    )


@dataclass(slots=True)
class GovernedToolRuntime:
    """One-call runtime which delegates every lifecycle action to public GAP APIs."""

    client: GovernedActionClient
    routes: GovernedRouteParser
    invocation: TrustedInvocation

    async def invoke(
        self,
        host_tool: str,
        model_arguments: object,
    ) -> GovernedLifecycle:
        spec = self.routes.select(host_tool)
        arguments = _validate_model_arguments(spec, model_arguments)
        envelope = self.invocation.adapter_invocation(spec, arguments)
        canonical = canonical_adapter_envelope(envelope)
        for field in spec.artifact_fields:
            content = arguments[field]
            if type(content) is not str:
                raise AdapterModelArgumentsError(
                    "connector ecosystem artifact fields currently require bounded string content"
                )
            await self.client.stage_artifact(
                action=spec.action,
                field=field,
                content=content.encode("utf-8"),
                media_type="text/plain",
                stable_id=self.invocation.stable_id,
                adapter_invocation=canonical,
            )
        result = await self.client.execute(
            spec.action,
            arguments,
            self.invocation.stable_id,
            trace_id=self.invocation.trace_id,
            owner=spec.owner,
            expected_principal=self.invocation.principal_id,
            adapter_invocation=canonical,
        )
        return classify_lifecycle(result)

    async def resume_pending(self, locator: object) -> GovernedLifecycle | PendingPresentation:
        """Re-read exactly the pending locator returned by an earlier invocation."""

        self.invocation.adapter.require("locator")
        self.invocation.adapter.require("pending-presentation")
        try:
            expected = validate_operation_locator(locator)
        except ValueError as exc:
            raise PendingLocatorMismatchError(
                "pending resume requires a valid pending locator"
            ) from exc
        pending_id = expected.get("pending_id")
        if pending_id is None:
            raise PendingLocatorMismatchError("pending resume requires an operation and pending id")
        lookup = await self.client.get_pending(pending_id)
        if lookup.kind == "terminal":
            assert lookup.result is not None
            presentation = classify_lifecycle(lookup.result)
            if presentation.locator["operation_id"] != expected["operation_id"]:
                raise PendingLocatorMismatchError(
                    "pending terminal result belongs to another operation"
                )
            return presentation
        assert lookup.pending is not None
        if (
            lookup.pending.pending_id != pending_id
            or lookup.pending.operation_id != expected["operation_id"]
        ):
            raise PendingLocatorMismatchError(
                "pending read did not return the requested operation locator"
            )
        return PendingPresentation(
            status="pending",
            operation_id=lookup.pending.operation_id,
            pending_id=lookup.pending.pending_id,
        )

    async def cancel_pending(self, locator: object) -> AdapterCancellationEnvelope:
        """Request cancellation only for the complete original pending locator."""

        self.invocation.adapter.require("locator")
        self.invocation.adapter.require("cancellation")
        try:
            expected = validate_operation_locator(locator)
        except ValueError as exc:
            raise PendingLocatorMismatchError(
                "pending cancellation requires a valid pending locator"
            ) from exc
        pending_id = expected.get("pending_id")
        if pending_id is None:
            raise PendingLocatorMismatchError(
                "pending cancellation requires an operation and pending id"
            )
        cancellation = await self.client.cancel_pending(pending_id)
        actual = validate_operation_locator(cancellation["locator"])
        if actual != expected:
            raise PendingLocatorMismatchError(
                "pending cancellation did not return the requested operation locator"
            )
        return cancellation

    async def get_receipt(self, locator: object) -> AuditRecord:
        """Read a receipt only when it names the complete original operation locator."""

        self.invocation.adapter.require("locator")
        self.invocation.adapter.require("receipt")
        try:
            expected = validate_operation_locator(locator)
        except ValueError as exc:
            raise PendingLocatorMismatchError("receipt requires a valid operation locator") from exc
        receipt = await self.client.get_audit(expected["operation_id"])
        if receipt.operation_id != expected["operation_id"]:
            raise PendingLocatorMismatchError("receipt belongs to another operation")
        return receipt


def _validate_model_arguments(
    spec: GovernedToolSpec,
    supplied: object,
) -> dict[str, Scalar]:
    if not isinstance(supplied, Mapping):
        raise AdapterModelArgumentsError("model arguments must be an object")
    if not all(type(name) is str for name in supplied):
        raise AdapterModelArgumentsError("model argument names must be strings")
    mapping = cast(Mapping[str, object], supplied)
    if spec.arguments is None:
        assert spec.input_schema is not None  # parser invariant
        return _validate_v2_scalar_arguments(spec.input_schema, mapping)
    supplied_names = set(mapping)
    declared_names = set(spec.arguments)
    if supplied_names != declared_names:
        unexpected = sorted(supplied_names - declared_names)
        missing = sorted(declared_names - supplied_names)
        parts: list[str] = []
        if unexpected:
            parts.append(f"unexpected model arguments: {', '.join(unexpected)}")
        if missing:
            parts.append(f"missing model arguments: {', '.join(missing)}")
        raise AdapterModelArgumentsError("; ".join(parts))
    parsed: dict[str, Scalar] = {}
    for name, kind in spec.arguments.items():
        value = mapping[name]
        if (kind == "string" and type(value) is str) or (kind == "boolean" and type(value) is bool):
            parsed[name] = cast(Scalar, value)
        elif (
            kind == "integer"
            and type(value) is int
            and _SAFE_INTEGER_MIN <= value <= _SAFE_INTEGER_MAX
        ):
            parsed[name] = value
        else:
            raise AdapterModelArgumentsError(f"model argument {name} must be {kind}")
    return parsed


def _validate_v2_scalar_arguments(
    schema: Mapping[str, JsonValue],
    supplied: Mapping[str, object],
) -> dict[str, Scalar]:
    """Validate the executable scalar subset of a compiled v2 route.

    V2 schemas can describe nested values for generated host tooling.  The
    established public ``/v1/actions`` endpoint remains scalar-only, so this
    runtime admits only the subset it can submit without flattening or losing
    the model's shape.  Operation-specific nested bridges are introduced with
    their provider packs, rather than silently turning structured content into
    a caller-controlled serialization.
    """

    properties = cast(dict[str, JsonValue], schema["properties"])
    required = set(cast(list[str], schema["required"]))
    supplied_names = set(supplied)
    if supplied_names != set(properties) and not (required <= supplied_names <= set(properties)):
        unexpected = sorted(supplied_names - set(properties))
        missing = sorted(required - supplied_names)
        details = []
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        if missing:
            details.append("missing: " + ", ".join(missing))
        raise AdapterModelArgumentsError(
            "model arguments do not match route: " + "; ".join(details)
        )
    parsed: dict[str, Scalar] = {}
    for name, raw_schema in properties.items():
        if name not in supplied:
            continue
        value = supplied[name]
        field_schema = cast(dict[str, JsonValue], raw_schema)
        kind = cast(str, field_schema["type"])
        if kind == "string":
            if type(value) is not str:
                raise AdapterModelArgumentsError(f"model argument {name} must be string")
            minimum = cast(int | None, field_schema.get("minLength"))
            maximum = cast(int | None, field_schema.get("maxLength"))
            if (minimum is not None and len(value) < minimum) or (
                maximum is not None and len(value) > maximum
            ):
                raise AdapterModelArgumentsError(f"model argument {name} violates string bounds")
            parsed[name] = value
        elif kind == "integer":
            if type(value) is not int or not (_SAFE_INTEGER_MIN <= value <= _SAFE_INTEGER_MAX):
                raise AdapterModelArgumentsError(f"model argument {name} must be integer")
            minimum = cast(int | None, field_schema.get("minimum"))
            maximum = cast(int | None, field_schema.get("maximum"))
            if (minimum is not None and value < minimum) or (
                maximum is not None and value > maximum
            ):
                raise AdapterModelArgumentsError(f"model argument {name} violates integer bounds")
            parsed[name] = value
        elif kind == "boolean":
            if type(value) is not bool:
                raise AdapterModelArgumentsError(f"model argument {name} must be boolean")
            parsed[name] = value
        else:
            raise AdapterModelArgumentsError(
                "nested v2 route inputs require an operation-specific protected-payload bridge"
            )
    return parsed
