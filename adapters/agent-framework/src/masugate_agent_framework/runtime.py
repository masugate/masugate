"""Exact-artifact MAF replacement tools over the public MasuGate adapter core.

This adapter deliberately relies on the tested implementation convention in
``agent-framework-core==1.12.0`` that writes the logical MAF function-call ID
to ``FunctionInvocationContext.metadata[\"call_id\"]`` before function middleware
runs. It is not a compatibility promise for any other MAF artifact.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
from typing import cast

from agent_framework import (
    AgentContext,
    AgentMiddleware,
    AgentSession,
    FunctionInvocationContext,
    FunctionMiddleware,
    FunctionTool,
)
from masugate_adapter_core import (
    AdapterCapabilities,
    GovernedActionClient,
    GovernedLifecycle,
    GovernedRouteParser,
    GovernedToolRuntime,
    GovernedToolSpec,
    PendingPresentation,
    TrustedInvocation,
)
from masugate_client import (
    operation_locator,
    validate_any_governed_route_manifest,
    validate_operation_locator,
)

MAF_CORE_VERSION = "1.12.0"
MAF_CORE_WHEEL_SHA256 = "71716a2c109b7ca89aaa221796876dc7166fed741d3fa75c967f8f24d02c6ead"
TRUSTED_CONTEXT_KEY = "masugate_agent_framework_trusted_context"
_PENDING_STATE_KEY = "masugate_agent_framework.pending.v1"
_IDENTITY_PREFIX = "maf:core-1.12.0:"
_DEFAULT_CAPABILITIES = ("cancellation", "locator", "pending-presentation", "receipt")
_JSON_TYPES = {
    "string": "string",
    "integer": "integer",
    "boolean": "boolean",
}


class MafAdapterError(ValueError):
    """Base error for invalid or unsupported MAF adapter context."""


class UnsupportedMafRuntimeError(MafAdapterError):
    """The deployment did not install the exact MAF artifact this adapter verifies."""


class MissingToolCallIdentityError(MafAdapterError):
    """The pinned MAF implementation did not provide its tested call-ID metadata."""


class UntrustedRuntimeContextError(MafAdapterError):
    """The deployment did not inject the trusted, non-model invocation context."""


class MafProfileViolationError(MafAdapterError):
    """A host registered another implementation for a governed tool name."""


class MafPendingStateError(MafAdapterError):
    """The MAF session did not retain the authoritative MasuGate pending locator."""


@dataclass(frozen=True, slots=True)
class MafTrustedContext:
    """Deployment-owned identity supplied through MAF function runtime kwargs.

    The application creates this object and passes it using
    ``Agent.run(..., function_invocation_kwargs=...)``. It is excluded from a
    MAF function schema, so model arguments cannot provide or override it.
    """

    principal_id: str
    session_id: str
    session_generation: str
    source_namespace: str = "microsoft-agent-framework"

    def __post_init__(self) -> None:
        for name in ("principal_id", "session_id", "session_generation", "source_namespace"):
            value = getattr(self, name)
            if type(value) is not str or not value or value != value.strip():
                raise MafAdapterError(f"{name} must be a non-empty, trimmed string")

    def invocation_for(
        self,
        call_id: str,
        *,
        adapter_id: str,
        capabilities: tuple[str, ...],
    ) -> TrustedInvocation:
        """Bind MAF's tested logical call ID to a stable MasuGate invocation."""

        if type(call_id) is not str or not call_id or call_id != call_id.strip():
            raise MissingToolCallIdentityError("MAF did not provide a non-empty logical call ID")
        source_identity = _identity(
            "source",
            self.principal_id,
            self.source_namespace,
            self.session_id,
            self.session_generation,
            call_id,
        )
        trace_identity = _identity(
            "trace",
            self.principal_id,
            self.source_namespace,
            self.session_id,
            self.session_generation,
            call_id,
        )
        return TrustedInvocation(
            principal_id=self.principal_id,
            source_namespace=self.source_namespace,
            source_id=source_identity,
            stable_id_override=source_identity,
            trace_id=trace_identity,
            adapter=AdapterCapabilities(adapter_id=adapter_id, capabilities=capabilities),
        )


@dataclass(frozen=True, slots=True)
class MafGovernedToolset:
    """The only MAF objects a governed-replacement host needs to register."""

    tools: tuple[FunctionTool, ...]
    middleware: MafGovernedMiddleware
    agent_middleware: MafNativeApprovalResponseGuard

    async def resume_pending(
        self,
        session: AgentSession,
        trusted_context: MafTrustedContext,
        locator: object,
    ) -> dict[str, object]:
        """Re-query one MasuGate pending locator without MAF native approval semantics.

        The host may present the pending locator in its own UI, but it must not
        turn a UI decision into MAF's ``function_approval_response``. Any
        independent MasuGate resolution occurs through the deployment's MasuGate
        authority; this method only re-reads that exact saved locator.
        """

        return await self.middleware.resume_pending(session, trusted_context, locator)


def verify_pinned_maf_runtime() -> None:
    """Reject any installed MAF distribution other than the verified exact release."""

    try:
        installed = version("agent-framework-core")
    except PackageNotFoundError as exc:
        raise UnsupportedMafRuntimeError("agent-framework-core is not installed") from exc
    if installed != MAF_CORE_VERSION:
        raise UnsupportedMafRuntimeError(
            "masugate-agent-framework requires "
            f"agent-framework-core=={MAF_CORE_VERSION}, got {installed}"
        )


def create_maf_governed_toolset(
    client: GovernedActionClient,
    manifest: object,
    *,
    adapter_id: str = "masugate.agent-framework",
    capabilities: tuple[str, ...] = _DEFAULT_CAPABILITIES,
    descriptions: Mapping[str, str] | None = None,
) -> MafGovernedToolset:
    """Create typed MAF replacement tools and their authoritative middleware.

    Register exactly ``toolset.tools`` and ``toolset.middleware`` on a MAF
    function-invoking client. The generated tools intentionally contain no
    consequential implementation: the middleware returns every MasuGate result
    and never calls the MAF final handler.
    """

    verify_pinned_maf_runtime()
    if type(adapter_id) is not str or not adapter_id or adapter_id != adapter_id.strip():
        raise MafAdapterError("adapter_id must be a non-empty, trimmed string")
    validated_manifest = validate_any_governed_route_manifest(manifest)
    routes = GovernedRouteParser(manifest)
    description_map = dict(descriptions or {})
    raw_routes = cast(list[Mapping[str, object]], validated_manifest["routes"])
    host_tools = tuple(cast(str, route["host_tool"]) for route in raw_routes)
    unknown_descriptions = set(description_map) - set(host_tools)
    if unknown_descriptions:
        names = ", ".join(sorted(unknown_descriptions))
        raise MafAdapterError(f"descriptions name unknown governed tools: {names}")

    tools = {
        host_tool: _replacement_tool(
            routes.select(host_tool),
            description_map.get(
                host_tool,
                f"Submit the governed MasuGate action {routes.select(host_tool).action}; "
                "MasuGate returns the authoritative result.",
            ),
        )
        for host_tool in host_tools
    }
    return MafGovernedToolset(
        tools=tuple(tools.values()),
        middleware=MafGovernedMiddleware(
            client=client,
            routes=routes,
            tools=tools,
            adapter_id=adapter_id,
            capabilities=capabilities,
        ),
        agent_middleware=MafNativeApprovalResponseGuard(),
    )


class MafNativeApprovalResponseGuard(AgentMiddleware):
    """Reject MAF native approval responses before MAF can consume them.

    The guarded profile deliberately has no MAF ``function_approval_request``
    flow. This guard keeps a fabricated native response from becoming the
    pinned runtime's model-visible "tool call rejected" result before function
    middleware has a chance to fail it closed.
    """

    async def process(
        self,
        context: AgentContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        if any(
            content.type == "function_approval_response"
            for message in context.messages
            for content in message.contents
        ):
            raise MafProfileViolationError(
                "native MAF approval responses are outside the MasuGate profile; "
                "re-query the saved MasuGate locator instead"
            )
        await call_next()


class MafGovernedMiddleware(FunctionMiddleware):
    """Short-circuit generated MAF replacement tools with the MasuGate lifecycle."""

    def __init__(
        self,
        *,
        client: GovernedActionClient,
        routes: GovernedRouteParser,
        tools: Mapping[str, FunctionTool],
        adapter_id: str,
        capabilities: tuple[str, ...],
    ) -> None:
        self._client = client
        self._routes = routes
        self._tools = dict(tools)
        self._adapter_id = adapter_id
        self._capabilities = capabilities

    async def process(
        self,
        context: FunctionInvocationContext,
        call_next: Callable[[], Awaitable[None]],
    ) -> None:
        tool = self._tools.get(context.function.name)
        if tool is None:
            await call_next()
            return
        if context.function is not tool:
            raise MafProfileViolationError(
                "governed MAF tool "
                f"{context.function.name!r} is not the generated MasuGate replacement"
            )
        if "approval_response" in context.metadata:
            raise MafProfileViolationError(
                "native MAF approval responses are outside the MasuGate profile; "
                "re-query the saved MasuGate locator instead"
            )

        trusted = _trusted_context(context)
        call_id = _maf_call_id(context)
        invocation = trusted.invocation_for(
            call_id,
            adapter_id=self._adapter_id,
            capabilities=self._capabilities,
        )
        runtime = GovernedToolRuntime(
            client=self._client,
            routes=self._routes,
            invocation=invocation,
        )
        presentation = await runtime.invoke(context.function.name, context.arguments)
        if presentation.status == "pending":
            _store_pending(context, trusted, call_id, presentation)
        context.result = _render_presentation(presentation)

    async def resume_pending(
        self,
        session: AgentSession,
        trusted_context: MafTrustedContext,
        locator: object,
    ) -> dict[str, object]:
        """Re-read a saved MasuGate locator after an out-of-band MasuGate resolution.

        This deliberately has no boolean approval parameter. MAF Core 1.12.0
        filters ``approved=False`` native approval responses before function
        middleware, so native MAF approval is not part of this profile.
        """

        _validate_resume_context(session, trusted_context)
        call_id, saved_locator = _find_saved_pending(session, trusted_context, locator)
        runtime = GovernedToolRuntime(
            client=self._client,
            routes=self._routes,
            invocation=trusted_context.invocation_for(
                call_id,
                adapter_id=self._adapter_id,
                capabilities=self._capabilities,
            ),
        )
        presentation = await runtime.resume_pending(saved_locator)
        return _render_presentation(presentation)


def _replacement_tool(spec: GovernedToolSpec, description: str) -> FunctionTool:
    async def native_path_forbidden(**_: object) -> str:
        raise MafProfileViolationError(
            "a generated MasuGate replacement reached MAF's native function path; "
            "middleware is required"
        )

    return FunctionTool(
        name=spec.host_tool,
        description=description,
        func=native_path_forbidden,
        input_model=(
            {
                "type": "object",
                "properties": {
                    name: {"type": _JSON_TYPES[kind]} for name, kind in spec.arguments.items()
                },
                "required": list(spec.arguments),
                "additionalProperties": False,
            }
            if spec.arguments is not None
            else cast(dict[str, object], spec.input_schema)
        ),
    )


def _trusted_context(context: FunctionInvocationContext) -> MafTrustedContext:
    trusted = context.kwargs.get(TRUSTED_CONTEXT_KEY)
    if not isinstance(trusted, MafTrustedContext):
        raise UntrustedRuntimeContextError(
            f"MAF tools require deployment-owned {TRUSTED_CONTEXT_KEY}"
        )
    if context.session is None or context.session.session_id != trusted.session_id:
        raise UntrustedRuntimeContextError("trusted MAF context must match the live AgentSession")
    return trusted


def _maf_call_id(context: FunctionInvocationContext) -> str:
    call_id = context.metadata.get("call_id")
    if type(call_id) is not str or not call_id or call_id != call_id.strip():
        raise MissingToolCallIdentityError(
            "the verified MAF implementation did not provide metadata['call_id']"
        )
    return call_id


def _store_pending(
    context: FunctionInvocationContext,
    trusted: MafTrustedContext,
    call_id: str,
    lifecycle: GovernedLifecycle,
) -> None:
    if context.session is None:
        raise MafPendingStateError("pending MasuGate work requires an AgentSession")
    state = context.session.state.setdefault(_PENDING_STATE_KEY, {})
    if not isinstance(state, dict):
        raise MafPendingStateError("MAF session pending state has an invalid shape")
    state[call_id] = {
        "principal_id": trusted.principal_id,
        "session_generation": trusted.session_generation,
        "source_namespace": trusted.source_namespace,
        "locator": dict(lifecycle.locator),
    }


def _validate_resume_context(
    session: AgentSession,
    trusted: MafTrustedContext,
) -> None:
    if session.session_id != trusted.session_id:
        raise UntrustedRuntimeContextError("trusted MAF context must match the live AgentSession")


def _find_saved_pending(
    session: AgentSession,
    trusted: MafTrustedContext,
    locator: object,
) -> tuple[str, Mapping[str, object]]:
    try:
        expected = validate_operation_locator(locator)
    except ValueError as exc:
        raise MafPendingStateError("MAF resume requires a valid MasuGate pending locator") from exc
    state = session.state.get(_PENDING_STATE_KEY)
    if not isinstance(state, dict):
        raise MafPendingStateError("MAF session has no saved MasuGate pending locator")
    matches: list[tuple[str, Mapping[str, object]]] = []
    for call_id, value in state.items():
        if type(call_id) is not str or not isinstance(value, dict):
            continue
        if (
            value.get("principal_id") != trusted.principal_id
            or value.get("session_generation") != trusted.session_generation
            or value.get("source_namespace") != trusted.source_namespace
        ):
            continue
        saved = value.get("locator")
        if not isinstance(saved, dict):
            continue
        try:
            saved_locator = validate_operation_locator(saved)
        except ValueError as exc:
            raise MafPendingStateError("MAF pending locator has an invalid shape") from exc
        if saved_locator == expected:
            matches.append((call_id, cast(Mapping[str, object], saved_locator)))
    if len(matches) != 1:
        raise MafPendingStateError(
            "MAF resume does not match exactly one saved MasuGate pending locator"
        )
    return matches[0]


def _render_presentation(
    presentation: GovernedLifecycle | PendingPresentation,
) -> dict[str, object]:
    if isinstance(presentation, GovernedLifecycle):
        return _render_lifecycle(presentation)
    locator = operation_locator(
        {
            "operation_id": presentation.operation_id,
            "status": "pending",
            "pending_id": presentation.pending_id,
        }
    )
    return {
        "kind": "masugate.pending.v1",
        "status": presentation.status,
        "operation_id": presentation.operation_id,
        "pending_id": presentation.pending_id,
        "locator": dict(locator),
        "native_effect_permitted": False,
        "retry_as_new_action": False,
    }


def _render_lifecycle(lifecycle: GovernedLifecycle) -> dict[str, object]:
    return {
        "kind": "masugate.lifecycle.v1",
        "status": lifecycle.status,
        "operation_id": lifecycle.result.operation_id,
        "pending_id": lifecycle.result.pending_id,
        "audit_ref": lifecycle.result.audit_ref,
        "payload": dict(lifecycle.result.payload),
        "replayed": lifecycle.result.replayed,
        "locator": dict(lifecycle.locator),
        "native_effect_permitted": False,
        "retry_as_new_action": False,
    }


def _identity(label: str, *parts: str) -> str:
    canonical = json.dumps([label, *parts], ensure_ascii=False, separators=(",", ":"))
    return _IDENTITY_PREFIX + sha256(canonical.encode("utf-8")).hexdigest()
