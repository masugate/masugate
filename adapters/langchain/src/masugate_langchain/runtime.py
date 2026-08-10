"""Pinned LangChain/LangGraph replacement tools over the public MasuGate adapter core."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cached_property
from hashlib import sha256
from typing import Annotated, Any, cast

from langchain.tools import ToolRuntime
from langchain_core.tools import BaseTool, StructuredTool
from langgraph.types import interrupt
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
from masugate_client import validate_any_governed_route_manifest
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr, create_model
from pydantic.experimental.missing_sentinel import MISSING

LANGCHAIN_VERSION = "1.3.14"
LANGGRAPH_VERSION = "1.2.9"
_IDENTITY_PREFIX = "langgraph:v1:"
_DEFAULT_CAPABILITIES = ("cancellation", "locator", "pending-presentation", "receipt")
_ARGUMENT_TYPES = {
    "string": StrictStr,
    "integer": StrictInt,
    "boolean": StrictBool,
}


class LangChainAdapterError(ValueError):
    """Base error for invalid host-owned LangChain/LangGraph context."""


class UntrustedRuntimeContextError(LangChainAdapterError):
    """The host did not inject the deployment-owned adapter context."""


class MissingToolCallIdentityError(LangChainAdapterError):
    """The public LangChain tool-call identity is absent or malformed."""


class _GovernedStructuredTool(StructuredTool):
    """Retain LangGraph's injected ``ToolRuntime`` through Pydantic parsing.

    ``StructuredTool.from_function`` intentionally drops directly injected
    parameters when an adapter supplies its own generated argument schema.
    This subclass keeps the hidden runtime after validation while the inherited
    tool-call schema still excludes it from model-visible arguments.
    """

    @cached_property
    def _injected_args_keys(self) -> frozenset[str]:
        return frozenset({"runtime"})

    @cached_property
    def tool_call_schema(self) -> Any:
        """Expose the closed, strict model schema after hiding injected runtime."""

        if isinstance(self.args_schema, dict):
            return super().tool_call_schema
        arguments_schema = cast(type[BaseModel], self.args_schema)
        fields = {
            name: (field.annotation, field)
            for name, field in arguments_schema.model_fields.items()
            if name != "runtime"
        }
        return create_model(
            f"{self.name}ToolCall",
            __config__=ConfigDict(extra="forbid", strict=True),
            **cast(Any, fields),
        )


@dataclass(frozen=True, slots=True)
class LangGraphTrustedContext:
    """Deployment-owned identity supplied through hidden ``ToolRuntime.context``.

    ``thread_id`` and ``thread_generation`` are chosen by the deployment that
    owns the durable LangGraph checkpoint.  They are never model-tool
    arguments.  Incrementing the generation creates a new source invocation
    domain even if an application deliberately reuses a thread identifier.
    """

    principal_id: str
    thread_id: str
    thread_generation: str
    source_namespace: str = "langgraph"

    def __post_init__(self) -> None:
        for name in ("principal_id", "thread_id", "thread_generation", "source_namespace"):
            value = getattr(self, name)
            if type(value) is not str or not value or value != value.strip():
                raise LangChainAdapterError(f"{name} must be a non-empty, trimmed string")

    def invocation_for(
        self,
        tool_call_id: str,
        *,
        adapter_id: str,
        capabilities: tuple[str, ...],
    ) -> TrustedInvocation:
        """Bind one public host call to a bounded, collision-resistant MasuGate identity."""

        if (
            type(tool_call_id) is not str
            or not tool_call_id
            or tool_call_id != tool_call_id.strip()
        ):
            raise MissingToolCallIdentityError("LangChain did not provide a non-empty tool_call_id")
        source_identity = _identity(
            "source",
            self.principal_id,
            self.source_namespace,
            self.thread_id,
            self.thread_generation,
            tool_call_id,
        )
        # The reference spend provider treats ``trace_id`` as the immutable
        # trusted tool-call identity.  It must therefore distinguish separate
        # calls in one durable thread while remaining stable across replay of
        # the same LangGraph tool call.
        trace_identity = _identity(
            "trace",
            self.principal_id,
            self.source_namespace,
            self.thread_id,
            self.thread_generation,
            tool_call_id,
        )
        return TrustedInvocation(
            principal_id=self.principal_id,
            source_namespace=self.source_namespace,
            source_id=source_identity,
            stable_id_override=source_identity,
            trace_id=trace_identity,
            adapter=AdapterCapabilities(adapter_id=adapter_id, capabilities=capabilities),
        )


def create_langchain_governed_tools(
    client: GovernedActionClient,
    manifest: object,
    *,
    adapter_id: str = "masugate.langchain",
    capabilities: tuple[str, ...] = _DEFAULT_CAPABILITIES,
    descriptions: Mapping[str, str] | None = None,
) -> dict[str, BaseTool]:
    """Generate typed MasuGate-owned replacements for every manifest route.

    The returned mapping contains no wrapped native callable.  Register these
    tools *instead of* a consequential host tool.  A ``pending`` MasuGate result
    calls LangGraph ``interrupt`` only to surface MasuGate's locator; a resumed
    graph re-reads that same locator and never treats resume input as approval.
    """

    if type(adapter_id) is not str or not adapter_id or adapter_id != adapter_id.strip():
        raise LangChainAdapterError("adapter_id must be a non-empty, trimmed string")
    validated_manifest = validate_any_governed_route_manifest(manifest)
    parsed_routes = GovernedRouteParser(manifest)
    description_map = dict(descriptions or {})
    raw_routes = cast(list[Mapping[str, object]], validated_manifest["routes"])
    host_tools = tuple(cast(str, route["host_tool"]) for route in raw_routes)
    unknown_descriptions = set(description_map) - set(host_tools)
    if unknown_descriptions:
        names = ", ".join(sorted(unknown_descriptions))
        raise LangChainAdapterError(f"descriptions name unknown governed tools: {names}")

    tools: dict[str, BaseTool] = {}
    for host_tool in host_tools:
        spec = parsed_routes.select(host_tool)
        tools[host_tool] = _create_tool(
            client=client,
            routes=parsed_routes,
            spec=spec,
            adapter_id=adapter_id,
            capabilities=capabilities,
            description=description_map.get(
                host_tool,
                f"Submit the governed MasuGate action {spec.action}; "
                "MasuGate returns the authoritative result.",
            ),
        )
    return tools


def _create_tool(
    *,
    client: GovernedActionClient,
    routes: GovernedRouteParser,
    spec: GovernedToolSpec,
    adapter_id: str,
    capabilities: tuple[str, ...],
    description: str,
) -> BaseTool:
    arguments_schema = _arguments_schema(spec)

    async def invoke_governed_tool(
        runtime: ToolRuntime[LangGraphTrustedContext], **model_arguments: object
    ) -> dict[str, object]:
        context = _trusted_context(runtime)
        if runtime.tool_call_id is None:
            raise MissingToolCallIdentityError("LangChain did not provide a non-empty tool_call_id")
        invocation = context.invocation_for(
            runtime.tool_call_id,
            adapter_id=adapter_id,
            capabilities=capabilities,
        )
        governed = GovernedToolRuntime(client=client, routes=routes, invocation=invocation)
        lifecycle = await governed.invoke(spec.host_tool, model_arguments)
        if lifecycle.status != "pending":
            return _render_lifecycle(lifecycle)

        # LangGraph restarts the surrounding node on resume.  The second pass
        # resubmits the same stable identity, receives a MasuGate replay, and then
        # reads the original locator.  The arbitrary resume value is ignored:
        # only MasuGate can turn pending work into a terminal lifecycle.
        interrupt(_pending_interrupt(lifecycle))
        resumed = await governed.resume_pending(lifecycle.locator)
        return _render_presentation(resumed)

    return _GovernedStructuredTool(
        name=spec.host_tool,
        description=description,
        args_schema=arguments_schema,
        coroutine=invoke_governed_tool,
    )


def _trusted_context(runtime: ToolRuntime[LangGraphTrustedContext]) -> LangGraphTrustedContext:
    context = runtime.context
    if not isinstance(context, LangGraphTrustedContext):
        raise UntrustedRuntimeContextError(
            "LangGraph tools require deployment-owned LangGraphTrustedContext"
        )
    return context


def _arguments_schema(spec: GovernedToolSpec) -> type[BaseModel]:
    fields: dict[str, Any] = {}
    if spec.arguments is not None:
        for name, kind in spec.arguments.items():
            fields[name] = (
                _ARGUMENT_TYPES[kind],
                Field(
                    ...,
                    description=f"Canonical {kind} argument for MasuGate action {spec.action}.",
                ),
            )
    else:
        assert spec.input_schema is not None
        properties = cast(dict[str, object], spec.input_schema["properties"])
        required = set(cast(list[str], spec.input_schema["required"]))
        for name in properties:
            fields[name] = (
                _bounded_schema_type(
                    cast(Mapping[str, object], properties[name]),
                    f"MasuGate{_model_component(spec.host_tool)}{_model_component(name)}",
                ),
                Field(
                    ... if name in required else MISSING,
                    description=f"Bounded v2 operation input for MasuGate action {spec.action}.",
                ),
            )
    # ``ToolRuntime`` is a LangChain directly-injected argument.  Keeping it
    # in the internal Pydantic model lets ``ToolNode`` inject it before schema
    # validation; LangChain omits directly-injected arguments from the schema
    # exported to the model.
    fields["runtime"] = (ToolRuntime, Field(..., exclude=True))
    model_name = "MasuGate" + re.sub(r"[^A-Za-z0-9]+", "_", spec.host_tool).title() + "Arguments"
    return cast(
        type[BaseModel],
        create_model(
            model_name,
            __config__=ConfigDict(arbitrary_types_allowed=True, extra="forbid", strict=True),
            **cast(Any, fields),
        ),
    )


def _bounded_schema_type(schema: Mapping[str, object], model_name: str) -> object:
    """Translate the already-validated bounded schema into strict Pydantic types."""

    kind = cast(str, schema["type"])
    if kind == "string":
        return Annotated[
            StrictStr,
            Field(
                min_length=cast(int, schema["minLength"]),
                max_length=cast(int, schema["maxLength"]),
            ),
        ]
    if kind == "integer":
        return Annotated[
            StrictInt,
            Field(ge=cast(int, schema["minimum"]), le=cast(int, schema["maximum"])),
        ]
    if kind == "boolean":
        return StrictBool
    if kind == "array":
        item_type = _bounded_schema_type(
            cast(Mapping[str, object], schema["items"]), f"{model_name}Item"
        )
        array_type = list[item_type]  # type: ignore[valid-type]
        return Annotated[
            cast(Any, array_type),
            Field(
                min_length=cast(int, schema["minItems"]),
                max_length=cast(int, schema["maxItems"]),
            ),
        ]
    if kind == "object":
        properties = cast(Mapping[str, object], schema["properties"])
        required = set(cast(list[str], schema["required"]))
        fields: dict[str, tuple[object, object]] = {}
        for name, child in properties.items():
            fields[name] = (
                _bounded_schema_type(
                    cast(Mapping[str, object], child), f"{model_name}{_model_component(name)}"
                ),
                Field(... if name in required else MISSING),
            )
        return create_model(
            model_name,
            __config__=ConfigDict(extra="forbid", strict=True),
            **cast(Any, fields),
        )
    raise AssertionError(f"validated bounded schema has unsupported type: {kind}")


def _model_component(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "_", value).title().replace("_", "")


def _identity(label: str, *parts: str) -> str:
    canonical = json.dumps([label, *parts], ensure_ascii=False, separators=(",", ":"))
    return _IDENTITY_PREFIX + sha256(canonical.encode("utf-8")).hexdigest()


def _pending_interrupt(lifecycle: GovernedLifecycle) -> dict[str, object]:
    return {
        "kind": "masugate.pending.v1",
        "locator": dict(lifecycle.locator),
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


def _render_presentation(
    presentation: GovernedLifecycle | PendingPresentation,
) -> dict[str, object]:
    if isinstance(presentation, GovernedLifecycle):
        return _render_lifecycle(presentation)
    return {
        "kind": "masugate.lifecycle.v1",
        "status": "pending",
        "operation_id": presentation.operation_id,
        "pending_id": presentation.pending_id,
        "native_effect_permitted": False,
        "retry_as_new_action": False,
    }
