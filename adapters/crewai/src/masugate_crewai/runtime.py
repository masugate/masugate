"""Bounded CrewAI ``BaseTool`` replacements over the public MasuGate adapter core.

CrewAI 1.15.6 does not expose a per-tool-call identifier to ``BaseTool._run``.
This exact-artifact profile therefore binds one governed host tool to one
deployment-owned CrewAI task identity.  Re-entering that tool in the same task
replays the original MasuGate operation; changed arguments fail closed in MasuGate.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Coroutine, Iterable, Mapping
from dataclasses import dataclass
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
from typing import Annotated, Any, cast

from crewai import Crew, Task
from crewai.context import get_current_task_id
from crewai.tools import BaseTool
from crewai.tools.structured_tool import CrewStructuredTool, ToolUsageLimitExceededError
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
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    StrictBool,
    StrictInt,
    StrictStr,
    create_model,
)
from pydantic.experimental.missing_sentinel import MISSING

CREWAI_VERSION = "1.15.6"
CREWAI_CORE_VERSION = "1.15.6"
CREWAI_WHEEL_SHA256 = "966183d71ceb855672e3ea7c99abadeb1d574df7a5657489f1ae6901cb51e919"
_IDENTITY_PREFIX = "crewai:1.15.6:"
_DEFAULT_CAPABILITIES = ("cancellation", "locator", "pending-presentation", "receipt")
_ARGUMENT_TYPES = {
    "string": StrictStr,
    "integer": StrictInt,
    "boolean": StrictBool,
}


class CrewAIAdapterError(ValueError):
    """Base error for invalid or unsupported CrewAI binding context."""


class UnsupportedCrewAIRuntimeError(CrewAIAdapterError):
    """The deployment did not install the exact CrewAI artifact this adapter verifies."""


class MissingCrewTaskIdentityError(CrewAIAdapterError):
    """The replacement did not run inside an active CrewAI task."""


class CrewAIProfileViolationError(CrewAIAdapterError):
    """The host did not register the generated MasuGate replacements exclusively."""


@dataclass(frozen=True, slots=True)
class CrewAITrustedContext:
    """Deployment-owned identity for one CrewAI execution generation.

    ``principal_id``, ``crew_id``, and ``crew_generation`` are created by the
    deployment; model arguments cannot supply or override them.  CrewAI's
    active ``Task.id`` is combined with the governed tool name to identify one
    logical MasuGate invocation.  Consequently a task may issue one logical call
    for each governed name.  It must use a distinct task for a second intended
    call to the same governed tool.
    """

    principal_id: str
    crew_id: str
    crew_generation: str
    source_namespace: str = "crewai"

    def __post_init__(self) -> None:
        for name in ("principal_id", "crew_id", "crew_generation", "source_namespace"):
            value = getattr(self, name)
            if type(value) is not str or not value or value != value.strip():
                raise CrewAIAdapterError(f"{name} must be a non-empty, trimmed string")

    def invocation_for(
        self,
        task_id: str,
        host_tool: str,
        *,
        adapter_id: str,
        capabilities: tuple[str, ...],
    ) -> TrustedInvocation:
        """Bind one active CrewAI task/tool pair to a stable MasuGate invocation."""

        _validate_task_id(task_id)
        if type(host_tool) is not str or not host_tool or host_tool != host_tool.strip():
            raise MissingCrewTaskIdentityError("CrewAI did not provide a valid governed tool name")
        source_identity = _identity(
            "source",
            self.principal_id,
            self.source_namespace,
            self.crew_id,
            self.crew_generation,
            task_id,
            host_tool,
        )
        trace_identity = _identity(
            "trace",
            self.principal_id,
            self.source_namespace,
            self.crew_id,
            self.crew_generation,
            task_id,
            host_tool,
        )
        return TrustedInvocation(
            principal_id=self.principal_id,
            source_namespace=self.source_namespace,
            source_id=source_identity,
            stable_id_override=source_identity,
            trace_id=trace_identity,
            adapter=AdapterCapabilities(adapter_id=adapter_id, capabilities=capabilities),
        )

    def control_invocation(
        self,
        *,
        adapter_id: str,
        capabilities: tuple[str, ...],
    ) -> TrustedInvocation:
        """Create a non-effecting invocation context for pending control-plane reads."""

        source_identity = _identity(
            "pending-control",
            self.principal_id,
            self.source_namespace,
            self.crew_id,
            self.crew_generation,
        )
        return TrustedInvocation(
            principal_id=self.principal_id,
            source_namespace=self.source_namespace,
            source_id=source_identity,
            stable_id_override=source_identity,
            trace_id=source_identity,
            adapter=AdapterCapabilities(adapter_id=adapter_id, capabilities=capabilities),
        )


@dataclass(frozen=True, slots=True)
class CrewAIGovernedToolset:
    """Generated MasuGate ``BaseTool`` replacements for one bounded CrewAI profile."""

    tools: tuple[BaseTool, ...]
    client: GovernedActionClient
    routes: GovernedRouteParser
    trusted_context: CrewAITrustedContext
    adapter_id: str
    capabilities: tuple[str, ...]

    async def resume_pending(self, locator: object) -> dict[str, object]:
        """Re-read a MasuGate locator after separately authorized MasuGate resolution.

        CrewAI's task retries may instead invoke the same replacement again;
        that uses the same task/tool identity and is a MasuGate replay.  This
        explicit method is for an application UI that retains the locator.
        It does not accept an approval value and never calls a native tool.
        """

        runtime = GovernedToolRuntime(
            client=self.client,
            routes=self.routes,
            invocation=self.trusted_context.control_invocation(
                adapter_id=self.adapter_id,
                capabilities=self.capabilities,
            ),
        )
        return _render_presentation(await runtime.resume_pending(locator))

    def validate_complete_mediation(self, registered_tools: Iterable[BaseTool]) -> None:
        """Require exactly the generated object at every governed tool name.

        Call this on the list passed to an ``Agent`` or task before starting a
        crew.  It makes a missing replacement or a same-named raw tool a
        configuration error rather than a best-effort hook observation.
        """

        expected = {tool.name: tool for tool in self.tools}
        registered = tuple(registered_tools)
        matching = {
            name: tuple(tool for tool in registered if tool.name == name) for name in expected
        }
        missing = sorted(name for name, candidates in matching.items() if not candidates)
        if missing:
            raise CrewAIProfileViolationError(
                "complete mediation is missing generated MasuGate tools: " + ", ".join(missing)
            )
        duplicate = sorted(name for name, candidates in matching.items() if len(candidates) != 1)
        if duplicate:
            raise CrewAIProfileViolationError(
                "complete mediation registered multiple tools for: " + ", ".join(duplicate)
            )
        substituted = sorted(
            name
            for name, expected_tool in expected.items()
            if matching[name][0] is not expected_tool
        )
        if substituted:
            raise CrewAIProfileViolationError(
                "complete mediation registered a non-MasuGate tool for: " + ", ".join(substituted)
            )


def reattach_restored_crewai_tools(
    restored: Crew | Task,
    toolset: CrewAIGovernedToolset,
) -> None:
    """Rebind generated replacements after a CrewAI checkpoint restoration.

    CrewAI serializes a generated ``_MasuGateCrewAITool`` as a Pydantic model but
    intentionally omits its private MasuGate binding.  This helper replaces only
    those restored generated objects with the newly bound objects in
    ``toolset``.  It never recreates a task, so CrewAI's restored ``Task.id``
    remains the MasuGate replay identity.  Call it after ``Crew.from_checkpoint``
    (or an equivalent restored ``Task``) and before resuming execution.

    Raw tools are deliberately left unchanged: complete-mediation validation
    must still reject a raw same-named substitute rather than this helper
    silently converting it into a governed replacement.
    """

    verify_pinned_crewai_runtime()
    replacements = {tool.name: tool for tool in toolset.tools}
    if len(replacements) != len(toolset.tools):
        raise CrewAIProfileViolationError("generated MasuGate tool names must be unique")

    seen_tool_lists: set[int] = set()
    for tools in _restored_tool_lists(restored):
        if tools is None or id(tools) in seen_tool_lists:
            continue
        seen_tool_lists.add(id(tools))
        for index, restored_tool in enumerate(tools):
            if not isinstance(restored_tool, _MasuGateCrewAITool):
                continue
            replacement = replacements.get(restored_tool.name)
            if replacement is None:
                raise CrewAIProfileViolationError(
                    "restored generated MasuGate tool is absent from the new toolset: "
                    + restored_tool.name
                )
            tools[index] = replacement


def verify_pinned_crewai_runtime() -> None:
    """Reject any installed CrewAI distribution other than the verified release."""

    _require_distribution("crewai", CREWAI_VERSION)
    _require_distribution("crewai-core", CREWAI_CORE_VERSION)


def create_crewai_governed_toolset(
    client: GovernedActionClient,
    manifest: object,
    trusted_context: CrewAITrustedContext,
    *,
    adapter_id: str = "masugate.crewai",
    capabilities: tuple[str, ...] = _DEFAULT_CAPABILITIES,
    descriptions: Mapping[str, str] | None = None,
) -> CrewAIGovernedToolset:
    """Create generated, replacement-only MasuGate ``BaseTool`` instances.

    Register only ``toolset.tools`` for governed names and call
    ``toolset.validate_complete_mediation`` on the resulting agent/task tool
    list before starting the crew.  Hooks are not an authorization path and no
    generated tool wraps or calls a native consequential implementation.
    """

    verify_pinned_crewai_runtime()
    if type(adapter_id) is not str or not adapter_id or adapter_id != adapter_id.strip():
        raise CrewAIAdapterError("adapter_id must be a non-empty, trimmed string")
    validated_manifest = validate_any_governed_route_manifest(manifest)
    routes = GovernedRouteParser(manifest)
    description_map = dict(descriptions or {})
    raw_routes = cast(list[Mapping[str, object]], validated_manifest["routes"])
    host_tools = tuple(cast(str, route["host_tool"]) for route in raw_routes)
    unknown_descriptions = set(description_map) - set(host_tools)
    if unknown_descriptions:
        names = ", ".join(sorted(unknown_descriptions))
        raise CrewAIAdapterError(f"descriptions name unknown governed tools: {names}")

    tools = tuple(
        _create_tool(
            client=client,
            routes=routes,
            spec=routes.select(host_tool),
            trusted_context=trusted_context,
            adapter_id=adapter_id,
            capabilities=capabilities,
            description=description_map.get(
                host_tool,
                f"Submit the governed MasuGate action {routes.select(host_tool).action}; "
                "MasuGate returns the authoritative result.",
            ),
        )
        for host_tool in host_tools
    )
    return CrewAIGovernedToolset(
        tools=tools,
        client=client,
        routes=routes,
        trusted_context=trusted_context,
        adapter_id=adapter_id,
        capabilities=capabilities,
    )


@dataclass(frozen=True, slots=True)
class _ToolBinding:
    client: GovernedActionClient
    routes: GovernedRouteParser
    spec: GovernedToolSpec
    trusted_context: CrewAITrustedContext
    adapter_id: str
    capabilities: tuple[str, ...]


class _MasuGateCrewStructuredTool(CrewStructuredTool):
    """Use the generated tool's async entry point without losing task context.

    CrewAI 1.15.6 dispatches a synchronous ``func`` through an executor from
    ``ainvoke``.  The executor boundary does not reliably resolve when used
    under its supported pytest asyncio profile.  The generated replacement has
    a semantically equivalent ``_arun`` entry point, so retain the active task
    context by awaiting that entry point directly instead of crossing the
    executor boundary.
    """

    async def ainvoke(
        self,
        input: str | dict[str, Any],
        config: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any:
        parsed_args = self._parse_args(input)
        if self.has_reached_max_usage_count():
            raise ToolUsageLimitExceededError(
                f"Tool '{self.name}' has reached its maximum usage count of {self.max_usage_count}."
            )
        self._increment_usage_count()
        original = self._original_tool
        if not isinstance(original, _MasuGateCrewAITool):
            raise CrewAIProfileViolationError("generated MasuGate tool lost its async binding")
        return await original._arun(**parsed_args, **kwargs)


class _MasuGateCrewAITool(BaseTool):
    """A generated ``BaseTool`` whose only effect path is ``GovernedToolRuntime``."""

    _binding: _ToolBinding = PrivateAttr()

    def _run(self, **model_arguments: object) -> dict[str, object]:
        return _run_sync(self._invoke_governed(model_arguments))

    async def _arun(self, **model_arguments: object) -> dict[str, object]:
        return await self._invoke_governed(model_arguments)

    async def _invoke_governed(self, model_arguments: Mapping[str, object]) -> dict[str, object]:
        binding = self._binding
        task_id = _current_task_id()
        invocation = binding.trusted_context.invocation_for(
            task_id,
            binding.spec.host_tool,
            adapter_id=binding.adapter_id,
            capabilities=binding.capabilities,
        )
        runtime = GovernedToolRuntime(
            client=binding.client,
            routes=binding.routes,
            invocation=invocation,
        )
        return _render_lifecycle(await runtime.invoke(binding.spec.host_tool, model_arguments))

    def format_output_for_agent(self, raw_result: object) -> str:
        """Return the model-visible lifecycle as canonical JSON, never native prose."""

        return json.dumps(raw_result, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def to_structured_tool(self) -> CrewStructuredTool:
        """Preserve CrewAI task context for both sync and async crew execution."""

        structured_tool = _MasuGateCrewStructuredTool(
            name=self.name,
            description=self.description,
            args_schema=self.args_schema,
            result_schema=self.result_schema,
            func=self._run,
            result_as_answer=self.result_as_answer,
            max_usage_count=self.max_usage_count,
            current_usage_count=self.current_usage_count,
            cache_function=self.cache_function,
        )
        structured_tool._original_tool = self
        return structured_tool


def _restored_tool_lists(restored: Crew | Task) -> tuple[list[BaseTool] | None, ...]:
    """Return every tool collection that a restored CrewAI object can execute."""

    if isinstance(restored, Task):
        agent_tools = restored.agent.tools if restored.agent is not None else None
        return (restored.tools, agent_tools)

    agent_collections: list[list[BaseTool] | None] = [agent.tools for agent in restored.agents]
    if restored.manager_agent is not None:
        agent_collections.append(restored.manager_agent.tools)
    task_collections: list[list[BaseTool] | None] = [task.tools for task in restored.tasks]
    return tuple([*task_collections, *agent_collections])


def _create_tool(
    *,
    client: GovernedActionClient,
    routes: GovernedRouteParser,
    spec: GovernedToolSpec,
    trusted_context: CrewAITrustedContext,
    adapter_id: str,
    capabilities: tuple[str, ...],
    description: str,
) -> BaseTool:
    tool = _MasuGateCrewAITool(
        name=spec.host_tool,
        description=description,
        args_schema=_arguments_schema(spec),
        cache_function=_never_cache,
    )
    tool._binding = _ToolBinding(
        client=client,
        routes=routes,
        spec=spec,
        trusted_context=trusted_context,
        adapter_id=adapter_id,
        capabilities=capabilities,
    )
    return tool


def _arguments_schema(spec: GovernedToolSpec) -> type[BaseModel]:
    if spec.arguments is not None:
        fields: dict[str, Any] = {
            name: (
                _ARGUMENT_TYPES[kind],
                Field(
                    ...,
                    description=f"Canonical {kind} argument for MasuGate action {spec.action}.",
                ),
            )
            for name, kind in spec.arguments.items()
        }
    else:
        assert spec.input_schema is not None
        properties = cast(dict[str, object], spec.input_schema["properties"])
        required = set(cast(list[str], spec.input_schema["required"]))
        fields = {
            name: (
                _bounded_schema_type(
                    cast(Mapping[str, object], properties[name]),
                    f"MasuGate{_model_component(spec.host_tool)}{_model_component(name)}",
                ),
                Field(
                    ... if name in required else MISSING,
                    description=f"Bounded v2 operation input for MasuGate action {spec.action}.",
                ),
            )
            for name in properties
        }
    return cast(
        type[BaseModel],
        create_model(
            "MasuGate" + "".join(part.title() for part in spec.host_tool.split("_")) + "Arguments",
            __config__=ConfigDict(extra="forbid", strict=True),
            **fields,
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
    return "".join(part.title() for part in value.split("_"))


def _never_cache(_arguments: object = None, _result: object = None) -> bool:
    """Force every CrewAI retry to re-enter MasuGate instead of returning a cached lifecycle."""

    return False


def _require_distribution(distribution: str, expected: str) -> None:
    try:
        installed = version(distribution)
    except PackageNotFoundError as exc:
        raise UnsupportedCrewAIRuntimeError(f"{distribution} is not installed") from exc
    if installed != expected:
        raise UnsupportedCrewAIRuntimeError(
            f"masugate-crewai requires {distribution}=={expected}, got {installed}"
        )


def _current_task_id() -> str:
    task_id = get_current_task_id()
    _validate_task_id(task_id)
    return cast(str, task_id)


def _validate_task_id(task_id: object) -> None:
    if type(task_id) is not str or not task_id or task_id != task_id.strip():
        raise MissingCrewTaskIdentityError(
            "CrewAI did not provide an active task id; use the generated tool inside a CrewAI task"
        )


def _identity(label: str, *parts: str) -> str:
    canonical = json.dumps([label, *parts], ensure_ascii=False, separators=(",", ":"))
    return _IDENTITY_PREFIX + sha256(canonical.encode("utf-8")).hexdigest()


def _run_sync(coroutine: Coroutine[Any, Any, dict[str, object]]) -> dict[str, object]:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    coroutine.close()
    raise CrewAIAdapterError("use await tool.arun(...) while an event loop is running")


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
        "kind": "masugate.pending.v1",
        "status": "pending",
        "operation_id": presentation.operation_id,
        "pending_id": presentation.pending_id,
        "native_effect_permitted": False,
        "retry_as_new_action": False,
    }
