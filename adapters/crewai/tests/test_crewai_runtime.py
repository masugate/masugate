"""Pinned CrewAI ``BaseTool`` tests for the bounded MasuGate replacement profile."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import httpx
import pytest
from crewai import Agent, Crew, Task
from crewai.context import reset_current_task_id, set_current_task_id
from crewai.state.checkpoint_config import CheckpointConfig
from crewai.state.runtime import RuntimeState
from crewai.tools import BaseTool
from masugate.errors import ResourceError
from masugate.model import ActionRequest, DecisionEffect, OperationResult, PolicyDecision
from masugate.masugated import ActionOwnerBinding, create_app
from masugate.provider_assembly import EffectExecutionPosition
from masugate_adapter_core import (
    ChangedInvocationConflictError,
    load_adapter_core_conformance_fixture,
    run_adapter_core_conformance,
)
from masugate_client import (
    ActionResult,
    AuditRecord,
    Decision,
    PendingLookup,
    PendingOperation,
    MasuGateClient,
)

from masugate_crewai import (
    CREWAI_CORE_VERSION,
    CREWAI_VERSION,
    CrewAIProfileViolationError,
    CrewAITrustedContext,
    MissingCrewTaskIdentityError,
    create_crewai_governed_toolset,
    reattach_restored_crewai_tools,
    verify_pinned_crewai_runtime,
)

FIXTURE_PATH = Path(__file__).parents[3] / "protocol" / "examples" / "adapter-core-conformance.json"
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
V2_FIXTURE_PATH = (
    Path(__file__).parents[3]
    / "protocol"
    / "examples"
    / "governed-route-manifest-v2-route-fixture.json"
)
V2_FIXTURE = json.loads(V2_FIXTURE_PATH.read_text(encoding="utf-8"))
CONTEXT = CrewAITrustedContext(
    principal_id="adapter:buyer",
    crew_id="deployment-crew-42",
    crew_generation="generation-7",
)
TASK_ONE = "00000000-0000-4000-8000-000000000001"
TASK_TWO = "00000000-0000-4000-8000-000000000002"


def _decision(status: str) -> Decision:
    return Decision(
        effect={"committed": "allow", "denied": "deny", "pending": "escalate"}.get(status, "allow"),
        policy_id="crewai-test",
        policy_version="v1",
        rule_id="test-rule",
        reason="CrewAI adapter test result",
    )


class _Client:
    def __init__(self, status: str = "committed") -> None:
        self.status = status
        self.calls: list[dict[str, object]] = []
        self._bindings: dict[str, tuple[object, ...]] = {}
        self._results: dict[str, ActionResult] = {}
        self._pending_operations: dict[str, str] = {}
        self.pending_reads: list[str] = []
        self.resolve_pending_to_terminal = False

    async def execute(self, action: str, args: Any, stable_id: str, **kwargs: Any) -> ActionResult:
        binding = (action, tuple(sorted(args.items())), kwargs["adapter_invocation"])
        previous = self._bindings.setdefault(stable_id, binding)
        if previous != binding:
            raise ChangedInvocationConflictError(
                "trusted source invocation is already bound to different canonical content"
            )
        self.calls.append({"action": action, "args": dict(args), "stable_id": stable_id, **kwargs})
        existing = self._results.get(stable_id)
        if existing is not None:
            return replace(existing, replayed=True)
        operation_id = str(uuid4())
        pending_id = str(uuid4()) if self.status == "pending" else None
        result = ActionResult(
            operation_id=operation_id,
            status=cast(Any, self.status),
            decision=(
                None
                if self.status in {"in_progress", "outcome_unknown"}
                else _decision(self.status)
            ),
            payload={"effect_count": len(self._results) + 1},
            audit_ref=f"/v1/audit/{operation_id}",
            replayed=False,
            pending_id=pending_id,
        )
        self._results[stable_id] = result
        if pending_id is not None:
            self._pending_operations[pending_id] = operation_id
        return result

    async def get_pending(self, pending_id: str) -> PendingLookup:
        self.pending_reads.append(pending_id)
        operation_id = self._pending_operations[pending_id]
        if self.resolve_pending_to_terminal:
            return PendingLookup(
                kind="terminal",
                result=ActionResult(
                    operation_id=operation_id,
                    status="committed",
                    decision=_decision("committed"),
                    payload={"effect_count": 1},
                    audit_ref=f"/v1/audit/{operation_id}",
                    replayed=True,
                    pending_id=None,
                ),
            )
        return PendingLookup(
            kind="pending",
            pending=PendingOperation(
                pending_id=pending_id,
                operation_id=operation_id,
                principal_id=CONTEXT.principal_id,
                action="spend.purchase",
                args=cast(dict[str, str | int | bool], FIXTURE["model_arguments"]),
                created_at=datetime.now(UTC),
                decision=_decision("pending"),
                audit_ref=f"/v1/audit/{operation_id}",
            ),
        )

    async def cancel_pending(self, pending_id: str) -> dict[str, object]:
        return {
            "kind": "cancellation",
            "locator": {
                "operation_id": self._pending_operations[pending_id],
                "pending_id": pending_id,
            },
            "accepted": True,
        }

    async def get_audit(self, operation_id: str) -> AuditRecord:
        return cast(AuditRecord, SimpleNamespace(operation_id=operation_id))


class _ConformanceClientFactory:
    def __init__(self) -> None:
        self.clients: dict[str, _Client] = {}

    def __call__(self, scenario: str) -> _Client:
        existing = self.clients.get(scenario)
        if existing is not None:
            return existing
        if scenario == "pending-terminal":
            client: _Client = _Client("pending")
            client.resolve_pending_to_terminal = True
        elif scenario.startswith("lifecycle-"):
            client = _Client(scenario.removeprefix("lifecycle-"))
        elif scenario == "locator-checks":
            client = _LocatorMismatchClient("pending")
        elif scenario == "pending-resume":
            client = _Client("pending")
        else:
            client = _Client()
        self.clients[scenario] = client
        return client


class _MasuGatedCoordinator:
    def __init__(self) -> None:
        self.calls = 0
        self._bindings: dict[str, tuple[object, ...]] = {}
        self._results: dict[str, OperationResult] = {}

    async def execute(self, request: ActionRequest) -> OperationResult:
        binding = (
            request.principal.id,
            request.action,
            tuple(sorted(request.arguments.items())),
            request.adapter_invocation_digest,
        )
        previous = self._bindings.setdefault(request.idempotency_key, binding)
        if previous != binding:
            raise ResourceError("idempotency key is already bound to different request content")
        existing = self._results.get(request.idempotency_key)
        if existing is not None:
            return replace(existing, replayed=True)
        self.calls += 1
        result = OperationResult(
            operation_id=request.operation_id,
            decision=PolicyDecision(
                effect=DecisionEffect.ALLOW,
                policy_id="crewai-real-masugated",
                policy_version="v1",
                rule_id="allow",
                reason="real masugated CrewAI adapter test",
            ),
            committed=True,
            payload={"effect_count": self.calls},
        )
        self._results[request.idempotency_key] = result
        return result


class _LocatorMismatchClient(_Client):
    """Return control-plane locators that name a different authoritative operation."""

    _other_operation_id = "00000000-0000-4000-8000-000000000099"

    async def get_pending(self, pending_id: str) -> PendingLookup:
        self.pending_reads.append(pending_id)
        return PendingLookup(
            kind="pending",
            pending=PendingOperation(
                pending_id=pending_id,
                operation_id=self._other_operation_id,
                principal_id=CONTEXT.principal_id,
                action="spend.purchase",
                args=cast(dict[str, str | int | bool], FIXTURE["model_arguments"]),
                created_at=datetime.now(UTC),
                decision=_decision("pending"),
                audit_ref=f"/v1/audit/{self._other_operation_id}",
            ),
        )

    async def cancel_pending(self, pending_id: str) -> dict[str, object]:
        return {
            "kind": "cancellation",
            "locator": {
                "operation_id": self._other_operation_id,
                "pending_id": pending_id,
            },
            "accepted": True,
        }

    async def get_audit(self, operation_id: str) -> AuditRecord:
        return cast(AuditRecord, SimpleNamespace(operation_id=self._other_operation_id))


class _RawPurchaseTool(BaseTool):
    name: str = "purchase"
    description: str = "raw consequential tool"
    invoked: bool = False

    def _run(self, **_: object) -> str:
        self.invoked = True
        return "raw native effect"


def _toolset(client: _Client):
    return create_crewai_governed_toolset(client, FIXTURE["manifest"], CONTEXT)


def _nested_schema(root: dict[str, object], property_name: str) -> dict[str, object]:
    properties = cast(dict[str, object], root["properties"])
    property_schema = cast(dict[str, object], properties[property_name])
    reference = cast(str, property_schema["$ref"])
    assert reference.startswith("#/$defs/")
    definitions = cast(dict[str, object], root["$defs"])
    return cast(dict[str, object], definitions[reference.removeprefix("#/$defs/")])


@contextmanager
def _task_scope(task_id: str) -> Iterator[None]:
    token = set_current_task_id(task_id)
    try:
        yield
    finally:
        reset_current_task_id(token)


def _sync_call(tool: BaseTool, task_id: str, **arguments: object) -> dict[str, object]:
    with _task_scope(task_id):
        return cast(dict[str, object], tool.to_structured_tool().invoke(arguments))


async def _async_call(tool: BaseTool, task_id: str, **arguments: object) -> dict[str, object]:
    with _task_scope(task_id):
        return cast(dict[str, object], await tool.to_structured_tool().ainvoke(arguments))


def test_pinned_runtime_and_generated_base_tool_are_exact_replacements() -> None:
    verify_pinned_crewai_runtime()
    assert version("crewai") == CREWAI_VERSION
    assert version("crewai-core") == CREWAI_CORE_VERSION

    client = _Client()
    toolset = _toolset(client)
    tool = toolset.tools[0]
    structured = tool.to_structured_tool()

    assert isinstance(tool, BaseTool)
    assert tool.name == "purchase"
    assert set(tool.args_schema.model_fields) == set(FIXTURE["model_arguments"])
    assert structured.cache_function(FIXTURE["model_arguments"], "ignored") is False
    assert "principal_id" not in tool.args_schema.model_fields
    assert "crew_id" not in tool.args_schema.model_fields


def test_v2_generated_tool_schema_preserves_nested_bounded_constraints() -> None:
    tool = create_crewai_governed_toolset(_Client(), V2_FIXTURE, CONTEXT).tools[0]
    schema = cast(dict[str, object], tool.args_schema.model_json_schema())
    properties = cast(dict[str, dict[str, object]], schema["properties"])

    assert schema["additionalProperties"] is False
    assert properties["recipient"]["minLength"] == 3
    assert properties["recipient"]["maxLength"] == 320
    metadata = _nested_schema(schema, "metadata")
    labels = cast(dict[str, object], cast(dict[str, object], metadata["properties"])["labels"])
    priority = cast(dict[str, object], cast(dict[str, object], metadata["properties"])["priority"])
    assert metadata["additionalProperties"] is False
    assert labels["maxItems"] == 8
    assert cast(dict[str, object], labels["items"])["maxLength"] == 48
    assert priority["minimum"] == 0
    assert priority["maximum"] == 9
    assert "default" not in priority
    parsed = tool.args_schema.model_validate(
        {"recipient": "recipient", "subject": "subject", "metadata": {"labels": []}}
    )
    assert "priority" not in parsed.model_dump()["metadata"]


def test_base_tool_requires_real_crewai_task_context_and_rejects_forged_fields() -> None:
    client = _Client()
    tool = _toolset(client).tools[0]

    with pytest.raises(MissingCrewTaskIdentityError, match="active task id"):
        tool.run(**FIXTURE["model_arguments"])
    with _task_scope(TASK_ONE), pytest.raises(ValueError, match="Extra inputs"):
        tool.run(**{**FIXTURE["model_arguments"], "principal_id": "model-controlled"})
    assert client.calls == []


def test_real_base_tool_replays_task_retry_and_changed_content_fails_closed() -> None:
    client = _Client()
    tool = _toolset(client).tools[0]

    first = _sync_call(tool, TASK_ONE, **FIXTURE["model_arguments"])
    replay = _sync_call(tool, TASK_ONE, **FIXTURE["model_arguments"])

    assert first["kind"] == "masugate.lifecycle.v1"
    assert first["status"] == "committed"
    assert replay["operation_id"] == first["operation_id"]
    assert replay["replayed"] is True
    assert len(client._results) == 1
    assert len(client.calls) == 2

    with pytest.raises(ChangedInvocationConflictError):
        _sync_call(tool, TASK_ONE, **{**FIXTURE["model_arguments"], "amount_cents": 1251})
    assert len(client._results) == 1


def test_real_crewai_task_sets_the_identity_seen_by_the_replacement() -> None:
    client = _Client()
    toolset = _toolset(client)
    agent = Agent(
        role="MasuGate test agent",
        goal="exercise one generated replacement",
        backstory="A local CrewAI task-level contract test.",
        llm="openai/gpt-4o-mini",
    )

    def execute_generated_tool(*, task: Task, context: str | None, tools: list[BaseTool]) -> str:
        del task, context
        result = tools[0].to_structured_tool().invoke(FIXTURE["model_arguments"])
        return json.dumps(result)

    object.__setattr__(agent, "execute_task", execute_generated_tool)
    task = Task(
        description="Call the generated purchase replacement.",
        expected_output="The MasuGate lifecycle.",
        agent=agent,
        tools=list(toolset.tools),
    )

    output = task.execute_sync()

    lifecycle = json.loads(output.raw)
    assert lifecycle["status"] == "committed"
    assert lifecycle["native_effect_permitted"] is False
    assert len(client._results) == 1


def test_real_crewai_task_guardrail_retry_replays_one_masugate_operation() -> None:
    client = _Client()
    toolset = _toolset(client)
    agent = Agent(
        role="MasuGate retry test agent",
        goal="exercise one generated replacement twice",
        backstory="A local CrewAI task-retry contract test.",
        llm="openai/gpt-4o-mini",
    )
    guardrail_calls = 0

    def execute_generated_tool(*, task: Task, context: str | None, tools: list[BaseTool]) -> str:
        del task, context
        result = tools[0].to_structured_tool().invoke(FIXTURE["model_arguments"])
        return json.dumps(result)

    def reject_once(result: object):
        nonlocal guardrail_calls
        guardrail_calls += 1
        return (guardrail_calls == 2, result if guardrail_calls == 2 else "retry once")

    object.__setattr__(agent, "execute_task", execute_generated_tool)
    task = Task(
        description="Retry the generated purchase replacement once.",
        expected_output="The MasuGate lifecycle.",
        agent=agent,
        tools=list(toolset.tools),
        guardrail=reject_once,
        guardrail_max_retries=1,
    )

    output = task.execute_sync()

    assert json.loads(output.raw)["status"] == "committed"
    assert guardrail_calls == 2
    assert len(client._results) == 1
    assert len(client.calls) == 2


@pytest.mark.asyncio
async def test_async_crewai_dispatch_preserves_the_active_task_context() -> None:
    client = _Client()
    tool = _toolset(client).tools[0]

    result = await _async_call(tool, TASK_ONE, **FIXTURE["model_arguments"])

    assert result["status"] == "committed"
    assert len(client._results) == 1
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_parallel_identical_arguments_in_distinct_tasks_remain_distinct() -> None:
    client = _Client()
    tool = _toolset(client).tools[0]

    first, second = await asyncio.gather(
        _async_call(tool, TASK_ONE, **FIXTURE["model_arguments"]),
        _async_call(tool, TASK_TWO, **FIXTURE["model_arguments"]),
    )

    assert first["operation_id"] != second["operation_id"]
    assert len(client._results) == 2
    assert len({cast(str, call["trace_id"]) for call in client.calls}) == 2


@pytest.mark.asyncio
async def test_checkpoint_restore_rebinds_tools_and_replays_the_restored_task(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CREWAI_STORAGE_DIR", str(tmp_path / "crewai-storage"))
    client = _Client("pending")
    first_toolset = _toolset(client)
    agent = Agent(
        role="MasuGate checkpoint test agent",
        goal="retain governed task identity through a real CrewAI checkpoint",
        backstory="A local CrewAI checkpoint-restoration contract test.",
        llm="openai/gpt-4o-mini",
        tools=list(first_toolset.tools),
    )
    task = Task(
        description="Resume a generated purchase replacement after restoration.",
        expected_output="The MasuGate lifecycle.",
        agent=agent,
        tools=list(first_toolset.tools),
    )
    crew = Crew(agents=[agent], tasks=[task])
    pending = await _async_call(first_toolset.tools[0], str(task.id), **FIXTURE["model_arguments"])

    assert pending["status"] == "pending"
    assert pending["native_effect_permitted"] is False
    assert pending["retry_as_new_action"] is False

    checkpoint = RuntimeState(root=[crew]).checkpoint(str(tmp_path / "checkpoints"))
    restored_crew = Crew.from_checkpoint(CheckpointConfig(restore_from=checkpoint))
    restored_task = restored_crew.tasks[0]

    assert restored_task.id == task.id
    assert not hasattr(restored_task.tools[0], "_binding")
    assert restored_crew.agents[0].tools is not None
    assert not hasattr(restored_crew.agents[0].tools[0], "_binding")

    restarted = _toolset(client)
    reattach_restored_crewai_tools(restored_crew, restarted)
    assert restored_task.id == task.id
    assert restored_task.tools == [*restarted.tools]
    assert restored_crew.agents[0].tools == [*restarted.tools]
    restarted.validate_complete_mediation(restored_task.tools)
    restarted.validate_complete_mediation(restored_crew.agents[0].tools)

    replay = await _async_call(
        restored_task.tools[0], str(restored_task.id), **FIXTURE["model_arguments"]
    )
    assert replay["operation_id"] == pending["operation_id"]
    assert replay["replayed"] is True

    client.resolve_pending_to_terminal = True
    resumed = await restarted.resume_pending(pending["locator"])
    assert resumed["kind"] == "masugate.lifecycle.v1"
    assert resumed["status"] == "committed"
    assert resumed["operation_id"] == pending["operation_id"]
    assert client.pending_reads == [pending["pending_id"]]


@pytest.mark.asyncio
async def test_real_pinned_crewai_profile_replays_one_operation_through_masugated() -> None:
    coordinator = _MasuGatedCoordinator()
    app = create_app(
        coordinator,  # type: ignore[arg-type]
        cast(Any, object()),
        {"crewai-token": CONTEXT.principal_id},
        action_owners={
            "spend.purchase": ActionOwnerBinding(
                provider_id="spend-v1",
                position=EffectExecutionPosition.PROTECTED_EXTERNAL,
                connector_id="purchase-v1",
            )
        },
        adapter_invocation_principals={CONTEXT.principal_id},
    )
    async with MasuGateClient(
        "http://masugated.test",
        "crewai-token",
        principal_id=CONTEXT.principal_id,
        transport=httpx.ASGITransport(app=app),
    ) as client:
        tool = create_crewai_governed_toolset(client, FIXTURE["manifest"], CONTEXT).tools[0]
        first = await _async_call(tool, TASK_ONE, **FIXTURE["model_arguments"])
        replay = await _async_call(tool, TASK_ONE, **FIXTURE["model_arguments"])

    assert first["status"] == "committed"
    assert replay["operation_id"] == first["operation_id"]
    assert replay["replayed"] is True
    assert coordinator.calls == 1


def test_complete_mediation_rejects_missing_and_raw_same_named_tools() -> None:
    client = _Client()
    toolset = _toolset(client)
    raw = _RawPurchaseTool()

    with pytest.raises(CrewAIProfileViolationError, match="missing"):
        toolset.validate_complete_mediation([])
    with pytest.raises(CrewAIProfileViolationError, match="non-MasuGate"):
        toolset.validate_complete_mediation([raw])
    with pytest.raises(CrewAIProfileViolationError, match="multiple"):
        toolset.validate_complete_mediation([*toolset.tools, raw])
    toolset.validate_complete_mediation(toolset.tools)
    assert raw.invoked is False
    assert client.calls == []


@pytest.mark.asyncio
async def test_shared_adapter_core_conformance_cases_remain_green() -> None:
    fixture = load_adapter_core_conformance_fixture()
    report = await run_adapter_core_conformance(_ConformanceClientFactory(), fixture)

    assert report.conformance_version == "masugate.adapter-core-conformance.v1"
    assert report.passed_case_ids == tuple(item["id"] for item in FIXTURE["scenarios"])
