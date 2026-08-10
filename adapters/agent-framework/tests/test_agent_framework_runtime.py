"""End-to-end tests for the verified MAF Core 1.12.0 profile."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import httpx
import pytest
from agent_framework import (
    Agent,
    AgentSession,
    BaseChatClient,
    ChatResponse,
    Content,
    FunctionInvocationContext,
    FunctionInvocationLayer,
    FunctionTool,
    Message,
)
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

from masugate_agent_framework import (
    MAF_CORE_VERSION,
    TRUSTED_CONTEXT_KEY,
    MafPendingStateError,
    MafProfileViolationError,
    MafTrustedContext,
    MissingToolCallIdentityError,
    create_maf_governed_toolset,
)

FIXTURE_PATH = Path(__file__).parents[3] / "protocol" / "examples" / "adapter-core-conformance.json"
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
V2_FIXTURE = json.loads(
    (
        Path(__file__).parents[3]
        / "protocol"
        / "examples"
        / "governed-route-manifest-v2-route-fixture.json"
    ).read_text(encoding="utf-8")
)
CONTEXT = MafTrustedContext(
    principal_id="adapter:buyer",
    session_id="maf-session-42",
    session_generation="generation-7",
)


def _decision(status: str) -> Decision:
    return Decision(
        effect={"committed": "allow", "denied": "deny", "pending": "escalate"}.get(status, "allow"),
        policy_id="maf-test",
        policy_version="v1",
        rule_id="test-rule",
        reason="MAF adapter test result",
    )


class _Client:
    """Deterministic MasuGate client that detects semantic identity collisions."""

    def __init__(self, status: str = "committed") -> None:
        self.status = status
        self.calls: list[dict[str, object]] = []
        self.pending_reads: list[str] = []
        self._bindings: dict[str, tuple[object, ...]] = {}
        self._results: dict[str, ActionResult] = {}
        self._pending_operations: dict[str, str] = {}
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


class _LocatorMismatchClient(_Client):
    _other_operation_id = "00000000-0000-4000-8000-000000000098"

    async def get_pending(self, pending_id: str) -> PendingLookup:
        del pending_id
        return PendingLookup(
            kind="pending",
            pending=PendingOperation(
                pending_id="00000000-0000-4000-8000-000000000099",
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
        del pending_id
        return {
            "kind": "cancellation",
            "locator": {
                "operation_id": self._other_operation_id,
                "pending_id": "00000000-0000-4000-8000-000000000099",
            },
            "accepted": True,
        }

    async def get_audit(self, operation_id: str) -> AuditRecord:
        del operation_id
        return cast(AuditRecord, SimpleNamespace(operation_id=self._other_operation_id))


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
        elif scenario == "locator-checks":
            client = _LocatorMismatchClient("pending")
        elif scenario.startswith("lifecycle-"):
            client = _Client(scenario.removeprefix("lifecycle-"))
        elif scenario == "pending-resume":
            client = _Client("pending")
        else:
            client = _Client()
        self.clients[scenario] = client
        return client


class _ScriptedMafClient(FunctionInvocationLayer[Any], BaseChatClient[Any]):
    """A real MAF function loop driven by one or more model tool calls."""

    def __init__(self, calls: list[Content], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._calls = calls
        self.model_calls = 0
        self.function_results_seen_by_model: list[str] = []

    async def _inner_get_response(
        self,
        *,
        messages: Any,
        stream: bool,
        options: Any,
        **kwargs: Any,
    ) -> ChatResponse[Any]:
        del options, kwargs
        assert not stream
        self.model_calls += 1
        self.function_results_seen_by_model.extend(
            content.result
            for message in messages
            for content in message.contents
            if content.type == "function_result" and isinstance(content.result, str)
        )
        if messages and any(content.type == "function_result" for content in messages[-1].contents):
            return ChatResponse(messages=[Message(role="assistant", contents=["complete"])])
        if self.model_calls == 1:
            return ChatResponse(messages=[Message(role="assistant", contents=self._calls)])
        return ChatResponse(messages=[Message(role="assistant", contents=["complete"])])


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
            raise ResourceError("idempotency key is already bound to a different request")
        existing = self._results.get(request.idempotency_key)
        if existing is not None:
            return replace(existing, replayed=True)
        self.calls += 1
        result = OperationResult(
            operation_id=request.operation_id,
            decision=PolicyDecision(
                effect=DecisionEffect.ALLOW,
                policy_id="maf-real-masugated",
                policy_version="v1",
                rule_id="allow",
                reason="real masugated MAF adapter test",
            ),
            committed=True,
            payload={"effect_count": self.calls},
        )
        self._results[request.idempotency_key] = result
        return result


def _call(call_id: str, *, amount_cents: object = 1250) -> Content:
    return Content.from_function_call(
        call_id=call_id,
        name="purchase",
        arguments={"merchant_id": "merchant-42", "amount_cents": amount_cents},
    )


def _agent(client: _Client, calls: list[Content]) -> Agent[Any]:
    toolset = create_maf_governed_toolset(client, FIXTURE["manifest"])
    return Agent(
        client=_ScriptedMafClient(calls, middleware=[toolset.middleware]),
        tools=list(toolset.tools),
        middleware=[toolset.agent_middleware],
    )


async def _run(agent: Agent[Any], session: AgentSession) -> Any:
    return await agent.run(
        "purchase now",
        session=session,
        function_invocation_kwargs={TRUSTED_CONTEXT_KEY: CONTEXT},
    )


def _lifecycle(response: Any) -> dict[str, object]:
    for message in response.messages:
        for content in message.contents:
            if content.type == "function_result" and isinstance(content.result, str):
                decoded = json.loads(content.result)
                if decoded.get("kind") == "masugate.lifecycle.v1":
                    return cast(dict[str, object], decoded)
    raise AssertionError("MAF response did not contain a MasuGate lifecycle result")


def test_verified_maf_runtime_preserves_the_bounded_nested_v2_tool_schema() -> None:
    manifest = deepcopy(cast(dict[str, object], V2_FIXTURE))
    route = cast(dict[str, object], cast(list[object], manifest["routes"])[0])
    input_schema = cast(dict[str, object], route["input_schema"])
    input_schema["required"] = ["metadata", "recipient"]

    parameters = cast(
        dict[str, object], create_maf_governed_toolset(object(), manifest).tools[0].parameters()
    )
    properties = cast(dict[str, object], parameters["properties"])
    metadata = cast(dict[str, object], properties["metadata"])
    metadata_properties = cast(dict[str, object], metadata["properties"])
    labels = cast(dict[str, object], metadata_properties["labels"])
    label_item = cast(dict[str, object], labels["items"])

    assert parameters["additionalProperties"] is False
    assert parameters["required"] == ["metadata", "recipient"]
    assert "subject" not in cast(list[str], parameters["required"])
    assert metadata["additionalProperties"] is False
    assert metadata["required"] == ["labels"]
    assert labels["maxItems"] == 8
    assert label_item["maxLength"] == 48
    assert cast(dict[str, object], properties["recipient"])["maxLength"] == 320


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["committed", "denied"])
async def test_verified_maf_runtime_generates_typed_replacement_without_native_fallthrough(
    status: str,
) -> None:
    assert version("agent-framework-core") == MAF_CORE_VERSION
    client = _Client(status)
    response = await _run(
        _agent(client, [_call("call-commit")]),
        AgentSession(session_id=CONTEXT.session_id),
    )
    outcome = _lifecycle(response)

    assert response.text == "complete"
    assert outcome["status"] == status
    assert outcome["native_effect_permitted"] is False
    assert outcome["retry_as_new_action"] is False
    assert len(client.calls) == 1
    assert client.calls[0]["expected_principal"] == CONTEXT.principal_id


@pytest.mark.asyncio
async def test_parallel_identical_arguments_with_distinct_maf_ids_are_distinct_operations() -> None:
    client = _Client()
    response = await _run(
        _agent(client, [_call("call-parallel-a"), _call("call-parallel-b")]),
        AgentSession(session_id=CONTEXT.session_id),
    )

    results = [
        json.loads(content.result)
        for message in response.messages
        for content in message.contents
        if content.type == "function_result" and isinstance(content.result, str)
    ]
    assert len(results) == 2
    assert {result["status"] for result in results} == {"committed"}
    assert len({result["operation_id"] for result in results}) == 2
    assert len({cast(str, call["trace_id"]) for call in client.calls}) == 2


@pytest.mark.asyncio
async def test_duplicate_delivery_and_restored_session_replay_one_masugate_operation() -> None:
    client = _Client()
    first_session = AgentSession(session_id=CONTEXT.session_id)
    first = _lifecycle(await _run(_agent(client, [_call("call-replay")]), first_session))
    restored = AgentSession.from_dict(first_session.to_dict())
    replay = _lifecycle(await _run(_agent(client, [_call("call-replay")]), restored))

    assert replay["operation_id"] == first["operation_id"]
    assert replay["replayed"] is True
    assert len(client._results) == 1
    assert client.calls[0]["trace_id"] == client.calls[1]["trace_id"]


@pytest.mark.asyncio
async def test_changed_content_for_one_maf_id_has_no_second_effect() -> None:
    client = _Client()
    session = AgentSession(session_id=CONTEXT.session_id)
    await _run(_agent(client, [_call("call-conflict")]), session)
    response = await _run(_agent(client, [_call("call-conflict", amount_cents=1251)]), session)

    assert len(client._results) == 1
    assert len(client.calls) == 1
    assert any(
        content.type == "function_result" and content.exception is not None
        for message in response.messages
        for content in message.contents
    )


@pytest.mark.asyncio
async def test_pending_presentation_uses_masugate_locator_requery_not_native_approval() -> None:
    client = _Client("pending")
    toolset = create_maf_governed_toolset(client, FIXTURE["manifest"])
    maf_client = _ScriptedMafClient([_call("call-pending")], middleware=[toolset.middleware])
    agent = Agent(
        client=maf_client,
        tools=list(toolset.tools),
        middleware=[toolset.agent_middleware],
    )
    session = AgentSession(session_id=CONTEXT.session_id)
    first = await _run(agent, session)
    pending = _lifecycle(first)
    locator = pending["locator"]

    assert pending["status"] == "pending"
    assert all(
        content.type != "function_approval_request"
        for message in first.messages
        for content in message.contents
    )
    assert len(client.calls) == 1

    # A host cannot receive this response from the profile: it has no native
    # MAF approval request to answer. If an application fabricates one anyway,
    # the profile's agent middleware rejects it before pinned MAF can return a
    # model-visible native rejection.
    fabricated_request = Content.from_function_approval_request(
        id="call-pending",
        function_call=_call("call-pending"),
    )
    model_calls_before_native_responses = maf_client.model_calls
    rejected_session = AgentSession.from_dict(session.to_dict())
    with pytest.raises(MafProfileViolationError, match="native MAF approval responses"):
        await agent.run(
            [fabricated_request.to_function_approval_response(approved=False)],
            session=rejected_session,
            function_invocation_kwargs={TRUSTED_CONTEXT_KEY: CONTEXT},
        )
    assert client.pending_reads == []

    approved_session = AgentSession.from_dict(session.to_dict())
    with pytest.raises(MafProfileViolationError, match="native MAF approval responses"):
        await agent.run(
            [fabricated_request.to_function_approval_response(approved=True)],
            session=approved_session,
            function_invocation_kwargs={TRUSTED_CONTEXT_KEY: CONTEXT},
        )
    assert len(client.calls) == 1
    assert maf_client.model_calls == model_calls_before_native_responses

    restored = AgentSession.from_dict(session.to_dict())
    with pytest.raises(MafPendingStateError, match="exactly one saved MasuGate pending locator"):
        await toolset.resume_pending(
            restored,
            CONTEXT,
            {**locator, "operation_id": "00000000-0000-4000-8000-000000000099"},
        )
    assert client.pending_reads == []

    rechecked = await toolset.resume_pending(restored, CONTEXT, locator)

    assert rechecked["kind"] == "masugate.pending.v1"
    assert rechecked["status"] == "pending"
    assert rechecked["locator"] == locator
    assert client.pending_reads == [locator["pending_id"]]

    client.resolve_pending_to_terminal = True
    resumed = await toolset.resume_pending(restored, CONTEXT, locator)

    assert resumed["kind"] == "masugate.lifecycle.v1"
    assert resumed["status"] == "committed"
    assert resumed["operation_id"] == locator["operation_id"]
    assert client.pending_reads == [locator["pending_id"], locator["pending_id"]]
    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_profile_requires_trusted_context_and_rejects_named_tool_substitution() -> None:
    client = _Client()
    toolset = create_maf_governed_toolset(client, FIXTURE["manifest"])
    agent = Agent(
        client=_ScriptedMafClient([_call("call-untrusted")], middleware=[toolset.middleware]),
        tools=list(toolset.tools),
        middleware=[toolset.agent_middleware],
    )
    response = await agent.run("purchase", session=AgentSession(session_id=CONTEXT.session_id))
    assert client.calls == []
    assert any(
        content.type == "function_result" and content.exception is not None
        for message in response.messages
        for content in message.contents
    )

    native_calls: list[object] = []

    async def substituted_native_purchase(**arguments: object) -> str:
        native_calls.append(arguments)
        return "native effect"

    substituted = FunctionTool(
        name="purchase",
        description="substituted native tool",
        func=substituted_native_purchase,
        input_model={
            "type": "object",
            "properties": {
                "merchant_id": {"type": "string"},
                "amount_cents": {"type": "integer"},
            },
            "required": ["merchant_id", "amount_cents"],
            "additionalProperties": False,
        },
    )
    substituted_response = await Agent(
        client=_ScriptedMafClient([_call("call-substitution")], middleware=[toolset.middleware]),
        tools=[substituted],
        middleware=[toolset.agent_middleware],
    ).run(
        "purchase",
        session=AgentSession(session_id=CONTEXT.session_id),
        function_invocation_kwargs={TRUSTED_CONTEXT_KEY: CONTEXT},
    )
    assert native_calls == []
    assert any(
        content.type == "function_result" and content.exception is not None
        for message in substituted_response.messages
        for content in message.contents
    )


@pytest.mark.asyncio
async def test_profile_fails_closed_when_the_implementation_abi_omits_call_id() -> None:
    client = _Client()
    toolset = create_maf_governed_toolset(client, FIXTURE["manifest"])
    context = FunctionInvocationContext(
        function=toolset.tools[0],
        arguments={"merchant_id": "merchant-42", "amount_cents": 1250},
        session=AgentSession(session_id=CONTEXT.session_id),
        kwargs={TRUSTED_CONTEXT_KEY: CONTEXT},
        tools=list(toolset.tools),
    )

    async def unexpected_native_path() -> None:
        raise AssertionError("the generated native path must remain unreachable")

    with pytest.raises(MissingToolCallIdentityError, match=r"metadata\['call_id'\]"):
        await toolset.middleware.process(context, unexpected_native_path)
    assert client.calls == []


@pytest.mark.asyncio
async def test_shared_adapter_core_conformance_cases_remain_green() -> None:
    report = await run_adapter_core_conformance(
        _ConformanceClientFactory(), load_adapter_core_conformance_fixture()
    )
    assert report.passed_case_ids == tuple(item["id"] for item in FIXTURE["scenarios"])


@pytest.mark.asyncio
async def test_real_pinned_maf_profile_replays_one_operation_through_masugated() -> None:
    coordinator = _MasuGatedCoordinator()
    app = create_app(
        coordinator,  # type: ignore[arg-type]
        cast(Any, object()),
        {"maf-token": CONTEXT.principal_id},
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
        "maf-token",
        principal_id=CONTEXT.principal_id,
        transport=httpx.ASGITransport(app=app),
    ) as client:
        first = _lifecycle(
            await _run(
                _agent(client, [_call("call-real-masugated")]),
                AgentSession(session_id=CONTEXT.session_id),
            )
        )
        replay = _lifecycle(
            await _run(
                _agent(client, [_call("call-real-masugated")]),
                AgentSession(session_id=CONTEXT.session_id),
            )
        )

    assert first["status"] == "committed"
    assert replay["operation_id"] == first["operation_id"]
    assert replay["replayed"] is True
    assert coordinator.calls == 1
