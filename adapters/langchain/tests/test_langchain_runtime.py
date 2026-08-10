"""Pinned real LangChain/LangGraph runtime tests for the replacement adapter."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import httpx
import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode
from langgraph.types import Command
from masugate.errors import ResourceError
from masugate.model import ActionRequest, DecisionEffect, OperationResult, PolicyDecision
from masugate.protected_execution import (
    ProtectedExecutionAuthority,
    ProtectedExecutionRunner,
    SqliteProtectedExecutionStore,
)
from masugate.masugated import ActionOwnerBinding, create_app
from masugate.provider_assembly import EffectExecutionPosition
from masugate.providers import (
    ReferencePurchaseConnector,
    SpendOperationStatus,
    SpendPolicy,
    SpendPurchaseRequest,
    SpendPurchaseService,
    SqliteReferencePurchaseApi,
    SqliteSpendOutboxStore,
)
from masugate_adapter_core import (
    ChangedInvocationConflictError,
    PendingLocatorMismatchError,
    UnsupportedAdapterCapabilityError,
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

from masugate_langchain import (
    LANGCHAIN_VERSION,
    LANGGRAPH_VERSION,
    LangGraphTrustedContext,
    create_langchain_governed_tools,
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
CONTEXT = LangGraphTrustedContext(
    principal_id="adapter:buyer",
    thread_id="deployment-thread-42",
    thread_generation="generation-7",
)


def _decision(status: str) -> Decision:
    return Decision(
        effect={"committed": "allow", "denied": "deny", "pending": "escalate"}.get(status, "allow"),
        policy_id="langgraph-test",
        policy_version="v1",
        rule_id="test-rule",
        reason="LangGraph adapter test result",
    )


class _Client:
    def __init__(self, status: str = "committed") -> None:
        self.status = status
        self.calls: list[dict[str, object]] = []
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
    """Return control-plane locators that name a different authoritative operation."""

    _other_operation_id = "00000000-0000-4000-8000-000000000099"

    async def get_pending(self, pending_id: str) -> PendingLookup:
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


class _ConformanceClientFactory:
    """Use the same host-facing client doubles as the LangGraph ToolNode tests."""

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


class _MasuGatedCoordinator:
    """Actual ``masugated`` HTTP boundary behind the real LangGraph ToolNode."""

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
                policy_id="langgraph-real-masugated",
                policy_version="v1",
                rule_id="allow",
                reason="real masugated adapter test",
            ),
            committed=True,
            payload={"effect_count": self.calls},
        )
        self._results[request.idempotency_key] = result
        return result


def _node(client: _Client, *, capabilities: tuple[str, ...] | None = None) -> ToolNode:
    tools = create_langchain_governed_tools(
        client,
        FIXTURE["manifest"],
        **({} if capabilities is None else {"capabilities": capabilities}),
    )
    return ToolNode(list(tools.values()))


def _graph(node: ToolNode, *, checkpointer: InMemorySaver | None = None) -> Any:
    builder = StateGraph(MessagesState, context_schema=LangGraphTrustedContext)
    builder.add_node("tools", node)
    builder.add_edge(START, "tools")
    builder.add_edge("tools", END)
    return builder.compile(checkpointer=checkpointer)


def _message(tool_call_id: str, *, amount_cents: object = 1250) -> AIMessage:
    return AIMessage(
        content="",
        tool_calls=[
            {
                "name": "purchase",
                "args": {"merchant_id": "merchant-42", "amount_cents": amount_cents},
                "id": tool_call_id,
            }
        ],
    )


async def _invoke(
    node: ToolNode,
    tool_call_id: str,
    *,
    amount_cents: object = 1250,
    context: object = CONTEXT,
) -> ToolMessage:
    result = await _graph(node).ainvoke(
        {"messages": [_message(tool_call_id, amount_cents=amount_cents)]},
        config={"configurable": {"thread_id": "model-visible-config-is-not-an-identity"}},
        context=context,
    )
    message = result["messages"][-1]
    assert isinstance(message, ToolMessage)
    return message


def _result(message: ToolMessage) -> dict[str, object]:
    assert isinstance(message.content, str)
    return cast(dict[str, object], json.loads(message.content))


async def test_pinned_runtime_generates_typed_replacement_without_native_fallthrough() -> None:
    assert LANGCHAIN_VERSION == "1.3.14"
    assert LANGGRAPH_VERSION == "1.2.9"
    assert version("langchain") == LANGCHAIN_VERSION
    assert version("langgraph") == LANGGRAPH_VERSION
    native_calls: list[object] = []

    @tool
    async def native_purchase(merchant_id: str, amount_cents: int) -> str:
        """An intentionally unregistered native implementation."""

        native_calls.append((merchant_id, amount_cents))
        return "native effect"

    client = _Client()
    tools = create_langchain_governed_tools(client, FIXTURE["manifest"])
    assert tools["purchase"].args_schema is not None
    assert "runtime" not in tools["purchase"].args

    message = await _invoke(_node(client), "call-commit")
    outcome = _result(message)

    assert outcome["status"] == "committed"
    assert outcome["native_effect_permitted"] is False
    assert outcome["retry_as_new_action"] is False
    assert native_calls == []
    assert len(client.calls) == 1
    assert client.calls[0]["expected_principal"] == CONTEXT.principal_id


def test_v2_generated_tool_schema_preserves_nested_bounded_constraints() -> None:
    tool = create_langchain_governed_tools(_Client(), V2_FIXTURE)["reference_notify"]
    assert tool.args_schema is not None
    call_schema = cast(Any, tool.tool_call_schema)
    rendered = cast(dict[str, object], call_schema.model_json_schema())
    rendered_properties = cast(dict[str, dict[str, object]], rendered["properties"])
    properties = cast(dict[str, dict[str, object]], tool.args)

    assert rendered["additionalProperties"] is False
    assert "runtime" not in rendered_properties
    assert properties["recipient"]["minLength"] == 3
    assert properties["recipient"]["maxLength"] == 320
    metadata_reference = cast(str, rendered_properties["metadata"]["$ref"])
    metadata = cast(
        dict[str, object],
        cast(dict[str, object], rendered["$defs"])[metadata_reference.removeprefix("#/$defs/")],
    )
    labels = cast(dict[str, object], cast(dict[str, object], metadata["properties"])["labels"])
    priority = cast(dict[str, object], cast(dict[str, object], metadata["properties"])["priority"])
    assert metadata["additionalProperties"] is False
    assert labels["maxItems"] == 8
    assert cast(dict[str, object], labels["items"])["maxLength"] == 48
    assert priority["minimum"] == 0
    assert priority["maximum"] == 9
    assert "default" not in priority
    parsed = call_schema.model_validate(
        {"recipient": "recipient", "subject": "subject", "metadata": {"labels": []}}
    )
    assert "priority" not in parsed.model_dump()["metadata"]


async def test_real_pinned_toolnode_replays_one_operation_through_public_masugated() -> None:
    coordinator = _MasuGatedCoordinator()
    app = create_app(
        coordinator,  # type: ignore[arg-type]
        cast(Any, object()),
        {"langgraph-token": CONTEXT.principal_id},
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
        "langgraph-token",
        principal_id=CONTEXT.principal_id,
        transport=httpx.ASGITransport(app=app),
    ) as client:
        first = _result(await _invoke(_node(client), "call-real-masugated"))
        replay = _result(await _invoke(_node(client), "call-real-masugated"))

    assert first["status"] == "committed"
    assert replay["operation_id"] == first["operation_id"]
    assert replay["replayed"] is True
    assert coordinator.calls == 1


async def test_published_shared_conformance_runner_reports_every_case() -> None:
    fixture = load_adapter_core_conformance_fixture()
    report = await run_adapter_core_conformance(_ConformanceClientFactory(), fixture)

    assert report.conformance_version == "masugate.adapter-core-conformance.v1"
    assert report.passed_case_ids == tuple(item["id"] for item in FIXTURE["scenarios"])


async def test_duplicate_delivery_and_restart_replay_one_masugate_operation() -> None:
    client = _Client()
    first = _result(await _invoke(_node(client), "call-replay"))
    restarted = _result(await _invoke(_node(client), "call-replay"))

    assert first["operation_id"] == restarted["operation_id"]
    assert restarted["replayed"] is True
    assert len(client._results) == 1
    assert len(client.calls) == 2
    assert client.calls[0]["trace_id"] == client.calls[1]["trace_id"]


async def test_parallel_identical_arguments_with_distinct_tool_ids_are_distinct_operations() -> (
    None
):
    client = _Client()
    node = _node(client)
    result = await _graph(node).ainvoke(
        {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "purchase",
                            "args": {"merchant_id": "merchant-42", "amount_cents": 1250},
                            "id": "call-parallel-a",
                        },
                        {
                            "name": "purchase",
                            "args": {"merchant_id": "merchant-42", "amount_cents": 1250},
                            "id": "call-parallel-b",
                        },
                    ],
                )
            ]
        },
        context=CONTEXT,
    )
    outputs = [
        _result(message) for message in result["messages"] if isinstance(message, ToolMessage)
    ]

    assert {output["status"] for output in outputs} == {"committed"}
    assert len({output["operation_id"] for output in outputs}) == 2
    assert len(client._results) == 2
    trace_ids = {cast(str, call["trace_id"]) for call in client.calls}
    assert len(trace_ids) == 2


async def test_distinct_calls_in_one_generation_have_unique_reference_provider_tool_ids(
    tmp_path: Path,
) -> None:
    """Two host calls must not collide on the provider's unique tool-call key."""

    policy = SpendPolicy(budget_limit_cents=10_000, approval_threshold_cents=10_000)
    service = SpendPurchaseService(
        SqliteSpendOutboxStore(
            tmp_path / "spend.sqlite",
            policy,
            allow_default_authorization_for_testing=True,
        ),
        ProtectedExecutionRunner(
            SqliteProtectedExecutionStore(tmp_path / "protected.sqlite"),
            ReferencePurchaseConnector(
                SqliteReferencePurchaseApi(tmp_path / "purchase-api.sqlite")
            ),
            ProtectedExecutionAuthority(
                action="spend.purchase",
                provider_identity=policy.provider_identity,
                coordination_domain_id="masugate.spend.reference.domain.v1",
                connector_id="reference-purchase-v1",
            ),
            worker_id="langgraph-reference-provider-test",
        ),
        policy,
        allow_unbound_policy_for_testing=True,
    )
    await service.initialize()
    try:
        contexts = (
            CONTEXT,
            LangGraphTrustedContext(
                principal_id="adapter:buyer-alt",
                thread_id=CONTEXT.thread_id,
                thread_generation=CONTEXT.thread_generation,
            ),
            LangGraphTrustedContext(
                principal_id=CONTEXT.principal_id,
                thread_id=CONTEXT.thread_id,
                thread_generation=CONTEXT.thread_generation,
                source_namespace="langgraph-alt",
            ),
        )
        invocations = tuple(
            context.invocation_for(
                "call-reference-shared",
                adapter_id="masugate.langchain",
                capabilities=("locator",),
            )
            for context in contexts
        )
        assert all(invocation.trace_id is not None for invocation in invocations)
        baseline, cross_principal, cross_namespace = invocations
        assert baseline.stable_id != cross_principal.stable_id
        assert baseline.trace_id != cross_principal.trace_id
        assert baseline.stable_id != cross_namespace.stable_id
        assert baseline.trace_id != cross_namespace.trace_id
        assert len({invocation.stable_id for invocation in invocations}) == len(invocations)
        assert len({invocation.trace_id for invocation in invocations}) == len(invocations)

        operations = []
        for index, (context, invocation) in enumerate(
            zip(contexts, invocations, strict=True), start=1
        ):
            assert invocation.trace_id is not None
            operations.append(
                await service.submit(
                    SpendPurchaseRequest(
                        principal_id=context.principal_id,
                        team_id="research",
                        amount_cents=100,
                        merchant_id="merchant-42",
                        request_ref=f"langgraph-reference-{index}",
                        idempotency_key=invocation.stable_id,
                        tool_call_id=invocation.trace_id,
                    )
                )
            )
    finally:
        await service.close()

    assert [operation.status for operation in operations] == [SpendOperationStatus.COMMITTED] * 3
    assert all(operation.entitlement is not None for operation in operations)
    assert len({operation.entitlement.request.tool_call_id for operation in operations}) == 3


async def test_changed_arguments_under_one_tool_call_conflict_without_native_effect() -> None:
    client = _Client()
    await _invoke(_node(client), "call-conflict")
    with pytest.raises(ChangedInvocationConflictError):
        await _invoke(_node(client), "call-conflict", amount_cents=1251)

    assert len(client._results) == 1


async def test_denied_result_is_authoritative_tool_output() -> None:
    outcome = _result(await _invoke(_node(_Client("denied")), "call-denied"))

    assert outcome["status"] == "denied"
    assert outcome["native_effect_permitted"] is False


@pytest.mark.parametrize("status", ("in_progress", "outcome_unknown"))
async def test_operational_lifecycle_states_remain_authoritative_tool_output(status: str) -> None:
    outcome = _result(await _invoke(_node(_Client(status)), f"call-{status}"))

    assert outcome["status"] == status
    assert outcome["native_effect_permitted"] is False
    assert outcome["retry_as_new_action"] is False


async def test_forged_model_identity_and_missing_trusted_context_never_reach_masugate() -> None:
    client = _Client()
    node = _node(client)
    forged = await _graph(node).ainvoke(
        {
            "messages": [
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "purchase",
                            "args": {
                                "merchant_id": "merchant-42",
                                "amount_cents": 1250,
                                "principal_id": "model-forged",
                            },
                            "id": "call-forged",
                        }
                    ],
                )
            ]
        },
        context=CONTEXT,
    )
    with pytest.raises(TypeError, match="thread_id"):
        await _invoke(node, "call-no-context", context={"principal_id": "forged"})

    forged_message = cast(ToolMessage, forged["messages"][-1])
    assert forged_message.status == "error"
    assert client.calls == []


async def test_pending_resume_rechecks_the_same_locator_through_langgraph() -> None:
    client = _Client("pending")
    checkpointer = InMemorySaver()
    graph = _graph(_node(client), checkpointer=checkpointer)
    config = {"configurable": {"thread_id": "checkpoint-thread-pending"}}

    paused = await graph.ainvoke(
        {"messages": [_message("call-pending-again")]}, config, context=CONTEXT
    )
    assert paused.get("__interrupt__") is not None
    original = next(iter(client._results.values()))

    resumed = await graph.ainvoke(
        Command(resume={"untrusted": "resume-value"}), config, context=CONTEXT
    )
    outcome = _result(cast(ToolMessage, resumed["messages"][-1]))

    assert outcome["status"] == "pending"
    assert outcome["operation_id"] == original.operation_id
    assert outcome["pending_id"] == original.pending_id
    assert outcome["native_effect_permitted"] is False


@pytest.mark.parametrize(
    ("client", "capabilities", "error_type", "expected_error"),
    (
        (
            _LocatorMismatchClient("pending"),
            None,
            PendingLocatorMismatchError,
            "pending read did not return the requested",
        ),
        (
            _Client("pending"),
            (),
            UnsupportedAdapterCapabilityError,
            "adapter does not declare required capability: locator",
        ),
    ),
)
async def test_pending_resume_rejects_invalid_control_plane_state(
    client: _Client,
    capabilities: tuple[str, ...] | None,
    error_type: type[Exception],
    expected_error: str,
) -> None:
    checkpointer = InMemorySaver()
    graph = _graph(_node(client, capabilities=capabilities), checkpointer=checkpointer)
    config = {"configurable": {"thread_id": f"checkpoint-thread-control-{id(client)}"}}

    paused = await graph.ainvoke({"messages": [_message("call-control")]}, config, context=CONTEXT)
    assert paused.get("__interrupt__") is not None

    with pytest.raises(error_type, match=expected_error):
        await graph.ainvoke(Command(resume={"untrusted": "resume-value"}), config, context=CONTEXT)
    assert client.calls


async def test_pending_interrupt_restarts_and_returns_only_masugate_terminal_result() -> None:
    client = _Client("pending")
    checkpointer = InMemorySaver()
    graph = _graph(_node(client), checkpointer=checkpointer)
    config = {"configurable": {"thread_id": "checkpoint-thread-1"}}

    paused = await graph.ainvoke({"messages": [_message("call-pending")]}, config, context=CONTEXT)
    interrupts = paused.get("__interrupt__")
    assert interrupts is not None
    assert len(client._results) == 1
    client.resolve_pending_to_terminal = True

    # Rebuild the graph around a fresh ToolNode to characterize host restart.
    restarted_graph = _graph(_node(client), checkpointer=checkpointer)
    resumed = await restarted_graph.ainvoke(
        Command(resume={"model_or_ui_input": "this is not MasuGate approval"}),
        config,
        context=CONTEXT,
    )
    outcome = _result(cast(ToolMessage, resumed["messages"][-1]))

    assert outcome["status"] == "committed"
    assert outcome["operation_id"] == next(iter(client._results.values())).operation_id
    assert outcome["native_effect_permitted"] is False
    assert len(client._results) == 1
