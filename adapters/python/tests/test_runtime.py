"""Framework-neutral adapter-core conformance scenarios over a fake GAP client."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import pytest
from masugate_client import (
    ActionResult,
    AuditRecord,
    Decision,
    PendingLookup,
    PendingOperation,
    canonical_adapter_envelope,
)

from masugate_adapter_core import (
    AdapterCapabilities,
    AdapterCoreError,
    AdapterModelArgumentsError,
    ChangedInvocationConflictError,
    GovernedRouteParser,
    GovernedToolRuntime,
    PendingLocatorMismatchError,
    TrustedInvocation,
    UnsupportedAdapterCapabilityError,
    assert_adapter_core_conformance_canonical_bytes,
    create_adapter_core_conformance_runtime,
    load_adapter_core_conformance_fixture,
    run_adapter_core_conformance,
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


def _decision(status: str) -> Decision:
    return Decision(
        effect={"committed": "allow", "denied": "deny", "pending": "escalate"}.get(status, "allow"),
        policy_id="adapter-core-test",
        policy_version="v1",
        rule_id="test-rule",
        reason="adapter core test result",
    )


def _result(status: str, operation_id: str, *, replayed: bool = False) -> ActionResult:
    return ActionResult(
        operation_id=operation_id,
        status=cast(Any, status),
        decision=None if status in {"in_progress", "outcome_unknown"} else _decision(status),
        payload={"status": status},
        audit_ref=f"/v1/audit/{operation_id}",
        replayed=replayed,
        pending_id=("11111111-1111-4111-8111-111111111111" if status == "pending" else None),
    )


class FakeLifecycleClient:
    def __init__(self, status: str = "committed") -> None:
        self.status = status
        self.calls: list[dict[str, object]] = []
        self._results: dict[str, ActionResult] = {}
        self._bindings: dict[str, tuple[object, ...]] = {}
        self._pending_operations: dict[str, str] = {}
        self.pending_reads: list[str] = []
        self.staged: list[dict[str, object]] = []

    async def stage_artifact(self, **kwargs: object) -> object:
        self.staged.append(dict(kwargs))
        return SimpleNamespace(reference="art:fixture")

    async def execute(self, action: str, args: Any, stable_id: str, **kwargs: Any) -> ActionResult:
        binding = (action, tuple(sorted(args.items())), kwargs.get("owner"))
        prior_binding = self._bindings.setdefault(stable_id, binding)
        if prior_binding != binding:
            raise ChangedInvocationConflictError(
                "trusted source invocation is already bound to different canonical content"
            )
        self.calls.append({"action": action, "args": dict(args), "stable_id": stable_id, **kwargs})
        prior = self._results.get(stable_id)
        if prior is not None:
            return replace(prior, replayed=True)
        result = _result(self.status, str(uuid4()))
        self._results[stable_id] = result
        if result.pending_id is not None:
            self._pending_operations[result.pending_id] = result.operation_id
        return result

    async def get_pending(self, pending_id: str) -> PendingLookup:
        self.pending_reads.append(pending_id)
        operation_id = self._pending_operations[pending_id]
        pending = PendingOperation(
            pending_id=pending_id,
            operation_id=operation_id,
            principal_id="adapter:buyer",
            action="spend.purchase",
            args={"amount_cents": 1250, "merchant_id": "merchant-42"},
            created_at=datetime.now(UTC),
            decision=_decision("pending"),
            audit_ref=f"/v1/audit/{operation_id}",
        )
        return PendingLookup(kind="pending", pending=pending)

    async def cancel_pending(self, pending_id: str) -> dict[str, object]:
        operation_id = self._pending_operations[pending_id]
        return {
            "kind": "cancellation",
            "locator": {
                "operation_id": operation_id,
                "pending_id": pending_id,
            },
            "accepted": True,
        }

    async def get_audit(self, operation_id: str) -> AuditRecord:
        return cast(AuditRecord, SimpleNamespace(operation_id=operation_id))


class TerminalMismatchClient(FakeLifecycleClient):
    async def get_pending(self, pending_id: str) -> PendingLookup:
        self.pending_reads.append(pending_id)
        return PendingLookup(
            kind="terminal",
            result=_result("committed", "22222222-2222-4222-8222-222222222222"),
        )


class TerminalSameOperationClient(FakeLifecycleClient):
    async def get_pending(self, pending_id: str) -> PendingLookup:
        self.pending_reads.append(pending_id)
        return PendingLookup(
            kind="terminal",
            result=_result("committed", self._pending_operations[pending_id]),
        )


class LocatorMismatchClient(FakeLifecycleClient):
    _other_operation = "22222222-2222-4222-8222-222222222222"

    async def get_pending(self, pending_id: str) -> PendingLookup:
        self.pending_reads.append(pending_id)
        return PendingLookup(
            kind="pending",
            pending=PendingOperation(
                pending_id=pending_id,
                operation_id=self._other_operation,
                principal_id="adapter:buyer",
                action="spend.purchase",
                args={"amount_cents": 1250, "merchant_id": "merchant-42"},
                created_at=datetime.now(UTC),
                decision=_decision("pending"),
                audit_ref=f"/v1/audit/{self._other_operation}",
            ),
        )

    async def cancel_pending(self, pending_id: str) -> dict[str, object]:
        return {
            "kind": "cancellation",
            "locator": {"operation_id": self._other_operation, "pending_id": pending_id},
            "accepted": True,
        }

    async def get_audit(self, operation_id: str) -> AuditRecord:
        return cast(AuditRecord, SimpleNamespace(operation_id=self._other_operation))


class ScenarioClientFactory:
    def __init__(self) -> None:
        self.clients: dict[str, FakeLifecycleClient] = {}

    def __call__(self, scenario: str) -> FakeLifecycleClient:
        existing = self.clients.get(scenario)
        if existing is not None:
            return existing
        if scenario == "pending-terminal":
            client: FakeLifecycleClient = TerminalSameOperationClient("pending")
        elif scenario == "locator-checks":
            client = LocatorMismatchClient("pending")
        elif scenario.startswith("lifecycle-"):
            client = FakeLifecycleClient(scenario.removeprefix("lifecycle-"))
        elif scenario == "pending-resume":
            client = FakeLifecycleClient("pending")
        else:
            client = FakeLifecycleClient()
        self.clients[scenario] = client
        return client


def _runtime(
    client: FakeLifecycleClient,
    *,
    source_id: str = "call-001",
) -> GovernedToolRuntime:
    return create_adapter_core_conformance_runtime(
        client,
        load_adapter_core_conformance_fixture(),
        source_id=source_id,
    )


def test_shared_fixture_canonicalizes_route_and_trusted_invocation() -> None:
    case = load_adapter_core_conformance_fixture()
    runtime = _runtime(FakeLifecycleClient())

    assert files("masugate_adapter_core").joinpath(
        "adapter-core-conformance.json"
    ).read_bytes() == (FIXTURE_PATH.read_bytes())
    assert case.model_arguments == FIXTURE["model_arguments"]
    assert_adapter_core_conformance_canonical_bytes(runtime, case)


def test_v2_route_parser_exposes_bounded_public_schema_without_private_binding() -> None:
    routes = GovernedRouteParser(V2_FIXTURE)
    spec = routes.select("reference_notify")

    assert spec.arguments is None
    assert spec.input_schema is not None
    assert spec.input_schema["type"] == "object"
    assert spec.public_result_schema is not None
    assert spec.artifact_fields == ()
    assert "credential_refs" not in routes.canonical_manifest
    assert "allowed_destinations" not in routes.canonical_manifest


async def test_v2_scalar_content_route_stages_before_governed_action() -> None:
    manifest = deepcopy(V2_FIXTURE)
    route = cast(dict[str, object], cast(list[object], manifest["routes"])[0])
    schema = cast(dict[str, object], route["input_schema"])
    properties = cast(dict[str, object], schema["properties"])
    properties["metadata"] = {"type": "string", "maxLength": 128}
    properties["content"] = {"type": "string", "maxLength": 256}
    cast(list[str], schema["required"]).append("content")
    route["artifact_fields"] = ["content"]
    client = FakeLifecycleClient()
    runtime = GovernedToolRuntime(
        client=client,
        routes=GovernedRouteParser(manifest),
        invocation=TrustedInvocation(
            principal_id="adapter:buyer",
            source_namespace="adapter-test",
            source_id="content-call-1",
            adapter=AdapterCapabilities("masugate.adapter.test", ()),
        ),
    )

    await runtime.invoke(
        "reference_notify",
        {
            "recipient": "buyer@example.test",
            "subject": "hello",
            "metadata": "plain",
            "content": "body",
        },
    )

    assert len(client.staged) == len(client.calls) == 1
    assert client.staged[0]["content"] == b"body"
    assert client.staged[0]["field"] == "content"
    assert client.staged[0]["stable_id"] == client.calls[0]["stable_id"]
    assert client.staged[0]["adapter_invocation"] == client.calls[0]["adapter_invocation"]


async def test_v2_nested_route_remains_closed_before_any_staging() -> None:
    client = FakeLifecycleClient()
    runtime = GovernedToolRuntime(
        client=client,
        routes=GovernedRouteParser(V2_FIXTURE),
        invocation=TrustedInvocation(
            principal_id="adapter:buyer",
            source_namespace="adapter-test",
            source_id="nested-call-1",
            adapter=AdapterCapabilities("masugate.adapter.test", ()),
        ),
    )

    with pytest.raises(AdapterModelArgumentsError, match="nested v2"):
        await runtime.invoke(
            "reference_notify",
            {
                "recipient": "buyer@example.test",
                "subject": "hello",
                "metadata": {"labels": []},
            },
        )
    assert client.staged == []
    assert client.calls == []


def test_empty_conformance_source_id_is_rejected_instead_of_aliased() -> None:
    with pytest.raises(AdapterCoreError, match="trusted principal and source"):
        _runtime(FakeLifecycleClient(), source_id="")


@pytest.mark.parametrize("forged", ["principal_id", "owner", "locator", "pending_id"])
async def test_model_arguments_cannot_forge_trusted_fields(forged: str) -> None:
    client = FakeLifecycleClient()
    runtime = _runtime(client)
    arguments = dict(cast(dict[str, object], FIXTURE["model_arguments"]))
    arguments[forged] = "model-controlled"

    with pytest.raises(AdapterModelArgumentsError, match="unexpected model arguments"):
        await runtime.invoke("purchase", arguments)
    assert client.calls == []


@pytest.mark.parametrize("value", ["1250", 1.5, 9_007_199_254_740_992])
async def test_model_arguments_must_match_the_declared_scalar_type(value: object) -> None:
    client = FakeLifecycleClient()
    arguments = dict(cast(dict[str, object], FIXTURE["model_arguments"]))
    arguments["amount_cents"] = value

    with pytest.raises(AdapterModelArgumentsError, match="amount_cents must be integer"):
        await _runtime(client).invoke("purchase", arguments)
    assert client.calls == []


async def test_model_arguments_must_be_an_object() -> None:
    client = FakeLifecycleClient()

    with pytest.raises(AdapterModelArgumentsError, match="must be an object"):
        await _runtime(client).invoke("purchase", ["not", "arguments"])
    assert client.calls == []


def test_empty_capability_list_remains_schema_valid() -> None:
    capabilities = AdapterCapabilities(adapter_id="masugate.adapter.submit-only", capabilities=())
    assert capabilities.capabilities == ()


async def test_retry_reuses_one_operation_and_changed_content_conflicts() -> None:
    client = FakeLifecycleClient()
    runtime = _runtime(client)
    arguments = cast(dict[str, object], FIXTURE["model_arguments"])

    first = await runtime.invoke("purchase", arguments)
    replay = await runtime.invoke("purchase", arguments)

    assert first.result.operation_id == replay.result.operation_id
    assert replay.result.replayed is True
    assert len(client._results) == 1
    assert client.calls[0]["owner"] == runtime.routes.select("purchase").owner
    assert client.calls[0]["expected_principal"] == "adapter:buyer"
    assert client.calls[0]["adapter_invocation"] == canonical_adapter_envelope(
        runtime.invocation.adapter_invocation(
            runtime.routes.select("purchase"),
            cast(dict[str, object], arguments),
        )
    )

    with pytest.raises(ChangedInvocationConflictError):
        await runtime.invoke("purchase", {**arguments, "amount_cents": 1251})
    assert len(client.calls) == 2

    with pytest.raises(ChangedInvocationConflictError):
        await _runtime(client).invoke("purchase", {**arguments, "amount_cents": 1251})
    assert len(client.calls) == 2


async def test_host_derived_replay_and_trace_identities_survive_shared_core_invocation() -> None:
    client = FakeLifecycleClient()
    baseline = _runtime(client)
    runtime = GovernedToolRuntime(
        client=client,
        routes=baseline.routes,
        invocation=TrustedInvocation(
            principal_id="openclaw:agent-alpha",
            source_namespace="openclaw",
            source_id="openclaw:v2:trusted-call",
            stable_id_override="openclaw:v2:trusted-call",
            trace_id="openclaw:v2:trace:trusted-call",
            adapter=AdapterCapabilities(
                adapter_id="masugate.openclaw",
                capabilities=("locator", "pending-presentation"),
            ),
        ),
    )

    await runtime.invoke("purchase", cast(dict[str, object], FIXTURE["model_arguments"]))

    assert client.calls[0]["stable_id"] == "openclaw:v2:trusted-call"
    assert client.calls[0]["trace_id"] == "openclaw:v2:trace:trusted-call"
    assert client.calls[0]["expected_principal"] == "openclaw:agent-alpha"


async def test_published_conformance_runner_reports_the_shared_scenarios() -> None:
    report = await run_adapter_core_conformance(ScenarioClientFactory())

    assert report.conformance_version == "masugate.adapter-core-conformance.v1"
    assert report.passed_case_ids == tuple(item["id"] for item in FIXTURE["scenarios"])


async def test_distinct_trusted_calls_with_identical_arguments_remain_distinct() -> None:
    client = FakeLifecycleClient()
    arguments = cast(dict[str, object], FIXTURE["model_arguments"])

    first = await _runtime(client, source_id="call-001").invoke("purchase", arguments)
    second = await _runtime(client, source_id="call-002").invoke("purchase", arguments)

    assert first.result.operation_id != second.result.operation_id
    assert {call["stable_id"] for call in client.calls} == {
        'adapter-core:v1:["adapter:buyer","adapter-core-conformance","call-001"]',
        'adapter-core:v1:["adapter:buyer","adapter-core-conformance","call-002"]',
    }


@pytest.mark.parametrize(
    "status", ["committed", "denied", "pending", "in_progress", "outcome_unknown"]
)
async def test_all_lifecycle_states_remain_replacement_only(status: str) -> None:
    presentation = await _runtime(FakeLifecycleClient(status)).invoke(
        "purchase", cast(dict[str, object], FIXTURE["model_arguments"])
    )

    assert presentation.status == status
    assert presentation.native_effect_permitted is False
    assert presentation.retry_as_new_action is False


async def test_pending_resume_reads_the_same_locator_without_a_new_action() -> None:
    client = FakeLifecycleClient("pending")
    runtime = _runtime(client)
    pending = await runtime.invoke("purchase", cast(dict[str, object], FIXTURE["model_arguments"]))
    assert pending.result.pending_id is not None

    with pytest.raises(PendingLocatorMismatchError, match="valid pending locator"):
        await runtime.resume_pending(pending.result.pending_id)
    assert client.pending_reads == []

    resumed = await runtime.resume_pending(pending.locator)

    assert resumed.status == "pending"
    assert resumed.pending_id == pending.result.pending_id
    assert client.pending_reads == [pending.result.pending_id]
    assert len(client.calls) == 1


async def test_pending_resume_rejects_a_different_operation() -> None:
    client = FakeLifecycleClient("pending")
    runtime = _runtime(client)
    pending = await runtime.invoke("purchase", cast(dict[str, object], FIXTURE["model_arguments"]))
    assert pending.result.pending_id is not None
    client._pending_operations[pending.result.pending_id] = "22222222-2222-4222-8222-222222222222"

    with pytest.raises(PendingLocatorMismatchError, match="requested operation locator"):
        await runtime.resume_pending(pending.locator)
    assert client.pending_reads == [pending.result.pending_id]
    assert len(client.calls) == 1


async def test_pending_resume_rejects_a_terminal_result_for_a_different_operation() -> None:
    client = TerminalMismatchClient("pending")
    runtime = _runtime(client)
    pending = await runtime.invoke("purchase", cast(dict[str, object], FIXTURE["model_arguments"]))

    with pytest.raises(
        PendingLocatorMismatchError,
        match="terminal result belongs to another operation",
    ):
        await runtime.resume_pending(pending.locator)
    assert len(client.calls) == 1


async def test_cancel_and_receipt_require_complete_locators_and_bind_the_operation() -> None:
    client = FakeLifecycleClient("pending")
    runtime = _runtime(client)
    pending = await runtime.invoke("purchase", cast(dict[str, object], FIXTURE["model_arguments"]))

    with pytest.raises(PendingLocatorMismatchError, match="valid pending locator"):
        await runtime.cancel_pending(pending.result.pending_id)
    with pytest.raises(PendingLocatorMismatchError, match="valid operation locator"):
        await runtime.get_receipt(pending.result.operation_id)

    cancellation = await runtime.cancel_pending(pending.locator)
    receipt = await runtime.get_receipt(pending.locator)

    assert cancellation["locator"] == pending.locator
    assert receipt.operation_id == pending.result.operation_id


async def test_control_plane_capabilities_are_hard_gates() -> None:
    client = FakeLifecycleClient("pending")
    baseline = _runtime(client)
    runtime = GovernedToolRuntime(
        client,
        baseline.routes,
        TrustedInvocation(
            principal_id="adapter:buyer",
            source_namespace="adapter-core-conformance",
            source_id="call-001",
            adapter=AdapterCapabilities("masugate.adapter.submit-only", ()),
        ),
    )
    pending = await _runtime(client).invoke(
        "purchase", cast(dict[str, object], FIXTURE["model_arguments"])
    )

    with pytest.raises(UnsupportedAdapterCapabilityError, match="locator"):
        await runtime.resume_pending(pending.locator)
    with pytest.raises(UnsupportedAdapterCapabilityError, match="locator"):
        await runtime.cancel_pending(pending.locator)
    with pytest.raises(UnsupportedAdapterCapabilityError, match="locator"):
        await runtime.get_receipt(pending.locator)


def test_core_source_remains_independent_of_framework_host_imports() -> None:
    source = (
        Path(__file__).parents[1] / "src" / "masugate_adapter_core" / "runtime.py"
    ).read_text(encoding="utf-8")
    for host in (
        "openclaw",
        "langchain",
        "langgraph",
        "crewai",
        "agent_framework",
        "agentframework",
        "microsoft-agent-framework",
        "@microsoft/agents",
        "microsoft",
    ):
        assert f"import {host}" not in source
        assert f"from {host}" not in source
