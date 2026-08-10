"""Round trips through the real ``masugated`` ASGI app without PostgreSQL."""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from copy import deepcopy
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import httpx
import pytest
from masugate.errors import ResourceError
from masugate.model import (
    ActionRequest,
    DecisionEffect,
    JsonValue,
    OperationResult,
    OperationStatus,
    PendingOperation,
    PendingResolutionPlan,
    PolicyDecision,
    PolicyProvenance,
    MasuGateMode,
    ViewRead,
)
from masugate.masugated import ActionOwnerBinding, create_app
from masugate.provider_assembly import EffectExecutionPosition

from masugate_client import (
    ExpectedActionOwner,
    MasuGateAPIError,
    MasuGateClient,
    MasuGateProtocolError,
    canonical_adapter_envelope,
    create_adapter_invocation,
    derive_idempotency_key,
)
from masugate_client._parsing import parse_action_result, parse_audit_record

CERTIFICATE_DIGEST = "0123456789abcdef" * 4
ENTITLEMENT_DIGEST = "fedcba9876543210" * 4


def test_protected_execution_audit_example_is_typed_and_replayable() -> None:
    example = Path(__file__).parents[3] / "protocol" / "examples" / "audit.json"
    record = parse_audit_record(json.loads(example.read_text(encoding="utf-8")))

    protected = record.protected_execution
    assert protected is not None
    assert protected.status == "succeeded"
    assert protected.entitlement_state == "consumed"
    assert protected.dispatch_started
    assert protected.receipt is not None
    assert protected.receipt.outcome == "succeeded"
    assert protected.events[-2].event_type == "connector-receipt-recorded"
    assert protected.events[-1].event_type == "terminal-position-recorded"
    assert record.policy.catalog is not None
    assert (
        record.policy.catalog.policy_digest
        == "f72bfbef3d3570fe5ad6be5c8c17de3e0c9c159c07dba45a7e3f47bb5f37c664"
    )
    assert record.entitlement is not None
    assert record.entitlement.authorization_digest == "c0ffee00" * 8


def test_audit_parser_preserves_strict_provenance() -> None:
    payload = _canonical_audit_payload()
    request = cast(dict[str, Any], payload["request"])
    request["adapter_invocation_digest"] = "d" * 64

    record = parse_audit_record(payload)

    assert record.request.adapter_invocation_digest == "d" * 64


def test_audit_parser_preserves_certified_protected_artifact_metadata() -> None:
    payload = _canonical_audit_payload()
    request = cast(dict[str, Any], payload["request"])
    request["protected_artifacts"] = {
        "content": {
            "reference": "art:certified-payload",
            "content_digest": "a" * 64,
            "content_bytes": 5,
            "media_type": "text/plain",
            "classification": "reference-text",
            "expires_at": "2026-01-01T00:00:00+00:00",
            "inspector_version": "reference-inspector.v1",
        }
    }

    record = parse_audit_record(payload)

    artifact = record.request.protected_artifacts["content"]
    assert artifact.reference == "art:certified-payload"
    assert artifact.content_digest == "a" * 64
    assert artifact.content_bytes == 5
    assert artifact.inspector_version == "reference-inspector.v1"


def test_audit_parser_rejects_oversized_protected_artifact_classification() -> None:
    payload = _canonical_audit_payload()
    request = cast(dict[str, Any], payload["request"])
    request["protected_artifacts"] = {
        "content": {
            "reference": "art:certified-payload",
            "content_digest": "a" * 64,
            "content_bytes": 5,
            "media_type": "text/plain",
            "classification": "x" * 256,
            "expires_at": "2026-01-01T00:00:00+00:00",
            "inspector_version": "reference-inspector.v1",
        }
    }

    with pytest.raises(MasuGateProtocolError, match="no longer than 255"):
        parse_audit_record(payload)


def test_audit_parser_rejects_removed_legacy_authorization_evidence() -> None:
    payload = _canonical_audit_payload()
    entitlement = cast(dict[str, Any], payload["entitlement"])
    entitlement["authorization_request_digest"] = "e" * 64

    with pytest.raises(MasuGateProtocolError, match="authorization_request_digest"):
        parse_audit_record(payload)


def test_protected_execution_audit_rejects_binding_payload_or_connector_key_drift() -> None:
    payload = _canonical_audit_payload()
    protected = cast(dict[str, Any], payload["protected_execution"])
    binding = cast(dict[str, Any], protected["binding"])
    arguments = cast(dict[str, Any], binding["arguments"])
    arguments["quantity"] = 999

    with pytest.raises(
        MasuGateProtocolError, match="binding_canonical_json does not match binding payload"
    ):
        parse_audit_record(payload)

    payload = _canonical_audit_payload()
    protected = cast(dict[str, Any], payload["protected_execution"])
    receipt = cast(dict[str, Any], protected["receipt"])
    receipt["idempotency_key"] = "masugate:wrong-binding"

    with pytest.raises(
        MasuGateProtocolError, match="idempotency key does not match binding digest"
    ):
        parse_audit_record(payload)


def test_protected_execution_audit_preserves_cross_language_canonical_binding_bytes() -> None:
    payload = _canonical_audit_payload()
    protected = cast(dict[str, Any], payload["protected_execution"])
    binding = cast(dict[str, Any], protected["binding"])
    binding["arguments"]["amount_cents"] = 1.0
    cast(dict[str, Any], payload["request"])["args"]["amount_cents"] = 1.0
    cast(dict[str, Any], payload["effect"])["args"]["amount_cents"] = 1.0
    canonical = json.dumps(
        binding, allow_nan=False, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    )
    digest = sha256(canonical.encode("utf-8")).hexdigest()
    protected["binding_canonical_json"] = canonical
    protected["binding_digest"] = digest
    protected["execution_id"] = f"px:{digest}"
    cast(dict[str, Any], protected["receipt"])["idempotency_key"] = f"masugate:{digest}"
    cast(list[dict[str, Any]], protected["events"])[0]["evidence"]["binding_digest"] = digest

    record = parse_audit_record(payload)
    assert record.protected_execution is not None
    assert record.protected_execution.binding_canonical_json == canonical


@pytest.mark.parametrize(
    ("name", "expected", "mutate"),
    [
        (
            "receipt connector",
            "receipt connector does not match binding",
            lambda payload: cast(dict[str, Any], payload["protected_execution"])[
                "receipt"
            ].__setitem__("connector_id", "other-connector"),
        ),
        (
            "receipt external operation",
            "terminal outcome requires an external operation id",
            lambda payload: (
                cast(dict[str, Any], payload["protected_execution"])["receipt"].__setitem__(
                    "external_operation_id", None
                ),
                cast(dict[str, Any], payload["protected_execution"]).__setitem__(
                    "external_operation_id", None
                ),
            ),
        ),
        (
            "request principal",
            "request principal does not match protected execution binding",
            lambda payload: cast(dict[str, Any], payload["request"])["principal"].__setitem__(
                "id", "mallory"
            ),
        ),
        (
            "request action",
            "request action does not match protected execution binding",
            lambda payload: cast(dict[str, Any], payload["request"]).__setitem__(
                "action", "other.transfer"
            ),
        ),
        (
            "request arguments",
            "request args do not match protected execution binding",
            lambda payload: cast(dict[str, Any], payload["request"])["args"].__setitem__(
                "amount_cents", 99
            ),
        ),
        (
            "request idempotency",
            "request idempotency key does not match protected execution binding",
            lambda payload: cast(dict[str, Any], payload["request"]).__setitem__(
                "idempotency_key", "different-request"
            ),
        ),
        (
            "effect",
            "effect does not match protected execution binding",
            lambda payload: cast(dict[str, Any], payload["effect"]).__setitem__(
                "action", "other.transfer"
            ),
        ),
        (
            "policy provenance",
            "policy provenance does not match protected execution binding",
            lambda payload: cast(
                list[dict[str, Any]],
                cast(dict[str, Any], payload["policy"])["evaluated_policy_provenance"],
            )[0].__setitem__("policy_declared_version", "2.0.0"),
        ),
    ],
)
def test_protected_execution_audit_rejects_unbound_receipt_or_displayed_evidence(
    name: str, expected: str, mutate: Any
) -> None:
    del name
    payload = _canonical_audit_payload()
    mutate(payload)

    with pytest.raises(MasuGateProtocolError, match=expected):
        parse_audit_record(payload)


def _canonical_audit_payload() -> dict[str, Any]:
    example = Path(__file__).parents[3] / "protocol" / "examples" / "audit.json"
    return cast(dict[str, Any], json.loads(example.read_text(encoding="utf-8")))


def _make_protected_execution_fail(protected: dict[str, Any]) -> None:
    protected["status"] = "failed"
    protected["entitlement_state"] = "released"
    protected["receipt"]["outcome"] = "failed"
    protected["result"]["outcome"] = "failed"
    protected["events"][-1]["to_status"] = "failed"


@pytest.mark.parametrize(
    ("status", "expected_message"),
    [
        ("committed", "requires protected execution status 'succeeded'"),
        ("denied", "requires protected execution status 'failed'"),
        ("pending", "protected_execution is forbidden"),
        ("in_progress", "requires intent or executing protected execution"),
        ("outcome_unknown", "requires protected execution status 'outcome_unknown'"),
    ],
)
def test_audit_rejects_contradictory_protected_execution_status(
    status: str, expected_message: str
) -> None:
    payload = deepcopy(_canonical_audit_payload())
    decision = cast(dict[str, Any], payload["decision"])
    if status == "committed":
        _make_protected_execution_fail(cast(dict[str, Any], payload["protected_execution"]))
    elif status == "denied":
        payload["status"] = status
        decision["effect"] = "deny"
        payload["effect"] = None
    elif status == "pending":
        payload["status"] = status
        decision["effect"] = "escalate"
        payload["effect"] = None
    else:
        payload["status"] = status
        payload["decision"] = None
        payload["effect"] = None

    with pytest.raises(MasuGateProtocolError, match=expected_message):
        parse_audit_record(payload)


@pytest.mark.parametrize(
    ("path", "expected_message"),
    [
        ("authorization_evaluations", "authorization_evaluations is required"),
        ("terminal_serialization", "terminal_serialization is required"),
        (
            "policy.evaluated_policy_provenance",
            "evaluated_policy_provenance is required",
        ),
    ],
)
def test_audit_rejects_missing_normative_evidence(path: str, expected_message: str) -> None:
    payload = deepcopy(_canonical_audit_payload())
    target = payload
    *parents, leaf = path.split(".")
    for parent in parents:
        target = cast(dict[str, Any], target[parent])
    del target[leaf]

    with pytest.raises(MasuGateProtocolError, match=expected_message):
        parse_audit_record(payload)


@pytest.mark.parametrize(
    ("status", "terminal_kind", "expected_message"),
    [
        ("committed", "denial-record", "committed requires effect-commit"),
        ("denied", "effect-commit", "denied requires denial-record"),
        ("pending", "effect-commit", "pending requires null terminal"),
    ],
)
def test_audit_rejects_terminal_serialization_for_the_wrong_outcome(
    status: str, terminal_kind: str, expected_message: str
) -> None:
    payload = deepcopy(_canonical_audit_payload())
    decision = cast(dict[str, Any], payload["decision"])
    if status == "denied":
        payload["status"] = status
        decision["effect"] = "deny"
        payload["effect"] = None
        _make_protected_execution_fail(cast(dict[str, Any], payload["protected_execution"]))
    elif status == "pending":
        payload["status"] = status
        decision["effect"] = "escalate"
        payload["effect"] = None
        del payload["protected_execution"]
    terminal = cast(dict[str, Any], payload["terminal_serialization"])
    terminal["kind"] = terminal_kind

    with pytest.raises(MasuGateProtocolError, match=expected_message):
        parse_audit_record(payload)


@pytest.mark.parametrize(
    ("path", "replacement", "expected_message"),
    [
        (
            "policy.catalog.policy_digest",
            "0" * 64,
            "policy.catalog does not match evaluated policy provenance",
        ),
        (
            "entitlement.entitlement_id",
            "entitlement:other",
            "entitlement_id does not match protected execution binding",
        ),
        (
            "entitlement.authorization_digest",
            "0" * 64,
            "authorization_digest does not match protected execution binding",
        ),
    ],
)
def test_audit_rejects_duplicate_authorization_evidence_drift(
    path: str, replacement: str, expected_message: str
) -> None:
    payload = deepcopy(_canonical_audit_payload())
    target = payload
    *parents, leaf = path.split(".")
    for parent in parents:
        target = cast(dict[str, Any], target[parent])
    target[leaf] = replacement

    with pytest.raises(MasuGateProtocolError, match=expected_message):
        parse_audit_record(payload)


def test_protected_execution_audit_rejects_external_identity_drift() -> None:
    example = Path(__file__).parents[3] / "protocol" / "examples" / "audit.json"
    payload = json.loads(example.read_text(encoding="utf-8"))
    protected = payload["protected_execution"]
    protected["receipt"]["external_operation_id"] = "remote:replacement"

    with pytest.raises(MasuGateProtocolError, match="external-operation identity"):
        parse_audit_record(payload)


def test_protected_execution_audit_rejects_evidence_without_dispatch() -> None:
    example = Path(__file__).parents[3] / "protocol" / "examples" / "audit.json"
    payload = json.loads(example.read_text(encoding="utf-8"))
    payload["protected_execution"]["dispatch_started"] = False

    with pytest.raises(MasuGateProtocolError, match="undispatched execution"):
        parse_audit_record(payload)


class FakeGovernanceResource:
    """The durable read side needed by the actual ``masugated`` routes."""

    def __init__(self) -> None:
        self.results_by_key: dict[str, OperationResult] = {}
        self.pending: dict[str, PendingOperation] = {}
        self.resolved: dict[str, OperationResult] = {}
        self.records: dict[str, dict[str, JsonValue]] = {}

    @asynccontextmanager
    async def open_session(self, *, write: bool) -> AsyncIterator[Any]:
        del write
        yield object()

    async def load_pending_operation(
        self, session: Any, pending_id: str
    ) -> PendingOperation | None:
        del session
        return self.pending.get(pending_id)

    async def load_resolved_pending_result(
        self, session: Any, pending_id: str
    ) -> OperationResult | None:
        del session
        return self.resolved.get(pending_id)

    async def list_pending_operations(
        self,
        session: Any,
        *,
        principal_id: str | None = None,
    ) -> tuple[PendingOperation, ...]:
        del session
        return tuple(
            pending
            for pending in self.pending.values()
            if principal_id is None or pending.request.principal.id == principal_id
        )

    async def load_pending_owner(self, session: Any, pending_id: str) -> str | None:
        del session
        pending = self.pending.get(pending_id)
        if pending is not None:
            return pending.request.principal.id
        resolved = self.resolved.get(pending_id)
        if resolved is None:
            return None
        record = self.records.get(resolved.operation_id)
        return None if record is None else str(record["principal_id"])

    async def load_governance_record(
        self, session: Any, operation_id: str
    ) -> dict[str, JsonValue] | None:
        del session
        return self.records.get(operation_id)

    def record(self, request: ActionRequest, result: OperationResult) -> None:
        decision = result.decision
        reads: list[JsonValue] = [
            {
                "function": read.function,
                "arguments": list(read.arguments),
                "value": read.value,
                "scope": read.scope,
                "version": read.version,
                "latency_ms": read.latency_ms,
            }
            for read in decision.reads
        ]
        decision_record: dict[str, JsonValue] = {
            "effect": str(decision.effect),
            "policy_id": decision.policy_id,
            "policy_version": decision.policy_version,
            "rule_id": decision.rule_id,
            "reason": decision.reason,
            "reads": reads,
            "evaluated_policies": [list(item) for item in decision.evaluated_policies],
            "policy_provenance": [
                {
                    "policy_id": item.policy_id,
                    "policy_declared_version": item.policy_declared_version,
                    "policy_runtime_version": item.policy_runtime_version,
                    "policy_digest": item.policy_digest,
                    "bundle_id": item.bundle_id,
                    "bundle_version": item.bundle_version,
                    "bundle_digest": item.bundle_digest,
                    "layer": item.layer,
                    "mode": item.mode,
                }
                for item in decision.policy_provenance
            ],
        }
        self.results_by_key[request.idempotency_key] = result
        self.records[result.operation_id] = {
            "operation_id": result.operation_id,
            "idempotency_key": request.idempotency_key,
            "principal_id": request.principal.id,
            "principal_attributes": request.principal.attributes,
            "action": request.action,
            "arguments": request.arguments,
            "timestamp": request.timestamp.isoformat(),
            "request_time": request.timestamp.isoformat(),
            "trace_id": request.trace_id,
            "decision": decision_record,
            "authorization_evaluations": [
                {
                    "phase": "admission",
                    "evaluated_at": request.timestamp.isoformat(),
                    "decision": decision_record,
                    "certified_inputs": [],
                }
            ],
            "terminal_serialization": (
                None
                if result.status is OperationStatus.PENDING
                else {
                    "kind": "effect-commit" if result.committed else "denial-record",
                    "authorization_basis": "mechanism-denial",
                    "provider_atomic": True,
                    "recorded_at": request.timestamp.isoformat(),
                }
            ),
            "committed": result.committed,
            "status": str(result.status),
            "payload": result.payload,
            "resolution_plan": str(result.resolution_plan),
            "reservation_safety_certificate_digest": (result.reservation_safety_certificate_digest),
            "reservation_entitlement_digest": result.reservation_entitlement_digest,
        }


class FakeCoordinator:
    """Effect-counting coordinator double behind the production HTTP boundary."""

    def __init__(self, resource: FakeGovernanceResource) -> None:
        self.resource = resource
        self.effect_count = 0
        self.concurrent_denials: set[str] = set()

    @staticmethod
    def _decision(effect: DecisionEffect) -> PolicyDecision:
        return PolicyDecision(
            effect=effect,
            policy_id="sdk-round-trip",
            policy_version="policy-v1",
            rule_id={
                DecisionEffect.ALLOW: "allow_action",
                DecisionEffect.DENY: "operator_rejected",
                DecisionEffect.ESCALATE: "needs_approval",
            }[effect],
            reason=f"test decision: {effect}",
            reads=(
                ViewRead(
                    function="limits.remaining",
                    arguments=("default",),
                    value=100_000,
                    scope="limit:default",
                    version=7,
                    latency_ms=0.25,
                ),
            ),
            evaluated_policies=(("sdk-round-trip", "policy-v1"),),
            policy_provenance=(
                PolicyProvenance(
                    policy_id="sdk-round-trip",
                    policy_declared_version="1.0.0",
                    policy_runtime_version="policy-v1",
                    policy_digest="a" * 64,
                    bundle_id="sdk.reference",
                    bundle_version="1.0.0",
                    bundle_digest="b" * 64,
                    layer="platform-safety",
                    mode="mandatory",
                ),
            ),
        )

    async def execute(self, request: ActionRequest) -> OperationResult:
        previous = self.resource.results_by_key.get(request.idempotency_key)
        if previous is not None:
            return replace(previous, replayed=True)

        if request.arguments.get("approval_required") is True:
            pending_id = str(uuid4())
            reservation_id = f"reservation:{pending_id}"
            result = OperationResult(
                operation_id=request.operation_id,
                decision=self._decision(DecisionEffect.ESCALATE),
                committed=False,
                status=OperationStatus.PENDING,
                pending_id=pending_id,
                reservation_id=reservation_id,
                resolution_plan=PendingResolutionPlan.RESERVATION_PROOF,
                reservation_safety_certificate_digest=CERTIFICATE_DIGEST,
                reservation_entitlement_digest=ENTITLEMENT_DIGEST,
            )
            self.resource.pending[pending_id] = PendingOperation(
                pending_id=pending_id,
                request=request,
                decision=result.decision,
                mode=MasuGateMode.RESERVATION,
                reservation_id=reservation_id,
                resolution_plan=result.resolution_plan,
                reservation_safety_certificate_digest=(
                    result.reservation_safety_certificate_digest
                ),
                reservation_entitlement_digest=result.reservation_entitlement_digest,
            )
        else:
            self.effect_count += 1
            result = OperationResult(
                operation_id=request.operation_id,
                decision=self._decision(DecisionEffect.ALLOW),
                committed=True,
                status=OperationStatus.COMMITTED,
                payload={"effect_number": self.effect_count},
            )
        self.resource.record(request, result)
        return result

    async def resolve_pending(
        self,
        pending_id: str,
        *,
        approved: bool,
        evidence: dict[str, JsonValue],
    ) -> OperationResult:
        previous = self.resource.resolved.get(pending_id)
        if previous is not None:
            return replace(previous, replayed=True)
        try:
            pending = self.resource.pending.pop(pending_id)
        except KeyError as exc:
            raise ResourceError(f"unknown pending operation: {pending_id}") from exc

        if pending_id in self.concurrent_denials:
            self.concurrent_denials.remove(pending_id)
            result = OperationResult(
                operation_id=pending.request.operation_id,
                decision=self._decision(DecisionEffect.DENY),
                committed=False,
                status=OperationStatus.DENIED,
                payload={"approval_evidence": {"resolution": "concurrent-denial"}},
                reservation_id=pending.reservation_id,
                resolution_plan=pending.resolution_plan,
                reservation_safety_certificate_digest=(
                    pending.reservation_safety_certificate_digest
                ),
                reservation_entitlement_digest=pending.reservation_entitlement_digest,
            )
            self.resource.record(pending.request, result)
            self.resource.resolved[pending_id] = result
            return replace(result, replayed=True)

        effect = DecisionEffect.ALLOW if approved else DecisionEffect.DENY
        if approved:
            self.effect_count += 1
        result = OperationResult(
            operation_id=pending.request.operation_id,
            decision=self._decision(effect),
            committed=approved,
            status=OperationStatus.COMMITTED if approved else OperationStatus.DENIED,
            payload={"approval_evidence": evidence},
            reservation_id=pending.reservation_id,
            resolution_plan=pending.resolution_plan,
            reservation_safety_certificate_digest=(pending.reservation_safety_certificate_digest),
            reservation_entitlement_digest=pending.reservation_entitlement_digest,
        )
        self.resource.record(pending.request, result)
        self.resource.resolved[pending_id] = result
        return result


def _stack() -> tuple[Any, FakeCoordinator]:
    resource = FakeGovernanceResource()
    coordinator = FakeCoordinator(resource)
    app = create_app(
        coordinator,  # type: ignore[arg-type]
        resource,  # type: ignore[arg-type]
        {"alice-token": "alice"},
        operator_principals={"alice"},
    )
    return app, coordinator


async def test_execute_retry_is_one_effect_and_audit_round_trip() -> None:
    app, coordinator = _stack()
    transport = httpx.ASGITransport(app=app)
    async with MasuGateClient(
        "http://masugated.test", "alice-token", transport=transport
    ) as client:
        first = await client.execute(
            "purchase",
            {"amount_cents": 1250},
            "checkout:order-42",
            "trace-42",
        )
        replay = await client.execute(
            "purchase",
            {"amount_cents": 1250},
            "checkout:order-42",
            "trace-42",
        )

        assert first.status == "committed"
        assert replay.operation_id == first.operation_id
        assert replay.replayed
        assert coordinator.effect_count == 1

        receipt = await client.get_audit(first.operation_id)
        assert receipt.status == "committed"
        assert receipt.request.idempotency_key == derive_idempotency_key("checkout:order-42")
        assert receipt.request.trace_id == "trace-42"
        assert receipt.request.request_time == receipt.request.timestamp
        assert len(receipt.authorization_evaluations) == 1
        assert receipt.authorization_evaluations[0].decision.evaluated_policies == (
            receipt.policy.evaluated_policies
        )
        assert receipt.authorization_evaluations[0].decision.policy_provenance == (
            receipt.policy.evaluated_policy_provenance
        )
        assert receipt.terminal_serialization is not None
        assert receipt.terminal_serialization.provider_atomic
        assert receipt.effect is not None
        assert receipt.effect.payload == {"effect_number": 1}
        assert receipt.view_reads[0].scope == "limit:default"


async def test_escalate_list_stream_resolve_and_terminal_audit() -> None:
    app, coordinator = _stack()
    transport = httpx.ASGITransport(app=app)
    async with MasuGateClient(
        "http://masugated.test", "alice-token", transport=transport
    ) as client:
        pending = await client.execute(
            "purchase",
            {"amount_cents": 7500, "approval_required": True},
            "checkout:approval-7",
        )
        assert pending.status == "pending"
        assert pending.pending_id is not None
        assert pending.pending_id != pending.operation_id
        assert pending.resolution_plan == "reservation-proof"
        assert pending.reservation_safety_certificate_digest == CERTIFICATE_DIGEST
        assert pending.reservation_entitlement_digest == ENTITLEMENT_DIGEST

        page = await client.list_pending()
        assert [item.pending_id for item in page.items] == [pending.pending_id]
        assert page.next_cursor == pending.pending_id
        assert page.items[0].resolution_plan == "reservation-proof"
        assert page.items[0].reservation_safety_certificate_digest == CERTIFICATE_DIGEST
        assert page.items[0].reservation_entitlement_digest == ENTITLEMENT_DIGEST

        events = [event async for event in client.stream_pending(once=True)]
        assert [event.event_id for event in events] == [pending.pending_id]
        assert events[0].pending.action == "purchase"
        assert events[0].pending.resolution_plan == "reservation-proof"
        assert events[0].pending.reservation_safety_certificate_digest == CERTIFICATE_DIGEST
        assert events[0].pending.reservation_entitlement_digest == ENTITLEMENT_DIGEST

        resolved = await client.resolve_pending(
            pending.pending_id,
            True,
            {"ticket": "CAB-7", "review": {"operator": "alice"}},
        )
        assert resolved.status == "committed"
        assert resolved.payload["approval_evidence"] == {
            "ticket": "CAB-7",
            "review": {"operator": "alice"},
        }
        assert coordinator.effect_count == 1
        assert (await client.list_pending()).items == ()

        receipt = await client.get_audit(resolved.operation_id)
        assert receipt.status == "committed"
        assert receipt.effect is not None
        assert receipt.resolution_plan == "reservation-proof"
        assert receipt.reservation_safety_certificate_digest == CERTIFICATE_DIGEST
        assert receipt.reservation_entitlement_digest == ENTITLEMENT_DIGEST
        assert len(receipt.policy.evaluated_policy_provenance) == 1
        assert receipt.policy.evaluated_policy_provenance[0].bundle_id == "sdk.reference"
        assert receipt.effect.payload["approval_evidence"] == {
            "ticket": "CAB-7",
            "review": {"operator": "alice"},
        }


async def test_adapter_client_surface_asserts_owner_and_recovers_cancellation_lifecycle() -> None:
    resource = FakeGovernanceResource()
    coordinator = FakeCoordinator(resource)
    app = create_app(
        coordinator,  # type: ignore[arg-type]
        resource,  # type: ignore[arg-type]
        {"adapter-token": "adapter:buyer"},
        operator_principals={"adapter:buyer"},
        action_owners={
            "purchase": ActionOwnerBinding(
                provider_id="spend-v1",
                position=EffectExecutionPosition.PROTECTED_EXTERNAL,
                connector_id="purchase-v1",
            )
        },
        adapter_invocation_principals={"adapter:buyer"},
    )
    owner = ExpectedActionOwner(
        provider_id="spend-v1",
        position="protected-external",
        connector_id="purchase-v1",
    )

    def adapter_invocation(source_id: str, args: dict[str, bool | int]) -> str:
        return canonical_adapter_envelope(
            create_adapter_invocation(
                {
                    "principal": {"id": "adapter:buyer"},
                    "source": {"namespace": "masugate-client-test", "id": source_id},
                    "adapter": {
                        "id": "masugate.client.test",
                        "contract_version": "masugate.host-adapter.v1",
                        "capabilities": ["cancellation", "locator", "receipt"],
                    },
                    "action": {"name": "purchase", "arguments": args},
                }
            )
        )

    async with MasuGateClient(
        "http://masugated.test",
        "adapter-token",
        principal_id="adapter:buyer",
        transport=httpx.ASGITransport(app=app),
    ) as client:
        committed = await client.execute(
            "purchase",
            {"amount_cents": 1},
            "adapter:commit",
            owner=owner,
            adapter_invocation=adapter_invocation("adapter:commit", {"amount_cents": 1}),
        )
        assert committed.status == "committed"

        pending = await client.execute(
            "purchase",
            {"amount_cents": 2, "approval_required": True},
            "adapter:cancel",
            owner=owner,
            adapter_invocation=adapter_invocation(
                "adapter:cancel", {"amount_cents": 2, "approval_required": True}
            ),
        )
        assert pending.status == "pending"
        assert pending.pending_id is not None
        before_cancel = await client.get_pending(pending.pending_id)
        assert before_cancel.kind == "pending"
        cancellation = await client.cancel_pending(pending.pending_id)
        assert cancellation["accepted"] is True
        assert cancellation["locator"] == {
            "operation_id": pending.operation_id,
            "pending_id": pending.pending_id,
        }
        after_cancel = await client.get_pending(pending.pending_id)
        assert after_cancel.kind == "terminal"
        assert after_cancel.result is not None and after_cancel.result.status == "denied"
        receipt = await client.get_audit(pending.operation_id)
        assert receipt.status == "denied"


async def test_cancel_pending_reports_a_concurrent_denial_as_settled() -> None:
    app, coordinator = _stack()
    async with MasuGateClient(
        "http://masugated.test",
        "alice-token",
        transport=httpx.ASGITransport(app=app),
    ) as client:
        pending = await client.execute(
            "purchase",
            {"amount_cents": 2, "approval_required": True},
            "cancellation-race",
        )
        assert pending.pending_id is not None
        coordinator.concurrent_denials.add(pending.pending_id)

        cancellation = await client.cancel_pending(pending.pending_id)

        assert cancellation["accepted"] is False
        terminal = cast(dict[str, JsonValue], cancellation["terminal_result"])
        assert terminal["status"] == "denied"


async def test_cancel_pending_rejects_a_response_for_a_different_locator() -> None:
    requested = "11111111-1111-4111-8111-111111111111"
    returned = "22222222-2222-4222-8222-222222222222"

    def cancellation(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "kind": "cancellation",
                "locator": {
                    "operation_id": "33333333-3333-4333-8333-333333333333",
                    "pending_id": returned,
                },
                "accepted": True,
            },
        )

    async with MasuGateClient(
        "http://masugated.test",
        "token",
        transport=httpx.MockTransport(cancellation),
    ) as client:
        with pytest.raises(MasuGateProtocolError, match="does not match the requested id"):
            await client.cancel_pending(requested)


async def test_stage_artifact_encodes_bytes_and_accepts_only_certified_metadata() -> None:
    captured: dict[str, object] = {}

    def staging(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["path"] = request.url.path
        captured["authorization"] = request.headers["Authorization"]
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "reference": "art:fixture",
                "content_digest": "a" * 64,
                "content_bytes": 5,
                "media_type": "text/plain",
                "classification": "reference-text",
                "expires_at": "2026-07-26T13:00:00+00:00",
            },
        )

    async with MasuGateClient(
        "http://masugated.test", "alice-token", transport=httpx.MockTransport(staging)
    ) as client:
        artifact = await client.stage_artifact(
            action="reference.notify",
            field="content",
            content=b"hello",
            media_type="text/plain",
            stable_id="payload-call-1",
            adapter_invocation='{"canonical":true}',
        )

    assert artifact.reference == "art:fixture"
    assert artifact.content_bytes == 5
    assert captured["method"] == "POST"
    assert captured["path"] == "/v1/artifacts"
    assert captured["authorization"] == "Bearer alice-token"
    body = cast(dict[str, object], captured["body"])
    assert body["content_base64"] == base64.b64encode(b"hello").decode("ascii")
    assert body["idempotency_key"] == derive_idempotency_key("payload-call-1")
    assert not {"reference", "content_digest", "classification", "retention"} & set(body)


async def test_execute_rejects_unsafe_integers_before_transport() -> None:
    called = False

    def transport(_request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(500)

    async with MasuGateClient(
        "http://masugated.test",
        "token",
        transport=httpx.MockTransport(transport),
    ) as client:
        with pytest.raises(ValueError, match="safe integer"):
            await client.execute(
                "purchase",
                {"amount_cents": 9_007_199_254_740_992},
                "unsafe-integer",
            )
    assert called is False


async def test_protocol_error_envelope_and_malformed_success_are_typed() -> None:
    app, _coordinator = _stack()
    async with MasuGateClient(
        "http://masugated.test",
        "wrong-token",
        transport=httpx.ASGITransport(app=app),
    ) as client:
        with pytest.raises(MasuGateAPIError) as error:
            await client.list_pending()
        assert error.value.status_code == 401
        assert error.value.code == "unauthorized"

    def contradictory(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "operation_id": "11111111-1111-4111-8111-111111111111",
                "status": "committed",
                "decision": {
                    "effect": "deny",
                    "policy_id": "bad-server",
                    "policy_version": "v1",
                    "rule_id": "contradiction",
                    "reason": "invalid status/effect pair",
                },
                "payload": {},
                "audit_ref": "/v1/audit/11111111-1111-4111-8111-111111111111",
                "replayed": False,
            },
        )

    async with MasuGateClient(
        "http://masugated.test",
        "token",
        transport=httpx.MockTransport(contradictory),
    ) as client:
        with pytest.raises(MasuGateProtocolError, match="invalid effect"):
            await client.execute("purchase", {"amount_cents": 1}, "malformed")


def test_idempotency_derivation_is_deterministic_and_bounded() -> None:
    first = derive_idempotency_key("logical-op:\u03b1")
    assert first == derive_idempotency_key("logical-op:\u03b1")
    assert first != derive_idempotency_key("logical-op:\u03b2")
    assert first == (
        "masugate:v1:f4b1fb6e236d6320ade3ef38048d7d0cbab7cd924be48fa3058722ec67a5a6af"
    )
    assert len(first) < 255


def test_legacy_pending_response_without_resolution_metadata_still_parses() -> None:
    result = parse_action_result(
        {
            "operation_id": "11111111-1111-4111-8111-111111111111",
            "status": "pending",
            "decision": {
                "effect": "escalate",
                "policy_id": "legacy",
                "policy_version": "v1",
                "rule_id": "review",
                "reason": "human review required",
            },
            "payload": {},
            "pending_id": "22222222-2222-4222-8222-222222222222",
            "audit_ref": "/v1/audit/11111111-1111-4111-8111-111111111111",
            "replayed": False,
        }
    )

    assert result.resolution_plan is None
    assert result.reservation_safety_certificate_digest is None
    assert result.reservation_entitlement_digest is None


@pytest.mark.parametrize("status", ["in_progress", "outcome_unknown"])
def test_protected_operational_action_results_have_no_detached_decision(status: str) -> None:
    payload = {
        "operation_id": "11111111-1111-4111-8111-111111111111",
        "status": status,
        "decision": None,
        "payload": {"protected_execution": {"status": status}},
        "audit_ref": "/v1/audit/11111111-1111-4111-8111-111111111111",
        "replayed": False,
    }

    parsed = parse_action_result(payload)

    assert parsed.status == status
    assert parsed.decision is None
    with pytest.raises(MasuGateProtocolError, match="decision must be null"):
        parse_action_result({**payload, "decision": {"effect": "allow"}})
    with pytest.raises(MasuGateProtocolError, match="pending_id is forbidden"):
        parse_action_result({**payload, "pending_id": "22222222-2222-4222-8222-222222222222"})


def test_operational_audit_and_resolver_attribution_are_typed() -> None:
    example = Path(__file__).parents[3] / "protocol" / "examples" / "audit.json"
    operational = json.loads(example.read_text(encoding="utf-8"))
    operational.update(
        {
            "status": "outcome_unknown",
            "decision": None,
            "terminal_serialization": None,
            "effect": None,
        }
    )
    del operational["protected_execution"]
    del operational["resolution_plan"]
    del operational["reservation_safety_certificate_digest"]
    del operational["reservation_entitlement_digest"]

    parsed_operational = parse_audit_record(operational)

    assert parsed_operational.status == "outcome_unknown"
    assert parsed_operational.decision is None
    resolved = json.loads(example.read_text(encoding="utf-8"))
    resolved["human_resolution"] = {
        "approved": True,
        "actor_id": "operator:alice",
        "evidence": {"ticket": "CAB-7"},
        "resolved_at": "2026-07-13T12:02:00Z",
    }
    parsed_resolved = parse_audit_record(resolved)
    assert parsed_resolved.human_resolution is not None
    assert parsed_resolved.human_resolution.actor_id == "operator:alice"
    assert parsed_resolved.human_resolution.resolved_at is not None
    assert parsed_resolved.human_resolution.evidence == {"ticket": "CAB-7"}

    expired = json.loads(example.read_text(encoding="utf-8"))
    expired.update(
        {
            "status": "denied",
            "decision": {
                "effect": "deny",
                "rule_id": "approval.expired",
                "reason": "approval deadline elapsed",
            },
            "terminal_serialization": {
                "kind": "denial-record",
                "authorization_basis": "mechanism-denial",
                "provider_atomic": False,
                "recorded_at": "2026-07-13T12:02:00Z",
            },
            "effect": None,
            "automatic_expiry": {
                "expires_at": "2026-07-13T12:00:00Z",
                "reason": "approval-window-expired",
            },
        }
    )
    del expired["protected_execution"]
    parsed_expired = parse_audit_record(expired)
    assert parsed_expired.human_resolution is None
    assert parsed_expired.automatic_expiry is not None
    assert parsed_expired.automatic_expiry.reason == "approval-window-expired"

    del expired["automatic_expiry"]
    with pytest.raises(
        MasuGateProtocolError, match=r"approval\.expired requires automatic expiry"
    ):
        parse_audit_record(expired)

    expired["automatic_expiry"] = {
        "expires_at": "2026-07-13T12:00:00Z",
        "reason": "approval-window-expired",
    }
    expired["human_resolution"] = resolved["human_resolution"]
    with pytest.raises(MasuGateProtocolError, match="may not claim a human resolution"):
        parse_audit_record(expired)


def test_pending_resolution_metadata_accepts_only_complete_legal_shapes() -> None:
    def pending_response() -> dict[str, object]:
        return {
            "operation_id": "11111111-1111-4111-8111-111111111111",
            "status": "pending",
            "decision": {
                "effect": "escalate",
                "policy_id": "reservation-policy",
                "policy_version": "v1",
                "rule_id": "review",
                "reason": "human review required",
            },
            "payload": {},
            "pending_id": "22222222-2222-4222-8222-222222222222",
            "resolution_plan": "reservation-proof",
            "reservation_safety_certificate_digest": CERTIFICATE_DIGEST,
            "reservation_entitlement_digest": ENTITLEMENT_DIGEST,
            "audit_ref": "/v1/audit/11111111-1111-4111-8111-111111111111",
            "replayed": False,
        }

    malformed: list[dict[str, object]] = []
    for missing_field in (
        "reservation_safety_certificate_digest",
        "reservation_entitlement_digest",
    ):
        value = pending_response()
        del value[missing_field]
        malformed.append(value)
    for remaining_digest, removed_digest in (
        (
            "reservation_safety_certificate_digest",
            "reservation_entitlement_digest",
        ),
        (
            "reservation_entitlement_digest",
            "reservation_safety_certificate_digest",
        ),
    ):
        value = pending_response()
        del value["resolution_plan"]
        del value[removed_digest]
        assert remaining_digest in value
        malformed.append(value)
        value = pending_response()
        value["resolution_plan"] = "revalidate"
        del value[removed_digest]
        assert remaining_digest in value
        malformed.append(value)

    for value in malformed:
        with pytest.raises(MasuGateProtocolError):
            parse_action_result(value)

    revalidation = pending_response()
    revalidation["resolution_plan"] = "revalidate"
    del revalidation["reservation_safety_certificate_digest"]
    del revalidation["reservation_entitlement_digest"]
    parsed = parse_action_result(revalidation)
    assert parsed.resolution_plan == "revalidate"
    assert parsed.reservation_safety_certificate_digest is None
    assert parsed.reservation_entitlement_digest is None
