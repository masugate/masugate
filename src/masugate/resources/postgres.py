"""Async PostgreSQL-backed policy-state ledger.

It implements resource protocols using pooled connections and
transaction-scoped advisory locks.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from psycopg import AsyncConnection, AsyncCursor, IsolationLevel
from psycopg.abc import Params, QueryNoTemplate
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from masugate.certification import certified_input_evidence_json
from masugate.contracts import (
    ContractRegistry,
    EffectContract,
    GovernanceViewContract,
    ProviderIdentity,
    ReservationCapability,
    ReservationViewKind,
    ResourceSession,
)
from masugate.errors import ResourceError, RetryableResourceError
from masugate.model import (
    ActionRequest,
    AuthorizationEvaluation,
    CertificationPhase,
    CertifiedInputEvidence,
    CertifiedInputStability,
    CertifiedInputStabilityProof,
    ConsistencyGuarantee,
    DecisionEffect,
    Duration,
    JsonValue,
    OperationMetrics,
    OperationResult,
    OperationStatus,
    PendingOperation,
    PendingResolutionPlan,
    PolicyDecision,
    PolicyProvenance,
    Principal,
    ProtectedArtifactMetadata,
    MasuGateMode,
    ResourceFootprint,
    Scalar,
    TypeName,
    ViewRead,
)
from masugate.provider_assembly import (
    CoordinationDomain,
    EffectBinding,
    EffectExecutionPosition,
    ProviderModule,
)
from masugate.resources.base import decode_idempotency_scope

# MasuGate domain configuration. Mirrors the frozen sqlite_ledger constants; defined
# in the product (not imported from the frozen tree) so the async provider does
# not depend on reference/.
TEAM_BUDGET_LIMIT_CENTS = 100_000
TEAM_BUDGET_WINDOW = Duration(24 * 60 * 60)
RESERVATION_TTL = timedelta(hours=1)
LEDGER_RESERVATION_PROOF = "masugate.postgres.team-budget.v1"
LEDGER_EFFECT_IMPLEMENTATION = "masugate.postgres.transfer-effect.v1"
LEDGER_RESERVATION_CONFIG_VERSION = hashlib.sha256(
    json.dumps(
        {
            "limit_cents": TEAM_BUDGET_LIMIT_CENTS,
            "reservation_ttl_seconds": int(RESERVATION_TTL.total_seconds()),
            "window_seconds": TEAM_BUDGET_WINDOW.seconds,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
).hexdigest()
LEDGER_PROVIDER_IDENTITY = ProviderIdentity(
    provider_id="masugate.postgres-ledger",
    implementation_version="async-postgres-ledger-v1",
    configuration_version=LEDGER_RESERVATION_CONFIG_VERSION,
)
LEDGER_COORDINATION_DOMAIN_ID = "masugate.postgres-ledger.domain.v1"
LEDGER_SCOPE_DERIVATION_ID = "masugate.postgres-ledger.scopes.v1"


def _reservation_request_digest(request: ActionRequest) -> str:
    """Return the canonical execution identity bound to a reservation.

    ``trace_id`` is deliberately excluded because it is transport metadata, not
    part of the governed effect.  The remaining fields match the coordinator's
    reservation-entitlement identity, including the original certified
    principal attributes, resource, and request timestamp.
    """

    payload: dict[str, JsonValue] = {
        "action": request.action,
        "arguments": dict(request.arguments),
        "certified_inputs": {
            name: certified_input_evidence_json(evidence)
            for name, evidence in sorted(request.certified_inputs.items())
        },
        "idempotency_key": request.idempotency_key,
        "operation_id": request.operation_id,
        "principal": {
            "attributes": dict(request.principal.attributes),
            "id": request.principal.id,
        },
        "resource": request.resource,
        "timestamp": request.timestamp.isoformat(),
    }
    # Version the identity by presence: durable reservations written before
    # adapter provenance existed did not carry this member.  Keeping an absent
    # digest absent preserves their authenticated hash while asserted adapter
    # provenance remains part of every new binding.
    if request.adapter_invocation_digest is not None:
        payload["adapter_invocation_digest"] = request.adapter_invocation_digest
    if request.protected_artifacts:
        payload["protected_artifacts"] = {
            name: metadata.payload()
            for name, metadata in sorted(request.protected_artifacts.items())
        }
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _pending_request_digest(request: ActionRequest) -> str:
    """Bind every persisted field of the certified pending request.

    Reservation identity deliberately excludes ``trace_id`` because tracing does
    not select an entitlement.  A pending row is the durable review artifact,
    however, so its independent binding also covers transport trace metadata.
    Keeping this digest in a relational column means later JSON corruption cannot
    silently change the action that an approval will execute.
    """

    payload: dict[str, JsonValue] = {
        "action": request.action,
        "arguments": dict(request.arguments),
        "certified_inputs": {
            name: certified_input_evidence_json(evidence)
            for name, evidence in sorted(request.certified_inputs.items())
        },
        "idempotency_key": request.idempotency_key,
        "operation_id": request.operation_id,
        "principal": {
            "attributes": dict(request.principal.attributes),
            "id": request.principal.id,
        },
        "resource": request.resource,
        "timestamp": request.timestamp.isoformat(),
        "trace_id": request.trace_id,
    }
    # See ``_reservation_request_digest``.  Pending rows must continue to
    # decode after this field was introduced, while asserted provenance is
    # always covered when supplied.
    if request.adapter_invocation_digest is not None:
        payload["adapter_invocation_digest"] = request.adapter_invocation_digest
    if request.protected_artifacts:
        payload["protected_artifacts"] = {
            name: metadata.payload()
            for name, metadata in sorted(request.protected_artifacts.items())
        }
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


@dataclass
class PostgresSession:
    """A resource-owned async transaction (one checked-out pooled connection).

    ``certified_now`` is the server-certified admission timestamp (0.12): set
    once by :meth:`AsyncPostgresLedger.certify_admission` after scope locks are
    acquired, then used as the single time anchor for every window/expiry
    comparison and effect timestamp in this operation. ``None`` (data-plane use
    without a coordinator) makes time-anchored queries fall back to the DB's
    ``now()`` — still server-side; the client clock never anchors anything.
    """

    connection: AsyncConnection[dict[str, Any]]
    certified_now: datetime | None = None
    cached_idempotency_identity: tuple[str, str] | None = None
    cached_record: dict[str, JsonValue] | None = None
    cached_result_is_pending: bool = False
    cached_durable_row: dict[str, Any] | None = None
    consumed_reservation_ids: set[str] = field(default_factory=set)
    query_count: int = 0
    on_query: Callable[[], None] | None = None

    async def execute(
        self,
        query: QueryNoTemplate,
        params: Params | None = None,
        *,
        prepare: bool | None = None,
        binary: bool = False,
    ) -> AsyncCursor[dict[str, Any]]:
        """Execute one SQL statement and count its actual provider round trip."""

        self.query_count += 1
        if self.on_query is not None:
            self.on_query()
        return await self.connection.execute(
            query,
            params,
            prepare=prepare,
            binary=binary,
        )


def _lock_key(scope: str) -> int:
    """Stable 64-bit signed advisory-lock key for a scope (matches frozen)."""
    digest = hashlib.blake2b(scope.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, byteorder="big", signed=True)


def _is_retryable(exc: BaseException) -> bool:
    sqlstate = getattr(exc, "sqlstate", None)
    return sqlstate in {"40001", "40P01"} or exc.__class__.__name__ in {
        "SerializationFailure",
        "DeadlockDetected",
    }


def _as_session(session: ResourceSession) -> PostgresSession:
    if not isinstance(session, PostgresSession):
        raise ResourceError("PostgreSQL ledger received an incompatible resource session")
    return session


# -- durable-record codec (ported from frozen _encode_record/_decode_result) -- #


def _json_record(raw: object) -> dict[str, JsonValue]:
    if isinstance(raw, dict):
        return cast(dict[str, JsonValue], raw)
    return cast(dict[str, JsonValue], json.loads(cast(str, raw)))


def _governance_record_digest(record: dict[str, JsonValue]) -> str:
    """Canonical integrity binding for one complete durable governance record."""

    return hashlib.sha256(
        json.dumps(
            record,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _encode_metrics(metrics: OperationMetrics) -> dict[str, JsonValue]:
    return {
        "total_latency_ms": metrics.total_latency_ms,
        "policy_eval_ms": metrics.policy_eval_ms,
        "effect_exec_ms": metrics.effect_exec_ms,
        "transaction_ms": metrics.transaction_ms,
        "local_lock_wait_ms": metrics.local_lock_wait_ms,
        "advisory_lock_wait_ms": metrics.advisory_lock_wait_ms,
        "reservation_create_ms": metrics.reservation_create_ms,
        "reservation_consume_ms": metrics.reservation_consume_ms,
        "reservation_release_ms": metrics.reservation_release_ms,
        "scope_hold_wait_ms": metrics.scope_hold_wait_ms,
        "retry_attempts": metrics.retry_attempts,
        "attempt_count": metrics.attempt_count,
    }


def _decode_metrics(record: dict[str, JsonValue]) -> OperationMetrics:
    metrics = record.get("metrics")
    if not isinstance(metrics, dict):
        return OperationMetrics()
    return OperationMetrics(
        total_latency_ms=float(cast(float | int, metrics.get("total_latency_ms", 0.0))),
        policy_eval_ms=float(cast(float | int, metrics.get("policy_eval_ms", 0.0))),
        effect_exec_ms=float(cast(float | int, metrics.get("effect_exec_ms", 0.0))),
        transaction_ms=float(cast(float | int, metrics.get("transaction_ms", 0.0))),
        local_lock_wait_ms=float(cast(float | int, metrics.get("local_lock_wait_ms", 0.0))),
        advisory_lock_wait_ms=float(cast(float | int, metrics.get("advisory_lock_wait_ms", 0.0))),
        reservation_create_ms=float(cast(float | int, metrics.get("reservation_create_ms", 0.0))),
        reservation_consume_ms=float(cast(float | int, metrics.get("reservation_consume_ms", 0.0))),
        reservation_release_ms=float(cast(float | int, metrics.get("reservation_release_ms", 0.0))),
        scope_hold_wait_ms=float(cast(float | int, metrics.get("scope_hold_wait_ms", 0.0))),
        retry_attempts=int(cast(int, metrics.get("retry_attempts", 0))),
        attempt_count=int(cast(int, metrics.get("attempt_count", 1))),
    )


def _encode_read(read: ViewRead) -> dict[str, JsonValue]:
    return {
        "function": read.function,
        "arguments": [
            argument.seconds if isinstance(argument, Duration) else argument
            for argument in read.arguments
        ],
        "value": read.value,
        "scope": read.scope,
        "version": read.version,
        "latency_ms": read.latency_ms,
    }


def _encode_decision(decision: PolicyDecision) -> dict[str, JsonValue]:
    return {
        "effect": str(decision.effect),
        "policy_id": decision.policy_id,
        "rule_id": decision.rule_id,
        "reason": decision.reason,
        "reads": [_encode_read(read) for read in decision.reads],
        "policy_version": decision.policy_version,
        "evaluated_policies": [
            [policy_id, version] for policy_id, version in decision.evaluated_policies
        ],
        "policy_provenance": [
            {
                "bundle_digest": item.bundle_digest,
                "bundle_id": item.bundle_id,
                "bundle_version": item.bundle_version,
                "layer": item.layer,
                "mode": item.mode,
                "policy_declared_version": item.policy_declared_version,
                "policy_digest": item.policy_digest,
                "policy_id": item.policy_id,
                "policy_runtime_version": item.policy_runtime_version,
            }
            for item in decision.policy_provenance
        ],
    }


def _decode_decision(record: dict[str, JsonValue]) -> PolicyDecision:
    read_records = cast(list[JsonValue], record.get("reads", []))
    reads: list[ViewRead] = []
    for item in read_records:
        read = cast(dict[str, JsonValue], item)
        reads.append(
            ViewRead(
                function=cast(str, read["function"]),
                arguments=tuple(cast(list[Scalar], read["arguments"])),
                value=cast(Scalar, read["value"]),
                scope=cast(str, read["scope"]),
                version=cast(int, read["version"]),
                latency_ms=float(cast(float | int, read["latency_ms"])),
            )
        )
    evaluated_raw = cast(list[JsonValue], record.get("evaluated_policies", []))
    evaluated = tuple(
        (pair[0], pair[1]) for pair in (cast(list[str], item) for item in evaluated_raw)
    )
    provenance_raw = cast(list[JsonValue], record.get("policy_provenance", []))
    provenance = tuple(
        PolicyProvenance(
            policy_id=cast(str, item["policy_id"]),
            policy_declared_version=cast(str, item["policy_declared_version"]),
            policy_runtime_version=cast(str, item["policy_runtime_version"]),
            policy_digest=cast(str, item["policy_digest"]),
            bundle_id=cast(str, item["bundle_id"]),
            bundle_version=cast(str, item["bundle_version"]),
            bundle_digest=cast(str, item["bundle_digest"]),
            layer=cast(str, item["layer"]),
            mode=cast(str, item["mode"]),
        )
        for item in (cast(dict[str, JsonValue], raw) for raw in provenance_raw)
    )
    return PolicyDecision(
        effect=DecisionEffect(cast(str, record["effect"])),
        policy_id=cast(str, record["policy_id"]),
        rule_id=cast(str, record["rule_id"]),
        reason=cast(str, record["reason"]),
        reads=tuple(reads),
        policy_version=cast(str, record.get("policy_version", "")),
        evaluated_policies=evaluated,
        policy_provenance=provenance,
    )


def _decode_certified_input(record: dict[str, JsonValue]) -> CertifiedInputEvidence:
    value_type = TypeName(cast(str, record["value_type"]))
    raw_value = record["value"]
    value: Scalar | Duration
    if value_type is TypeName.DURATION:
        value = Duration(cast(int, cast(dict[str, JsonValue], raw_value)["seconds"]))
    else:
        value = cast(Scalar, raw_value)
    raw_proof = record.get("stability_proof")
    return CertifiedInputEvidence(
        name=cast(str, record["name"]),
        value=value,
        value_type=value_type,
        stability=CertifiedInputStability(cast(str, record["stability"])),
        stability_proof=(
            CertifiedInputStabilityProof(cast(str, raw_proof)) if raw_proof is not None else None
        ),
        source_id=cast(str, record["source_id"]),
        source_version=cast(str, record["source_version"]),
        contract_version=cast(str, record["contract_version"]),
        observed_at=datetime.fromisoformat(cast(str, record["observed_at"])),
        certified_at=datetime.fromisoformat(cast(str, record["certified_at"])),
        freshness_ttl=Duration(cast(int, record["freshness_ttl_seconds"])),
        phase=CertificationPhase(cast(str, record["phase"])),
    )


def _encode_authorization_evaluation(
    evaluation: AuthorizationEvaluation,
) -> dict[str, JsonValue]:
    return {
        "phase": evaluation.phase.value,
        "evaluated_at": evaluation.evaluated_at.isoformat(),
        "decision": _encode_decision(evaluation.decision),
        "certified_inputs": [
            certified_input_evidence_json(evidence)
            for _, evidence in sorted(evaluation.certified_inputs.items())
        ],
    }


def _decode_authorization_evaluations(
    record: dict[str, JsonValue],
) -> tuple[AuthorizationEvaluation, ...]:
    raw_evaluations = cast(list[JsonValue], record.get("authorization_evaluations", []))
    evaluations: list[AuthorizationEvaluation] = []
    for raw in raw_evaluations:
        item = cast(dict[str, JsonValue], raw)
        certified_inputs = {
            evidence.name: evidence
            for evidence in (
                _decode_certified_input(cast(dict[str, JsonValue], evidence_record))
                for evidence_record in cast(list[JsonValue], item.get("certified_inputs", []))
            )
        }
        evaluations.append(
            AuthorizationEvaluation(
                phase=CertificationPhase(cast(str, item["phase"])),
                evaluated_at=datetime.fromisoformat(cast(str, item["evaluated_at"])),
                decision=_decode_decision(cast(dict[str, JsonValue], item["decision"])),
                certified_inputs=certified_inputs,
            )
        )
    return tuple(evaluations)


def _terminal_serialization(
    result: OperationResult,
    recorded_at: datetime,
) -> dict[str, JsonValue] | None:
    if result.status is OperationStatus.PENDING:
        return None
    latest = result.authorization_evaluations[-1] if result.authorization_evaluations else None
    if (
        result.resolution_plan is PendingResolutionPlan.RESERVATION_PROOF
        and result.resolution_evidence is not None
        and latest is not None
        and latest.phase is CertificationPhase.ADMISSION
    ):
        basis = "preserved-admission-evaluation"
    elif latest is not None and latest.phase is CertificationPhase.RESOLUTION:
        basis = "resolution-evaluation"
    elif latest is not None:
        basis = "admission-evaluation"
    else:
        basis = "mechanism-denial"
    payload: dict[str, JsonValue] = {
        "kind": "effect-commit" if result.committed else "denial-record",
        "authorization_basis": basis,
        "provider_atomic": True,
        "recorded_at": recorded_at.isoformat(),
    }
    if latest is not None:
        payload["evaluation_phase"] = latest.phase.value
        payload["evaluation_at"] = latest.evaluated_at.isoformat()
    return payload


def _recorded_at(
    pg: PostgresSession,
    result: OperationResult,
) -> datetime:
    """Choose a provider-certified timestamp already obtained in this tx.

    The value is carried by the atomic governance record but is not presented
    as the physical database commit time.  Revalidation uses its new evaluation
    point; reservation resolution uses the fresh protected-session clock; an
    immediate operation uses its admission evaluation point.
    """

    latest = result.authorization_evaluations[-1] if result.authorization_evaluations else None
    if (
        result.resolution_evidence is not None
        and latest is not None
        and latest.phase is CertificationPhase.ADMISSION
    ):
        return pg.certified_now or latest.evaluated_at
    if latest is not None:
        return latest.evaluated_at
    return pg.certified_now or datetime.now(UTC)


def _encode_record(
    request: ActionRequest,
    result: OperationResult,
    mode: MasuGateMode,
    recorded_at: datetime,
) -> dict[str, JsonValue]:
    record: dict[str, JsonValue] = {
        "operation_id": request.operation_id,
        "idempotency_key": request.idempotency_key,
        "principal_id": request.principal.id,
        "principal_attributes": {
            name: cast(JsonValue, value) for name, value in request.principal.attributes.items()
        },
        "action": request.action,
        "arguments": {name: cast(JsonValue, value) for name, value in request.arguments.items()},
        "timestamp": request.timestamp.isoformat(),
        "request_time": request.timestamp.isoformat(),
        "recorded_at": recorded_at.isoformat(),
        "resource": request.resource,
        "trace_id": request.trace_id,
        "adapter_invocation_digest": request.adapter_invocation_digest,
        "mode": str(mode),
        "decision": _encode_decision(result.decision),
        "authorization_evaluations": [
            _encode_authorization_evaluation(evaluation)
            for evaluation in result.authorization_evaluations
        ],
        "terminal_serialization": _terminal_serialization(result, recorded_at),
        "resolution_evidence": result.resolution_evidence,
        "status": str(result.status) if result.status is not None else None,
        "committed": result.committed,
        "payload": result.payload,
        "metrics": _encode_metrics(result.metrics),
        "pending_id": result.pending_id,
        "reservation_id": result.reservation_id,
        "resolution_plan": str(result.resolution_plan),
        "reservation_safety_certificate_digest": (result.reservation_safety_certificate_digest),
        "reservation_entitlement_digest": result.reservation_entitlement_digest,
    }
    if request.protected_artifacts:
        record["protected_artifacts"] = {
            name: metadata.payload()
            for name, metadata in sorted(request.protected_artifacts.items())
        }
    return record


def _decode_protected_artifacts(
    record: dict[str, JsonValue],
) -> dict[str, ProtectedArtifactMetadata]:
    """Decode only the content-free artifact projection from a durable record."""

    raw = record.get("protected_artifacts", {})
    if not isinstance(raw, dict):
        raise ResourceError("protected artifact metadata is malformed")
    parsed: dict[str, ProtectedArtifactMetadata] = {}
    required = {
        "reference",
        "content_digest",
        "content_bytes",
        "media_type",
        "classification",
        "expires_at",
        "inspector_version",
    }
    for artifact_field, value in raw.items():
        if type(artifact_field) is not str or not isinstance(value, dict) or set(value) != required:
            raise ResourceError("protected artifact metadata is malformed")
        try:
            parsed[artifact_field] = ProtectedArtifactMetadata(
                reference=cast(str, value["reference"]),
                content_digest=cast(str, value["content_digest"]),
                content_bytes=cast(int, value["content_bytes"]),
                media_type=cast(str, value["media_type"]),
                classification=cast(str, value["classification"]),
                expires_at=datetime.fromisoformat(cast(str, value["expires_at"])),
                inspector_version=cast(str, value["inspector_version"]),
            )
        except (TypeError, ValueError) as exc:
            raise ResourceError("protected artifact metadata is malformed") from exc
    return parsed


def _decode_result(record: dict[str, JsonValue]) -> OperationResult:
    decision_record = cast(dict[str, JsonValue], record["decision"])
    decision = _decode_decision(decision_record)
    committed = cast(bool, record["committed"])
    raw_status = record.get("status")
    status = (
        OperationStatus(cast(str, raw_status))
        if raw_status is not None
        else OperationStatus.COMMITTED
        if committed
        else OperationStatus.DENIED
    )
    resolution_plan, certificate_digest, entitlement_digest = _decode_resolution_metadata(record)
    raw_reservation_id = record.get("reservation_id")
    reservation_id = raw_reservation_id if isinstance(raw_reservation_id, str) else None
    # The model intentionally rejects a proof plan without an entitlement. A
    # durable codec must normalize that corrupt combination before construction
    # so the row can reach the coordinator's fail-closed integrity path.
    if resolution_plan is PendingResolutionPlan.RESERVATION_PROOF and reservation_id is None:
        resolution_plan = PendingResolutionPlan.REVALIDATE
        certificate_digest = None
        entitlement_digest = None
    return OperationResult(
        operation_id=cast(str, record["operation_id"]),
        decision=decision,
        committed=committed,
        status=status,
        payload=cast(dict[str, JsonValue], record["payload"]),
        metrics=_decode_metrics(record),
        pending_id=cast(str | None, record.get("pending_id")),
        reservation_id=reservation_id,
        resolution_plan=resolution_plan,
        reservation_safety_certificate_digest=certificate_digest,
        reservation_entitlement_digest=entitlement_digest,
        authorization_evaluations=_decode_authorization_evaluations(record),
        resolution_evidence=(
            cast(dict[str, JsonValue], record["resolution_evidence"])
            if isinstance(record.get("resolution_evidence"), dict)
            else None
        ),
    )


def _decode_replay_for_request(
    record: dict[str, JsonValue],
    request: ActionRequest,
) -> OperationResult:
    """Validate that a principal-owned key is being replayed for the same request."""

    recorded_principal = cast(str, record["principal_id"])
    recorded_action = cast(str, record["action"])
    recorded_arguments = cast(dict[str, Scalar], record["arguments"])
    recorded_resource = cast(str | None, record.get("resource"))
    recorded_adapter_invocation_digest = cast(str | None, record.get("adapter_invocation_digest"))
    recorded_protected_artifacts = _decode_protected_artifacts(record)
    if (
        recorded_principal != request.principal.id
        or recorded_action != request.action
        or recorded_arguments != request.arguments
        or recorded_resource != request.resource
        or recorded_adapter_invocation_digest != request.adapter_invocation_digest
        or recorded_protected_artifacts != request.protected_artifacts
    ):
        raise ResourceError(
            "idempotency key is already bound to a different request for this principal"
        )
    return _decode_result(record)


def _encode_result_only(result: OperationResult) -> dict[str, JsonValue]:
    return {
        "operation_id": result.operation_id,
        "decision_effect": str(result.decision.effect),
        "rule_id": result.decision.rule_id,
        "status": str(result.status) if result.status is not None else None,
        "committed": result.committed,
        "metrics": _encode_metrics(result.metrics),
        "pending_id": result.pending_id,
        "reservation_id": result.reservation_id,
        "resolution_plan": str(result.resolution_plan),
        "reservation_safety_certificate_digest": (result.reservation_safety_certificate_digest),
        "reservation_entitlement_digest": result.reservation_entitlement_digest,
    }


def _decode_pending(record: dict[str, JsonValue]) -> PendingOperation:
    authorization_evaluations = _decode_authorization_evaluations(record)
    admission_inputs = (
        authorization_evaluations[0].certified_inputs
        if authorization_evaluations
        and authorization_evaluations[0].phase is CertificationPhase.ADMISSION
        else {}
    )
    request = ActionRequest(
        operation_id=cast(str, record["operation_id"]),
        principal=Principal(
            id=cast(str, record["principal_id"]),
            attributes=cast(dict[str, Scalar], record["principal_attributes"]),
        ),
        action=cast(str, record["action"]),
        arguments=cast(dict[str, Scalar], record["arguments"]),
        idempotency_key=cast(str, record["idempotency_key"]),
        timestamp=datetime.fromisoformat(cast(str, record["timestamp"])),
        resource=cast(str | None, record.get("resource")),
        trace_id=cast(str | None, record.get("trace_id")),
        adapter_invocation_digest=cast(str | None, record.get("adapter_invocation_digest")),
        protected_artifacts=_decode_protected_artifacts(record),
        certified_inputs=admission_inputs,
    )
    result = _decode_result(record)
    mode = _decode_pending_mode(record.get("mode"))
    # A proof paired with a corrupt/non-reservation mode is not a proof. Clear
    # the coupled metadata before constructing the stricter model object; the
    # relational row decoder records an integrity error for an explicit forged
    # combination and lets resolution durably deny it.
    if (
        result.resolution_plan is PendingResolutionPlan.RESERVATION_PROOF
        and mode is not MasuGateMode.RESERVATION
    ):
        result = replace(
            result,
            resolution_plan=PendingResolutionPlan.REVALIDATE,
            reservation_safety_certificate_digest=None,
            reservation_entitlement_digest=None,
        )
    return PendingOperation(
        pending_id=cast(str, result.pending_id),
        request=request,
        decision=result.decision,
        mode=mode,
        reservation_id=result.reservation_id,
        resolution_plan=result.resolution_plan,
        reservation_safety_certificate_digest=(result.reservation_safety_certificate_digest),
        reservation_entitlement_digest=result.reservation_entitlement_digest,
        authorization_evaluations=authorization_evaluations,
    )


def _decode_pending_row(
    row: dict[str, Any],
    *,
    expected_state: str = "pending",
) -> PendingOperation:
    """Cross-check JSON identity against authoritative pending-row columns."""

    relational_pending_id = cast(str, row["pending_id"])
    relational_operation_id = cast(str, row["operation_id"])
    relational_principal_id = cast(str, row["principal_id"])
    relational_idempotency_key = cast(str, row["idempotency_key"])
    relational_reservation_id = cast(str | None, row["reservation_id"])
    try:
        record = _json_record(row["record_json"])
        decoded_result = _decode_result(record)
        pending = _decode_pending(record)
    except (AttributeError, IndexError, KeyError, OverflowError, TypeError, ValueError) as exc:
        return _invalid_pending_row(
            row,
            f"pending record cannot be decoded ({type(exc).__name__})",
        )

    errors: list[str] = []
    if row.get("pending_state") != expected_state:
        errors.append("pending lifecycle state disagrees with the expected durable state")
    relational_record_digest = row.get("record_digest")
    if _valid_sha256_digest(
        cast(JsonValue, relational_record_digest)
    ) is None or relational_record_digest != _governance_record_digest(record):
        errors.append("pending record disagrees with durable integrity binding")
    request_identity_error = False
    if pending.pending_id != relational_pending_id:
        errors.append("pending id disagrees with durable row")
    if pending.request.operation_id != relational_operation_id:
        errors.append("operation id disagrees with durable row")
        request_identity_error = True
    if pending.request.principal.id != relational_principal_id:
        errors.append("principal id disagrees with durable row")
        request_identity_error = True
    if pending.request.idempotency_key != relational_idempotency_key:
        errors.append("idempotency key disagrees with durable row")
        request_identity_error = True
    if pending.reservation_id != relational_reservation_id:
        errors.append("reservation id disagrees with durable row")
    raw_status = record.get("status")
    if raw_status is not None and decoded_result.status is not OperationStatus.PENDING:
        errors.append("pending lifecycle status disagrees with durable row")
    if decoded_result.committed is not False:
        errors.append("pending committed flag disagrees with durable row")
    if decoded_result.decision.effect is not DecisionEffect.ESCALATE:
        errors.append("pending decision effect disagrees with durable row")

    raw_plan = record.get("resolution_plan")
    if raw_plan is not None and raw_plan not in {plan.value for plan in PendingResolutionPlan}:
        errors.append("pending resolution plan is invalid")
    if (
        raw_plan == PendingResolutionPlan.RESERVATION_PROOF.value
        and pending.resolution_plan is not PendingResolutionPlan.RESERVATION_PROOF
    ):
        errors.append("reservation proof metadata is inconsistent")
    raw_mode = record.get("mode")
    if raw_mode is not None and raw_mode not in {mode.value for mode in MasuGateMode}:
        errors.append("pending mode is invalid")

    request_binding_error = False
    relational_request_digest = row.get("request_digest")
    if _valid_sha256_digest(relational_request_digest) is None:
        errors.append("pending request has no valid durable binding")
        request_binding_error = True
    elif relational_request_digest != _pending_request_digest(pending.request):
        errors.append("pending request disagrees with durable binding")
        request_binding_error = True
    if not errors:
        return pending
    if request_binding_error or request_identity_error:
        # The serialized action itself is no longer trustworthy. Do not carry it
        # into scope selection, cleanup, a terminal audit record, or an executor;
        # retain only the authoritative relational identity. In particular, do
        # not hash a hybrid request made from JSON fields plus conflicting row
        # identities: that could select another request's escrow entitlement.
        return _invalid_pending_row(row, "; ".join(errors))

    request = pending.request
    # The request digest authenticates the execution identity needed for exact
    # request-bound cleanup. No other JSON field is trusted after any envelope
    # error: a forged mode, decision, read set, or policy provenance must not be
    # copied into the fresh terminal record and thereby receive a valid digest.
    return PendingOperation(
        pending_id=relational_pending_id,
        request=request,
        decision=PolicyDecision(
            effect=DecisionEffect.DENY,
            policy_id="pending-record",
            rule_id="integrity_invalid",
            reason="durable pending record failed integrity validation",
        ),
        mode=MasuGateMode.TRANSACTION,
        reservation_id=relational_reservation_id,
        resolution_plan=PendingResolutionPlan.REVALIDATE,
        integrity_error="; ".join(errors),
        authorization_evaluations=pending.authorization_evaluations,
    )


def _invalid_pending_row(row: dict[str, Any], reason: str) -> PendingOperation:
    """Return a relationally identified sentinel for undecodable pending JSON.

    The sentinel can be locked and terminally denied by the coordinator, which
    also releases any scope holds by authoritative pending id. Its deliberately
    invalid action cannot select or release a reservation; unverifiable escrow
    is therefore left to exact-request recovery or TTL expiry rather than being
    followed by an untrusted identifier.
    """

    created_at = row.get("created_at")
    timestamp = (
        created_at if isinstance(created_at, datetime) else datetime.fromtimestamp(0, tz=UTC)
    )
    request = ActionRequest(
        operation_id=cast(str, row["operation_id"]),
        principal=Principal(id=cast(str, row["principal_id"])),
        action="__invalid_pending_record__",
        arguments={},
        idempotency_key=cast(str, row["idempotency_key"]),
        timestamp=timestamp,
    )
    return PendingOperation(
        pending_id=cast(str, row["pending_id"]),
        request=request,
        decision=PolicyDecision(
            effect=DecisionEffect.DENY,
            policy_id="pending-record",
            rule_id="decode_invalid",
            reason="durable pending record cannot be decoded",
        ),
        mode=MasuGateMode.TRANSACTION,
        reservation_id=(
            cast(str, row["reservation_id"]) if isinstance(row.get("reservation_id"), str) else None
        ),
        integrity_error=reason,
    )


def _decode_pending_replay_for_request(
    row: dict[str, Any],
    request: ActionRequest,
) -> OperationResult:
    """Decode a live pending replay from its authoritative relational envelope."""

    pending = _decode_pending_row(row)
    if pending.integrity_error is not None:
        raise ResourceError("pending operation failed durable integrity validation")
    record = _json_record(row["record_json"])
    result = _decode_replay_for_request(record, request)
    if (
        (record.get("status") is not None and result.status is not OperationStatus.PENDING)
        or result.committed is not False
        or result.decision.effect is not DecisionEffect.ESCALATE
        or result.pending_id != pending.pending_id
        or result.operation_id != pending.request.operation_id
    ):
        raise ResourceError("pending operation failed durable lifecycle validation")
    # Relational state is the lifecycle authority. Reconstruct the public result
    # from the already verified pending snapshot instead of returning JSON-owned
    # identifiers or proof metadata.
    return replace(
        result,
        operation_id=pending.request.operation_id,
        decision=pending.decision,
        committed=False,
        status=OperationStatus.PENDING,
        pending_id=pending.pending_id,
        reservation_id=pending.reservation_id,
        resolution_plan=pending.resolution_plan,
        reservation_safety_certificate_digest=(pending.reservation_safety_certificate_digest),
        reservation_entitlement_digest=pending.reservation_entitlement_digest,
    )


def _decode_governance_record_row(row: dict[str, Any]) -> dict[str, JsonValue]:
    """Return an audit record only when JSON agrees with authoritative identity."""

    record = _json_record(row["record_json"])
    record_digest = row.get("record_digest")
    if _valid_sha256_digest(
        cast(JsonValue, record_digest)
    ) is None or record_digest != _governance_record_digest(record):
        raise ResourceError("governance record failed durable integrity validation")
    if (
        record.get("operation_id") != row["operation_id"]
        or record.get("principal_id") != row["principal_id"]
        or record.get("idempotency_key") != row["idempotency_key"]
    ):
        raise ResourceError("governance record identity disagrees with durable row")
    if bool(row.get("is_pending")):
        pending = _decode_pending_row(row)
        if pending.integrity_error is not None:
            raise ResourceError("pending governance record failed durable integrity validation")
    else:
        _validate_terminal_result(_decode_result(record))
    return record


def _validate_terminal_result(result: OperationResult) -> None:
    """Reject lifecycle combinations that cannot be an enforced terminal result."""

    if result.committed:
        valid = (
            result.status is OperationStatus.COMMITTED
            and result.decision.effect is DecisionEffect.ALLOW
        )
    else:
        valid = (
            result.status is OperationStatus.DENIED
            and result.decision.effect is DecisionEffect.DENY
        )
    if not valid or result.pending_id is not None:
        raise ResourceError("terminal governance record has an invalid lifecycle")


def _decode_terminal_replay_for_request(
    row: dict[str, Any],
    request: ActionRequest,
) -> OperationResult:
    record = _decode_governance_record_row(row)
    result = _decode_replay_for_request(record, request)
    _validate_terminal_result(result)
    return result


def _decode_resolution_plan(raw: JsonValue) -> PendingResolutionPlan:
    if isinstance(raw, str):
        try:
            return PendingResolutionPlan(raw)
        except ValueError:
            pass
    return PendingResolutionPlan.REVALIDATE


def _valid_sha256_digest(raw: JsonValue) -> str | None:
    if (
        isinstance(raw, str)
        and len(raw) == 64
        and all(character in "0123456789abcdef" for character in raw)
    ):
        return raw
    return None


def _decode_resolution_metadata(
    record: dict[str, JsonValue],
) -> tuple[PendingResolutionPlan, str | None, str | None]:
    """Decode the plan/certificate/entitlement fields as one fail-closed unit."""

    raw_plan = record.get("resolution_plan")
    raw_certificate = record.get("reservation_safety_certificate_digest")
    raw_entitlement = record.get("reservation_entitlement_digest")
    if raw_plan is None and raw_certificate is None and raw_entitlement is None:
        return PendingResolutionPlan.REVALIDATE, None, None
    plan = _decode_resolution_plan(raw_plan)
    if plan is PendingResolutionPlan.RESERVATION_PROOF:
        certificate = _valid_sha256_digest(raw_certificate)
        entitlement = _valid_sha256_digest(raw_entitlement)
        if certificate is not None and entitlement is not None:
            return plan, certificate, entitlement
        return PendingResolutionPlan.REVALIDATE, None, None
    if raw_certificate is None and raw_entitlement is None:
        return plan, None, None
    return PendingResolutionPlan.REVALIDATE, None, None


def _decode_pending_mode(raw: JsonValue) -> MasuGateMode:
    if isinstance(raw, str):
        try:
            return MasuGateMode(raw)
        except ValueError:
            pass
    # Unknown/corrupt mode plus any reservation id is rejected by the
    # coordinator's raw-reservation proof check; transaction is the fail-safe
    # decode for non-reservation legacy rows.
    return MasuGateMode.TRANSACTION


class AsyncPostgresLedger:
    """Async resource owner backed by PostgreSQL + transaction advisory locks.

    Construct, then ``await open()`` once (idempotent); ``await close()`` on
    shutdown. Sessions are ``async with ledger.open_session(write=...) as s:``.
    """

    def __init__(
        self,
        dsn: str,
        *,
        min_size: int = 1,
        max_size: int = 10,
    ) -> None:
        self.dsn = dsn
        # Per-task actual SQL statement count for the 0.17 hardware-independent
        # regression gate. Context-local accounting keeps concurrent benchmark
        # clients from contaminating one another.
        self._query_count: ContextVar[int] = ContextVar("masugate_pg_query_count", default=0)
        # open=False: do not connect in __init__ (deprecated in psycopg_pool and
        # bad for an async ctor). open() below performs the first connection.
        self._pool = AsyncConnectionPool(
            dsn,
            min_size=min_size,
            max_size=max_size,
            kwargs={"row_factory": dict_row, "autocommit": True},
            open=False,
        )
        self._opened = False

    # -- lifecycle ---------------------------------------------------------- #

    async def open(self, *, initialize: bool = True) -> None:
        if self._opened:
            return
        await self._pool.open(wait=True)
        self._opened = True
        if initialize:
            await self._initialize()

    async def close(self) -> None:
        if not self._opened:
            return
        await self._pool.close()
        self._opened = False

    async def __aenter__(self) -> AsyncPostgresLedger:
        await self.open()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    def pool_stats(self) -> dict[str, int]:
        """Live pool stats (used by the 0.11 pool-reuse assertion)."""
        return dict(self._pool.get_stats())

    def reset_query_count(self) -> None:
        """Start an actual-SQL count for the current async client context."""

        self._query_count.set(0)

    def query_count(self) -> int:
        """Actual provider SQL statements since ``reset_query_count``."""

        return self._query_count.get()

    def _count_query(self) -> None:
        self._query_count.set(self._query_count.get() + 1)

    # -- contracts (0.12) ---------------------------------------------------- #

    def install_contracts(self, registry: ContractRegistry) -> None:
        """Register this ledger's governance views + transfer effect.

        Mirrors the frozen ``install_contracts`` (same names/types/scopes) with
        async resolvers (legal since the 0.12 ViewResolver widening) and the
        0.5 ``consumable_arg`` declared on the effect instead of hardcoded.
        """
        registry.register_view(
            GovernanceViewContract(
                name="accounts.balance",
                argument_types=(TypeName.STRING,),
                return_type=TypeName.INT,
                owner="ledger-service",
                consistency="scoped-transaction",
                max_latency_ms=1000,
                bounded=True,
                scope_resolver=lambda args: f"account:{args[0]}",
                resolver=self._balance_resolver,
                reservation_kind=ReservationViewKind.COMMIT_GUARDED,
                provider_identity=LEDGER_PROVIDER_IDENTITY,
            )
        )
        registry.register_view(
            GovernanceViewContract(
                name="ledger.sum_sent_by_team",
                argument_types=(TypeName.STRING, TypeName.DURATION),
                return_type=TypeName.INT,
                owner="ledger-service",
                consistency="scoped-policy-state",
                max_latency_ms=1000,
                bounded=True,
                scope_resolver=lambda args: f"team-budget:{args[0]}",
                resolver=self._team_spend_resolver,
                reservation_kind=ReservationViewKind.CONSUMED_CAPACITY,
                reservation_proof=LEDGER_RESERVATION_PROOF,
                reservation_literal_constraints={1: TEAM_BUDGET_WINDOW},
                provider_identity=LEDGER_PROVIDER_IDENTITY,
            )
        )
        registry.register_view(
            GovernanceViewContract(
                name="ledger.available_team_budget",
                argument_types=(TypeName.STRING, TypeName.DURATION),
                return_type=TypeName.INT,
                owner="ledger-service",
                consistency="scoped-policy-state",
                max_latency_ms=1000,
                bounded=True,
                scope_resolver=lambda args: f"team-budget:{args[0]}",
                resolver=self._available_budget_resolver,
                reservation_kind=ReservationViewKind.AVAILABLE_CAPACITY,
                reservation_proof=LEDGER_RESERVATION_PROOF,
                reservation_literal_constraints={1: TEAM_BUDGET_WINDOW},
                provider_identity=LEDGER_PROVIDER_IDENTITY,
            )
        )
        registry.register_effect(
            EffectContract(
                action="transfer",
                argument_types={
                    "receiver_id": TypeName.STRING,
                    "amount_cents": TypeName.INT,
                },
                owner="ledger-service",
                required_guarantee=ConsistencyGuarantee.POLICY_STATE_SERIALIZABLE,
                footprint_resolver=self.transfer_footprint,
                executor=self.execute_transfer,
                consumable_arg="amount_cents",
                reservation_proof=LEDGER_RESERVATION_PROOF,
                reservation_effect_implementation=LEDGER_EFFECT_IMPLEMENTATION,
                provider_identity=LEDGER_PROVIDER_IDENTITY,
            )
        )

    def provider_module(
        self,
        *,
        domain: CoordinationDomain | None = None,
    ) -> ProviderModule:
        """Expose this provider through the fail-closed deployment-assembly surface."""

        coordination_domain = domain or CoordinationDomain(
            domain_id=LEDGER_COORDINATION_DOMAIN_ID,
            configuration_id=LEDGER_RESERVATION_CONFIG_VERSION,
            scope_derivation_id=LEDGER_SCOPE_DERIVATION_ID,
            resource=self,
        )
        if coordination_domain.resource is not self:
            raise ResourceError("ledger provider module received a foreign domain resource")
        registry = ContractRegistry()
        self.install_contracts(registry)
        return ProviderModule(
            module_id="ledger-service",
            identity=LEDGER_PROVIDER_IDENTITY,
            domain=coordination_domain,
            scope_derivation_id=LEDGER_SCOPE_DERIVATION_ID,
            views=registry.views(),
            effects=tuple(
                EffectBinding(
                    contract=contract,
                    position=EffectExecutionPosition.TRANSACTIONAL,
                )
                for contract in registry.effects()
            ),
        )

    # Contract-shaped resolver adapters: (session, arguments, scope) -> value+version.
    async def _balance_resolver(
        self,
        session: ResourceSession,
        arguments: tuple[Scalar | Duration, ...],
        scope: str,
    ) -> tuple[Scalar, int]:
        return await self.balance_view(session, cast(str, arguments[0]))

    async def _team_spend_resolver(
        self,
        session: ResourceSession,
        arguments: tuple[Scalar | Duration, ...],
        scope: str,
    ) -> tuple[Scalar, int]:
        return await self.team_spend_view(
            session, cast(str, arguments[0]), cast(Duration, arguments[1])
        )

    async def _available_budget_resolver(
        self,
        session: ResourceSession,
        arguments: tuple[Scalar | Duration, ...],
        scope: str,
    ) -> tuple[Scalar, int]:
        return await self.available_team_budget_view(
            session, cast(str, arguments[0]), cast(Duration, arguments[1])
        )

    # -- sessions ----------------------------------------------------------- #

    @asynccontextmanager
    async def _session(self, *, write: bool) -> AsyncIterator[PostgresSession]:
        # READ COMMITTED for both read and write (see module docstring item 4).
        # The connection is autocommit; the `transaction()` block is the unit of
        # atomicity, and advisory xact locks live for its duration.
        async with self._pool.connection() as conn:
            # The pool applies dict_row via kwargs at runtime, but that row-factory
            # choice isn't visible in the pool's static connection type, so mypy
            # sees AsyncConnection[tuple[...]]. Narrow to the dict-row type we
            # actually get. (psycopg has no typed "pool with row_factory" ctor.)
            dict_conn = cast("AsyncConnection[dict[str, Any]]", conn)
            try:
                # These configure psycopg's generated BEGIN statement without
                # issuing a standalone SET round trip. Read sessions therefore
                # remain DB-enforced READ ONLY (view purity is load-bearing).
                await dict_conn.set_isolation_level(IsolationLevel.READ_COMMITTED)
                await dict_conn.set_read_only(not write)
                async with dict_conn.transaction():
                    yield PostgresSession(dict_conn, on_query=self._count_query)
            except BaseException as exc:
                # transaction() already rolled back; classify for the coordinator.
                if _is_retryable(exc):
                    raise RetryableResourceError("retryable transaction failure") from exc
                raise

    def open_session(self, *, write: bool) -> Any:
        return self._session(write=write)

    def open_uncoordinated_session(self, *, write: bool) -> Any:
        # No isolation distinction in the shipping design; identical to a
        # coordinated session (the frozen ledger also aliased these).
        return self._session(write=write)

    # -- locks -------------------------------------------------------------- #

    async def acquire_scoped_locks(
        self,
        session: ResourceSession,
        scopes: frozenset[str],
    ) -> float | None:
        if not scopes:
            return None
        pg = _as_session(session)
        keys = sorted(_lock_key(s) for s in scopes)
        try:
            identities = tuple(
                identity
                for scope in scopes
                if (identity := decode_idempotency_scope(scope)) is not None
            )
        except ValueError as exc:
            raise ResourceError("coordinator supplied a malformed idempotency scope") from exc
        if len(identities) > 1:
            raise ResourceError("coordinator supplied multiple idempotency scopes")
        identity = identities[0] if identities else None
        principal_id, idempotency_key = identity or (None, None)
        # Tier-1 admission in ONE actual SQL round trip: acquire every scope in
        # deterministic order, stamp time *after* the lock barrier, and fetch a
        # terminal or still-pending idempotency record. The coordinator's later
        # certify/load calls read this session cache. MATERIALIZED + the count
        # dependency prevents PostgreSQL from pruning or reordering the locks.
        row = await (
            await pg.execute(
                """
                WITH locked AS MATERIALIZED (
                    SELECT pg_advisory_xact_lock(k) AS acquired
                    FROM unnest(%s::bigint[]) AS k
                    ORDER BY k
                ),
                lock_barrier AS MATERIALIZED (
                    SELECT count(*) AS lock_count FROM locked
                ),
                existing AS (
                    SELECT operation_id, principal_id, idempotency_key,
                           NULL::text AS pending_id,
                           NULL::text AS reservation_id,
                           NULL::text AS request_digest,
                           NULL::text AS pending_state,
                           record_digest, created_at, record_json,
                           FALSE AS is_pending, 0 AS precedence
                    FROM operations
                    WHERE principal_id = %s AND idempotency_key = %s
                    UNION ALL
                    SELECT operation_id, principal_id, idempotency_key,
                           pending_id, reservation_id, request_digest,
                           state AS pending_state,
                           record_digest, created_at, record_json,
                           TRUE AS is_pending, 1 AS precedence
                    FROM pending_operations
                    WHERE principal_id = %s AND idempotency_key = %s
                )
                SELECT clock_timestamp() AS certified,
                       cached.operation_id,
                       cached.principal_id,
                       cached.idempotency_key,
                       cached.pending_id,
                       cached.reservation_id,
                       cached.request_digest,
                       cached.pending_state,
                       cached.record_digest,
                       cached.created_at,
                       cached.record_json,
                       cached.is_pending,
                       lock_barrier.lock_count
                FROM lock_barrier
                LEFT JOIN LATERAL (
                    SELECT operation_id, principal_id, idempotency_key,
                           pending_id, reservation_id, request_digest,
                           pending_state,
                           record_digest, created_at, record_json, is_pending
                    FROM existing ORDER BY precedence LIMIT 1
                ) AS cached ON TRUE
                """,
                (keys, principal_id, idempotency_key, principal_id, idempotency_key),
            )
        ).fetchone()
        if row is None:  # pragma: no cover - lock_barrier always yields one row
            raise ResourceError("failed to acquire and certify admission")
        pg.certified_now = cast(datetime, row["certified"])
        pg.cached_idempotency_identity = identity
        pg.cached_record = None
        pg.cached_result_is_pending = False
        pg.cached_durable_row = None
        if row["record_json"] is not None:
            pg.cached_record = _json_record(row["record_json"])
            pg.cached_result_is_pending = bool(row["is_pending"])
            pg.cached_durable_row = {
                "operation_id": row["operation_id"],
                "principal_id": row["principal_id"],
                "idempotency_key": row["idempotency_key"],
                "pending_id": row["pending_id"],
                "reservation_id": row["reservation_id"],
                "request_digest": row["request_digest"],
                "pending_state": row["pending_state"],
                "record_digest": row["record_digest"],
                "created_at": row["created_at"],
                "record_json": row["record_json"],
            }
        return None

    # -- admission certification (0.12) ------------------------------------- #

    async def certify_admission(self, session: ResourceSession) -> datetime:
        """Stamp the server-certified admission timestamp for this operation.

        Called by the coordinator AFTER scope locks are acquired, so certified
        times are monotone with the serialization order on each scope.
        ``clock_timestamp()`` (not ``now()``): the transaction began before the
        lock wait, and the tx-start time would predate the previous holder's
        commit. The result is stored on the session and anchors every window
        comparison and effect timestamp of this operation.
        """
        pg = _as_session(session)
        if pg.certified_now is not None:
            return pg.certified_now
        row = await (await pg.execute("SELECT clock_timestamp() AS certified")).fetchone()
        if row is None:  # pragma: no cover - SELECT of a literal always returns
            raise ResourceError("failed to read certified admission time")
        certified = cast(datetime, row["certified"])
        pg.certified_now = certified
        return certified

    async def certify_authorization_evaluation(
        self,
        session: ResourceSession,
    ) -> datetime:
        """Read the server clock for one protected evaluation event.

        Unlike ``certify_admission``, this value is never cached: source
        resolution and policy reads may take time, and the recorded evaluation
        point must be the actual event after that work, not the transaction or
        admission timestamp.
        """

        pg = _as_session(session)
        row = await (await pg.execute("SELECT clock_timestamp() AS evaluated_at")).fetchone()
        if row is None:  # pragma: no cover - SELECT of a literal always returns
            raise ResourceError("failed to read authorization evaluation time")
        return cast(datetime, row["evaluated_at"])

    # -- views (merged value + version) ------------------------------------ #

    async def balance_view(self, session: ResourceSession, account_id: str) -> tuple[Scalar, int]:
        pg = _as_session(session)
        scope = f"account:{account_id}"
        row = await (
            await pg.execute(
                """
                SELECT a.balance_cents AS value, v.version AS version
                FROM accounts AS a
                JOIN scope_versions AS v ON v.scope = %s
                WHERE a.account_id = %s
                """,
                (scope, account_id),
            )
        ).fetchone()
        if row is None:
            raise ResourceError(f"unknown account or missing scope version: {account_id}")
        return int(row["value"]), int(row["version"])

    async def team_spend_view(
        self, session: ResourceSession, team: str, window: Duration
    ) -> tuple[Scalar, int]:
        pg = _as_session(session)
        scope = f"team-budget:{team}"
        # Window anchored at the certified admission time (0.12) — the same
        # anchor as the effect timestamp — falling back to the DB's now() when
        # uncertified. The frozen ledger anchored at the CLIENT clock
        # (datetime.now in Python), so view and effect could disagree about
        # "the last 24h"; the client clock never anchors anything here.
        row = await (
            await pg.execute(
                """
                SELECT
                    COALESCE(
                        (SELECT SUM(amount_cents) FROM team_spend_events
                         WHERE team = %s
                           AND created_at >= COALESCE(%s, now())
                                             - make_interval(secs => %s)),
                        0
                    )::bigint AS value,
                    (SELECT version FROM scope_versions WHERE scope = %s) AS version
                """,
                (team, pg.certified_now, window.seconds, scope),
            )
        ).fetchone()
        if row is None or row["version"] is None:
            raise ResourceError(f"missing versioned governance scope: {scope}")
        return int(row["value"]), int(row["version"])

    async def available_team_budget_view(
        self, session: ResourceSession, team: str, window: Duration
    ) -> tuple[Scalar, int]:
        # O(1) read of the incremental escrow row (0.13), replacing the frozen
        # sum-of-spend + sum-of-held scan. The version is still the scope's,
        # so a committed reservation (which bumps the version) shows up as a
        # read-version conflict to the PSS checker exactly as before.
        #
        # This is a READ path — it must not write. The escrow row is created on
        # a write path (create_account / reserve). If it is somehow absent, fall
        # back to the windowed computation rather than INSERT here (which would
        # fail in a read-only session).
        pg = _as_session(session)
        if window != TEAM_BUDGET_WINDOW:
            # The incremental escrow row implements exactly the configured 24h
            # reservation window.  Other windows remain valid for transaction
            # and revalidation policies, but must use their actual windowed
            # committed spend rather than borrowing the 24h counters.
            spent, version = await self.team_spend_view(pg, team, window)
            return TEAM_BUDGET_LIMIT_CENTS - int(spent), version
        scope = f"team-budget:{team}"
        row = await (
            await pg.execute(
                """
                SELECT (e.limit_cents - e.committed_cents - e.held_cents) AS available,
                       (SELECT version FROM scope_versions WHERE scope = %s) AS version
                FROM escrow AS e
                WHERE e.scope = %s
                """,
                (scope, scope),
            )
        ).fetchone()
        if row is not None and row["version"] is not None:
            return int(row["available"]), int(row["version"])
        # Fallback (no escrow row yet): windowed spend, no holds.
        spent, version = await self.team_spend_view(pg, team, window)
        return TEAM_BUDGET_LIMIT_CENTS - int(spent), version

    # -- reservations (incremental escrow, 0.13) --------------------------- #

    def reservation_capability(self, action: str) -> ReservationCapability | None:
        if action != "transfer":
            return None
        return ReservationCapability(
            action="transfer",
            reservation_proof=LEDGER_RESERVATION_PROOF,
            implementation_version="async-postgres-ledger-reservation-v2",
            configuration_version=LEDGER_RESERVATION_CONFIG_VERSION,
            scope_scheme="team-budget:{principal.team}",
            consumable_arg="amount_cents",
            effect_implementation_version=LEDGER_EFFECT_IMPLEMENTATION,
            effect_executor=self.execute_transfer,
            effect_atomic_with_reservation=True,
            effect_idempotent=True,
        )

    def reservation_scopes(self, request: ActionRequest) -> frozenset[str]:
        if request.action != "transfer":
            return frozenset()
        return frozenset({f"team-budget:{self._principal_team(request)}"})

    async def reserve_for_request(
        self, session: ResourceSession, request: ActionRequest
    ) -> str | None:
        """Reserve capacity via a single atomic conditional UPDATE on the escrow.

        The `WHERE limit - committed - held >= amt` clause + the row-level lock
        the UPDATE takes make the check-and-hold **one atomic step** — no
        read-then-write window, so concurrent reservers on one scope serialize
        on the row and the second sees the first's held increment. This is
        strictly stronger than the 0.11 advisory-lock-then-read approach (the
        0.13 teeth-check proves a non-atomic read-then-update over-reserves).
        Returns the reservation id on success, None if capacity is unavailable.
        """
        pg = _as_session(session)
        team = self._principal_team(request)
        scope = f"team-budget:{team}"
        request_digest = _reservation_request_digest(request)
        await self._ensure_escrow(pg, scope, team, TEAM_BUDGET_WINDOW)
        await self._expire_reservations(pg)

        existing = await (
            await pg.execute(
                "SELECT reservation_id, state, request_digest FROM reservations "
                "WHERE principal_id = %s AND idempotency_key = %s",
                (request.principal.id, request.idempotency_key),
            )
        ).fetchone()
        if existing is not None:
            return (
                cast(str, existing["reservation_id"])
                if existing["state"] == "held" and existing["request_digest"] == request_digest
                else None
            )

        amount_cents = cast(int, request.arguments["amount_cents"])
        if amount_cents <= 0:
            return None

        held_row = await (
            await pg.execute(
                """
                UPDATE escrow SET held_cents = held_cents + %s
                WHERE scope = %s AND limit_cents - committed_cents - held_cents >= %s
                RETURNING held_cents
                """,
                (amount_cents, scope, amount_cents),
            )
        ).fetchone()
        if held_row is None:
            return None  # capacity unavailable — the conditional UPDATE matched no row

        reservation_id = request.operation_id
        now = pg.certified_now or datetime.now(UTC)
        await pg.execute(
            """
            INSERT INTO reservations(
                reservation_id, principal_id, idempotency_key, scope, amount_cents,
                request_digest, state, expires_at, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, 'held', %s, %s)
            """,
            (
                reservation_id,
                request.principal.id,
                request.idempotency_key,
                scope,
                amount_cents,
                request_digest,
                now + RESERVATION_TTL,
                now,
            ),
        )
        await self._bump_version(pg, scope)
        return reservation_id

    async def validate_reservation(
        self,
        session: ResourceSession,
        reservation_id: str,
        request: ActionRequest,
    ) -> bool:
        """Verify that a held entitlement belongs to this exact request."""

        if request.action != "transfer" or reservation_id != request.operation_id:
            return False
        pg = _as_session(session)
        # Expire and release stale reservations/entitlements before checking identity.
        # This keeps the escrow aggregate coherent even when validation, rather
        # than a new reservation or consume, is the first operation after TTL.
        await self._expire_reservations(pg)
        try:
            request_digest = _reservation_request_digest(request)
            expected_scopes = self.reservation_scopes(request)
        except (AttributeError, ResourceError, TypeError, ValueError):
            # Malformed persisted request identity is not an entitlement. Do
            # not turn corruption into a provider error or follow an untrusted
            # reservation id; retryable database failures remain uncaught.
            return False
        row = await (
            await pg.execute(
                "SELECT principal_id, idempotency_key, scope, amount_cents, request_digest "
                "FROM reservations "
                "WHERE reservation_id = %s AND state = 'held' AND expires_at > %s",
                (reservation_id, pg.certified_now or datetime.now(UTC)),
            )
        ).fetchone()
        if row is None:
            return False
        return (
            row["principal_id"] == request.principal.id
            and row["idempotency_key"] == request.idempotency_key
            and row["scope"] in expected_scopes
            and row["amount_cents"] == request.arguments.get("amount_cents")
            and row["request_digest"] == request_digest
        )

    async def consume_reservation(self, session: ResourceSession, reservation_id: str) -> None:
        """Move held→committed on the escrow, at most once.

        The state transition `held→consumed` (rowcount == 1) is the at-most-once
        guard: a second consume finds no `held` row and raises, so the escrow
        counters move exactly once.
        """
        pg = _as_session(session)
        # Expiry is checked in the same transaction before the held→consumed
        # transition. The coordinator consumes before invoking the effect, so
        # an expired entitlement cannot expose an effect and fail afterward.
        await self._expire_reservations(pg)
        updated = await pg.execute(
            """
            UPDATE reservations SET state = 'consumed', consumed_at = %s
            WHERE reservation_id = %s AND state = 'held'
            RETURNING scope, amount_cents
            """,
            (pg.certified_now or datetime.now(UTC), reservation_id),
        )
        row = await updated.fetchone()
        if row is None:
            raise ResourceError(f"reservation is not held: {reservation_id}")
        pg.consumed_reservation_ids.add(reservation_id)
        await pg.execute(
            """
            UPDATE escrow SET held_cents = held_cents - %s, committed_cents = committed_cents + %s
            WHERE scope = %s
            """,
            (row["amount_cents"], row["amount_cents"], row["scope"]),
        )
        await self._bump_version(pg, cast(str, row["scope"]))

    async def release_reservation(self, session: ResourceSession, reservation_id: str) -> None:
        """Return held capacity to the escrow, at most once (held→released)."""
        pg = _as_session(session)
        updated = await pg.execute(
            """
            UPDATE reservations SET state = 'released', released_at = %s
            WHERE reservation_id = %s AND state = 'held'
            RETURNING scope, amount_cents
            """,
            (pg.certified_now or datetime.now(UTC), reservation_id),
        )
        row = await updated.fetchone()
        if row is None:
            # Unknown, or already terminal (consumed/released/expired) — a
            # release of a non-held reservation is a no-op (idempotent cancel).
            return
        await pg.execute(
            "UPDATE escrow SET held_cents = held_cents - %s WHERE scope = %s",
            (row["amount_cents"], row["scope"]),
        )
        await self._bump_version(pg, cast(str, row["scope"]))

    async def release_reservation_for_request(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> str | None:
        """Release only the held entitlement bound to ``request``.

        Pending metadata is not allowed to select an arbitrary reservation for
        cleanup.  This request-bound lookup recovers the original entitlement
        when a persisted ``reservation_id`` is malformed or cross-linked, while
        returning ``None`` for a changed request or unverifiable legacy row.
        """

        if request.action != "transfer":
            return None
        pg = _as_session(session)
        await self._expire_reservations(pg)
        try:
            scopes = self.reservation_scopes(request)
            request_digest = _reservation_request_digest(request)
        except (AttributeError, ResourceError, TypeError, ValueError):
            return None
        if len(scopes) != 1:
            return None
        scope = next(iter(scopes))
        row = await (
            await pg.execute(
                "SELECT reservation_id FROM reservations "
                "WHERE reservation_id = %s AND principal_id = %s "
                "AND idempotency_key = %s AND scope = %s "
                "AND request_digest = %s AND state = 'held' "
                "FOR UPDATE",
                (
                    request.operation_id,
                    request.principal.id,
                    request.idempotency_key,
                    scope,
                    request_digest,
                ),
            )
        ).fetchone()
        if row is None:
            return None
        reservation_id = cast(str, row["reservation_id"])
        await self.release_reservation(pg, reservation_id)
        return reservation_id

    # -- durable results (idempotency) -------------------------------------- #

    async def load_result(
        self, session: ResourceSession, request: ActionRequest
    ) -> OperationResult | None:
        pg = _as_session(session)
        identity = (request.principal.id, request.idempotency_key)
        if pg.cached_idempotency_identity == identity:
            if pg.cached_result_is_pending or pg.cached_durable_row is None:
                return None
            return _decode_terminal_replay_for_request(pg.cached_durable_row, request)
        row = await (
            await pg.execute(
                "SELECT operation_id, principal_id, idempotency_key, "
                "record_digest, record_json, FALSE AS is_pending "
                "FROM operations "
                "WHERE principal_id = %s AND idempotency_key = %s",
                identity,
            )
        ).fetchone()
        if row is None:
            return None
        return _decode_terminal_replay_for_request(row, request)

    async def record_result(
        self,
        session: ResourceSession,
        request: ActionRequest,
        result: OperationResult,
        mode: MasuGateMode,
    ) -> None:
        pg = _as_session(session)
        recorded_at = _recorded_at(pg, result)
        record = _encode_record(request, result, mode, recorded_at)
        await pg.execute(
            "INSERT INTO operations("
            "operation_id, principal_id, idempotency_key, record_digest, "
            "created_at, record_json"
            ") VALUES (%s, %s, %s, %s, %s, %s)",
            (
                request.operation_id,
                request.principal.id,
                request.idempotency_key,
                _governance_record_digest(record),
                recorded_at,
                json.dumps(record, sort_keys=True),
            ),
        )

    async def load_governance_record(
        self,
        session: ResourceSession,
        operation_id: str,
    ) -> dict[str, JsonValue] | None:
        """Load the durable audit record for a server-assigned operation id.

        Terminal records take precedence over the original pending snapshot.
        Looking in both tables means the audit endpoint can render a receipt
        while approval is outstanding and naturally switches to the terminal
        receipt once resolution commits.
        """
        pg = _as_session(session)
        row = await (
            await pg.execute(
                """
                SELECT operation_id, principal_id, idempotency_key,
                       pending_id, reservation_id, request_digest,
                       pending_state,
                       record_digest, created_at, record_json, is_pending
                FROM (
                    SELECT operation_id, principal_id, idempotency_key,
                           NULL::text AS pending_id,
                           NULL::text AS reservation_id,
                           NULL::text AS request_digest,
                           NULL::text AS pending_state,
                           record_digest, created_at, record_json,
                           FALSE AS is_pending, 0 AS precedence
                    FROM operations
                    WHERE operation_id = %s
                    UNION ALL
                    SELECT operation_id, principal_id, idempotency_key,
                           pending_id, reservation_id, request_digest,
                           state AS pending_state,
                           record_digest, created_at, record_json,
                           TRUE AS is_pending, 1 AS precedence
                    FROM pending_operations
                    WHERE operation_id = %s
                ) AS records
                ORDER BY precedence
                LIMIT 1
                """,
                (operation_id, operation_id),
            )
        ).fetchone()
        if row is None:
            return None
        return _decode_governance_record_row(row)

    # -- pending operations + scope holds (0.14) --------------------------- #

    async def record_pending_operation(
        self,
        session: ResourceSession,
        request: ActionRequest,
        result: OperationResult,
        mode: MasuGateMode,
    ) -> None:
        pg = _as_session(session)
        if result.pending_id is None:
            raise ResourceError("pending result is missing a pending id")
        recorded_at = _recorded_at(pg, result)
        record = _encode_record(request, result, mode, recorded_at)
        await pg.execute(
            """
            INSERT INTO pending_operations(
                pending_id, operation_id, principal_id, idempotency_key, reservation_id,
                request_digest, record_digest, state, created_at, record_json
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'pending', %s, %s)
            """,
            (
                result.pending_id,
                request.operation_id,
                request.principal.id,
                request.idempotency_key,
                result.reservation_id,
                _pending_request_digest(request),
                _governance_record_digest(record),
                recorded_at,
                json.dumps(record, sort_keys=True),
            ),
        )

    async def load_pending_operation(
        self, session: ResourceSession, pending_id: str
    ) -> PendingOperation | None:
        pg = _as_session(session)
        row = await (
            await pg.execute(
                "SELECT pending_id, operation_id, principal_id, idempotency_key, "
                "reservation_id, request_digest, record_digest, "
                "state AS pending_state, created_at, record_json "
                "FROM pending_operations "
                "WHERE pending_id = %s AND state = 'pending'",
                (pending_id,),
            )
        ).fetchone()
        if row is None:
            return None
        return _decode_pending_row(row)

    async def list_pending_operations(
        self,
        session: ResourceSession,
        *,
        principal_id: str | None = None,
    ) -> tuple[PendingOperation, ...]:
        """Return visible live pending operations in durable creation order."""
        pg = _as_session(session)
        owner_clause = "" if principal_id is None else "AND principal_id = %s"
        params: tuple[object, ...] = () if principal_id is None else (principal_id,)
        rows = await (
            await pg.execute(
                f"""
                SELECT pending_id, operation_id, principal_id, idempotency_key,
                       reservation_id, request_digest, record_digest,
                       state AS pending_state, created_at, record_json
                FROM pending_operations
                WHERE state = 'pending'
                  {owner_clause}
                ORDER BY created_at, pending_id
                """,
                params,
            )
        ).fetchall()
        return tuple(_decode_pending_row(row) for row in rows)

    async def load_pending_owner(
        self,
        session: ResourceSession,
        pending_id: str,
    ) -> str | None:
        """Load the certified owner for a pending id in any lifecycle state."""

        pg = _as_session(session)
        row = await (
            await pg.execute(
                "SELECT principal_id FROM pending_operations WHERE pending_id = %s",
                (pending_id,),
            )
        ).fetchone()
        return None if row is None else cast(str, row["principal_id"])

    async def load_pending_result(
        self, session: ResourceSession, request: ActionRequest
    ) -> OperationResult | None:
        # Idempotent replay of a still-pending op by idempotency key: returns the
        # recorded PENDING result so a duplicate submit returns the same pending
        # marker instead of creating a second pending op.
        pg = _as_session(session)
        identity = (request.principal.id, request.idempotency_key)
        if pg.cached_idempotency_identity == identity:
            if (
                not pg.cached_result_is_pending
                or pg.cached_record is None
                or pg.cached_durable_row is None
            ):
                return None
            return _decode_pending_replay_for_request(pg.cached_durable_row, request)
        row = await (
            await pg.execute(
                "SELECT pending_id, operation_id, principal_id, idempotency_key, "
                "reservation_id, request_digest, record_digest, "
                "state AS pending_state, created_at, record_json "
                "FROM pending_operations "
                "WHERE principal_id = %s AND idempotency_key = %s",
                identity,
            )
        ).fetchone()
        if row is None:
            return None
        return _decode_pending_replay_for_request(row, request)

    async def load_resolved_pending_result(
        self,
        session: ResourceSession,
        pending_id: str,
    ) -> OperationResult | None:
        """Load the terminal result for a resolved pending operation.

        ``pending_id`` is the public resolution id, while terminal records are
        keyed by idempotency key.  Joining through the durable pending row
        preserves the public protocol's replay semantics without assuming that
        those identifiers are interchangeable for another provider.
        """
        pg = _as_session(session)
        row = await (
            await pg.execute(
                """
                SELECT pending.pending_id,
                       pending.operation_id AS pending_operation_id,
                       pending.principal_id AS pending_principal_id,
                       pending.idempotency_key AS pending_idempotency_key,
                       pending.reservation_id AS pending_reservation_id,
                       pending.request_digest AS pending_request_digest,
                       pending.record_digest AS pending_record_digest,
                       pending.state AS pending_state,
                       pending.created_at AS pending_created_at,
                       pending.record_json AS pending_record_json,
                       terminal.operation_id AS terminal_operation_id,
                       terminal.principal_id AS terminal_principal_id,
                       terminal.idempotency_key AS terminal_idempotency_key,
                       terminal.record_digest AS terminal_record_digest,
                       terminal.record_json AS terminal_record_json
                FROM pending_operations AS pending
                JOIN operations AS terminal
                  ON terminal.operation_id = pending.operation_id
                 AND terminal.principal_id = pending.principal_id
                 AND terminal.idempotency_key = pending.idempotency_key
                WHERE pending.pending_id = %s
                  AND pending.state = 'resolved'
                """,
                (pending_id,),
            )
        ).fetchone()
        if row is None:
            return None
        pending = _decode_pending_row(
            {
                "pending_id": row["pending_id"],
                "operation_id": row["pending_operation_id"],
                "principal_id": row["pending_principal_id"],
                "idempotency_key": row["pending_idempotency_key"],
                "reservation_id": row["pending_reservation_id"],
                "request_digest": row["pending_request_digest"],
                "record_digest": row["pending_record_digest"],
                "pending_state": row["pending_state"],
                "created_at": row["pending_created_at"],
                "record_json": row["pending_record_json"],
            },
            expected_state="resolved",
        )
        if pending.integrity_error is not None:
            raise ResourceError("resolved pending operation failed durable integrity validation")
        record = _decode_governance_record_row(
            {
                "operation_id": row["terminal_operation_id"],
                "principal_id": row["terminal_principal_id"],
                "idempotency_key": row["terminal_idempotency_key"],
                "record_digest": row["terminal_record_digest"],
                "record_json": row["terminal_record_json"],
                "is_pending": False,
            }
        )
        result = _decode_result(record)
        _validate_terminal_result(result)
        if result.operation_id != pending.request.operation_id:
            raise ResourceError("resolved pending operation links a different terminal result")
        return result

    async def resolve_pending_operation(
        self,
        session: ResourceSession,
        pending_id: str,
        result: OperationResult,
        evidence: dict[str, JsonValue],
    ) -> None:
        pg = _as_session(session)
        updated = await pg.execute(
            """
            UPDATE pending_operations
            SET state = 'resolved', resolved_at = %s, resolution_json = %s
            WHERE pending_id = %s AND state = 'pending'
            """,
            (
                pg.certified_now or datetime.now(UTC),
                json.dumps({"result": _encode_result_only(result), "evidence": evidence}),
                pending_id,
            ),
        )
        if updated.rowcount != 1:
            raise ResourceError(f"pending operation is not resolvable: {pending_id}")

    async def create_scope_holds(
        self, session: ResourceSession, pending_id: str, scopes: frozenset[str]
    ) -> None:
        pg = _as_session(session)
        now = pg.certified_now or datetime.now(UTC)
        expires_at = now + RESERVATION_TTL
        for scope in sorted(scopes):
            await pg.execute(
                """
                INSERT INTO scope_holds(pending_id, scope, state, expires_at, created_at)
                VALUES (%s, %s, 'held', %s, %s)
                ON CONFLICT (pending_id, scope) DO UPDATE
                    SET state = 'held', expires_at = EXCLUDED.expires_at,
                        created_at = EXCLUDED.created_at, released_at = NULL
                    WHERE scope_holds.state <> 'held'
                """,
                (pending_id, scope, expires_at, now),
            )

    async def release_scope_holds(self, session: ResourceSession, pending_id: str) -> None:
        pg = _as_session(session)
        await pg.execute(
            "UPDATE scope_holds SET state = 'released', released_at = %s "
            "WHERE pending_id = %s AND state = 'held'",
            (pg.certified_now or datetime.now(UTC), pending_id),
        )

    async def has_active_scope_hold(
        self,
        session: ResourceSession,
        scopes: frozenset[str],
        *,
        owner_pending_id: str | None = None,
    ) -> bool:
        """True if any of ``scopes`` is held by a *different* pending op.

        Must be called INSIDE the advisory-locked transaction (0.14): the lock
        serializes competitors on the scope, and this read then observes any
        committed hold — closing the frozen check-before-lock TOCTOU.
        """
        if not scopes:
            return False
        pg = _as_session(session)
        params: list[object] = [list(scopes), pg.certified_now or datetime.now(UTC)]
        owner_clause = ""
        if owner_pending_id is not None:
            owner_clause = "AND pending_id <> %s"
            params.append(owner_pending_id)
        row = await (
            await pg.execute(
                f"""
                SELECT 1 FROM scope_holds
                WHERE scope = ANY(%s) AND state = 'held' AND expires_at > %s
                {owner_clause}
                LIMIT 1
                """,
                params,
            )
        ).fetchone()
        return row is not None

    # -- transfer effect ---------------------------------------------------- #

    def transfer_footprint(self, request: ActionRequest) -> ResourceFootprint:
        receiver_id = cast(str, request.arguments["receiver_id"])
        team = self._principal_team(request)
        scopes = frozenset(
            {f"account:{request.principal.id}", f"account:{receiver_id}", f"team-budget:{team}"}
        )
        return ResourceFootprint(reads=scopes, writes=scopes)

    async def execute_transfer(
        self, session: ResourceSession, request: ActionRequest
    ) -> dict[str, JsonValue]:
        pg = _as_session(session)
        sender_id = request.principal.id
        receiver_id = cast(str, request.arguments["receiver_id"])
        amount_cents = cast(int, request.arguments["amount_cents"])
        if amount_cents <= 0:
            raise ResourceError("transfer amount must be positive")
        if sender_id == receiver_id:
            raise ResourceError("sender and receiver must differ")
        trusted_team = self._principal_team(request)
        # Effect timestamps use the certified admission time when set (0.12) —
        # the same anchor the views read — so a caller-supplied (possibly
        # backdated) request.timestamp cannot move an effect out of the window.
        created_at = pg.certified_now or request.timestamp
        # Tier-1 effect in ONE actual SQL statement. The data-modifying CTE
        # couples validation, debit, credit, transfer/spend events, and all
        # version bumps; any missing precondition yields no row and the outer
        # transaction rolls back.  Keeping this as one provider call is what
        # makes the baseline hardening four-round-trip gate an actual SQL property,
        # rather than a count of logical helper calls.
        scopes = sorted(self.transfer_footprint(request).writes)
        budget_scope = f"team-budget:{trusted_team}"
        reservation_consumed = request.operation_id in pg.consumed_reservation_ids
        effect = await (
            await pg.execute(
                """
                WITH eligible AS MATERIALIZED (
                    SELECT sender.account_id AS sender_id,
                           sender.team,
                           receiver.account_id AS receiver_id
                    FROM accounts AS sender
                    JOIN accounts AS receiver ON receiver.account_id = %s
                    WHERE sender.account_id = %s
                      AND sender.team = %s
                      AND sender.balance_cents >= %s
                      AND (
                          %s
                          OR NOT EXISTS (SELECT 1 FROM escrow WHERE scope = %s)
                          OR EXISTS (
                              SELECT 1 FROM escrow
                              WHERE scope = %s
                                AND limit_cents - committed_cents - held_cents >= %s
                          )
                      )
                ),
                debit AS (
                    UPDATE accounts AS account
                    SET balance_cents = account.balance_cents - %s
                    FROM eligible
                    WHERE account.account_id = eligible.sender_id
                    RETURNING account.balance_cents AS sender_balance_cents,
                              eligible.sender_id, eligible.receiver_id, eligible.team
                ),
                credit AS (
                    UPDATE accounts AS account
                    SET balance_cents = account.balance_cents + %s
                    FROM debit
                    WHERE account.account_id = debit.receiver_id
                    RETURNING account.balance_cents AS receiver_balance_cents,
                              debit.sender_id, debit.receiver_id, debit.team
                ),
                created_transfer AS (
                    INSERT INTO transfers(
                        sender_id, receiver_id, amount_cents, created_at
                    )
                    SELECT sender_id, receiver_id, %s, %s FROM credit
                    RETURNING transfer_id
                ),
                spend AS (
                    INSERT INTO team_spend_events(
                        transfer_id, team, amount_cents, created_at
                    )
                    SELECT created_transfer.transfer_id, credit.team, %s, %s
                    FROM created_transfer CROSS JOIN credit
                    RETURNING transfer_id
                ),
                escrow_advanced AS (
                    UPDATE escrow
                    SET committed_cents = committed_cents + %s
                    FROM spend
                    WHERE scope = %s AND NOT %s
                    RETURNING scope
                ),
                bumped AS (
                    INSERT INTO scope_versions(scope, version)
                    SELECT scope, 1
                    FROM unnest(%s::text[]) AS scope CROSS JOIN spend
                    ON CONFLICT (scope) DO UPDATE
                    SET version = scope_versions.version + 1
                    RETURNING scope
                )
                SELECT debit.sender_balance_cents,
                       credit.receiver_balance_cents,
                       created_transfer.transfer_id,
                       (SELECT count(*) FROM bumped) AS bumped_count
                FROM debit CROSS JOIN credit CROSS JOIN created_transfer CROSS JOIN spend
                """,
                (
                    receiver_id,
                    sender_id,
                    trusted_team,
                    amount_cents,
                    reservation_consumed,
                    budget_scope,
                    budget_scope,
                    amount_cents,
                    amount_cents,
                    amount_cents,
                    amount_cents,
                    created_at,
                    amount_cents,
                    created_at,
                    amount_cents,
                    budget_scope,
                    reservation_consumed,
                    scopes,
                ),
            )
        ).fetchone()
        if effect is None:
            raise ResourceError(
                "transfer precondition failed (account, trusted team, balance, or escrow)"
            )
        return {
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "amount_cents": amount_cents,
            "sender_balance_cents": int(effect["sender_balance_cents"]),
            "receiver_balance_cents": int(effect["receiver_balance_cents"]),
        }

    # -- seed helpers (tests / bootstrap) ---------------------------------- #

    async def create_account(self, account_id: str, team: str, balance_cents: int) -> None:
        if balance_cents < 0:
            raise ValueError("opening balance cannot be negative")
        async with self._session(write=True) as session:
            await session.execute(
                "INSERT INTO accounts(account_id, team, balance_cents) VALUES (%s, %s, %s) "
                "ON CONFLICT (account_id) DO UPDATE SET team = EXCLUDED.team, "
                "balance_cents = EXCLUDED.balance_cents",
                (account_id, team, balance_cents),
            )
            for scope in (f"account:{account_id}", f"team-budget:{team}"):
                await self._ensure_version(session, scope)
            # NB: the escrow row is NOT created here — it is created lazily at the
            # first reserve (a write path that runs AFTER any seed spend), so its
            # committed_cents is initialized from the then-current windowed sum.
            # Creating it now would capture committed=0 before the seed transfer.

    async def balance(self, account_id: str) -> int:
        async with self._session(write=False) as session:
            account = await self._account(session, account_id)
            return int(account["balance_cents"])

    # -- internal helpers --------------------------------------------------- #

    async def _ensure_escrow(
        self, pg: PostgresSession, scope: str, team: str, window: Duration
    ) -> None:
        """Create the escrow row for a scope if absent (idempotent).

        ``committed_cents`` is seeded ONCE, at row creation, from the current
        windowed ``sum_sent_by_team`` — so pre-existing direct spend (e.g. the
        test seed, or a prior transaction-mode workload) is reflected in the
        reservation capacity. Thereafter it is maintained incrementally by
        consume/release. LIMITATION (documented, 0.13): the escrow is a
        per-accounting-period capacity counter — window *expiry* of the seeded
        spend is not reflected after creation; a production deployment resets or
        re-bases the escrow per window (the standard quota pattern). Once an
        escrow row exists, transaction-mode effects advance it too. Reservation
        consumption marks the session so the same effect is not counted twice,
        keeping mode changes and mixed action plans coherent.
        """
        exists = await (
            await pg.execute("SELECT 1 FROM escrow WHERE scope = %s", (scope,))
        ).fetchone()
        if exists is not None:
            return
        spent, _version = await self.team_spend_view(pg, team, window)
        await pg.execute(
            """
            INSERT INTO escrow(scope, limit_cents, committed_cents, held_cents)
            VALUES (%s, %s, %s, 0)
            ON CONFLICT (scope) DO NOTHING
            """,
            (scope, TEAM_BUDGET_LIMIT_CENTS, int(spent)),
        )

    async def _expire_reservations(self, pg: PostgresSession) -> None:
        now = pg.certified_now or datetime.now(UTC)
        rows = await (
            await pg.execute(
                "SELECT reservation_id, scope, amount_cents FROM reservations "
                "WHERE state = 'held' AND expires_at <= %s",
                (now,),
            )
        ).fetchall()
        for row in rows:
            expired = await pg.execute(
                "UPDATE reservations SET state = 'expired', released_at = %s "
                "WHERE reservation_id = %s AND state = 'held'",
                (now, row["reservation_id"]),
            )
            if expired.rowcount == 1:
                # Return the expired hold to the escrow (mirror of release).
                await pg.execute(
                    "UPDATE escrow SET held_cents = held_cents - %s WHERE scope = %s",
                    (row["amount_cents"], row["scope"]),
                )
                await self._bump_version(pg, cast(str, row["scope"]))

    async def _account(self, pg: PostgresSession, account_id: str) -> dict[str, Any]:
        row = await (
            await pg.execute(
                "SELECT account_id, team, balance_cents FROM accounts WHERE account_id = %s",
                (account_id,),
            )
        ).fetchone()
        if row is None:
            raise ResourceError(f"unknown account: {account_id}")
        return row

    def _principal_team(self, request: ActionRequest) -> str:
        team = request.principal.attributes.get("team")
        if not isinstance(team, str):
            raise ResourceError("principal is missing trusted String attribute 'team'")
        return team

    async def _ensure_version(self, session: PostgresSession, scope: str) -> None:
        await session.execute(
            "INSERT INTO scope_versions(scope, version) VALUES (%s, 0) "
            "ON CONFLICT (scope) DO NOTHING",
            (scope,),
        )

    async def _bump_version(self, pg: PostgresSession, scope: str) -> None:
        await pg.execute(
            "UPDATE scope_versions SET version = version + 1 WHERE scope = %s",
            (scope,),
        )

    async def _bump_versions(self, pg: PostgresSession, scopes: frozenset[str]) -> None:
        """Bump several scope versions in ONE round-trip (0.17 batching)."""
        if not scopes:
            return
        await pg.connection.execute(
            "UPDATE scope_versions SET version = version + 1 WHERE scope = ANY(%s)",
            (sorted(scopes),),
        )

    async def _migrate_principal_idempotency(
        self,
        conn: AsyncConnection[dict[str, Any]],
    ) -> None:
        """Migrate legacy globally-unique keys to principal-owned composite keys."""

        for table in ("operations", "pending_operations", "reservations"):
            await conn.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS principal_id TEXT")
        await conn.execute(
            "UPDATE operations SET principal_id = record_json ->> 'principal_id' "
            "WHERE principal_id IS NULL"
        )
        await conn.execute(
            "UPDATE pending_operations SET principal_id = record_json ->> 'principal_id' "
            "WHERE principal_id IS NULL"
        )
        await conn.execute(
            """
            UPDATE reservations AS reservation
            SET principal_id = COALESCE(
                (
                    SELECT operation.principal_id
                    FROM operations AS operation
                    WHERE operation.operation_id = reservation.reservation_id
                    LIMIT 1
                ),
                (
                    SELECT pending.principal_id
                    FROM pending_operations AS pending
                    WHERE pending.operation_id = reservation.reservation_id
                    LIMIT 1
                ),
                '__masugate_legacy_orphan__'
            )
            WHERE reservation.principal_id IS NULL
            """
        )
        for table in ("operations", "pending_operations", "reservations"):
            await conn.execute(f"ALTER TABLE {table} ALTER COLUMN principal_id SET NOT NULL")
            await conn.execute(
                f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {table}_idempotency_key_key"
            )
            await conn.execute(
                f"CREATE UNIQUE INDEX IF NOT EXISTS "
                f"idx_{table}_principal_idempotency "
                f"ON {table}(principal_id, idempotency_key)"
            )

    async def _migrate_governance_integrity_bindings(
        self,
        conn: AsyncConnection[dict[str, Any]],
    ) -> None:
        """Add integrity columns without blessing legacy serialized data.

        A trust anchor cannot safely be derived from the legacy JSON it is
        intended to authenticate: that would certify any pre-upgrade request or
        lifecycle corruption. Existing NULL rows remain explicitly
        unverifiable and fail closed on replay/audit/resolution. New writes
        always populate both bindings.
        """

        await conn.execute(
            "ALTER TABLE pending_operations ADD COLUMN IF NOT EXISTS request_digest TEXT"
        )
        await conn.execute(
            "ALTER TABLE pending_operations ADD COLUMN IF NOT EXISTS record_digest TEXT"
        )
        await conn.execute("ALTER TABLE operations ADD COLUMN IF NOT EXISTS record_digest TEXT")

    async def _initialize(self) -> None:
        # DDL matches the frozen schema (subset used by the async governed path:
        # accounts, transfers, team_spend_events, scope_versions, reservations).
        # Pending/scope-hold tables arrive with the pending path (0.13+).
        async with self._pool.connection() as conn:
            # Pool connections are autocommit for the hot path.  Schema setup is
            # explicitly transactional so the xact advisory lock covers every
            # migration statement across concurrent process startups.
            await conn.execute("BEGIN")
            await conn.execute(
                "SELECT pg_advisory_xact_lock(%s)", (_lock_key("masugate:schema:init"),)
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS accounts (
                    account_id TEXT PRIMARY KEY,
                    team TEXT NOT NULL,
                    balance_cents BIGINT NOT NULL CHECK(balance_cents >= 0)
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS transfers (
                    transfer_id BIGSERIAL PRIMARY KEY,
                    sender_id TEXT NOT NULL REFERENCES accounts(account_id),
                    receiver_id TEXT NOT NULL REFERENCES accounts(account_id),
                    amount_cents BIGINT NOT NULL CHECK(amount_cents > 0),
                    created_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS team_spend_events (
                    transfer_id BIGINT PRIMARY KEY REFERENCES transfers(transfer_id)
                        ON DELETE CASCADE,
                    team TEXT NOT NULL,
                    amount_cents BIGINT NOT NULL CHECK(amount_cents > 0),
                    created_at TIMESTAMPTZ NOT NULL
                )
                """
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_team_spend_events_team_created "
                "ON team_spend_events(team, created_at)"
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scope_versions (
                    scope TEXT PRIMARY KEY,
                    version BIGINT NOT NULL
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS operations (
                    operation_id TEXT PRIMARY KEY,
                    principal_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    record_digest TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    record_json JSONB NOT NULL
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS reservations (
                    reservation_id TEXT PRIMARY KEY,
                    principal_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    amount_cents BIGINT NOT NULL CHECK(amount_cents > 0),
                    request_digest TEXT,
                    state TEXT NOT NULL CHECK(state IN ('held','consumed','released','expired')),
                    expires_at TIMESTAMPTZ NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    consumed_at TIMESTAMPTZ,
                    released_at TIMESTAMPTZ
                )
                """
            )
            # Existing held rows predate exact request binding and therefore
            # remain intentionally unverifiable (NULL) until they expire.  New
            # reservations always persist the canonical digest above.
            await conn.execute(
                "ALTER TABLE reservations ADD COLUMN IF NOT EXISTS request_digest TEXT"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_reservations_scope_state "
                "ON reservations(scope, state)"
            )
            # Incremental escrow aggregate (0.13): one row per scope replaces the
            # O(window-rows) sum-of-held / sum-of-spend scan. held/committed are
            # running counters; capacity = limit - committed - held, checked and
            # advanced in a single atomic conditional UPDATE (no read-then-write
            # TOCTOU). The CHECKs are the escrow invariants enforced by the DB:
            # both counters non-negative and never jointly exceeding the limit.
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS escrow (
                    scope TEXT PRIMARY KEY,
                    limit_cents BIGINT NOT NULL CHECK(limit_cents >= 0),
                    committed_cents BIGINT NOT NULL DEFAULT 0 CHECK(committed_cents >= 0),
                    held_cents BIGINT NOT NULL DEFAULT 0 CHECK(held_cents >= 0),
                    CONSTRAINT escrow_within_limit
                        CHECK(committed_cents + held_cents <= limit_cents)
                )
                """
            )
            # Pending operations + scope holds (0.14, MASUGATE_SCOPED_HOLD). A pending
            # op escrows nothing on the budget itself; instead it places a *hold*
            # on the scopes it will touch, so a same-scope competitor is denied
            # while a human decides. Holds are created/checked INSIDE the
            # advisory-locked transaction (0.14 fixes the frozen check-before-lock
            # order); the async core has no coarse in-process lock to mask it.
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pending_operations (
                    pending_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL UNIQUE,
                    principal_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    reservation_id TEXT,
                    request_digest TEXT,
                    record_digest TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending', 'resolved')),
                    created_at TIMESTAMPTZ NOT NULL,
                    resolved_at TIMESTAMPTZ,
                    record_json JSONB NOT NULL,
                    resolution_json JSONB
                )
                """
            )
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scope_holds (
                    pending_id TEXT NOT NULL REFERENCES pending_operations(pending_id)
                        ON DELETE CASCADE,
                    scope TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('held', 'released', 'expired')),
                    expires_at TIMESTAMPTZ NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    released_at TIMESTAMPTZ,
                    PRIMARY KEY (pending_id, scope)
                )
                """
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scope_holds_scope_state "
                "ON scope_holds(scope, state)"
            )
            await self._migrate_principal_idempotency(cast("AsyncConnection[dict[str, Any]]", conn))
            await self._migrate_governance_integrity_bindings(
                cast("AsyncConnection[dict[str, Any]]", conn)
            )
            await conn.execute("COMMIT")
