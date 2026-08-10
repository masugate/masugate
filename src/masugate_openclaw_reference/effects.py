"""Durable reference connectors and provider-owned outbox for protected effects.

The connector intentionally implements a bounded reference sink: every
external action becomes one durable effect row with idempotent dispatch,
status-query, cancellation, fence, and evidence semantics.  It is suitable for
the SQLite and PostgreSQL conformance deployments without pretending to be a
real customer filesystem, messaging service, or Internet endpoint.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, cast

from masugate.contracts import ResourceSession
from masugate.errors import ContractError
from masugate.model import (
    ActionRequest,
    AuthorizationEvaluation,
    DecisionEffect,
    JsonValue,
    PendingResolutionPlan,
)
from masugate.protected_execution import (
    ConnectorCapabilities,
    ConnectorEvidence,
    ConnectorOutcome,
    ProtectedExecutionBinding,
    ProtectedExecutionRecord,
    ProtectedExecutionStatus,
    StaleFenceError,
)
from masugate.providers.operational_limits import (
    action_request_from_payload,
    action_request_payload,
    authorization_evaluation_from_payload,
    authorization_evaluation_payload,
)
from masugate.providers.spend import reference_purchase_binding_from_payload


class _SessionResource(Protocol):
    def open_session(self, *, write: bool) -> Any: ...


def _connection(session: ResourceSession) -> Any:
    connection = getattr(session, "connection", None)
    if connection is None or not callable(getattr(connection, "execute", None)):
        raise ContractError("reference effect lifecycle requires a durable SQL session")
    return connection


def _json(value: JsonValue) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("reference effect time must be timezone-aware")
    return value.isoformat()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class ReferenceEffectConnector:
    """Durable bounded sink implementing the complete protected connector API."""

    capabilities = ConnectorCapabilities(
        idempotent_dispatch=True,
        status_query=True,
        cancellation=True,
    )

    def __init__(self, resource: object, connector_id: str) -> None:
        if not connector_id or connector_id.strip() != connector_id:
            raise ValueError("reference effect connector id must be canonical")
        self._resource = cast(_SessionResource, resource)
        self.connector_id = connector_id

    async def initialize(self) -> None:
        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            execute_script = getattr(connection, "executescript", None)
            if not callable(execute_script):
                raise ContractError("reference effect connector cannot initialize SQL state")
            execute_script(
                """
                CREATE TABLE IF NOT EXISTS reference_connector_effects (
                    connector_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    binding_digest TEXT NOT NULL,
                    action TEXT NOT NULL,
                    external_operation_id TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    highest_fence BIGINT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(connector_id, idempotency_key),
                    CHECK(outcome IN ('succeeded', 'failed')),
                    CHECK(highest_fence > 0)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS reference_connector_effects_binding
                    ON reference_connector_effects(connector_id, binding_digest);
                CREATE UNIQUE INDEX IF NOT EXISTS reference_connector_effects_external_operation
                    ON reference_connector_effects(connector_id, external_operation_id);
                """
            )

    def _validate_call_identity(
        self,
        binding: ProtectedExecutionBinding,
        idempotency_key: str,
    ) -> None:
        if binding.connector_id != self.connector_id:
            raise ContractError("reference connector received a binding for another connector")
        if idempotency_key != binding.provider_idempotency_key:
            raise ContractError(
                "reference connector received an idempotency key outside its binding"
            )

    def _evidence(self, row: Mapping[str, object]) -> ConnectorEvidence:
        try:
            payload = json.loads(cast(str, row["evidence_json"]))
            if not isinstance(payload, dict):
                raise ValueError("evidence payload is not an object")
            return ConnectorEvidence(
                connector_id=cast(str, row["connector_id"]),
                evidence_id="refevidence:" + _digest(cast(str, row["binding_digest"])),
                idempotency_key=cast(str, row["idempotency_key"]),
                external_operation_id=cast(str, row["external_operation_id"]),
                outcome=ConnectorOutcome(cast(str, row["outcome"])),
                observed_at=datetime.fromisoformat(cast(str, row["updated_at"])),
                payload=cast(dict[str, JsonValue], payload),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ContractError("reference connector effect evidence is malformed") from exc

    def _validate_row(
        self,
        row: Mapping[str, object],
        binding: ProtectedExecutionBinding,
        idempotency_key: str,
    ) -> None:
        if (
            row["connector_id"] != self.connector_id
            or row["idempotency_key"] != idempotency_key
            or row["binding_digest"] != binding.digest
            or row["action"] != binding.action
        ):
            raise ContractError("reference connector idempotency identity was reused")

    async def execute(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        fence_token: int,
    ) -> ConnectorEvidence:
        self._validate_call_identity(binding, idempotency_key)
        if fence_token < 1:
            raise ContractError("reference connector fence token must be positive")
        now = datetime.now(UTC)
        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            external_operation_id = "refeffect:" + binding.digest
            payload: dict[str, JsonValue] = {
                "action": binding.action,
                "arguments": dict(binding.arguments),
                "binding_digest": binding.digest,
                "fence_token": fence_token,
            }
            # Both PostgreSQL and SQLite serialize a conflicting insert before
            # evaluating the conditional update below.  Keeping the identity
            # predicates and monotonic fence comparison in SQL prevents a
            # stale concurrent writer from lowering the highest accepted fence.
            connection.execute(
                "INSERT INTO reference_connector_effects("
                "connector_id, idempotency_key, binding_digest, action, "
                "external_operation_id, outcome, highest_fence, evidence_json, "
                "created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, 'succeeded', ?, ?, ?, ?) "
                "ON CONFLICT(connector_id, idempotency_key) DO NOTHING",
                (
                    self.connector_id,
                    idempotency_key,
                    binding.digest,
                    binding.action,
                    external_operation_id,
                    fence_token,
                    _json(payload),
                    _time(now),
                    _time(now),
                ),
            )
            connection.execute(
                "UPDATE reference_connector_effects "
                "SET highest_fence = ?, updated_at = ? "
                "WHERE connector_id = ? AND idempotency_key = ? "
                "AND binding_digest = ? AND action = ? AND highest_fence < ?",
                (
                    fence_token,
                    _time(now),
                    self.connector_id,
                    idempotency_key,
                    binding.digest,
                    binding.action,
                    fence_token,
                ),
            )
            row = connection.execute(
                "SELECT * FROM reference_connector_effects "
                "WHERE connector_id = ? AND idempotency_key = ?",
                (self.connector_id, idempotency_key),
            ).fetchone()
            assert row is not None
            self._validate_row(cast(Mapping[str, object], row), binding, idempotency_key)
            if fence_token < int(row["highest_fence"]):
                raise StaleFenceError("reference connector rejected a stale fence token")
            return self._evidence(cast(Mapping[str, object], row))

    async def query_status(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        external_operation_id: str | None,
    ) -> ConnectorEvidence:
        self._validate_call_identity(binding, idempotency_key)
        async with self._resource.open_session(write=True) as session:
            row = (
                _connection(session)
                .execute(
                    "SELECT * FROM reference_connector_effects "
                    "WHERE connector_id = ? AND idempotency_key = ?",
                    (self.connector_id, idempotency_key),
                )
                .fetchone()
            )
            if row is None:
                return ConnectorEvidence(
                    connector_id=self.connector_id,
                    evidence_id="refquery:" + binding.digest,
                    idempotency_key=idempotency_key,
                    external_operation_id=external_operation_id,
                    outcome=ConnectorOutcome.UNKNOWN,
                    observed_at=datetime.now(UTC),
                    payload={"binding_digest": binding.digest, "found": False},
                )
            self._validate_row(cast(Mapping[str, object], row), binding, idempotency_key)
            if external_operation_id not in {None, row["external_operation_id"]}:
                raise ContractError("reference connector query names another external operation")
            return self._evidence(cast(Mapping[str, object], row))

    async def cancel(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        external_operation_id: str | None,
    ) -> ConnectorEvidence:
        self._validate_call_identity(binding, idempotency_key)
        # A durable succeeded reference effect cannot be undone.  Missing
        # effects are reported unknown, allowing the runner's pre-dispatch
        # cancellation proof to remain the only no-effect cancellation path.
        return await self.query_status(
            binding,
            idempotency_key=idempotency_key,
            external_operation_id=external_operation_id,
        )

    async def effect_count(self, *, action: str | None = None) -> int:
        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            if action is None:
                row = connection.execute(
                    "SELECT COUNT(*) AS effect_count FROM reference_connector_effects "
                    "WHERE connector_id = ?",
                    (self.connector_id,),
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT COUNT(*) AS effect_count FROM reference_connector_effects "
                    "WHERE connector_id = ? AND action = ?",
                    (self.connector_id, action),
                ).fetchone()
            assert row is not None
            return int(row["effect_count"])

    async def highest_fence(self, *, idempotency_key: str) -> int | None:
        async with self._resource.open_session(write=True) as session:
            row = (
                _connection(session)
                .execute(
                    "SELECT highest_fence FROM reference_connector_effects "
                    "WHERE connector_id = ? AND idempotency_key = ?",
                    (self.connector_id, idempotency_key),
                )
                .fetchone()
            )
            return None if row is None else int(row["highest_fence"])


@dataclass(frozen=True)
class ReferencePendingEffect:
    pending_id: str
    request: ActionRequest
    evaluation: AuthorizationEvaluation
    evaluation_started_at: datetime
    evaluation_completed_at: datetime
    pending_plan: PendingResolutionPlan
    resolution: Mapping[str, JsonValue] | None


@dataclass(frozen=True)
class ReferenceEffectHandoff:
    binding: ProtectedExecutionBinding
    state: str


@dataclass(frozen=True)
class ReferenceEffectAuthorizationOutcome:
    """Exact terminal authorization committed beside a reference effect outbox."""

    request: ActionRequest
    evaluation: AuthorizationEvaluation
    evaluation_started_at: datetime
    evaluation_completed_at: datetime
    effect_committed: bool
    resolution: Mapping[str, JsonValue] | None

    def __post_init__(self) -> None:
        if self.evaluation.evaluated_at != self.evaluation_completed_at:
            raise ValueError("reference authorization evaluation time is inconsistent")
        if self.evaluation_started_at > self.evaluation_completed_at:
            raise ValueError("reference authorization evaluation completed before it started")
        if (self.evaluation.decision.effect is DecisionEffect.ALLOW) != self.effect_committed:
            raise ValueError("reference authorization effect state is inconsistent")


class ReferenceEffectOutbox:
    """Provider-side dispatch authority committed with protected state."""

    def __init__(self, resource: object) -> None:
        self._resource = cast(_SessionResource, resource)

    async def initialize(self) -> None:
        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            execute_script = getattr(connection, "executescript", None)
            if not callable(execute_script):
                raise ContractError("reference effect outbox cannot initialize SQL state")
            execute_script(
                """
                CREATE TABLE IF NOT EXISTS reference_effect_handoffs (
                    execution_id TEXT PRIMARY KEY,
                    binding_digest TEXT NOT NULL UNIQUE,
                    binding_json TEXT NOT NULL,
                    action TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(action, principal_id, idempotency_key),
                    CHECK(state IN ('outbox', 'succeeded', 'failed', 'outcome_unknown'))
                );
                CREATE TABLE IF NOT EXISTS reference_effect_pending (
                    pending_id TEXT PRIMARY KEY,
                    action TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    authorization_evaluation_json TEXT NOT NULL,
                    evaluation_started_at TEXT NOT NULL,
                    evaluation_completed_at TEXT NOT NULL,
                    pending_plan TEXT NOT NULL,
                    state TEXT NOT NULL,
                    resolution_json TEXT,
                    created_at TEXT NOT NULL,
                    resolved_at TEXT,
                    UNIQUE(action, principal_id, idempotency_key),
                    CHECK(pending_plan = 'revalidate'),
                    CHECK(state IN ('pending', 'resolved')),
                    CHECK(
                        (state = 'pending' AND resolution_json IS NULL AND resolved_at IS NULL)
                        OR
                        (state = 'resolved' AND resolution_json IS NOT NULL
                            AND resolved_at IS NOT NULL)
                    )
                );
                CREATE TABLE IF NOT EXISTS reference_effect_authorization_outcomes (
                    action TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    authorization_evaluation_json TEXT NOT NULL,
                    evaluation_started_at TEXT NOT NULL,
                    evaluation_completed_at TEXT NOT NULL,
                    effect_committed INTEGER NOT NULL,
                    resolution_json TEXT,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(action, principal_id, idempotency_key),
                    CHECK(effect_committed IN (0, 1))
                );
                """
            )

    @staticmethod
    def _pending_id(request: ActionRequest) -> str:
        return "refpending:" + _digest(
            _json(
                {
                    "action": request.action,
                    "idempotency_key": request.idempotency_key,
                    "principal_id": request.principal.id,
                }
            )
        )

    def _pending_from_row(self, row: Mapping[str, object]) -> ReferencePendingEffect:
        try:
            raw_request = json.loads(cast(str, row["request_json"]))
            raw_evaluation = json.loads(cast(str, row["authorization_evaluation_json"]))
            if not isinstance(raw_request, dict) or not isinstance(raw_evaluation, dict):
                raise ValueError("pending payload is not an object")
            request = action_request_from_payload(cast(dict[str, JsonValue], raw_request))
            evaluation = authorization_evaluation_from_payload(
                cast(dict[str, JsonValue], raw_evaluation)
            )
            raw_resolution = row["resolution_json"]
            resolution: Mapping[str, JsonValue] | None = None
            if raw_resolution is not None:
                decoded = json.loads(cast(str, raw_resolution))
                if not isinstance(decoded, dict):
                    raise ValueError("pending resolution is not an object")
                resolution = cast(dict[str, JsonValue], decoded)
            pending = ReferencePendingEffect(
                pending_id=cast(str, row["pending_id"]),
                request=request,
                evaluation=evaluation,
                evaluation_started_at=datetime.fromisoformat(
                    cast(str, row["evaluation_started_at"])
                ),
                evaluation_completed_at=datetime.fromisoformat(
                    cast(str, row["evaluation_completed_at"])
                ),
                pending_plan=PendingResolutionPlan(cast(str, row["pending_plan"])),
                resolution=resolution,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ContractError("reference pending effect is malformed") from exc
        if (
            pending.request.action != row["action"]
            or pending.request.principal.id != row["principal_id"]
            or pending.request.idempotency_key != row["idempotency_key"]
            or self._pending_id(pending.request) != pending.pending_id
            or pending.pending_plan is not PendingResolutionPlan.REVALIDATE
            or pending.evaluation.decision.effect.value != "escalate"
            or pending.evaluation.evaluated_at != pending.evaluation_completed_at
        ):
            raise ContractError("reference pending effect identity is inconsistent")
        return pending

    @staticmethod
    def _idempotency_payload(request: ActionRequest) -> dict[str, JsonValue]:
        payload = action_request_payload(request)
        payload.pop("operation_id", None)
        payload.pop("timestamp", None)
        payload.pop("trace_id", None)
        return payload

    def _outcome_from_row(
        self,
        row: Mapping[str, object],
    ) -> ReferenceEffectAuthorizationOutcome:
        try:
            raw_request = json.loads(cast(str, row["request_json"]))
            raw_evaluation = json.loads(cast(str, row["authorization_evaluation_json"]))
            if not isinstance(raw_request, dict) or not isinstance(raw_evaluation, dict):
                raise ValueError("authorization payload is not an object")
            raw_resolution = row["resolution_json"]
            resolution: Mapping[str, JsonValue] | None = None
            if raw_resolution is not None:
                decoded = json.loads(cast(str, raw_resolution))
                if not isinstance(decoded, dict):
                    raise ValueError("authorization resolution is not an object")
                resolution = cast(dict[str, JsonValue], decoded)
            outcome = ReferenceEffectAuthorizationOutcome(
                request=action_request_from_payload(cast(dict[str, JsonValue], raw_request)),
                evaluation=authorization_evaluation_from_payload(
                    cast(dict[str, JsonValue], raw_evaluation)
                ),
                evaluation_started_at=datetime.fromisoformat(
                    cast(str, row["evaluation_started_at"])
                ),
                evaluation_completed_at=datetime.fromisoformat(
                    cast(str, row["evaluation_completed_at"])
                ),
                effect_committed=bool(row["effect_committed"]),
                resolution=resolution,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ContractError("reference authorization outcome is malformed") from exc
        if (
            outcome.request.action != row["action"]
            or outcome.request.principal.id != row["principal_id"]
            or outcome.request.idempotency_key != row["idempotency_key"]
        ):
            raise ContractError("reference authorization outcome identity is inconsistent")
        return outcome

    def load_outcome_in_session(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> ReferenceEffectAuthorizationOutcome | None:
        row = (
            _connection(session)
            .execute(
                "SELECT * FROM reference_effect_authorization_outcomes "
                "WHERE action = ? AND principal_id = ? AND idempotency_key = ?",
                (request.action, request.principal.id, request.idempotency_key),
            )
            .fetchone()
        )
        if row is None:
            return None
        outcome = self._outcome_from_row(cast(Mapping[str, object], row))
        if self._idempotency_payload(outcome.request) != self._idempotency_payload(request):
            raise ContractError(
                "reference authorization idempotency key has different immutable inputs"
            )
        return outcome

    def record_outcome_in_session(
        self,
        session: ResourceSession,
        request: ActionRequest,
        evaluation: AuthorizationEvaluation,
        *,
        evaluation_started_at: datetime,
        evaluation_completed_at: datetime,
        effect_committed: bool,
        resolution: Mapping[str, JsonValue] | None = None,
    ) -> ReferenceEffectAuthorizationOutcome:
        outcome = ReferenceEffectAuthorizationOutcome(
            request=request,
            evaluation=evaluation,
            evaluation_started_at=evaluation_started_at,
            evaluation_completed_at=evaluation_completed_at,
            effect_committed=effect_committed,
            resolution=resolution,
        )
        existing = self.load_outcome_in_session(session, request)
        if existing is not None:
            if existing != outcome:
                raise ContractError("reference authorization outcome is immutable")
            return existing
        _connection(session).execute(
            "INSERT INTO reference_effect_authorization_outcomes("
            "action, principal_id, idempotency_key, request_json, "
            "authorization_evaluation_json, evaluation_started_at, "
            "evaluation_completed_at, effect_committed, resolution_json, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                request.action,
                request.principal.id,
                request.idempotency_key,
                _json(action_request_payload(request)),
                _json(authorization_evaluation_payload(evaluation)),
                _time(evaluation_started_at),
                _time(evaluation_completed_at),
                1 if effect_committed else 0,
                None if resolution is None else _json(cast(JsonValue, dict(resolution))),
                _time(datetime.now(UTC)),
            ),
        )
        persisted = self.load_outcome_in_session(session, request)
        if persisted is None:  # pragma: no cover - inserted in this transaction
            raise ContractError("reference authorization outcome disappeared")
        return persisted

    def load_pending_in_session(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> ReferencePendingEffect | None:
        row = (
            _connection(session)
            .execute(
                "SELECT * FROM reference_effect_pending "
                "WHERE action = ? AND principal_id = ? AND idempotency_key = ?",
                (request.action, request.principal.id, request.idempotency_key),
            )
            .fetchone()
        )
        if row is None:
            return None
        pending = self._pending_from_row(cast(Mapping[str, object], row))
        left = action_request_payload(pending.request)
        right = action_request_payload(request)
        for payload in (left, right):
            payload.pop("timestamp", None)
            payload.pop("trace_id", None)
        if left != right:
            raise ContractError("reference pending idempotency key has different immutable inputs")
        return pending

    async def load_pending(self, pending_id: str) -> ReferencePendingEffect:
        async with self._resource.open_session(write=True) as session:
            row = (
                _connection(session)
                .execute(
                    "SELECT * FROM reference_effect_pending WHERE pending_id = ?",
                    (pending_id,),
                )
                .fetchone()
            )
            if row is None:
                raise ContractError("reference pending effect is unknown")
            return self._pending_from_row(cast(Mapping[str, object], row))

    def record_pending_in_session(
        self,
        session: ResourceSession,
        request: ActionRequest,
        evaluation: AuthorizationEvaluation,
        *,
        evaluation_started_at: datetime,
        evaluation_completed_at: datetime,
        pending_plan: PendingResolutionPlan,
    ) -> ReferencePendingEffect:
        if (
            pending_plan is not PendingResolutionPlan.REVALIDATE
            or evaluation.decision.effect.value != "escalate"
        ):
            raise ContractError("reference pending effect requires revalidation escalation")
        existing = self.load_pending_in_session(session, request)
        if existing is not None:
            return existing
        pending_id = self._pending_id(request)
        _connection(session).execute(
            "INSERT INTO reference_effect_pending("
            "pending_id, action, principal_id, idempotency_key, request_json, "
            "authorization_evaluation_json, evaluation_started_at, evaluation_completed_at, "
            "pending_plan, state, resolution_json, created_at, resolved_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, ?, NULL)",
            (
                pending_id,
                request.action,
                request.principal.id,
                request.idempotency_key,
                _json(action_request_payload(request)),
                _json(authorization_evaluation_payload(evaluation)),
                _time(evaluation_started_at),
                _time(evaluation_completed_at),
                pending_plan.value,
                _time(datetime.now(UTC)),
            ),
        )
        pending = self.load_pending_in_session(session, request)
        if pending is None:  # pragma: no cover - inserted in this transaction
            raise ContractError("reference pending effect disappeared")
        return pending

    def resolve_pending_in_session(
        self,
        session: ResourceSession,
        pending: ReferencePendingEffect,
        resolution: Mapping[str, JsonValue],
    ) -> ReferencePendingEffect:
        normalized = json.loads(_json(cast(JsonValue, dict(resolution))))
        row = (
            _connection(session)
            .execute(
                "SELECT * FROM reference_effect_pending WHERE pending_id = ?",
                (pending.pending_id,),
            )
            .fetchone()
        )
        if row is None:
            raise ContractError("reference pending effect is unknown")
        current = self._pending_from_row(cast(Mapping[str, object], row))
        if current.resolution is not None:
            if dict(current.resolution) != normalized:
                raise ContractError("reference pending resolution is immutable")
            return current
        _connection(session).execute(
            "UPDATE reference_effect_pending SET state = 'resolved', resolution_json = ?, "
            "resolved_at = ? WHERE pending_id = ? AND state = 'pending'",
            (
                _json(cast(JsonValue, normalized)),
                _time(datetime.now(UTC)),
                pending.pending_id,
            ),
        )
        row = (
            _connection(session)
            .execute(
                "SELECT * FROM reference_effect_pending WHERE pending_id = ?",
                (pending.pending_id,),
            )
            .fetchone()
        )
        assert row is not None
        return self._pending_from_row(cast(Mapping[str, object], row))

    def record_in_session(
        self,
        session: ResourceSession,
        binding: ProtectedExecutionBinding,
    ) -> ProtectedExecutionBinding:
        connection = _connection(session)
        row = connection.execute(
            "SELECT * FROM reference_effect_handoffs WHERE execution_id = ?",
            (binding.execution_id,),
        ).fetchone()
        encoded = _json(binding.payload())
        if row is not None:
            if row["binding_digest"] != binding.digest or row["binding_json"] != encoded:
                raise ContractError("reference effect handoff identity was reused")
            return binding
        now = datetime.now(UTC)
        connection.execute(
            "INSERT INTO reference_effect_handoffs("
            "execution_id, binding_digest, binding_json, action, principal_id, "
            "idempotency_key, state, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, 'outbox', ?, ?)",
            (
                binding.execution_id,
                binding.digest,
                encoded,
                binding.action,
                binding.principal_id,
                binding.idempotency_key,
                _time(now),
                _time(now),
            ),
        )
        return binding

    def load_in_session(
        self,
        session: ResourceSession,
        *,
        action: str,
        principal_id: str,
        idempotency_key: str,
    ) -> ProtectedExecutionBinding | None:
        row = (
            _connection(session)
            .execute(
                "SELECT binding_json FROM reference_effect_handoffs "
                "WHERE action = ? AND principal_id = ? AND idempotency_key = ?",
                (action, principal_id, idempotency_key),
            )
            .fetchone()
        )
        if row is None:
            return None
        try:
            payload = json.loads(cast(str, row["binding_json"]))
            if not isinstance(payload, dict):
                raise ValueError("binding is not an object")
            return reference_purchase_binding_from_payload(cast(dict[str, JsonValue], payload))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ContractError("reference effect handoff is malformed") from exc

    async def require_dispatchable(self, binding: ProtectedExecutionBinding) -> None:
        async with self._resource.open_session(write=True) as session:
            row = (
                _connection(session)
                .execute(
                    "SELECT binding_digest, binding_json FROM reference_effect_handoffs "
                    "WHERE execution_id = ?",
                    (binding.execution_id,),
                )
                .fetchone()
            )
            if row is None or row["binding_digest"] != binding.digest:
                raise ContractError("protected dispatch has no exact provider outbox authority")
            if row["binding_json"] != _json(binding.payload()):
                raise ContractError("protected dispatch binding differs from provider outbox")

    async def settle(self, record: ProtectedExecutionRecord) -> None:
        state = {
            ProtectedExecutionStatus.INTENT: "outbox",
            ProtectedExecutionStatus.EXECUTING: "outbox",
            ProtectedExecutionStatus.SUCCEEDED: "succeeded",
            ProtectedExecutionStatus.FAILED: "failed",
            ProtectedExecutionStatus.OUTCOME_UNKNOWN: "outcome_unknown",
        }[record.status]
        async with self._resource.open_session(write=True) as session:
            updated = (
                _connection(session)
                .execute(
                    "UPDATE reference_effect_handoffs SET state = ?, updated_at = ? "
                    "WHERE execution_id = ? AND binding_digest = ?",
                    (state, _time(datetime.now(UTC)), record.execution_id, record.binding.digest),
                )
                .rowcount
            )
            if updated != 1:
                raise ContractError("protected result has no exact provider outbox authority")

    async def unresolved(self) -> tuple[ReferenceEffectHandoff, ...]:
        async with self._resource.open_session(write=True) as session:
            rows = (
                _connection(session)
                .execute(
                    "SELECT binding_json, state FROM reference_effect_handoffs "
                    "WHERE state IN ('outbox', 'outcome_unknown') ORDER BY execution_id"
                )
                .fetchall()
            )
            result: list[ReferenceEffectHandoff] = []
            for row in rows:
                try:
                    payload = json.loads(cast(str, row["binding_json"]))
                    if not isinstance(payload, dict):
                        raise ValueError("binding is not an object")
                    result.append(
                        ReferenceEffectHandoff(
                            binding=reference_purchase_binding_from_payload(
                                cast(dict[str, JsonValue], payload)
                            ),
                            state=cast(str, row["state"]),
                        )
                    )
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise ContractError("reference effect handoff is malformed") from exc
            return tuple(result)


__all__ = [
    "ReferenceEffectAuthorizationOutcome",
    "ReferenceEffectConnector",
    "ReferenceEffectHandoff",
    "ReferenceEffectOutbox",
    "ReferencePendingEffect",
]
