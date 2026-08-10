"""Durable SQLite reference store for the protected-execution lifecycle.

The shipping PostgreSQL implementation and cross-backend recovery matrix make
this durable implementation available. This dependency-free SQLite store makes
the protected-execution state machine durable across process/store recreation
and keeps every transition in an
explicit short transaction; connector I/O is never invoked from this module.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from typing import Protocol, cast

from masugate.contracts import ProviderIdentity
from masugate.model import JsonValue
from masugate.protected_execution.errors import (
    ProtectedExecutionBusy,
    ProtectedExecutionConflict,
    ProtectedExecutionError,
    StaleFenceError,
)
from masugate.protected_execution.model import (
    ConnectorEvidence,
    ConnectorOutcome,
    EntitlementState,
    PolicyBinding,
    ProtectedExecutionBinding,
    ProtectedExecutionEvent,
    ProtectedExecutionRecord,
    ProtectedExecutionStatus,
    canonical_json,
)


def _time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("protected-execution store time must be timezone-aware")
    return value.isoformat()


def _parse_time(value: object) -> datetime:
    if type(value) is not str:
        raise ProtectedExecutionError("durable protected-execution time is malformed")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ProtectedExecutionError("durable protected-execution time is not aware")
    return parsed


def _json_object(value: object, field_name: str) -> dict[str, JsonValue]:
    if isinstance(value, dict) and all(type(key) is str for key in value):
        return deepcopy(cast(dict[str, JsonValue], value))
    try:
        decoded = json.loads(cast(str, value))
    except (TypeError, json.JSONDecodeError) as exc:
        raise ProtectedExecutionError(f"durable {field_name} JSON is malformed") from exc
    if not isinstance(decoded, dict) or any(type(key) is not str for key in decoded):
        raise ProtectedExecutionError(f"durable {field_name} must be a JSON object")
    return cast(dict[str, JsonValue], decoded)


def _binding_from_payload(payload: Mapping[str, JsonValue]) -> ProtectedExecutionBinding:
    provider = cast(dict[str, JsonValue], payload["provider_identity"])
    policies = cast(list[JsonValue], payload["policies"])
    return ProtectedExecutionBinding(
        principal_id=cast(str, payload["principal_id"]),
        action=cast(str, payload["action"]),
        arguments=cast(dict[str, JsonValue], payload["arguments"]),
        idempotency_key=cast(str, payload["idempotency_key"]),
        policies=tuple(
            PolicyBinding(
                policy_id=cast(str, item["policy_id"]),
                policy_version=cast(str, item["policy_version"]),
                policy_digest=cast(str, item["policy_digest"]),
                bundle_id=cast(str, item["bundle_id"]),
                bundle_version=cast(str, item["bundle_version"]),
                bundle_digest=cast(str, item["bundle_digest"]),
            )
            for raw in policies
            for item in [cast(dict[str, JsonValue], raw)]
        ),
        provider_identity=ProviderIdentity(
            provider_id=cast(str, provider["provider_id"]),
            implementation_version=cast(str, provider["implementation_version"]),
            configuration_version=cast(str, provider["configuration_version"]),
        ),
        coordination_domain_id=cast(str, payload["coordination_domain_id"]),
        scopes=tuple(cast(list[str], payload["scopes"])),
        tool_call_id=cast(str, payload["tool_call_id"]),
        connector_id=cast(str, payload["connector_id"]),
        entitlement_id=cast(str, payload["entitlement_id"]),
        authorization_digest=cast(str | None, payload.get("authorization_digest")),
    )


def _evidence_from_payload(payload: Mapping[str, JsonValue]) -> ConnectorEvidence:
    return ConnectorEvidence(
        connector_id=cast(str, payload["connector_id"]),
        evidence_id=cast(str, payload["evidence_id"]),
        idempotency_key=cast(str, payload["idempotency_key"]),
        external_operation_id=cast(str | None, payload["external_operation_id"]),
        outcome=ConnectorOutcome(cast(str, payload["outcome"])),
        observed_at=_parse_time(payload["observed_at"]),
        payload=cast(dict[str, JsonValue], payload["payload"]),
    )


class ProtectedExecutionStore(Protocol):
    """Durable transition surface consumed by the framework-neutral runner."""

    async def initialize(self) -> None: ...

    async def create_intent(
        self,
        binding: ProtectedExecutionBinding,
        *,
        now: datetime,
    ) -> ProtectedExecutionRecord: ...

    async def get(self, execution_id: str) -> ProtectedExecutionRecord: ...

    async def claim_dispatch(
        self,
        execution_id: str,
        *,
        worker_id: str,
        now: datetime,
        lease_duration: timedelta,
    ) -> ProtectedExecutionRecord: ...

    async def claim_reconciliation(
        self,
        execution_id: str,
        *,
        worker_id: str,
        now: datetime,
        lease_duration: timedelta,
    ) -> ProtectedExecutionRecord: ...

    async def claim_cancellation(
        self,
        execution_id: str,
        *,
        worker_id: str,
        now: datetime,
        lease_duration: timedelta,
    ) -> ProtectedExecutionRecord: ...

    async def claim_expired_execution(
        self,
        execution_id: str,
        *,
        worker_id: str,
        now: datetime,
        lease_duration: timedelta,
    ) -> ProtectedExecutionRecord: ...

    async def recoverable(self) -> tuple[ProtectedExecutionRecord, ...]: ...

    async def mark_dispatch_started(
        self,
        execution_id: str,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
    ) -> ProtectedExecutionRecord: ...

    async def record_receipt(
        self,
        execution_id: str,
        evidence: ConnectorEvidence,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
    ) -> ProtectedExecutionRecord: ...

    async def finalize_receipt(
        self,
        execution_id: str,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
    ) -> ProtectedExecutionRecord: ...

    async def mark_outcome_unknown(
        self,
        execution_id: str,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
        reason: str,
        external_operation_id: str | None = None,
    ) -> ProtectedExecutionRecord: ...

    async def finish_reconciliation_unknown(
        self,
        execution_id: str,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
        reason: str,
        external_operation_id: str | None = None,
    ) -> ProtectedExecutionRecord: ...

    async def cancel_pre_dispatch(
        self,
        execution_id: str,
        *,
        now: datetime,
    ) -> tuple[bool, ProtectedExecutionRecord]: ...

    async def fail_pre_dispatch(
        self,
        execution_id: str,
        *,
        now: datetime,
        reason: str,
    ) -> tuple[bool, ProtectedExecutionRecord]: ...

    async def request_post_dispatch_cancel(
        self,
        execution_id: str,
        *,
        now: datetime,
    ) -> ProtectedExecutionRecord: ...

    async def record_reconciliation_attempt(
        self,
        execution_id: str,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
        evidence: Mapping[str, JsonValue],
    ) -> None: ...

    async def events(self, execution_id: str) -> tuple[ProtectedExecutionEvent, ...]: ...


class SqliteProtectedExecutionStore:
    """File-backed reference implementation of the durable lifecycle store."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    async def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS protected_executions (
                    execution_id TEXT PRIMARY KEY,
                    tool_call_id TEXT NOT NULL UNIQUE,
                    principal_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    binding_digest TEXT NOT NULL UNIQUE,
                    binding_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    entitlement_state TEXT NOT NULL,
                    dispatch_started INTEGER NOT NULL DEFAULT 0,
                    cancel_requested INTEGER NOT NULL DEFAULT 0,
                    external_operation_id TEXT,
                    lease_owner TEXT,
                    fence_token INTEGER NOT NULL DEFAULT 0,
                    lease_expires_at TEXT,
                    receipt_json TEXT,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(principal_id, idempotency_key),
                    CHECK(dispatch_started IN (0, 1)),
                    CHECK(cancel_requested IN (0, 1)),
                    CHECK(fence_token >= 0)
                );
                CREATE TABLE IF NOT EXISTS protected_execution_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    execution_id TEXT NOT NULL REFERENCES protected_executions(execution_id),
                    event_type TEXT NOT NULL,
                    from_status TEXT,
                    to_status TEXT NOT NULL,
                    worker_id TEXT,
                    fence_token INTEGER,
                    recorded_at TEXT NOT NULL,
                    evidence_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS protected_execution_events_execution
                    ON protected_execution_events(execution_id, sequence);
                """
            )
            connection.commit()
        finally:
            connection.close()

    def _event(
        self,
        connection: sqlite3.Connection,
        *,
        execution_id: str,
        event_type: str,
        from_status: ProtectedExecutionStatus | None,
        to_status: ProtectedExecutionStatus,
        recorded_at: datetime,
        worker_id: str | None = None,
        fence_token: int | None = None,
        evidence: Mapping[str, JsonValue] | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO protected_execution_events(
                execution_id, event_type, from_status, to_status, worker_id,
                fence_token, recorded_at, evidence_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                execution_id,
                event_type,
                from_status.value if from_status is not None else None,
                to_status.value,
                worker_id,
                fence_token,
                _time(recorded_at),
                canonical_json(dict(evidence or {})),
            ),
        )

    def _load_row(
        self,
        connection: sqlite3.Connection,
        execution_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM protected_executions WHERE execution_id = ?",
            (execution_id,),
        ).fetchone()
        if row is None:
            raise ProtectedExecutionError(f"unknown protected execution: {execution_id}")
        return cast(sqlite3.Row, row)

    def _decode(self, row: sqlite3.Row) -> ProtectedExecutionRecord:
        binding_payload = _json_object(row["binding_json"], "binding")
        binding = _binding_from_payload(binding_payload)
        if (
            row["tool_call_id"] != binding.tool_call_id
            or row["principal_id"] != binding.principal_id
            or row["idempotency_key"] != binding.idempotency_key
        ):
            raise ProtectedExecutionError(
                "durable protected-execution identity columns do not match binding"
            )
        receipt = (
            None
            if row["receipt_json"] is None
            else _evidence_from_payload(_json_object(row["receipt_json"], "receipt"))
        )
        return ProtectedExecutionRecord(
            execution_id=cast(str, row["execution_id"]),
            binding=binding,
            binding_digest=cast(str, row["binding_digest"]),
            status=ProtectedExecutionStatus(cast(str, row["status"])),
            entitlement_state=EntitlementState(cast(str, row["entitlement_state"])),
            dispatch_started=bool(row["dispatch_started"]),
            cancel_requested=bool(row["cancel_requested"]),
            external_operation_id=cast(str | None, row["external_operation_id"]),
            lease_owner=cast(str | None, row["lease_owner"]),
            fence_token=int(row["fence_token"]),
            lease_expires_at=(
                None if row["lease_expires_at"] is None else _parse_time(row["lease_expires_at"])
            ),
            receipt=receipt,
            result=_json_object(row["result_json"], "result"),
            created_at=_parse_time(row["created_at"]),
            updated_at=_parse_time(row["updated_at"]),
        )

    async def create_intent(
        self,
        binding: ProtectedExecutionBinding,
        *,
        now: datetime,
    ) -> ProtectedExecutionRecord:
        timestamp = _time(now)
        with self._transaction() as connection:
            existing = connection.execute(
                """
                SELECT * FROM protected_executions
                WHERE tool_call_id = ? OR (principal_id = ? AND idempotency_key = ?)
                """,
                (binding.tool_call_id, binding.principal_id, binding.idempotency_key),
            ).fetchone()
            if existing is not None:
                record = self._decode(existing)
                if record.binding_digest != binding.digest:
                    raise ProtectedExecutionConflict(
                        "tool-call/idempotency identity was reused with a different binding"
                    )
                return record
            connection.execute(
                """
                INSERT INTO protected_executions(
                    execution_id, tool_call_id, principal_id, idempotency_key,
                    binding_digest, binding_json, status, entitlement_state,
                    result_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    binding.execution_id,
                    binding.tool_call_id,
                    binding.principal_id,
                    binding.idempotency_key,
                    binding.digest,
                    canonical_json(binding.payload()),
                    ProtectedExecutionStatus.INTENT.value,
                    EntitlementState.HELD.value,
                    "{}",
                    timestamp,
                    timestamp,
                ),
            )
            self._event(
                connection,
                execution_id=binding.execution_id,
                event_type="intent-persisted",
                from_status=None,
                to_status=ProtectedExecutionStatus.INTENT,
                recorded_at=now,
                evidence={
                    "binding_digest": binding.digest,
                    "entitlement_id": binding.entitlement_id,
                },
            )
            return self._decode(self._load_row(connection, binding.execution_id))

    async def get(self, execution_id: str) -> ProtectedExecutionRecord:
        connection = self._connect()
        try:
            return self._decode(self._load_row(connection, execution_id))
        finally:
            connection.close()

    def _current_fence(
        self,
        row: sqlite3.Row,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
    ) -> ProtectedExecutionStatus:
        status = ProtectedExecutionStatus(cast(str, row["status"]))
        expires_at = (
            None if row["lease_expires_at"] is None else _parse_time(row["lease_expires_at"])
        )
        if (
            row["lease_owner"] != worker_id
            or int(row["fence_token"]) != fence_token
            or expires_at is None
            or expires_at <= now
        ):
            raise StaleFenceError("protected-execution worker lease/fence is stale")
        return status

    async def claim_dispatch(
        self,
        execution_id: str,
        *,
        worker_id: str,
        now: datetime,
        lease_duration: timedelta,
    ) -> ProtectedExecutionRecord:
        if lease_duration <= timedelta(0):
            raise ValueError("lease duration must be positive")
        with self._transaction() as connection:
            row = self._load_row(connection, execution_id)
            status = ProtectedExecutionStatus(cast(str, row["status"]))
            if status is not ProtectedExecutionStatus.INTENT:
                raise ProtectedExecutionBusy(
                    f"protected execution cannot dispatch from {status.value}"
                )
            fence = int(row["fence_token"]) + 1
            connection.execute(
                """
                UPDATE protected_executions
                SET status = ?, lease_owner = ?, fence_token = ?, lease_expires_at = ?,
                    updated_at = ?
                WHERE execution_id = ?
                """,
                (
                    ProtectedExecutionStatus.EXECUTING.value,
                    worker_id,
                    fence,
                    _time(now + lease_duration),
                    _time(now),
                    execution_id,
                ),
            )
            self._event(
                connection,
                execution_id=execution_id,
                event_type="dispatch-lease-claimed",
                from_status=status,
                to_status=ProtectedExecutionStatus.EXECUTING,
                worker_id=worker_id,
                fence_token=fence,
                recorded_at=now,
            )
            return self._decode(self._load_row(connection, execution_id))

    async def claim_cancellation(
        self,
        execution_id: str,
        *,
        worker_id: str,
        now: datetime,
        lease_duration: timedelta,
    ) -> ProtectedExecutionRecord:
        """Fence an in-flight/unknown execution before best-effort cancellation."""

        if lease_duration <= timedelta(0):
            raise ValueError("lease duration must be positive")
        with self._transaction() as connection:
            row = self._load_row(connection, execution_id)
            status = ProtectedExecutionStatus(cast(str, row["status"]))
            if status not in {
                ProtectedExecutionStatus.EXECUTING,
                ProtectedExecutionStatus.OUTCOME_UNKNOWN,
            } or not bool(row["dispatch_started"]):
                raise ProtectedExecutionBusy(
                    f"protected execution cannot cancel from {status.value}"
                )
            fence = int(row["fence_token"]) + 1
            connection.execute(
                """
                UPDATE protected_executions
                SET cancel_requested = 1, lease_owner = ?, fence_token = ?,
                    lease_expires_at = ?, updated_at = ?
                WHERE execution_id = ?
                """,
                (
                    worker_id,
                    fence,
                    _time(now + lease_duration),
                    _time(now),
                    execution_id,
                ),
            )
            self._event(
                connection,
                execution_id=execution_id,
                event_type="cancellation-lease-claimed",
                from_status=status,
                to_status=status,
                worker_id=worker_id,
                fence_token=fence,
                recorded_at=now,
                evidence={"previous_worker_fenced": True},
            )
            return self._decode(self._load_row(connection, execution_id))

    async def claim_expired_execution(
        self,
        execution_id: str,
        *,
        worker_id: str,
        now: datetime,
        lease_duration: timedelta,
    ) -> ProtectedExecutionRecord:
        """Fence an expired executing worker and classify its safe recovery path."""

        if lease_duration <= timedelta(0):
            raise ValueError("lease duration must be positive")
        with self._transaction() as connection:
            row = self._load_row(connection, execution_id)
            status = ProtectedExecutionStatus(cast(str, row["status"]))
            lease_expiry = (
                None if row["lease_expires_at"] is None else _parse_time(row["lease_expires_at"])
            )
            if (
                status is not ProtectedExecutionStatus.EXECUTING
                or lease_expiry is None
                or lease_expiry > now
            ):
                raise ProtectedExecutionBusy(
                    "protected execution does not have an expired executing lease"
                )
            fence = int(row["fence_token"]) + 1
            if bool(row["dispatch_started"]) and row["receipt_json"] is None:
                target = ProtectedExecutionStatus.OUTCOME_UNKNOWN
                entitlement = EntitlementState.QUARANTINED
                lease_owner: str | None = None
                expires: str | None = None
                event_type = "expired-dispatch-quarantined"
            else:
                target = status
                entitlement = EntitlementState(cast(str, row["entitlement_state"]))
                lease_owner = worker_id
                expires = _time(now + lease_duration)
                event_type = (
                    "expired-receipt-recovery-claimed"
                    if row["receipt_json"] is not None
                    else "expired-predispatch-recovery-claimed"
                )
            connection.execute(
                """
                UPDATE protected_executions
                SET status = ?, entitlement_state = ?, lease_owner = ?, fence_token = ?,
                    lease_expires_at = ?, updated_at = ?
                WHERE execution_id = ?
                """,
                (
                    target.value,
                    entitlement.value,
                    lease_owner,
                    fence,
                    expires,
                    _time(now),
                    execution_id,
                ),
            )
            self._event(
                connection,
                execution_id=execution_id,
                event_type=event_type,
                from_status=status,
                to_status=target,
                worker_id=worker_id,
                fence_token=fence,
                recorded_at=now,
                evidence={
                    "expired_worker_fenced": True,
                    "had_dispatch_marker": bool(row["dispatch_started"]),
                    "had_receipt": row["receipt_json"] is not None,
                },
            )
            return self._decode(self._load_row(connection, execution_id))

    async def recoverable(self) -> tuple[ProtectedExecutionRecord, ...]:
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT * FROM protected_executions
                WHERE status IN (?, ?, ?)
                ORDER BY created_at, execution_id
                """,
                (
                    ProtectedExecutionStatus.INTENT.value,
                    ProtectedExecutionStatus.EXECUTING.value,
                    ProtectedExecutionStatus.OUTCOME_UNKNOWN.value,
                ),
            ).fetchall()
            return tuple(self._decode(row) for row in rows)
        finally:
            connection.close()

    async def claim_reconciliation(
        self,
        execution_id: str,
        *,
        worker_id: str,
        now: datetime,
        lease_duration: timedelta,
    ) -> ProtectedExecutionRecord:
        if lease_duration <= timedelta(0):
            raise ValueError("lease duration must be positive")
        with self._transaction() as connection:
            row = self._load_row(connection, execution_id)
            status = ProtectedExecutionStatus(cast(str, row["status"]))
            if status is not ProtectedExecutionStatus.OUTCOME_UNKNOWN:
                raise ProtectedExecutionBusy(
                    f"protected execution cannot reconcile from {status.value}"
                )
            lease_expiry = (
                None if row["lease_expires_at"] is None else _parse_time(row["lease_expires_at"])
            )
            if row["lease_owner"] is not None and lease_expiry is not None and lease_expiry > now:
                raise ProtectedExecutionBusy("protected execution has a live reconciliation lease")
            fence = int(row["fence_token"]) + 1
            connection.execute(
                """
                UPDATE protected_executions
                SET lease_owner = ?, fence_token = ?, lease_expires_at = ?, updated_at = ?
                WHERE execution_id = ?
                """,
                (
                    worker_id,
                    fence,
                    _time(now + lease_duration),
                    _time(now),
                    execution_id,
                ),
            )
            self._event(
                connection,
                execution_id=execution_id,
                event_type="reconciliation-lease-claimed",
                from_status=status,
                to_status=status,
                worker_id=worker_id,
                fence_token=fence,
                recorded_at=now,
            )
            return self._decode(self._load_row(connection, execution_id))

    async def mark_dispatch_started(
        self,
        execution_id: str,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
    ) -> ProtectedExecutionRecord:
        with self._transaction() as connection:
            row = self._load_row(connection, execution_id)
            status = self._current_fence(
                row,
                worker_id=worker_id,
                fence_token=fence_token,
                now=now,
            )
            if status is not ProtectedExecutionStatus.EXECUTING:
                raise StaleFenceError("dispatch marker requires executing status")
            if bool(row["dispatch_started"]):
                return self._decode(row)
            connection.execute(
                """
                UPDATE protected_executions SET dispatch_started = 1, updated_at = ?
                WHERE execution_id = ?
                """,
                (_time(now), execution_id),
            )
            self._event(
                connection,
                execution_id=execution_id,
                event_type="dispatch-started",
                from_status=status,
                to_status=status,
                worker_id=worker_id,
                fence_token=fence_token,
                recorded_at=now,
            )
            return self._decode(self._load_row(connection, execution_id))

    async def record_receipt(
        self,
        execution_id: str,
        evidence: ConnectorEvidence,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
    ) -> ProtectedExecutionRecord:
        with self._transaction() as connection:
            row = self._load_row(connection, execution_id)
            status = self._current_fence(
                row,
                worker_id=worker_id,
                fence_token=fence_token,
                now=now,
            )
            if status not in {
                ProtectedExecutionStatus.EXECUTING,
                ProtectedExecutionStatus.OUTCOME_UNKNOWN,
            }:
                raise StaleFenceError("connector receipt cannot attach to terminal execution")
            record = self._decode(row)
            if not record.dispatch_started:
                raise ProtectedExecutionError(
                    "connector receipt requires a durable dispatch marker"
                )
            if (
                record.external_operation_id is not None
                and evidence.external_operation_id != record.external_operation_id
            ):
                raise ProtectedExecutionConflict("external-operation identity is immutable")
            evidence.validate_for(
                record.binding,
                expected_external_operation_id=record.external_operation_id,
            )
            if evidence.outcome is ConnectorOutcome.UNKNOWN:
                raise ProtectedExecutionError("unknown evidence cannot be a terminal receipt")
            if record.receipt is not None:
                if record.receipt != evidence:
                    raise ProtectedExecutionConflict("conflicting connector receipt")
                return record
            connection.execute(
                """
                UPDATE protected_executions
                SET receipt_json = ?, external_operation_id = ?, updated_at = ?
                WHERE execution_id = ?
                """,
                (
                    canonical_json(evidence.payload_json()),
                    evidence.external_operation_id,
                    _time(now),
                    execution_id,
                ),
            )
            self._event(
                connection,
                execution_id=execution_id,
                event_type="connector-receipt-recorded",
                from_status=status,
                to_status=status,
                worker_id=worker_id,
                fence_token=fence_token,
                recorded_at=now,
                evidence={
                    "connector_evidence_id": evidence.evidence_id,
                    "connector_observed_at": evidence.observed_at.isoformat(),
                    "external_operation_id": evidence.external_operation_id,
                    "outcome": evidence.outcome.value,
                },
            )
            return self._decode(self._load_row(connection, execution_id))

    async def finalize_receipt(
        self,
        execution_id: str,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
    ) -> ProtectedExecutionRecord:
        with self._transaction() as connection:
            row = self._load_row(connection, execution_id)
            status = self._current_fence(
                row,
                worker_id=worker_id,
                fence_token=fence_token,
                now=now,
            )
            record = self._decode(row)
            if not record.dispatch_started:
                raise ProtectedExecutionError(
                    "terminal recording requires a durable dispatch marker"
                )
            if record.receipt is None:
                raise ProtectedExecutionError("terminal recording requires connector receipt")
            if record.receipt.outcome is ConnectorOutcome.SUCCEEDED:
                terminal = ProtectedExecutionStatus.SUCCEEDED
                entitlement = EntitlementState.CONSUMED
            elif record.receipt.outcome is ConnectorOutcome.FAILED:
                terminal = ProtectedExecutionStatus.FAILED
                entitlement = EntitlementState.RELEASED
            else:  # pragma: no cover - record_receipt rejects this
                raise ProtectedExecutionError("unknown connector receipt cannot finalize")
            if record.entitlement_state not in {
                EntitlementState.HELD,
                EntitlementState.QUARANTINED,
            }:
                raise ProtectedExecutionConflict("entitlement was already terminally resolved")
            connection.execute(
                """
                UPDATE protected_executions
                SET status = ?, entitlement_state = ?, result_json = ?, lease_owner = NULL,
                    lease_expires_at = NULL, updated_at = ?
                WHERE execution_id = ?
                """,
                (
                    terminal.value,
                    entitlement.value,
                    canonical_json(dict(record.receipt.payload)),
                    _time(now),
                    execution_id,
                ),
            )
            self._event(
                connection,
                execution_id=execution_id,
                event_type="terminal-position-recorded",
                from_status=status,
                to_status=terminal,
                worker_id=worker_id,
                fence_token=fence_token,
                recorded_at=now,
                evidence={
                    "connector_evidence_id": record.receipt.evidence_id,
                    "entitlement_id": record.binding.entitlement_id,
                    "entitlement_state": entitlement.value,
                },
            )
            return self._decode(self._load_row(connection, execution_id))

    async def mark_outcome_unknown(
        self,
        execution_id: str,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
        reason: str,
        external_operation_id: str | None = None,
    ) -> ProtectedExecutionRecord:
        with self._transaction() as connection:
            row = self._load_row(connection, execution_id)
            status = self._current_fence(
                row,
                worker_id=worker_id,
                fence_token=fence_token,
                now=now,
            )
            if status is not ProtectedExecutionStatus.EXECUTING:
                raise StaleFenceError("only executing dispatch can become outcome_unknown")
            if not bool(row["dispatch_started"]):
                raise ProtectedExecutionError("pre-dispatch failure cannot become outcome_unknown")
            if row["receipt_json"] is not None:
                raise ProtectedExecutionConflict("recorded connector receipt must be finalized")
            known_operation_id = cast(str | None, row["external_operation_id"])
            if (
                known_operation_id is not None
                and external_operation_id is not None
                and external_operation_id != known_operation_id
            ):
                raise ProtectedExecutionConflict("external-operation identity is immutable")
            operation_id = (
                known_operation_id if known_operation_id is not None else external_operation_id
            )
            connection.execute(
                """
                UPDATE protected_executions
                SET status = ?, entitlement_state = ?, external_operation_id = ?,
                    result_json = ?, lease_owner = NULL, lease_expires_at = NULL,
                    updated_at = ?
                WHERE execution_id = ?
                """,
                (
                    ProtectedExecutionStatus.OUTCOME_UNKNOWN.value,
                    EntitlementState.QUARANTINED.value,
                    operation_id,
                    canonical_json({"reason": reason}),
                    _time(now),
                    execution_id,
                ),
            )
            self._event(
                connection,
                execution_id=execution_id,
                event_type="outcome-quarantined",
                from_status=status,
                to_status=ProtectedExecutionStatus.OUTCOME_UNKNOWN,
                worker_id=worker_id,
                fence_token=fence_token,
                recorded_at=now,
                evidence={
                    "external_operation_id": operation_id,
                    "reason": reason,
                },
            )
            return self._decode(self._load_row(connection, execution_id))

    async def finish_reconciliation_unknown(
        self,
        execution_id: str,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
        reason: str,
        external_operation_id: str | None = None,
    ) -> ProtectedExecutionRecord:
        """End a status/cancel attempt without guessing an unknown outcome."""

        with self._transaction() as connection:
            row = self._load_row(connection, execution_id)
            status = self._current_fence(
                row,
                worker_id=worker_id,
                fence_token=fence_token,
                now=now,
            )
            if status is ProtectedExecutionStatus.EXECUTING:
                if not bool(row["dispatch_started"]):
                    raise ProtectedExecutionError(
                        "pre-dispatch execution cannot become outcome_unknown"
                    )
                target = ProtectedExecutionStatus.OUTCOME_UNKNOWN
            elif status is ProtectedExecutionStatus.OUTCOME_UNKNOWN:
                target = status
            else:
                raise StaleFenceError("terminal execution cannot remain outcome_unknown")
            known_operation_id = cast(str | None, row["external_operation_id"])
            if (
                known_operation_id is not None
                and external_operation_id is not None
                and external_operation_id != known_operation_id
            ):
                raise ProtectedExecutionConflict("external-operation identity is immutable")
            operation_id = (
                known_operation_id if known_operation_id is not None else external_operation_id
            )
            connection.execute(
                """
                UPDATE protected_executions
                SET status = ?, entitlement_state = ?, external_operation_id = ?,
                    result_json = ?, lease_owner = NULL, lease_expires_at = NULL,
                    updated_at = ?
                WHERE execution_id = ?
                """,
                (
                    target.value,
                    EntitlementState.QUARANTINED.value,
                    operation_id,
                    canonical_json({"reason": reason}),
                    _time(now),
                    execution_id,
                ),
            )
            self._event(
                connection,
                execution_id=execution_id,
                event_type="outcome-remains-quarantined",
                from_status=status,
                to_status=target,
                worker_id=worker_id,
                fence_token=fence_token,
                recorded_at=now,
                evidence={
                    "external_operation_id": operation_id,
                    "reason": reason,
                },
            )
            return self._decode(self._load_row(connection, execution_id))

    async def cancel_pre_dispatch(
        self,
        execution_id: str,
        *,
        now: datetime,
    ) -> tuple[bool, ProtectedExecutionRecord]:
        with self._transaction() as connection:
            row = self._load_row(connection, execution_id)
            status = ProtectedExecutionStatus(cast(str, row["status"]))
            if status in {
                ProtectedExecutionStatus.SUCCEEDED,
                ProtectedExecutionStatus.FAILED,
            }:
                return False, self._decode(row)
            if bool(row["dispatch_started"]):
                return False, self._decode(row)
            if status not in {
                ProtectedExecutionStatus.INTENT,
                ProtectedExecutionStatus.EXECUTING,
            }:
                return False, self._decode(row)
            invalidated_fence = int(row["fence_token"]) + 1
            connection.execute(
                """
                UPDATE protected_executions
                SET status = ?, entitlement_state = ?, cancel_requested = 1,
                    lease_owner = NULL, lease_expires_at = NULL, fence_token = ?,
                    result_json = ?, updated_at = ?
                WHERE execution_id = ?
                """,
                (
                    ProtectedExecutionStatus.FAILED.value,
                    EntitlementState.RELEASED.value,
                    invalidated_fence,
                    canonical_json({"cancelled": "pre-dispatch"}),
                    _time(now),
                    execution_id,
                ),
            )
            self._event(
                connection,
                execution_id=execution_id,
                event_type="pre-dispatch-cancelled",
                from_status=status,
                to_status=ProtectedExecutionStatus.FAILED,
                fence_token=invalidated_fence,
                recorded_at=now,
                evidence={
                    "dispatch_proven_absent": True,
                    "entitlement_state": EntitlementState.RELEASED.value,
                },
            )
            return True, self._decode(self._load_row(connection, execution_id))

    async def fail_pre_dispatch(
        self,
        execution_id: str,
        *,
        now: datetime,
        reason: str,
    ) -> tuple[bool, ProtectedExecutionRecord]:
        """Terminalize a proven admission failure before any connector call.

        This is intentionally distinct from user cancellation: the durable
        event tells an operator why the effect was never dispatched while the
        invalidated fence prevents a stale pre-dispatch worker from continuing.
        """

        if type(reason) is not str or not reason:
            raise ValueError("pre-dispatch failure reason must be a non-empty string")
        with self._transaction() as connection:
            row = self._load_row(connection, execution_id)
            status = ProtectedExecutionStatus(cast(str, row["status"]))
            if status in {
                ProtectedExecutionStatus.SUCCEEDED,
                ProtectedExecutionStatus.FAILED,
            }:
                return False, self._decode(row)
            if bool(row["dispatch_started"]):
                return False, self._decode(row)
            if status not in {
                ProtectedExecutionStatus.INTENT,
                ProtectedExecutionStatus.EXECUTING,
            }:
                return False, self._decode(row)
            invalidated_fence = int(row["fence_token"]) + 1
            connection.execute(
                """
                UPDATE protected_executions
                SET status = ?, entitlement_state = ?, lease_owner = NULL,
                    lease_expires_at = NULL, fence_token = ?, result_json = ?,
                    updated_at = ?
                WHERE execution_id = ?
                """,
                (
                    ProtectedExecutionStatus.FAILED.value,
                    EntitlementState.RELEASED.value,
                    invalidated_fence,
                    canonical_json({"pre_dispatch_failure": reason}),
                    _time(now),
                    execution_id,
                ),
            )
            self._event(
                connection,
                execution_id=execution_id,
                event_type="pre-dispatch-admission-failed",
                from_status=status,
                to_status=ProtectedExecutionStatus.FAILED,
                fence_token=invalidated_fence,
                recorded_at=now,
                evidence={
                    "dispatch_proven_absent": True,
                    "entitlement_state": EntitlementState.RELEASED.value,
                    "reason": reason,
                },
            )
            return True, self._decode(self._load_row(connection, execution_id))

    async def request_post_dispatch_cancel(
        self,
        execution_id: str,
        *,
        now: datetime,
    ) -> ProtectedExecutionRecord:
        with self._transaction() as connection:
            row = self._load_row(connection, execution_id)
            status = ProtectedExecutionStatus(cast(str, row["status"]))
            if not bool(row["dispatch_started"]):
                raise ProtectedExecutionError("post-dispatch cancel requires dispatch proof")
            if status not in {
                ProtectedExecutionStatus.EXECUTING,
                ProtectedExecutionStatus.OUTCOME_UNKNOWN,
            }:
                return self._decode(row)
            connection.execute(
                """
                UPDATE protected_executions SET cancel_requested = 1, updated_at = ?
                WHERE execution_id = ?
                """,
                (_time(now), execution_id),
            )
            self._event(
                connection,
                execution_id=execution_id,
                event_type="post-dispatch-cancel-requested",
                from_status=status,
                to_status=status,
                recorded_at=now,
                evidence={"best_effort": True},
            )
            return self._decode(self._load_row(connection, execution_id))

    async def record_reconciliation_attempt(
        self,
        execution_id: str,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
        evidence: Mapping[str, JsonValue],
    ) -> None:
        with self._transaction() as connection:
            row = self._load_row(connection, execution_id)
            status = self._current_fence(
                row,
                worker_id=worker_id,
                fence_token=fence_token,
                now=now,
            )
            self._event(
                connection,
                execution_id=execution_id,
                event_type="reconciliation-attempted",
                from_status=status,
                to_status=status,
                worker_id=worker_id,
                fence_token=fence_token,
                recorded_at=now,
                evidence=evidence,
            )

    async def events(self, execution_id: str) -> tuple[ProtectedExecutionEvent, ...]:
        connection = self._connect()
        try:
            self._load_row(connection, execution_id)
            rows = connection.execute(
                """
                SELECT * FROM protected_execution_events
                WHERE execution_id = ? ORDER BY sequence
                """,
                (execution_id,),
            ).fetchall()
            return tuple(
                ProtectedExecutionEvent(
                    sequence=int(row["sequence"]),
                    execution_id=cast(str, row["execution_id"]),
                    event_type=cast(str, row["event_type"]),
                    from_status=(
                        None
                        if row["from_status"] is None
                        else ProtectedExecutionStatus(cast(str, row["from_status"]))
                    ),
                    to_status=ProtectedExecutionStatus(cast(str, row["to_status"])),
                    worker_id=cast(str | None, row["worker_id"]),
                    fence_token=(None if row["fence_token"] is None else int(row["fence_token"])),
                    recorded_at=_parse_time(row["recorded_at"]),
                    evidence=_json_object(row["evidence_json"], "event evidence"),
                )
                for row in rows
            )
        finally:
            connection.close()


__all__ = ["SqliteProtectedExecutionStore"]
