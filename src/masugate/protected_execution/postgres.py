"""PostgreSQL durable store for protected-execution recovery.

The transition implementation is deliberately shared with the SQLite oracle.
Short synchronous libpq transactions run in worker threads so the async runner
never blocks its event loop and connector I/O remains outside every transaction.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine, Mapping, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

import psycopg
from psycopg import Connection
from psycopg.rows import dict_row

from masugate.model import JsonValue
from masugate.protected_execution.model import (
    ConnectorEvidence,
    ProtectedExecutionBinding,
    ProtectedExecutionEvent,
    ProtectedExecutionRecord,
)
from masugate.protected_execution.store import SqliteProtectedExecutionStore


class _PostgresConnection:
    """Translate the store's small portable SQL subset to psycopg syntax."""

    def __init__(self, raw: Connection[dict[str, Any]]) -> None:
        self.raw = raw

    def execute(self, sql: str, params: Sequence[object] = ()) -> Any:
        statement = sql.strip()
        if statement == "BEGIN IMMEDIATE":
            # The portable transition engine relies on SQLite's BEGIN IMMEDIATE
            # to serialize read-modify-write transitions.  PostgreSQL's plain
            # BEGIN does not provide that property: two workers could read the
            # same fence and both claim it.  A self-conflicting table lock keeps
            # the shared transition implementation correct and every critical
            # section short; connector I/O is outside this lock.
            self.raw.execute("BEGIN")
            return self.raw.execute("LOCK TABLE protected_executions IN SHARE ROW EXCLUSIVE MODE")
        return self.raw.execute(statement.replace("?", "%s"), tuple(params))

    def commit(self) -> None:
        self.raw.commit()

    def rollback(self) -> None:
        self.raw.rollback()

    def close(self) -> None:
        self.raw.close()


class _SyncPostgresProtectedExecutionStore(SqliteProtectedExecutionStore):
    """Reuse the reviewed transition engine against PostgreSQL transactions."""

    def __init__(self, dsn: str) -> None:
        super().__init__(Path(":postgres:"))
        self.dsn = dsn

    def _connect(self) -> Any:
        raw = cast(
            "Connection[dict[str, Any]]",
            psycopg.connect(self.dsn, row_factory=dict_row),
        )
        return _PostgresConnection(raw)

    async def initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute(
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
                    fence_token BIGINT NOT NULL DEFAULT 0,
                    lease_expires_at TEXT,
                    receipt_json TEXT,
                    result_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(principal_id, idempotency_key),
                    CHECK(dispatch_started IN (0, 1)),
                    CHECK(cancel_requested IN (0, 1)),
                    CHECK(fence_token >= 0)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS protected_execution_events (
                    sequence BIGSERIAL PRIMARY KEY,
                    execution_id TEXT NOT NULL REFERENCES protected_executions(execution_id),
                    event_type TEXT NOT NULL,
                    from_status TEXT,
                    to_status TEXT NOT NULL,
                    worker_id TEXT,
                    fence_token BIGINT,
                    recorded_at TEXT NOT NULL,
                    evidence_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS protected_execution_events_execution
                ON protected_execution_events(execution_id, sequence)
                """
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()


class PostgresProtectedExecutionStore:
    """Non-blocking async facade over the shared PostgreSQL transition store."""

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        self._sync = _SyncPostgresProtectedExecutionStore(dsn)

    async def _call[T](self, operation: Callable[[], Coroutine[Any, Any, T]]) -> T:
        def invoke() -> T:
            return asyncio.run(operation())

        return await asyncio.to_thread(invoke)

    async def initialize(self) -> None:
        await self._call(self._sync.initialize)

    async def create_intent(
        self,
        binding: ProtectedExecutionBinding,
        *,
        now: datetime,
    ) -> ProtectedExecutionRecord:
        return await self._call(lambda: self._sync.create_intent(binding, now=now))

    async def get(self, execution_id: str) -> ProtectedExecutionRecord:
        return await self._call(lambda: self._sync.get(execution_id))

    async def claim_dispatch(
        self,
        execution_id: str,
        *,
        worker_id: str,
        now: datetime,
        lease_duration: timedelta,
    ) -> ProtectedExecutionRecord:
        return await self._call(
            lambda: self._sync.claim_dispatch(
                execution_id,
                worker_id=worker_id,
                now=now,
                lease_duration=lease_duration,
            )
        )

    async def claim_reconciliation(
        self,
        execution_id: str,
        *,
        worker_id: str,
        now: datetime,
        lease_duration: timedelta,
    ) -> ProtectedExecutionRecord:
        return await self._call(
            lambda: self._sync.claim_reconciliation(
                execution_id,
                worker_id=worker_id,
                now=now,
                lease_duration=lease_duration,
            )
        )

    async def claim_cancellation(
        self,
        execution_id: str,
        *,
        worker_id: str,
        now: datetime,
        lease_duration: timedelta,
    ) -> ProtectedExecutionRecord:
        return await self._call(
            lambda: self._sync.claim_cancellation(
                execution_id,
                worker_id=worker_id,
                now=now,
                lease_duration=lease_duration,
            )
        )

    async def claim_expired_execution(
        self,
        execution_id: str,
        *,
        worker_id: str,
        now: datetime,
        lease_duration: timedelta,
    ) -> ProtectedExecutionRecord:
        return await self._call(
            lambda: self._sync.claim_expired_execution(
                execution_id,
                worker_id=worker_id,
                now=now,
                lease_duration=lease_duration,
            )
        )

    async def recoverable(self) -> tuple[ProtectedExecutionRecord, ...]:
        return await self._call(self._sync.recoverable)

    async def mark_dispatch_started(
        self,
        execution_id: str,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
    ) -> ProtectedExecutionRecord:
        return await self._call(
            lambda: self._sync.mark_dispatch_started(
                execution_id,
                worker_id=worker_id,
                fence_token=fence_token,
                now=now,
            )
        )

    async def record_receipt(
        self,
        execution_id: str,
        evidence: ConnectorEvidence,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
    ) -> ProtectedExecutionRecord:
        return await self._call(
            lambda: self._sync.record_receipt(
                execution_id,
                evidence,
                worker_id=worker_id,
                fence_token=fence_token,
                now=now,
            )
        )

    async def finalize_receipt(
        self,
        execution_id: str,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
    ) -> ProtectedExecutionRecord:
        return await self._call(
            lambda: self._sync.finalize_receipt(
                execution_id,
                worker_id=worker_id,
                fence_token=fence_token,
                now=now,
            )
        )

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
        return await self._call(
            lambda: self._sync.mark_outcome_unknown(
                execution_id,
                worker_id=worker_id,
                fence_token=fence_token,
                now=now,
                reason=reason,
                external_operation_id=external_operation_id,
            )
        )

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
        return await self._call(
            lambda: self._sync.finish_reconciliation_unknown(
                execution_id,
                worker_id=worker_id,
                fence_token=fence_token,
                now=now,
                reason=reason,
                external_operation_id=external_operation_id,
            )
        )

    async def cancel_pre_dispatch(
        self,
        execution_id: str,
        *,
        now: datetime,
    ) -> tuple[bool, ProtectedExecutionRecord]:
        return await self._call(lambda: self._sync.cancel_pre_dispatch(execution_id, now=now))

    async def fail_pre_dispatch(
        self,
        execution_id: str,
        *,
        now: datetime,
        reason: str,
    ) -> tuple[bool, ProtectedExecutionRecord]:
        return await self._call(
            lambda: self._sync.fail_pre_dispatch(
                execution_id,
                now=now,
                reason=reason,
            )
        )

    async def request_post_dispatch_cancel(
        self,
        execution_id: str,
        *,
        now: datetime,
    ) -> ProtectedExecutionRecord:
        return await self._call(
            lambda: self._sync.request_post_dispatch_cancel(execution_id, now=now)
        )

    async def record_reconciliation_attempt(
        self,
        execution_id: str,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
        evidence: Mapping[str, JsonValue],
    ) -> None:
        await self._call(
            lambda: self._sync.record_reconciliation_attempt(
                execution_id,
                worker_id=worker_id,
                fence_token=fence_token,
                now=now,
                evidence=evidence,
            )
        )

    async def events(self, execution_id: str) -> tuple[ProtectedExecutionEvent, ...]:
        return await self._call(lambda: self._sync.events(execution_id))


__all__ = ["PostgresProtectedExecutionStore"]
