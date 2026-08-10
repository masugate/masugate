"""Deterministic PostgreSQL fault injection for recovery tests.

The harness trips at coordinator hazard boundaries while the provider's write
transaction is still open.  Connection-loss faults close the checked-out
connection, which makes PostgreSQL roll the entire transaction back exactly as
an abruptly killed worker would.  SQLSTATE faults are raised by PostgreSQL
itself, exercising the provider's ``40001``/``40P01`` classification rather
than faking a :class:`~masugate.errors.RetryableResourceError` in Python.

This is a dev/test helper, not a production extension point.  Product code has
no schedule or failure hooks on its hot path.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from masugate.contracts import ResourceSession
from masugate.model import ActionRequest, JsonValue
from masugate.resources.postgres import AsyncPostgresLedger, PostgresSession


class FaultPoint(StrEnum):
    """Transaction boundaries exercised by the core runtime recovery matrix."""

    MID_EFFECT = "mid_effect"
    BEFORE_RESERVATION_CONSUME = "before_reservation_consume"
    BEFORE_SCOPE_HOLDS = "before_scope_holds"
    ACQUIRE_LOCK_SQLSTATE = "acquire_lock_sqlstate"


class InjectedWorkerCrash(BaseException):
    """Abrupt worker/connection loss, deliberately outside ``Exception``."""

    def __init__(self, point: FaultPoint) -> None:
        super().__init__(f"injected worker crash at {point}")
        self.point = point


@dataclass
class FaultPlan:
    """One armed failpoint, tripped ``remaining`` times before disarming."""

    point: FaultPoint
    remaining: int = 1
    sqlstate: str | None = None
    hits: int = 0

    def __post_init__(self) -> None:
        if self.remaining < 1:
            raise ValueError("fault-plan remaining count must be positive")
        if self.point is FaultPoint.ACQUIRE_LOCK_SQLSTATE:
            if self.sqlstate not in {"40001", "40P01"}:
                raise ValueError("SQLSTATE fault must be 40001 or 40P01")
        elif self.sqlstate is not None:
            raise ValueError("sqlstate is only valid for ACQUIRE_LOCK_SQLSTATE")

    def take(self, point: FaultPoint) -> bool:
        """Consume one matching trip and report whether to inject it."""

        if self.point is not point or self.remaining == 0:
            return False
        self.remaining -= 1
        self.hits += 1
        return True


def _postgres_session(session: ResourceSession) -> PostgresSession:
    if not isinstance(session, PostgresSession):
        raise TypeError("fault harness requires a PostgreSQL resource session")
    return session


class FaultInjectingPostgresLedger(AsyncPostgresLedger):
    """PostgreSQL ledger with a single deterministic, re-armable fault plan."""

    def __init__(
        self,
        dsn: str,
        *,
        plan: FaultPlan | None = None,
        min_size: int = 1,
        max_size: int = 8,
    ) -> None:
        super().__init__(dsn, min_size=min_size, max_size=max_size)
        self.plan = plan

    def arm(self, plan: FaultPlan | None) -> None:
        """Replace the current plan; ``None`` restores normal behavior."""

        self.plan = plan

    def _take(self, point: FaultPoint) -> bool:
        return self.plan is not None and self.plan.take(point)

    async def _crash_connection(
        self,
        session: ResourceSession,
        point: FaultPoint,
    ) -> None:
        pg = _postgres_session(session)
        # Closing an in-flight connection makes PostgreSQL roll back every
        # statement in its open transaction.  Raising BaseException models the
        # worker disappearing instead of taking an application error path.
        await pg.connection.close()
        raise InjectedWorkerCrash(point)

    async def acquire_scoped_locks(
        self,
        session: ResourceSession,
        scopes: frozenset[str],
    ) -> float | None:
        if self._take(FaultPoint.ACQUIRE_LOCK_SQLSTATE):
            assert self.plan is not None and self.plan.sqlstate is not None
            sqlstate = self.plan.sqlstate
            pg = _postgres_session(session)
            # The code is selected from a closed set in FaultPlan.__post_init__.
            # PostgreSQL creates the real psycopg SerializationFailure or
            # DeadlockDetected instance; AsyncPostgresLedger._session maps it.
            await pg.execute(
                "DO $masugate$ BEGIN RAISE EXCEPTION 'injected retry' "
                f"USING ERRCODE = '{sqlstate}'; END $masugate$"
            )
        return await super().acquire_scoped_locks(session, scopes)

    async def execute_transfer(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> dict[str, JsonValue]:
        if self._take(FaultPoint.MID_EFFECT):
            # The production transfer is deliberately one atomic SQL command,
            # so it has no externally visible halfway point.  For the recovery
            # teeth-check, perform only its first mutation (the debit) and then
            # kill the connection before credit/log/version writes.  A clean
            # restart must observe that even this partial statement sequence
            # was rolled back.
            pg = _postgres_session(session)
            amount_cents = int(request.arguments["amount_cents"])
            team = str(request.principal.attributes["team"])
            debited = await (
                await pg.execute(
                    "UPDATE accounts SET balance_cents = balance_cents - %s "
                    "WHERE account_id = %s AND team = %s AND balance_cents >= %s "
                    "RETURNING balance_cents",
                    (amount_cents, request.principal.id, team, amount_cents),
                )
            ).fetchone()
            if debited is None:
                raise ValueError("mid-effect fault could not apply its partial debit")
            await self._crash_connection(session, FaultPoint.MID_EFFECT)
        return await super().execute_transfer(session, request)

    async def consume_reservation(
        self,
        session: ResourceSession,
        reservation_id: str,
    ) -> None:
        if self._take(FaultPoint.BEFORE_RESERVATION_CONSUME):
            await self._crash_connection(
                session,
                FaultPoint.BEFORE_RESERVATION_CONSUME,
            )
        await super().consume_reservation(session, reservation_id)

    async def create_scope_holds(
        self,
        session: ResourceSession,
        pending_id: str,
        scopes: frozenset[str],
    ) -> None:
        if self._take(FaultPoint.BEFORE_SCOPE_HOLDS):
            await self._crash_connection(session, FaultPoint.BEFORE_SCOPE_HOLDS)
        await super().create_scope_holds(session, pending_id, scopes)
