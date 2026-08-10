"""Startup recovery for durable protected executions."""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass

from masugate.protected_execution.errors import ProtectedExecutionBusy
from masugate.protected_execution.model import (
    ProtectedExecutionRecord,
    ProtectedExecutionStatus,
)
from masugate.protected_execution.runner import ProtectedExecutionRunner


@dataclass(frozen=True)
class RecoveryReport:
    scanned: int
    recovered: tuple[ProtectedExecutionRecord, ...]
    skipped: tuple[str, ...]
    errors: tuple[tuple[str, str], ...]


class ProtectedExecutionRecovery:
    """Recover safe work and query ambiguous work without blind redispatch."""

    def __init__(self, runner: ProtectedExecutionRunner) -> None:
        self.runner = runner

    async def recover(
        self,
        *,
        execution_ids: Collection[str] | None = None,
    ) -> RecoveryReport:
        """Recover the caller's durable execution set without touching others.

        A provider can share a generic protected-execution store with other
        providers.  Its startup worker must therefore be able to hand the
        generic recovery primitive the exact outbox-derived identities it owns
        rather than accidentally reconciling unrelated connector work.
        """

        snapshots = await self.runner.store.recoverable()
        if execution_ids is not None:
            selected = frozenset(execution_ids)
            snapshots = tuple(
                snapshot for snapshot in snapshots if snapshot.execution_id in selected
            )
        recovered: list[ProtectedExecutionRecord] = []
        skipped: list[str] = []
        errors: list[tuple[str, str]] = []
        worker_id = f"{self.runner.worker_id}:recovery"
        for snapshot in snapshots:
            try:
                current = await self.runner.store.get(snapshot.execution_id)
                if current.status is ProtectedExecutionStatus.INTENT:
                    recovered.append(await self.runner.start(current.binding))
                    continue
                if current.status is ProtectedExecutionStatus.OUTCOME_UNKNOWN:
                    recovered.append(await self.runner.reconcile(current.execution_id))
                    continue
                if current.status is not ProtectedExecutionStatus.EXECUTING:
                    skipped.append(current.execution_id)
                    continue
                now = self.runner.clock()
                if current.lease_expires_at is None or current.lease_expires_at > now:
                    skipped.append(current.execution_id)
                    continue
                claimed = await self.runner.store.claim_expired_execution(
                    current.execution_id,
                    worker_id=worker_id,
                    now=now,
                    lease_duration=self.runner.lease_duration,
                )
                if claimed.status is ProtectedExecutionStatus.OUTCOME_UNKNOWN:
                    recovered.append(await self.runner.reconcile(claimed.execution_id))
                elif claimed.receipt is not None:
                    recovered.append(
                        await self.runner.store.finalize_receipt(
                            claimed.execution_id,
                            worker_id=worker_id,
                            fence_token=claimed.fence_token,
                            now=self.runner.clock(),
                        )
                    )
                else:
                    recovered.append(
                        await self.runner.resume_claimed_dispatch(
                            claimed,
                            worker_id=worker_id,
                        )
                    )
            except ProtectedExecutionBusy:
                # Another process won the transaction/fence race.
                skipped.append(snapshot.execution_id)
            except Exception as exc:  # keep startup recovery progressing/auditable
                errors.append((snapshot.execution_id, type(exc).__name__))
        return RecoveryReport(
            scanned=len(snapshots),
            recovered=tuple(recovered),
            skipped=tuple(skipped),
            errors=tuple(errors),
        )


__all__ = ["ProtectedExecutionRecovery", "RecoveryReport"]
