"""Framework-neutral durable runner for provider-owned external effects."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime, timedelta

from masugate.model import JsonValue
from masugate.protected_execution.connector import ProtectedConnector
from masugate.protected_execution.errors import (
    ConnectorContractError,
    ConnectorOutcomeUnknown,
    ProtectedExecutionBusy,
    StaleFenceError,
)
from masugate.protected_execution.model import (
    ConnectorEvidence,
    ConnectorOutcome,
    ProtectedExecutionAuthority,
    ProtectedExecutionBinding,
    ProtectedExecutionRecord,
    ProtectedExecutionStatus,
)
from masugate.protected_execution.store import ProtectedExecutionStore


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _contract_error_evidence(
    evidence: object,
    error: Exception,
) -> dict[str, JsonValue]:
    """Build safe audit data even when an adapter returns the wrong type."""

    audit: dict[str, JsonValue] = {"error": type(error).__name__}
    if isinstance(evidence, ConnectorEvidence):
        audit.update(
            {
                "connector_evidence_id": evidence.evidence_id,
                "external_operation_id": evidence.external_operation_id,
                "outcome": evidence.outcome.value,
            }
        )
    else:
        audit["returned_type"] = type(evidence).__name__
    return audit


class ProtectedExecutionRunner:
    """Execute one bounded connector without holding a DB transaction over I/O."""

    def __init__(
        self,
        store: ProtectedExecutionStore,
        connector: ProtectedConnector,
        authority: ProtectedExecutionAuthority,
        *,
        worker_id: str,
        lease_duration: timedelta = timedelta(seconds=30),
        clock: Callable[[], datetime] = _utc_now,
    ) -> None:
        if not worker_id or worker_id.strip() != worker_id:
            raise ValueError("protected runner worker_id must be canonical")
        if lease_duration <= timedelta(0):
            raise ValueError("protected runner lease duration must be positive")
        self.store = store
        self.connector = connector
        self.authority = authority
        self.worker_id = worker_id
        self.lease_duration = lease_duration
        self.clock = clock
        self._dispatch_admission: Callable[[ProtectedExecutionBinding], Awaitable[None]] | None = (
            None
        )

    def bind_dispatch_admission(
        self,
        admission: Callable[[ProtectedExecutionBinding], Awaitable[None]],
    ) -> None:
        """Bind one provider-owned durable admission check before any dispatch.

        The generic runner deliberately does not know which durable provider
        record authorizes a binding.  Providers with an outbox can bind that
        knowledge once; framework-neutral uses may leave the hook unbound.
        """

        if not callable(admission):
            raise TypeError("protected dispatch admission must be callable")
        if self._dispatch_admission is not None:
            raise ValueError("protected dispatch admission is already bound")
        self._dispatch_admission = admission

    def append_dispatch_admission(
        self,
        admission: Callable[[ProtectedExecutionBinding], Awaitable[None]],
    ) -> None:
        """Add one trusted admission after an already-bound worker admission.

        A worker first proves that an execution has a committed connector
        handoff; a provider then proves that its own durable outbox still
        authorizes the same binding. Both facts are required before dispatch.
        This is intentionally append-only and unavailable until the first
        admission has already been installed.
        """

        if not callable(admission):
            raise TypeError("protected dispatch admission must be callable")
        if self._dispatch_admission is None:
            raise ValueError("protected dispatch admission must be bound before composition")
        existing = self._dispatch_admission

        async def composed(binding: ProtectedExecutionBinding) -> None:
            await existing(binding)
            await admission(binding)

        self._dispatch_admission = composed

    async def _require_dispatch_admission(
        self,
        binding: ProtectedExecutionBinding,
    ) -> None:
        if self._dispatch_admission is not None:
            await self._dispatch_admission(binding)

    def _validate_connector(self, binding: ProtectedExecutionBinding) -> None:
        try:
            self.authority.validate(binding)
        except ValueError as exc:
            raise ConnectorContractError(
                "execution binding does not match its assembled provider authority"
            ) from exc
        if self.connector.connector_id != binding.connector_id:
            raise ConnectorContractError("runner connector does not match execution binding")

    async def _terminal_from_evidence(
        self,
        record: ProtectedExecutionRecord,
        evidence: ConnectorEvidence,
        *,
        worker_id: str,
        fence_token: int,
    ) -> ProtectedExecutionRecord:
        try:
            evidence.validate_for(
                record.binding,
                expected_external_operation_id=record.external_operation_id,
            )
        except (TypeError, ValueError) as exc:
            await self.store.finish_reconciliation_unknown(
                record.execution_id,
                worker_id=worker_id,
                fence_token=fence_token,
                now=self.clock(),
                reason="connector-contract-error",
            )
            raise ConnectorContractError("connector returned mismatched evidence") from exc
        if evidence.outcome is ConnectorOutcome.UNKNOWN:
            return await self.store.finish_reconciliation_unknown(
                record.execution_id,
                worker_id=worker_id,
                fence_token=fence_token,
                now=self.clock(),
                reason="connector-reported-unknown",
                external_operation_id=evidence.external_operation_id,
            )
        try:
            receipt = await self.store.record_receipt(
                record.execution_id,
                evidence,
                worker_id=worker_id,
                fence_token=fence_token,
                now=self.clock(),
            )
            return await self.store.finalize_receipt(
                receipt.execution_id,
                worker_id=worker_id,
                fence_token=fence_token,
                now=self.clock(),
            )
        except StaleFenceError:
            # Cancellation/recovery may have fenced this worker while the
            # connector call was in flight. It must not write a terminal result.
            return await self.store.get(record.execution_id)

    async def start(
        self,
        binding: ProtectedExecutionBinding,
    ) -> ProtectedExecutionRecord:
        """Persist intent, dispatch once, then record receipt and terminal state."""

        self._validate_connector(binding)
        await self._require_dispatch_admission(binding)
        record = await self.store.create_intent(binding, now=self.clock())
        if record.status in {
            ProtectedExecutionStatus.SUCCEEDED,
            ProtectedExecutionStatus.FAILED,
            ProtectedExecutionStatus.OUTCOME_UNKNOWN,
        }:
            return record
        if record.status is ProtectedExecutionStatus.EXECUTING:
            raise ProtectedExecutionBusy("protected execution already has a dispatch lease")
        claimed = await self.store.claim_dispatch(
            record.execution_id,
            worker_id=self.worker_id,
            now=self.clock(),
            lease_duration=self.lease_duration,
        )
        return await self.resume_claimed_dispatch(claimed, worker_id=self.worker_id)

    async def resume_claimed_dispatch(
        self,
        claimed: ProtectedExecutionRecord,
        *,
        worker_id: str,
    ) -> ProtectedExecutionRecord:
        """Dispatch an already fenced pre-dispatch record during normal/recovery work."""

        self._validate_connector(claimed.binding)
        await self._require_dispatch_admission(claimed.binding)
        if (
            claimed.status is not ProtectedExecutionStatus.EXECUTING
            or claimed.dispatch_started
            or claimed.lease_owner != worker_id
        ):
            raise ProtectedExecutionBusy("record is not a claimed pre-dispatch execution")
        try:
            dispatched = await self.store.mark_dispatch_started(
                claimed.execution_id,
                worker_id=worker_id,
                fence_token=claimed.fence_token,
                now=self.clock(),
            )
        except StaleFenceError:
            # A pre-dispatch cancellation invalidated the fence and proved no
            # connector call occurred.
            return await self.store.get(claimed.execution_id)

        try:
            evidence = await self.connector.execute(
                dispatched.binding,
                idempotency_key=dispatched.binding.provider_idempotency_key,
                fence_token=dispatched.fence_token,
            )
        except ConnectorOutcomeUnknown as exc:
            try:
                return await self.store.mark_outcome_unknown(
                    dispatched.execution_id,
                    worker_id=worker_id,
                    fence_token=dispatched.fence_token,
                    now=self.clock(),
                    reason="connector-outcome-unknown",
                    external_operation_id=exc.external_operation_id,
                )
            except StaleFenceError:
                return await self.store.get(dispatched.execution_id)
        except TimeoutError:
            try:
                return await self.store.mark_outcome_unknown(
                    dispatched.execution_id,
                    worker_id=worker_id,
                    fence_token=dispatched.fence_token,
                    now=self.clock(),
                    reason="connector-timeout",
                )
            except StaleFenceError:
                return await self.store.get(dispatched.execution_id)
        except Exception as exc:
            # Once dispatch_started is durable, an arbitrary adapter failure
            # cannot prove the remote effect did not happen.
            try:
                return await self.store.mark_outcome_unknown(
                    dispatched.execution_id,
                    worker_id=worker_id,
                    fence_token=dispatched.fence_token,
                    now=self.clock(),
                    reason=f"connector-exception:{type(exc).__name__}",
                )
            except StaleFenceError:
                return await self.store.get(dispatched.execution_id)
        return await self._terminal_from_evidence(
            dispatched,
            evidence,
            worker_id=worker_id,
            fence_token=dispatched.fence_token,
        )

    async def _finish_unknown_attempt(
        self,
        record: ProtectedExecutionRecord,
        *,
        worker_id: str,
        reason: str,
        evidence: Mapping[str, JsonValue],
        external_operation_id: str | None = None,
    ) -> ProtectedExecutionRecord:
        attempt_evidence = dict(evidence)
        if external_operation_id is not None:
            attempt_evidence["external_operation_id"] = external_operation_id
        await self.store.record_reconciliation_attempt(
            record.execution_id,
            worker_id=worker_id,
            fence_token=record.fence_token,
            now=self.clock(),
            evidence=attempt_evidence,
        )
        if (
            record.external_operation_id is not None
            and external_operation_id is not None
            and external_operation_id != record.external_operation_id
        ):
            await self.store.finish_reconciliation_unknown(
                record.execution_id,
                worker_id=worker_id,
                fence_token=record.fence_token,
                now=self.clock(),
                reason="external-operation-identity-contract-error",
            )
            raise ConnectorContractError("connector changed the external-operation identity")
        return await self.store.finish_reconciliation_unknown(
            record.execution_id,
            worker_id=worker_id,
            fence_token=record.fence_token,
            now=self.clock(),
            reason=reason,
            external_operation_id=external_operation_id,
        )

    async def reconcile(self, execution_id: str) -> ProtectedExecutionRecord:
        """Use status evidence to resolve unknown; never redispatch the effect."""

        current = await self.store.get(execution_id)
        self._validate_connector(current.binding)
        if current.status in {
            ProtectedExecutionStatus.SUCCEEDED,
            ProtectedExecutionStatus.FAILED,
        }:
            return current
        if current.status is not ProtectedExecutionStatus.OUTCOME_UNKNOWN:
            raise ProtectedExecutionBusy(
                f"protected execution cannot reconcile from {current.status.value}"
            )
        worker_id = f"{self.worker_id}:reconcile"
        claimed = await self.store.claim_reconciliation(
            execution_id,
            worker_id=worker_id,
            now=self.clock(),
            lease_duration=self.lease_duration,
        )
        if claimed.receipt is not None:
            try:
                return await self.store.finalize_receipt(
                    claimed.execution_id,
                    worker_id=worker_id,
                    fence_token=claimed.fence_token,
                    now=self.clock(),
                )
            except StaleFenceError:
                return await self.store.get(claimed.execution_id)
        if not self.connector.capabilities.status_query:
            return await self._finish_unknown_attempt(
                claimed,
                worker_id=worker_id,
                reason="connector-status-query-unsupported",
                evidence={"status_query": "unsupported"},
            )
        try:
            connector_evidence = await self.connector.query_status(
                claimed.binding,
                idempotency_key=claimed.binding.provider_idempotency_key,
                external_operation_id=claimed.external_operation_id,
            )
        except (ConnectorOutcomeUnknown, TimeoutError) as exc:
            return await self._finish_unknown_attempt(
                claimed,
                worker_id=worker_id,
                reason="status-query-unknown",
                evidence={"error": type(exc).__name__},
                external_operation_id=getattr(exc, "external_operation_id", None),
            )
        except Exception as exc:
            return await self._finish_unknown_attempt(
                claimed,
                worker_id=worker_id,
                reason="status-query-error",
                evidence={"error": type(exc).__name__},
            )
        try:
            connector_evidence.validate_for(
                claimed.binding,
                expected_external_operation_id=claimed.external_operation_id,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            await self._finish_unknown_attempt(
                claimed,
                worker_id=worker_id,
                reason="status-evidence-contract-error",
                evidence=_contract_error_evidence(connector_evidence, exc),
            )
            raise ConnectorContractError("status query returned mismatched evidence") from exc
        await self.store.record_reconciliation_attempt(
            claimed.execution_id,
            worker_id=worker_id,
            fence_token=claimed.fence_token,
            now=self.clock(),
            evidence={
                "connector_evidence_id": connector_evidence.evidence_id,
                "outcome": connector_evidence.outcome.value,
            },
        )
        return await self._terminal_from_evidence(
            claimed,
            connector_evidence,
            worker_id=worker_id,
            fence_token=claimed.fence_token,
        )

    async def cancel(self, execution_id: str) -> ProtectedExecutionRecord:
        """Release only with pre-dispatch proof or trustworthy connector evidence."""

        cancelled, record = await self.store.cancel_pre_dispatch(
            execution_id,
            now=self.clock(),
        )
        if cancelled or record.status in {
            ProtectedExecutionStatus.SUCCEEDED,
            ProtectedExecutionStatus.FAILED,
        }:
            return record
        await self.store.request_post_dispatch_cancel(execution_id, now=self.clock())
        worker_id = f"{self.worker_id}:cancel"
        claimed = await self.store.claim_cancellation(
            execution_id,
            worker_id=worker_id,
            now=self.clock(),
            lease_duration=self.lease_duration,
        )
        if claimed.receipt is not None:
            try:
                return await self.store.finalize_receipt(
                    claimed.execution_id,
                    worker_id=worker_id,
                    fence_token=claimed.fence_token,
                    now=self.clock(),
                )
            except StaleFenceError:
                return await self.store.get(claimed.execution_id)
        if not self.connector.capabilities.cancellation:
            return await self._finish_unknown_attempt(
                claimed,
                worker_id=worker_id,
                reason="connector-cancellation-unsupported",
                evidence={"cancellation": "unsupported"},
            )
        try:
            connector_evidence = await self.connector.cancel(
                claimed.binding,
                idempotency_key=claimed.binding.provider_idempotency_key,
                external_operation_id=claimed.external_operation_id,
            )
        except (ConnectorOutcomeUnknown, TimeoutError) as exc:
            return await self._finish_unknown_attempt(
                claimed,
                worker_id=worker_id,
                reason="post-dispatch-cancellation-unknown",
                evidence={"error": type(exc).__name__},
                external_operation_id=getattr(exc, "external_operation_id", None),
            )
        except Exception as exc:
            return await self._finish_unknown_attempt(
                claimed,
                worker_id=worker_id,
                reason="post-dispatch-cancellation-error",
                evidence={"error": type(exc).__name__},
            )
        try:
            connector_evidence.validate_for(
                claimed.binding,
                expected_external_operation_id=claimed.external_operation_id,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            await self._finish_unknown_attempt(
                claimed,
                worker_id=worker_id,
                reason="cancellation-evidence-contract-error",
                evidence=_contract_error_evidence(connector_evidence, exc),
            )
            raise ConnectorContractError("cancellation returned mismatched evidence") from exc
        await self.store.record_reconciliation_attempt(
            claimed.execution_id,
            worker_id=worker_id,
            fence_token=claimed.fence_token,
            now=self.clock(),
            evidence={
                "cancellation": "connector-evidence",
                "connector_evidence_id": connector_evidence.evidence_id,
                "outcome": connector_evidence.outcome.value,
            },
        )
        return await self._terminal_from_evidence(
            claimed,
            connector_evidence,
            worker_id=worker_id,
            fence_token=claimed.fence_token,
        )


__all__ = ["ProtectedExecutionRunner"]
