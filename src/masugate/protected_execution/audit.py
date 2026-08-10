"""Public audit projection for durable protected executions and recovery."""

from __future__ import annotations

from masugate.model import JsonValue
from masugate.protected_execution.model import (
    ProtectedExecutionEvent,
    ProtectedExecutionRecord,
    canonical_json,
)


def protected_execution_audit(
    record: ProtectedExecutionRecord,
    events: tuple[ProtectedExecutionEvent, ...],
) -> dict[str, JsonValue]:
    """Project one durable execution and its ordered recovery evidence.

    The binding and digest make the projection independently replayable.  The
    dispatch marker, entitlement state, receipt, and ordered events prevent an
    operator or SDK from mistaking an ambiguous external outcome for a safe
    retry or a known failure.
    """

    return {
        "execution_id": record.execution_id,
        "binding_digest": record.binding_digest,
        "binding": record.binding.payload(),
        "binding_canonical_json": canonical_json(record.binding.payload()),
        "status": record.status.value,
        "entitlement_state": record.entitlement_state.value,
        "dispatch_started": record.dispatch_started,
        "cancel_requested": record.cancel_requested,
        "external_operation_id": record.external_operation_id,
        "lease": (
            None
            if record.lease_owner is None
            else {
                "owner": record.lease_owner,
                "fence_token": record.fence_token,
                "expires_at": (
                    record.lease_expires_at.isoformat()
                    if record.lease_expires_at is not None
                    else None
                ),
            }
        ),
        "last_fence_token": record.fence_token,
        "receipt": record.receipt.payload_json() if record.receipt is not None else None,
        "result": dict(record.result),
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "events": [
            {
                "sequence": event.sequence,
                "event_type": event.event_type,
                "from_status": (event.from_status.value if event.from_status is not None else None),
                "to_status": event.to_status.value,
                "worker_id": event.worker_id,
                "fence_token": event.fence_token,
                "recorded_at": event.recorded_at.isoformat(),
                "evidence": dict(event.evidence),
            }
            for event in events
        ],
    }


__all__ = ["protected_execution_audit"]
