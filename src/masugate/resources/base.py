"""Async protocols implemented by resource-owned governed adapters."""

from __future__ import annotations

import base64
import binascii
import json
from contextlib import AbstractAsyncContextManager
from datetime import datetime
from typing import Protocol, runtime_checkable

from masugate.contracts import ReservationCapability, ResourceSession
from masugate.model import (
    ActionRequest,
    JsonValue,
    OperationResult,
    PendingOperation,
    MasuGateMode,
)

_IDEMPOTENCY_SCOPE_PREFIX = "idempotency:v1:"


def encode_idempotency_scope(principal_id: str, idempotency_key: str) -> str:
    """Encode a collision-free internal lock scope for one principal-owned key.

    The caller-visible key remains unchanged in requests and audit records.  The
    versioned base64url payload is only an internal advisory-lock namespace and
    can be decoded by a provider that folds replay lookup into lock admission.
    """

    if not principal_id or not idempotency_key:
        raise ValueError("principal id and idempotency key must be non-empty")
    payload = json.dumps(
        [principal_id, idempotency_key],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    return f"{_IDEMPOTENCY_SCOPE_PREFIX}{encoded}"


def decode_idempotency_scope(scope: str) -> tuple[str, str] | None:
    """Decode :func:`encode_idempotency_scope`, or return ``None`` for other scopes."""

    if not scope.startswith(_IDEMPOTENCY_SCOPE_PREFIX):
        return None
    encoded = scope.removeprefix(_IDEMPOTENCY_SCOPE_PREFIX)
    try:
        padding = "=" * (-len(encoded) % 4)
        raw = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
        value = json.loads(raw.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("malformed idempotency scope") from exc
    if (
        not isinstance(value, list)
        or len(value) != 2
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise ValueError("malformed idempotency scope")
    identity = (value[0], value[1])
    if encode_idempotency_scope(*identity) != scope:
        raise ValueError("non-canonical idempotency scope")
    return identity


@runtime_checkable
class GovernedResource(Protocol):
    """Core capability: open a coordinated session and read/record results."""

    def open_session(self, *, write: bool) -> AbstractAsyncContextManager[ResourceSession]:
        """Enter a resource transaction/session (``async with``).

        Not ``async def``: it returns the async context manager object
        synchronously; entering it (``__aenter__``) is what awaits. This matches
        the ``async with resource.open_session(write=True) as s:`` call shape.
        """
        ...

    async def load_result(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> OperationResult | None: ...

    async def record_result(
        self,
        session: ResourceSession,
        request: ActionRequest,
        result: OperationResult,
        mode: MasuGateMode,
    ) -> None: ...


@runtime_checkable
class WeakIsolationResource(Protocol):
    def open_uncoordinated_session(
        self,
        *,
        write: bool,
    ) -> AbstractAsyncContextManager[ResourceSession]: ...


@runtime_checkable
class AdmissionCertifier(Protocol):
    """Stamps the server-certified admission timestamp for an operation (0.12).

    Called by the coordinator after scope locks are acquired; the returned
    timestamp is the single time anchor for the operation (window reads,
        effect timestamps). It prevents caller-controlled timestamps from
        governing the protected operation's time anchor.
    """

    async def certify_admission(self, session: ResourceSession) -> datetime: ...


@runtime_checkable
class AuthorizationEvaluationCertifier(Protocol):
    """Returns the provider clock at an actual protected evaluation event."""

    async def certify_authorization_evaluation(
        self,
        session: ResourceSession,
    ) -> datetime: ...


@runtime_checkable
class ScopedLockResource(Protocol):
    async def acquire_scoped_locks(
        self,
        session: ResourceSession,
        scopes: frozenset[str],
    ) -> float | None: ...


@runtime_checkable
class ScopeHoldResource(Protocol):
    """Scope holds for MASUGATE_SCOPED_HOLD (0.14).

    DELTA from the frozen surface: the frozen `wait_for_scope_holds` was a 5 ms
    busy-poll that blocked until holds cleared. The async core replaces it with
    `has_active_scope_hold` — a single point-in-time check the coordinator runs
    INSIDE the advisory-locked transaction, so a same-scope competitor is denied
    immediately (no busy-poll, no unbounded wait for a human). This is what
    closes the frozen check-before-lock TOCTOU without an in-process lock.
    """

    async def has_active_scope_hold(
        self,
        session: ResourceSession,
        scopes: frozenset[str],
        *,
        owner_pending_id: str | None = None,
    ) -> bool: ...

    async def create_scope_holds(
        self,
        session: ResourceSession,
        pending_id: str,
        scopes: frozenset[str],
    ) -> None: ...

    async def release_scope_holds(
        self,
        session: ResourceSession,
        pending_id: str,
    ) -> None: ...


@runtime_checkable
class ExpertTransactionResource(Protocol):
    async def execute_expert_transaction(
        self,
        request: ActionRequest,
        mode: MasuGateMode,
        *,
        service_delay_ms: float = 0.0,
    ) -> OperationResult: ...


@runtime_checkable
class StoredProcedureTransactionResource(Protocol):
    async def execute_stored_procedure_transaction(
        self,
        request: ActionRequest,
        mode: MasuGateMode,
        *,
        service_delay_ms: float = 0.0,
    ) -> OperationResult: ...


@runtime_checkable
class ReservationResource(Protocol):
    def reservation_capability(self, action: str) -> ReservationCapability | None: ...

    def reservation_scopes(self, request: ActionRequest) -> frozenset[str]: ...

    async def reserve_for_request(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> str | None: ...

    async def validate_reservation(
        self,
        session: ResourceSession,
        reservation_id: str,
        request: ActionRequest,
    ) -> bool: ...

    async def consume_reservation(
        self,
        session: ResourceSession,
        reservation_id: str,
    ) -> None: ...

    async def release_reservation(
        self,
        session: ResourceSession,
        reservation_id: str,
    ) -> None: ...

    async def release_reservation_for_request(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> str | None:
        """Release and return the held entitlement bound to ``request``.

        Cleanup of a durable pending record must not follow its persisted
        reservation identifier blindly: a corrupt record could point at another
        operation's entitlement.  Providers therefore locate the entitlement by
        their canonical exact-request binding and release only that row.
        """
        ...


@runtime_checkable
class PendingOperationResource(Protocol):
    async def load_pending_operation(
        self,
        session: ResourceSession,
        pending_id: str,
    ) -> PendingOperation | None: ...

    async def load_pending_result(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> OperationResult | None: ...

    async def load_resolved_pending_result(
        self,
        session: ResourceSession,
        pending_id: str,
    ) -> OperationResult | None:
        """Return the terminal result for an already-resolved pending id.

        Resolution itself is idempotent at the protocol boundary.  A caller
        retrying ``POST /pending/{id}/resolve`` therefore needs a typed
        provider query that distinguishes a resolved operation from an unknown
        pending id without exposing provider tables to the coordinator.
        """
        ...

    async def record_pending_operation(
        self,
        session: ResourceSession,
        request: ActionRequest,
        result: OperationResult,
        mode: MasuGateMode,
    ) -> None: ...

    async def resolve_pending_operation(
        self,
        session: ResourceSession,
        pending_id: str,
        result: OperationResult,
        evidence: dict[str, JsonValue],
    ) -> None: ...


@runtime_checkable
class GovernanceQueryResource(GovernedResource, PendingOperationResource, Protocol):
    """Durable read-side queries used by the ``masugated`` protocol surface.

    The HTTP server needs the same session and pending-operation capabilities
    as the coordinator, plus resource-owned queries for visible approvals,
    pending ownership, and complete governance records. Keeping these on a
    typed capability avoids coupling ``masugated`` to PostgreSQL-specific SQL or
    record codecs.
    """

    async def list_pending_operations(
        self,
        session: ResourceSession,
        *,
        principal_id: str | None = None,
    ) -> tuple[PendingOperation, ...]: ...

    async def load_pending_owner(
        self,
        session: ResourceSession,
        pending_id: str,
    ) -> str | None:
        """Return the certified owner of a pending or resolved operation."""
        ...

    async def load_governance_record(
        self,
        session: ResourceSession,
        operation_id: str,
    ) -> dict[str, JsonValue] | None: ...
