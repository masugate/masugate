"""Async resource-adapter protocols for the MasuGate product core."""

from masugate.resources.base import (
    AdmissionCertifier,
    AuthorizationEvaluationCertifier,
    ExpertTransactionResource,
    GovernanceQueryResource,
    GovernedResource,
    PendingOperationResource,
    ReservationResource,
    ScopedLockResource,
    ScopeHoldResource,
    StoredProcedureTransactionResource,
    WeakIsolationResource,
    decode_idempotency_scope,
    encode_idempotency_scope,
)

__all__ = [
    "AdmissionCertifier",
    "AuthorizationEvaluationCertifier",
    "ExpertTransactionResource",
    "GovernanceQueryResource",
    "GovernedResource",
    "PendingOperationResource",
    "ReservationResource",
    "ScopeHoldResource",
    "ScopedLockResource",
    "StoredProcedureTransactionResource",
    "WeakIsolationResource",
    "decode_idempotency_scope",
    "encode_idempotency_scope",
]
