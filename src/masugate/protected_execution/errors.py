"""Typed failures for protected external execution."""

from __future__ import annotations

from masugate.errors import MasuGateError


class ProtectedExecutionError(MasuGateError):
    """Base protected-execution failure."""


class ProtectedExecutionConflict(ProtectedExecutionError):
    """A durable identity was reused with different immutable content."""


class ProtectedExecutionBusy(ProtectedExecutionError):
    """Another live lease owns the execution."""


class StaleFenceError(ProtectedExecutionError):
    """A worker attempted a state transition with an obsolete fence."""


class ConnectorContractError(ProtectedExecutionError):
    """Connector behavior/evidence violated its trusted contract."""


class ConnectorOutcomeUnknown(ProtectedExecutionError):
    """Dispatch may have occurred, but no trustworthy terminal evidence exists."""

    def __init__(self, message: str, *, external_operation_id: str | None = None) -> None:
        super().__init__(message)
        self.external_operation_id = external_operation_id


__all__ = [
    "ConnectorContractError",
    "ConnectorOutcomeUnknown",
    "ProtectedExecutionBusy",
    "ProtectedExecutionConflict",
    "ProtectedExecutionError",
    "StaleFenceError",
]
