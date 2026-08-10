"""Durable protected external execution and recovery."""

from masugate.protected_execution.audit import protected_execution_audit
from masugate.protected_execution.connector import ConnectorCapabilities, ProtectedConnector
from masugate.protected_execution.errors import (
    ConnectorContractError,
    ConnectorOutcomeUnknown,
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
    ProtectedExecutionAuthority,
    ProtectedExecutionBinding,
    ProtectedExecutionEvent,
    ProtectedExecutionRecord,
    ProtectedExecutionStatus,
    canonical_json,
)
from masugate.protected_execution.postgres import PostgresProtectedExecutionStore
from masugate.protected_execution.recovery import ProtectedExecutionRecovery, RecoveryReport
from masugate.protected_execution.runner import ProtectedExecutionRunner
from masugate.protected_execution.store import (
    ProtectedExecutionStore,
    SqliteProtectedExecutionStore,
)

__all__ = [
    "ConnectorCapabilities",
    "ConnectorContractError",
    "ConnectorEvidence",
    "ConnectorOutcome",
    "ConnectorOutcomeUnknown",
    "EntitlementState",
    "PolicyBinding",
    "PostgresProtectedExecutionStore",
    "ProtectedConnector",
    "ProtectedExecutionAuthority",
    "ProtectedExecutionBinding",
    "ProtectedExecutionBusy",
    "ProtectedExecutionConflict",
    "ProtectedExecutionError",
    "ProtectedExecutionEvent",
    "ProtectedExecutionRecord",
    "ProtectedExecutionRecovery",
    "ProtectedExecutionRunner",
    "ProtectedExecutionStatus",
    "ProtectedExecutionStore",
    "RecoveryReport",
    "SqliteProtectedExecutionStore",
    "StaleFenceError",
    "canonical_json",
    "protected_execution_audit",
]
