"""Policy-State Serializability checker — the reference verifier.

See README.md in this package for the correctness argument.
"""

from masugate.pss.adapters import budget_history_from_events
from masugate.pss.checker import (
    DecisionValidator,
    DependencyKind,
    PSSDependency,
    PSSVerdict,
    check_pss,
)
from masugate.pss.model import Decision, History, Operation, ScopeAccess, TransitionKind
from masugate.pss.oracle import check_pss_exhaustively

__all__ = [
    "Decision",
    "DecisionValidator",
    "DependencyKind",
    "History",
    "Operation",
    "PSSDependency",
    "PSSVerdict",
    "ScopeAccess",
    "TransitionKind",
    "budget_history_from_events",
    "check_pss",
    "check_pss_exhaustively",
]
