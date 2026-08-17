"""Adapters from recorded budget-operation events to PSS ``History`` values.

Some event sources record the shared budget scope, decision, effect outcome,
and operation timing rather than explicit policy-state versions. This helper
constructs a *diagnostic reconstruction* of scope accesses for those sparse
events. It is not certified PSS evidence: a reconstructed read version cannot
prove what a provider actually observed or replay an arbitrary policy decision.
Event sources that retain actual ``ViewRead.version`` values must construct
``History`` directly for a claim-bearing PSS check.

The reconstruction uses the number of committed operations on a scope whose
terminal event precedes an operation's start as that operation's observed
version.  It is intended for sparse recorded races; densely submitted work can
perform its policy read later than the recorded submission timestamp and should
therefore use its actual observed versions.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from masugate.pss.model import History, Operation, ScopeAccess


def _team_scope(team: str) -> str:
    return f"team-budget:{team}"


def budget_history_from_events(
    events: Sequence[dict[str, Any]],
    *,
    initial_spend_by_team: dict[str, int] | None = None,
) -> History:
    """Reconstruct a PSS ``History`` from recorded budget-policy events.

    Versions are assigned in commit-time order per team scope.  A committed
    operation reads the version that was available when it started and writes
    the next version; a denied operation reads but writes no effect.  The
    checker then detects whether the resulting schedule permits a legal serial
    explanation. This compatibility adapter must not be used as evidence that
    a provider retained certified read-from or policy-decision information.
    """

    # Retain the accepted public parameter for API compatibility.  The history
    # representation records scope versions, not monetary balances.
    del initial_spend_by_team
    ordered = sorted(events, key=lambda event: int(event.get("completed_at_ns", 0)))
    commit_count: dict[str, int] = {}
    operations: list[Operation] = []
    committed_terminals: list[tuple[int, str]] = []

    for event in ordered:
        team = str(event["team"])
        scope = _team_scope(team)
        begin_ns = int(event.get("started_at_ns", 0))
        commit_ns = int(event.get("completed_at_ns", 0))
        committed = bool(event.get("committed")) and event.get("decision") == "allow"
        observed_version = sum(
            1
            for terminal_ns, terminal_scope in committed_terminals
            if terminal_scope == scope and terminal_ns < begin_ns
        )
        effect_writes: tuple[ScopeAccess, ...] = ()
        if committed:
            produced = commit_count.get(scope, 0) + 1
            commit_count[scope] = produced
            effect_writes = (ScopeAccess(scope=scope, version=produced),)
            committed_terminals.append((commit_ns, scope))
        operations.append(
            Operation(
                op_id=str(event["operation_id"]),
                begin_ns=begin_ns,
                commit_ns=commit_ns,
                committed=committed,
                policy_reads=(ScopeAccess(scope=scope, version=observed_version),),
                effect_writes=effect_writes,
            )
        )
    return History(operations=tuple(operations))
