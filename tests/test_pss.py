"""Candidate-native tests for the PSS checker."""

from __future__ import annotations

from masugate.pss import Operation, ScopeAccess, budget_history_from_events, check_pss
from masugate.pss.model import History

S = "team-budget:research"


def _op(
    op_id: str,
    begin: int,
    commit: int,
    *,
    committed: bool,
    reads: list[tuple[str, int]] | None = None,
    writes: list[tuple[str, int]] | None = None,
) -> Operation:
    return Operation(
        op_id=op_id,
        begin_ns=begin,
        commit_ns=commit,
        committed=committed,
        policy_reads=tuple(ScopeAccess(s, v) for s, v in (reads or [])),
        effect_writes=tuple(ScopeAccess(s, v) for s, v in (writes or [])),
    )


# --------------------------------------------------------------------------- #
# Hand-authored histories.
# --------------------------------------------------------------------------- #


def test_valid_serial_is_pss() -> None:
    # A commits at v1 (read v0), B begins after A commits, reads v1, denied.
    a = _op("A", begin=0, commit=10, committed=True, reads=[(S, 0)], writes=[(S, 1)])
    b = _op("B", begin=20, commit=30, committed=False, reads=[(S, 1)])
    v = check_pss(History((a, b)))
    assert v.pss, v.reason


def test_stale_authorization_is_not_pss() -> None:
    # Both read v0 and both commit (the minimal stale race). Read-legality fails.
    a = _op("A", begin=0, commit=10, committed=True, reads=[(S, 0)], writes=[(S, 1)])
    b = _op("B", begin=1, commit=11, committed=True, reads=[(S, 0)], writes=[(S, 2)])
    v = check_pss(History((a, b)))
    assert not v.pss
    assert "stale authorization" in v.reason


def test_repeated_views_of_one_scope_share_one_snapshot() -> None:
    op = _op(
        "A",
        begin=0,
        commit=10,
        committed=True,
        reads=[(S, 0), (S, 0)],
        writes=[(S, 1)],
    )
    assert check_pss(History((op,))).pss


def test_one_operation_with_conflicting_scope_versions_is_not_pss() -> None:
    op = _op(
        "A",
        begin=0,
        commit=10,
        committed=True,
        reads=[(S, 0), (S, 1)],
        writes=[(S, 2)],
    )
    verdict = check_pss(History((op,)))
    assert not verdict.pss
    assert "inconsistent policy snapshot" in verdict.reason


def test_denied_op_may_read_stale_version() -> None:
    # A committed at v1 reading v0; B read v0 too but was DENIED (no write).
    # A deny that saw a stale version produced no effect, so it's legal.
    a = _op("A", begin=0, commit=10, committed=True, reads=[(S, 0)], writes=[(S, 1)])
    b = _op("B", begin=1, commit=11, committed=False, reads=[(S, 0)])
    v = check_pss(History((a, b)))
    assert v.pss, v.reason


def test_wr_edge_respected_when_serial() -> None:
    # A writes v1; B reads v1 and commits writing v2. Clean chain, PSS.
    a = _op("A", begin=0, commit=10, committed=True, reads=[(S, 0)], writes=[(S, 1)])
    b = _op("B", begin=11, commit=20, committed=True, reads=[(S, 1)], writes=[(S, 2)])
    assert check_pss(History((a, b))).pss


# --------------------------------------------------------------------------- #
# Real-time constraint.
# --------------------------------------------------------------------------- #


def test_real_time_violation_is_not_pss_but_conflict_order_ok() -> None:
    """A history that is conflict-serializable AND budget-legal, but violates
    real-time order — PSS must reject it; the budget invariant would pass it.

    Two DISJOINT-scope ops: X on scope S1 commits entirely before Y on scope S2
    begins (real-time X < Y), but a WR/version chain forces Y before X. With a
    cross-scope read that inverts the order, the real-time edge X→Y plus a
    version edge Y→X form a cycle.
    """
    s1, s2 = "budget:a", "budget:b"
    # Y writes s2 v1; X reads s2 v1 (so version edge Y->X). But X commits before
    # Y begins in real time (real-time edge X->Y). Cycle X->Y->X.
    x = _op("X", begin=0, commit=10, committed=True, reads=[(s2, 1)], writes=[(s1, 1)])
    y = _op("Y", begin=20, commit=30, committed=True, reads=[(s2, 0)], writes=[(s2, 1)])
    v = check_pss(History((x, y)), real_time=True)
    assert not v.pss, v.reason
    # Without the real-time constraint, the conflict order alone is acyclic here.
    assert check_pss(History((x, y)), real_time=False).pss


def test_acyclicity_only_mode_ignores_real_time() -> None:
    # Same ops as a valid chain; real_time=False must also pass.
    a = _op("A", begin=0, commit=10, committed=True, reads=[(S, 0)], writes=[(S, 1)])
    b = _op("B", begin=11, commit=20, committed=True, reads=[(S, 1)], writes=[(S, 2)])
    assert check_pss(History((a, b)), real_time=False).pss


# --------------------------------------------------------------------------- #
# Adversarial "does the checker have teeth" cases — the traps most likely to
# expose a subtly-wrong checker.
# --------------------------------------------------------------------------- #


def test_three_way_stale_is_not_pss() -> None:
    ops = tuple(
        _op(name, begin=i, commit=10 + i, committed=True, reads=[(S, 0)], writes=[(S, i + 1)])
        for i, name in enumerate("ABC")
    )
    assert not check_pss(History(ops)).pss


def test_serial_chain_of_three_is_pss() -> None:
    ops = (
        _op("A", 0, 10, committed=True, reads=[(S, 0)], writes=[(S, 1)]),
        _op("B", 11, 20, committed=True, reads=[(S, 1)], writes=[(S, 2)]),
        _op("C", 21, 30, committed=True, reads=[(S, 2)], writes=[(S, 3)]),
    )
    assert check_pss(History(ops)).pss


def test_disjoint_scopes_overlapping_time_is_pss() -> None:
    a = _op("A", 0, 10, committed=True, reads=[("x", 0)], writes=[("x", 1)])
    b = _op("B", 0, 10, committed=True, reads=[("y", 0)], writes=[("y", 1)])
    assert check_pss(History((a, b))).pss


def test_empty_and_single_histories_are_pss() -> None:
    assert check_pss(History(())).pss
    single = _op("A", 0, 10, committed=True, reads=[(S, 0)], writes=[(S, 1)])
    assert check_pss(History((single,))).pss


def test_mutual_wr_dependency_is_not_pss() -> None:
    # A reads B's write and B reads A's write — no serial order exists.
    a = _op("A", 0, 10, committed=True, reads=[("x", 1)], writes=[("y", 1)])
    b = _op("B", 0, 10, committed=True, reads=[("y", 1)], writes=[("x", 1)])
    assert not check_pss(History((a, b))).pss


def test_budget_history_adapter_preserves_a_sparse_committed_race() -> None:
    history = budget_history_from_events(
        [
            {
                "operation_id": "first",
                "team": "research",
                "started_at_ns": 0,
                "completed_at_ns": 10,
                "committed": True,
                "decision": "allow",
            },
            {
                "operation_id": "second",
                "team": "research",
                "started_at_ns": 1,
                "completed_at_ns": 11,
                "committed": True,
                "decision": "allow",
            },
        ],
        initial_spend_by_team={"research": 0},
    )
    assert not check_pss(history).pss
