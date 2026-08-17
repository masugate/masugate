"""Candidate-native tests for the PSS checker."""

from __future__ import annotations

from pytest import MonkeyPatch

import masugate.pss.checker as checker
from masugate.pss import (
    DependencyKind,
    Operation,
    ScopeAccess,
    budget_history_from_events,
    check_pss,
    check_pss_exhaustively,
)
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
    # Both read v0 and both commit (the minimal stale race).  Each read is an
    # RW anti-dependency to the other operation's next-version write.
    a = _op("A", begin=0, commit=10, committed=True, reads=[(S, 0)], writes=[(S, 1)])
    b = _op("B", begin=1, commit=11, committed=True, reads=[(S, 0)], writes=[(S, 2)])
    v = check_pss(History((a, b)))
    assert not v.pss
    assert v.cycle == ("A", "B")
    assert {edge.kind for edge in v.dependencies} == {DependencyKind.RW, DependencyKind.WW}
    assert not check_pss_exhaustively(History((a, b))).pss


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
    assert "reads multiple versions" in verdict.reason


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


# --------------------------------------------------------------------------- #
# v0.1.1 PSS correction cases.
# --------------------------------------------------------------------------- #


def test_write_skew_requires_rw_anti_dependencies() -> None:
    """A classic write skew has no WR or WW conflict but is not PSS.

    A observes x=0 and writes y=1; B observes y=0 and writes x=1.  No serial
    order can explain both observations: whichever transition goes second must
    observe the other's write.
    """

    a = _op("A", 0, 10, committed=True, reads=[("x", 0)], writes=[("y", 1)])
    b = _op("B", 0, 10, committed=True, reads=[("y", 0)], writes=[("x", 1)])
    history = History((a, b))

    verdict = check_pss(history)
    oracle = check_pss_exhaustively(history)

    assert not verdict.pss
    assert not oracle.pss
    assert verdict.cycle == ("A", "B")
    assert {edge.kind for edge in verdict.dependencies} == {DependencyKind.RW}


def test_shared_read_of_unchanged_policy_state_is_pss() -> None:
    """Two allows may share a read when neither effect advances that scope."""

    a = _op("A", 0, 10, committed=True, reads=[("risk", 0)], writes=[("x", 1)])
    b = _op("B", 0, 10, committed=True, reads=[("risk", 0)], writes=[("y", 1)])
    history = History((a, b))

    verdict = check_pss(history)
    oracle = check_pss_exhaustively(history)

    assert verdict.pss, verdict.reason
    assert oracle.pss, oracle.reason
    assert set(verdict.serial_order) == {"A", "B"}


def test_real_time_forces_rejection_of_a_stale_denial() -> None:
    """A denied decision must also read the state at its serial position."""

    update = _op("update", 0, 10, committed=True, writes=[("flag", 1)])
    denied = _op("denied", 20, 30, committed=False, reads=[("flag", 0)])
    history = History((update, denied))

    verdict = check_pss(history)

    assert not verdict.pss
    assert {edge.kind for edge in verdict.dependencies} == {
        DependencyKind.RW,
        DependencyKind.REAL_TIME,
    }
    assert not check_pss_exhaustively(history).pss


def test_explicit_baseline_allows_a_retained_history_suffix() -> None:
    later = _op("later", 0, 10, committed=True, reads=[("budget", 5)], writes=[("budget", 6)])
    history = History((later,), initial_versions=(ScopeAccess("budget", 5),))

    assert check_pss(history).pss
    assert check_pss_exhaustively(history).pss


def test_observable_reservation_is_a_separate_transition() -> None:
    reserve = Operation(
        op_id="purchase:reservation",
        begin_ns=0,
        commit_ns=10,
        committed=True,
        policy_reads=(ScopeAccess("capacity", 0),),
        effect_writes=(ScopeAccess("capacity", 1),),
        causal_operation_id="purchase",
        transition_kind="coordination-reservation",
    )
    denied = Operation(
        op_id="competitor",
        begin_ns=1,
        commit_ns=11,
        committed=False,
        policy_reads=(ScopeAccess("capacity", 1),),
        transition_kind="terminal-denial",
    )
    settle = Operation(
        op_id="purchase:settlement",
        begin_ns=20,
        commit_ns=30,
        committed=True,
        effect_reads=(ScopeAccess("capacity", 1),),
        effect_writes=(ScopeAccess("capacity", 2),),
        causal_operation_id="purchase",
        transition_kind="terminal-settlement",
    )
    history = History((reserve, denied, settle))

    verdict = check_pss(history)
    assert verdict.pss, verdict.reason
    assert verdict.serial_order == ("purchase:reservation", "competitor", "purchase:settlement")
    assert check_pss_exhaustively(history).pss


def test_provider_decision_validator_checks_all_terminal_decisions() -> None:
    denied = Operation(
        op_id="denied",
        begin_ns=0,
        commit_ns=10,
        committed=False,
        decision="deny",
        policy_reads=(ScopeAccess("risk", 0, 10),),
        policy_id="risk-guard",
        policy_version="v1",
        evaluation_time="2026-08-17T00:00:00Z",
        evaluation_input_digest="0" * 64,
    )

    def validator(operation: Operation, _state: object) -> str | None:
        if operation.declared_decision != "allow":
            return "risk policy permits the recorded read value"
        return None

    verdict = check_pss(History((denied,)), decision_validator=validator)
    assert not verdict.pss
    assert verdict.decision_semantics_checked
    assert "decision replay rejected denied" in verdict.reason
    assert not check_pss_exhaustively(History((denied,)), decision_validator=validator).pss


# --------------------------------------------------------------------------- #
# Deterministic bounded oracle gate.
# --------------------------------------------------------------------------- #


def _generated_bounded_history(seed: int) -> History:
    """Build one of several bounded histories from a deterministic seed.

    The families deliberately cover serial chains, stale reads, write skew,
    shared unchanged policy reads, version gaps, mutual dependencies, and
    varied raw histories.  Keeping every case to at most four operations makes
    comparison with the independent exhaustive oracle practical in CI.
    """

    state = seed + 1

    def draw(bound: int) -> int:
        nonlocal state
        state = (state * 1_103_515_245 + 12_345) & 0x7FFF_FFFF
        return state % bound

    family = seed % 7
    count = 1 + draw(4)
    if family == 0:
        operations = tuple(
            _op(
                f"serial-{seed}-{index}",
                index * 20,
                index * 20 + 10,
                committed=True,
                reads=[("serial", index)],
                writes=[("serial", index + 1)],
            )
            for index in range(count)
        )
    elif family == 1:
        operations = tuple(
            _op(
                f"stale-{seed}-{index}",
                index,
                10 + index,
                committed=True,
                reads=[("stale", 0)],
                writes=[("stale", index + 1)],
            )
            for index in range(max(2, count))
        )
    elif family == 2:
        operations = (
            _op("skew-x-" + str(seed), 0, 10, committed=True, reads=[("x", 0)], writes=[("y", 1)]),
            _op("skew-y-" + str(seed), 0, 10, committed=True, reads=[("y", 0)], writes=[("x", 1)]),
        )
    elif family == 3:
        operations = tuple(
            _op(
                f"shared-{seed}-{index}",
                0,
                10,
                committed=True,
                reads=[("risk", 0)],
                writes=[(f"effect-{index}", 1)],
            )
            for index in range(max(2, count))
        )
    elif family == 4:
        operations = (
            _op(
                f"gap-{seed}",
                0,
                10,
                committed=True,
                reads=[("gap", 0)],
                writes=[("gap", 2)],
            ),
        )
    elif family == 5:
        operations = (
            _op(
                f"mutual-x-{seed}",
                0,
                10,
                committed=True,
                reads=[("y", 1)],
                writes=[("x", 1)],
            ),
            _op(
                f"mutual-y-{seed}",
                0,
                10,
                committed=True,
                reads=[("x", 1)],
                writes=[("y", 1)],
            ),
        )
    else:
        operations = tuple(
            _op(
                f"raw-{seed}-{index}",
                draw(5),
                6 + draw(5),
                committed=bool(draw(2)),
                reads=[(f"raw-{draw(3)}", draw(4))] if draw(2) else [],
                writes=[(f"raw-{draw(3)}", 1 + draw(3))] if draw(2) else [],
            )
            for index in range(count)
        )
    return History(operations)


def test_optimized_checker_matches_exhaustive_oracle_on_30k_generated_histories() -> None:
    accepted = 0
    rejected = 0
    for seed in range(30_000):
        history = _generated_bounded_history(seed)
        optimized = check_pss(history)
        exhaustive = check_pss_exhaustively(history)
        assert optimized.pss == exhaustive.pss, f"oracle disagreement for generated seed {seed}"
        if optimized.pss:
            accepted += 1
        else:
            rejected += 1
    assert accepted > 0
    assert rejected > 0


def test_write_skew_regression_kills_legacy_graph_only_mutant(monkeypatch: MonkeyPatch) -> None:
    """The pre-v0.1.1 no-RW/no-replay checker would accept write skew."""

    history = History(
        (
            _op("A", 0, 10, committed=True, reads=[("x", 0)], writes=[("y", 1)]),
            _op("B", 0, 10, committed=True, reads=[("y", 0)], writes=[("x", 1)]),
        )
    )
    assert not check_pss(history).pss

    original_add = checker._Graph.add

    def add_without_rw(graph: checker._Graph, dependency: checker.PSSDependency) -> None:
        if dependency.kind is not DependencyKind.RW:
            original_add(graph, dependency)

    monkeypatch.setattr(checker._Graph, "add", add_without_rw)
    monkeypatch.setattr(checker, "_replay_witness", lambda *_args, **_kwargs: None)

    assert checker.check_pss(history).pss


def test_shared_read_regression_kills_duplicate_read_rejection_mutant(
    monkeypatch: MonkeyPatch,
) -> None:
    """Reinstating the old global duplicate-read heuristic rejects a legal history."""

    history = History(
        (
            _op("A", 0, 10, committed=True, reads=[("risk", 0)], writes=[("x", 1)]),
            _op("B", 0, 10, committed=True, reads=[("risk", 0)], writes=[("y", 1)]),
        )
    )
    assert check_pss(history).pss

    original_validate = checker._validate_history

    def reject_shared_reads(candidate: History) -> object:
        validated = original_validate(candidate)
        if isinstance(validated, str):
            return validated
        seen: set[tuple[str, int]] = set()
        for operation in candidate.operations:
            for read in operation.reads:
                key = (read.scope, read.version)
                if key in seen:
                    return "legacy duplicate-read rejection"
                seen.add(key)
        return validated

    monkeypatch.setattr(checker, "_validate_history", reject_shared_reads)

    assert not checker.check_pss(history).pss
