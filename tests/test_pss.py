"""Candidate-native tests for the PSS checker."""

from __future__ import annotations

from collections.abc import Mapping
from random import Random

from pytest import MonkeyPatch

import masugate.pss.checker as checker
from masugate.pss import (
    DependencyKind,
    Operation,
    PSSDependency,
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
    assert "mentions multiple versions" in verdict.reason


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
    assert verdict.decision_validator_supplied
    assert "decision replay rejected denied" in verdict.reason
    assert not check_pss_exhaustively(History((denied,)), decision_validator=validator).pss


def test_decision_validator_searches_all_serial_witnesses() -> None:
    """Operation names cannot choose a different existential PSS verdict."""

    def spend(op_id: str) -> Operation:
        return Operation(
            op_id,
            0,
            10,
            True,
            decision="allow",
            policy_reads=(ScopeAccess("budget", 0, 100),),
            effect_writes=(ScopeAccess("budget", 1, 40),),
        )

    def denial(op_id: str) -> Operation:
        return Operation(op_id, 0, 10, False, decision="deny")

    def balance_policy(operation: Operation, state: Mapping[str, ScopeAccess]) -> str | None:
        expected = "allow" if state["budget"].value >= 60 else "deny"
        if operation.declared_decision != expected:
            return f"recorded {operation.declared_decision} conflicts with the balance"
        return None

    baseline = (ScopeAccess("budget", 0, 100),)
    for spend_id, denial_id in (("a-spend", "b-review"), ("z-spend", "a-review")):
        history = History((spend(spend_id), denial(denial_id)), initial_versions=baseline)
        verdict = check_pss(history, decision_validator=balance_policy)
        oracle = check_pss_exhaustively(history, decision_validator=balance_policy)

        assert verdict.pss, verdict.reason
        assert verdict.serial_order == (spend_id, denial_id)
        assert verdict.decision_semantics_checked
        assert verdict.decision_validator_supplied
        assert oracle.pss


def test_empty_validator_backed_history_has_an_empty_witness() -> None:
    invoked: list[str] = []

    def validator(operation: Operation, _state: Mapping[str, ScopeAccess]) -> str | None:
        invoked.append(operation.op_id)
        return None

    history = History(())
    verdict = check_pss(history, decision_validator=validator)
    oracle = check_pss_exhaustively(history, decision_validator=validator)

    assert verdict.pss, verdict.reason
    assert verdict.serial_order == ()
    assert verdict.decision_validator_supplied
    assert not verdict.decision_semantics_checked
    assert invoked == []
    assert oracle.pss


def test_semantic_witness_search_handles_histories_beyond_recursion_depth() -> None:
    operation_count = 1_100
    history = History(
        tuple(
            Operation(
                f"operation-{index:04d}",
                0,
                0,
                True,
                decision="allow",
            )
            for index in range(operation_count)
        )
    )

    def validator(_operation: Operation, _state: Mapping[str, ScopeAccess]) -> str | None:
        return None

    verdict = check_pss(history, decision_validator=validator)

    assert verdict.pss, verdict.reason
    assert verdict.serial_order is not None
    assert len(verdict.serial_order) == operation_count
    assert verdict.decision_validator_supplied
    assert verdict.decision_semantics_checked


def test_semantic_witness_search_reports_budget_exhaustion_as_inconclusive() -> None:
    history = History(
        (
            Operation(
                "z-spend",
                0,
                10,
                True,
                decision="allow",
                policy_reads=(ScopeAccess("budget", 0, 100),),
                effect_writes=(ScopeAccess("budget", 1, 40),),
            ),
            Operation("a-review", 0, 10, False, decision="deny"),
        ),
        initial_versions=(ScopeAccess("budget", 0, 100),),
    )

    def balance_policy(operation: Operation, state: Mapping[str, ScopeAccess]) -> str | None:
        expected = "allow" if state["budget"].value >= 60 else "deny"
        return None if operation.declared_decision == expected else "unexpected decision"

    verdict = check_pss(
        history,
        decision_validator=balance_policy,
        max_witness_search_steps=1,
    )

    assert not verdict.pss
    assert verdict.inconclusive
    assert verdict.decision_validator_supplied
    assert verdict.decision_semantics_checked


def test_structural_cycle_does_not_claim_unperformed_semantic_replay() -> None:
    invoked: list[str] = []

    def validator(operation: Operation, _state: Mapping[str, ScopeAccess]) -> str | None:
        invoked.append(operation.op_id)
        return None

    weak = History(
        (
            Operation(
                "weak-alpha",
                0,
                10,
                True,
                decision="allow",
                policy_reads=(ScopeAccess("budget", 0, 100),),
                effect_writes=(ScopeAccess("budget", 1, 40),),
            ),
            Operation(
                "weak-beta",
                1,
                11,
                True,
                decision="allow",
                policy_reads=(ScopeAccess("budget", 0, 100),),
                effect_writes=(ScopeAccess("budget", 2, -20),),
            ),
        ),
        initial_versions=(ScopeAccess("budget", 0, 100),),
    )

    verdict = check_pss(weak, decision_validator=validator)

    assert not verdict.pss
    assert verdict.decision_validator_supplied
    assert not verdict.decision_semantics_checked
    assert invoked == []


def test_cycle_reconstruction_handles_converging_discovery_paths() -> None:
    graph = checker._Graph(("a", "b", "c", "d"))
    for source, target in (("a", "b"), ("a", "c"), ("b", "d"), ("c", "d"), ("d", "b")):
        graph.add(PSSDependency(source, target, DependencyKind.WR))

    cycle = graph.find_cycle()

    assert cycle
    assert all(
        target in graph._adj[source]
        for source, target in zip(cycle, (*cycle[1:], cycle[0]), strict=True)
    )


# --------------------------------------------------------------------------- #
# Deterministic bounded oracle gate.
# --------------------------------------------------------------------------- #


def _generated_decision_validator(
    operation: Operation,
    state: Mapping[str, ScopeAccess],
) -> str | None:
    """A deterministic policy used only to exercise semantic witness search."""

    if operation.declared_decision != ("allow" if operation.committed else "deny"):
        return "decision does not match the transition outcome"
    if operation.op_id.startswith("semantic-denial"):
        available = state["budget"].value
        if available >= 60:
            return "denial occurred before the budget was spent"
    return None


def _generated_bounded_history(seed: int) -> History:
    """Build a varied bounded history from a deterministic seed.

    Every generated case has an explicit baseline and decision metadata. The
    families additionally exercise stale reads, RW write skew, shared reads,
    version gaps, effect reads, real-time order, and validators whose result
    selects one of several otherwise valid serial witnesses.
    """

    random = Random(seed)
    family = seed % 9
    token = random.randrange(1_000_000)
    primary = f"scope-{token}"
    initial_value = random.randrange(100, 10_000)
    operations: tuple[Operation, ...]
    baselines: tuple[ScopeAccess, ...]

    if family == 0:
        count = 1 + random.randrange(4)
        current_value = initial_value
        serial: list[Operation] = []
        for index in range(count):
            next_value = current_value - random.randrange(1, min(50, current_value) + 1)
            serial.append(
                Operation(
                    f"serial-{token}-{index}",
                    index * 20,
                    index * 20 + 10,
                    True,
                    policy_reads=(ScopeAccess(primary, index, current_value),),
                    effect_writes=(ScopeAccess(primary, index + 1, next_value),),
                    decision="allow",
                )
            )
            current_value = next_value
        operations = tuple(serial)
        baselines = (ScopeAccess(primary, 0, initial_value),)
    elif family == 1:
        count = 2 + random.randrange(3)
        operations = tuple(
            Operation(
                f"stale-{token}-{index}",
                index,
                10 + index,
                True,
                policy_reads=(ScopeAccess(primary, 0, initial_value),),
                effect_writes=(ScopeAccess(primary, index + 1, initial_value - index - 1),),
                decision="allow",
            )
            for index in range(count)
        )
        baselines = (ScopeAccess(primary, 0, initial_value),)
    elif family == 2:
        x, y = f"x-{token}", f"y-{token}"
        operations = (
            Operation(
                f"skew-x-{token}",
                0,
                10,
                True,
                policy_reads=(ScopeAccess(x, 0, initial_value),),
                effect_writes=(ScopeAccess(y, 1, initial_value - 1),),
                decision="allow",
            ),
            Operation(
                f"skew-y-{token}",
                0,
                10,
                True,
                policy_reads=(ScopeAccess(y, 0, initial_value),),
                effect_writes=(ScopeAccess(x, 1, initial_value - 1),),
                decision="allow",
            ),
        )
        baselines = (ScopeAccess(x, 0, initial_value), ScopeAccess(y, 0, initial_value))
    elif family == 3:
        risk = f"risk-{token}"
        count = 2 + random.randrange(3)
        operations = tuple(
            Operation(
                f"shared-{token}-{index}",
                0,
                10,
                True,
                policy_reads=(ScopeAccess(risk, 0, initial_value),),
                effect_writes=(ScopeAccess(f"effect-{token}-{index}", 1, index),),
                decision="allow",
            )
            for index in range(count)
        )
        baselines = (ScopeAccess(risk, 0, initial_value),)
    elif family == 4:
        operations = (
            Operation(
                f"gap-{token}",
                0,
                10,
                True,
                policy_reads=(ScopeAccess(primary, 0, initial_value),),
                effect_writes=(ScopeAccess(primary, 2, initial_value - 1),),
                decision="allow",
            ),
        )
        baselines = (ScopeAccess(primary, 0, initial_value),)
    elif family == 5:
        x, y = f"x-{token}", f"y-{token}"
        operations = (
            Operation(
                f"mutual-x-{token}",
                0,
                10,
                True,
                policy_reads=(ScopeAccess(y, 1, initial_value - 1),),
                effect_writes=(ScopeAccess(x, 1, initial_value - 1),),
                decision="allow",
            ),
            Operation(
                f"mutual-y-{token}",
                0,
                10,
                True,
                policy_reads=(ScopeAccess(x, 1, initial_value - 1),),
                effect_writes=(ScopeAccess(y, 1, initial_value - 1),),
                decision="allow",
            ),
        )
        baselines = (ScopeAccess(x, 0, initial_value), ScopeAccess(y, 0, initial_value))
    elif family == 6:
        operations = (
            Operation(
                f"reservation-{token}",
                0,
                10,
                True,
                policy_reads=(ScopeAccess(primary, 0, initial_value),),
                effect_writes=(ScopeAccess(primary, 1, initial_value - 1),),
                decision="allow",
                causal_operation_id=f"purchase-{token}",
                transition_kind="coordination-reservation",
            ),
            Operation(
                f"settlement-{token}",
                20,
                30,
                True,
                effect_reads=(ScopeAccess(primary, 1, initial_value - 1),),
                effect_writes=(ScopeAccess(primary, 2, initial_value - 1),),
                decision="allow",
                causal_operation_id=f"purchase-{token}",
                transition_kind="terminal-settlement",
            ),
        )
        baselines = (ScopeAccess(primary, 0, initial_value),)
    elif family == 7:
        operations = (
            Operation(
                f"semantic-spend-{token}",
                0,
                10,
                True,
                policy_reads=(ScopeAccess("budget", 0, 100),),
                effect_writes=(ScopeAccess("budget", 1, 40),),
                decision="allow",
            ),
            Operation(
                f"semantic-denial-{token}",
                0,
                10,
                False,
                decision="deny",
            ),
        )
        baselines = (ScopeAccess("budget", 0, 100),)
    else:
        count = 1 + random.randrange(4)
        operations = tuple(
            Operation(
                f"denial-{token}-{index}",
                random.randrange(5),
                10 + random.randrange(5),
                False,
                policy_reads=(ScopeAccess(primary, 0, initial_value),),
                decision="deny",
            )
            for index in range(count)
        )
        baselines = (ScopeAccess(primary, 0, initial_value),)
    return History(operations, initial_versions=baselines)


def _history_signature(history: History) -> tuple[object, ...]:
    return (
        tuple((access.scope, access.version, access.value) for access in history.initial_versions),
        tuple(
            (
                operation.begin_ns,
                operation.commit_ns,
                operation.committed,
                operation.declared_decision,
            tuple(
                (access.scope, access.version, access.value)
                for access in operation.policy_reads
            ),
            tuple(
                (access.scope, access.version, access.value)
                for access in operation.effect_reads
            ),
            tuple(
                (access.scope, access.version, access.value)
                for access in operation.effect_writes
            ),
            )
            for operation in history.operations
        ),
    )


def test_optimized_checker_matches_exhaustive_oracle_on_30k_generated_histories() -> None:
    accepted = 0
    rejected = 0
    histories = tuple(_generated_bounded_history(seed) for seed in range(30_000))
    for seed, history in enumerate(histories):
        for real_time in (False, True):
            optimized = check_pss(
                history,
                real_time=real_time,
                decision_validator=_generated_decision_validator,
            )
            exhaustive = check_pss_exhaustively(
                history,
                real_time=real_time,
                decision_validator=_generated_decision_validator,
            )
            assert optimized.pss == exhaustive.pss, (
                f"oracle disagreement for generated seed {seed}, real_time={real_time}"
            )
            if optimized.pss:
                accepted += 1
            else:
                rejected += 1
    assert len({_history_signature(history) for history in histories}) > 25_000
    assert all(history.initial_versions for history in histories)
    assert any(operation.effect_reads for history in histories for operation in history.operations)
    assert all(
        operation.decision is not None for history in histories for operation in history.operations
    )
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
    monkeypatch.setattr(
        checker,
        "_replay_witness",
        lambda *_args, **_kwargs: checker._ReplayResult(None),
    )

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
