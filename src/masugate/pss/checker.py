"""Policy-State Serializability (PSS) checker for declared versioned state.

For a complete recorded access history, PSS requires a real-time-respecting
serial witness in which every read observes the state immediately before its
transition and every committed write advances its scope exactly once.  The
checker builds the multiversion serialization graph:

* WR: a writer precedes a reader of the version it produced;
* WW: writes of one scope follow their declared version order;
* RW: a reader of an old version precedes every later writer of that scope;
* RT: a completed operation precedes an operation that begins later.

RW anti-dependencies are essential.  Omitting them accepts write skew; using a
"no duplicate reads" shortcut rejects legal shared read-only state.  After a
topological sort, the checker replays every declared read and write against the
witness.  A provider may additionally supply a decision validator to replay
its policy predicate from retained policy evidence.  Because that validator can
make one valid graph order fail and another pass, the checker searches
deterministic topological witnesses when a validator is supplied, bounded by a
fail-closed search budget.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from itertools import pairwise
from types import MappingProxyType

from masugate.pss.model import History, Operation, ScopeAccess


class DependencyKind(StrEnum):
    WR = "WR"
    WW = "WW"
    RW = "RW"
    REAL_TIME = "real-time"


@dataclass(frozen=True)
class PSSDependency:
    """One required serialization edge and the evidence that induced it."""

    source: str
    target: str
    kind: DependencyKind
    scope: str | None = None
    version: int | None = None


DecisionValidator = Callable[[Operation, Mapping[str, ScopeAccess]], str | None]


@dataclass(frozen=True)
class PSSVerdict:
    pss: bool
    cycle: tuple[str, ...]
    reason: str
    serial_order: tuple[str, ...] = ()
    dependencies: tuple[PSSDependency, ...] = ()
    # True only when the validator was actually invoked while producing this
    # verdict.  This distinguishes a structural short-circuit from policy
    # replay, even when a caller supplied a validator.
    decision_semantics_checked: bool = False
    decision_validator_supplied: bool = False
    # Search-budget exhaustion is fail-closed but is not proof that no PSS
    # witness exists.
    inconclusive: bool = False

    def __bool__(self) -> bool:
        return self.pss


@dataclass(frozen=True)
class _ValidatedHistory:
    operations: tuple[Operation, ...]
    initial_state: Mapping[str, ScopeAccess]
    writers: Mapping[str, tuple[tuple[int, str], ...]]
    writer_of: Mapping[tuple[str, int], str]


class _Graph:
    def __init__(self, nodes: tuple[str, ...]) -> None:
        self._nodes = nodes
        self._adj: dict[str, dict[str, list[PSSDependency]]] = {node: {} for node in nodes}

    def add(self, dependency: PSSDependency) -> None:
        if dependency.source == dependency.target:
            return
        edges = self._adj[dependency.source].setdefault(dependency.target, [])
        if dependency not in edges:
            edges.append(dependency)

    @property
    def dependencies(self) -> tuple[PSSDependency, ...]:
        return tuple(
            dependency
            for source in self._nodes
            for target in sorted(self._adj[source])
            for dependency in sorted(
                self._adj[source][target],
                key=lambda edge: (edge.kind.value, edge.scope or "", edge.version or -1),
            )
        )

    def find_cycle(self) -> tuple[str, ...]:
        white, gray, black = 0, 1, 2
        color = dict.fromkeys(self._nodes, white)
        parent: dict[str, str | None] = dict.fromkeys(self._nodes, None)

        def walk(start: str) -> tuple[str, ...]:
            color[start] = gray
            stack: list[tuple[str, tuple[str, ...], int]] = [
                (start, tuple(sorted(self._adj[start])), 0)
            ]
            while stack:
                node, neighbors, index = stack[-1]
                if index == len(neighbors):
                    color[node] = black
                    stack.pop()
                    continue
                neighbor = neighbors[index]
                stack[-1] = (node, neighbors, index + 1)
                if color[neighbor] == white:
                    parent[neighbor] = node
                    color[neighbor] = gray
                    stack.append((neighbor, tuple(sorted(self._adj[neighbor])), 0))
                elif color[neighbor] == gray:
                    path = [node]
                    cursor = node
                    while cursor != neighbor:
                        predecessor = parent[cursor]
                        if predecessor is None:
                            return ()
                        cursor = predecessor
                        path.append(cursor)
                    path.reverse()
                    return tuple(path)
            return ()

        for node in self._nodes:
            if color[node] == white:
                cycle = walk(node)
                if cycle:
                    return cycle
        return ()

    def topological_order(self) -> tuple[str, ...]:
        indegree = dict.fromkeys(self._nodes, 0)
        for outgoing in self._adj.values():
            for target in outgoing:
                indegree[target] += 1
        ready = sorted(node for node, degree in indegree.items() if degree == 0)
        order: list[str] = []
        while ready:
            node = ready.pop(0)
            order.append(node)
            for target in sorted(self._adj[node]):
                indegree[target] -= 1
                if indegree[target] == 0:
                    ready.append(target)
                    ready.sort()
        return tuple(order)


def _invalid(reason: str, *, validator_supplied: bool = False) -> PSSVerdict:
    return PSSVerdict(False, (), reason, decision_validator_supplied=validator_supplied)


def _scope_versions(accesses: tuple[ScopeAccess, ...]) -> tuple[dict[str, ScopeAccess], str | None]:
    by_scope: dict[str, ScopeAccess] = {}
    for access in accesses:
        if not access.scope:
            return {}, "contains an empty scope name"
        if access.version < 0:
            return {}, f"uses negative version {access.version} for {access.scope}"
        existing = by_scope.get(access.scope)
        if existing is not None and existing.version != access.version:
            return {}, (
                f"mentions multiple versions of {access.scope} "
                f"({existing.version} and {access.version})"
            )
        if (
            existing is not None
            and existing.value is not None
            and access.value is not None
            and (
                type(existing.value) is not type(access.value)
                or existing.value != access.value
            )
        ):
            return {}, (
                f"records conflicting values for {access.scope} version {access.version}"
            )
        # ``None`` means that this view did not retain a provider-certified
        # value.  It is compatible with a concrete view of the same version,
        # and the concrete value is the useful canonical representative.
        if existing is None or (existing.value is None and access.value is not None):
            by_scope[access.scope] = access
    return by_scope, None


def _validate_history(history: History) -> _ValidatedHistory | str:
    operations = history.operations
    operation_ids = [operation.op_id for operation in operations]
    if len(set(operation_ids)) != len(operation_ids):
        return "history contains duplicate transition identities"
    if any(not operation.op_id for operation in operations):
        return "history contains an empty transition identity"

    initial_state, initial_error = _scope_versions(history.initial_versions)
    if initial_error is not None:
        return f"initial policy state {initial_error}"
    if len(initial_state) != len(history.initial_versions):
        seen_initial_scopes: set[str] = set()
        for access in history.initial_versions:
            if access.scope in seen_initial_scopes:
                return f"initial policy state repeats the baseline for {access.scope}"
            seen_initial_scopes.add(access.scope)
        raise AssertionError("collapsed initial state did not contain a repeated scope")

    writers_by_scope: dict[str, list[tuple[int, str]]] = defaultdict(list)
    writer_of: dict[tuple[str, int], str] = {}
    reads_by_operation: dict[str, dict[str, ScopeAccess]] = {}

    for operation in operations:
        if operation.begin_ns < 0 or operation.commit_ns < operation.begin_ns:
            return f"operation {operation.op_id} has an invalid real-time interval"
        if operation.decision is not None and operation.decision != (
            "allow" if operation.committed else "deny"
        ):
            return f"operation {operation.op_id} has a decision inconsistent with committed"
        if not operation.committed and operation.effect_writes:
            return f"denied operation {operation.op_id} contains policy-state writes"
        reads, read_error = _scope_versions(operation.reads)
        if read_error is not None:
            return f"operation {operation.op_id} {read_error}"
        reads_by_operation[operation.op_id] = reads
        writes, write_error = _scope_versions(operation.effect_writes)
        if write_error is not None:
            return f"operation {operation.op_id} {write_error}"
        if len(writes) != len(operation.effect_writes):
            return f"operation {operation.op_id} writes one scope more than once"
        for write in operation.effect_writes:
            key = (write.scope, write.version)
            if key in writer_of:
                return (
                    f"operations {writer_of[key]} and {operation.op_id} both write "
                    f"{write.scope} version {write.version}"
                )
            writer_of[key] = operation.op_id
            writers_by_scope[write.scope].append((write.version, operation.op_id))

    scopes = set(initial_state) | set(writers_by_scope)
    scopes.update(access.scope for operation in operations for access in operation.reads)
    for scope in scopes:
        base = initial_state.get(scope, ScopeAccess(scope, 0))
        initial_state.setdefault(scope, base)
        expected = base.version + 1
        for version, _operation_id in sorted(writers_by_scope.get(scope, [])):
            if version != expected:
                return (
                    f"scope {scope} has non-contiguous write versions: expected {expected}, "
                    f"found {version}"
                )
            expected += 1

    for operation in operations:
        for read in reads_by_operation[operation.op_id].values():
            baseline_version = initial_state[read.scope].version
            if read.version < baseline_version:
                return (
                    f"operation {operation.op_id} reads {read.scope} version {read.version} "
                    f"before retained baseline {baseline_version}"
                )
            if read.version > baseline_version and (read.scope, read.version) not in writer_of:
                return (
                    f"operation {operation.op_id} reads unknown {read.scope} "
                    f"version {read.version}"
                )

    return _ValidatedHistory(
        operations=operations,
        initial_state=MappingProxyType(dict(initial_state)),
        writers=MappingProxyType(
            {scope: tuple(sorted(writers)) for scope, writers in writers_by_scope.items()}
        ),
        writer_of=MappingProxyType(dict(writer_of)),
    )


def _build_graph(validated: _ValidatedHistory, *, real_time: bool) -> _Graph:
    graph = _Graph(tuple(operation.op_id for operation in validated.operations))
    for operation in validated.operations:
        reads, _ = _scope_versions(operation.reads)
        for read in reads.values():
            writer = validated.writer_of.get((read.scope, read.version))
            if writer is not None:
                graph.add(
                    PSSDependency(
                        writer,
                        operation.op_id,
                        DependencyKind.WR,
                        read.scope,
                        read.version,
                    )
                )
            for write_version, writer_id in validated.writers.get(read.scope, ()):
                if write_version > read.version:
                    graph.add(
                        PSSDependency(
                            operation.op_id,
                            writer_id,
                            DependencyKind.RW,
                            read.scope,
                            read.version,
                        )
                    )

    for scope, writers in validated.writers.items():
        for (_earlier_version, earlier_id), (later_version, later_id) in pairwise(writers):
            graph.add(PSSDependency(earlier_id, later_id, DependencyKind.WW, scope, later_version))

    if real_time:
        for earlier in validated.operations:
            for later in validated.operations:
                if earlier.op_id != later.op_id and earlier.commit_ns < later.begin_ns:
                    graph.add(PSSDependency(earlier.op_id, later.op_id, DependencyKind.REAL_TIME))
    return graph


def _cycle_reason(cycle: tuple[str, ...], dependencies: tuple[PSSDependency, ...]) -> str:
    pairs = tuple(zip(cycle, (*cycle[1:], cycle[0]), strict=True))
    edge_kinds = [
        next(
            dependency.kind.value
            for dependency in dependencies
            if dependency.source == source and dependency.target == target
        )
        for source, target in pairs
    ]
    return (
        f"serialization cycle ({' -> '.join(edge_kinds)}) "
        f"among {' -> '.join(cycle)} -> {cycle[0]}"
    )


@dataclass(frozen=True)
class _ReplayResult:
    error: str | None
    decision_semantics_checked: bool = False


def _replay_operation(
    operation: Operation,
    state: dict[str, ScopeAccess],
    *,
    decision_validator: DecisionValidator | None,
) -> _ReplayResult:
    reads, _ = _scope_versions(operation.reads)
    for scope, read in reads.items():
        current = state[scope]
        if current.version != read.version:
            return _ReplayResult(
                f"serial witness reads {scope} version {read.version} for {operation.op_id}, "
                f"but current version is {current.version}"
            )
    checked = decision_validator is not None
    if decision_validator is not None:
        decision_error = decision_validator(operation, MappingProxyType(dict(state)))
        if decision_error is not None:
            return _ReplayResult(
                f"decision replay rejected {operation.op_id}: {decision_error}",
                decision_semantics_checked=True,
            )
    for write in operation.effect_writes:
        current = state[write.scope]
        if write.version != current.version + 1:
            return _ReplayResult(
                f"serial witness writes {write.scope} version {write.version} "
                f"for {operation.op_id}, "
                f"but current version is {current.version}",
                decision_semantics_checked=checked,
            )
        state[write.scope] = write
    return _ReplayResult(None, decision_semantics_checked=checked)


def _replay_witness(
    validated: _ValidatedHistory,
    order: tuple[str, ...],
    *,
    decision_validator: DecisionValidator | None,
) -> _ReplayResult:
    state = dict(validated.initial_state)
    by_id = {operation.op_id: operation for operation in validated.operations}
    checked = False
    for operation_id in order:
        operation = by_id[operation_id]
        result = _replay_operation(
            operation,
            state,
            decision_validator=decision_validator,
        )
        checked = checked or result.decision_semantics_checked
        if result.error is not None:
            return _ReplayResult(result.error, decision_semantics_checked=checked)
    return _ReplayResult(None, decision_semantics_checked=checked)


@dataclass(frozen=True)
class _WitnessSearchResult:
    serial_order: tuple[str, ...] | None = None
    replay_error: str | None = None
    decision_semantics_checked: bool = False
    inconclusive: bool = False


@dataclass
class _SearchFrame:
    order: tuple[str, ...]
    ready: tuple[str, ...]
    indegree: dict[str, int]
    state: dict[str, ScopeAccess]
    next_index: int = 0


def _search_semantic_witness(
    validated: _ValidatedHistory,
    graph: _Graph,
    *,
    decision_validator: DecisionValidator,
    max_steps: int,
) -> _WitnessSearchResult:
    """Search valid graph orders while replaying policy decisions incrementally.

    A semantic validator may depend on the full declared witness-prefix state,
    so an acyclic dependency graph alone does not choose its unique witness.
    Search is deterministic and fail-closed at ``max_steps`` rather than
    allowing a broad ready set to consume unbounded verifier time.
    """

    by_id = {operation.op_id: operation for operation in validated.operations}
    operation_ids = tuple(by_id)
    indegree = dict.fromkeys(operation_ids, 0)
    successors: dict[str, tuple[str, ...]] = {}
    for source, outgoing in graph._adj.items():
        successors[source] = tuple(sorted(outgoing))
        for target in outgoing:
            indegree[target] += 1
    initial_ready = tuple(
        sorted(operation_id for operation_id, degree in indegree.items() if degree == 0)
    )
    steps = 0
    checked = False
    last_error: str | None = None
    stack = [
        _SearchFrame(
            order=(),
            ready=initial_ready,
            indegree=indegree,
            state=dict(validated.initial_state),
        )
    ]
    while stack:
        frame = stack[-1]
        if len(frame.order) == len(validated.operations):
            return _WitnessSearchResult(
                serial_order=frame.order,
                replay_error=last_error,
                decision_semantics_checked=checked,
            )
        if frame.next_index == len(frame.ready):
            stack.pop()
            continue
        if steps >= max_steps:
            return _WitnessSearchResult(
                replay_error=last_error,
                decision_semantics_checked=checked,
                inconclusive=True,
            )

        index = frame.next_index
        frame.next_index += 1
        operation_id = frame.ready[index]
        steps += 1
        next_state = dict(frame.state)
        replay = _replay_operation(
            by_id[operation_id],
            next_state,
            decision_validator=decision_validator,
        )
        checked = checked or replay.decision_semantics_checked
        if replay.error is not None:
            last_error = replay.error
            continue

        next_indegree = dict(frame.indegree)
        next_ready = list(frame.ready[:index] + frame.ready[index + 1 :])
        for target in successors[operation_id]:
            next_indegree[target] -= 1
            if next_indegree[target] == 0:
                next_ready.append(target)
        stack.append(
            _SearchFrame(
                order=(*frame.order, operation_id),
                ready=tuple(sorted(next_ready)),
                indegree=next_indegree,
                state=next_state,
            )
        )

    return _WitnessSearchResult(
        replay_error=last_error,
        decision_semantics_checked=checked,
    )


def check_pss(
    history: History,
    *,
    real_time: bool = True,
    decision_validator: DecisionValidator | None = None,
    max_witness_search_steps: int = 100_000,
) -> PSSVerdict:
    """Verify PSS for a complete declared versioned-access history.

    The checker proves existence of a serial witness for the exact reads and
    writes in the history.  Supplying ``decision_validator`` additionally
    checks every terminal decision, including denials, against provider-retained
    policy evidence at its witness position.  The checker searches valid
    topological orders up to ``max_witness_search_steps``; exhaustion returns
    a fail-closed, inconclusive verdict.  Without a validator, the verdict is
    structural PSS under the trusted assumption that recorded policy decisions
    and reads are faithful.
    """

    if max_witness_search_steps < 1:
        raise ValueError("max_witness_search_steps must be positive")
    validated = _validate_history(history)
    validator_supplied = decision_validator is not None
    if isinstance(validated, str):
        return _invalid(
            f"malformed PSS history: {validated}",
            validator_supplied=validator_supplied,
        )
    graph = _build_graph(validated, real_time=real_time)
    dependencies = graph.dependencies
    cycle = graph.find_cycle()
    if cycle:
        return PSSVerdict(
            False,
            cycle,
            _cycle_reason(cycle, dependencies),
            dependencies=dependencies,
            decision_validator_supplied=validator_supplied,
        )
    order = graph.topological_order()
    if len(order) != len(validated.operations):
        return _invalid(
            "serialization graph did not yield a complete witness",
            validator_supplied=validator_supplied,
        )
    if decision_validator is None:
        replay = _replay_witness(
            validated,
            order,
            decision_validator=None,
        )
        if replay.error is not None:
            return PSSVerdict(
                False,
                (),
                replay.error,
                serial_order=order,
                dependencies=dependencies,
            )
        suffix = "; policy predicates not replayed (trusted recorded-decision evidence)"
        return PSSVerdict(
            True,
            (),
            f"acyclic WR/WW/RW/real-time dependencies + serial read/write replay{suffix}",
            serial_order=order,
            dependencies=dependencies,
        )

    search = _search_semantic_witness(
        validated,
        graph,
        decision_validator=decision_validator,
        max_steps=max_witness_search_steps,
    )
    if search.inconclusive:
        return PSSVerdict(
            False,
            (),
            f"semantic witness search exhausted {max_witness_search_steps} steps",
            dependencies=dependencies,
            decision_semantics_checked=search.decision_semantics_checked,
            decision_validator_supplied=True,
            inconclusive=True,
        )
    if search.serial_order is None:
        return PSSVerdict(
            False,
            (),
            search.replay_error or "no serial witness satisfies the decision validator",
            dependencies=dependencies,
            decision_semantics_checked=search.decision_semantics_checked,
            decision_validator_supplied=True,
        )
    suffix = (
        "; policy decisions replayed"
        if search.decision_semantics_checked
        else "; policy validator supplied but no terminal decision required replay"
    )
    return PSSVerdict(
        True,
        (),
        f"acyclic WR/WW/RW/real-time dependencies + serial read/write replay{suffix}",
        serial_order=search.serial_order,
        dependencies=dependencies,
        decision_semantics_checked=search.decision_semantics_checked,
        decision_validator_supplied=True,
    )


__all__ = ["DecisionValidator", "DependencyKind", "PSSDependency", "PSSVerdict", "check_pss"]
