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
its policy predicate from retained policy evidence.
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
    decision_semantics_checked: bool = False

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
            stack: list[tuple[str, bool]] = [(start, False)]
            while stack:
                node, leaving = stack.pop()
                if leaving:
                    color[node] = black
                    continue
                if color[node] != white:
                    continue
                color[node] = gray
                stack.append((node, True))
                for neighbor in reversed(sorted(self._adj[node])):
                    if color[neighbor] == white:
                        parent[neighbor] = node
                        stack.append((neighbor, False))
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


def _invalid(reason: str, *, checked: bool = False) -> PSSVerdict:
    return PSSVerdict(False, (), reason, decision_semantics_checked=checked)


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
                f"reads multiple versions of {access.scope} "
                f"({existing.version} and {access.version})"
            )
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


def _replay_witness(
    validated: _ValidatedHistory,
    order: tuple[str, ...],
    *,
    decision_validator: DecisionValidator | None,
) -> str | None:
    state = dict(validated.initial_state)
    by_id = {operation.op_id: operation for operation in validated.operations}
    for operation_id in order:
        operation = by_id[operation_id]
        reads, _ = _scope_versions(operation.reads)
        for scope, read in reads.items():
            current = state[scope]
            if current.version != read.version:
                return (
                    f"serial witness reads {scope} version {read.version} for {operation_id}, "
                    f"but current version is {current.version}"
                )
        if decision_validator is not None:
            decision_error = decision_validator(operation, MappingProxyType(dict(state)))
            if decision_error is not None:
                return f"decision replay rejected {operation_id}: {decision_error}"
        for write in operation.effect_writes:
            current = state[write.scope]
            if write.version != current.version + 1:
                return (
                    f"serial witness writes {write.scope} version {write.version} "
                    f"for {operation_id}, "
                    f"but current version is {current.version}"
                )
            state[write.scope] = write
    return None


def check_pss(
    history: History,
    *,
    real_time: bool = True,
    decision_validator: DecisionValidator | None = None,
) -> PSSVerdict:
    """Verify PSS for a complete declared versioned-access history.

    The checker proves existence of a serial witness for the exact reads and
    writes in the history.  Supplying ``decision_validator`` additionally
    checks every terminal decision, including denials, against provider-retained
    policy evidence at its witness position.  Without one, the verdict is a
    structural PSS result under the trusted assumption that recorded policy
    decisions and reads are faithful.
    """

    validated = _validate_history(history)
    checked = decision_validator is not None
    if isinstance(validated, str):
        return _invalid(f"malformed PSS history: {validated}", checked=checked)
    graph = _build_graph(validated, real_time=real_time)
    dependencies = graph.dependencies
    cycle = graph.find_cycle()
    if cycle:
        return PSSVerdict(
            False,
            cycle,
            _cycle_reason(cycle, dependencies),
            dependencies=dependencies,
            decision_semantics_checked=checked,
        )
    order = graph.topological_order()
    if len(order) != len(validated.operations):
        return _invalid("serialization graph did not yield a complete witness", checked=checked)
    replay_error = _replay_witness(
        validated,
        order,
        decision_validator=decision_validator,
    )
    if replay_error is not None:
        return PSSVerdict(
            False,
            (),
            replay_error,
            serial_order=order,
            dependencies=dependencies,
            decision_semantics_checked=checked,
        )
    suffix = (
        "; policy decisions replayed"
        if checked
        else "; policy predicates not replayed (trusted recorded-decision evidence)"
    )
    return PSSVerdict(
        True,
        (),
        f"acyclic WR/WW/RW/real-time dependencies + serial read/write replay{suffix}",
        serial_order=order,
        dependencies=dependencies,
        decision_semantics_checked=checked,
    )


__all__ = ["DecisionValidator", "DependencyKind", "PSSDependency", "PSSVerdict", "check_pss"]
