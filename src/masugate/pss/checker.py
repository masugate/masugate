"""Policy-State Serializability (PSS) checker — the reference verifier.

Given a recorded ``History`` of terminal governed operations, decide whether it
satisfies PSS (paper Def. 1): there exists a serial order that (1) respects the
real-time order of the history and (2) makes every decision explainable against
the policy state immediately before the operation's serial position, with each
allowed effect applied at that position.

This is decided by the standard serialization-graph method (Papadimitriou 1979
for conflict-serializability; Herlihy-Wing 1990 for the real-time constraint):
build a directed graph over terminal operations whose edges are the
required orderings, and report PSS iff the graph has no cycle. See pss/README.md
for the correctness argument that acyclicity + real-time ⟺ PSS for this model.

The check has two parts, both required (a graph cycle alone is necessary but
NOT sufficient — see the read-legality note):

1. **Serialization graph acyclicity.** Edges (all mean "must precede"):
   - *version order (WR/WW):* if i writes scope s to version v and j reads s at
     v, then i → j (j observed i's write). If i and j both write s, order by
     version. These are the policy-induced conflicts of §3.4
     (W_effect(i) ∩ R_policy(j)).
   - *real-time (0.9b):* if i's terminal event precedes j's begin event
     (commit_ns(i) < begin_ns(j)), then i → j. Makes the check strict-
     serializability-like, not merely conflict-serializable.
   A cycle means no serial order satisfies the constraints ⇒ PSS violated.

2. **Read legality** (Def. 1 clause 2). Even an acyclic history can violate PSS:
   if two committed operations both read the SAME version of a scope, no serial
   order explains them — the second in any order sees the first's write, so it
   should have read version+1. Formally: on each scope, the committed writers
   form a chain v=1,2,3,…; a committed op that read version r of that scope is
   only legal if exactly r committed writes to that scope precede it in the
   serial order. Two committed ops sharing a read-version is the signature of
   stale authorization, and is illegal regardless of acyclicity.

Denied operations contribute no effect writes (they change no policy state) but
still take part in real-time ordering and read-legality (a deny that read a
stale version is fine — it produced nothing).
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import pairwise

from masugate.pss.model import History, Operation


@dataclass(frozen=True)
class PSSVerdict:
    pss: bool
    cycle: tuple[str, ...]  # op_ids forming a violating cycle, empty if none
    reason: str

    def __bool__(self) -> bool:
        return self.pss


class _Graph:
    def __init__(self, nodes: list[str]) -> None:
        self._adj: dict[str, set[str]] = {n: set() for n in nodes}

    def add_edge(self, src: str, dst: str) -> None:
        if src != dst:
            self._adj[src].add(dst)

    def find_cycle(self) -> list[str]:
        """Return one cycle (as an op_id list) if the graph has one, else []."""
        WHITE, GRAY, BLACK = 0, 1, 2
        color = dict.fromkeys(self._adj, WHITE)
        parent: dict[str, str | None] = dict.fromkeys(self._adj, None)

        def walk(start: str) -> list[str]:
            # Iterative DFS to avoid recursion limits on large histories.
            stack: list[tuple[str, bool]] = [(start, False)]
            while stack:
                node, leaving = stack.pop()
                if leaving:
                    color[node] = BLACK
                    continue
                if color[node] != WHITE:
                    continue
                color[node] = GRAY
                stack.append((node, True))
                for nbr in self._adj[node]:
                    if color[nbr] == WHITE:
                        parent[nbr] = node
                        stack.append((nbr, False))
                    elif color[nbr] == GRAY:
                        # Back edge node -> nbr: reconstruct nbr ... node nbr.
                        cyc = [node]
                        cur = node
                        while cur != nbr and parent[cur] is not None:
                            cur = parent[cur]  # type: ignore[assignment]
                            cyc.append(cur)
                        cyc.reverse()
                        return cyc
            return []

        for n in self._adj:
            if color[n] == WHITE:
                cyc = walk(n)
                if cyc:
                    return cyc
        return []


def _add_version_edges(graph: _Graph, ops: list[Operation]) -> None:
    # Index writers of (scope, version) and all writers per scope.
    writer_of: dict[tuple[str, int], str] = {}
    writers_by_scope: dict[str, list[tuple[int, str]]] = {}
    for op in ops:
        for w in op.effect_writes:
            writer_of[(w.scope, w.version)] = op.op_id
            writers_by_scope.setdefault(w.scope, []).append((w.version, op.op_id))

    # WR edges: reader of (scope, v) must follow the writer that produced v.
    for op in ops:
        for r in (*op.policy_reads, *op.effect_reads):
            writer = writer_of.get((r.scope, r.version))
            if writer is not None and writer != op.op_id:
                graph.add_edge(writer, op.op_id)

    # WW edges: order writers of the same scope by version.
    for scope_writers in writers_by_scope.values():
        ordered = [op_id for _version, op_id in sorted(scope_writers)]
        for earlier, later in pairwise(ordered):
            graph.add_edge(earlier, later)


def _add_realtime_edges(graph: _Graph, ops: list[Operation]) -> None:
    # i -> j when i's terminal event precedes j's begin event.
    # O(n^2) is appropriate for the bounded histories this verifier accepts.
    for i in ops:
        for j in ops:
            if i.op_id != j.op_id and i.commit_ns < j.begin_ns:
                graph.add_edge(i.op_id, j.op_id)


def _inconsistent_policy_snapshot(ops: list[Operation]) -> tuple[str, str] | None:
    """Reject one operation that assigns multiple versions to one scope."""

    for op in ops:
        versions_by_scope: dict[str, int] = {}
        for read in op.policy_reads:
            existing = versions_by_scope.setdefault(read.scope, read.version)
            if existing != read.version:
                return op.op_id, read.scope
    return None


def _read_legality_violation(ops: list[Operation]) -> tuple[str, str] | None:
    """Find a stale read: two COMMITTED ops that read the same (scope, version).

    In any serial order the second reader of a version would instead observe the
    write that advanced the scope, so two committed ops sharing a read-version
    cannot both be legal (Def. 1 clause 2). Returns (op_id, scope) of the second
    such reader, or None. Denied ops are exempt (they write nothing, so a stale
    read that produced no effect is harmless).
    """
    seen: dict[tuple[str, int], str] = {}
    for op in ops:
        if not op.committed:
            continue
        for key in {(read.scope, read.version) for read in op.policy_reads}:
            if key in seen:
                return op.op_id, key[0]
            seen[key] = op.op_id
    return None


def check_pss(history: History, *, real_time: bool = True) -> PSSVerdict:
    """Decide PSS for a recorded history.

    ``real_time=False`` checks conflict-serializability + read-legality (0.9a);
    the default adds the real-time constraint for full PSS (0.9b).
    """
    ops = list(history.operations)

    inconsistent = _inconsistent_policy_snapshot(ops)
    if inconsistent is not None:
        op_id, scope = inconsistent
        return PSSVerdict(
            pss=False,
            cycle=(op_id,),
            reason=(
                f"inconsistent policy snapshot: operation {op_id} read multiple versions of {scope}"
            ),
        )

    # Part 2 first (cheap, and the common stale-auth signature): read legality.
    stale = _read_legality_violation(ops)
    if stale is not None:
        op_id, scope = stale
        return PSSVerdict(
            pss=False,
            cycle=(op_id,),
            reason=(
                f"stale authorization: committed op {op_id} read a version of "
                f"{scope} already read by another committed op (no serial order "
                f"explains both)"
            ),
        )

    # Part 1: serialization graph acyclicity (+ real-time).
    graph = _Graph([op.op_id for op in ops])
    _add_version_edges(graph, ops)
    if real_time:
        _add_realtime_edges(graph, ops)

    cycle = graph.find_cycle()
    if cycle:
        kind = "serialization+real-time" if real_time else "serialization"
        return PSSVerdict(
            pss=False,
            cycle=tuple(cycle),
            reason=f"{kind} cycle among {' -> '.join(cycle)} -> {cycle[0]}",
        )
    return PSSVerdict(
        pss=True, cycle=(), reason="acyclic + reads legal; a valid serial order exists"
    )
