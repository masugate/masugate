"""Small exhaustive PSS oracle used to test the optimized graph checker.

This module intentionally enumerates serial orders rather than consuming the
optimized checker's dependency graph.  It is suitable only for bounded test
histories and is not a production verifier.
"""

from __future__ import annotations

from itertools import permutations
from types import MappingProxyType

from masugate.pss.checker import DecisionValidator, PSSVerdict
from masugate.pss.model import History, Operation, ScopeAccess


def _initial_state(history: History) -> dict[str, ScopeAccess]:
    state: dict[str, ScopeAccess] = {}
    for access in history.initial_versions:
        if access.scope in state and state[access.scope].version != access.version:
            raise ValueError(f"conflicting initial versions for {access.scope}")
        if access.version < 0:
            raise ValueError(f"negative initial version for {access.scope}")
        state[access.scope] = access
    for operation in history.operations:
        for access in (*operation.reads, *operation.effect_writes):
            state.setdefault(access.scope, ScopeAccess(access.scope, 0))
    return state


def _reads_are_current(operation: Operation, state: dict[str, ScopeAccess]) -> bool:
    versions: dict[str, int] = {}
    for read in operation.reads:
        if read.version < 0 or not read.scope:
            return False
        existing = versions.setdefault(read.scope, read.version)
        if existing != read.version or state[read.scope].version != read.version:
            return False
    return True


def _writes_are_next(operation: Operation, state: dict[str, ScopeAccess]) -> bool:
    if not operation.committed and operation.effect_writes:
        return False
    seen: set[str] = set()
    for write in operation.effect_writes:
        if write.scope in seen or write.version != state[write.scope].version + 1:
            return False
        seen.add(write.scope)
    return True


def _respects_real_time(order: tuple[Operation, ...]) -> bool:
    position = {operation.op_id: index for index, operation in enumerate(order)}
    for earlier in order:
        for later in order:
            if (
                earlier.op_id != later.op_id
                and earlier.commit_ns < later.begin_ns
                and position[earlier.op_id] > position[later.op_id]
            ):
                return False
    return True


def check_pss_exhaustively(
    history: History,
    *,
    real_time: bool = True,
    decision_validator: DecisionValidator | None = None,
    max_operations: int = 8,
) -> PSSVerdict:
    """Enumerate valid serial witnesses for a bounded history.

    The oracle is deliberately independent of graph construction.  It replays
    all candidate serial orders and accepts the first one that makes each
    recorded read current, each write the next version, and each optional
    provider decision validator succeed.
    """

    operations = history.operations
    checked = decision_validator is not None
    if len(operations) > max_operations:
        raise ValueError(f"oracle accepts at most {max_operations} operations")
    if len({operation.op_id for operation in operations}) != len(operations):
        return PSSVerdict(False, (), "malformed PSS history: duplicate transition identities")
    try:
        initial = _initial_state(history)
    except ValueError as exc:
        return PSSVerdict(
            False,
            (),
            f"malformed PSS history: {exc}",
            decision_semantics_checked=checked,
        )

    for order in permutations(operations):
        if real_time and not _respects_real_time(order):
            continue
        state = dict(initial)
        accepted = True
        for operation in order:
            if operation.decision is not None and operation.decision != (
                "allow" if operation.committed else "deny"
            ):
                accepted = False
                break
            if not _reads_are_current(operation, state) or not _writes_are_next(operation, state):
                accepted = False
                break
            if decision_validator is not None:
                error = decision_validator(operation, MappingProxyType(dict(state)))
                if error is not None:
                    accepted = False
                    break
            for write in operation.effect_writes:
                state[write.scope] = write
        if accepted:
            return PSSVerdict(
                True,
                (),
                "exhaustive serial replay found a valid witness",
                serial_order=tuple(operation.op_id for operation in order),
                decision_semantics_checked=checked,
            )
    return PSSVerdict(
        False,
        (),
        "no serial replay makes every declared read current and every write next-version legal",
        decision_semantics_checked=checked,
    )


__all__ = ["check_pss_exhaustively"]
