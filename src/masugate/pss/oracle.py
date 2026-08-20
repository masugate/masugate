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


def _accesses_error(
    accesses: tuple[ScopeAccess, ...],
    *,
    subject: str,
    allow_compatible_repeats: bool,
) -> str | None:
    """Validate one access collection without using checker internals."""

    by_scope: dict[str, ScopeAccess] = {}
    for access in accesses:
        if not access.scope:
            return f"{subject} contains an empty scope name"
        if access.version < 0:
            return f"{subject} uses negative version {access.version} for {access.scope}"
        existing = by_scope.get(access.scope)
        if existing is None:
            by_scope[access.scope] = access
            continue
        if existing.version != access.version:
            return (
                f"{subject} mentions multiple versions of {access.scope} "
                f"({existing.version} and {access.version})"
            )
        if (
            existing.value is not None
            and access.value is not None
            and (
                type(existing.value) is not type(access.value)
                or existing.value != access.value
            )
        ):
            return (
                f"{subject} records conflicting values for {access.scope} "
                f"version {access.version}"
            )
        if not allow_compatible_repeats:
            return f"{subject} repeats scope {access.scope}"
        if existing.value is None and access.value is not None:
            by_scope[access.scope] = access
    return None


def _initial_state(history: History) -> dict[str, ScopeAccess]:
    error = _accesses_error(
        history.initial_versions,
        subject="initial policy state",
        allow_compatible_repeats=False,
    )
    if error is not None:
        raise ValueError(error)
    state: dict[str, ScopeAccess] = {}
    for access in history.initial_versions:
        state[access.scope] = access
    for operation in history.operations:
        for access in (*operation.reads, *operation.effect_writes):
            state.setdefault(access.scope, ScopeAccess(access.scope, 0))
    return state


def _reads_are_current(operation: Operation, state: dict[str, ScopeAccess]) -> bool:
    if (
        _accesses_error(
            operation.reads,
            subject=f"operation {operation.op_id}",
            allow_compatible_repeats=True,
        )
        is not None
    ):
        return False
    return all(state[read.scope].version == read.version for read in operation.reads)


def _writes_are_next(operation: Operation, state: dict[str, ScopeAccess]) -> bool:
    if not operation.committed and operation.effect_writes:
        return False
    seen: set[str] = set()
    for write in operation.effect_writes:
        if write.scope in seen or write.version != state[write.scope].version + 1:
            return False
        seen.add(write.scope)
    return True


def _operation_error(operation: Operation) -> str | None:
    if operation.begin_ns < 0 or operation.commit_ns < operation.begin_ns:
        return f"operation {operation.op_id} has an invalid real-time interval"
    if operation.decision is not None and operation.decision != (
        "allow" if operation.committed else "deny"
    ):
        return f"operation {operation.op_id} has a decision inconsistent with committed"
    if not operation.committed and operation.effect_writes:
        return f"denied operation {operation.op_id} contains policy-state writes"
    read_error = _accesses_error(
        operation.reads,
        subject=f"operation {operation.op_id}",
        allow_compatible_repeats=True,
    )
    if read_error is not None:
        return read_error
    return _accesses_error(
        operation.effect_writes,
        subject=f"operation {operation.op_id}",
        allow_compatible_repeats=False,
    )


def _global_chain_error(
    operations: tuple[Operation, ...],
    initial_state: dict[str, ScopeAccess],
) -> str | None:
    """Validate history-wide version chains before replaying provider code."""

    writer_of: dict[tuple[str, int], str] = {}
    writers_by_scope: dict[str, list[int]] = {}
    for operation in operations:
        for write in operation.effect_writes:
            key = (write.scope, write.version)
            existing = writer_of.get(key)
            if existing is not None:
                return (
                    f"operations {existing} and {operation.op_id} both write "
                    f"{write.scope} version {write.version}"
                )
            writer_of[key] = operation.op_id
            writers_by_scope.setdefault(write.scope, []).append(write.version)

    for scope, versions in writers_by_scope.items():
        expected = initial_state[scope].version + 1
        for version in sorted(versions):
            if version != expected:
                return (
                    f"scope {scope} has non-contiguous write versions: expected {expected}, "
                    f"found {version}"
                )
            expected += 1

    for operation in operations:
        for read in operation.reads:
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
    return None


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
    validator_supplied = decision_validator is not None
    decision_semantics_checked = False
    if len(operations) > max_operations:
        raise ValueError(f"oracle accepts at most {max_operations} operations")
    if len({operation.op_id for operation in operations}) != len(operations):
        return PSSVerdict(
            False,
            (),
            "malformed PSS history: duplicate transition identities",
            decision_validator_supplied=validator_supplied,
        )
    if any(not operation.op_id for operation in operations):
        return PSSVerdict(
            False,
            (),
            "malformed PSS history: empty transition identity",
            decision_validator_supplied=validator_supplied,
        )
    try:
        initial = _initial_state(history)
    except ValueError as exc:
        return PSSVerdict(
            False,
            (),
            f"malformed PSS history: {exc}",
            decision_validator_supplied=validator_supplied,
        )
    for operation in operations:
        operation_error = _operation_error(operation)
        if operation_error is not None:
            return PSSVerdict(
                False,
                (),
                f"malformed PSS history: {operation_error}",
                decision_validator_supplied=validator_supplied,
            )

    chain_error = _global_chain_error(operations, initial)
    if chain_error is not None:
        return PSSVerdict(
            False,
            (),
            f"malformed PSS history: {chain_error}",
            decision_validator_supplied=validator_supplied,
        )

    for order in permutations(operations):
        if real_time and not _respects_real_time(order):
            continue
        state = dict(initial)
        accepted = True
        for operation in order:
            if not _reads_are_current(operation, state) or not _writes_are_next(operation, state):
                accepted = False
                break
            if decision_validator is not None:
                decision_semantics_checked = True
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
                decision_semantics_checked=decision_semantics_checked,
                decision_validator_supplied=validator_supplied,
            )
    return PSSVerdict(
        False,
        (),
        "no serial replay makes every declared read current and every write next-version legal",
        decision_semantics_checked=decision_semantics_checked,
        decision_validator_supplied=validator_supplied,
    )


__all__ = ["check_pss_exhaustively"]
