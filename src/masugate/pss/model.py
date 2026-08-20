"""Evidence model for Policy-State Serializability (PSS).

PSS is a property of *recorded policy-state transitions*.  The record must say
which version of each declared scope was observed, which version a transition
produced, and where the transition sits in real time.  Version evidence lets
the checker reconstruct a serial witness without conflating PSS with a final
invariant check.

The model deliberately keeps the policy evaluator outside the generic checker:
providers may attach policy identity, version, certified evaluation time, and
an input digest, then pass a provider-specific decision validator to
``check_pss``.  This separation makes the trusted policy-replay boundary
explicit instead of claiming that scope versions alone prove an arbitrary
policy predicate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ScopeValue = str | int | float | bool | None
Decision = Literal["allow", "deny"]
TransitionKind = Literal[
    "terminal-effect",
    "terminal-denial",
    "coordination-reservation",
    "terminal-settlement",
]


@dataclass(frozen=True)
class ScopeAccess:
    """One read or write of a logical policy-state scope.

    ``version`` names the exact state observed or produced.  ``value`` is an
    optional provider-certified read value retained for a provider-specific
    decision replay.  It is never used by the generic version checker as a
    substitute for a policy evaluator.
    """

    scope: str
    version: int
    value: ScopeValue = None


@dataclass(frozen=True)
class Operation:
    """One visible policy-state transition in a PSS history.

    ``committed`` remains the wire-compatible effect marker: a committed
    transition may write declared policy state, whereas a denied transition may
    not.  ``decision`` is optional for compatibility with v0.1.0 evidence; if
    present it must agree with ``committed``.  New evidence should record the
    policy metadata fields so a provider can bind this transition to its
    retained policy evaluation.

    A reservation that can affect another operation's policy-visible state is
    its own transition. Its later settlement is another transition with the
    same ``causal_operation_id``. This makes a pending action visible to PSS;
    provider or release-evidence verifiers enforce lifecycle pairing because
    the generic checker only decides declared-state serializability.
    """

    op_id: str
    begin_ns: int
    commit_ns: int
    committed: bool
    policy_reads: tuple[ScopeAccess, ...] = ()
    effect_reads: tuple[ScopeAccess, ...] = ()
    effect_writes: tuple[ScopeAccess, ...] = ()
    decision: Decision | None = None
    policy_id: str | None = None
    policy_version: str | None = None
    evaluation_time: str | None = None
    evaluation_input_digest: str | None = None
    causal_operation_id: str | None = None
    transition_kind: TransitionKind | None = None

    @property
    def declared_decision(self) -> Decision:
        """Return the explicit decision or the v0.1.0-compatible projection."""

        return self.decision if self.decision is not None else (
            "allow" if self.committed else "deny"
        )

    @property
    def causal_id(self) -> str:
        return self.causal_operation_id or self.op_id

    @property
    def kind(self) -> TransitionKind:
        if self.transition_kind is not None:
            return self.transition_kind
        return "terminal-effect" if self.committed else "terminal-denial"

    @property
    def read_scopes(self) -> frozenset[str]:
        return frozenset(a.scope for a in self.policy_reads) | frozenset(
            a.scope for a in self.effect_reads
        )

    @property
    def write_scopes(self) -> frozenset[str]:
        return frozenset(a.scope for a in self.effect_writes)

    @property
    def reads(self) -> tuple[ScopeAccess, ...]:
        """All declared reads that must be current at the serial position."""

        return (*self.policy_reads, *self.effect_reads)


@dataclass(frozen=True)
class History:
    """A finite PSS history and optional baseline versions for its projection.

    Histories often start at version zero, so omitted baselines default to zero.
    A retained suffix that begins after earlier transitions must declare the
    observed baseline for every such scope in ``initial_versions``.
    """

    operations: tuple[Operation, ...] = field(default_factory=tuple)
    initial_versions: tuple[ScopeAccess, ...] = ()
