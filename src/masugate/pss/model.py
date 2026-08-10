"""Abstract history model for the PSS checker.

The checker operates on this model rather than on a provider event schema, so
it can verify recorded histories that carry policy-state scope versions.

A ``ScopeAccess`` is a read or write of one logical policy-state scope at a
version. Versions are monotonic per scope: reading version v means "observed the
state produced by the write that set the scope to v"; writing version v means
"this effect advanced the scope to v". The checker uses these to orient the
serialization edges.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScopeAccess:
    scope: str
    version: int


@dataclass(frozen=True)
class Operation:
    """One serializable policy-state transition in a recorded history.

    Most governed actions contribute one terminal transition. A durable
    multi-phase action may instead contribute a committed coordination
    transition (for example, a capacity reservation) and a later terminal
    transition. Keeping those independently visible is necessary when another
    operation can observe the intermediate policy-state version.

    - ``op_id``: unique id.
    - ``begin_ns`` / ``commit_ns``: real-time interval endpoints (the begin and
      terminal events). ``commit_ns`` is the serialization point observed for
      this transition (coordination commit, effect commit, or denial record).
    - ``committed``: True when this transition applied policy state, False for
      a denial.
    - ``policy_reads``: scopes+versions the policy evaluation observed.
    - ``effect_reads`` / ``effect_writes``: scopes+versions the effect touched
      (only meaningful for committed ops; a deny writes nothing).
    """

    op_id: str
    begin_ns: int
    commit_ns: int
    committed: bool
    policy_reads: tuple[ScopeAccess, ...] = ()
    effect_reads: tuple[ScopeAccess, ...] = ()
    effect_writes: tuple[ScopeAccess, ...] = ()

    @property
    def read_scopes(self) -> frozenset[str]:
        return frozenset(a.scope for a in self.policy_reads) | frozenset(
            a.scope for a in self.effect_reads
        )

    @property
    def write_scopes(self) -> frozenset[str]:
        return frozenset(a.scope for a in self.effect_writes)


@dataclass(frozen=True)
class History:
    operations: tuple[Operation, ...] = field(default_factory=tuple)
