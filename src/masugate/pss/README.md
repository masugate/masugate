# PSS checker and corrected theory

> Reader and reviewer navigation: [Documentation map](../../../docs/README.md)
> and the [v0.1.1 correction record](../../../docs/pss-v0.1.1-correction.md).

Policy-State Serializability (PSS) is the requirement that a concurrent history
of declared policy-state transitions has a real-time-respecting serial
explanation. At each position in that explanation, the operation must observe
the declared policy state that was current immediately before it; an allow then
applies its declared effect and a deny applies no policy-state effect.

This package validates that explanation from versioned transition evidence. It
does **not** treat a final budget, inventory, or invariant check as PSS.

## Corrected history model

For every visible transition, the history retains:

- its unique transition identity and real-time interval;
- every policy and effect read as a `(scope, version)` read-from witness;
- every policy-state write as the next version of its scope;
- whether the transition committed and, in v0.1.1 evidence, the recorded
  allow/deny decision, policy identity/version, certified evaluation time, and
  evaluation-input digest;
- a causal action identity and transition kind for multi-phase operations.

A retained history suffix may declare a baseline version for each included
scope. A history that starts at the ordinary initial state omits those entries,
which means version zero.

Reservations are visible transitions. If creating a reservation changes
capacity seen by a concurrent policy evaluation, the reservation write is one
PSS node and later settlement, cancellation, or release is another node with
the same causal action identity. Omitting a pending reservation would make a
subsequent capacity denial impossible to explain from the terminal history.
The generic checker serializes those declared state transitions; a provider or
release-evidence verifier remains responsible for enforcing its own lifecycle
pairing and causal-identity rules.

## Dependency graph

For every declared scope, the checker adds all four required orderings:

- **WR**: if transition `i` writes version `v` and transition `j` reads `v`,
  then `i → j`.
- **WW**: writers of one scope follow its monotonic version order.
- **RW**: if transition `i` reads version `v` and transition `j` writes a
  later version of that scope, then `i → j`.
- **Real time**: if `commit_ns(i) < begin_ns(j)`, then `i → j`.

The RW anti-dependency is the critical v0.1.1 repair. Consider concurrent
operations `A: r(x0), w(y1)` and `B: r(y0), w(x1)`. Neither serial order can
explain both reads. RW creates `A → B` and `B → A`, so the graph has a cycle.
WR and WW alone incorrectly accept this write-skew history.

Conversely, `A` and `B` may both read an unchanged risk scope and write
disjoint private scopes. Shared reads are legal when no later write makes one
of them stale; v0.1.0's blanket duplicate-read rejection was therefore also
incorrect.

## Decision legality and trusted replay

An acyclic dependency graph yields a witness space. Without a decision
validator, the checker deterministically replays one topological order: every
read must see the current version and every write must advance its scope by
exactly one. A recorded denial participates in this replay exactly like an
allow, except that it writes no policy state. Thus a stale denial cannot be
accepted merely because it had no effect.

Versions prove that the recorded policy evaluation observed the correct
*declared state*. They cannot by themselves evaluate an arbitrary policy
program. Providers that want the checker to verify predicate outcomes pass a
`DecisionValidator` to `check_pss`. The validator receives the operation and
witness-prefix state and may replay the retained policy bundle and inputs. To
preserve PSS's existential definition, the checker searches ready transitions
when a validator is supplied; it accepts the first serial witness whose policy
decisions replay. The search is deterministic and bounded by
`max_witness_search_steps` (100,000 operation attempts by default). Exhausting
that budget returns a fail-closed, explicitly `inconclusive` verdict rather
than claiming that no witness exists.

`decision_validator_supplied` records configuration, while
`decision_semantics_checked` is true only if the callback actually ran. This
keeps a structural cycle or malformed-history rejection from being mislabeled
as policy replay. Without a validator, a successful verdict is structural PSS
under the explicit trusted assumption that retained policy decisions and reads
are faithful.

Certified evaluation time and policy identity/version belong to this replay
boundary. A rolling window or an activated policy version must be provided to
the validator as recorded, provider-certified input; it is not inferred from a
caller clock or from effect versions alone.

## Correctness argument for the declared version model

Assume that the retained history is complete for its declared scopes: every
policy/effect read is recorded with its observed version, every visible write is
recorded with a unique monotonic version, and baselines cover any omitted prior
history. Under these assumptions:

1. Every legal serial explanation obeys WR, WW, RW, and real-time edges. In
   particular, a reader of `v` must precede any writer of a later version;
   otherwise the reader would observe that later version.
2. A graph cycle therefore rules out a serial explanation.
3. If the graph is acyclic, each topological order respects every required
   dependency. Structural replay requires every read to equal the current
   version and each write to be the next version.
4. With a provider decision validator, the checker searches those orders until
   one accepts every transition at its witness prefix. That witness also
   establishes the policy-predicate clauses of PSS, including denials.

The bounded oracle in `oracle.py` independently enumerates serial orders and
replays them. The test gate compares it with the optimized graph checker on
30,000 deterministic generated histories of at most four operations, under
both real-time modes and with explicit baselines, decisions, effect reads, and
provider validators. It covers serial chains, stale reads, write skew, shared
unchanged reads, version gaps, mutual dependencies, reservations, and
validator-selected witness order. Mutation regressions also show that the
pre-v0.1.1 graph-only checker accepts write skew and that the former global
duplicate-read heuristic rejects a legal shared read. The oracle is
intentionally not a production path.

## Limits and assumptions

- The checker decides a recorded declared-state history, not the behavior of
  undeclared state, direct provider bypasses, or an arbitrary host topology.
- A policy predicate is semantically verified only when its provider supplies
  a validator and retained evidence sufficient to replay it.
- A validator-backed history that exceeds the configured semantic-search budget
  is inconclusive and must not support a positive PSS claim.
- PSS is a safety property. It does not imply liveness, fairness, bounded
  waiting, task correctness, or unconditional exactly-once external effects.
- A connector's external-effect guarantees remain conditional on its stated
  idempotency, fencing, status-query, and reconciliation contracts.
