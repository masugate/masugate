# PSS correction record — v0.1.1

**Status:** research-preview correction release candidate. This record
supersedes the v0.1.0 checker explanation and documents the semantic change
that must be used by future measurements and paper revisions.

## Why the checker changed

The v0.1.0 checker used WR and WW version edges plus real-time order, then
rejected two committed operations that read the same version. That shortcut is
neither sound nor complete for the PSS definition.

| History | v0.1.0 result | Correct result | Reason |
| --- | --- | --- | --- |
| `A: r(x0), w(y1)` and `B: r(y0), w(x1)` | accepted | rejected | RW anti-dependencies form `A → B → A`; neither serial order explains both allows. |
| Two operations read unchanged `risk0` and write disjoint scopes | rejected | accepted | Both serial orders retain `risk0`; a shared read alone is not stale. |
| A completed write precedes a denial that retained an old read | may be accepted | rejected | PSS requires the denial itself to match the policy state at its serial position. |

The corrected checker constructs WR, WW, RW, and real-time dependencies,
returns their provenance, and replays its serial witness. When a provider
validator is supplied, it iteratively searches valid topological witnesses
rather than letting transition names choose one order or Python's call-stack
limit bound valid history length. The bounded search is explicitly inconclusive
on budget exhaustion. The checker also rejects malformed version
chains rather than silently overwriting duplicate writers or accepting missing
versions.

## Definition carried forward

PSS remains the intended property: a history has a serial order respecting
real time in which every terminal policy decision matches the policy evaluated
against the immediately preceding declared policy state, allows apply their
governed effects, denials apply no governed effect, and the final declared state
matches the recorded history.

The definition requires two distinct checks:

1. **Declared-state ordering.** Versioned reads/writes and real-time intervals
   admit a legal serial witness.
2. **Policy-decision replay.** The policy bundle, certified inputs, and
   provider-certified time produce the recorded allow or deny at that witness
   position.

The generic checker implements the first and accepts a provider decision
validator for the second. Its verdict distinguishes a supplied validator from
semantic replay that actually ran; callers must not describe a structural
short-circuit as arbitrary-policy replay. Retained evidence also serializes the
separate `inconclusive` status so consumers never need to infer it from prose.

## Multi-phase actions

Pending actions are not terminal decisions, but their coordination writes can
be visible. A capacity reservation therefore appears as a committed
`coordination-reservation` transition, followed by a `terminal-settlement`,
cancellation, or release transition. Both retain the same causal action
identity. The generic checker serializes those visible state transitions; the
reference evidence verifier enforces its causal pairing and lifecycle shape.
Together, that prevents a concurrent denial from observing a reservation that
is absent from the retained history.

## Evidence and compatibility

`Operation` is backward compatible with v0.1.0 captures: its original fields
remain valid, and omitted baselines still mean version zero. New captures
should populate:

- explicit `decision`;
- `policy_id` and `policy_version`;
- provider-certified `evaluation_time`;
- a digest binding the evaluation inputs to retained audit evidence;
- `causal_operation_id` and `transition_kind` where a logical action has more
  than one visible policy-state transition.

The reference procurement workload now retains policy-read values, an explicit
initial policy-state baseline, and runs its fixed spend predicate through a
provider validator. Its independent demo and release-evidence verifiers rebuild
that complete history, invoke the same validator, and compare the resulting
semantic PSS verdict rather than trusting a producer-supplied flag. They also
bind every transition's policy identity, runtime version, certified evaluation
time, and evaluation-input digest to its corresponding fully validated audit;
the audit's policy version is in turn checked against the executed release
anchor. Its
evidence records validator supply separately from actual semantic replay, so a
structural cycle is not mislabeled as policy validation. Other providers
receive only a structural PSS verdict until they pass a validator. Existing
v0.1.0 experimental PSS labels should be treated as workload-specific
invariant observations until rerun with corrected histories, the corrected
checker, and provider decision replay.

## Required gates before publication

1. The optimized checker and bounded exhaustive oracle agree on the corrected
   counterexamples and 30,000 deterministic generated bounded histories under
   both real-time modes, with baselines, effect reads, and provider decision
   validators; the regression suite also kills the historical graph-only and
   duplicate-read checker mutants.
2. Reference procurement evidence records visible reservation and settlement
   transitions with causal linkage.
3. Provider policy replay validates both allows and denials for claim-bearing
   histories.
4. Every PSS-labelled experiment is rerun; raw history evidence, checker
   verdict, semantic-replay status, and release identity are retained.
5. The paper formal section explains RW dependencies, time and policy-version
   inputs, and observable reservation transitions, and narrows any claim whose
   evidence has not yet been rerun.

Version: `0.1.1` (research-preview correction candidate). Next: [PSS checker theory](../src/masugate/pss/README.md).
