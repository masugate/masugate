# PSS checker — correctness argument

> Reader and reviewer navigation: [Documentation map](../../../docs/README.md).

The reference verifier for Policy-State Serializability (paper Def. 1). This
note argues why the two-part decision in `checker.py` — serialization-graph
acyclicity **plus** read-legality, with an optional real-time constraint — is
sound and complete for PSS on the abstract history model in `model.py`. It is
the defensible, executable correctness argument for the runtime's PSS verdict.

## What PSS requires (Def. 1, restated)

A concurrent history `H` of terminal governed operations satisfies PSS iff there
is a serial history `S(H)` such that: (1) `S(H)` respects the real-time order of
`H`; (2) every terminal decision in `S(H)` matches the policy evaluated against
the policy state immediately before the operation's serial position; (3) each
allowed op applies its effect at that position; (4) denies produce no effect;
(5) `S(H)` yields the same final policy state as `H`.

We decide "does such an `S(H)` exist" by graph construction.

Durable multi-phase actions need one additional modeling rule: if a reservation
commits policy state before the external effect is terminal, and another action
can observe that intermediate state, the reservation and settlement are
separate serializable transitions in `H`. They retain one causal action identity
in the evidence adapter but receive unique checker node identities. Compressing
both into one terminal node would hide an observable write and could violate the
same-final-state requirement.

## The two conditions

Model each op as reads/writes of scoped policy state at monotonic versions
(§`model.py`). Build a directed graph over terminal ops:

- **WR edge** `i → j` when `i` wrote scope `s` to version `v` and `j` read `s`
  at `v` (j observed i's write, so i precedes j).
- **WW edge** ordering writers of the same scope by version.
- **Real-time edge** `i → j` when `commit_ns(i) < begin_ns(j)`.

**Claim (soundness + completeness for conflict order).** Ignoring reads-legality
for a moment: a serial order consistent with all WR/WW/real-time edges exists iff
the graph is acyclic. This is the classic serialization-graph theorem
(Papadimitriou 1979) extended with the real-time precedence of linearizability
(Herlihy–Wing 1990). A topological sort of an acyclic graph *is* a serial order
respecting every edge; conversely any valid serial order induces exactly these
edges, so a cycle proves no order exists.

**Why acyclicity alone is not enough — read legality.** The graph orders ops but
does not by itself force each op to have read the *immediately preceding*
version. Two committed ops can both read version `v` of a scope and both commit;
the graph may still be acyclic (e.g. two overlapping ops, one WW edge, no WR
edge because neither read the other's write). Yet no serial order explains them:
whichever is second in the order sees the first's write and should have read
`v+1`. This is precisely **stale authorization**. So we add:

- **Read-legality:** no two committed ops may share a read `(scope, version)`.

Equivalently, on each scope the committed ops must form a chain where the op that
read version `v` is preceded by exactly `v` committed writes to that scope. A
shared read-version breaks the chain. (Denied ops are exempt: a deny that read a
stale version produced no effect, clause 4, so it cannot make the final state
wrong.)

**Together, acyclic graph + read-legality ⟺ a legal `S(H)` exists ⟺ PSS.** Read
legality guarantees clause (2) (each decision saw the immediately-prior state);
the acyclic graph guarantees clauses (1) and (3) (a real-time-respecting order in
which effects apply at their positions); clause (4) is structural (denies carry
no writes); clause (5) follows because applying the same writes in the serial
order reaches the same per-scope final version.

## Limits / assumptions

- Versions must be assigned soundly from recorded `ViewRead.version` values and
  effect writes.
- The checker decides PSS of a *recorded terminal history*; it does not itself
  observe the runtime. Garbage in (unsound versions) → garbage out — which is
  why the adapter's reconstruction is cross-checked rather than trusted.
