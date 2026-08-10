# Claims and limitations

**Audience:** readers, researchers, and artifact reviewers. Start with
[Concepts](concepts.md) and use [Artifact evaluation](artifact-evaluation.md)
to assess the required evidence. **Boundary:** this page summarizes the
`0.1.0` research-preview claim ledger. It does not declare a named
gate passed, a deployment production-ready, or an external service validated.

The machine-readable
[claim ledger](claims/reference-release-claims.json) is authoritative. This
page is a reader guide to its ten affirmative claims and seven explicit
exclusions. The named gate is the evidence requirement for each claim; a
release record must contain that gate's result against its required artifact
and environment. A nearby unit test, a descriptor check, or a successful
optional live-service check does not replace a named gate.

## Affirmative claims

| Claim | Statement | Premises and required evidence |
| --- | --- | --- |
| `PSS-DECLARED-STATE` | Governed terminal histories are policy-state serializable over declared policy state. | Policy-relevant transitions stay in conforming providers and coordination domains, with the complete-mediation profile enabled. Required gates: `pytest tests/test_pss.py` and the clean-artifact PSS workload gate. |
| `TRUSTED-TOOL-IDENTITY` | The pinned OpenClaw adapter derives governed-tool identity from trusted host context and returns the MasuGate-owned result without a second native effect. | The exact host contract and allowlisted tool profile are used; model-controlled fields are not authority. Required gates: `npm test --workspace @masugate/openclaw` and `pytest tests/test_openclaw_spend_integration.py`. |
| `COMPLETE-MEDIATION-PROFILE` | The reference profile blocks tested direct paths to its named protected resources. | Administrators retain the checked-in sandbox, network, credential, mount, and tool restrictions. The boundary is the named resources and tested escape paths, not every host topology. Required gates: `pytest -m containment_live tests/test_openclaw_reference_containment_live.py` and `python scripts/verify-reference-containment.py`. |
| `DURABLE-APPROVAL-RECOVERY` | The bounded reference purchase preserves or revalidates approval authority and converges through tested restart boundaries without duplicate connector effects. | The connector retains idempotency, status-query, and fencing behavior; outcome-unknown work remains visible for reconciliation. Required gates: the spend-reference acceptance, Gateway crash-matrix, and clean-artifact recovery gates named in the ledger. |
| `REPLAYABLE-RECEIPTS` | Reference governance records retain enough versioned evidence to replay the tested authorization and protected-execution bindings. | Receipt integrity uses canonical hashes and retained release provenance. Records are not signed or independently witnessed attestations. Required gates: protocol schema/contract checks and the reference-demo evidence-mutation gate. |
| `REPRODUCIBLE-REFERENCE-RELEASE` | The bounded amd64 CPython 3.12 reference preview is assembled from a coherent manifest and checksummed clean artifacts. | The clean-install-only schema boundary and exact runtime target are respected; arbitrary platforms and upgrade compatibility are not implied. Required gates: `python scripts/build-reference-release.py --verify-only` and `pytest tests/test_release_identity.py`. |
| `BOUNDED-ADVERSARIAL-SLICE` | The clean-artifact gate reports zero governed attack successes for the named adapted AgentDojo and ASB slice over the declared mediated purchase route. | The selected slice, upstream revisions, and mediation profile remain fixed. The result does not cover arbitrary models, the full upstream corpus, or undeclared routes. Required gate: the clean-artifact reference-release gate named in the ledger. |
| `AUTHORIZATION-AND-STATE-BOUNDARIES` | The clean-artifact gate records an allowed task-semantically-wrong purchase and detects its deliberate out-of-band budget mutation against retained spend records. | The disposable reference database retains budget and consumed-entitlement state. This is not an independent signing or tamper-evidence mechanism. Required gate: the clean-artifact reference-release gate named in the ledger. |
| `BOUNDED-FLEET-MEASUREMENTS` | The clean-artifact gate retains raw two-principal timing samples, derived latency/throughput measures, resource observations, and the stated coordinator-loss result. | Measurements apply only to the named release, workload, topology, and observation environment. The server-to-server comparison bypasses provider admission and is outside the governed claim. Required gate: the clean-artifact reference-release gate named in the ledger. |
| `PINNED-OPENCLAW-INTEGRATION` | The clean-artifact gate records the pinned OpenClaw integration footprint, no-fork check, and Compose-start-to-first-governed-action time for the reference stack. | The named compatibility pin, packed adapter, MasuGate-owned tools, and sandbox profile are used. This does not establish a generic MCP integration. Required gate: the clean-artifact reference-release gate named in the ledger. |

For the exact test paths, expected outcomes, and full premise wording, consult
the machine-readable ledger. Its evidence fields define the requirements; this
reader page does not replace them.

## Explicit exclusions

The candidate does **not** claim:

- `EX-LIVENESS`: liveness, fairness, bounded wait, or freedom from starvation.
- `EX-TAMPER-ATTESTATION`: tamper-evident records, signed attestations, or
  auditor-accepted evidence.
- `EX-UNIVERSAL-MEDIATION`: complete mediation outside the named resources and
  tested paths of the reference profile.
- `EX-TASK-CORRECTNESS`: that an authorized action is task-semantically
  correct.
- `EX-LEGAL-SUFFICIENCY`: that policy projections or records are authoritative
  legal determinations or compliance-sufficiency evidence.
- `EX-PRODUCTION-READINESS`: high availability or production assurance.
- `EX-EXTERNAL-VALIDITY`: external validity for a named realistic workload;
  that question remains deferred.

## Reading evidence responsibly

The [reproduction guide](reproduction.md) separates the required local tier
from optional Calendar and Stripe checks. Missing credentials, network access,
a reviewed live harness, or a disposable account requires `SKIPPED` for an
optional check; it never proves a core property. A nonzero required command is
a failed gate, not a reason to narrow the claim or relabel the result.

See [Expected results](expected-results.md) for command status meanings and
[Paper and provenance](paper-and-provenance.md) for the research-preview and
release boundary.

Version: `0.1.0` (research preview). Next: [Artifact evaluation](artifact-evaluation.md).
