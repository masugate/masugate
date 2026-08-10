# Expected results

**Audience:** artifact reviewers. Prerequisite: [Reproduction](reproduction.md).
**Support boundary:** this page describes observable command status, not a
broader scientific or deployment assurance claim.

| Check | Success | Failure meaning |
|---|---|---|
| One-time reviewer setup | Exit status `0`; prints `MasuGate reviewer inputs: /tmp/masugate-reviewer-setup/reviewer.env`; manifest records no credentials, exact locks and image IDs, elapsed time, and retained bytes | A tool or platform premise is absent, a clean clone cannot be made, a lock/hash/digest differs, an anonymous public input cannot be retrieved, or the local Docker target is incompatible |
| README five-minute `procurement` scenario | Exit status `0` in less than 300 seconds; prints `MasuGate procurement evidence: /tmp/masugate-five-minute-demo/evidence/procurement.json`; the supplied verifier confirms the unsafe stale baseline, governed PSS-valid execution, successful governed receipt, and both PSS results from the timed `run-metadata.json` | The verified release or local cache does not match the candidate, a pinned image/runtime input is absent, the stack failed, the evidence contract failed, cleanup failed, the four-observation proof is incomplete, or the five-minute requirement was missed |
| Reviewer Python descriptor integrity check | Exit status `0`; no release bundle is written | A named descriptor input, schema, lock, package, or catalog identity disagrees |
| Reviewer Python demo help check | Exit status `0`; usage lists the supported scenarios | The local Python execution environment cannot load the runner |
| Protected worker artifact | Exit status `0`; archive manifest binds the verified release, pinned base, reviewed controls, and a reloaded non-root one-pass result of `{"recovered": 0, "scanned": 0}` | Docker, the preflighted base, release wheels, containment rendering, archive identity, or closed worker startup does not meet its declared contract |
| Optional Calendar/Stripe preflight | `SKIPPED` when credentials, network, disposable accounts, or the reviewed harness are absent | A missing prerequisite is not a core-gate pass or failure |

Reference-demo JSON contains generated identifiers, timestamps, durations,
temporary directories, setup duration, retained byte counts, and environment
observations. Those values are expected
to differ across runs. The selected scenario name, schema version, terminal
outcome shape, and referenced release identity should remain consistent with
the generated descriptor. The clean-candidate documentation gate records the
full procurement command wall time, excluding the one-time setup; that value must be
below 300 seconds.

Do not interpret an optional live-service `SKIPPED` result as a connector
conformance pass. Do not interpret a descriptor check as a successful live
effect. The [artifact evaluation guide](artifact-evaluation.md) explains what
each tier can and cannot establish.

Version: `0.1.0` (research preview). Next: [Troubleshooting](troubleshooting.md).
