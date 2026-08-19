# Changelog

## 0.1.1 — 2026-08-17

- Correct Policy-State Serializability (PSS): add RW anti-dependencies,
  validate complete version chains, and replay the serial witness rather than
  using the unsound duplicate-read shortcut.
- Add a bounded exhaustive PSS oracle and counterexamples for write skew,
  shared unchanged reads, stale denials, and visible reservations.
- Retain explicit decision, policy, timing, causal-transition, and certified
  policy-read-value evidence in the reference procurement realization; its
  fixed spend predicate is replayed during workload verification.
- Search validator-backed serial witnesses, report bounded search exhaustion as
  inconclusive, and distinguish a supplied validator from semantic replay that
  actually ran in retained evidence.
- Record the correction, evidence boundary, and paper/re-measurement gates in
  `docs/pss-v0.1.1-correction.md`. Existing v0.1.0 PSS measurements require
  rerunning before they support the corrected general claim.
- Advance the coordinated research-preview artifact identities to `0.1.1`.

## 0.1.0 — 2026-08-10

- Correct Python package metadata and require descriptor verification in source CI.
- Research-preview source staged with read-only GitHub checks, a paper-backed
  citation record, reporting contact, and registry-ready package metadata.
  Public activation remains pending repository visibility, release-environment,
  and protected-branch configuration.
- Package, container, and hosted release artifacts are not published by this
  source release.
- First research-preview release of the MasuGate policy-governed action
  runtime.
- Includes the bounded framework adapters, connector and operation-pack
  distributions, protected-worker reference path, credential-free flagship
  demonstration, and claim-evidence documentation.
- Calendar and Stripe live validation remain optional and report `SKIPPED`
  without the required disposable credentials and network access.

Version: `0.1.1` (research preview). Next: [Project overview](README.md).
