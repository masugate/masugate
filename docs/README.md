# MasuGate documentation

This map is for the `0.1.1` research-preview release. It uses stable product and
code names; it does not describe private migration history.

For the conceptual overview, interactive OpenClaw walkthrough, and project
updates, visit the [MasuGate website](https://masugate.github.io/). Return to the
[repository overview](../README.md) for the source checkout and local demo.

## Reader and researcher path

- [Concepts](concepts.md) explains declared policy state, protected execution,
  pending resolution, receipts, and PSS.
- [Architecture](architecture.md) shows the component and trust boundaries.
- [Governed action walkthrough](governed-action-walkthrough.md) traces one
  declared action through the implementation.
- [Claims and limitations](claims-and-limitations.md) states the ten recorded
  affirmative claims, their premises and required evidence, and the seven
  guarantees expressly excluded from the release boundary.
- [PSS correction record](pss-v0.1.1-correction.md) records the v0.1.1
  serializability correction and the re-measurement boundary for prior data.

## Artifact reviewer path

- [Artifact evaluation](artifact-evaluation.md) gives the review checklist.
- [Release engineering](release-engineering.md) explains the release archive,
  clean-consumer, and container reproducibility controls.
- [Protected connector worker](protected-worker.md) explains the local worker
  artifact, closed bootstrap, and containment check.
- [Reproduction](reproduction.md) distinguishes the required local tier from
  optional credentialed service checks.
- [Expected results](expected-results.md) explains success, `SKIPPED`, and
  failure outcomes.
- [Troubleshooting](troubleshooting.md) lists common environment failures
  without redefining a failed gate as success.

## Developer and extender path

- [Code map](code-map.md) points to every included top-level component.
- [Extending MasuGate](extending-masugate.md) describes the bounded extension
  surfaces.
- [Testing](testing.md) describes the checks available in this candidate.
- [Framework adapters](framework-adapters.md), the [CrewAI adapter profile](adapters/crewai.md),
  [Protocol](protocol.md), and [Connectors](connectors.md) describe their public contracts.

Version: `0.1.1` (research preview). Next: [Concepts](concepts.md).
