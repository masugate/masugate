# Testing

**Audience:** developers and artifact reviewers. Read the [Code map](code-map.md)
first. **Supported boundary:** the `0.1.0` research-preview release,
its pinned OpenClaw reference profile, and the test paths present in this tree.
Legacy marker tokens are exact command-line selectors; they are not broader
product or assurance levels.

Tests are intentionally tiered. Run the narrow deterministic tier first, then
the service-backed or clean-artifact gate required by the claim being assessed.
A passing typecheck, unit test, package smoke, or descriptor check never replaces
a named database, containment, demonstration, or release gate.

## Source-checkout bootstrap

This local developer path is distinct from the clean-artifact reviewer setup.
The root Python package declares the in-tree connector SDK as a normal runtime
distribution, so install that SDK first when working from this source checkout:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e connectors/sdk
python -m pip install -e ".[dev]"
```

The exact static-quality tools installed by the `dev` extra are Ruff `0.6.0`,
mypy `1.11.0`, and Hypothesis `6.100.0`. Do not substitute newer versions when
reproducing the recorded formatting, lint, type, or property-test results.

The root Node workspace is also a source-checkout profile. On its supported
Linux/amd64 target, install its locked dependencies from the repository root:

```sh
npm ci
```

Run the adapter conformance tests with the Python environment above. They start
a real local `masugated` fixture and therefore require an interpreter with
the installed MasuGate dependencies (including `uvicorn`):

```sh
export MASUGATE_CONFORMANCE_PYTHON="$VIRTUAL_ENV/bin/python"
npm run typecheck
npm test
```

`MASUGATE_CONFORMANCE_PYTHON` may instead name any equivalent Python
interpreter. The `@masugate/mcp-gateway` workspace lock is intentionally
Linux/x64-only, so the root `npm test` tier is not supported on macOS or other
non-Linux/amd64 targets. Use `npm ci`, not `npm install`, so the checked-in
root lock is not rewritten.

## Test locations and entry points

The root Python suite contains these twenty-one modules:

| Module | Primary coverage |
|---|---|
| [`tests/test_masugated_models.py`](../tests/test_masugated_models.py) | daemon request, response, and validation models |
| [`tests/test_masugated.py`](../tests/test_masugated.py) | daemon endpoints and governed execution paths |
| [`tests/test_pss.py`](../tests/test_pss.py) | policy-state serializability checker and mutants |
| [`tests/test_catalog_capabilities.py`](../tests/test_catalog_capabilities.py) | operation catalog capability and deployment-boundary validation |
| [`tests/test_connector_worker_release_controls.py`](../tests/test_connector_worker_release_controls.py) | protected worker release-control and artifact-boundary checks |
| [`tests/test_flagship_demo_verifier.py`](../tests/test_flagship_demo_verifier.py) | flagship demonstration evidence verifier |
| [`tests/test_protocol_schemas.py`](../tests/test_protocol_schemas.py) | closed JSON Schema validation and examples |
| [`tests/test_protocol_contract.py`](../tests/test_protocol_contract.py) | cross-language protocol semantics and contract vectors |
| [`tests/test_openclaw_spend_integration.py`](../tests/test_openclaw_spend_integration.py) | trusted host identity and governed purchase integration |
| [`tests/test_openclaw_reference_containment_live.py`](../tests/test_openclaw_reference_containment_live.py) | live reference-profile escape-path probes |
| [`tests/test_spend_reference_app.py`](../tests/test_spend_reference_app.py) | durable approval, expiry, idempotency, and restart behavior |
| [`tests/test_gateway_recovery_gateway_crash_matrix.py`](../tests/test_gateway_recovery_gateway_crash_matrix.py) | pinned gateway crash-boundary matrix |
| [`tests/test_reference_demo_reference_demos.py`](../tests/test_reference_demo_reference_demos.py) | clean-artifact race, replay, recovery, and evidence mutation |
| [`tests/test_prepare_reference_demo_cache.py`](../tests/test_prepare_reference_demo_cache.py) | reviewer setup cache and immutable input validation |
| [`tests/test_release_verification_reference_release.py`](../tests/test_release_verification_reference_release.py) | complete clean-artifact claim and measurement gate |
| [`tests/test_npm_clean_consumer.py`](../tests/test_npm_clean_consumer.py) | offline clean-consumer lock and built-tarball resolution checks |
| [`tests/test_release_npm_build_order.py`](../tests/test_release_npm_build_order.py) | npm workspace build order and package-release boundary checks |
| [`tests/test_reference_container_artifact.py`](../tests/test_reference_container_artifact.py) | reference-container archive validation and cleanup behavior |
| [`tests/test_release_identity.py`](../tests/test_release_identity.py) | release closure, checksums, SBOM, provenance, and drift mutants |
| [`tests/test_release_controls.py`](../tests/test_release_controls.py) | immutable CI action pins, enabled read-only source checks, disabled publication workflows, compatibility matrix, and two-person release-design controls |
| [`tests/test_optional_connector_preflight.py`](../tests/test_optional_connector_preflight.py) | no-network, no-secret `SKIPPED` disposition for optional Calendar and Stripe profiles |

Package test ownership is explicit:

| Package test location | Execution owner |
|---|---|
| `clients/python/tests/` | Python package suite |
| `clients/typescript/test/` | Root npm workspace |
| `adapters/typescript/test/` | Root npm workspace |
| `gateway/test/` | Root npm workspace |
| `integrations/openclaw/test/` | Root npm workspace |
| `integrations/openclaw-contract/test/` | Clean-artifact contract gates |
| `integrations/openclaw-reference/test/` | Clean-artifact reference gates |

The root [`package.json`](../package.json) exposes the current Node workspace
`typecheck`, `test`, package-dry-run, and OpenClaw runtime-smoke entry points.
The contract/reference package suites are consumed by the clean-artifact gates
rather than by the root npm workspace.

## Tiers and ordinary commands

| Tier | Selection | Source/config binding | Meaning |
|---|---|---|---|
| Deterministic Python | `python -m pytest` | `pyproject.toml` `testpaths` and default `addopts` | Default fast suite. The checked-in `addopts` excludes PostgreSQL, live-container, optional-service, performance, demonstration, and release profiles. SQLite remains available. |
| Narrow Python | `python -m pytest tests/<module>.py` | `pyproject.toml` default `addopts` plus the selected live module path | Preferred first check for a changed component; configured marker exclusions still apply. |
| Node workspace | `npm run typecheck` followed by `npm test` | Root `package.json` scripts `typecheck` and `test` | TypeScript build/type contracts and the four root workspace test suites. |
| Package integrity | `npm run pack:smoke` | Root `package.json` script `pack:smoke` | Dry-run package contents and runtime packaging boundaries; does not establish a governance claim by itself. |
| PostgreSQL | `python -m pytest -o addopts='' -m postgres` | Registered `postgres` marker and `conftest.py` local-skip/CI-fail setup | Real durable-resource behavior using an explicit test DSN or an isolated local container. |
| Live containment | `python -m pytest -o addopts='' -m containment_live tests/test_openclaw_reference_containment_live.py` | Registered `containment_live` marker and the named live test module | Named shell, child-process, network, credential, mount, and native-tool probes in the pinned local topology. |
| Clean demonstration | `python -m pytest -o addopts='' -m reference_demo_demo_live tests/test_reference_demo_reference_demos.py` | Registered `reference_demo_demo_live` marker, named module, and reviewer setup inputs | Race, approval replay, recovery, receipts, and evidence mutants from the reviewer-prepared clean artifact. |
| Complete release gate | `python -m pytest -o addopts='' -m release_verification_release_live tests/test_release_verification_reference_release.py` | Registered `release_verification_release_live` marker, named module, and verified release directory | The bounded adversarial, state-boundary, fleet-measurement, and pinned-integration evidence gate. |

The local descriptor-integrity command is intentionally safe and credential
free:

```sh
python scripts/build-reference-release.py --verify-only
```

The release-control contract is also local and credential free:

```sh
python scripts/verify-release-controls.py
```

The clean demonstration and complete release commands use the exact values
written by the [reviewer setup](artifact-evaluation.md#exact-one-time-setup).
`MASUGATE_OFFLINE_NPM_CACHE` names a native cache whose URLs and SHA-512
payloads are validated against the checked-in OpenClaw contract lock.
`MASUGATE_SOURCE_REVISION` and `MASUGATE_SOURCE_DATE_EPOCH` bind the immutable
origin as a pair. `MASUGATE_RELEASE_VERIFICATION_RELEASE_DIR` names the verified release
built from the clean candidate. Missing, stale, or mismatched required local
inputs are gate failures, not skips.

## Pytest markers

The following twelve selectors are registered in
[`pyproject.toml`](../pyproject.toml). A configured marker can be a reserved
profile contract even when this candidate has no root module selecting it.

| Marker | Scope and prerequisite | Default run |
|---|---|---|
| `backend_matrix` | Parameterizes a compatible test over every available backend. | Included when used; PostgreSQL availability still governs the backend set. |
| `postgres` | Live PostgreSQL via `MASUGATE_TEST_POSTGRES_DSN` or an isolated local container. | Excluded. |
| `gateway_recovery_acceptance` | Durable reference-purchase acceptance on PostgreSQL. | Its current tests are also `postgres`, so excluded. |
| `gateway_recovery_crash_live` | Pinned local container topology for gateway crash boundaries. | Excluded. |
| `containment_live` | Pinned local reference topology for direct-path probes. | Excluded. |
| `connector_worker_containment_live` | Local clean-artifact worker image and checked-in Compose fragment; it starts a one-pass closed bootstrap under the containment profile. | Excluded. |
| `reference_demo_demo_live` | Reviewer-prepared clean-artifact demonstration stack. | Excluded. |
| `release_verification_release_live` | Complete reviewer-prepared clean-artifact release stack. | Excluded. |
| `google_calendar_live` | Optional disposable Calendar OAuth sandbox, credentials, and network. | Excluded. |
| `stripe_payment_intent_live` | Optional disposable Stripe test-mode account, credentials, and network. | Excluded. |
| `filesystem_live` | Reserved exact dedicated Linux/ext4 profile; no current root selector module. | Not explicitly excluded; no current root selector module runs it. |
| `performance` | Runner-sensitive PostgreSQL latency/throughput profile with the pinned stack. | Excluded. |

Use `-o addopts=''` only when deliberately selecting a non-default marker; it
removes the default exclusions, so pair it with an exact `-m` expression and
test path. Never use it to turn an unavailable required gate into a narrower
substitute.

## Shared fixtures and required services

The root [`conftest.py`](../conftest.py) owns three public suite fixtures. Their
provisioning and teardown mappings are explicit:

| Fixture | Provisioning mapping | Teardown mapping |
|---|---|---|
| `backend` | A fresh isolated `SqliteBackend`, plus `PostgresBackend` when available. | Each backend is closed by its async context manager. |
| `pg_ledger` | A unique PostgreSQL schema and an initialized `AsyncPostgresLedger`. | The ledger closes, then the schema is dropped with `CASCADE`. |
| `reference_postgres_dsn` | A unique clean PostgreSQL schema with no platform tables preinstalled. | The schema is dropped with `CASCADE`. |

| Profile | Bound pytest markers | Required local inputs/services | Absence behavior |
|---|---|---|---|
| Default Python and Node | `backend_matrix` | CPython 3.12 and the already installed locked dependencies; no credential or network requirement. | A missing installed dependency is setup failure. |
| PostgreSQL and durable acceptance | `postgres`; `gateway_recovery_acceptance` | `MASUGATE_TEST_POSTGRES_DSN`, or a working local Docker/testcontainers runtime. | Marked tests skip on an unprovisioned developer machine; CI fails closed. |
| Crash and containment | `gateway_recovery_crash_live`; `containment_live`; `connector_worker_containment_live` | Preflighted pinned local images, Docker, isolated disposable state, and the checked-in topology. The worker artifact builder runs a closed one-pass bootstrap from its archive, not a checkout. | If Docker is unavailable, the current live modules report `SKIPPED` locally and fail closed in CI. Other required-input mismatches fail. A skip is not gate evidence. |
| Clean demonstration and release | `reference_demo_demo_live`; `release_verification_release_live` | Successful reviewer setup, the exact clean candidate, native offline npm cache, pinned images, local PostgreSQL, and an explicit disposable output directory. | If Docker is unavailable, the live modules report `SKIPPED` locally and fail closed in CI. Other missing or mismatched inputs fail. The measured run uses no credentials or network access, and a skip is not gate evidence. |
| Calendar and Stripe live checks | `google_calendar_live`; `stripe_payment_intent_live` | Network access plus explicitly disposable service accounts and credentials. | Report `SKIPPED` with the missing prerequisite; local fixture coverage remains the core evidence path. |
| Filesystem live profile | `filesystem_live` | Dedicated reviewed Linux/ext4 target and its containment setup. | No current root selector is present; do not report the profile as run. |
| Performance | `performance` | Its named provisioned runner profile. | Not part of the ordinary reader tier; absence does not permit a release claim based on a smaller test. |

## Claim-to-gate map

This table is a navigation aid. The machine-readable
[`docs/claims/reference-release-claims.json`](claims/reference-release-claims.json)
remains authoritative for exact premises, paths, and expected results.

| Claim ID | Exact ledger evidence paths |
|---|---|
| `PSS-DECLARED-STATE` | `tests/test_pss.py`; `tests/test_reference_demo_reference_demos.py` |
| `TRUSTED-TOOL-IDENTITY` | `integrations/openclaw/package.json`; `integrations/openclaw/test/approval.test.ts`; `integrations/openclaw/test/host-profile.test.mjs`; `integrations/openclaw/test/plugin.test.ts`; `tests/test_openclaw_spend_integration.py` |
| `COMPLETE-MEDIATION-PROFILE` | `tests/test_openclaw_reference_containment_live.py`; `scripts/verify-reference-containment.py` |
| `DURABLE-APPROVAL-RECOVERY` | `tests/test_spend_reference_app.py`; `tests/test_gateway_recovery_gateway_crash_matrix.py`; `tests/test_reference_demo_reference_demos.py` |
| `REPLAYABLE-RECEIPTS` | `tests/test_protocol_schemas.py`; `tests/test_protocol_contract.py`; `tests/test_reference_demo_reference_demos.py` |
| `REPRODUCIBLE-REFERENCE-RELEASE` | `scripts/build-reference-release.py`; `tests/test_release_identity.py` |
| `BOUNDED-ADVERSARIAL-SLICE` | `tests/test_release_verification_reference_release.py` |
| `AUTHORIZATION-AND-STATE-BOUNDARIES` | `tests/test_release_verification_reference_release.py` |
| `BOUNDED-FLEET-MEASUREMENTS` | `tests/test_release_verification_reference_release.py` |
| `PINNED-OPENCLAW-INTEGRATION` | `tests/test_release_verification_reference_release.py` |

All 16 unique evidence paths named by these ten claims exist in this candidate.
The [claims and limitations](claims-and-limitations.md) page explains their
premises and all seven exclusions. Presence of a test path is not a recorded
pass: results must be bound to the required artifact and environment.

## Failure interpretation and limitations

- A nonzero required command is a failed gate. Preserve its output, correct the
  defect, and rerun the same gate; do not delete, skip, or relabel it.
- A PostgreSQL skip is acceptable only for an unprovisioned local development
  run. It is not evidence for a claim requiring PostgreSQL, and CI treats it as
  failure.
- A Docker-backed containment, crash, demonstration, or release test reports
  `SKIPPED` when Docker is unavailable outside CI and fails closed in CI. A
  local skip can keep pytest's process exit successful, but it is not a passed
  gate and cannot support a claim; provision the required profile and rerun it.
- Optional Calendar and Stripe checks report `SKIPPED` when credentials or
  network are absent. Their success would validate only the named disposable
  profile, not the required local claim tier.
- Tests do not establish liveness, universal mediation, task correctness,
  legal sufficiency, production readiness, tamper attestation, or external
  validity beyond the explicit ledger boundary.
- Generated test evidence, packages, release archives, and container state
  belong below explicit disposable output paths, never in the source tree.

Version: `0.1.0` (research preview). Next:
[Protocol](protocol.md).
