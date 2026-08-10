# `@masugate/adapter-core`

> Reader and reviewer navigation: [Documentation map](../../docs/README.md).

`@masugate/adapter-core` is the framework-neutral runtime used by MasuGate host
adapters. It depends only on `@masugate/client`; host context and credentials are
injected by the binding that owns them.

The core parses a governed route manifest, accepts a trusted principal/source
invocation, validates only the route's declared model arguments, asserts the
route owner to GAP, and returns an authoritative lifecycle presentation. It
does not import a host SDK, evaluate policy, resolve pending work, own
credentials, or invoke a host-native effect.

Bindings with a pre-existing, trusted idempotency namespace may provide a
non-model `stableId` and paired `traceId` when constructing
`TrustedInvocation`; otherwise the core derives its own `adapter-core:v1`
stable identity. This lets a migrated host preserve its deployed replay domain
without moving identity derivation into model-visible inputs.

## Conformance kit

The published `@masugate/adapter-core/conformance-fixture.json` asset and exported
helpers construct and run the common scenarios for a fake responder or any real
`masugated` endpoint. Submission sends the canonical trusted invocation and a
per-call expected principal to GAP; `masugated` durably binds that assertion to the
idempotency record. Resume and cancellation take the complete MasuGate-owned
pending locator returned by `invoke`; receipt retrieval takes its complete
operation locator. These optional operations require their declared adapter
capabilities.

The following is an integration excerpt, not a standalone program: `client` and
`clientFactory` are supplied by the host-specific binding. The executable
package tests instantiate both roles and run the complete fixture.

```text
import { readFile } from "node:fs/promises";
import {
  adapterCoreConformanceFixtureUrl,
  assertAdapterCoreConformanceCanonicalBytes,
  createAdapterCoreConformanceRuntime,
  parseAdapterCoreConformanceFixture,
  runAdapterCoreConformance,
} from "@masugate/adapter-core";

const fixture = parseAdapterCoreConformanceFixture(
  JSON.parse(await readFile(adapterCoreConformanceFixtureUrl, "utf8")),
);
const runtime = createAdapterCoreConformanceRuntime(client, fixture);
assertAdapterCoreConformanceCanonicalBytes(runtime, fixture);
// The factory returns a scenario-configured public client. It can use real
// masugated for submission/replay and deterministic responders for the remaining
// lifecycle matrix.
const report = await runAdapterCoreConformance(clientFactory, fixture);
console.log(report.passedCaseIds);
```

```bash
npm test
```
