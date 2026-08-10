# `@masugate/client`

> Reader and reviewer navigation: [Documentation map](../../docs/README.md).

Strict TypeScript client for the MasuGate Governed Action Protocol. It uses the
built-in Fetch and Web Crypto APIs, has no runtime dependencies, and runs on
Node.js 20 or newer (as well as compatible browser and worker runtimes).

## Install and build

```sh
npm ci
npm run build
```

The package exports ESM JavaScript and declarations from `dist/`.

## Host-adapter surface

The package exports the `masugate.host-adapter.v1` validators and the
`masugate.governed-route-manifest.v1` route-manifest parser. `principalId` and the
`owner` option on `execute` emit server-checked identity and
provider/position/connector assertions. `getPending`, `cancelPending`, and
`getAudit` provide durable locator, bounded-cancellation, terminal replay, and
receipt access. A cancellation acknowledgement is nonterminal; re-read the
locator or receipt for the authoritative lifecycle.

## Usage

```ts
import { MasuGateClient } from "@masugate/client";

const masugate = new MasuGateClient({
  baseUrl: "http://127.0.0.1:8000",
  token: process.env.MASUGATED_TOKEN!,
  principalId: "openclaw:buyer-alpha",
});
const approvals = new MasuGateClient({
  baseUrl: "http://127.0.0.1:8000",
  token: process.env.MASUGATED_OPERATOR_TOKEN!,
});

const result = await masugate.execute<{ receipt_id: string }>({
  action: "transfer",
  args: { receiver_id: "merchant", amount_cents: 2500 },
  stableId: "workflow-42:transfer-1",
  traceId: "trace-42",
  owner: {
    providerId: "masugate.postgres-ledger",
    position: "transactional",
  },
});

if (result.status === "committed") {
  console.log(result.payload.receipt_id);
} else if (result.status === "pending") {
  // Only an explicitly configured operator principal may resolve approval.
  const resolved = await approvals.resolvePending({
    pendingId: result.pending_id,
    approved: true,
    evidence: { reviewer: "finance", ticket: "FIN-1832" },
  });
  console.log(resolved.status);
} else {
  console.error(result.decision?.reason ?? "operation failed without a decision");
}

const audit = await masugate.getAudit(result.operation_id);
console.log(audit.view_reads);
```

`execute` asynchronously derives `masugate:v1:<sha256(UTF-8 stableId)>` with Web
Crypto. This canonical mapping is shared by every MasuGate SDK. Use one stable ID
for one logical action and reuse it only when retrying the exact same action and
arguments. Action argument values must be strings, booleans, or safe integers;
the client rejects nulls, floats, unsafe integers, arrays, and nested objects
before making a request.

`principalId` is optional. When supplied, the client sends it as
`MasuGate-Expected-Principal`; `masugated` requires it to equal the principal mapped
from the bearer credential before an action can reach policy evaluation. This
is a fail-closed credential-subject consistency check for trusted adapters. It
cannot select or override the server-assigned principal.

For a declared content-bearing operation field, `stageArtifact` takes a `Uint8Array`,
the same `stableId`, and the canonical trusted adapter invocation used by the
governed operation. It returns certified opaque metadata and never accepts a
caller-provided reference, digest, path, classification, or retention value.
That reference is for trusted server/provider handoff, not an `execute` input.

`owner` is optional for generic clients and required by trusted adapter
profiles whose server principal sets `masugate_require_action_assertions=true` or
`masugate_require_adapter_invocation=true`. The latter strict adapter mode also
requires a canonical `adapter_invocation` body assertion.
It sends the expected server-certified provider and execution position before
admission. A `transactional` effect has no connector; a
`protected-external` effect must also supply `connectorId`. These fields only
restrict execution and cannot override `masugated`'s assembly-derived owner.

`resolvePending` accepts a pending ID but returns only a terminal `committed` or
`denied` result. A protocol-invalid second `pending` result throws
`MasuGateProtocolError`. `masugated` requires an operator credential for resolution;
an ordinary action principal cannot approve its own escalation.

## Pending stream

`streamPending` is an async iterable over decoded `pending.created` SSE data.
The following is a continuation of the `masugate` client created in the
complete usage example above, not a standalone program:

```text
let cursor: string | undefined;

for await (const event of masugate.streamPending({ lastEventId: cursor })) {
  cursor = event.event_id;
  console.log(event.pending.pending_id, event.pending.decision.reason);
}
```

Pending delivery is at least once. Persist the last processed `event_id`,
deduplicate by that ID, and provide it as `lastEventId` when reconnecting. Pass
`once: true` to consume only the server's current durable snapshot, or an
`AbortSignal` to stop a live stream.

Pending results, pending operations, and audit receipts expose
`resolution_plan`. A `reservation-proof` plan includes both
`reservation_safety_certificate_digest` and `reservation_entitlement_digest`;
`revalidate` and `scoped-hold` include neither. The client accepts an older
server response only when the plan and both digests are absent together and
rejects every partial proof shape.

Certified-context audit receipts also expose immutable `request.request_time`, ordered
`authorization_evaluations` with certified-input provenance, optional
`human_resolution` or `automatic_expiry`, and `terminal_serialization`. The latter names the logical
effect-commit/denial-record point; its timestamp is not advertised as a
separately observable physical database commit time.

All response types preserve the protocol's snake_case wire names. Non-2xx
responses throw `MasuGateHttpError`; malformed successful responses throw
`MasuGateProtocolError`. In particular, the client rejects an illegal detached
`allow` decision that is not paired with `status: "committed"`.

## Tests

```sh
npm test
```

The Node built-in test suite runs against local fake HTTP servers and covers a
committed execution plus idempotent retry, pending resolution, audit retrieval,
chunked SSE parsing, the cross-SDK hash vector, scalar argument validation, and
malformed success-response rejection. `npm pack` runs the build automatically
so a clean package always contains its exported JavaScript and declarations.
