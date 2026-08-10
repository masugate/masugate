# Governed Action Protocol

> Reader and reviewer navigation: [Documentation map](../docs/README.md).

The Governed Action Protocol is the HTTP boundary for `masugated`. It executes an
effect under policy and returns the result of that execution; it is deliberately
not a preflight authorization API.

This directory is the normative wire contract. The schemas use JSON
Schema Draft 2020-12. Requests and JSON responses use
`Content-Type: application/json` unless the endpoint is the Server-Sent Events
stream.

## Invariants

1. **Execute, never check.** There is no endpoint that returns a reusable allow
   token. An allow decision is valid only inside a response whose status is
   `committed`, meaning the effect was applied in the same governed operation.
   The action-result schema couples the three legal pairs structurally:
   `committed` + `allow`, `denied` + `deny`, and `pending` + `escalate`.
2. **Every submission is idempotent.** `idempotency_key` is required. Repeating
   the same authenticated request with the same key returns the original
   operation with `replayed: true` and never applies a second effect. Keys are
   scoped to the authenticated principal, so two principals may independently
   use the same caller key. Within one principal, reusing a key for different
   `action` or `args` is a `409 resource_conflict`, never a replay. Clients MUST
   bind a key to one stable logical action.
3. **Identity is server-assigned.** Every endpoint requires
   `Authorization: Bearer <token>`. `masugated` maps that credential to a principal
   and obtains trusted attributes from its registry. Action bodies cannot carry
   `principal_ref`, a principal id, attributes, or any other identity claim.
4. **Time and operation identity are server-assigned.** Action bodies cannot
   carry `timestamp` or `operation_id`. `masugated` creates the operation id, and the
   core stamps the provider-certified `request_time` from its database clock
   after acquiring the operation's complete coordination set. The current wire
   field remains `request.timestamp` for compatibility. It is the immutable
   policy-time anchor, including for request-time/window views re-evaluated at
   resolution; it is not the protected authorization evaluation point or the
   formal PSS serialization point.
5. **Resolution re-enters enforcement.** Approval is never returned as a token
   that a client may cache or apply. A human decision is submitted to
   `POST /v1/pending/{pending_id}/resolve`. A revalidate/scoped-hold plan performs
   a new complete protected policy evaluation, retaining the original
   `request_time` for request-time views and refreshing separately declared
   resolution-volatile evidence. A reservation-proof plan instead verifies and
   consumes an entitlement that preserves the admission evaluation basis. The
   admission result was escalation, not a terminal allow; the allowed operation
   is serialized when its governed effect commits at resolution.

The **authorization evaluation point** is the server-recorded logical event at
which the complete policy set is evaluated after the complete coordination set
is protected. It is fixed by execution and cannot be caller-selected or chosen
retrospectively. It is distinct from the PSS serialization point: effect commit
for allow and denial recording for deny. Scoped protection, validation, or a
verified reservation proof connects evaluation evidence to that terminal point.

Unknown JSON fields are rejected. Effect-specific argument validation remains
the responsibility of the registered MasuGate effect contract; the protocol only
requires `args` to be a JSON object.

## Authentication

All endpoints below require an HTTPS Bearer credential:

```http
Authorization: Bearer <opaque-masugated-token>
```

The token is opaque to clients. Authentication failure returns `401` using the
standard error envelope. A body field never overrides the authenticated
identity. Pending snapshots, streams, and audit receipts are visible only to
their authenticated owner and to explicitly configured operator principals;
cross-principal lookups return `404` to avoid disclosing record existence.

Trusted adapters may add an optional consistency header on action submission:

```http
MasuGate-Expected-Principal: openclaw:buyer-alpha
```

When present, `masugated` compares it to the bearer token's server-side subject and
returns `401` before policy evaluation if they differ. The header can only
restrict use of a credential; it cannot change or elevate its principal.

Trusted adapters may also assert the deployment-certified execution
owner:

```http
MasuGate-Expected-Provider: masugate.postgres-ledger
MasuGate-Expected-Position: transactional
```

`protected-external` assertions additionally require
`MasuGate-Expected-Connector`; transactional assertions must omit it. `masugated`
compares these headers to its server-side provider assembly before coordinator
admission. A deployment can mark header-asserting principals with certified
`masugate_require_action_assertions: true`; those principals fail closed when the
expected subject or owner headers are omitted or stripped. A separately named
`masugate_require_adapter_invocation: true` setting marks a strict
adapter principal and additionally requires its canonical body assertion. The
two modes are disjoint. Neither assertion can create ownership that is absent
from the server assembly.

The adapter's trusted deployment configuration is the versioned
[`host-adapter-route-manifest.schema.json`](schemas/host-adapter-route-manifest.schema.json).
It binds each host tool and its exact scalar schema to one canonical action and
these expected-owner headers. It is not submitted by a model or carried in an
action body. See the [host-adapter contract](Host-Adapter-Contract.md) for the
replacement-only boundary and cross-language golden vectors.

A separate, additive operation-pack layer provides a public
[`masugate.operation-pack.v1`](Operation-Pack-Contract.md) is compiled with one
server-only deployment binding into a
[`masugate.governed-route-manifest.v2`](schemas/governed-route-manifest-v2.schema.json)
projection. The projection admits bounded nested object/array tool schemas but
never contains credential references or allowed destinations. Existing v1
scalar manifests retain their byte-identical interpretation.

Pending resolution is an operator authority. A deployment marks certified
principals with `masugate_operator: true` (or supplies the equivalent explicit
operator set when embedding the app). An ordinary action principal cannot
approve its own escalation.

## Endpoints

### `POST /v1/actions`

Executes a governed action. The body validates against
[`action-request.schema.json`](schemas/action-request.schema.json):

```json
{
  "action": "transfer",
  "args": {"receiver_id": "merchant", "amount_cents": 2500},
  "idempotency_key": "mcp:req-7:attempt-1",
  "trace_id": "trace-2026-07-12-0007"
}
```

The server returns `200` with
[`action-response.schema.json`](schemas/action-response.schema.json) for all
three governed outcomes:

- `committed`: the decision effect is `allow` and the effect already happened;
- `denied`: the decision effect is `deny` and no effect happened;
- `pending`: the decision effect is `escalate`, no effect happened yet, and
  `pending_id` and `resolution_plan` are present. A `reservation-proof` plan
  also carries both the 64-hex `reservation_safety_certificate_digest` and
  `reservation_entitlement_digest`. The coordinator verifies the former as the
  proof basis and the latter as the exact reserved request identity before
  skipping revalidation. For trusted catalogs, the certificate also binds every
  applicable layer's bundle id/version/digest and policy declared/runtime
  identity at runtime admission; catalog-authority drift therefore fails proof
  verification after restart.

Current pending and audit producers always emit `resolution_plan`. For compatibility, consumers
may accept a legacy pending or audit representation only when
`resolution_plan` and both reservation digests are all absent. Partial legacy
metadata is invalid. `revalidate` and `scoped-hold` explicitly forbid both
digests; `reservation-proof` requires both.

`operation_id` and `audit_ref` are assigned by the server. `payload` is the
effect result for a commit and is normally empty for a deny or pending result.

### `POST /v1/artifacts`

An installed operation pack may declare content-bearing input fields.
An authenticated trusted adapter stages each one first through `POST
/v1/artifacts`; the request binds bytes to the canonical adapter invocation,
action, idempotency key, and declared field. The response contains only an
opaque server reference and certified digest, length, media type,
classification, and expiry. Callers cannot set or submit a reference, digest,
classification, storage path, or retention value. See the
[operation-payload contract](Operation-Payload-Contract.md) for replay,
expiry, provider-handoff, and connector-reader rules.
The closed request and response wire shapes are
[`artifact-request.schema.json`](schemas/artifact-request.schema.json) and
[`artifact-response.schema.json`](schemas/artifact-response.schema.json).

### `POST /v1/pending/{pending_id}/resolve`

Submits a human approval or rejection. The body validates against
[`resolve-request.schema.json`](schemas/resolve-request.schema.json):

```json
{
  "approved": true,
  "evidence": {"reviewer": "on-call-finance", "ticket": "FIN-1832"}
}
```

The server returns `200` with the action-response schema and a terminal
`committed` or `denied` status. Approval is not a promise of commitment: a
revalidation mode may return a policy deny when the approval basis is stale.
That revalidation is a new protected authorization evaluation, while the
request's certified `request_time` remains unchanged; any declared
resolution-volatile certified input is refreshed separately.
Repeated resolution of an already-resolved operation returns its terminal
result as an idempotent replay. This endpoint requires an operator credential.

### `POST /v1/pending/{pending_id}/cancel`

Requests bounded cancellation of a durable pending locator. This also requires
an operator credential; it is not a self-approval or model authorization path.
The response is the `cancellation` envelope from
[`host-adapter-lifecycle.schema.json`](schemas/host-adapter-lifecycle.schema.json):

```json
{
  "kind": "cancellation",
  "locator": {
    "operation_id": "4a006f4b-80f5-48d7-a431-b5f7eb1da8e6",
    "pending_id": "4a006f4b-80f5-48d7-a431-b5f7eb1da8e6"
  },
  "accepted": true
}
```

`accepted: true` means MasuGate accepted the cancellation request, not that the
adapter may invent a terminal result or execute a native fallback. Re-read the
pending locator or its audit receipt for the authoritative lifecycle. If a
concurrent resolver already settled it, MasuGate returns `accepted: false` and the
existing `terminal_result` instead.

### `GET /v1/pending`

Returns the caller-visible unresolved operations as
[`pending-list.schema.json`](schemas/pending-list.schema.json). The response's
opaque `next_cursor` identifies the final item in the snapshot (`"0"` for an
empty list). Ordinary principals see only their own operations; operators see
all pending work. The cursor is suitable as the initial `Last-Event-ID` when
connecting to the one-process CoreRuntime stream. Each item exposes its durable
resolution plan and, only for `reservation-proof`, its safety-certificate and
entitlement digests; the SSE event embeds the same pending-operation shape.

### `GET /v1/pending/stream`

Streams pending creation events using Server-Sent Events. Clients send
`Accept: text/event-stream`; the server replies with
`Content-Type: text/event-stream`. Each non-comment frame has this shape:

```text
id: 42
event: pending.created
data: {"event_id":"42","event_type":"pending.created",...}
```

The decoded `data` value validates against
[`pending-event.schema.json`](schemas/pending-event.schema.json), and its
`event_id` equals the SSE `id` field.

Catch-up behavior in the CoreRuntime one-process service is at-least-once:

- with `Last-Event-ID` matching a currently unresolved item, the server replays
  unresolved items after it and then continues live;
- without `Last-Event-ID`, the server replays retained unresolved
  `pending.created` events and then continues live;
- delivery is at least once across reconnects, so clients deduplicate by
  `event_id`;
- if an id no longer appears in the unresolved snapshot, the server conservatively
  replays the whole unresolved snapshot (duplicates are preferable to a missed
  approval);
- comment frames such as `: keep-alive` carry no protocol event.

`once=true` returns only the durable unresolved snapshot and closes the stream;
it is useful for batch consumers and contract tests.

### `GET /v1/audit/{operation_id}`

Returns the immutable governance receipt described by
[`audit.schema.json`](schemas/audit.schema.json): the certified request,
authenticated principal and attributes, policy ids and content versions, exact
versioned view reads, decision, and applied effect. A committed receipt contains
an effect object. A denied or pending receipt has `effect: null`. Receipts
also retain the operation's resolution plan and both reservation-proof digests,
when applicable, so an auditor can identify the proof basis and exact reserved
request after a pending operation becomes terminal. Receipts follow the same
owner/operator visibility rule as pending work.

The `policy.evaluated_policy_provenance` array is the mandatory-policy-layer receipt. For
each catalog-admitted policy it records the policy id, declared version,
runtime semantic version, canonical policy SHA-256, bundle id/version/SHA-256,
layer, and mandatory/configurable mode. Legacy raw-policy embeddings project an
empty array rather than inventing bundle authority.

The certified-context receipt names `request_time` separately and carries an ordered
`authorization_evaluations` array. Each entry records its admission/resolution
phase, fixed `evaluated_at` point, complete evaluated decision, and every
certified input's value, type, stability proof, source/contract versions,
observation/certification/expiry times, and phase. Pending resolution adds a
`human_resolution`; an automatic approval deadline instead records
`automatic_expiry` and never claims human action. A revalidation appends a
resolution evaluation while a
reservation retains the admission evaluation basis. `terminal_serialization`
then names `effect-commit` or `denial-record`, the evaluation basis it used, and
whether the receipt/effect is provider-atomic. Its `recorded_at` is a
provider-certified timestamp carried by that atomic record (the applicable
evaluation or protected resolution clock), not a claim of an independently
observable physical commit timestamp. A reservation record
therefore describes a proof over the admission evaluation basis plus later
approval and never relabels the original escalation as terminal authorization.

When a receipt includes `protected_execution`, `binding_canonical_json` carries
the exact sorted, ASCII-only JSON bytes produced for the immutable `binding` by
`ProtectedExecutionBinding`. Its `binding_digest` is SHA-256 over those exact
UTF-8 bytes; `execution_id` is `px:<digest>`, and connector evidence uses
`masugate:<digest>` as its idempotency key. Carrying the canonical form avoids
asking a consumer in another language to recreate Python number or Unicode
serialization. JSON Schema can validate those fields' shapes but cannot
recompute a hash, so protocol consumers must verify the mirror binding and all
derived identities before treating the receipt as replayable. The published
Python and TypeScript SDKs do so.

## Errors

Non-governance failures use an HTTP error status and the same envelope on every
endpoint, validated by [`error.schema.json`](schemas/error.schema.json):

```json
{
  "error": {
    "code": "invalid_request",
    "message": "request does not match the action schema",
    "details": {"field": "idempotency_key"}
  }
}
```

`details` is optional and machine-readable. The stable baseline codes are:

| HTTP | Code | Meaning |
|---:|---|---|
| 400 | `invalid_request` | Malformed JSON or protocol-schema failure |
| 401 | `unauthorized` | Missing or invalid Bearer credential |
| 404 | `not_found` | No visible audit or pending operation has that id |
| 409 | `resource_conflict` | The durable operation cannot be completed in its current state |
| 422 | `invalid_request` | A decoded body violates the closed request schema |
| 500 | `internal_error` | Unexpected server failure |

Policy denials are successful governed results (`200`, status `denied`), not
HTTP errors.

## Schema and example index

| Artifact | Applies to |
|---|---|
| `schemas/action-request.schema.json` | `POST /v1/actions` request |
| `schemas/action-response.schema.json` | action submission and resolution responses |
| `schemas/resolve-request.schema.json` | pending resolution request |
| `schemas/pending-list.schema.json` | pending snapshot response |
| `schemas/pending-event.schema.json` | SSE `data` for `pending.created` |
| `schemas/audit.schema.json` | audit receipt response |
| `schemas/error.schema.json` | every HTTP error response |

The [`examples/`](examples/) directory contains a valid instance for every
schema, all three action outcomes, and an intentionally invalid detached-allow
response used to prove that the structural invariant has teeth.
