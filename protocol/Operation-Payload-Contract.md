# MasuGate operation-payload contract

Version: `masugate.operation-payload.v1`

`POST /v1/artifacts` stages one bounded byte sequence before a declared
content-bearing operation. It is an authenticated server boundary, not a
general file service or a connector RPC.

The request contains only `action`, a declared `field`, an idempotency key,
declared media type, base64 content, and the canonical trusted host-adapter
invocation. MasuGate derives the principal, staging binding digest, SHA-256,
length, media type, classification, inspector version, opaque reference, and
expiry. The opaque reference commits every certified fact, so a mutation of
metadata in the durable availability store fails lookup before a handoff can
be constructed. It rejects caller
supplied references, digests, classifications, paths, and retention values.

The exact same binding and bytes replay the same metadata; a changed byte
sequence, invocation, or media type for the same principal/action/stable-key/
field conflicts. After byte expiry, a bounded metadata-only replay window lets
generated adapters repeat their staging call and lets the action boundary
return an already durable action or pending result without restoring content.
The replay window holds at most the configured staging-record count and evicts
the oldest expired metadata first, so expired retries are intentionally a
bounded availability feature rather than a lifetime global write quota. The
staged bytes must exactly be the UTF-8 encoding of the declared canonical
invocation field, so a caller cannot bind one model-visible string to different
connector bytes. Artifacts are bound to the authenticated principal, action,
idempotency key, adapter-invocation digest, and field. A provider obtains
metadata from that trusted binding only;
it does not accept a reference from model input. The connector worker is the
sole consumer of the opaque reference and receives a read-only reader that
verifies the reference, committed metadata, length, digest, and current TTL
at admission and read time. No API returns a filesystem path.

The action endpoint re-resolves every declared artifact from the authenticated
binding before it reaches the coordinator. It replaces the transient raw text
field with the server-derived opaque reference, so provider execution,
governance/audit records, and the protected binding contain no payload bytes.
They retain the complete immutable content-free projection (reference, digest,
byte count, media type, classification, expiry, and inspector version), so a
terminal audit can explain an already-expired payload.
An `art:` value supplied by a model is rejected; it is never a caller-selected
reference. Artifact staging and its matching action assertion share a 16,384
character bound.

The connector-facing reader is exposed only through the independently versioned
`masugate-connector-sdk` package. Its immutable `ConnectorInvocation` contains
canonical action arguments, execution id and binding digest for evidence, the
idempotency key, fence, declared reader handles, named non-printing secret
handles, and allowed destinations. It deliberately excludes the complete
protected binding, principal/policy/provider/runtime objects, stores, worker,
host context, and arbitrary server configuration. The worker creates that
projection only after it has accepted a committed handoff; it loads connector
code only after admission has verified that handoff, and only from the exact
package and `masugate.connector` entry point selected in the closed registry.
Connector code is trusted for its assigned secret and
destination authority—containment limits its blast radius but does not make a
malicious connector safe.

The reference implementation limits one payload to 8 MiB, uses a 64 MiB total
store quota, applies a one-hour TTL by default, and deletes expired staging.
The configured deployment may make those bounds stricter. Audit records use
certified metadata only, never payload bytes or mounted secret material.
The reference inspector does not decompress opaque uploads and rejects common
compressed media types, so a compressed byte stream cannot bypass the staged
or connector-reader byte quotas. A future pack that needs decompression must
provide an independently bounded inspector and decompression budget.

Generated adapters stage each declared scalar text field before the governed
action call and reuse the same stable id and canonical invocation. Nested v2
inputs remain fail-closed until an operation-specific protected-payload bridge
defines their provider request projection; they are never flattened or
serialized by an adapter as a workaround.

The independently packaged `masugate-connector-sdk` owns the offline
`masugate-connector-conformance` lifecycle/fault harness. It constructs its own
bounded invocation, artifact, secret, fence, response-loss case, and one
coherent execute/status/cancel lifecycle. Optional status/cancellation profiles
must prove their declared unsupported/quarantine behavior. Pack mutants are
closed executable invocation facts (arguments, declared artifacts/secrets, and
destinations), not connector-recognizable labels. The harness owns the effect
input oracle and requires rejection before that input is consumed; a connector
cannot pass by returning claimed case names or rejecting an arbitrary label.
