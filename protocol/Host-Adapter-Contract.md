# Host-Adapter Contract

> Reader and reviewer navigation: [Documentation map](../docs/README.md).

Version: `masugate.host-adapter.v1`

The language-neutral schema is split between `schemas/host-adapter-envelope.schema.json` (submission), `schemas/host-adapter-lifecycle.schema.json` (authoritative lifecycle, locator, cancellation, and receipt), and `schemas/host-adapter-route-manifest.schema.json` (trusted host-tool routes).

This contract is language- and framework-neutral. A host adapter derives an
authenticated principal, source namespace, and source-invocation identity from
trusted host context. A model request must not supply, override, or select any
of those values, adapter provenance, credentials, policy results, retry
authority, operation locators, or receipts.

The adapter submits only a canonical action name and typed arguments to the
Governed Action Protocol. One authenticated principal/source-invocation tuple
selects one operation and is immutably bound to its canonical adapter, action,
and arguments. Reusing that identity with changed request content is a conflict,
not a second operation or a model-controlled retry.

## Governed route manifest

`masugate.governed-route-manifest.v1` is the versioned, trusted deployment
configuration that binds one host-visible `host_tool` and exact scalar argument
schema to one canonical MasuGate action and its expected execution owner. Each
route names `provider_id` and either a `transactional` position with no
connector or a `protected-external` position with an exact `connector_id`.
The runtime sends those facts as expected-owner assertions; `masugated` compares
them with its server-certified assembly before coordinator admission.

The manifest is not a tool input, policy, or credential store. Model input can
select only a host tool already registered from it and fill that tool's declared
arguments. A host adapter must reject duplicate `host_tool` entries, untyped
arguments, reserved trust-boundary names, and incomplete owner bindings before
it accepts model work. The canonical validator sorts routes by `host_tool` for
cross-language vectors; route order does not carry authority.

The normative example is
[`host-adapter-route-manifest.json`](examples/host-adapter-route-manifest.json).

Integer action arguments are restricted to the inclusive JavaScript-safe range
`-9007199254740991` through `9007199254740991`. This bound is normative in the
schemas, SDK runtime validators, and generated host-tool schemas, so every
supported implementation preserves the exact same integer value.

Adapter argument names are already-canonical `lower_snake_case`. For the
authority-field check, underscores are removed and the resulting name is
compared with the versioned reserved set exported by the SDK. This same rule is
normative in both JSON schemas and every adapter configuration parser; an
adapter must not normalize an otherwise-invalid caller name into acceptance.
Argument names are at most 256 characters and may not use JavaScript prototype
keys (`__proto__`, `prototype`, or `constructor`).
The reserved set includes direct aliases for source identity and adapter
provenance, including `source_id`, `source_namespace`, `invocation_id`,
`contract_version`, and `adapter_capabilities`; model arguments cannot recreate
trusted envelope fields under alternate spellings.

MasuGate owns the authoritative operation identifier, committed/denied/pending
lifecycle, audit reference, and any pending locator. Protected execution may
also expose `in_progress` or `outcome_unknown`; both are operational,
nonterminal states with no policy decision or human-approval locator. Only
`committed` and `denied` are terminal results. The adapter may present pending
work and request cancellation, but a cancellation acknowledgement is not a
terminal result. It may present an opaque receipt without inventing a native
duplicate result or falling through to a host-native effect.

For a production GAP endpoint, adapters use the following public operations:

- submit the declared action through `POST /v1/actions` with the expected
  principal and owner headers plus the canonical `adapter_invocation` string;
- locate an outstanding or settled pending locator through
  `GET /v1/pending/{pending_id}`;
- request bounded operator cancellation through
  `POST /v1/pending/{pending_id}/cancel`;
- retrieve the authoritative receipt through `GET /v1/audit/{operation_id}`.

The cancellation endpoint returns the contract's cancellation envelope. An
`accepted: true` acknowledgement is intentionally nonterminal: adapters must
re-read the locator or receipt. Its locator is required to repeat the exact
`pending_id` requested in the URL; SDKs reject a response bound to another
locator. If the locator was already settled, it returns `accepted: false`
together with the prior terminal result. Cancellation is not a model
authorization path and never permits a host-native effect.

The audit reference is not an opaque adapter choice. For operation
`<operation_id>`, every lifecycle result and receipt uses exactly
`/v1/audit/<operation_id>`. An adapter must reject an otherwise well-shaped
audit reference that names another operation.

JSON Schema establishes each envelope's shape, but cannot express equality
between repeated identifiers. A lifecycle is valid only when the result and
locator `operation_id` values are identical and, for pending work, their
`pending_id` values are identical. A cancellation carrying a terminal result
must bind to the same operation; an accepted cancellation carries no terminal
result. Lifecycle and receipt audit references must also identify that same
operation. JSON arrays are dense; sparse runtime arrays are invalid even though
ordinary JSON serialization would turn their holes into `null`. The generic
TypeScript SDK's exported validators enforce the complete structural shape and
these semantic relationships. Host adapters must delegate to those validators
rather than maintain a weaker shadow result type.

For an adapter submission, the public SDK transmits the exact canonical
`masugate.host-adapter.v1` invocation string as `adapter_invocation`. `masugated`
parses it before coordinator admission, requires its principal, action, and
arguments to equal the bearer-derived GAP request, and stores its SHA-256
digest in the request's immutable replay binding. The expected-principal header
is supplied per invocation, not merely as a client-construction default. Thus a
new adapter runtime cannot turn a changed canonical adapter/source assertion
into an exact retry: it conflicts against the authoritative durable operation.
The string is an assertion from the authenticated adapter boundary, not a way
for a model to supply identity or provenance.

`action_assertion_principals` requires those principals
must supply the expected-principal and owner headers. A deployment opts into
the stricter provenance boundary through the separately named
`adapter_invocation_principals`; those principals must also supply a canonical
`adapter_invocation`. The two sets are disjoint. `masugated` applies the same
identifier length, reserved argument-name, scalar, capability-order, and
canonical-JSON constraints as the normative SDK validator before it certifies
the strict assertion's digest.

Lifecycle control-plane calls are locator-bound and capability-gated. Resume
and cancellation require the complete pending locator (`operation_id` and
`pending_id`); receipt retrieval requires the complete operation locator. A
runtime that did not declare `locator`, `pending-presentation`, `cancellation`,
or `receipt` must reject the corresponding operation locally with its typed
unsupported-capability error. Capability declarations remain schema-valid when
empty; they then expose no optional control-plane operation.

The versioned `schemas/host-adapter-roster.schema.json` artifact defines the
generic deployment configuration shape for adapter identities. Its
`principals` array may be empty. A production adapter deployment must
cross-check its configured principals and credentials at its own composition
boundary; neither an identity prefix nor a bearer-token population may infer
adapter membership. This host-neutral canary has no deployment or credential
authority.

The platform packages, protocol, SDKs, provider SPI, protected execution, and
capability packs must not import, inspect, or require host framework types,
identity prefixes, release pins, configuration layouts, credentials, or
runtime assumptions. Host-specific code ends at its adapter boundary.

The normative contract, schemas, and examples ship inside the Python `masugate`
artifact under `masugate/protocol/` as well as in this source directory. Artifact
inventory checks fail when those installed resources are absent.

The scripted responder remains a conformance fixture only: it has no policy
engine, provider credential, durable pending store, recovery loop, protected
lifecycle, or native effect. Production adapters use the public GAP routes
above; they never need the scripted responder or a Python internal result type.

The framework-neutral runtimes are documented in
[`Adapter-Core-Conformance.md`](Adapter-Core-Conformance.md). They consume this
contract and the public SDKs, but do not extract host identity, own credentials,
authorize policy, resolve pending work, or invoke host-native effects.

[`host-adapter-golden-vectors.json`](examples/host-adapter-golden-vectors.json)
is the cross-language byte-canonical corpus. Canonical envelopes use JSON
string escaping (with unpaired surrogate code units rejected), UTF-16 key
order, and ECMAScript finite-number serialization; integer-valued payload
numbers are restricted to the JavaScript-safe range. The corpus covers
reserved argument names, number and supplementary Unicode boundaries, repeated
locator/result identifiers, the route manifest,
cancellation, receipt retrieval, and every lifecycle state.
