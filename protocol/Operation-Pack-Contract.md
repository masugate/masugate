# MasuGate operation-pack contract

Version: `masugate.operation-pack.v1` and `masugate.governed-route-manifest.v2`

An operation pack is a framework-neutral, declarative package of public
semantic actions. It declares the pack id/version, a bounded model input
schema, public result schema, artifact-bearing input fields, the legal effect
position, connector capabilities, maturity, and route/connector compatibility.
It cannot name a secret, a credential reference, a destination, a provider
implementation, connector code, policy fact, scope resolver, or host
framework.

`production-profile` is reserved for a `protected-external` action: its exact
connector, credential model, vendor API, and deployment gate are part of that
maturity claim. Transactional actions may be `logical-only` or
`reference-effect`, but cannot advertise a production profile.

The server-only `masugate.operation-deployment-binding.v1` document selects an
exact pack digest and binds each action to one provider identity digest and,
where required, one connector identity/configuration. Credential *references*
and destination ids live only there. The compiler emits the public v2 route
projection used by host adapters. That projection contains neither credential
references nor destination configuration, and its canonical bytes are the
cross-language identity for the generated route set. Every v2 route has one
unique `host_tool` and one unique action; a manifest cannot expose aliases for
the same action.

## Bounded schema subset

Input and public-result schemas use a deliberately small, non-coercing JSON
Schema subset: closed objects, bounded arrays, bounded strings, JavaScript-safe
integers, and booleans. `$ref`, `$defs`, composition, `default`, formats,
patterns, nullable unions, unknown keywords, open object properties, unbounded
arrays/strings, and schemas exceeding the configured canonical-byte budget are
rejected. Object properties are canonical lower-snake-case model fields.

To bound whole-document work as well as individual schemas, packs and v2
manifests allow at most 64 actions/routes, each action/route allows at most 128
artifact fields and 64 required connector capabilities, and both canonical
documents have a 1 MiB runtime byte budget. The normative schemas mirror the
collection limits; loaders, the compiler, and public clients enforce the
canonical-byte limit. Schema validators charge canonical bytes while traversing
the tree, so they stop before recursively expanding a schema whose eventual
canonical form exceeds that budget. `masugated` also checks an operation-pack file's
source bytes before JSON parsing.

Model fields additionally exclude the normalized host trust-boundary namespace
(for example, `principal_id`) and credential-shaped names, including compound
aliases such as `service_api_key`, `apikey`, `private_key`, and `access_key`.
They also exclude unsafe object keys and the generated-host namespace
(`runtime` and `model_*`) so every validated field survives strict Pydantic
tool-model construction unchanged.
The shared negative vectors in
`examples/operation-pack-v2-field-vectors.json` keep the pack compiler and
both public clients aligned on that boundary.

`masugate.governed-route-manifest.v1` remains byte-for-byte supported for scalar
profiles. V2 is additive; it never reinterprets a v1 scalar route.

## Compilation and startup gate

The compiler fails unless one binding names every action in one exact pack and
the binding's pack SHA-256 equals the canonical loaded pack. It refuses
`logical-only` actions in a generated host tool. At startup `masugated` validates
every compiled owner against the concrete `ProviderAssembly`, derives the
provider implementation/configuration digests from that exact assembled
identity, and checks the exact connector version/digests/capabilities against
the closed connector registry. Any provider, connector, configuration, owner,
capability, or pack drift fails before the HTTP service is exposed.

The included route-fixture pack is an executable contract fixture only; it
does not advertise an external effect. Independently
versioned operation and connector packages with their own effect/recovery
evidence.

## Protected payload and connector-worker substrate

For a declared `artifact_fields` member, the host stages model-provided content
through the versioned [operation-payload contract](Operation-Payload-Contract.md)
before its governed action. The public route cannot contain an artifact
reference, digest, classification, path, TTL, secret reference, destination,
or connector configuration. MasuGate derives those facts from authenticated
staging; a changed retry conflicts rather than replacing bytes.

The trusted provider resolves staged metadata from the authenticated binding
and commits it with the protected-execution handoff. `masugate-connector-worker`
accepts only that durable handoff and projects it into the public
`masugate-connector-sdk` invocation: canonical action arguments, evidence
identities, idempotency key, fence, declared destination ids, allowlisted
mounted secret handles, and verified read-only artifact readers. Connector
authors do not receive the complete protected binding, model identity, policy
or runtime objects, raw host configuration, filesystem paths, or a
caller-facing execution endpoint. The worker's deployment is derived from the
compiled private route binding and the closed connector registry, so exact
package/entry-point/SDK identity, implementation/configuration digests,
credential references, destinations, and capabilities cannot drift at startup.
The connector is trusted code for the secrets and destinations of that exact
profile; containment reduces authority but does not claim hostile connector
code is sandboxed into safety.

An `artifact_fields` member is executable only when its matching input-schema
property is a **required**, bounded `string`.  It is invalid on a
`transactional` or other non-`protected-external` action, and it cannot be an
optional, nullable, integer, array, or object field.  The compiler and both
public clients reject those packs before route generation, so the generic host
bridge never has to guess how to stage a model value.

Certified artifact metadata is part of the request binding and the durable
handoff: opaque reference, content digest and byte count, media type,
classification, normalized expiry, and inspector version are sealed together.
The provider's public audit projection preserves those content-free facts.
Workers retain that commitment for recovery; after the payload TTL expires,
status and cancellation still use the committed execution identity and fence,
while any attempt to reopen payload bytes fails closed.

The reference containment profile and Compose fragment live in
`connectors/worker/`. They require a non-root read-only worker with all Linux
capabilities dropped, no-new-privileges, one read-only named secret mount, and
only a connector network. Agent/Gateway networks, host root, Docker socket,
proxy environment, and database-administration credentials are explicitly
blocked. The Compose command runs `masugate-connector-worker
--serve-committed-handoffs` from a read-only bootstrap document. That bootstrap
has no caller-facing execution API or dynamic module/factory field; it names
only closed registry/deployment facts and durable stores, and the process
recovers/claims committed handoffs.
