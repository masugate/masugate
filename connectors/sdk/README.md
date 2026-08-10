# MasuGate connector SDK

`masugate-connector-sdk` is the only Python import surface needed by an
independently packaged MasuGate connector. It intentionally has no dependency on
the MasuGate server, provider, worker, host adapters, database drivers, or web
frameworks.

A connector receives an immutable `ConnectorInvocation`, containing only the
declared action arguments, operation/binding identities needed for evidence,
idempotency key, fence, verified artifact readers, named non-printing secret
handles, and allowlisted destinations. It never receives a MasuGate internal
binding, policy object, provider/store handle, host context, filesystem path,
or arbitrary deployment configuration. `ConnectorOutcome`, `ConnectorEvidence`,
and the bounded JSON `ConnectorResult` payload are the corresponding public
result/evidence surface.

Workers discover a connector only through a deployment-owned `masugate.connector`
entry point whose distribution and SDK contract identity match MasuGate's closed
registry. A connector is trusted code for the secrets and destinations assigned
to that exact profile; the SDK and worker containment do not claim to make
malicious connector code safe.

The `masugate-connector-conformance` command owns and executes the installed
entry point's coherent execute/status/cancel lifecycle, response-loss fault,
and pack-owned executable invariant invocations using a synthetic bounded
invocation. A mutant file supplies full action/argument/artifact/secret/
destination facts; the harness owns the effect-input oracle and a mutant passes
only when those unsafe facts are rejected before the effect input is consumed.
Optional lifecycle capabilities instead prove their declared unsupported or
quarantine behavior. It does not accept connector-supplied pass labels or a
connector-owned conformance hook as evidence.
