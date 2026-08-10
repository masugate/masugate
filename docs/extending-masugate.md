# Extending MasuGate

**Audience:** developers. Prerequisites: [Code map](code-map.md) and
[Protocol](protocol.md). **Supported boundary:** extension points already
represented by the current package, protocol, operation-pack, and connector
contracts.

## Add an operation

Create a separately versioned operation-pack package under `operations/` with
an `operation-pack.json` that validates against
[`protocol/schemas/operation-pack.schema.json`](../protocol/schemas/operation-pack.schema.json).
Bind it through the deployment-owned operation binding and connector registry;
do not let a model or request choose a provider, connector, secret, or
destination. The current pack loaders are in
[`src/masugate/operations/`](../src/masugate/operations/).

## Add a provider or connector

A provider represents declared policy-relevant state and belongs in the
protected coordination design. A connector is an effect boundary that depends
only on the public SDK. Keep those responsibilities separate. For connectors,
start from [`connectors/sdk/`](../connectors/sdk/) and add installed-entry-point
conformance coverage; for providers, start from
[`src/masugate/providers/`](../src/masugate/providers/).

## Add an adapter or protocol change

An adapter maps trusted host context to a declared route. It must not make
model-controlled fields authoritative for principal, provider, connector,
credential, or idempotency identity. Update the closed schemas, examples,
parser/client contracts, and route tests together. Do not add compatibility
aliases, fallback protocol versions, or a detached authorize-then-act path.

## Required checks

Every extension needs a narrow unit or conformance check, an identity scan for
renamed code-level identifiers, and the relevant package/schema validation.
When an extension changes a recorded claim, premise, exclusion, or evidence
gate, stop for a separate claim decision rather than revising prose alone.

Version: `0.1.0` (research preview). Next: [Connectors](connectors.md).
