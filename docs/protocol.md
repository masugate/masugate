# Protocol guide

**Audience:** client, adapter, and service developers. Prerequisite:
[Concepts](concepts.md). **Normative material:** the schemas and examples under
[`protocol/`](../protocol/), especially [the protocol overview](../protocol/README.md).

The current protocol uses closed JSON Schema documents. Start with these
concrete files:

- [`action-request.schema.json`](../protocol/schemas/action-request.schema.json)
  and [`action-response.schema.json`](../protocol/schemas/action-response.schema.json)
  for execution;
- [`pending-list.schema.json`](../protocol/schemas/pending-list.schema.json)
  and [`pending-event.schema.json`](../protocol/schemas/pending-event.schema.json)
  for durable pending state and streams;
- [`audit.schema.json`](../protocol/schemas/audit.schema.json) for receipts;
- [`host-adapter-envelope.schema.json`](../protocol/schemas/host-adapter-envelope.schema.json)
  and [`governed-route-manifest-v2.schema.json`](../protocol/schemas/governed-route-manifest-v2.schema.json)
  for trusted adapter configuration.

Use the paired JSON files in [`protocol/examples/`](../protocol/examples/) as
testable fixtures. Do not treat an example bearer value, idempotency key, or
identifier as a real credential.

## Lifecycle and versioning

The action lifecycle is `committed`, `denied`, or `pending`. A pending operation
is resolved through the dedicated closed request shape, not by applying a
previous allow out of band. Schemas reject unknown fields where the contract
requires a closed object. Protocol names and versioned identifiers are code-level
interfaces: change them only alongside their schemas, examples, parsers, and
conformance tests.

The daemon’s HTTP wiring is in
[`src/masugate/masugated/app.py`](../src/masugate/masugated/app.py); typed
client parsers are in
[`clients/python/src/masugate_client/`](../clients/python/src/masugate_client/).
For the full execution path, read the [governed action walkthrough](governed-action-walkthrough.md).

Version: `0.1.0` (research preview). Next: [Connectors](connectors.md).
