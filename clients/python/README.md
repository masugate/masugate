# masugate-client

> Reader and reviewer navigation: [Documentation map](../../docs/README.md).

`masugate-client` is the typed, asynchronous Python SDK for the MasuGate Governed
Action Protocol. The distribution installs the `masugate_client` import package and
depends only on HTTPX.

## Host-adapter surface

The SDK exports the `masugate.host-adapter.v1` validators and the
`masugate.governed-route-manifest.v1` route-manifest parser. Set
`principal_id` on `MasuGateClient` and pass `ExpectedActionOwner` to
`execute(..., owner=...)` to emit server-checked identity and
provider/position/connector assertions. `get_pending`, `cancel_pending`, and
`get_audit` provide the durable locator, bounded-cancellation, replay, and
receipt surfaces required by a host adapter. A cancellation acknowledgement is
not terminal; query the locator or audit record afterward.

```bash
python -m pip install ./clients/python
```

## Usage

```python
import asyncio

from masugate_client import MasuGateClient


async def main() -> None:
    async with (
        MasuGateClient("http://127.0.0.1:8080", token="agent-token") as masugate,
        MasuGateClient("http://127.0.0.1:8080", token="operator-token") as approvals,
    ):
        result = await masugate.execute(
            "purchase",
            {"vendor": "example", "amount_cents": 2500},
            stable_id="checkout:order-184:attempt-1",
            trace_id="trace-184",
        )

        if result.status == "pending":
            assert result.pending_id is not None
            # Resolution requires a principal configured as a masugated operator;
            # an ordinary action principal cannot approve its own escalation.
            result = await approvals.resolve_pending(
                result.pending_id,
                approved=True,
                evidence={"ticket": "CAB-42"},
            )

        receipt = await masugate.get_audit(result.operation_id)
        print(receipt.decision, receipt.view_reads)


asyncio.run(main())
```

`stable_id` identifies one logical action attempt. The SDK hashes it into a
bounded, versioned idempotency key; retry the same logical action with the same
stable id to receive the original result without applying its effect twice.
Changing a stable id requests a new governed operation.

For a declared content-bearing operation field, call `stage_artifact(...)` with the same
`stable_id` and canonical trusted adapter invocation that identify the governed
operation. It accepts raw bytes and returns certified opaque metadata; it never
accepts an artifact reference, digest, path, classification, or retention
choice. The returned reference is for trusted server/provider handoff and is
not an `execute` argument.

Pending work can be consumed as a durable snapshot or as typed server-sent
events. This is a continuation of the `masugate` client created in the complete
usage example above, so it is intentionally an excerpt rather than a standalone
program:

```text
page = await masugate.list_pending()

async for event in masugate.stream_pending(last_event_id="previous-event-id"):
    print(event.pending.pending_id, event.pending.action)
```

The stream reconnect cursor is sent as `Last-Event-ID`. Pass `once=True` to
receive only the server's current durable catch-up snapshot.

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

## Errors

- `MasuGateAPIError` exposes the HTTP status, protocol error code, message, and
  optional structured details returned by `masugated`.
- `MasuGateProtocolError` means a success response or SSE event contradicted the
  Governed Action Protocol.
- `MasuGateTransportError` wraps an HTTPX networking failure.

## Development

The round-trip suite uses the real `masugate.masugated.create_app` in process with a
durable in-memory fake, so it requires the MasuGate source tree as well as this
package source. From the repository root:

```bash
PYTHONPATH=clients/python/src:connectors/sdk/src:src python -m pytest clients/python/tests
```

The release CI additionally runs Ruff and strict mypy checks; the repository
gate definitions pin those tool environments rather than assuming a local
`.venv` directory.
