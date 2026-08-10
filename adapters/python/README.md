# `masugate-adapter-core`

> Current reference-release claims and exclusions: [Claims and limitations](../../docs/claims-and-limitations.md).

`masugate-adapter-core` is the framework-neutral runtime used by MasuGate host
adapters. It depends only on `masugate-client`; host context and credentials are
injected by the binding that owns them.

The core parses a governed route manifest, accepts a trusted principal/source
invocation, validates only the route's declared model arguments, asserts the
route owner to GAP, and returns an authoritative lifecycle presentation. It
does not import a host SDK, evaluate policy, resolve pending work, own
credentials, or invoke a host-native effect.

Bindings with a pre-existing, trusted idempotency namespace may provide a
non-model `stable_id_override` and paired `trace_id` to `TrustedInvocation`;
otherwise the core derives its own `adapter-core:v1` stable identity. This lets
a migrated host preserve its deployed replay domain without moving identity
derivation into model-visible inputs.

## Conformance kit

The installed package includes `adapter-core-conformance.json` plus helpers
that construct and run the shared scenarios against either a fake GAP client or
a real `masugated` client. Submission sends the canonical trusted invocation and a
per-call expected principal to GAP; `masugated` durably binds that assertion to the
idempotency record. Resume and cancellation take the complete MasuGate-owned
pending locator returned by `invoke`; receipt retrieval takes its complete
operation locator. These optional operations require their declared adapter
capabilities.

```python
from masugate_adapter_core import (
    assert_adapter_core_conformance_canonical_bytes,
    create_adapter_core_conformance_runtime,
    load_adapter_core_conformance_fixture,
    run_adapter_core_conformance,
)

fixture = load_adapter_core_conformance_fixture()
runtime = create_adapter_core_conformance_runtime(client, fixture)
assert_adapter_core_conformance_canonical_bytes(runtime, fixture)

# The factory returns a scenario-configured public client. It can use a real
# masugated client for submission/replay and deterministic test responders for
# pending or operational lifecycle scenarios.
report = await run_adapter_core_conformance(client_factory, fixture)
assert report.passed_case_ids == tuple(identifier for identifier, _ in fixture.scenarios)
```

```bash
PYTHONPATH=adapters/python/src:clients/python/src .venv/bin/python -m pytest adapters/python/tests
```
