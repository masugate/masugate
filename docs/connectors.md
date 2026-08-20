# Connectors

**Audience:** connector authors and deployment reviewers. Prerequisite:
[Architecture](architecture.md). **Supported boundary:** the public connector
SDK and the named reference profiles; arbitrary connector code remains trusted
code within its assigned deployment boundary.

The Python contract lives in
[`connectors/sdk/src/masugate_connector_sdk/`](../connectors/sdk/src/masugate_connector_sdk/)
and is summarized by the [SDK README](../connectors/sdk/README.md). A connector
receives an immutable invocation with declared arguments, idempotency and
fencing information, bounded artifact readers, named secret handles, and
allowlisted destinations. It must not receive internal policy objects, provider
stores, arbitrary deployment configuration, or a raw server binding.

## Reference profiles

- [`connectors/filesystem/`](../connectors/filesystem/) is an exact Linux/ext4
  profile with a preconfigured dedicated mount.
- [`connectors/google-calendar/`](../connectors/google-calendar/) is a bounded
  Google Calendar v3 profile.
- [`connectors/stripe-payment-intent/`](../connectors/stripe-payment-intent/)
  is a bounded Stripe PaymentIntent test-mode profile.

The filesystem profile is not a generic storage abstraction. Calendar and
Stripe are optional credentialed profiles, not required local-tier tests. A
connector test must report `SKIPPED` when a required live-service prerequisite
is absent; it must never print token content or silently turn a live failure
into an offline pass.

## Extending safely

Declare a finite action and argument surface, retain a stable idempotency key,
implement the claimed execute/status/cancel capabilities, and return bounded
evidence. Add a package-local test plus a conformance case that exercises the
installed entry point. See [Extending MasuGate](extending-masugate.md) for the
repository-level sequence.

Version: `0.1.1` (research preview). Next: [Testing](testing.md).
