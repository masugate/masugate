# MasuGate OpenClaw reference deployment

> Reader and reviewer navigation: [Documentation map](../../docs/README.md).

This package contains a bounded reference deployment for the pinned OpenClaw
adapter. It is not a general OpenClaw policy plugin, does not give an agent
direct purchase credentials, and does not establish a guarantee for arbitrary
OpenClaw configuration.

## Composition

`masugate-openclaw-reference` is a distinct `0.1.0` research-preview Python
distribution. The reusable `masugate` package excludes the deployment-specific
OpenClaw code. The checked-in reference descriptor at
[`../../release/reference-release.json`](../../release/reference-release.json)
binds the package identities, target platform, and named release inputs.

```text
@masugate/openclaw -> MasuGate action API -> Reference spend resource
                                      | PostgreSQL entitlement/outbox
                                      | PostgreSQL protected-execution store
                                      '-- authenticated reference purchase API
```

The deployment assets are under [`containment/`](containment/). They separate
the agent, gateway, governance, safe-content, database, and purchase-service
surfaces. The agent has no direct purchase credential; the trusted gateway has
the agent-scoped MasuGate credential; the connector retains a separate
server-to-server purchase credential. The bounded `masugate_governed_action`
route is the protected path to `spend.purchase`.

## Configuration

Start from [`plugin-config.example.json`](plugin-config.example.json) and
[`fleet-roster.example.json`](fleet-roster.example.json). The two agent maps
must agree. An approval-enabled deployment uses the separate
[`plugin-config.native-approval.example.json`](plugin-config.native-approval.example.json)
and a distinct resolver credential. Configuration files contain environment
variable *names*, never secret values.

The route is deliberately finite:

```json
{
  "action": "spend.purchase",
  "arguments": {},
  "owner": {
    "providerId": "masugate.spend.reference",
    "position": "protected-external",
    "connectorId": "reference-purchase-v1"
  }
}
```

Unknown agents, mismatched roster entries, shared or misbound action
credentials, missing owner assertions, and an action principal that is also an
operator are rejected by the deployment composition. A native approval choice
is presentation only: MasuGate retains the pending locator, timeout,
authorization, terminal decision, protected handoff, and audit record.

## Review boundary

The demo runner is described in [Reproduction](../../docs/reproduction.md).
It uses a disposable output directory and local container runtime; it is not a
general host-sandbox proof or a public deployment recipe. Optional live
integration work must be explicitly configured and reported as `SKIPPED` when
credentials or network access are unavailable.

Version: `0.1.0` (research preview). Next: [Architecture](../../docs/architecture.md).
