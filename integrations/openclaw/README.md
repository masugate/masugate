# `@masugate/openclaw`

> Reader and reviewer navigation: [Documentation map](../../docs/README.md).

`@masugate/openclaw` is the production OpenClaw adapter for MasuGate-owned governed
tools. It targets the exact OpenClaw `2026.7.1` compatibility line established
by the checked-in contract oracle.

The adapter registers one static OpenClaw tool, `masugate_governed_action`. A
deployment declares its finite route catalog in trusted plugin configuration.
Each route names a MasuGate action, its exact scalar arguments, and its provider and
legal execution position. A protected-external route also names its connector;
a transactional route cannot. Model input can choose only one declared route and supply only
that route's exact arguments. It cannot supply a principal, trace namespace,
idempotency namespace, action name, credential, provider, connector, or other
reserved trust-boundary field.

## Identity and credentials

For every execution the plugin derives:

- principal `openclaw:<trusted agentId>`;
- bounded replay and trace identities from a versioned SHA-256 digest of the
  trusted `agentId`, canonical `sessionKey`, live `sessionId`, and `toolCallId`.

`sessionId` is required because OpenClaw keeps a `sessionKey` across `/new`,
daily reset, and idle expiry. The generation prevents a later transcript that
recycles a tool-call id from replaying an older effect. `runId` is not present
in the tool-factory context and is not claimed as request correlation.

`agents` maps each trusted OpenClaw agent id to a distinct environment-variable
name containing that agent's MasuGate bearer credential. The credential remains in
the OpenClaw gateway/plugin process, not in tool input or agent context. The
client sends the derived principal as `MasuGate-Expected-Principal`; `masugated` checks
it against the bearer credential's server-side principal mapping before policy
evaluation or execution. A shared or misbound credential therefore fails
closed rather than silently executing as another fleet principal.

Example OpenClaw plugin configuration:

```json
{
  "masugatedBaseUrl": "http://masugated:8000",
  "agents": {
    "buyer-alpha": "MASUGATE_BUYER_ALPHA_TOKEN"
  },
  "routes": {
    "purchase": {
      "action": "spend.purchase",
      "arguments": {
        "amount_cents": "integer",
        "merchant_id": "string",
        "request_ref": "string"
      },
      "owner": {
        "providerId": "spend-v1",
        "position": "protected-external",
        "connectorId": "purchase-v1"
      }
    }
  }
}
```

Deployments may instead supply `compiledRouteManifest` with the exact
public `masugate.governed-route-manifest.v2` output from the operation-pack
compiler. It is mutually exclusive with `routes`; plugin startup validates the
closed v2 document and uses that same projection for both model-visible TypeBox
parameters and shared route selection. V2 nested-input submission remains
deliberately fail-closed until the versioned protected-payload path is available;
the plugin never flattens a nested operation into the scalar request.

The reference deployment binds `MASUGATE_BUYER_ALPHA_TOKEN`'s value to
`openclaw:buyer-alpha`, marks that finite action roster as assertion-required,
and keeps it distinct from resolver/operator credentials. This is deployment
configuration, not a rule that makes generic `masugated` recognize an
`openclaw:` prefix: the host-neutral assertion interface supplies the assertion
seam and the purchase provider validates the reference roster against it. The
bootstrap derives the independent action-owner catalog directly from the
deployment assembly.
For this route the assembly must bind `spend.purchase` to the same provider,
`protected-external` position, and connector. The plugin sends those expected
facts on every action; `masugated` rejects missing, stripped, unknown, or mismatched
assertions before coordinator admission. Provider credentials, policy state, durable pending
state, protected effects, and recovery remain owned by MasuGate and its protected
runner; they are never placed in this plugin.

The package fails closed if a credential is shared or misbound, but it does not
by itself prove that all declared agents have one-to-one credential and server
roster entries. The `masugate-openclaw-reference` bootstrap must perform that whole
deployment composition check before serving traffic.

## Optional native approval presentation

An approval-enabled reference deployment may add this configuration:

```json
{
  "nativeApproval": {
    "resolverTokenEnv": "MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN",
    "timeoutMs": 600000
  }
}
```

The resolver environment variable must differ from every action credential and
must be available only to the trusted Gateway as a separately certified MasuGate
resolver/operator principal. This registers the optional
`masugate_resume_pending` tool. It re-reads the exact MasuGate-issued pending locator
under the trusted action identity, then presents the pinned native **allow
once** or **deny** choice. The timeout, cancel, and any unexpected decision
fail closed. `allow-always` is never offered.

Only an explicit native **allow once** or **deny** records one ordinary
resolver-authenticated MasuGate pending resolution with the exact locator and
decision evidence. Timeout, cancellation, and unexpected callback outcomes do
not fabricate human-rejection evidence; they fail closed and leave MasuGate's
durable automatic-expiry path authoritative. The callback never dispatches a
provider, creates an entitlement, or turns a native choice into a reusable
authorization token. OpenClaw's callback and reminder queue are process-local;
after a Gateway restart the durable MasuGate locator can be presented again but a
new native decision is required. See the bounded
[governed-action walkthrough](../../docs/governed-action-walkthrough.md).

## Execution boundary

A governed tool call enters `@masugate/adapter-core`, which validates the declared
route and exact scalar arguments, attaches the certified owner assertion and
canonical host provenance, and invokes `@masugate/client` exactly once. The
OpenClaw binding retains only trusted context extraction, its deployed
`openclaw:v2` replay/trace derivation, credential lookup, tool registration,
and native-approval presentation. The complete MasuGate result envelope—status,
operation id, decision, payload, audit reference, and replay marker—is
returned as the OpenClaw tool result. The adapter never calls an original
native or upstream effect afterward. Denied and pending MasuGate responses are
returned as governance outcomes, not detached authorization tokens.

Routes without complete provider/position ownership are rejected at plugin
startup; protected-external routes require a connector, while transactional
routes forbid one. Unknown routes and agents are quarantined at call time. The
plugin does not intercept or rewrite unrelated native tools; harmless reads
outside the declared protected-resource surface remain OpenClaw-owned. The
reference deployment's complete-mediation boundary is deployment-specific,
not a claim made by installing this package alone.

The packaged [gateway profile](profile/openclaw.json) is exported as
`@masugate/openclaw/profile/openclaw.json`. It explicitly allowlists plugin id
`masugate` and exposes **only** the optional `masugate_governed_action` tool; an
approval-enabled deployment must explicitly add `masugate_resume_pending` to its
reviewed profile. Copying
only the plugin configuration without that tool policy leaves the optional tool
hidden. The profile deliberately does not permit OpenClaw's mutable
`session_status` tool. It is not the deployment sandbox/egress profile.

## Development

From the repository root, use the pinned Node.js 24.16.0 runtime:

```sh
npm run typecheck --workspace @masugate/openclaw
npm test --workspace @masugate/openclaw
npm run pack:openclaw
```

The package bundles its complete runtime closure—`@masugate/adapter-core`,
`@masugate/client`, and `typebox`—as physical package contents, without workspace
links or a registry lookup for private MasuGate packages. Its OpenClaw peer remains
an optional host-provided runtime contract, not an install-time download. The
installed-artifact smoke runs the real OpenClaw installer with networking
disabled, then checks profile resolution and runtime inspection; the release
gate executes the installed governed tool.
The pinned OpenClaw peer declarations currently fail TypeScript 6's full
library check independently of this package.
