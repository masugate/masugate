# MasuGate MCP gateway

> Reader and reviewer navigation: [Documentation map](../docs/README.md).

`@masugate/mcp-gateway` is a local stdio MCP server that fronts one stdio MCP
upstream. Its YAML manifest divides tools into two explicit classes:

- `passthrough` tools are called on the upstream and their MCP result is
  returned unchanged;
- `governed` tools are normalized into a MasuGate action and executed by `masugated`.

Everything not listed is denied. The gateway validates every declared name
against the upstream before it starts serving requests. Because this release
does not advertise or implement MCP task handlers, a passthrough tool whose
upstream descriptor requires task execution is rejected at startup. Governed
tools return ordinary MasuGate results, so their upstream task metadata is removed.

## Execute, never check

A `committed` response from `masugated` means the provider effect already happened
inside MasuGate's protected transaction. The gateway returns that committed
payload and **does not call the upstream tool afterward**. Calling upstream at
that point would turn the response into a detached authorization token and
could apply the effect twice.

The outcome mapping is:

| MasuGate outcome | MCP result |
|---|---|
| `committed` / `allow` | committed `payload` as text and `structuredContent`; upstream is not called |
| `denied` / `deny` | `isError: true`, with policy, rule, reason, operation id, and audit reference |
| `pending` / `escalate` | immediate readable pending marker with `pending_id`, `operation_id`, and `audit_ref` |

The synthetic `masugate_audit_get` tool retrieves the latest receipt by
`operation_id`, including a terminal receipt after a pending operation is
resolved elsewhere. It is read-only and exposes no approval or resolution
authority.

## Install and run

Node.js 20 or newer is required.

```sh
npm ci
npm run build
```

Running the gateway requires a real upstream command and a reachable
`masugated`. The following is a deployment template, not a standalone
clean-artifact command: `example-manifest.yaml` must first be adapted to the
operator's upstream and credential environment.

```text
export MASUGATED_TOKEN='replace-me'
node dist/cli.js --manifest ./example-manifest.yaml
```

The process speaks MCP on stdin/stdout. Diagnostics and upstream stderr go to
stderr to preserve MCP framing.

## Manifest

```yaml
version: 1

upstream:
  command: node
  args: [./merchant-server.mjs]
  cwd: /srv/merchant
  env:
    MERCHANT_API_KEY: ${MERCHANT_API_KEY}

masugated:
  base_url: http://127.0.0.1:8000
  token_env: MASUGATED_TOKEN

governed:
  purchase:
    action: transfer
    stable_id: $.request_id
    args:
      receiver_id: $.merchant.id
      amount_cents: $.amount_cents

passthrough:
  - catalog_search
```

Every governed route requires `stable_id`, an exact JSONPath selecting the
upstream caller's durable logical-operation ID. It must resolve to a non-empty
string or safe integer. Retries and reconnects must reuse that value for the
same logical effect; do not use an MCP JSON-RPC request ID, because those IDs
are scoped only to one connection.

`governed.<tool>.args` maps MasuGate argument names to exact JSONPath selectors
over MCP tool arguments. Deterministic object-key and array-index paths are
supported, such as `$.merchant.id`, `$['merchant-id']`, and `$.items[0].sku`.
Wildcards, filters, recursive descent, unions, and script expressions are
rejected because a governed argument must normalize to exactly one string,
integer, or boolean.

Environment values written exactly as `${NAME}` are resolved from the gateway
process. A missing variable is a startup error. Other values are passed
literally.

The gateway rejects:

- malformed YAML and unknown manifest fields;
- duplicate or overlapping governed/passthrough entries;
- routes without `stable_id` or an explicit `args` map (`{}` is valid for
  no-argument actions);
- the reserved `masugate_audit_get` name;
- invalid or ambiguous JSONPath selectors;
- declared tools absent from the upstream;
- passthrough tools whose upstream descriptor has `execution.taskSupport:
  required`;
- calls to undeclared tools.

## Idempotency

The governed tool name, selected `stable_id` value, and its scalar type form
the stable logical-call input. The published `@masugate/client` SDK hashes that
input using `masugate:v1:<sha256(UTF-8 stable-id)>`, keeping the wire key bounded
while making retries and reconnects free. `masugated` fingerprints the action and
normalized arguments behind that key, so reusing a stable ID with drifted
effect data fails closed instead of replaying a mismatched result.

## Development

Run the workspace workflow from the repository root so the gateway always
resolves a freshly built `@masugate/client` package:

```sh
npm ci
npm run typecheck
npm test
npm run build
npm run pack:smoke
```

`npm run pack:gateway` is also safe on its own: it builds `@masugate/client` before
running the gateway's package dry-run.

Tests use injected upstream and `masugated` interfaces for routing guarantees and
the official MCP SDK's linked in-memory client/server transports for a protocol
smoke test. Production wiring uses the SDK's stdio client and server
transports.
