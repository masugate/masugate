# OpenClaw contract harness

> Reader and reviewer navigation: [Documentation map](../../docs/README.md).

This package is the executable contract oracle for the one OpenClaw release
supported by the MasuGate reference deployment. It is not the production
`@masugate/openclaw` plugin.

The harness pins and checks:

- OpenClaw `v2026.7.1`, its GitHub release manifest and commit, downloaded npm
  tarball integrity, and live GHCR index, platform, config, and provenance pins;
- Node.js `24.16.0`, matching the pinned official image;
- the public plugin entry and tool-result SDK imports;
- trusted `agentId`/`sessionKey`/`sessionId` tool-factory context plus the
  required `execute(toolCallId, ...)` seam, including the pinned host's actual
  context forwarding;
- MasuGate-owned result return, spoof-resistant identity derivation, cancellation,
  collision-free bounded replay keys, transcript-generation separation,
  duplicate delivery of the same host callback across plugin recreation, and
  exactly one protected effect;
- the pinned Gateway approval manager's wait, timeout cap, and process-local
  restart behavior and the real approval executor's timeout/cancel callback
  delivery plus fire-and-forget async callback ordering;
- executable pinned-artifact checks for approval RPC scopes and enabled-sandbox
  defaults, plus a two-process proof that the test reminder helper's public
  next-turn injection persists across restart until one destructive drain;
- a clean temporary-home install plus real `openclaw plugins inspect --runtime`
  smoke proving the pinned host loads the declared tool and hook without
  diagnostics.

Run it with the exact Node version:

```bash
cd integrations/openclaw-contract
npm ci
npm run verify:offline
```

The behavioral restart oracle locates an internal bundled Gateway chunk in the
exact pinned npm artifact. That import is deliberately test-only: production
plugin code may use only the public SDK exports recorded in
`contract/openclaw-v2026.7.1.json`.

Any OpenClaw tag, npm package, OCI image, Node version, or SDK change requires a
manifest update, a full harness run, and manual review of identity, result,
approval, restart, and sandbox deltas.

`npm run verify:offline` is the credential-free clean-artifact gate. An optional
upstream re-attestation can run `npm run verify:remote` in a separately
authorized network-enabled environment; that oracle downloads and hashes
release-manifest/checksum assets and the official Node archive, then
interrogates GHCR. It does not verify a producer signature or attestation.
`npm run verify:pins` remains the fast offline lockfile and SDK check.
