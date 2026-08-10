import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createOpenClawCodingTools } from "openclaw/plugin-sdk/agent-harness";

const baseUrl = process.argv[2];
assert.ok(baseUrl, "masugated base URL is required");
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
process.env.MASUGATE_AGENT_ALPHA_TOKEN = "openclaw-token";

const config = {
  masugatedBaseUrl: baseUrl,
  agents: { "agent-alpha": "MASUGATE_AGENT_ALPHA_TOKEN" },
  routes: {
    transfer: {
      action: "transfer",
      arguments: { receiver_id: "string", amount_cents: "integer" },
      owner: { providerId: "masugate.postgres-ledger", position: "transactional" },
    },
  },
};

function buildTool() {
  const runtimeConfig = {
    plugins: {
      allow: ["masugate"],
      load: { paths: [resolve(root, "dist/src/plugin.js")] },
      entries: { masugate: { enabled: true, config } },
    },
    tools: { allow: ["masugate_governed_action"] },
  };
  const tool = createOpenClawCodingTools({
    agentId: "agent-alpha",
    sessionId: "transcript-roundtrip",
    sessionKey: "agent:agent-alpha:main",
    config: runtimeConfig,
    cwd: root,
    workspaceDir: root,
  }).find((candidate) => candidate.name === "masugate_governed_action");
  assert.ok(tool, "real OpenClaw host resolver must select the governed tool");
  return tool;
}

if (process.argv[3] === "--registration-only") {
  const tool = buildTool();
  assert.equal(tool.name, "masugate_governed_action");
  process.stdout.write(JSON.stringify({ registered: tool.name }));
  process.exit(0);
}

const input = {
  route: "transfer",
  args: { receiver_id: "receiver", amount_cents: 1_000 },
};
const first = await buildTool().execute("openclaw-call-17", input, undefined, undefined);
const replay = await buildTool().execute("openclaw-call-17", input, undefined, undefined);

// The pinned host may emit its own diagnostics on stdout while resolving the
// optional governed tool. Keep the integration fixture's machine result
// unambiguous without requiring the host to suppress those diagnostics.
process.stdout.write(`MASUGATE_RESULT:${JSON.stringify({ first: first.details, replay: replay.details })}\n`);
