import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createOpenClawCodingTools } from "openclaw/plugin-sdk/agent-harness";

const baseUrl = process.argv[2];
assert.ok(baseUrl, "MasuGate reference-spend base URL is required");

const here = dirname(fileURLToPath(import.meta.url));
const pluginRoot = resolve(here, "..", "..", "openclaw");
process.env.MASUGATE_BUYER_ALPHA_TOKEN = "buyer-token";
process.env.MASUGATE_BUYER_BETA_TOKEN = "beta-token";

const config = {
  masugatedBaseUrl: baseUrl,
  agents: {
    "buyer-alpha": "MASUGATE_BUYER_ALPHA_TOKEN",
    "buyer-beta": "MASUGATE_BUYER_BETA_TOKEN",
  },
  routes: {
    purchase: {
      action: "spend.purchase",
      arguments: {
        amount_cents: "integer",
        merchant_id: "string",
        request_ref: "string",
      },
      owner: {
        providerId: "masugate.spend.reference",
        position: "protected-external",
        connectorId: "reference-purchase-v1",
      },
    },
  },
};

function governedTool(agentId, sessionId) {
  const tool = createOpenClawCodingTools({
    agentId,
    sessionId,
    sessionKey: `agent:${agentId}:main`,
    config: {
      plugins: {
        allow: ["masugate"],
        load: { paths: [pluginRoot] },
        entries: { masugate: { enabled: true, config } },
      },
      tools: { allow: ["masugate_governed_action"] },
    },
    cwd: pluginRoot,
    workspaceDir: pluginRoot,
  }).find((candidate) => candidate.name === "masugate_governed_action");
  assert.ok(tool, "real OpenClaw resolver must expose the MasuGate-owned spend tool");
  return tool;
}

const input = {
  route: "purchase",
  args: {
    amount_cents: 100,
    merchant_id: "office-supply",
    request_ref: "openclaw-reference-request",
  },
};

const alpha = governedTool("buyer-alpha", "reference-spend-alpha-session");
const beta = governedTool("buyer-beta", "reference-spend-beta-session");
const first = await alpha.execute("openclaw-spend-call-17", input, undefined, undefined);
const replay = await governedTool("buyer-alpha", "reference-spend-alpha-session").execute(
  "openclaw-spend-call-17",
  input,
  undefined,
  undefined,
);
const pending = await alpha.execute(
  "openclaw-spend-pending-18",
  {
    route: "purchase",
    args: {
      amount_cents: 600,
      merchant_id: "office-supply",
      request_ref: "openclaw-pending-request",
    },
  },
  undefined,
  undefined,
);
const [raceAlpha, raceBeta] = await Promise.all([
  alpha.execute(
    "openclaw-spend-race-alpha",
    {
      route: "purchase",
      args: {
        amount_cents: 250,
        merchant_id: "office-supply",
        request_ref: "openclaw-race-alpha",
      },
    },
    undefined,
    undefined,
  ),
  beta.execute(
    "openclaw-spend-race-beta",
    {
      route: "purchase",
      args: {
        amount_cents: 250,
        merchant_id: "office-supply",
        request_ref: "openclaw-race-beta",
      },
    },
    undefined,
    undefined,
  ),
]);

process.stdout.write(
  `MASUGATE_RESULT:${JSON.stringify({
    first: first.details,
    replay: replay.details,
    pending: pending.details,
    race: [raceAlpha.details, raceBeta.details],
  })}\n`,
);
