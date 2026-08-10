import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createOpenClawCodingTools } from "openclaw/plugin-sdk/agent-harness";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const publicEntry = fileURLToPath(import.meta.resolve("openclaw/plugin-sdk/plugin-entry"));
const packageRoot = resolve(dirname(publicEntry), "../..");
const distFiles = await readdir(resolve(packageRoot, "dist"));

async function chunkModule(pattern, marker) {
  for (const name of distFiles.filter((candidate) => pattern.test(candidate))) {
    const path = resolve(packageRoot, "dist", name);
    if ((await readFile(path, "utf8")).includes(marker)) {
      return import(pathToFileURL(path).href);
    }
  }
  assert.fail(`pinned OpenClaw chunk missing ${marker}`);
}

const runtimeModule = await chunkModule(/^runtime-pr_.*\.js$/u, "function setActivePluginRegistry");

function committed() {
  return {
    operation_id: "11111111-1111-4111-8111-111111111111",
    status: "committed",
    decision: {
      effect: "allow",
      policy_id: "host-policy",
      policy_version: "1",
      rule_id: "allow",
      reason: "allowed",
    },
    payload: { receipt: "host-resolved" },
    audit_ref: "/v1/audit/11111111-1111-4111-8111-111111111111",
    replayed: false,
  };
}

function resolvedTools(config, sessionId) {
  return createOpenClawCodingTools({
    agentId: "buyer-alpha",
    sessionKey: "agent:buyer-alpha:main",
    sessionId,
    config,
    cwd: root,
    workspaceDir: root,
  });
}

test("reference profile opts into the optional tool through the real host resolver", async () => {
  const profile = JSON.parse(await readFile(resolve(root, "profile/openclaw.json"), "utf8"));
  assert.deepEqual(profile.plugins.allow, ["masugate"]);
  assert.deepEqual(profile.tools.allow, ["masugate_governed_action"]);

  // The published profile assumes an installed package. Point the pinned host
  // discovery layer at this source artifact for the repository oracle.
  const hostConfig = structuredClone(profile);
  hostConfig.plugins.load = { paths: [resolve(root, "dist/src/plugin.js")] };
  const requests = [];
  const previousFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    requests.push({
      input: String(input),
      method: init?.method,
      headers: new Headers(init?.headers),
      body: JSON.parse(String(init?.body)),
    });
    return new Response(JSON.stringify(committed()), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const previousToken = process.env.MASUGATE_BUYER_ALPHA_TOKEN;
  process.env.MASUGATE_BUYER_ALPHA_TOKEN = "profile-token";
  try {
    const tools = resolvedTools(hostConfig, "host-session-1");
    assert.deepEqual(
      tools.map((tool) => tool.name).sort(),
      ["masugate_governed_action"],
      "the reference profile must expose only the MasuGate-owned governed tool",
    );
    const governed = tools.find((tool) => tool.name === "masugate_governed_action");
    assert.ok(governed, "optional MasuGate tool must resolve from the versioned profile");

    const result = await governed.execute(
      "host-call-1",
      {
        route: "transfer",
        args: { receiver_id: "receiver", amount_cents: 1000 },
      },
      undefined,
      undefined,
    );
    assert.deepEqual(result.details, committed());
    assert.equal(requests.length, 1, "one host invocation must make one MasuGate call");
    assert.equal(requests[0].method, "POST");
    assert.equal(requests[0].input, "http://masugated:8000/v1/actions");
    assert.equal(requests[0].headers.get("authorization"), "Bearer profile-token");
    assert.equal(requests[0].headers.get("masugate-expected-principal"), "openclaw:buyer-alpha");
    assert.equal(requests[0].headers.get("masugate-expected-provider"), "masugate.postgres-ledger");
    assert.equal(requests[0].headers.get("masugate-expected-position"), "transactional");
    assert.equal(requests[0].headers.get("masugate-expected-connector"), null);
    assert.ok(requests[0].body.trace_id.length <= 255);
    assert.equal(
      requests[0].body.adapter_invocation,
      '{"action":{"arguments":{"amount_cents":1000,"receiver_id":"receiver"},"name":"transfer"},"adapter":{"capabilities":["locator","pending-presentation"],"contract_version":"masugate.host-adapter.v1","id":"masugate.openclaw"},"principal":{"id":"openclaw:buyer-alpha"},"source":{"id":"openclaw:v2:baf8cd54fb52b9292c94f5fc49c09e37e66402cb5c7fdaacf0ecebb079efee7e","namespace":"openclaw"}}',
      "the shared core must submit canonical host provenance alongside the established v2 identities",
    );

    const nextGeneration = resolvedTools(hostConfig, "host-session-2").find(
      (tool) => tool.name === "masugate_governed_action",
    );
    assert.ok(nextGeneration);
    await nextGeneration.execute(
      "host-call-1",
      {
        route: "transfer",
        args: { receiver_id: "receiver", amount_cents: 1000 },
      },
      undefined,
      undefined,
    );
    assert.equal(requests.length, 2);
    assert.notEqual(
      requests[1].body.idempotency_key,
      requests[0].body.idempotency_key,
    );

    const disabled = structuredClone(hostConfig);
    disabled.tools.allow = [];
    assert.equal(
      resolvedTools(disabled, "host-session-3").some(
        (tool) => tool.name === "masugate_governed_action",
      ),
      false,
      "removing the explicit allowlist must remove the governed tool",
    );
  } finally {
    if (previousToken === undefined) delete process.env.MASUGATE_BUYER_ALPHA_TOKEN;
    else process.env.MASUGATE_BUYER_ALPHA_TOKEN = previousToken;
    globalThis.fetch = previousFetch;
    runtimeModule.T();
  }
});
