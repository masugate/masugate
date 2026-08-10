import assert from "node:assert/strict";
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createOpenClawCodingTools } from "openclaw/plugin-sdk/agent-harness";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const sourcePluginRoot = resolve(root, "..", "openclaw-reference", "safe-content-plugin");
const sourceSandboxConfig = resolve(root, "..", "openclaw-reference", "containment", "openclaw-sandbox.json");

function installContentPluginForHarness() {
  const temporaryRoot = mkdtempSync("/tmp/masugate-reference-content-plugin-");
  const pluginRoot = resolve(temporaryRoot, "plugin");
  cpSync(sourcePluginRoot, pluginRoot, { recursive: true });
  // The source plugin is a peer of the pinned host package. Loading a copied
  // package with the harness's node_modules emulates its installed layout and
  // avoids relying on a repository-root node_modules directory in CI.
  symlinkSync(resolve(root, "node_modules"), resolve(pluginRoot, "node_modules"), "dir");
  return { temporaryRoot, pluginRoot };
}

function resolveContentTool(pluginRoot) {
  const config = JSON.parse(readFileSync(sourceSandboxConfig, "utf8"));
  config.plugins.load = { paths: [pluginRoot] };
  const tools = createOpenClawCodingTools({
    agentId: "buyer-alpha",
    sessionId: "reference-content-session",
    sessionKey: "agent:buyer-alpha:main",
    config,
    cwd: root,
    workspaceDir: root,
  });
  assert.deepEqual(tools.map((tool) => tool.name), ["read", "masugate_reference_content"]);
  assert.equal(tools.some((tool) => tool.name === "web_fetch"), false);
  const tool = tools.find((candidate) => candidate.name === "masugate_reference_content");
  assert.ok(tool);
  return tool;
}

test("the pinned host resolves a fixed safe-content tool without exposing web_fetch", async () => {
  const requests = [];
  const priorFetch = globalThis.fetch;
  globalThis.fetch = async (input, init) => {
    requests.push({ input: String(input), method: init?.method, redirect: init?.redirect });
    return new Response("Use the approved travel handbook for itinerary drafts.", {
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  };
  const installation = installContentPluginForHarness();
  try {
    const result = await resolveContentTool(installation.pluginRoot).execute(
      "reference-content-call",
      { document: "travel" },
      undefined,
      undefined,
    );
    assert.deepEqual(result.details, {
      document: "travel",
      content: "Use the approved travel handbook for itinerary drafts.",
    });
    assert.deepEqual(requests, [
      {
        input: "http://safe-content:8080/reference/travel",
        method: "GET",
        redirect: "error",
      },
    ]);
  } finally {
    rmSync(installation.temporaryRoot, { force: true, recursive: true });
    globalThis.fetch = priorFetch;
  }
});

test("a sandbox tools.allow policy removes plugin tools from the effective host set", async () => {
  const installation = installContentPluginForHarness();
  try {
    const config = JSON.parse(readFileSync(sourceSandboxConfig, "utf8"));
    config.plugins.load = { paths: [installation.pluginRoot] };
    const tools = createOpenClawCodingTools({
      agentId: "buyer-alpha",
      sessionId: "sandbox-policy-session",
      sessionKey: "agent:buyer-alpha:sandbox-policy-session",
      config,
      cwd: root,
      workspaceDir: root,
      // The live oracle supplies this shape from resolveSandboxContext. This
      // focused regression proves the pinned host's policy pipeline consumes it.
      sandbox: {
        enabled: true,
        tools: { allow: ["read"], deny: ["image"] },
        // The host consults this fallback while constructing shell tools even
        // though the restrictive policy removes those tools afterward.
        docker: { env: {} },
      },
    });
    assert.deepEqual(tools.map((tool) => tool.name), ["read"]);
  } finally {
    rmSync(installation.temporaryRoot, { force: true, recursive: true });
  }
});
