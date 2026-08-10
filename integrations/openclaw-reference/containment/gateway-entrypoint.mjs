import { mkdir, readFile, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import path from "node:path";

import { startGatewayModelFixtures } from "./gateway-model-fixture.mjs";

const stateRoot = process.env.MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT;
if (typeof stateRoot !== "string" || !path.isAbsolute(stateRoot)) {
  throw new Error("MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT must be an absolute host-visible path");
}
const sandboxImage = process.env.MASUGATE_AGENT_SANDBOX_IMAGE;
if (typeof sandboxImage !== "string" || sandboxImage.length === 0) {
  throw new Error("MASUGATE_AGENT_SANDBOX_IMAGE must name the staged sandbox image");
}

const config = JSON.parse(await readFile("/opt/openclaw/openclaw-sandbox.json", "utf8"));
config.gateway = { ...config.gateway, mode: "local" };
config.agents.defaults.workspace = path.join(stateRoot, "agent-workspace");
config.agents.defaults.skipBootstrap = true;
config.agents.defaults.sandbox.workspaceRoot = path.join(stateRoot, "sandbox-workspaces");
config.agents.defaults.sandbox.docker.image = sandboxImage;
config.agents.defaults.sandbox.docker.containerPrefix = "masugate-openclaw-reference-agent-";
// OpenClaw's explicit loader accepts runtime entry files, not package
// directories.  Each entry is paired with its co-located manifest: the MasuGate
// package build copies its manifest into dist/src, while the fixture plugin
// already keeps its manifest next to index.mjs.
config.plugins.load = {
  paths: [
    "/opt/openclaw/masugate-plugin/dist/src/plugin.js",
    "/opt/openclaw/reference-safe-content-plugin/index.mjs",
  ],
};
if (process.env.MASUGATE_GATEWAY_RECOVERY_LIVE === "1") {
  config.agents.defaults.model = { primary: "gateway_recovery/gateway_recovery" };
  config.models.providers.gateway_recovery = {
    baseUrl: "http://127.0.0.1:18792/v1",
    apiKey: "gateway-recovery-loopback-model",
    api: "openai-completions",
    models: [{
      id: "gateway_recovery",
      name: "gateway recovery deterministic native approval fixture",
      reasoning: false,
      input: ["text"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: 131072,
      maxTokens: 4096,
      compat: { requiresStringContent: true },
    }],
  };
  config.plugins.entries.masugate.config.nativeApproval = {
    resolverTokenEnv: "MASUGATE_RESOLVER_TOKEN",
    timeoutMs: 600000,
  };
  for (const policy of [config.tools, config.tools.sandbox.tools]) {
    policy.allow = ["read", "masugate_governed_action", "masugate_reference_content", "masugate_resume_pending"];
  }
}
if (process.env.MASUGATE_REFERENCE_DEMO_DEMO === "1") {
  // The clean-artifact runner gives each Compose project a unique network
  // prefix. Gateway-created Docker sandboxes are outside Compose, so bind
  // them explicitly to that project's internal agent network rather than the
  // fixed reference containment acceptance-matrix network.
  const reference_demoNetworkPrefix = process.env.MASUGATE_REFERENCE_DEMO_NETWORK_PREFIX;
  if (
    typeof reference_demoNetworkPrefix !== "string"
    || !/^[a-z0-9][a-z0-9-]*$/u.test(reference_demoNetworkPrefix)
  ) {
    throw new Error("MASUGATE_REFERENCE_DEMO_NETWORK_PREFIX must be a lowercase Docker network prefix");
  }
  config.agents.defaults.sandbox.docker.network = `${reference_demoNetworkPrefix}-agent`;

  // The second action identity exists only in the disposable procurement
  // workload.  It lets the demo race two independently authenticated fleet
  // members without widening the reviewed 2.4 profile.
  config.agents.list.push({ id: "buyer-beta" });
  config.plugins.entries.masugate.config.agents["buyer-beta"] = "MASUGATE_BUYER_BETA_TOKEN";
}

await mkdir(config.agents.defaults.workspace, { recursive: true });
await mkdir(config.agents.defaults.sandbox.workspaceRoot, { recursive: true });
await writeFile(
  path.join(config.agents.defaults.workspace, "reference-containment-sandbox-read-proof.txt"),
  "reference-containment sandbox-bound read proof\n",
  "utf8",
);
const configPath = path.join(stateRoot, "openclaw.json");
await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`, "utf8");
const modelFixture = await startGatewayModelFixtures({ stateRoot });

const child = spawn(
  "node",
  ["node_modules/openclaw/openclaw.mjs", "gateway", "run", "--port", "18789", "--allow-unconfigured"],
  {
    env: {
      ...process.env,
      OPENCLAW_CONFIG_PATH: configPath,
      OPENCLAW_STATE_DIR: stateRoot,
      OPENCLAW_WORKSPACE_DIR: config.agents.defaults.workspace,
    },
    stdio: "inherit",
  },
);

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    child.kill(signal);
    void modelFixture.close();
  });
}
child.on("exit", (code, signal) => {
  void modelFixture.close();
  if (signal !== null) process.exit(1);
  process.exit(code ?? 1);
});
