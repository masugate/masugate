import assert from "node:assert/strict";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const [mode, storePath, resultPath] = process.argv.slice(2);
assert.ok(mode === "enqueue" || mode === "drain", "mode must be enqueue or drain");
assert.ok(storePath, "session store path is required");
assert.ok(resultPath, "result path is required");

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const publicEntry = fileURLToPath(import.meta.resolve("openclaw/plugin-sdk/plugin-entry"));
const packageRoot = resolve(dirname(publicEntry), "../..");
const distFiles = await readdir(resolve(packageRoot, "dist"));
async function chunkContaining(pattern, marker) {
  for (const name of distFiles.filter((candidate) => pattern.test(candidate))) {
    if ((await readFile(resolve(packageRoot, "dist", name), "utf8")).includes(marker)) return name;
  }
  return undefined;
}
const registryChunk = await chunkContaining(/^registry-.*\.js$/u, "function createPluginRegistry");
const runtimeChunk = await chunkContaining(/^runtime-pr_.*\.js$/u, "function setActivePluginRegistry");
assert.ok(registryChunk, "pinned package must contain the plugin registry chunk");
assert.ok(runtimeChunk, "pinned package must contain the plugin runtime-state chunk");
const registryModule = await import(pathToFileURL(resolve(packageRoot, "dist", registryChunk)).href);
const runtimeModule = await import(pathToFileURL(resolve(packageRoot, "dist", runtimeChunk)).href);
const { enqueueApprovalResume } = await import(
  pathToFileURL(resolve(root, "dist/src/contract-probe.js")).href
);

const config = {
  session: { store: storePath },
  agents: { list: [{ id: "main" }] },
  plugins: { entries: { "masugate-contract-probe": { hooks: { allowPromptInjection: true } } } },
};
const runtime = {
  config: {
    current: () => config,
    mutateConfigFile: async () => undefined,
    replaceConfigFile: async () => undefined,
  },
};
const record = {
  id: "masugate-contract-probe",
  name: "MasuGate contract probe",
  version: "0.1.1",
  description: "pinned next-turn durability oracle",
  source: resolve(root, "dist/src/contract-probe.js"),
  rootDir: root,
  origin: "local",
  enabled: true,
  status: "loaded",
  contracts: { tools: ["masugate_contract_probe"] },
};
const created = registryModule.t({ runtime, logger: {} });

async function emit(value) {
  await writeFile(resultPath, JSON.stringify(value));
}

if (mode === "enqueue") {
  const api = created.createApi(record, { config, pluginConfig: {}, registrationMode: "full" });
  const resume = {
    sessionKey: "agent:main:main",
    pendingId: "pending-17",
    ttlMs: 300_000,
  };
  const first = await enqueueApprovalResume(api, resume);
  const duplicate = await enqueueApprovalResume(api, resume);
  await emit({ first, duplicate });
} else {
  created.registry.plugins.push(record);
  runtimeModule.D(created.registry, "masugate-contract-restart-probe");
  const drained = await registryModule.m({ cfg: config, sessionKey: "agent:main:main" });
  await emit(drained);
}
