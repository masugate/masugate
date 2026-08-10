import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workspaceRoot = resolve(root, "..", "..");
const readJson = async (path) => JSON.parse(await readFile(path, "utf8"));

const contract = await readJson(resolve(root, "contract/openclaw-v2026.7.1.json"));
const openclawPackage = await readJson(resolve(root, "node_modules/openclaw/package.json"));
const lock = await readJson(resolve(root, "package-lock.json"));
const productionLock = await readJson(resolve(workspaceRoot, "package-lock.json"));
const lockedOpenClaw = lock.packages?.["node_modules/openclaw"];
const productionLockedOpenClaw = productionLock.packages?.["node_modules/openclaw"];
const productionPackage = productionLock.packages?.["integrations/openclaw"];
const openclawRoot = resolve(root, "node_modules/openclaw");
const distRoot = resolve(openclawRoot, "dist");
const distFiles = await readdir(distRoot);

async function pinnedSource(pattern, marker) {
  for (const name of distFiles.filter((candidate) => pattern.test(candidate))) {
    const source = await readFile(resolve(distRoot, name), "utf8");
    if (source.includes(marker)) return source;
  }
  assert.fail(`missing pinned runtime artifact containing ${marker}`);
}

assert.equal(process.version, `v${contract.node.version}`);
assert.equal(openclawPackage.name, contract.npm.name);
assert.equal(openclawPackage.version, contract.npm.version);
assert.equal(openclawPackage.license, contract.release.license);
assert.equal(openclawPackage.engines?.node, contract.npm.enginesNode);
assert.match(String(openclawPackage.repository?.url ?? openclawPackage.repository), /openclaw\/openclaw/);

for (const subpath of contract.npm.requiredSdkExports) {
  assert.ok(openclawPackage.exports?.[subpath], `missing pinned SDK export ${subpath}`);
}

assert.ok(lockedOpenClaw, "package-lock.json must pin openclaw");
assert.equal(lockedOpenClaw.version, contract.npm.version);
assert.equal(lockedOpenClaw.resolved, contract.npm.tarball);
assert.equal(lockedOpenClaw.integrity, contract.npm.integrity);
assert.ok(productionLockedOpenClaw, "production package-lock.json must pin openclaw");
assert.equal(productionLockedOpenClaw.version, contract.npm.version);
assert.equal(productionLockedOpenClaw.resolved, contract.npm.tarball);
assert.equal(productionLockedOpenClaw.integrity, contract.npm.integrity);
assert.ok(productionPackage, "production workspace package must be locked");
assert.equal(productionPackage.devDependencies?.openclaw, contract.npm.version);
assert.equal(productionPackage.peerDependencies?.openclaw, contract.npm.version);

assert.equal(contract.release.commit.length, 40);
assert.match(contract.container.image, /@sha256:[a-f0-9]{64}$/);
assert.equal(contract.container.nodeVersion, contract.node.version);
assert.equal(contract.approval.allowAlwaysForConsequentialActions, false);
assert.equal(contract.approval.durableAcrossGatewayRestart, false);
assert.equal(contract.approval.recoveryAuthority, "MasuGate pending ledger");
assert.match(contract.approval.backgroundNativeApprovalRpc, /unavailable/);

const sandboxConfig = await pinnedSource(/^config-.*\.js$/u, "readOnlyRoot: agentDocker?.readOnlyRoot");
assert.match(sandboxConfig, /readOnlyRoot: agentDocker\?\.readOnlyRoot \?\? globalDocker\?\.readOnlyRoot \?\? true/u);
assert.match(sandboxConfig, /network: agentDocker\?\.network \?\? globalDocker\?\.network \?\? "none"/u);
assert.match(sandboxConfig, /capDrop: agentDocker\?\.capDrop \?\? globalDocker\?\.capDrop \?\? \["ALL"\]/u);

const approvalDescriptors = await pinnedSource(
  /^core-descriptors-.*\.js$/u,
  'name: "plugin.approval.request"',
);
for (const method of [
  "plugin.approval.list",
  "plugin.approval.request",
  "plugin.approval.waitDecision",
  "plugin.approval.resolve",
]) {
  assert.match(
    approvalDescriptors,
    new RegExp(`name: "${method.replaceAll(".", "\\.")}",[\\s\\S]{0,80}scope: "operator\\.approvals"`, "u"),
  );
}
const pluginGatewayRuntime = await pinnedSource(
  /^server-plugins-.*\.js$/u,
  "function createSyntheticOperatorClient",
);
assert.match(pluginGatewayRuntime, /scopes: params\?\.scopes \?\? \["operator\.write"\]/u);

const pluginToolContext = await pinnedSource(
  /^openclaw-tools-.*\.js$/u,
  "function resolveOpenClawPluginToolInputs",
);
assert.match(pluginToolContext, /sessionKey: options\?\.agentSessionKey,[\s\S]{0,100}sessionId: options\?\.sessionId/u);
assert.match(pluginToolContext, /agentId: sessionAgentId,[\s\S]{0,100}sessionKey: options\?\.agentSessionKey,[\s\S]{0,100}sessionId: options\?\.sessionId/u);

console.log(
  `verified OpenClaw ${contract.npm.version}, matching private/production locks, Node ${contract.node.version}, ${contract.container.image}, and pinned identity/approval/sandbox runtime facts`,
);
