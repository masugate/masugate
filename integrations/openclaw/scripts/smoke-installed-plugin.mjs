import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import {
  closeSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workspaceRoot = resolve(root, "../..");
const openclawCli = resolve(root, "../../node_modules/openclaw/openclaw.mjs");
const home = mkdtempSync("/tmp/masugate-openclaw-plugin-");
const configPath = resolve(home, ".openclaw/openclaw.json");
// Offline verification supplies a separately verified input closure; ordinary
// clean-consumer execution retains its independent empty cache.
const offlineCache = process.env.MASUGATE_SMOKE_NPM_CACHE;
const localOfflineCache = resolve(home, ".npm");
const cacheCapture = process.env.MASUGATE_SMOKE_NPM_CACHE_CAPTURE;
const cacheInvalidationKey = process.env.MASUGATE_SMOKE_NPM_CACHE_INVALIDATE_KEY;
const fixedHostCacheAssertion = process.env.MASUGATE_SMOKE_NPM_CACHE_ASSERT_FIXED_HOST;
let packSequence = 0;
const env = {
  ...process.env,
  HOME: home,
  TMPDIR: home,
  TMP: home,
  TEMP: home,
  MASUGATE_AGENT_ALPHA_TOKEN: "packed-artifact-action-token",
  MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN: "packed-artifact-native-approval-token",
  npm_config_cache: offlineCache ? localOfflineCache : resolve(home, "npm-cache"),
  NODE_DISABLE_COMPILE_CACHE: "1",
};

function runOpenClaw(args) {
  const outputPath = resolve(home, "openclaw-command.log");
  const outputFd = openSync(outputPath, "w");
  const result = spawnSync(process.execPath, [openclawCli, ...args], {
    cwd: root,
    env,
    encoding: "utf8",
    stdio: ["ignore", outputFd, outputFd],
  });
  closeSync(outputFd);
  const output = readFileSync(outputPath, "utf8");
  assert.equal(result.status, 0, `openclaw ${args.join(" ")} failed:\n${output}`);
  return output;
}

function packPackage(npmCli, cwd) {
  const outputPath = resolve(home, `npm-pack-${packSequence}.json`);
  packSequence += 1;
  const outputFd = openSync(outputPath, "w");
  const packed = spawnSync(
    process.execPath,
    [npmCli, "pack", "--silent", "--json", "--pack-destination", home],
    { cwd, env, encoding: "utf8", stdio: ["ignore", outputFd, outputFd] },
  );
  closeSync(outputFd);
  const output = readFileSync(outputPath, "utf8");
  assert.equal(packed.status, 0, `npm pack failed for ${cwd}:\n${output}`);
  const jsonStart = output.lastIndexOf("\n[");
  const entries = JSON.parse(output.slice(jsonStart >= 0 ? jsonStart + 1 : 0));
  assert.ok(Array.isArray(entries) && entries.length === 1, `unexpected npm pack output: ${output}`);
  assert.equal(typeof entries[0]?.filename, "string", `npm pack did not return a tarball: ${output}`);
  return resolve(home, entries[0].filename);
}

async function invalidateGeneratedPackument(npmCli) {
  if (!cacheInvalidationKey) {
    return;
  }
  assert.ok(offlineCache, "cache invalidation requires a verified seed cache");
  assert.equal(
    cacheInvalidationKey,
    "make-fetch-happen:request-cache:https://registry.npmjs.org/@types%2fretry",
    "only the generated retry-packument cache key may be invalidated",
  );
  const cacache = createRequire(npmCli)("cacache");
  const cacheRoot = resolve(localOfflineCache, "_cacache");
  const info = await cacache.get.info(cacheRoot, cacheInvalidationKey);
  assert.ok(info, "generated @types/retry packument cache entry is unavailable");
  const raw = await cacache.get.byDigest(cacheRoot, info.integrity);
  const packument = JSON.parse(raw.toString("utf8"));
  assert.equal(packument.name, "@types/retry");
  assert.deepEqual(Object.keys(packument.versions), ["0.12.5"]);
  await cacache.rm.entry(cacheRoot, cacheInvalidationKey);
  console.log("invalidated the generated @types/retry packument before fixed-host installation");
}

function assertFixedHostNpmCache(npmCli, cwd) {
  if (!cacheInvalidationKey && !fixedHostCacheAssertion) {
    return;
  }
  const outputPath = resolve(home, "fixed-host-npm-cache-path.txt");
  const outputFd = openSync(outputPath, "w");
  const safeHostEnv = { ...env, npm_config_location: "project" };
  delete safeHostEnv.NPM_CONFIG_CACHE;
  delete safeHostEnv.npm_config_cache;
  const result = spawnSync(process.execPath, [npmCli, "config", "get", "cache"], {
    cwd,
    env: safeHostEnv,
    encoding: "utf8",
    stdio: ["ignore", outputFd, outputFd],
  });
  closeSync(outputFd);
  const cachePath = readFileSync(outputPath, "utf8").trim();
  assert.equal(result.status, 0, `could not resolve the fixed-host npm cache: ${cachePath}`);
  assert.equal(cachePath, localOfflineCache, "fixed-host npm cache must be the temporary home cache");
  console.log(`fixed-host npm cache is pinned to ${cachePath}`);
}

function tarEntries(tarball) {
  const archive = gunzipSync(readFileSync(tarball));
  const entries = [];
  for (let offset = 0; offset + 512 <= archive.length;) {
    const header = archive.subarray(offset, offset + 512);
    if (header.every((value) => value === 0)) {
      break;
    }
    const field = (start, length) => header
      .subarray(start, start + length)
      .toString("utf8")
      .replace(/\0.*$/u, "");
    const name = field(0, 100);
    const prefix = field(345, 155);
    const rawSize = field(124, 12).trim();
    const size = rawSize.length === 0 ? 0 : Number.parseInt(rawSize, 8);
    assert.ok(Number.isSafeInteger(size) && size >= 0, `invalid packed tar entry size: ${name}`);
    entries.push(prefix.length === 0 ? name : `${prefix}/${name}`);
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return entries;
}

function assertBundledRuntimeDependencies(tarball) {
  const entries = new Set(tarEntries(tarball));
  for (const dependency of [
    "@masugate/adapter-core",
    "@masugate/client",
    "typebox",
  ]) {
    assert.ok(
      entries.has(`package/node_modules/${dependency}/package.json`),
      `packed OpenClaw plugin omits bundled runtime dependency ${dependency}`,
    );
  }
}

try {
  if (offlineCache) {
    assert.ok(existsSync(offlineCache), "verified offline cache is unavailable");
    cpSync(offlineCache, localOfflineCache, { dereference: true, recursive: true });
  }
  const npmCli = process.env.npm_execpath;
  assert.ok(npmCli, "npm_execpath is required for the packed-artifact smoke");
  const clientTarball = packPackage(npmCli, resolve(workspaceRoot, "clients/typescript"));
  const adapterCoreTarball = packPackage(npmCli, resolve(workspaceRoot, "adapters/typescript"));
  const typeboxTarball = packPackage(npmCli, resolve(workspaceRoot, "node_modules/typebox"));
  const tarball = packPackage(npmCli, root);
  assertBundledRuntimeDependencies(tarball);

  // NPM must see the declared host peer while installing the production
  // artifact. This intentionally contains metadata only: the real pinned host
  // is linked below solely for the subsequent runtime inspection.
  const peerFixture = resolve(home, "openclaw-peer");
  mkdirSync(peerFixture, { recursive: true });
  writeFileSync(
    resolve(peerFixture, "package.json"),
    `${JSON.stringify({ name: "openclaw", version: "2026.7.1" }, null, 2)}\n`,
    "utf8",
  );
  const peerTarball = packPackage(npmCli, peerFixture);

  const consumer = resolve(home, "consumer");
  mkdirSync(consumer, { recursive: true });
  writeFileSync(
    resolve(consumer, "package.json"),
    `${JSON.stringify({ private: true, type: "module" }, null, 2)}\n`,
    "utf8",
  );
  const installed = spawnSync(
    process.execPath,
    [
      npmCli,
      "install",
      "--ignore-scripts",
      "--no-save",
      "--package-lock=false",
      "--offline",
      "--no-audit",
      peerTarball,
      typeboxTarball,
      clientTarball,
      adapterCoreTarball,
      tarball,
    ],
    { cwd: consumer, env, encoding: "utf8" },
  );
  assert.equal(
    installed.status,
    0,
    `clean consumer install failed:\n${installed.stderr || installed.stdout}`,
  );
  const consumerNodeModules = resolve(consumer, "node_modules");
  for (const packagePath of [
    resolve(consumerNodeModules, "@masugate/client"),
    resolve(consumerNodeModules, "@masugate/adapter-core"),
    resolve(consumerNodeModules, "@masugate/openclaw"),
  ]) {
    assert.ok(existsSync(packagePath), `clean consumer is missing ${packagePath}`);
    assert.equal(lstatSync(packagePath).isSymbolicLink(), false, `consumer linked ${packagePath}`);
  }
  const profileResolver = resolve(consumer, "resolve-profile.mjs");
  writeFileSync(
    profileResolver,
    [
      'import { readFile } from "node:fs/promises";',
      'const profileUrl = import.meta.resolve("@masugate/openclaw/profile/openclaw.json");',
      'process.stdout.write(await readFile(new URL(profileUrl), "utf8"));',
      "",
    ].join("\n"),
    "utf8",
  );
  const profileOutputPath = resolve(home, "resolved-profile.json");
  const profileOutputFd = openSync(profileOutputPath, "w");
  const resolvedProfile = spawnSync(process.execPath, [profileResolver], {
    cwd: consumer,
    env,
    encoding: "utf8",
    stdio: ["ignore", profileOutputFd, profileOutputFd],
  });
  closeSync(profileOutputFd);
  const profileOutput = readFileSync(profileOutputPath, "utf8");
  assert.equal(
    resolvedProfile.status,
    0,
    `clean consumer could not resolve the exported profile:\n${profileOutput}`,
  );
  const profile = JSON.parse(profileOutput);
  assert.deepEqual(profile.plugins.allow, ["masugate"]);
  assert.deepEqual(profile.tools.allow, ["masugate_governed_action"]);
  const consumerOpenClaw = resolve(consumerNodeModules, "openclaw");
  rmSync(consumerOpenClaw, { recursive: true, force: true });
  symlinkSync(resolve(root, "../../node_modules/openclaw"), consumerOpenClaw, "dir");

  // OpenClaw validates plugin settings immediately after unpacking. Seed the
  // clean consumer with the packed profile before asking the host to install it.
  mkdirSync(dirname(configPath), { recursive: true });
  writeFileSync(
    configPath,
    `${JSON.stringify(
      {
        plugins: {
          allow: profile.plugins.allow,
          entries: {
            masugate: {
              enabled: profile.plugins.entries.masugate.enabled,
              config: {
                ...profile.plugins.entries.masugate.config,
                nativeApproval: {
                  resolverTokenEnv: "MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN",
                  timeoutMs: 600_000,
                },
              },
            },
          },
        },
        tools: {
          ...profile.tools,
          allow: [...profile.tools.allow, "masugate_resume_pending"],
        },
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  assertFixedHostNpmCache(npmCli, consumer);
  await invalidateGeneratedPackument(npmCli);
  runOpenClaw(["plugins", "install", tarball]);
  const config = JSON.parse(readFileSync(configPath, "utf8"));
  config.plugins.allow = profile.plugins.allow;
  config.tools = {
    ...profile.tools,
    allow: [...profile.tools.allow, "masugate_resume_pending"],
  };
  config.plugins.entries.masugate.enabled = profile.plugins.entries.masugate.enabled;
  config.plugins.entries.masugate.config = {
    ...profile.plugins.entries.masugate.config,
    nativeApproval: {
      resolverTokenEnv: "MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN",
      timeoutMs: 600_000,
    },
  };
  writeFileSync(configPath, `${JSON.stringify(config, null, 2)}\n`, "utf8");

  const output = runOpenClaw(["plugins", "inspect", "masugate", "--runtime", "--json"]);
  const jsonStart = output.indexOf("{");
  const jsonEnd = output.lastIndexOf("}");
  assert.ok(jsonStart >= 0 && jsonEnd > jsonStart, `inspection did not return JSON:\n${output}`);
  const inspection = JSON.parse(output.slice(jsonStart, jsonEnd + 1));
  assert.equal(
    inspection.plugin?.status,
    "loaded",
    `production plugin failed runtime inspection:\n${JSON.stringify(inspection, null, 2)}`,
  );
  assert.equal(inspection.plugin?.imported, true);
  assert.deepEqual(inspection.plugin?.contracts?.tools, [
    "masugate_governed_action",
    "masugate_resume_pending",
  ]);
  assert.deepEqual(inspection.tools, [
    {
      // The clean installed package must load the optional gateway recovery bridge
      // from its bundled runtime code, not only advertise it in metadata.
      names: ["masugate_governed_action"],
      optional: true,
    },
    {
      names: ["masugate_resume_pending"],
      optional: true,
    },
  ]);
  assert.deepEqual(inspection.diagnostics, []);
  const invokeResolver = resolve(consumer, "invoke-governed-tool.mjs");
  writeFileSync(
    invokeResolver,
    [
      'import assert from "node:assert/strict";',
      'import { fileURLToPath } from "node:url";',
      'import { createOpenClawCodingTools } from "openclaw/plugin-sdk/agent-harness";',
      "",
      "const requests = [];",
      "const previousFetch = globalThis.fetch;",
      "globalThis.fetch = async (input, init) => {",
      "  requests.push({ input: String(input), method: init?.method, headers: new Headers(init?.headers), body: JSON.parse(String(init?.body)) });",
      "  return new Response(JSON.stringify({ operation_id: '00000000-0000-4000-8000-000000003502', status: 'committed', decision: { effect: 'allow', policy_id: 'packed-artifact-policy', policy_version: '1', rule_id: 'allow', reason: 'smoke' }, payload: { receipt: 'packed-artifact' }, audit_ref: '/v1/audit/00000000-0000-4000-8000-000000003502', replayed: false }), { status: 200, headers: { 'content-type': 'application/json' } });",
      "};",
      "try {",
      '  const pluginPath = fileURLToPath(import.meta.resolve("@masugate/openclaw/plugin"));',
      "  const tool = createOpenClawCodingTools({",
      "    agentId: 'agent-alpha',",
      "    sessionId: 'installed_plugin_release-packed-artifact-session',",
      "    sessionKey: 'agent:agent-alpha:main',",
      "    config: {",
      "      plugins: {",
      "        allow: ['masugate'],",
      "        load: { paths: [pluginPath] },",
      "        entries: { masugate: { enabled: true, config: {",
      "          masugatedBaseUrl: 'http://masugated.test',",
      "          agents: { 'agent-alpha': 'MASUGATE_AGENT_ALPHA_TOKEN' },",
      "          routes: { transfer: { action: 'transfer', arguments: { receiver_id: 'string', amount_cents: 'integer' }, owner: { providerId: 'masugate.postgres-ledger', position: 'transactional' } } },",
      "        } } },",
      "      },",
      "      tools: { allow: ['masugate_governed_action'] },",
      "    },",
      "    cwd: process.cwd(),",
      "    workspaceDir: process.cwd(),",
      "  }).find((candidate) => candidate.name === 'masugate_governed_action');",
      "  assert.ok(tool, 'packed plugin must register the governed replacement');",
      "  const result = await tool.execute('installed_plugin_release-packed-artifact-call', { route: 'transfer', args: { receiver_id: 'receiver', amount_cents: 100 } }, undefined, undefined);",
      "  assert.equal(result.details.status, 'committed');",
      "  assert.equal(result.details.operation_id, '00000000-0000-4000-8000-000000003502');",
      "  assert.equal(result.details.replayed, false);",
      "  assert.equal(requests.length, 1, 'one generated host tool call must make one MasuGate request');",
      "  assert.equal(requests[0].input, 'http://masugated.test/v1/actions');",
      "  assert.equal(requests[0].method, 'POST');",
      "  assert.equal(requests[0].headers.get('authorization'), 'Bearer packed-artifact-action-token');",
      "  assert.equal(requests[0].headers.get('masugate-expected-principal'), 'openclaw:agent-alpha');",
      "  assert.equal(requests[0].headers.get('masugate-expected-provider'), 'masugate.postgres-ledger');",
      "  assert.equal(requests[0].headers.get('masugate-expected-position'), 'transactional');",
      "  assert.equal(typeof requests[0].body.adapter_invocation, 'string');",
      "  process.stdout.write('packed governed tool invocation succeeded\\n');",
      "} finally {",
      "  globalThis.fetch = previousFetch;",
      "}",
      "",
    ].join("\n"),
    "utf8",
  );
  const invoked = spawnSync(process.execPath, [invokeResolver], {
    cwd: consumer,
    env,
    encoding: "utf8",
  });
  assert.equal(
    invoked.status,
    0,
    `packed governed tool invocation failed:\n${invoked.stderr || invoked.stdout}`,
  );
  console.log("installed OpenClaw runtime loaded and invoked the production MasuGate-owned tool");
} finally {
  try {
    if (cacheCapture) {
      assert.ok(offlineCache, "cache capture requires a verified seed cache");
      assert.ok(cacheCapture.startsWith("/tmp/"), "cache capture must use a disposable temporary path");
      assert.equal(existsSync(cacheCapture), false, "cache capture destination must be empty");
      cpSync(localOfflineCache, cacheCapture, { dereference: true, recursive: true });
    }
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
}
