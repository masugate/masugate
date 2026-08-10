import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const clientRoot = resolve(root, "../clients/typescript");
const home = mkdtempSync("/tmp/masugate-gateway-package-");
const consumer = resolve(home, "consumer");
const npmCli = process.env.npm_execpath;
assert.ok(npmCli, "npm_execpath is required for the packed gateway smoke");
const env = {
  ...process.env,
  HOME: home,
  TMPDIR: home,
  TMP: home,
  TEMP: home,
  npm_config_cache: resolve(home, "npm-cache"),
};

function npmPack(directory, label) {
  const result = spawnSync(
    process.execPath,
    [npmCli, "pack", "--json", "--pack-destination", home],
    { cwd: directory, env, encoding: "utf8" },
  );
  assert.equal(result.status, 0, `${label} pack failed:\n${result.stderr || result.stdout}`);
}

try {
  npmPack(clientRoot, "@masugate/client");
  npmPack(root, "@masugate/mcp-gateway");
  const tarballs = readdirSync(home).filter((name) => name.endsWith(".tgz"));
  const client = tarballs.find((name) => name.startsWith("masugate-client-"));
  const gateway = tarballs.find((name) => name.startsWith("masugate-mcp-gateway-"));
  assert.ok(client, "packed @masugate/client artifact is missing");
  assert.ok(gateway, "packed @masugate/mcp-gateway artifact is missing");

  mkdirSync(consumer, { recursive: true });
  writeFileSync(
    resolve(consumer, "package.json"),
    `${JSON.stringify({ private: true, type: "module" }, null, 2)}\n`,
    "utf8",
  );
  const install = spawnSync(
    process.execPath,
    [npmCli, "install", "--ignore-scripts", "--no-save", resolve(home, client), resolve(home, gateway)],
    { cwd: consumer, env, encoding: "utf8" },
  );
  assert.equal(install.status, 0, `gateway clean install failed:\n${install.stderr || install.stdout}`);
  assert.equal(existsSync(resolve(consumer, "node_modules/@masugate/client/package.json")), true);
  assert.equal(existsSync(resolve(consumer, "node_modules/@masugate/mcp-gateway/package.json")), true);

  const imported = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", "const g=await import('@masugate/mcp-gateway');if(!g.createGatewayServer)process.exit(1)"],
    { cwd: consumer, env, encoding: "utf8" },
  );
  assert.equal(imported.status, 0, `packed gateway import failed:\n${imported.stderr || imported.stdout}`);

  const cli = spawnSync(
    process.execPath,
    [resolve(consumer, "node_modules/@masugate/mcp-gateway/dist/cli.js"), "--help"],
    { cwd: consumer, env, encoding: "utf8" },
  );
  assert.equal(cli.status, 0, `packed gateway CLI failed:\n${cli.stderr || cli.stdout}`);
  assert.match(cli.stderr + cli.stdout, /Usage: masugate-mcp-gateway/);
  console.log("clean consumer imported and executed the packed MasuGate MCP gateway");
} finally {
  rmSync(home, { recursive: true, force: true });
}
