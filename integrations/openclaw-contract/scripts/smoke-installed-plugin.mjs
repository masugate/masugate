import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const openclawCli = resolve(root, "node_modules/openclaw/openclaw.mjs");
const home = mkdtempSync("/tmp/masugate-openclaw-contract-");
const env = {
  ...process.env,
  HOME: home,
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
  assert.equal(
    result.status,
    0,
    `openclaw ${args.join(" ")} failed:\n${output}`,
  );
  return output;
}

try {
  runOpenClaw(["plugins", "install", root]);
  const output = runOpenClaw([
    "plugins",
    "inspect",
    "masugate-contract-probe",
    "--runtime",
    "--json",
  ]);
  const jsonStart = output.indexOf("{");
  const jsonEnd = output.lastIndexOf("}");
  assert.ok(
    jsonStart >= 0 && jsonEnd > jsonStart,
    `runtime inspection did not return JSON:\n${output}`,
  );
  const inspection = JSON.parse(output.slice(jsonStart, jsonEnd + 1));

  assert.equal(inspection.plugin?.status, "loaded");
  assert.equal(inspection.plugin?.imported, true);
  assert.deepEqual(inspection.plugin?.contracts?.tools, ["masugate_contract_probe"]);
  assert.deepEqual(inspection.typedHooks, [{ name: "before_tool_call" }]);
  assert.deepEqual(inspection.tools, [
    {
      names: ["masugate_contract_probe"],
      optional: true,
    },
  ]);
  assert.deepEqual(inspection.diagnostics, []);

  console.log("installed OpenClaw runtime loaded the MasuGate contract tool and hook");
} finally {
  rmSync(home, { recursive: true, force: true });
}
