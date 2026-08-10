import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const configPath = resolve(
  root,
  "..",
  "openclaw-reference",
  "containment",
  "openclaw-sandbox.json",
);
const isolatedHome = await mkdtemp(
  resolve(process.env.TMPDIR ?? "/tmp", "masugate-openclaw-containment-"),
);

try {
  const result = spawnSync(process.execPath, [resolve(root, "node_modules/openclaw/openclaw.mjs"), "config", "validate"], {
    cwd: root,
    encoding: "utf8",
    env: {
      ...process.env,
      HOME: isolatedHome,
      OPENCLAW_CONFIG_PATH: configPath,
    },
  });
  assert.equal(result.error, undefined, result.error?.message);
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.match(result.stdout, /Config valid:/u);
  console.log("validated the reference containment reference containment fragment with pinned OpenClaw");
} finally {
  await rm(isolatedHome, { force: true, recursive: true });
}
