import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

const publicEntry = fileURLToPath(import.meta.resolve("openclaw/plugin-sdk/plugin-entry"));
const packageRoot = resolve(dirname(publicEntry), "../..");

async function createPinnedApprovalManager() {
  const distFiles = await readdir(resolve(packageRoot, "dist"));
  const auxChunk = distFiles.find((name) => /^server-aux-handlers-.*\.js$/.test(name));
  assert.ok(auxChunk, "pinned package must contain the Gateway auxiliary-handler chunk");
  const { createGatewayAuxHandlers } = await import(
    pathToFileURL(resolve(packageRoot, "dist", auxChunk)).href
  );
  return createGatewayAuxHandlers({ log: {} }).pluginApprovalManager;
}

async function loadPinnedBeforeToolCallRuntime() {
  const distFiles = await readdir(resolve(packageRoot, "dist"));
  const chunk = distFiles.find((name) => /^agent-tools\.before-tool-call-.*\.js$/u.test(name));
  assert.ok(chunk, "pinned package must contain the before-tool-call runtime chunk");
  return import(pathToFileURL(resolve(packageRoot, "dist", chunk)).href);
}

function deferredApproval(onResolution, timeoutMs = 25) {
  return {
    approval: {
      pluginId: "masugate-contract-probe",
      title: "MasuGate probe",
      description: "Approve the bounded MasuGate probe.",
      allowedDecisions: ["allow-once", "deny"],
      timeoutMs,
      timeoutBehavior: "deny",
      onResolution,
    },
    toolName: "masugate_contract_probe",
    toolCallId: "tool-call-approval",
    ctx: {
      agentId: "agent-alpha",
      sessionId: "session-approval",
      sessionKey: "agent:agent-alpha:main",
    },
    baseParams: { amount: 25 },
  };
}

test("pinned approval manager pauses until an explicit decision", async () => {
  const manager = await createPinnedApprovalManager();
  const record = manager.create(
    { title: "MasuGate probe", description: "Approve the bounded probe." },
    600_000,
    "plugin:masugate-contract-probe",
  );
  const decision = manager.register(record, 600_000);

  assert.equal(manager.listPendingRecords().length, 1);
  assert.equal(manager.resolve(record.id, "allow-once", "test-reviewer"), true);
  assert.equal(await decision, "allow-once");
});

test("pinned native approval state is process-local and must be reissued after restart", async () => {
  const beforeRestart = await createPinnedApprovalManager();
  const record = beforeRestart.create(
    { title: "MasuGate probe", description: "Approve the bounded probe." },
    600_000,
    "plugin:masugate-restart-probe",
  );
  beforeRestart.register(record, 600_000);

  const afterRestart = await createPinnedApprovalManager();
  assert.equal(afterRestart.getSnapshot(record.id), null);
  assert.equal(afterRestart.awaitDecision(record.id), null);

  beforeRestart.expire(record.id, "test-cleanup");
});

test("pinned native plugin approval timeout is capped at ten minutes", async () => {
  const { resolvePluginApprovalTimeoutMs } = await import("openclaw/plugin-sdk/infra-runtime");
  assert.equal(resolvePluginApprovalTimeoutMs(60 * 60 * 1000), 600_000);
});

test("pinned approval executor delivers real timeout and cancellation callbacks", async () => {
  const runtime = await loadPinnedBeforeToolCallRuntime();
  runtime.k(true);
  const broker = new runtime.T();
  runtime.D(broker);
  try {
    const timeoutResolutions = [];
    const keepAlive = setTimeout(() => {}, 100);
    const timedOut = await runtime.u({
      deferredApproval: deferredApproval((resolution) => timeoutResolutions.push(resolution), 10),
    });
    clearTimeout(keepAlive);
    assert.equal(timedOut.blocked, true);
    assert.equal(timedOut.disposition, "timed_out");
    assert.deepEqual(timeoutResolutions, ["timeout"]);

    const cancellationResolutions = [];
    const controller = new AbortController();
    const cancelledPromise = runtime.u({
      deferredApproval: deferredApproval((resolution) =>
        cancellationResolutions.push(resolution),
      ),
      signal: controller.signal,
    });
    await new Promise((resolvePromise) => setImmediate(resolvePromise));
    assert.equal(broker.listPending().length, 1);
    controller.abort(new DOMException("cancelled by test", "AbortError"));
    const cancelled = await cancelledPromise;
    assert.equal(cancelled.blocked, true);
    assert.equal(cancelled.disposition, "cancelled");
    assert.deepEqual(cancellationResolutions, ["cancelled"]);
  } finally {
    runtime.E(broker);
    runtime.k(false);
    broker.stop();
  }
});

test("pinned approval allow does not await an async resolution callback", async () => {
  const runtime = await loadPinnedBeforeToolCallRuntime();
  runtime.k(true);
  const broker = new runtime.T();
  runtime.D(broker);
  let releaseCallback;
  let callbackFinished = false;
  const callbackBlocker = new Promise((resolvePromise) => {
    releaseCallback = resolvePromise;
  });
  try {
    const approval = runtime.u({
      deferredApproval: deferredApproval(async () => {
        await callbackBlocker;
        callbackFinished = true;
      }, 1_000),
    });
    await new Promise((resolvePromise) => setImmediate(resolvePromise));
    const pending = broker.listPending();
    assert.equal(pending.length, 1);
    assert.equal(broker.resolve(pending[0].id, "allow-once"), true);

    const allowed = await approval;
    assert.equal(allowed.blocked, false);
    assert.equal(callbackFinished, false);
  } finally {
    releaseCallback?.();
    await new Promise((resolvePromise) => setImmediate(resolvePromise));
    runtime.E(broker);
    runtime.k(false);
    broker.stop();
  }
  assert.equal(callbackFinished, true);
});

test("pinned next-turn injection persists across restart until its destructive drain", async () => {
  const home = await mkdtemp("/tmp/masugate-openclaw-restart-");
  const storePath = resolve(home, "sessions.json");
  const worker = resolve(packageRoot, "..", "..", "scripts", "probe-next-turn-injection.mjs");
  await writeFile(
    storePath,
    JSON.stringify({
      "agent:main:main": {
        sessionId: "session-17",
        updatedAt: Date.now(),
      },
    }),
  );
  const run = (mode) => {
    const resultPath = resolve(home, `${mode}-result.json`);
    const env = { ...process.env, NODE_DISABLE_COMPILE_CACHE: "1" };
    delete env.NODE_TEST_CONTEXT;
    const result = spawnSync(process.execPath, [worker, mode, storePath, resultPath], {
      cwd: resolve(packageRoot, "..", ".."),
      encoding: "utf8",
      env,
    });
    assert.equal(result.status, 0, result.stderr || result.stdout);
    return JSON.parse(readFileSync(resultPath, "utf8"));
  };

  try {
    const enqueued = run("enqueue");
    assert.equal(enqueued.first.enqueued, true);
    assert.equal(enqueued.duplicate.enqueued, false);
    assert.equal(enqueued.duplicate.id, enqueued.first.id);
    const persisted = JSON.parse(await readFile(storePath, "utf8"));
    assert.equal(
      persisted["agent:main:main"].pluginNextTurnInjections["masugate-contract-probe"].length,
      1,
    );

    const drained = run("drain");
    assert.equal(drained.queuedInjections.length, 1);
    assert.equal(drained.queuedInjections[0].metadata.pendingId, "pending-17");
    assert.match(drained.prependContext, /pending-17/u);
    assert.equal(run("drain").queuedInjections.length, 0);
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
