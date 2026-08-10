import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const [command, caseId] = process.argv.slice(2);
assert.ok(
  command === "CREATE" || command === "PRESENT" || command === "CONTINUE",
  "gateway_recovery command must be CREATE, PRESENT, or CONTINUE",
);
assert.match(caseId ?? "", /^[a-z0-9-]+$/u, "gateway_recovery case id must be canonical");
const gatewayToken = process.env.OPENCLAW_GATEWAY_TOKEN;
assert.equal(typeof gatewayToken, "string", "Gateway control-plane token is unavailable");

// Exercise the pinned Gateway's real `chat.send` session pipeline rather than
// its OpenAI-compatibility endpoint.  The latter only health-checks the
// Gateway and can choose a compatibility-session generation that differs from
// the native plugin session.  This client follows the host's own control-plane
// API and waits for its `chat` final event for the exact requested session.
const distDir = fileURLToPath(new URL("./node_modules/openclaw/dist/", import.meta.url));
const clientCandidates = (await readdir(distDir))
  .filter((name) => /^client-[A-Za-z0-9_-]+\.js$/u.test(name));
const clientModuleName = (
  await Promise.all(
    clientCandidates.map(async (name) => ({
      name,
      source: await readFile(path.join(distDir, name), "utf8"),
    })),
  )
).find(({ source }) => source.includes("GatewayClient$1"))?.name;
assert.notEqual(clientModuleName, undefined, "pinned OpenClaw Gateway client module is unavailable");
const clientModule = await import(pathToFileURL(path.join(distDir, clientModuleName)).href);
const GatewayClient = clientModule.t;
assert.equal(typeof GatewayClient, "function", "pinned OpenClaw Gateway client export changed");

const sessionKey = `agent:buyer-alpha:gateway_recovery-${caseId}`;
let resolveHello;
let rejectHello;
let resolveFinal;
let rejectFinal;
let expectedRunId;
const hello = new Promise((resolve, reject) => {
  resolveHello = resolve;
  rejectHello = reject;
});
const final = new Promise((resolve, reject) => {
  resolveFinal = resolve;
  rejectFinal = reject;
});
const client = new GatewayClient({
  url: "ws://127.0.0.1:18789",
  token: gatewayToken,
  clientName: "gateway-client",
  clientDisplayName: "gateway recovery Gateway crash-matrix session",
  mode: "backend",
  role: "operator",
  scopes: ["operator.admin"],
  deviceIdentity: null,
  onHelloOk: () => resolveHello(),
  onEvent: (event) => {
    if (event?.event !== "chat") return;
    const payload = event.payload;
    if (payload?.sessionKey !== sessionKey || payload?.runId !== expectedRunId) return;
    if (payload.state === "error") {
      rejectFinal(new Error(`Gateway chat session failed: ${JSON.stringify(payload)}`));
      return;
    }
    if (payload.state !== "final") return;
    const text = Array.isArray(payload.message?.content)
      ? payload.message.content
        .map((part) => part?.type === "text" && typeof part.text === "string" ? part.text : "")
        .filter(Boolean)
        .join("\n")
      : "";
    resolveFinal(text);
  },
  onConnectError: rejectHello,
  onClose: (code, reason) => rejectHello(new Error(`Gateway closed before chat completed (${code}): ${reason}`)),
});

const timeout = setTimeout(
  () => rejectFinal(new Error("Gateway did not finish the native approval session")),
  120_000,
);
try {
  client.start();
  await hello;
  const accepted = await client.request("chat.send", {
    sessionKey,
    agentId: "buyer-alpha",
    message: `GATEWAY_RECOVERY_${command}:${caseId}`,
    deliver: false,
    idempotencyKey: `gateway_recovery-${command.toLowerCase()}-${caseId}-${randomUUID()}`,
  });
  assert.equal(typeof accepted?.runId, "string", "Gateway chat.send did not return a run id");
  expectedRunId = accepted.runId;
  if (command === "PRESENT") {
    // A pinned native approval suspends the model turn while the host-owned
    // operator dialog is outstanding.  The separate real reviewer observes
    // that dialog and resolves it through plugin.approval.resolve; waiting for
    // this control client to receive a model-final event would turn that
    // deliberately asynchronous host contract into a false timeout.  The
    // acknowledged run id plus the reviewer event are the presentation proof;
    // CONTINUE below uses a second real chat.send turn to obtain MasuGate's durable
    // terminal result after the callback handoff completes.
    console.log(`GATEWAY_RECOVERY_APPROVAL_PRESENTED:${caseId}:${accepted.runId}`);
  } else {
    const text = await final;
    assert.equal(typeof text, "string", "Gateway native-approval turn returned no assistant completion");
    if (command === "CREATE") {
      assert.match(text, new RegExp(`^GATEWAY_RECOVERY_PENDING_READY:${caseId}:`), "Gateway did not return a durable MasuGate pending locator");
    } else {
      assert.match(text, new RegExp(`^GATEWAY_RECOVERY_COMMITTED:${caseId}:`), "Gateway did not return the native-resumed terminal result");
    }
    console.log(text);
  }
} finally {
  clearTimeout(timeout);
  await client.stopAndWait().catch(() => client.stop());
}
