import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

const [command, caseId, approvalId] = process.argv.slice(2);
assert.ok(command === "RESOLVE" || command === "WATCH", "gateway_recovery approval command must be RESOLVE or WATCH");
assert.match(caseId ?? "", /^[a-z0-9-]+$/u, "gateway_recovery approval case id must be canonical");
if (command === "RESOLVE") {
  assert.match(approvalId ?? "", /^plugin:[0-9a-f-]{36}$/u, "gateway_recovery approval id must be canonical");
}

const gatewayToken = process.env.OPENCLAW_GATEWAY_TOKEN;
assert.equal(typeof gatewayToken, "string", "Gateway control-plane token is unavailable");

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

let resolveHello;
let rejectHello;
let resolveNativeRecord;
const hello = new Promise((resolve, reject) => {
  resolveHello = resolve;
  rejectHello = reject;
});
const nativeRecord = new Promise((resolve) => {
  resolveNativeRecord = resolve;
});
const client = new GatewayClient({
  url: "ws://127.0.0.1:18789",
  token: gatewayToken,
  clientName: "gateway-client",
  clientDisplayName: "gateway recovery native approval reviewer",
  mode: "backend",
  role: "operator",
  scopes: ["operator.admin"],
  deviceIdentity: null,
  onHelloOk: () => resolveHello(),
  onEvent: (event) => {
    const request = event?.event === "plugin.approval.requested" ? event.payload?.request : undefined;
    if (
      request?.toolName === "masugate_resume_pending" &&
      typeof request?.sessionKey === "string" &&
      request.sessionKey === `agent:buyer-alpha:gateway_recovery-${caseId}` &&
      typeof event.payload?.id === "string" &&
      /^plugin:[0-9a-f-]{36}$/u.test(event.payload.id)
    ) {
      resolveNativeRecord({ id: event.payload.id });
    }
  },
  onConnectError: rejectHello,
  onClose: (code, reason) => rejectHello(new Error(`Gateway closed before approval review (${code}): ${reason}`)),
});

const timeout = setTimeout(() => rejectHello(new Error("Gateway approval reviewer did not connect")), 10_000);
try {
  client.start();
  await hello;
  if (command === "WATCH") {
    // The pinned host expires a plugin approval that has no eligible reviewer
    // at creation time.  Announce this connected operator before the Gateway
    // session begins, then keep the real RPC connection alive until its record
    // arrives.  This makes delivery-route existence part of the live oracle.
    console.log(JSON.stringify({ status: "ready" }));
    let recordTimer;
    try {
      const record = await Promise.race([
        nativeRecord,
        new Promise((_, reject) => {
          recordTimer = setTimeout(
            () => reject(new Error("Gateway did not create a native approval for the connected reviewer")),
            45_000,
          );
        }),
      ]);
      console.log(JSON.stringify({ status: "record", ...record }));
    } finally {
      clearTimeout(recordTimer);
    }
  } else {
    await client.request("plugin.approval.resolve", { id: approvalId, decision: "allow-once" });
    console.log(JSON.stringify({ id: approvalId }));
  }
} finally {
  clearTimeout(timeout);
  await client.stopAndWait().catch(() => client.stop());
}
