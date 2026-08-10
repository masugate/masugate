import { MasuGateClient } from "../dist/index.js";

const baseUrl = process.argv[2];
if (!baseUrl) {
  throw new Error("usage: node masugated-roundtrip.mjs <masugated-base-url>");
}

const client = new MasuGateClient({ baseUrl, token: "alice-token" });
const operator = new MasuGateClient({ baseUrl, token: "operator-token" });

const committed = await client.execute({
  action: "transfer",
  args: { receiver_id: "receiver", amount_cents: 1000 },
  stableId: "ts-live:committed",
  traceId: "ts-live-trace",
});
const replay = await client.execute({
  action: "transfer",
  args: { receiver_id: "receiver", amount_cents: 1000 },
  stableId: "ts-live:committed",
  traceId: "ts-live-trace",
});
const receipt = await client.getAudit(committed.operation_id);

const pending = await client.execute({
  action: "transfer",
  args: { receiver_id: "receiver-b", amount_cents: 5000 },
  stableId: "ts-live:pending",
});
if (pending.status !== "pending") {
  throw new Error(`expected pending result, got ${pending.status}`);
}

const eventIds = [];
for await (const event of client.streamPending({ once: true })) {
  eventIds.push(event.event_id);
}
const resolved = await operator.resolvePending({
  pendingId: pending.pending_id,
  approved: true,
  evidence: { reviewer: "typescript-sdk-integration" },
});

process.stdout.write(
  JSON.stringify({ committed, replay, receipt, pending, eventIds, resolved }),
);
