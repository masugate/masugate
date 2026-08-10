import assert from "node:assert/strict";

const gatewayToken = process.env.OPENCLAW_GATEWAY_TOKEN;
assert.equal(typeof gatewayToken, "string", "Gateway control-plane token is unavailable");

async function invoke({ agentId, sessionKey, expectedMarker }) {
  const response = await fetch("http://127.0.0.1:18789/v1/chat/completions", {
    method: "POST",
    headers: {
      authorization: `Bearer ${gatewayToken}`,
      "content-type": "application/json",
      "x-openclaw-agent-id": agentId,
      "x-openclaw-session-key": sessionKey,
    },
    body: JSON.stringify({
      model: `openclaw/${agentId}`,
      messages: [{ role: "user", content: "Run the bounded reference containment session fixture." }],
    }),
    signal: AbortSignal.timeout(45_000),
  });
  const payload = await response.json();
  assert.equal(response.status, 200, `Gateway agent turn failed: ${JSON.stringify(payload)}`);
  assert.equal(
    payload?.choices?.[0]?.message?.content,
    expectedMarker,
    "Gateway agent turn did not complete the expected session pipeline",
  );
}

await invoke({
  agentId: "buyer-alpha",
  sessionKey: "agent:buyer-alpha:reference-containment-live-session",
  expectedMarker: "REFERENCE_CONTAINMENT_GATEWAY_SESSION_OK",
});
await invoke({
  agentId: "buyer-narrow",
  sessionKey: "agent:buyer-narrow:reference-containment-narrow-session",
  expectedMarker: "REFERENCE_CONTAINMENT_NARROW_POLICY_OK",
});
console.log("REFERENCE_CONTAINMENT_GATEWAY_SESSION_OK");
console.log("REFERENCE_CONTAINMENT_GATEWAY_NARROW_POLICY_OK");
