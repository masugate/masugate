import { describe, expect, it } from "vitest";

import { AUDIT_TOOL_NAME } from "../src/manifest.js";
import { GatewayRouter } from "../src/router.js";
import {
  ECHO_TOOL,
  FakeMasuGated,
  FakeUpstream,
  PURCHASE_TOOL,
  committed,
  denied,
  manifest,
  pending,
} from "./helpers.js";

const CONTEXT = { requestId: "rpc-17" } as const;
const PURCHASE_ARGS = {
  request_id: "logical-purchase-17",
  merchant: { id: "merchant-7" },
  amount: 2500,
  ignored: "not certified into the action",
};

describe("GatewayRouter", () => {
  it("strips governed output/task claims, including required upstream tasks", async () => {
    const passthrough = ECHO_TOOL;
    const hidden = { name: "hidden", inputSchema: { type: "object" as const } };
    const router = new GatewayRouter(
      manifest(),
      new FakeUpstream([passthrough, PURCHASE_TOOL, hidden]),
      new FakeMasuGated(),
    );

    const tools = await router.listTools();
    expect(tools.map((tool) => tool.name)).toEqual([
      "echo",
      "purchase",
      AUDIT_TOOL_NAME,
    ]);
    expect(tools[0]).toBe(passthrough);
    expect(tools[1]?.outputSchema).toBeUndefined();
    expect(tools[1]?.execution).toBeUndefined();
    expect(tools[2]?.annotations?.readOnlyHint).toBe(true);
  });

  it("forwards passthrough arguments and result unchanged", async () => {
    const upstream = new FakeUpstream();
    const expected = upstream.result;
    const masugated = new FakeMasuGated();
    const router = new GatewayRouter(manifest(), upstream, masugated);
    const args = { text: "hello" };

    const actual = await router.callTool("echo", args, CONTEXT);

    expect(actual).toBe(expected);
    expect(upstream.calls).toEqual([{ name: "echo", args }]);
    expect(masugated.executions).toEqual([]);
  });

  it("preserves omitted passthrough arguments", async () => {
    const upstream = new FakeUpstream();
    const router = new GatewayRouter(manifest(), upstream, new FakeMasuGated());

    await router.callTool("echo", undefined, CONTEXT);

    expect(upstream.calls).toEqual([{ name: "echo" }]);
  });

  it("normalizes governed args, calls masugated, and never calls upstream after commit", async () => {
    const upstream = new FakeUpstream();
    const masugated = new FakeMasuGated();
    masugated.result = committed({ receipt: "committed-by-masugate" });
    const router = new GatewayRouter(manifest(), upstream, masugated);

    const result = await router.callTool("purchase", PURCHASE_ARGS, CONTEXT);

    expect(masugated.executions).toHaveLength(1);
    expect(masugated.executions[0]).toMatchObject({
      action: "transfer",
      args: { receiver_id: "merchant-7", amount_cents: 2500 },
      traceId: "mcp:rpc-17",
    });
    expect(masugated.executions[0]?.stableId).toBe(
      "mcp-tool\u0000purchase\u0000string\u0000logical-purchase-17",
    );
    expect(upstream.calls).toEqual([]);
    expect(result).toEqual({
      content: [{ type: "text", text: '{"receipt":"committed-by-masugate"}' }],
      structuredContent: { receipt: "committed-by-masugate" },
    });
  });

  it("derives durable idempotency from stable_id, not connection-scoped RPC ids", async () => {
    const masugated = new FakeMasuGated();
    const upstream = new FakeUpstream();
    const firstConnection = new GatewayRouter(manifest(), upstream, masugated);
    const reconnected = new GatewayRouter(manifest(), upstream, masugated);

    await firstConnection.callTool("purchase", PURCHASE_ARGS, { requestId: 1 });
    await reconnected.callTool("purchase", PURCHASE_ARGS, { requestId: 1 });
    await reconnected.callTool("purchase", PURCHASE_ARGS, { requestId: 99 });

    expect(masugated.executions.map((request) => request.stableId)).toEqual([
      "mcp-tool\u0000purchase\u0000string\u0000logical-purchase-17",
      "mcp-tool\u0000purchase\u0000string\u0000logical-purchase-17",
      "mcp-tool\u0000purchase\u0000string\u0000logical-purchase-17",
    ]);
    expect(masugated.executions.map((request) => request.traceId)).toEqual([
      "mcp:1",
      "mcp:1",
      "mcp:99",
    ]);
  });

  it("accepts safe-integer stable ids and rejects missing/invalid stable ids", async () => {
    const masugated = new FakeMasuGated();
    const router = new GatewayRouter(manifest(), new FakeUpstream(), masugated);
    const base = { merchant: { id: "merchant-7" }, amount: 2500 };

    await router.callTool("purchase", { ...base, request_id: 42 }, CONTEXT);
    expect(masugated.executions[0]?.stableId).toBe(
      "mcp-tool\u0000purchase\u0000integer\u000042",
    );
    await expect(
      router.callTool("purchase", { ...base, request_id: "" }, CONTEXT),
    ).rejects.toThrow(/stable_id.*non-empty string or safe integer/);
    await expect(
      router.callTool("purchase", { ...base, request_id: 1.5 }, CONTEXT),
    ).rejects.toThrow(/stable_id.*non-empty string or safe integer/);
    await expect(router.callTool("purchase", base, CONTEXT)).rejects.toThrow(
      /stable_id.*non-empty string or safe integer/,
    );
  });

  it("maps a policy deny to readable MCP error content and structured data", async () => {
    const upstream = new FakeUpstream();
    const masugated = new FakeMasuGated();
    masugated.result = denied();
    const router = new GatewayRouter(manifest(), upstream, masugated);

    const result = await router.callTool("purchase", PURCHASE_ARGS, CONTEXT);

    expect(result.isError).toBe(true);
    expect(result.content[0]).toMatchObject({
      type: "text",
      text: expect.stringMatching(/budget-policy.*over_budget.*daily budget exceeded/),
    });
    expect(result.structuredContent).toMatchObject({
      status: "denied",
      operation_id: "op-2",
      decision: {
        policy_id: "budget-policy",
        rule_id: "over_budget",
        reason: "daily budget exceeded",
      },
    });
    expect(upstream.calls).toEqual([]);
  });

  it("returns an immediate pending marker without approval authority", async () => {
    const masugated = new FakeMasuGated();
    masugated.result = pending();
    const upstream = new FakeUpstream();
    const router = new GatewayRouter(manifest(), upstream, masugated);

    const result = await router.callTool("purchase", PURCHASE_ARGS, CONTEXT);

    expect(result.isError).toBeUndefined();
    expect(result.content[0]).toMatchObject({
      type: "text",
      text: expect.stringContaining("pending_id=pending-3"),
    });
    expect(result.structuredContent).toEqual({
      status: "pending",
      pending_id: "pending-3",
      operation_id: "op-3",
      audit_ref: "/v1/audit/op-3",
    });
    expect(upstream.calls).toEqual([]);
  });

  it("retrieves terminal state with the synthetic read-only audit tool", async () => {
    const masugated = new FakeMasuGated();
    masugated.audit = { operation_id: "op-3", status: "committed", effect: { receipt: "r3" } };
    const upstream = new FakeUpstream();
    const router = new GatewayRouter(manifest(), upstream, masugated);

    const result = await router.callTool(
      AUDIT_TOOL_NAME,
      { operation_id: "op-3" },
      CONTEXT,
    );

    expect(masugated.audits).toEqual(["op-3"]);
    expect(result.structuredContent).toEqual(masugated.audit);
    expect(upstream.calls).toEqual([]);
  });

  it("fails closed for unlisted tools and missing mapped values", async () => {
    const masugated = new FakeMasuGated();
    const router = new GatewayRouter(manifest(), new FakeUpstream(), masugated);
    await expect(router.callTool("hidden", {}, CONTEXT)).rejects.toThrow(
      /not declared governed or passthrough/,
    );
    await expect(
      router.callTool("purchase", { merchant: {}, amount: 1 }, CONTEXT),
    ).rejects.toThrow(/missing value for receiver_id/);
    expect(masugated.executions).toEqual([]);
  });

  it("fails startup when a declared tool is missing upstream", async () => {
    const router = new GatewayRouter(
      manifest(),
      new FakeUpstream([ECHO_TOOL]),
      new FakeMasuGated(),
    );
    await expect(router.initialize()).rejects.toThrow(/upstream does not expose it/);
  });
});
