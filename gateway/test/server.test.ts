import {
  MasuGateClient,
  deriveIdempotencyKey,
  type JsonObject,
} from "@masugate/client";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";

import { AUDIT_TOOL_NAME } from "../src/manifest.js";
import { GatewayRouter } from "../src/router.js";
import { MasuGateSdkAdapter } from "../src/masugated.js";
import { connectGatewayServer } from "../src/server.js";
import {
  ECHO_TOOL,
  FakeMasuGated,
  FakeUpstream,
  PURCHASE_TOOL,
  manifest,
} from "./helpers.js";

const COMMITTED_ID = "11111111-1111-4111-8111-111111111111";
const DENIED_ID = "22222222-2222-4222-8222-222222222222";
const PENDING_ID = "33333333-3333-4333-8333-333333333333";
const PENDING_MARKER = "44444444-4444-4444-8444-444444444444";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function actionResponse(index: number): JsonObject {
  if (index === 0) {
    return {
      operation_id: COMMITTED_ID,
      status: "committed",
      decision: {
        effect: "allow",
        policy_id: "budget-policy",
        policy_version: "v1",
        rule_id: "purchase_rule",
        reason: "within budget",
      },
      payload: { receipt: "masugate-1" },
      audit_ref: `/v1/audit/${COMMITTED_ID}`,
      replayed: false,
    };
  }
  if (index === 1) {
    return {
      operation_id: DENIED_ID,
      status: "denied",
      decision: {
        effect: "deny",
        policy_id: "budget-policy",
        policy_version: "v1",
        rule_id: "over_budget",
        reason: "daily budget exceeded",
      },
      payload: {},
      audit_ref: `/v1/audit/${DENIED_ID}`,
      replayed: false,
    };
  }
  return {
    operation_id: PENDING_ID,
    status: "pending",
    pending_id: PENDING_MARKER,
    decision: {
      effect: "escalate",
      policy_id: "budget-policy",
      policy_version: "v1",
      rule_id: "purchase_review",
      reason: "human review required",
    },
    payload: {},
    audit_ref: `/v1/audit/${PENDING_ID}`,
    replayed: false,
  };
}

async function terminalAudit(): Promise<JsonObject> {
  const args = { receiver_id: "merchant-7", amount_cents: 5000 };
  return {
    operation_id: PENDING_ID,
    status: "committed",
    request: {
      idempotency_key: await deriveIdempotencyKey(
        "mcp-tool\u0000purchase\u0000string\u0000logical-purchase-wire-3",
      ),
      principal: { id: "agent-1", attributes: { team: "research" } },
      action: "transfer",
      args,
      timestamp: "2026-07-12T17:00:00Z",
      trace_id: "mcp:3",
    },
    policy: {
      policy_id: "budget-policy",
      policy_version: "v1",
      evaluated_policies: [
        { policy_id: "budget-policy", policy_version: "v1" },
      ],
      evaluated_policy_provenance: [
        {
          policy_id: "budget-policy",
          policy_declared_version: "1.0.0",
          policy_runtime_version: "v1",
          policy_digest: "a".repeat(64),
          bundle_id: "masugate.gateway.test",
          bundle_version: "1.0.0",
          bundle_digest: "b".repeat(64),
          layer: "platform-safety",
          mode: "mandatory",
        },
      ],
    },
    decision: {
      effect: "allow",
      rule_id: "purchase_review.approved",
      reason: "approved",
    },
    view_reads: [],
    authorization_evaluations: [],
    terminal_serialization: {
      kind: "effect-commit",
      authorization_basis: "resolution-evaluation",
      provider_atomic: true,
      recorded_at: "2026-07-12T17:01:00Z",
    },
    effect: { action: "transfer", args, payload: { receipt: "approved-r3" } },
    recorded_at: "2026-07-12T17:01:00Z",
  };
}

describe("official MCP client/server smoke", () => {
  it("fails startup when a passthrough tool requires unsupported MCP tasks", async () => {
    const taskRequiredEcho = {
      ...ECHO_TOOL,
      execution: { taskSupport: "required" as const },
    };
    const router = new GatewayRouter(
      manifest(),
      new FakeUpstream([taskRequiredEcho, PURCHASE_TOOL]),
      new FakeMasuGated(),
    );
    const [, serverTransport] = InMemoryTransport.createLinkedPair();

    await expect(connectGatewayServer(router, serverTransport)).rejects.toThrow(
      /passthrough tool "echo" requires MCP task execution.*does not advertise or handle MCP tasks/,
    );
  });

  it("drives committed, denied, pending, then terminal audit through the SDK HTTP adapter", async () => {
    const actionBodies: JsonObject[] = [];
    let terminal = false;
    const fakeFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      if (url.pathname === "/v1/actions") {
        const body = JSON.parse(String(init?.body)) as JsonObject;
        actionBodies.push(body);
        return jsonResponse(actionResponse(actionBodies.length - 1));
      }
      if (url.pathname === `/v1/audit/${PENDING_ID}` && terminal) {
        return jsonResponse(await terminalAudit());
      }
      return jsonResponse(
        { error: { code: "not_found", message: "receipt is not terminal" } },
        404,
      );
    }) as typeof fetch;

    const upstream = new FakeUpstream();
    const masugated = new MasuGateSdkAdapter(
      new MasuGateClient({
        baseUrl: "http://masugated.test",
        token: "gateway-token",
        fetch: fakeFetch,
      }),
    );
    const router = new GatewayRouter(manifest(), upstream, masugated);
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = await connectGatewayServer(router, serverTransport);
    const client = new Client(
      { name: "gateway-smoke-client", version: "0.1.1" },
      { capabilities: {} },
    );

    try {
      await client.connect(clientTransport);
      const listed = await client.listTools();
      expect(listed.tools.map((tool) => tool.name)).toEqual([
        "echo",
        "purchase",
        AUDIT_TOOL_NAME,
      ]);
      expect(listed.tools.find((tool) => tool.name === "purchase")?.execution).toBeUndefined();

      const passthrough = await client.callTool({
        name: "echo",
        arguments: { text: "hello" },
      });
      expect(passthrough).toMatchObject({
        content: [{ type: "text", text: "from upstream" }],
      });

      const committed = await client.callTool({
        name: "purchase",
        arguments: {
          request_id: "logical-purchase-wire-1",
          merchant: { id: "merchant-7" },
          amount: 2500,
        },
      });
      expect(committed).toMatchObject({
        content: [{ type: "text", text: '{"receipt":"masugate-1"}' }],
        structuredContent: { receipt: "masugate-1" },
      });

      const denied = await client.callTool({
        name: "purchase",
        arguments: {
          request_id: "logical-purchase-wire-2",
          merchant: { id: "merchant-7" },
          amount: 500_000,
        },
      });
      expect(denied).toMatchObject({
        isError: true,
        structuredContent: {
          status: "denied",
          operation_id: DENIED_ID,
          decision: {
            policy_id: "budget-policy",
            rule_id: "over_budget",
            reason: "daily budget exceeded",
          },
        },
      });

      const pending = await client.callTool({
        name: "purchase",
        arguments: {
          request_id: "logical-purchase-wire-3",
          merchant: { id: "merchant-7" },
          amount: 5000,
        },
      });
      expect(pending).toMatchObject({
        structuredContent: {
          status: "pending",
          pending_id: PENDING_MARKER,
          operation_id: PENDING_ID,
          audit_ref: `/v1/audit/${PENDING_ID}`,
        },
      });

      terminal = true;
      const audit = await client.callTool({
        name: AUDIT_TOOL_NAME,
        arguments: { operation_id: PENDING_ID },
      });
      expect(audit).toMatchObject({
        structuredContent: {
          operation_id: PENDING_ID,
          status: "committed",
          effect: { payload: { receipt: "approved-r3" } },
        },
      });

      expect(upstream.calls).toHaveLength(1);
      expect(actionBodies).toHaveLength(3);
      expect(actionBodies[0]?.["idempotency_key"]).toBe(
        await deriveIdempotencyKey(
          "mcp-tool\u0000purchase\u0000string\u0000logical-purchase-wire-1",
        ),
      );

      await expect(
        client.callTool({ name: "hidden", arguments: {} }),
      ).rejects.toBeInstanceOf(McpError);
    } finally {
      await client.close();
      await server.close();
    }
  });
});
