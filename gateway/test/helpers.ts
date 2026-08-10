import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";

import { parseManifest } from "../src/manifest.js";
import type {
  GatewayManifest,
  JsonObject,
  MasuGatedActionResult,
  MasuGatedClient,
  MasuGatedExecuteRequest,
  Upstream,
} from "../src/types.js";

export const ECHO_TOOL: Tool = {
  name: "echo",
  description: "Echo input",
  inputSchema: {
    type: "object",
    properties: { text: { type: "string" } },
    required: ["text"],
  },
  outputSchema: {
    type: "object",
    properties: { echoed: { type: "string" } },
    required: ["echoed"],
  },
};

export const PURCHASE_TOOL: Tool = {
  name: "purchase",
  description: "Purchase from a merchant",
  inputSchema: {
    type: "object",
    properties: {
      request_id: { type: "string" },
      merchant: { type: "object" },
      amount: { type: "integer" },
    },
    required: ["request_id", "merchant", "amount"],
  },
  outputSchema: {
    type: "object",
    properties: { upstream_receipt: { type: "string" } },
  },
  execution: { taskSupport: "required" },
};

export function manifest(): GatewayManifest {
  return parseManifest(`
version: 1
upstream:
  command: node
  args: [fake-upstream.mjs]
masugated:
  base_url: http://masugated.test
  token_env: MASUGATED_TOKEN
governed:
  purchase:
    action: transfer
    stable_id: $.request_id
    args:
      receiver_id: $.merchant.id
      amount_cents: $.amount
passthrough:
  - echo
`);
}

export class FakeUpstream implements Upstream {
  readonly calls: Array<{ name: string; args?: Record<string, unknown> }> = [];
  result: CallToolResult = {
    content: [{ type: "text", text: "from upstream" }],
    structuredContent: { echoed: "from upstream" },
  };

  constructor(readonly tools: Tool[] = [ECHO_TOOL, PURCHASE_TOOL]) {}

  async listTools(): Promise<Tool[]> {
    return this.tools;
  }

  async callTool(name: string, args?: Record<string, unknown>): Promise<CallToolResult> {
    this.calls.push(args === undefined ? { name } : { name, args });
    return this.result;
  }
}

function decision(
  effect: "allow" | "deny" | "escalate",
): {
  effect: "allow" | "deny" | "escalate";
  policy_id: string;
  policy_version: string;
  rule_id: string;
  reason: string;
} {
  return {
    effect,
    policy_id: "budget-policy",
    policy_version: "v1",
    rule_id: effect === "deny" ? "over_budget" : "purchase_rule",
    reason: effect === "deny" ? "daily budget exceeded" : "test result",
  };
}

export function committed(payload: JsonObject = { receipt: "masugate-1" }): MasuGatedActionResult {
  return {
    operation_id: "op-1",
    status: "committed",
    decision: { ...decision("allow"), effect: "allow" },
    payload,
    audit_ref: "/v1/audit/op-1",
    replayed: false,
  };
}

export function denied(): MasuGatedActionResult {
  return {
    operation_id: "op-2",
    status: "denied",
    decision: { ...decision("deny"), effect: "deny" },
    payload: {},
    audit_ref: "/v1/audit/op-2",
    replayed: false,
  };
}

export function pending(): MasuGatedActionResult {
  return {
    operation_id: "op-3",
    status: "pending",
    pending_id: "pending-3",
    decision: { ...decision("escalate"), effect: "escalate" },
    payload: {},
    audit_ref: "/v1/audit/op-3",
    replayed: false,
  };
}

export class FakeMasuGated implements MasuGatedClient {
  readonly executions: MasuGatedExecuteRequest[] = [];
  readonly audits: string[] = [];
  result: MasuGatedActionResult = committed();
  audit: JsonObject = { operation_id: "op-1", status: "committed" };

  async execute(request: MasuGatedExecuteRequest): Promise<MasuGatedActionResult> {
    this.executions.push(request);
    return this.result;
  }

  async getAudit(operationId: string): Promise<JsonObject> {
    this.audits.push(operationId);
    return this.audit;
  }
}
