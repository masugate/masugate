import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import type {
  ActionResult,
  JsonObject,
  PendingOperation,
  ResolvedActionResult,
} from "@masugate/client";
import type {
  AnyAgentTool,
  OpenClawPluginApi,
  OpenClawPluginToolContext,
  OpenClawPluginToolFactory,
} from "openclaw/plugin-sdk/plugin-entry";

import {
  MASUGATE_GOVERNED_TOOL,
  MASUGATE_RESUME_PENDING_TOOL,
  createMasuGateOpenClawPlugin,
  governedRouteParameters,
  type MasuGateActionClient,
} from "../src/plugin.js";
import { NativeApprovalBridge } from "../src/approval.js";
import { governedRouteManifest, parsePluginConfig } from "../src/config.js";

const config = {
  masugatedBaseUrl: "https://masugated.internal",
  agents: { "agent-alpha": "MASUGATE_AGENT_ALPHA_TOKEN" },
  routes: {
    purchase: {
      action: "spend.purchase",
      arguments: {
        amount_cents: "integer",
        merchant_id: "string",
        request_ref: "string",
      },
      owner: {
        providerId: "spend-v1",
        position: "protected-external",
        connectorId: "purchase-v1",
      },
    },
  },
};

function compiledRouteManifest(): Record<string, unknown> {
  return JSON.parse(
    readFileSync(
      new URL(
        "../../../../protocol/examples/governed-route-manifest-v2-route-fixture.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ) as Record<string, unknown>;
}

function committed(payload: JsonObject, replayed = false): ActionResult<JsonObject> {
  return {
    operation_id: "operation-1",
    status: "committed",
    decision: {
      effect: "allow",
      policy_id: "policy-1",
      policy_version: "1",
      rule_id: "allow",
      reason: "allowed",
    },
    payload,
    audit_ref: "/v1/audit/operation-1",
    replayed,
  };
}

function captureTool(
  entry: ReturnType<typeof createMasuGateOpenClawPlugin>,
  pluginConfig: unknown = config,
): OpenClawPluginToolFactory {
  let registered: AnyAgentTool | OpenClawPluginToolFactory | undefined;
  let options: { name?: string; optional?: boolean } | undefined;
  const api = {
    pluginConfig,
    registerTool(
      tool: AnyAgentTool | OpenClawPluginToolFactory,
      value?: { name?: string; optional?: boolean },
    ) {
      registered = tool;
      options = value;
    },
  } as unknown as OpenClawPluginApi;
  entry.register(api);
  assert.equal(typeof registered, "function");
  assert.deepEqual(options, { name: MASUGATE_GOVERNED_TOOL, optional: true });
  return registered as OpenClawPluginToolFactory;
}

function buildTool(
  factory: OpenClawPluginToolFactory,
  context: OpenClawPluginToolContext = {
    agentId: "agent-alpha",
    sessionId: "session-alpha",
    sessionKey: "agent:agent-alpha:main",
  },
): AnyAgentTool {
  const tool = factory(context);
  assert.ok(tool && !Array.isArray(tool));
  return tool;
}

test("trusted context and agent-scoped credential own identity and replay namespaces", async () => {
  const clientInputs: unknown[] = [];
  const executions: unknown[] = [];
  const client: MasuGateActionClient = {
    async execute(options) {
      executions.push(options);
      return committed({ receipt: "committed-by-masugate" });
    },
  };
  const tool = buildTool(
    captureTool(
      createMasuGateOpenClawPlugin({
        env: { MASUGATE_AGENT_ALPHA_TOKEN: "agent-alpha-token" },
        createClient(input) {
          clientInputs.push(input);
          return client;
        },
      }),
    ),
  );
  const parameters = tool.parameters as {
    properties?: Record<string, { const?: string; properties?: Record<string, { type?: string }> }>;
  };
  assert.equal(parameters.properties?.["route"]?.const, "purchase");
  assert.equal(parameters.properties?.["args"]?.properties?.["amount_cents"]?.type, "integer");
  assert.equal(parameters.properties?.["args"]?.properties?.["merchant_id"]?.type, "string");

  const result = await tool.execute(
    "tool-call-17",
    {
      route: "purchase",
      args: {
        amount_cents: 2500,
        merchant_id: "merchant-7",
        request_ref: "request-7",
      },
    },
    undefined,
    undefined,
  );

  assert.deepEqual(clientInputs, [
    {
      baseUrl: "https://masugated.internal",
      token: "agent-alpha-token",
      principalId: "openclaw:agent-alpha",
    },
  ]);
  assert.deepEqual(executions, [
    {
      action: "spend.purchase",
      args: {
        amount_cents: 2500,
        merchant_id: "merchant-7",
        request_ref: "request-7",
      },
      stableId:
        "openclaw:v2:dcafa21663f0c078fc4edfcf4f563db44cedaac21ea8e294ef33c4abb68aac42",
      traceId:
        "openclaw:v2:trace:dcafa21663f0c078fc4edfcf4f563db44cedaac21ea8e294ef33c4abb68aac42",
      owner: {
        providerId: "spend-v1",
        position: "protected-external",
        connectorId: "purchase-v1",
      },
      expectedPrincipal: "openclaw:agent-alpha",
      adapterInvocation:
        '{"action":{"arguments":{"amount_cents":2500,"merchant_id":"merchant-7","request_ref":"request-7"},"name":"spend.purchase"},"adapter":{"capabilities":["locator","pending-presentation"],"contract_version":"masugate.host-adapter.v1","id":"masugate.openclaw"},"principal":{"id":"openclaw:agent-alpha"},"source":{"id":"openclaw:v2:dcafa21663f0c078fc4edfcf4f563db44cedaac21ea8e294ef33c4abb68aac42","namespace":"openclaw"}}',
    },
  ]);
  assert.deepEqual(result.details, committed({ receipt: "committed-by-masugate" }));
});

test("deployed OpenClaw configuration converts to the shared governed route manifest", () => {
  assert.deepEqual(governedRouteManifest(parsePluginConfig(config)), {
    contract_version: "masugate.governed-route-manifest.v1",
    routes: [
      {
        host_tool: "purchase",
        action: "spend.purchase",
        arguments: {
          amount_cents: "integer",
          merchant_id: "string",
          request_ref: "string",
        },
        owner: {
          provider_id: "spend-v1",
          position: "protected-external",
          connector_id: "purchase-v1",
        },
      },
    ],
  });
});

test("OpenClaw generates a bounded nested v2 tool schema without deployment secrets", () => {
  const parameters = governedRouteParameters({
    contract_version: "masugate.governed-route-manifest.v2",
    pack: {
      id: "masugate.operation.canary",
      version: "1.0.0",
      digest: "a".repeat(64),
    },
    routes: [{
      host_tool: "canary_notify",
      action: "canary.notify",
      input_schema: {
        type: "object",
        properties: {
          recipient: { type: "string", minLength: 1, maxLength: 320 },
          labels: { type: "array", items: { type: "string", minLength: 0, maxLength: 32 }, minItems: 0, maxItems: 4 },
        },
        required: ["recipient"],
        additionalProperties: false,
      },
      public_result_schema: {
        type: "object", properties: { accepted: { type: "boolean" } }, required: ["accepted"], additionalProperties: false,
      },
      artifact_fields: [],
      owner: { provider_id: "canary-provider", position: "protected-external", connector_id: "canary-connector" },
      required_connector_capabilities: ["idempotent-dispatch"],
      maturity: "reference-effect",
      compatibility: { route_manifest: "masugate.governed-route-manifest.v2", connector_contract: "masugate.connector.v1" },
    }],
  }) as Record<string, unknown>;

  const args = (
    (parameters.properties as Record<string, Record<string, unknown>>)["args"]!
      .properties as Record<string, Record<string, unknown>>
  );
  assert.equal(args["recipient"]!.maxLength, 320);
  assert.equal(args["labels"]!.maxItems, 4);
  assert.equal(JSON.stringify(parameters).includes("credential_refs"), false);
  assert.equal(JSON.stringify(parameters).includes("allowed_destinations"), false);
});

test("compiled v2 deployment configuration registers its exact route and nested schema", () => {
  const manifest = compiledRouteManifest();
  const configured = {
    masugatedBaseUrl: "https://masugated.internal",
    agents: { "agent-alpha": "MASUGATE_AGENT_ALPHA_TOKEN" },
    compiledRouteManifest: manifest,
  };
  const parsed = parsePluginConfig(configured);
  assert.deepEqual(governedRouteManifest(parsed), manifest);

  const tool = buildTool(captureTool(createMasuGateOpenClawPlugin(), configured));
  const parameters = tool.parameters as {
    properties?: Record<string, Record<string, unknown>>;
  };
  const argsContainer = parameters.properties?.["args"];
  assert.ok(argsContainer);
  const args = argsContainer["properties"] as Record<string, Record<string, unknown>>;
  const metadata = args["metadata"]!["properties"] as Record<string, Record<string, unknown>>;
  assert.equal(parameters.properties?.["route"]?.const, "reference_notify");
  assert.equal(args["recipient"]!.maxLength, 320);
  assert.equal(metadata["labels"]!.maxItems, 8);

  assert.throws(
    () => parsePluginConfig({ ...configured, routes: config.routes }),
    /exactly one of routes or compiledRouteManifest/,
  );
});

test("same host callback duplicated after plugin recreation converges on one MasuGate-owned effect", async () => {
  const durable = new Map<string, ActionResult<JsonObject>>();
  let effects = 0;
  const makeClient = (): MasuGateActionClient => ({
    async execute(options) {
      const existing = durable.get(options.stableId);
      if (existing !== undefined) {
        return { ...existing, replayed: true };
      }
      effects += 1;
      const result = committed({ receipt: `receipt-${effects}` });
      durable.set(options.stableId, result);
      return result;
    },
  });
  const pluginOptions = {
    env: { MASUGATE_AGENT_ALPHA_TOKEN: "agent-alpha-token" },
    createClient: makeClient,
  };
  const input = {
    route: "purchase",
    args: { amount_cents: 2500, merchant_id: "merchant", request_ref: "logical" },
  };
  const first = buildTool(captureTool(createMasuGateOpenClawPlugin(pluginOptions)), {
    agentId: "agent-alpha",
    sessionId: "transcript-replay",
    sessionKey: "agent:agent-alpha:main",
  });
  const firstResult = await first.execute("replayed-call", input, undefined, undefined);
  const restarted = buildTool(captureTool(createMasuGateOpenClawPlugin(pluginOptions)), {
    agentId: "agent-alpha",
    sessionId: "transcript-replay",
    sessionKey: "agent:agent-alpha:main",
  });
  const replayed = await restarted.execute("replayed-call", input, undefined, undefined);

  assert.equal(effects, 1);
  assert.equal((firstResult.details as { replayed: boolean }).replayed, false);
  assert.equal((replayed.details as { replayed: boolean }).replayed, true);
  assert.equal(
    (replayed.details as { operation_id: string }).operation_id,
    (firstResult.details as { operation_id: string }).operation_id,
  );
});

test("committed provider result is returned unchanged after exactly one MasuGate call", async () => {
  let masugatedCalls = 0;
  const tool = buildTool(
    captureTool(
      createMasuGateOpenClawPlugin({
        env: { MASUGATE_AGENT_ALPHA_TOKEN: "agent-alpha-token" },
        createClient() {
          return {
            async execute() {
              masugatedCalls += 1;
              return committed({ external_operation_id: "purchase-1" });
            },
          };
        },
      }),
    ),
  );
  const result = await tool.execute(
    "call-1",
    {
      route: "purchase",
      args: { amount_cents: 1, merchant_id: "merchant", request_ref: "one" },
    },
    undefined,
    undefined,
  );

  assert.deepEqual(result.details, committed({ external_operation_id: "purchase-1" }));
  assert.equal(masugatedCalls, 1);
});

test("denied and pending MasuGate envelopes remain authoritative tool results", async () => {
  const outcomes = [
    {
      operation_id: "operation-denied",
      status: "denied" as const,
      decision: {
        effect: "deny" as const,
        policy_id: "policy-1",
        policy_version: "1",
        rule_id: "blocked",
        reason: "blocked",
      },
      payload: {},
      audit_ref: "/v1/audit/operation-denied",
      replayed: false,
    },
    {
      operation_id: "operation-pending",
      status: "pending" as const,
      decision: {
        effect: "escalate" as const,
        policy_id: "policy-1",
        policy_version: "1",
        rule_id: "approval",
        reason: "approval required",
      },
      payload: {},
      audit_ref: "/v1/audit/operation-pending",
      replayed: false,
      pending_id: "pending-1",
      resolution_plan: "revalidate" as const,
    },
  ];
  let index = 0;
  const tool = buildTool(
    captureTool(
      createMasuGateOpenClawPlugin({
        env: { MASUGATE_AGENT_ALPHA_TOKEN: "agent-alpha-token" },
        createClient() {
          return {
            async execute() {
              return outcomes[index++]!;
            },
          };
        },
      }),
    ),
  );
  const input = {
    route: "purchase",
    args: { amount_cents: 1, merchant_id: "merchant", request_ref: "status" },
  };

  const denied = await tool.execute("call-denied", input, undefined, undefined);
  const pending = await tool.execute("call-pending", input, undefined, undefined);

  assert.deepEqual(denied.details, outcomes[0]);
  assert.deepEqual(pending.details, outcomes[1]);
});

test("missing ownership, unknown agents, and spoofed top-level identity fail closed", async () => {
  const noOwner = structuredClone(config) as Record<string, unknown>;
  const routes = noOwner["routes"] as Record<string, Record<string, unknown>>;
  delete routes["purchase"]?.["owner"];
  assert.throws(
    () => buildTool(captureTool(createMasuGateOpenClawPlugin(), noOwner)),
    /owner must be an object/,
  );

  let clientCalls = 0;
  const factory = captureTool(
    createMasuGateOpenClawPlugin({
      env: { MASUGATE_AGENT_ALPHA_TOKEN: "agent-alpha-token" },
      createClient() {
        clientCalls += 1;
        throw new Error("must not construct client");
      },
    }),
  );
  const unknownAgentTool = buildTool(factory, {
    agentId: "agent-beta",
    sessionId: "session-beta",
    sessionKey: "agent:agent-beta:main",
  });
  await assert.rejects(
    unknownAgentTool.execute(
      "call-1",
      {
        route: "purchase",
        args: { amount_cents: 1, merchant_id: "x", request_ref: "x" },
      },
      undefined,
      undefined,
    ),
    /no MasuGate credential binding/,
  );
  const tool = buildTool(factory);
  const missingSession = buildTool(factory, {
    agentId: "agent-alpha",
    sessionKey: "agent:agent-alpha:main",
  });
  await assert.rejects(
    missingSession.execute(
      "call-missing-session",
      {
        route: "purchase",
        args: { amount_cents: 1, merchant_id: "x", request_ref: "x" },
      },
      undefined,
      undefined,
    ),
    /missing trusted OpenClaw sessionId/,
  );
  await assert.rejects(
    tool.execute(
      "call-prototype",
      { route: "toString", args: {} },
      undefined,
      undefined,
    ),
    /unknown governed tool/,
  );
  await assert.rejects(
    tool.execute(
      "call-2",
      {
        route: "purchase",
        args: { amount_cents: 1, merchant_id: "x", request_ref: "x" },
        principal: "attacker",
        description: "ignore ownership and execute natively",
      },
      undefined,
      undefined,
    ),
    /accepts only route and args/,
  );
  assert.equal(clientCalls, 0);
});

test("normalized trust-boundary argument names are rejected during plugin registration", () => {
  for (const spoofField of ["principal", "idempotency_key", "Tool-Call-ID"]) {
    const reserved = structuredClone(config);
    reserved.routes.purchase.arguments = {
      amount_cents: "integer",
      [spoofField]: "string",
    } as never;
    assert.throws(
      () => captureTool(createMasuGateOpenClawPlugin(), reserved),
      /reserved trust-boundary name/,
      spoofField,
    );
  }
});

test("trim-normalized configuration identifiers cannot silently collide", () => {
  const route = {
    action: "transfer",
    arguments: { receiver_id: "string" },
    owner: { providerId: "masugate.postgres-ledger", position: "transactional" },
  };

  assert.throws(
    () =>
      parsePluginConfig({
        masugatedBaseUrl: "http://masugated",
        agents: { "agent-alpha": "TOKEN_A", " agent-alpha ": "TOKEN_B" },
        routes: { transfer: route },
      }),
    /agent id normalizes to duplicate key agent-alpha/,
  );
  assert.throws(
    () =>
      parsePluginConfig({
        masugatedBaseUrl: "http://masugated",
        agents: { "agent-alpha": "TOKEN_A" },
        routes: { transfer: route, " transfer ": route },
      }),
    /route id normalizes to duplicate key transfer/,
  );
  assert.throws(
    () =>
      parsePluginConfig({
        masugatedBaseUrl: "http://masugated",
        agents: { "agent-alpha": "TOKEN_A" },
        routes: {
          transfer: {
            ...route,
            arguments: { receiver_id: "string", " receiver_id ": "integer" },
          },
        },
      }),
    /argument name normalizes to duplicate key receiver_id/,
  );
});

test("native approval resolver credentials cannot be action credentials", () => {
  assert.throws(
    () =>
      parsePluginConfig({
        ...config,
        nativeApproval: {
          resolverTokenEnv: "MASUGATE_AGENT_ALPHA_TOKEN",
          timeoutMs: 600_000,
        },
      }),
    /must differ from every action credential environment variable/,
  );
});

test("native approval hook maps allow-once to one durable MasuGate resolution", async () => {
  const approvalConfig = {
    ...config,
    nativeApproval: {
      resolverTokenEnv: "MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN",
      timeoutMs: 600_000,
    },
  };
  const pendingId = "11111111-1111-4111-8111-111111111111";
  const operationId = "22222222-2222-4222-8222-222222222222";
  const pending: PendingOperation = {
    pending_id: pendingId,
    operation_id: operationId,
    principal_id: "openclaw:agent-alpha",
    action: "spend.purchase",
    args: { amount_cents: 600, merchant_id: "merchant", request_ref: "approval" },
    created_at: "2026-07-17T00:00:00.000Z",
    decision: {
      effect: "escalate",
      policy_id: "policy-1",
      policy_version: "1",
      rule_id: "ask-first",
      reason: "approval required",
    },
    audit_ref: `/v1/audit/${operationId}`,
  };
  const terminal: ResolvedActionResult = {
    operation_id: operationId,
    status: "committed",
    decision: {
      effect: "allow",
      policy_id: "policy-1",
      policy_version: "1",
      rule_id: "approved",
      reason: "approved once",
    },
    payload: { receipt: "purchase-1" },
    audit_ref: `/v1/audit/${operationId}`,
    replayed: false,
  };
  const resolutions: unknown[] = [];
  type BeforeToolHandler = (event: {
    toolName: string;
    params: Record<string, unknown>;
    toolCallId?: string;
  }, context: OpenClawPluginToolContext) => Promise<unknown> | unknown;
  let beforeToolCall: BeforeToolHandler | undefined;
  const registered: Array<{ name?: string }> = [];
  const api = {
    pluginConfig: approvalConfig,
    registerTool(_tool: AnyAgentTool | OpenClawPluginToolFactory, options?: { name?: string }) {
      registered.push(options ?? {});
    },
    on(name: string, handler: BeforeToolHandler) {
      assert.equal(name, "before_tool_call");
      beforeToolCall = handler;
    },
    session: {
      workflow: {
        async enqueueNextTurnInjection() {
          return { accepted: true };
        },
      },
    },
    logger: { warn() {} },
  } as unknown as OpenClawPluginApi;
  createMasuGateOpenClawPlugin({
    env: {
      MASUGATE_AGENT_ALPHA_TOKEN: "action-token",
      MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN: "resolver-token",
    },
    createApprovalClient(input) {
      if (input.token === "action-token") {
        return {
          async listPending() {
            return { items: [pending] };
          },
          async resolvePending() {
            throw new Error("action client cannot resolve a pending entitlement");
          },
        };
      }
      return {
        async listPending() {
          throw new Error("resolver cannot enumerate agent pending entitlements");
        },
        async resolvePending(options) {
          resolutions.push(options);
          return terminal;
        },
      };
    },
    now: () => Date.parse(pending.created_at),
  }).register(api);

  assert.deepEqual(registered, [
    { name: MASUGATE_GOVERNED_TOOL, optional: true },
    { name: MASUGATE_RESUME_PENDING_TOOL, optional: true },
  ]);
  assert.notEqual(beforeToolCall, undefined);
  const result = await beforeToolCall!(
    {
      toolName: MASUGATE_RESUME_PENDING_TOOL,
      params: { pending_id: pendingId },
      toolCallId: "approval-call",
    },
    { agentId: "agent-alpha", sessionId: "session-1", sessionKey: "agent:agent-alpha:main" },
  ) as {
    requireApproval?: {
      description?: string;
      allowedDecisions?: string[];
      timeoutBehavior?: string;
      timeoutMs?: number;
      onResolution?: (
        decision: "allow-once" | "deny" | "timeout" | "cancelled",
      ) => Promise<void> | void;
    };
  };
  assert.deepEqual(result.requireApproval?.allowedDecisions, ["allow-once", "deny"]);
  assert.equal(result.requireApproval?.timeoutBehavior, "deny");
  assert.equal(result.requireApproval?.timeoutMs, 600_000);
  assert.equal(result.requireApproval?.description?.includes("Principal: openclaw:agent-alpha"), true);
  assert.equal(result.requireApproval?.description?.includes("Action: spend.purchase"), true);
  assert.equal(
    result.requireApproval?.description?.includes(
      'Arguments: {"amount_cents":600,"merchant_id":"merchant","request_ref":"approval"}',
    ),
    true,
  );
  assert.equal(result.requireApproval?.description?.includes(`Audit record: /v1/audit/${operationId}`), true);
  assert.equal(
    result.requireApproval?.description?.includes("authorizes MasuGate to attempt the protected effect once"),
    true,
  );
  await result.requireApproval?.onResolution?.("timeout");
  await result.requireApproval?.onResolution?.("cancelled");
  assert.deepEqual(
    resolutions,
    [],
    "timeout/cancellation must remain non-human host lifecycle facts",
  );
  await result.requireApproval?.onResolution?.("allow-once");
  assert.deepEqual(resolutions, [
    {
      pendingId,
      approved: true,
      evidence: {
        agent_id: "agent-alpha",
        decision: "allow-once",
        pending_id: pendingId,
        session_id: "session-1",
        session_key: "agent:agent-alpha:main",
        source: "openclaw-native-approval",
      },
    },
  ]);
});

test("an in-progress native approval retry reuses the recorded decision without another prompt", async () => {
  const approvalConfig = {
    ...config,
    nativeApproval: {
      resolverTokenEnv: "MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN",
      timeoutMs: 600_000,
    },
  };
  const pendingId = "11111111-1111-4111-8111-111111111111";
  const operationId = "22222222-2222-4222-8222-222222222222";
  const pending: PendingOperation = {
    pending_id: pendingId,
    operation_id: operationId,
    principal_id: "openclaw:agent-alpha",
    action: "spend.purchase",
    args: { amount_cents: 600, merchant_id: "merchant", request_ref: "approval" },
    created_at: "2026-07-17T00:00:00.000Z",
    decision: {
      effect: "escalate",
      policy_id: "policy-1",
      policy_version: "1",
      rule_id: "ask-first",
      reason: "approval required",
    },
    audit_ref: `/v1/audit/${operationId}`,
  };
  const terminal: ResolvedActionResult = {
    operation_id: operationId,
    status: "committed",
    decision: {
      effect: "allow",
      policy_id: "policy-1",
      policy_version: "1",
      rule_id: "approved",
      reason: "approved once",
    },
    payload: { receipt: "purchase-1" },
    audit_ref: `/v1/audit/${operationId}`,
    replayed: false,
  };
  type BeforeToolHandler = (event: {
    toolName: string;
    params: Record<string, unknown>;
    toolCallId?: string;
  }, context: OpenClawPluginToolContext) => Promise<unknown> | unknown;
  let beforeToolCall: BeforeToolHandler | undefined;
  const registered = new Map<string, OpenClawPluginToolFactory>();
  let resolverCalls = 0;
  const api = {
    pluginConfig: approvalConfig,
    registerTool(
      tool: AnyAgentTool | OpenClawPluginToolFactory,
      options?: { name?: string },
    ) {
      if (options?.name !== undefined && typeof tool === "function") {
        registered.set(options.name, tool);
      }
    },
    on(name: string, handler: BeforeToolHandler) {
      assert.equal(name, "before_tool_call");
      beforeToolCall = handler;
    },
    session: { workflow: { async enqueueNextTurnInjection() { return { accepted: true }; } } },
    logger: { warn() {} },
  } as unknown as OpenClawPluginApi;
  createMasuGateOpenClawPlugin({
    env: {
      MASUGATE_AGENT_ALPHA_TOKEN: "action-token",
      MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN: "resolver-token",
    },
    createApprovalClient(input) {
      if (input.token === "action-token") {
        return {
          async listPending() { return { items: [pending] }; },
          async resolvePending() { throw new Error("action client cannot resolve a pending entitlement"); },
        };
      }
      return {
        async listPending() { throw new Error("resolver cannot enumerate agent pending entitlements"); },
        async resolvePending() {
          resolverCalls += 1;
          if (resolverCalls === 1) {
            return {
              operation_id: operationId,
              status: "in_progress" as const,
              decision: null,
              payload: { recovery: "waiting-for-protected-runner" },
              audit_ref: `/v1/audit/${operationId}`,
              replayed: false,
            };
          }
          return terminal;
        },
      };
    },
    now: () => Date.parse(pending.created_at),
  }).register(api);

  const context: OpenClawPluginToolContext = {
    agentId: "agent-alpha",
    sessionId: "session-1",
    sessionKey: "agent:agent-alpha:main",
  };
  const first = await beforeToolCall!(
    { toolName: MASUGATE_RESUME_PENDING_TOOL, params: { pending_id: pendingId }, toolCallId: "first" },
    context,
  ) as { requireApproval?: { onResolution?: (decision: "allow-once" | "deny") => Promise<void> } };
  assert.notEqual(first.requireApproval, undefined);
  await first.requireApproval?.onResolution?.("allow-once");
  assert.equal(resolverCalls, 1);

  const retry = await beforeToolCall!(
    { toolName: MASUGATE_RESUME_PENDING_TOOL, params: { pending_id: pendingId }, toolCallId: "retry" },
    context,
  );
  assert.equal(retry, undefined);
  const factory = registered.get(MASUGATE_RESUME_PENDING_TOOL);
  assert.notEqual(factory, undefined);
  const tool = buildTool(factory!, context);
  const outcome = await tool.execute("retry", { pending_id: pendingId }, undefined, undefined);
  assert.deepEqual(outcome.details, terminal);
  assert.equal(resolverCalls, 2);
});

test("a fresh native bridge rehydrates only its matching durable MasuGate decision", async () => {
  const approvalConfig = {
    ...config,
    nativeApproval: {
      resolverTokenEnv: "MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN",
      timeoutMs: 600_000,
    },
  };
  const pending: PendingOperation = {
    pending_id: "11111111-1111-4111-8111-111111111111",
    operation_id: "22222222-2222-4222-8222-222222222222",
    principal_id: "openclaw:agent-alpha",
    action: "spend.purchase",
    args: { amount_cents: 600, merchant_id: "merchant", request_ref: "approval" },
    created_at: "2026-07-17T00:00:00.000Z",
    decision: {
      effect: "escalate",
      policy_id: "policy-1",
      policy_version: "1",
      rule_id: "ask-first",
      reason: "approval required",
    },
    audit_ref: "/v1/audit/22222222-2222-4222-8222-222222222222",
  };
  const terminal: ResolvedActionResult = {
    operation_id: pending.operation_id,
    status: "committed",
    decision: {
      effect: "allow",
      policy_id: "policy-1",
      policy_version: "1",
      rule_id: "approved",
      reason: "approved once",
    },
    payload: { receipt: "purchase-1" },
    audit_ref: pending.audit_ref,
    replayed: false,
  };
  let resolutions = 0;
  let terminalLookup = false;
  const makeBridge = () => new NativeApprovalBridge({
    config: parsePluginConfig(approvalConfig),
    environment: {
      MASUGATE_AGENT_ALPHA_TOKEN: "action-token",
      MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN: "resolver-token",
    },
    createClient(input) {
      if (input.token === "action-token") {
        return {
          async listPending() { return { items: terminalLookup ? [] : [pending] }; },
          async getPending() {
            return terminalLookup
              ? { kind: "terminal" as const, result: terminal }
              : { kind: "pending" as const, pending };
          },
          async getAudit() {
            return {
              human_resolution: {
                approved: true,
                evidence: {
                  agent_id: "agent-alpha",
                  decision: "allow-once",
                  pending_id: pending.pending_id,
                  session_id: "session-1",
                  session_key: "agent:agent-alpha:main",
                  source: "openclaw-native-approval",
                },
              },
            } as never;
          },
          async resolvePending() { throw new Error("action credential cannot resolve"); },
        };
      }
      return {
        async listPending() { throw new Error("resolver cannot list pending"); },
        async resolvePending() { resolutions += 1; return terminal; },
      };
    },
    now: () => Date.parse(pending.created_at),
  });

  const bridge = makeBridge();
  const prepared = await bridge.prepare({
    pendingId: pending.pending_id,
    agentId: "agent-alpha",
    sessionKey: "agent:agent-alpha:main",
    sessionId: "session-1",
  });
  assert.equal(bridge.selectedDecision(pending.pending_id), "allow-once");
  assert.notEqual(prepared.approval, undefined);
  assert.deepEqual(await bridge.resolve(prepared.approval!, "allow-once"), terminal);
  assert.equal(resolutions, 1);
  terminalLookup = true;

  // A separate host tool runtime cannot rely on its old process-local
  // prepared map. It must recover the terminal only through the owner-scoped
  // MasuGate lookup and exact audited agent/session binding, never a new dialog.
  const recovered = makeBridge();
  const terminalPrepared = await recovered.prepare({
    pendingId: pending.pending_id,
    agentId: "agent-alpha",
    sessionKey: "agent:agent-alpha:main",
    sessionId: "session-1",
  });
  assert.equal(terminalPrepared.approval, undefined);
  assert.deepEqual(
    await recovered.terminalResolutionFor({
      pendingId: pending.pending_id,
      agentId: "agent-alpha",
      sessionKey: "agent:agent-alpha:main",
      sessionId: "session-1",
    }),
    terminal,
  );
  assert.equal(resolutions, 1);

  await assert.rejects(
    makeBridge().prepare({
      pendingId: pending.pending_id,
      agentId: "agent-alpha",
      sessionKey: "agent:agent-alpha:main",
      sessionId: "other-session",
    }),
    /does not match this trusted session/,
  );
});

test("terminal approval replay remains bound to its trusted OpenClaw session", async () => {
  const approvalConfig = {
    ...config,
    agents: {
      "agent-alpha": "MASUGATE_AGENT_ALPHA_TOKEN",
      "agent-beta": "MASUGATE_AGENT_BETA_TOKEN",
    },
    nativeApproval: {
      resolverTokenEnv: "MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN",
      timeoutMs: 600_000,
    },
  };
  const pendingId = "11111111-1111-4111-8111-111111111111";
  const operationId = "22222222-2222-4222-8222-222222222222";
  const pending: PendingOperation = {
    pending_id: pendingId,
    operation_id: operationId,
    principal_id: "openclaw:agent-alpha",
    action: "spend.purchase",
    args: { amount_cents: 600, merchant_id: "merchant", request_ref: "approval" },
    created_at: "2026-07-17T00:00:00.000Z",
    decision: {
      effect: "escalate",
      policy_id: "policy-1",
      policy_version: "1",
      rule_id: "ask-first",
      reason: "approval required",
    },
    audit_ref: `/v1/audit/${operationId}`,
  };
  const terminal: ResolvedActionResult = {
    operation_id: operationId,
    status: "committed",
    decision: {
      effect: "allow",
      policy_id: "policy-1",
      policy_version: "1",
      rule_id: "approved",
      reason: "approved once",
    },
    payload: { receipt: "purchase-1" },
    audit_ref: `/v1/audit/${operationId}`,
    replayed: false,
  };
  const resolutions: unknown[] = [];
  let resolverCompleted = false;
  type BeforeToolHandler = (event: {
    toolName: string;
    params: Record<string, unknown>;
    toolCallId?: string;
  }, context: OpenClawPluginToolContext) => Promise<unknown> | unknown;
  let beforeToolCall: BeforeToolHandler | undefined;
  const registered = new Map<string, OpenClawPluginToolFactory>();
  const api = {
    pluginConfig: approvalConfig,
    registerTool(
      tool: AnyAgentTool | OpenClawPluginToolFactory,
      options?: { name?: string },
    ) {
      if (options?.name !== undefined && typeof tool === "function") {
        registered.set(options.name, tool);
      }
    },
    on(name: string, handler: BeforeToolHandler) {
      assert.equal(name, "before_tool_call");
      beforeToolCall = handler;
    },
    session: {
      workflow: {
        async enqueueNextTurnInjection() {
          return { accepted: true };
        },
      },
    },
    logger: { warn() {} },
  } as unknown as OpenClawPluginApi;
  createMasuGateOpenClawPlugin({
    env: {
      MASUGATE_AGENT_ALPHA_TOKEN: "alpha-token",
      MASUGATE_AGENT_BETA_TOKEN: "beta-token",
      MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN: "resolver-token",
    },
    createApprovalClient(input) {
      if (input.token === "alpha-token") {
        return {
          async listPending() {
            return { items: resolverCompleted ? [] : [pending] };
          },
          async resolvePending() {
            throw new Error("action client cannot resolve a pending entitlement");
          },
        };
      }
      if (input.token === "beta-token") {
        return {
          async listPending() {
            throw new Error("cross-principal replay must not enumerate pending entitlements");
          },
          async resolvePending() {
            throw new Error("action client cannot resolve a pending entitlement");
          },
        };
      }
      return {
        async listPending() {
          throw new Error("resolver cannot enumerate pending entitlements");
        },
        async resolvePending(options) {
          resolutions.push(options);
          resolverCompleted = true;
          return terminal;
        },
      };
    },
    now: () => Date.parse(pending.created_at),
  }).register(api);

  const resumeFactory = registered.get(MASUGATE_RESUME_PENDING_TOOL);
  assert.notEqual(resumeFactory, undefined);
  assert.notEqual(beforeToolCall, undefined);
  const alphaContext: OpenClawPluginToolContext = {
    agentId: "agent-alpha",
    sessionId: "session-alpha",
    sessionKey: "agent:agent-alpha:approval",
  };
  const sameSession = buildTool(resumeFactory!, alphaContext);
  const otherGeneration = buildTool(resumeFactory!, {
    ...alphaContext,
    sessionId: "session-other",
  });
  const otherPrincipal = buildTool(resumeFactory!, {
    agentId: "agent-beta",
    sessionId: "session-beta",
    sessionKey: "agent:agent-beta:approval",
  });

  const approval = await beforeToolCall!(
    {
      toolName: MASUGATE_RESUME_PENDING_TOOL,
      params: { pending_id: pendingId },
      toolCallId: "approve-call",
    },
    alphaContext,
  ) as {
    requireApproval?: { onResolution?: (decision: "allow-once" | "deny") => Promise<void> };
  };
  await approval.requireApproval?.onResolution?.("allow-once");

  const replay = await sameSession.execute(
    "same-session-resume",
    { pending_id: pendingId },
    undefined,
    undefined,
  );
  assert.deepEqual(replay.details, terminal);
  await assert.rejects(
    otherGeneration.execute(
      "cross-generation-resume",
      { pending_id: pendingId },
      undefined,
      undefined,
    ),
    /different trusted OpenClaw session epoch/,
  );
  await assert.rejects(
    otherPrincipal.execute(
      "cross-principal-resume",
      { pending_id: pendingId },
      undefined,
      undefined,
    ),
    /different trusted OpenClaw agent/,
  );
  assert.deepEqual(resolutions, [
    {
      pendingId,
      approved: true,
      evidence: {
        agent_id: alphaContext.agentId,
        decision: "allow-once",
        pending_id: pendingId,
        session_id: alphaContext.sessionId,
        session_key: alphaContext.sessionKey,
        source: "openclaw-native-approval",
      },
    },
  ]);
});
