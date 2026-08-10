import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import type {
  ActionResult,
  AdapterCancellationEnvelope,
  AuditRecord,
  ExecuteOptions,
  PendingLookup,
  StagedArtifact,
} from "@masugate/client";

import {
  AdapterCapabilities,
  AdapterModelArgumentsError,
  assertAdapterCoreConformanceCanonicalBytes,
  ChangedInvocationConflictError,
  createAdapterCoreConformanceRuntime,
  GovernedRouteParser,
  GovernedToolRuntime,
  PendingLocatorMismatchError,
  parseAdapterCoreConformanceFixture,
  runAdapterCoreConformance,
  TrustedInvocation,
  UnsupportedAdapterCapabilityError,
} from "../src/index.js";

const fixture = JSON.parse(
  readFileSync(
    new URL("../../../../protocol/examples/adapter-core-conformance.json", import.meta.url),
    "utf8",
  ),
) as Record<string, unknown>;
const conformance = parseAdapterCoreConformanceFixture(fixture);
const v2Fixture = JSON.parse(
  readFileSync(
    new URL("../../../../protocol/examples/governed-route-manifest-v2-route-fixture.json", import.meta.url),
    "utf8",
  ),
) as Record<string, unknown>;

test("v2 route parser exposes bounded public schema without private binding", () => {
  const routes = new GovernedRouteParser(v2Fixture);
  const spec = routes.select("reference_notify");

  assert.equal(spec.arguments, undefined);
  assert.equal((spec.inputSchema as Record<string, unknown>)["type"], "object");
  assert.equal(routes.canonicalManifest.includes("credential_refs"), false);
  assert.equal(routes.canonicalManifest.includes("allowed_destinations"), false);
});

test("v2 scalar content route stages before governed action", async () => {
  const manifest = JSON.parse(JSON.stringify(v2Fixture)) as {
    routes: Array<{ input_schema: { properties: Record<string, unknown>; required: string[] }; artifact_fields: string[] }>;
  };
  const route = manifest.routes[0]!;
  route.input_schema.properties["metadata"] = { type: "string", maxLength: 128 };
  route.input_schema.properties["content"] = { type: "string", maxLength: 256 };
  route.input_schema.required.push("content");
  route.artifact_fields = ["content"];
  const client = new FakeLifecycleClient();
  const runtime = new GovernedToolRuntime(
    client,
    new GovernedRouteParser(manifest),
    new TrustedInvocation({
      principalId: "adapter:buyer",
      sourceNamespace: "adapter-test",
      sourceId: "content-call-1",
      adapter: new AdapterCapabilities("masugate.adapter.test", []),
    }),
  );

  await runtime.invoke("reference_notify", {
    recipient: "buyer@example.test",
    subject: "hello",
    metadata: "plain",
    content: "body",
  });

  assert.equal(client.staged.length, 1);
  assert.equal(client.calls.length, 1);
  assert.equal(new TextDecoder().decode(client.staged[0]!.content), "body");
  assert.equal(client.staged[0]!.field, "content");
  assert.equal(client.staged[0]!.stableId, client.calls[0]!.stableId);
  assert.equal(client.staged[0]!.adapterInvocation, client.calls[0]!.adapterInvocation);
});

test("v2 string bounds count Unicode code points and reject lone surrogates", async () => {
  const manifest = JSON.parse(JSON.stringify(v2Fixture)) as {
    routes: Array<{ input_schema: { properties: Record<string, unknown> } }>;
  };
  const route = manifest.routes[0]!;
  route.input_schema.properties["subject"] = { type: "string", minLength: 1, maxLength: 1 };
  route.input_schema.properties["metadata"] = { type: "string", maxLength: 128 };
  const client = new FakeLifecycleClient();
  const runtime = new GovernedToolRuntime(
    client,
    new GovernedRouteParser(manifest),
    new TrustedInvocation({
      principalId: "adapter:buyer",
      sourceNamespace: "adapter-test",
      sourceId: "unicode-call-1",
      adapter: new AdapterCapabilities("masugate.adapter.test", []),
    }),
  );

  await runtime.invoke("reference_notify", {
    recipient: "buyer@example.test",
    subject: "😀",
    metadata: "plain",
  });
  await assert.rejects(
    runtime.invoke("reference_notify", {
      recipient: "buyer@example.test",
      subject: "ab",
      metadata: "plain",
    }),
    AdapterModelArgumentsError,
  );
  await assert.rejects(
    runtime.invoke("reference_notify", {
      recipient: "buyer@example.test",
      subject: "\ud800",
      metadata: "plain",
    }),
    AdapterModelArgumentsError,
  );
});

test("v2 nested route is closed before any staging", async () => {
  const client = new FakeLifecycleClient();
  const runtime = new GovernedToolRuntime(
    client,
    new GovernedRouteParser(v2Fixture),
    new TrustedInvocation({
      principalId: "adapter:buyer",
      sourceNamespace: "adapter-test",
      sourceId: "nested-call-1",
      adapter: new AdapterCapabilities("masugate.adapter.test", []),
    }),
  );

  await assert.rejects(
    runtime.invoke("reference_notify", {
      recipient: "buyer@example.test",
      subject: "hello",
      metadata: { labels: [] },
    }),
    AdapterModelArgumentsError,
  );
  assert.equal(client.staged.length, 0);
  assert.equal(client.calls.length, 0);
});

function result(
  status: ActionResult["status"],
  operationId: string,
  replayed = false,
): ActionResult {
  const base = {
    operation_id: operationId,
    status,
    payload: { status },
    audit_ref: `/v1/audit/${operationId}`,
    replayed,
  };
  if (status === "committed") {
    return {
      ...base,
      status,
      decision: {
        effect: "allow", policy_id: "adapter-core-test", policy_version: "v1",
        rule_id: "test-rule", reason: "adapter core test result",
      },
    };
  }
  if (status === "denied") {
    return {
      ...base,
      status,
      decision: {
        effect: "deny", policy_id: "adapter-core-test", policy_version: "v1",
        rule_id: "test-rule", reason: "adapter core test result",
      },
    };
  }
  if (status === "pending") {
    return {
      ...base,
      status,
      pending_id: "11111111-1111-4111-8111-111111111111",
      decision: {
        effect: "escalate", policy_id: "adapter-core-test", policy_version: "v1",
        rule_id: "test-rule", reason: "adapter core test result",
      },
    };
  }
  return { ...base, status, decision: null };
}

class FakeLifecycleClient {
  status: ActionResult["status"];
  readonly calls: ExecuteOptions[] = [];
  readonly results = new Map<string, ActionResult>();
  readonly bindings = new Map<string, string>();
  readonly pendingOperations = new Map<string, string>();
  readonly pendingReads: string[] = [];
  readonly staged: Array<{
    action: string;
    field: string;
    content: Uint8Array;
    stableId: string;
    adapterInvocation: string;
  }> = [];

  constructor(status: ActionResult["status"] = "committed") {
    this.status = status;
  }

  async execute(options: ExecuteOptions): Promise<ActionResult> {
    const binding = JSON.stringify({
      action: options.action,
      args: options.args,
      owner: options.owner,
      adapterInvocation: options.adapterInvocation,
    });
    const previousBinding = this.bindings.get(options.stableId);
    if (previousBinding !== undefined && previousBinding !== binding) {
      throw new ChangedInvocationConflictError(
        "trusted source invocation is already bound to different canonical content",
      );
    }
    this.bindings.set(options.stableId, binding);
    const prior = this.results.get(options.stableId);
    this.calls.push(options);
    if (prior !== undefined) return { ...prior, replayed: true } as ActionResult;
    const operationId = `00000000-0000-4000-8000-${String(this.results.size + 1).padStart(12, "0")}`;
    const next = result(this.status, operationId);
    this.results.set(options.stableId, next);
    if (next.status === "pending") this.pendingOperations.set(next.pending_id, next.operation_id);
    return next;
  }

  async stageArtifact(options: {
    action: string;
    field: string;
    content: Uint8Array;
    mediaType: string;
    stableId: string;
    adapterInvocation: string;
    signal?: AbortSignal;
  }): Promise<StagedArtifact> {
    this.staged.push(options);
    return {
      reference: "art:fixture",
      content_digest: "a".repeat(64),
      content_bytes: options.content.byteLength,
      media_type: options.mediaType,
      classification: "reference-text",
      expires_at: "2026-07-26T12:00:00Z",
    };
  }

  async getPending(pendingId: string): Promise<PendingLookup> {
    this.pendingReads.push(pendingId);
    const operationId = this.pendingOperations.get(pendingId);
    if (operationId === undefined) throw new Error("unknown pending test operation");
    return {
      kind: "pending",
      pending: {
        pending_id: pendingId,
        operation_id: operationId,
        principal_id: "adapter:buyer",
        action: "spend.purchase",
        args: { amount_cents: 1250, merchant_id: "merchant-42" },
        created_at: "2026-07-25T00:00:00Z",
        decision: {
          effect: "escalate", policy_id: "adapter-core-test", policy_version: "v1",
          rule_id: "test-rule", reason: "adapter core test result",
        },
        audit_ref: `/v1/audit/${operationId}`,
      },
    };
  }

  async cancelPending(options: { pendingId: string }): Promise<AdapterCancellationEnvelope> {
    const operationId = this.pendingOperations.get(options.pendingId);
    if (operationId === undefined) throw new Error("unknown pending test operation");
    return {
      kind: "cancellation",
      locator: {
        operation_id: operationId,
        pending_id: options.pendingId,
      },
      accepted: true,
    };
  }

  async getAudit(operationId: string): Promise<AuditRecord> {
    return { operation_id: operationId } as AuditRecord;
  }
}

class TerminalMismatchClient extends FakeLifecycleClient {
  override async getPending(pendingId: string): Promise<PendingLookup> {
    this.pendingReads.push(pendingId);
    const terminal = result("committed", "22222222-2222-4222-8222-222222222222");
    if (terminal.status !== "committed") throw new Error("expected committed terminal");
    return { kind: "terminal", result: terminal };
  }
}

class TerminalSameOperationClient extends FakeLifecycleClient {
  override async getPending(pendingId: string): Promise<PendingLookup> {
    this.pendingReads.push(pendingId);
    const operationId = this.pendingOperations.get(pendingId);
    if (operationId === undefined) throw new Error("unknown pending test operation");
    const terminal = result("committed", operationId);
    if (terminal.status !== "committed") throw new Error("expected committed terminal");
    return { kind: "terminal", result: terminal };
  }
}

class LocatorMismatchClient extends FakeLifecycleClient {
  readonly otherOperation = "22222222-2222-4222-8222-222222222222";

  override async getPending(pendingId: string): Promise<PendingLookup> {
    this.pendingReads.push(pendingId);
    return {
      kind: "pending",
      pending: {
        pending_id: pendingId,
        operation_id: this.otherOperation,
        principal_id: "adapter:buyer",
        action: "spend.purchase",
        args: { amount_cents: 1250, merchant_id: "merchant-42" },
        created_at: "2026-07-25T00:00:00Z",
        decision: {
          effect: "escalate", policy_id: "adapter-core-test", policy_version: "v1",
          rule_id: "test-rule", reason: "adapter core test result",
        },
        audit_ref: `/v1/audit/${this.otherOperation}`,
      },
    };
  }

  override async cancelPending(options: { pendingId: string }): Promise<AdapterCancellationEnvelope> {
    return {
      kind: "cancellation",
      locator: { operation_id: this.otherOperation, pending_id: options.pendingId },
      accepted: true,
    };
  }

  override async getAudit(_operationId: string): Promise<AuditRecord> {
    return { operation_id: this.otherOperation } as AuditRecord;
  }
}

class ScenarioClientFactory {
  readonly clients = new Map<string, FakeLifecycleClient>();

  get(scenario: string): FakeLifecycleClient {
    const existing = this.clients.get(scenario);
    if (existing !== undefined) return existing;
    let client: FakeLifecycleClient;
    if (scenario === "pending-terminal") {
      client = new TerminalSameOperationClient("pending");
    } else if (scenario === "locator-checks") {
      client = new LocatorMismatchClient("pending");
    } else if (scenario.startsWith("lifecycle-")) {
      client = new FakeLifecycleClient(
        scenario.slice("lifecycle-".length) as ActionResult["status"],
      );
    } else if (scenario === "pending-resume") {
      client = new FakeLifecycleClient("pending");
    } else {
      client = new FakeLifecycleClient();
    }
    this.clients.set(scenario, client);
    return client;
  }
}

function runtime(client: FakeLifecycleClient, sourceId = "call-001"): GovernedToolRuntime {
  return createAdapterCoreConformanceRuntime(
    client,
    conformance,
    { sourceId },
  );
}

test("shared fixture canonicalizes route and trusted invocation", () => {
  const core = runtime(new FakeLifecycleClient());

  assert.equal(
    readFileSync(new URL("../../src/adapter-core-conformance.json", import.meta.url), "utf8"),
    readFileSync(
      new URL("../../../../protocol/examples/adapter-core-conformance.json", import.meta.url),
      "utf8",
    ),
  );
  assertAdapterCoreConformanceCanonicalBytes(core, conformance);
});

for (const forged of ["principal_id", "owner", "locator", "pending_id"]) {
  test(`model arguments cannot forge ${forged}`, async () => {
    const client = new FakeLifecycleClient();
    const arguments_ = { ...(fixture["model_arguments"] as Record<string, unknown>), [forged]: "model" };

    await assert.rejects(runtime(client).invoke("purchase", arguments_), AdapterModelArgumentsError);
    assert.equal(client.calls.length, 0);
  });
}

for (const value of ["1250", 1.5, Number.MAX_SAFE_INTEGER + 1]) {
  test(`model integer arguments reject ${String(value)}`, async () => {
    const client = new FakeLifecycleClient();
    const arguments_ = { ...(fixture["model_arguments"] as Record<string, unknown>), amount_cents: value };

    await assert.rejects(runtime(client).invoke("purchase", arguments_), AdapterModelArgumentsError);
    assert.equal(client.calls.length, 0);
  });
}

test("model arguments must be an object", async () => {
  const client = new FakeLifecycleClient();

  await assert.rejects(runtime(client).invoke("purchase", ["not", "arguments"]), AdapterModelArgumentsError);
  assert.equal(client.calls.length, 0);
});

test("empty capability list remains schema-valid", () => {
  assert.deepEqual(new AdapterCapabilities("masugate.adapter.submit-only", []).capabilities, []);
});

test("retry reuses one operation and changed content conflicts", async () => {
  const client = new FakeLifecycleClient();
  const core = runtime(client);
  const arguments_ = fixture["model_arguments"] as Record<string, unknown>;

  const first = await core.invoke("purchase", arguments_);
  const replay = await core.invoke("purchase", arguments_);

  assert.equal(first.result.operation_id, replay.result.operation_id);
  assert.equal(replay.result.replayed, true);
  assert.equal(client.results.size, 1);
  assert.deepEqual(client.calls[0]?.owner, {
    providerId: "spend-v1", position: "protected-external", connectorId: "purchase-v1",
  });
  assert.equal(client.calls[0]?.expectedPrincipal, "adapter:buyer");
  assert.equal(client.calls[0]?.adapterInvocation, conformance.canonicalTrustedInvocation);
  await assert.rejects(
    core.invoke("purchase", { ...arguments_, amount_cents: 1251 }),
    ChangedInvocationConflictError,
  );
  assert.equal(client.calls.length, 2);
  await assert.rejects(
    runtime(client).invoke("purchase", { ...arguments_, amount_cents: 1251 }),
    ChangedInvocationConflictError,
  );
  assert.equal(client.calls.length, 2);
});

test("host-derived replay and trace identities survive shared-core invocation", async () => {
  const client = new FakeLifecycleClient();
  const invocation = new TrustedInvocation({
    principalId: "openclaw:agent-alpha",
    sourceNamespace: "openclaw",
    sourceId: "openclaw:v2:trusted-call",
    stableId: "openclaw:v2:trusted-call",
    traceId: "openclaw:v2:trace:trusted-call",
    adapter: new AdapterCapabilities("masugate.openclaw", ["locator", "pending-presentation"]),
  });
  const core = new GovernedToolRuntime(
    client,
    runtime(client).routes,
    invocation,
  );

  await core.invoke("purchase", fixture["model_arguments"]);

  assert.equal(client.calls[0]?.stableId, "openclaw:v2:trusted-call");
  assert.equal(client.calls[0]?.traceId, "openclaw:v2:trace:trusted-call");
  assert.equal(client.calls[0]?.expectedPrincipal, "openclaw:agent-alpha");
});

test("published conformance runner reports the shared scenarios", async () => {
  const factory = new ScenarioClientFactory();
  const report = await runAdapterCoreConformance((scenario) => factory.get(scenario), conformance);

  assert.equal(report.conformanceVersion, "masugate.adapter-core-conformance.v1");
  assert.deepEqual(
    report.passedCaseIds,
    (fixture["scenarios"] as { id: string }[]).map((scenario) => scenario.id),
  );
});

test("distinct trusted calls with identical arguments remain distinct", async () => {
  const client = new FakeLifecycleClient();
  const arguments_ = fixture["model_arguments"] as Record<string, unknown>;

  const first = await runtime(client, "call-001").invoke("purchase", arguments_);
  const second = await runtime(client, "call-002").invoke("purchase", arguments_);

  assert.notEqual(first.result.operation_id, second.result.operation_id);
  assert.deepEqual(client.calls.map((call) => call.stableId).sort(), [
    'adapter-core:v1:["adapter:buyer","adapter-core-conformance","call-001"]',
    'adapter-core:v1:["adapter:buyer","adapter-core-conformance","call-002"]',
  ]);
});

for (const status of ["committed", "denied", "pending", "in_progress", "outcome_unknown"] as const) {
  test(`${status} remains a replacement-only lifecycle`, async () => {
    const presentation = await runtime(new FakeLifecycleClient(status)).invoke(
      "purchase",
      fixture["model_arguments"],
    );
    assert.equal(presentation.status, status);
    assert.equal(presentation.nativeEffectPermitted, false);
    assert.equal(presentation.retryAsNewAction, false);
  });
}

test("pending resume reads the same locator without a new action", async () => {
  const client = new FakeLifecycleClient("pending");
  const core = runtime(client);
  const pending = await core.invoke("purchase", fixture["model_arguments"]);
  if (pending.result.status !== "pending") throw new Error("expected pending result");

  await assert.rejects(core.resumePending(pending.result.pending_id), PendingLocatorMismatchError);
  assert.deepEqual(client.pendingReads, []);

  const resumed = await core.resumePending(pending.locator);

  assert.equal(resumed.status, "pending");
  if (!("pendingId" in resumed)) throw new Error("expected pending presentation");
  assert.equal(resumed.pendingId, pending.result.pending_id);
  assert.deepEqual(client.pendingReads, [pending.result.pending_id]);
  assert.equal(client.calls.length, 1);
});

test("pending resume rejects a different operation", async () => {
  const client = new FakeLifecycleClient("pending");
  const core = runtime(client);
  const pending = await core.invoke("purchase", fixture["model_arguments"]);
  if (pending.result.status !== "pending") throw new Error("expected pending result");
  client.pendingOperations.set(
    pending.result.pending_id,
    "22222222-2222-4222-8222-222222222222",
  );

  await assert.rejects(core.resumePending(pending.locator), PendingLocatorMismatchError);
  assert.deepEqual(client.pendingReads, [pending.result.pending_id]);
  assert.equal(client.calls.length, 1);
});

test("pending resume rejects a terminal result for a different operation", async () => {
  const client = new TerminalMismatchClient("pending");
  const core = runtime(client);
  const pending = await core.invoke("purchase", fixture["model_arguments"]);

  await assert.rejects(core.resumePending(pending.locator), PendingLocatorMismatchError);
  assert.equal(client.calls.length, 1);
});

test("cancel and receipt require complete locators and bind the operation", async () => {
  const client = new FakeLifecycleClient("pending");
  const core = runtime(client);
  const pending = await core.invoke("purchase", fixture["model_arguments"]);
  if (pending.result.status !== "pending") throw new Error("expected pending result");

  await assert.rejects(core.cancelPending(pending.result.pending_id), PendingLocatorMismatchError);
  await assert.rejects(core.getReceipt(pending.result.operation_id), PendingLocatorMismatchError);

  const cancellation = await core.cancelPending(pending.locator);
  const receipt = await core.getReceipt(pending.locator);

  assert.deepEqual(cancellation.locator, pending.locator);
  assert.equal(receipt.operation_id, pending.result.operation_id);
});

test("control-plane capabilities are hard gates", async () => {
  const client = new FakeLifecycleClient("pending");
  const baseline = runtime(client);
  const core = new GovernedToolRuntime(
    client,
    baseline.routes,
    new TrustedInvocation({
      principalId: "adapter:buyer",
      sourceNamespace: "adapter-core-conformance",
      sourceId: "call-001",
      adapter: new AdapterCapabilities("masugate.adapter.submit-only", []),
    }),
  );
  const pending = await baseline.invoke("purchase", fixture["model_arguments"]);

  await assert.rejects(core.resumePending(pending.locator), UnsupportedAdapterCapabilityError);
  await assert.rejects(core.cancelPending(pending.locator), UnsupportedAdapterCapabilityError);
  await assert.rejects(core.getReceipt(pending.locator), UnsupportedAdapterCapabilityError);
});

test("core source remains independent of framework host imports", () => {
  const source = readFileSync(new URL("../../src/index.ts", import.meta.url), "utf8");
  for (const host of [
    "openclaw", "langchain", "langgraph", "crewai", "agent-framework",
    "agentframework", "microsoft-agent-framework", "@microsoft/agents",
    "microsoft",
  ]) {
    assert.equal(source.includes(`from \"${host}`), false);
    assert.equal(source.includes(`from '${host}`), false);
  }
});
