import assert from "node:assert/strict";
import test from "node:test";

import type {
  PendingOperation,
  ResolvedActionResult,
} from "@masugate/client";

import {
  NativeApprovalBridge,
  type MasuGateApprovalClientFactory,
} from "../src/approval.js";
import type { MasuGateOpenClawConfig } from "../src/config.js";

const createdAt = "2026-07-17T00:00:00.000Z";
const pendingId = "11111111-1111-4111-8111-111111111111";

const config: MasuGateOpenClawConfig = {
  masugatedBaseUrl: "https://masugated.internal",
  agents: { "buyer-alpha": "MASUGATE_BUYER_ALPHA_TOKEN" },
  nativeApproval: {
    resolverTokenEnv: "MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN",
    timeoutMs: 600_000,
  },
  routes: {
    purchase: {
      action: "spend.purchase",
      arguments: {
        amount_cents: "integer",
        merchant_id: "string",
        request_ref: "string",
      },
      owner: {
        providerId: "masugate.spend.reference",
        position: "protected-external",
        connectorId: "reference-purchase-v1",
      },
    },
  },
};

function pending(): PendingOperation {
  return {
    pending_id: pendingId,
    operation_id: "22222222-2222-4222-8222-222222222222",
    principal_id: "openclaw:buyer-alpha",
    action: "spend.purchase",
    args: {
      amount_cents: 600,
      merchant_id: "office-supply",
      request_ref: "approval-1",
    },
    created_at: createdAt,
    decision: {
      effect: "escalate",
      policy_id: "spend_budget_guard",
      policy_version: "1.0.0",
      rule_id: "ask_first.pending",
      reason: "approval required",
    },
    audit_ref: "/v1/audit/22222222-2222-4222-8222-222222222222",
  };
}

function committed(): ResolvedActionResult {
  return {
    operation_id: "22222222-2222-4222-8222-222222222222",
    status: "committed",
    decision: {
      effect: "allow",
      policy_id: "spend_budget_guard",
      policy_version: "1.0.0",
      rule_id: "approval.approved",
      reason: "committed",
    },
    payload: { receipt: "purchase-1" },
    audit_ref: "/v1/audit/22222222-2222-4222-8222-222222222222",
    replayed: false,
  };
}

function inProgress(): ResolvedActionResult {
  return {
    operation_id: "22222222-2222-4222-8222-222222222222",
    status: "in_progress",
    decision: null,
    payload: { recovery: "waiting-for-protected-runner" },
    audit_ref: "/v1/audit/22222222-2222-4222-8222-222222222222",
    replayed: false,
  };
}

test("native approval resolves only the exact durable pending locator once", async () => {
  const clientInputs: Array<{ baseUrl: string; token: string; principalId?: string }> = [];
  const resolutions: unknown[] = [];
  const factory: MasuGateApprovalClientFactory = (input) => {
    clientInputs.push(input);
    if (input.token === "buyer-token") {
      return {
        async listPending() {
          return { items: [pending()] };
        },
        async resolvePending() {
          throw new Error("action client must not resolve approval");
        },
      };
    }
    return {
      async listPending() {
        throw new Error("resolver must not enumerate another agent's approvals");
      },
      async resolvePending(options) {
        resolutions.push(options);
        return committed();
      },
    };
  };
  const bridge = new NativeApprovalBridge({
    config,
    environment: {
      MASUGATE_BUYER_ALPHA_TOKEN: "buyer-token",
      MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN: "operator-token",
    },
    createClient: factory,
    now: () => Date.parse(createdAt),
  });

  const prepared = await bridge.prepare({
    pendingId,
    agentId: "buyer-alpha",
    sessionKey: "agent:buyer-alpha:main",
    sessionId: "session-main",
  });
  assert.equal(prepared.expired, false);
  assert.equal(prepared.approval!.expiresAt, Date.parse(createdAt) + 600_000);

  const first = await bridge.resolve(prepared.approval!, "allow-once");
  const replay = await bridge.resolve(prepared.approval!, "allow-once");
  assert.deepEqual(replay, first);
  assert.deepEqual(resolutions, [
    {
      pendingId,
      approved: true,
      evidence: {
        agent_id: "buyer-alpha",
        decision: "allow-once",
        pending_id: pendingId,
        session_id: "session-main",
        session_key: "agent:buyer-alpha:main",
        source: "openclaw-native-approval",
      },
    },
  ]);
  assert.deepEqual(clientInputs, [
    {
      baseUrl: "https://masugated.internal",
      token: "buyer-token",
      principalId: "openclaw:buyer-alpha",
    },
    { baseUrl: "https://masugated.internal", token: "operator-token" },
  ]);
  assert.throws(
    () => bridge.resolve(prepared.approval!, "deny"),
    /conflicting resolutions/,
  );
});

test("non-human native timeout and cancellation never create a MasuGate human resolution", async () => {
  const resolutions: unknown[] = [];
  const factory: MasuGateApprovalClientFactory = (input) => ({
    async listPending() {
      assert.equal(input.token, "buyer-token");
      return { items: [pending()] };
    },
    async resolvePending(options) {
      resolutions.push(options);
      return committed();
    },
  });
  const bridge = new NativeApprovalBridge({
    config,
    environment: {
      MASUGATE_BUYER_ALPHA_TOKEN: "buyer-token",
      MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN: "operator-token",
    },
    createClient: factory,
    now: () => Date.parse(createdAt) + 600_000,
  });

  const prepared = await bridge.prepare({
    pendingId,
    agentId: "buyer-alpha",
    sessionKey: "agent:buyer-alpha:main",
    sessionId: "session-main",
  });
  assert.equal(prepared.expired, true);
  assert.throws(
    () => bridge.resolve(prepared.approval!, "timeout" as never),
    /only an explicit native allow-once or deny/,
  );
  assert.throws(
    () => bridge.resolve(prepared.approval!, "cancelled" as never),
    /only an explicit native allow-once or deny/,
  );
  assert.deepEqual(resolutions, []);
  await assert.rejects(
    bridge.prepare({
      pendingId,
      agentId: "buyer-alpha",
      sessionKey: "agent:buyer-alpha:other",
      sessionId: "session-other",
    }),
    /different trusted OpenClaw session/,
  );
});

test("concurrent first presentations linearize one trusted session binding", async () => {
  let listCalls = 0;
  let markFirstListed: (() => void) | undefined;
  let releaseListing: (() => void) | undefined;
  const firstListed = new Promise<void>((resolve) => {
    markFirstListed = resolve;
  });
  const listingGate = new Promise<void>((resolve) => {
    releaseListing = resolve;
  });
  const factory: MasuGateApprovalClientFactory = (input) => ({
    async listPending() {
      assert.equal(input.token, "buyer-token");
      listCalls += 1;
      markFirstListed?.();
      await listingGate;
      return { items: [pending()] };
    },
    async resolvePending() {
      return committed();
    },
  });
  const bridge = new NativeApprovalBridge({
    config,
    environment: {
      MASUGATE_BUYER_ALPHA_TOKEN: "buyer-token",
      MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN: "operator-token",
    },
    createClient: factory,
    now: () => Date.parse(createdAt),
  });

  const first = bridge.prepare({
    pendingId,
    agentId: "buyer-alpha",
    sessionKey: "agent:buyer-alpha:main",
    sessionId: "session-main",
  });
  await firstListed;
  const contender = bridge.prepare({
    pendingId,
    agentId: "buyer-alpha",
    sessionKey: "agent:buyer-alpha:other",
    sessionId: "session-other",
  });
  releaseListing?.();

  await assert.rejects(contender, /different trusted OpenClaw session/);
  const prepared = await first;
  const replay = await bridge.prepare({
    pendingId,
    agentId: "buyer-alpha",
    sessionKey: "agent:buyer-alpha:main",
    sessionId: "session-main",
  });
  assert.equal(listCalls, 1);
  assert.equal(replay.approval, prepared.approval);
});

test("a transient resolver failure evicts only its failed promise", async () => {
  let resolverCalls = 0;
  const bridge = new NativeApprovalBridge({
    config,
    environment: {
      MASUGATE_BUYER_ALPHA_TOKEN: "buyer-token",
      MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN: "operator-token",
    },
    createClient(input) {
      if (input.token === "buyer-token") {
        return {
          async listPending() {
            return { items: [pending()] };
          },
          async resolvePending() {
            throw new Error("action client must not resolve approval");
          },
        };
      }
      return {
        async listPending() {
          throw new Error("resolver cannot enumerate pending entitlements");
        },
        async resolvePending() {
          resolverCalls += 1;
          if (resolverCalls === 1) {
            throw new Error("temporary resolver outage");
          }
          return committed();
        },
      };
    },
    now: () => Date.parse(createdAt),
  });
  const prepared = await bridge.prepare({
    pendingId,
    agentId: "buyer-alpha",
    sessionKey: "agent:buyer-alpha:main",
    sessionId: "session-main",
  });

  await assert.rejects(
    bridge.resolve(prepared.approval!, "allow-once"),
    /temporary resolver outage/,
  );
  await Promise.resolve();
  assert.deepEqual(await bridge.resolve(prepared.approval!, "allow-once"), committed());
  assert.equal(resolverCalls, 2);
  assert.throws(
    () => bridge.resolve(prepared.approval!, "deny"),
    /conflicting resolutions/,
  );
});

test("a nonterminal recovery snapshot is not cached as a native terminal replay", async () => {
  let resolverCalls = 0;
  const bridge = new NativeApprovalBridge({
    config,
    environment: {
      MASUGATE_BUYER_ALPHA_TOKEN: "buyer-token",
      MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN: "operator-token",
    },
    createClient(input) {
      if (input.token === "buyer-token") {
        return {
          async listPending() {
            return { items: [pending()] };
          },
          async resolvePending() {
            throw new Error("action client must not resolve approval");
          },
        };
      }
      return {
        async listPending() {
          throw new Error("resolver cannot enumerate pending entitlements");
        },
        async resolvePending() {
          resolverCalls += 1;
          return resolverCalls === 1 ? inProgress() : committed();
        },
      };
    },
    now: () => Date.parse(createdAt),
  });
  const prepared = await bridge.prepare({
    pendingId,
    agentId: "buyer-alpha",
    sessionKey: "agent:buyer-alpha:main",
    sessionId: "session-main",
  });

  assert.equal((await bridge.resolve(prepared.approval!, "allow-once")).status, "in_progress");
  await Promise.resolve();
  assert.equal(bridge.resolution(pendingId), undefined);
  assert.equal((await bridge.resolve(prepared.approval!, "allow-once")).status, "committed");
  assert.equal(resolverCalls, 2);
});

test("a prepared presentation rehydrates an audited native choice after MasuGate recovery", async () => {
  let auditReady = false;
  let resolverCalls = 0;
  const bridge = new NativeApprovalBridge({
    config,
    environment: {
      MASUGATE_BUYER_ALPHA_TOKEN: "buyer-token",
      MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN: "operator-token",
    },
    createClient(input) {
      if (input.token === "buyer-token") {
        return {
          async listPending() {
            return { items: [pending()] };
          },
          async getAudit() {
            return (auditReady
              ? {
                  human_resolution: {
                    approved: true,
                    evidence: {
                      agent_id: "buyer-alpha",
                      decision: "allow-once",
                      pending_id: pendingId,
                      session_id: "session-main",
                      session_key: "agent:buyer-alpha:main",
                      source: "openclaw-native-approval",
                    },
                  },
                }
              : {}) as never;
          },
          async resolvePending() {
            throw new Error("action client must not resolve approval");
          },
        };
      }
      return {
        async listPending() {
          throw new Error("resolver cannot enumerate pending entitlements");
        },
        async resolvePending() {
          resolverCalls += 1;
          return committed();
        },
      };
    },
    now: () => Date.parse(createdAt),
  });
  const first = await bridge.prepare({
    pendingId,
    agentId: "buyer-alpha",
    sessionKey: "agent:buyer-alpha:main",
    sessionId: "session-main",
  });
  assert.equal(bridge.selectedDecision(pendingId), undefined);
  auditReady = true;
  const replay = await bridge.prepare({
    pendingId,
    agentId: "buyer-alpha",
    sessionKey: "agent:buyer-alpha:main",
    sessionId: "session-main",
  });
  assert.equal(replay.approval, first.approval);
  assert.equal(bridge.selectedDecision(pendingId), "allow-once");
  assert.deepEqual(await bridge.resolve(first.approval!, "allow-once"), committed());
  assert.equal(resolverCalls, 1);
});
