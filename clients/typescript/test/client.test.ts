import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";

import {
  MasuGateClient,
  MasuGateProtocolError,
  deriveIdempotencyKey,
  type ActionArguments,
  type JsonObject,
  type JsonValue,
} from "../src/index.js";

const operationId = "11111111-1111-4111-8111-111111111111";
const pendingId = "22222222-2222-4222-8222-222222222222";
const certificateDigest = "0123456789abcdef".repeat(4);
const entitlementDigest = "fedcba9876543210".repeat(4);

test("deriveIdempotencyKey matches the cross-SDK UTF-8 SHA-256 vector", async () => {
  assert.equal(
    await deriveIdempotencyKey("logical-op:α"),
    "masugate:v1:f4b1fb6e236d6320ade3ef38048d7d0cbab7cd924be48fa3058722ec67a5a6af",
  );
});

test("execute commits and an exact stable-id retry reuses one idempotency key", async () => {
  const bodies: JsonObject[] = [];
  let effects = 0;
  const server = await startServer(async (request, response) => {
    assert.equal(request.method, "POST");
    assert.equal(request.url, "/v1/actions");
    assert.equal(request.headers.authorization, "Bearer test-token");
    assert.equal(request.headers["masugate-expected-principal"], "openclaw:agent-alpha");
    assert.equal(request.headers["masugate-expected-provider"], "spend-v1");
    assert.equal(request.headers["masugate-expected-position"], "protected-external");
    assert.equal(request.headers["masugate-expected-connector"], "purchase-v1");
    const body = await readJsonObject(request);
    bodies.push(body);
    if (bodies.length === 1) {
      effects += 1;
    }
    sendJson(response, 200, committedResponse(bodies.length > 1));
  });

  try {
    const client = new MasuGateClient({
      baseUrl: server.baseUrl,
      token: "test-token",
      principalId: "openclaw:agent-alpha",
    });
    const request = {
      action: "transfer",
      args: { receiver_id: "merchant", amount_cents: 2500 },
      stableId: "workflow-7:transfer-1",
      owner: {
        providerId: "spend-v1",
        position: "protected-external" as const,
        connectorId: "purchase-v1",
      },
      traceId: "trace-7",
    };
    const first = await client.execute<{ receipt: string }>(request);
    const retried = await client.execute<{ receipt: string }>(request);

    assert.equal(first.status, "committed");
    assert.equal(first.payload.receipt, "posted-once");
    assert.equal(first.replayed, false);
    assert.equal(retried.replayed, true);
    assert.equal(effects, 1);
    assert.equal(bodies.length, 2);
    assert.equal(
      bodies[0]?.["idempotency_key"],
      await deriveIdempotencyKey("workflow-7:transfer-1"),
    );
    assert.equal(bodies[0]?.["idempotency_key"], bodies[1]?.["idempotency_key"]);
    assert.deepEqual(bodies[0]?.["args"], request.args);
    assert.equal(bodies[0]?.["trace_id"], "trace-7");
    assert.equal("principal_ref" in (bodies[0] ?? {}), false);

    const invalidArguments: unknown[] = [
      { bad: null },
      { bad: { nested: true } },
      { bad: [1] },
      { bad: 1.5 },
      { bad: Number.MAX_SAFE_INTEGER + 1 },
      { bad: Number.POSITIVE_INFINITY },
    ];
    for (const [index, invalid] of invalidArguments.entries()) {
      await assert.rejects(
        client.execute({
          action: "transfer",
          args: invalid as ActionArguments,
          stableId: `invalid-${index}`,
        }),
        { name: "TypeError" },
      );
    }
    assert.equal(bodies.length, 2, "invalid arguments must fail before fetch");
  } finally {
    await server.close();
  }
});

test("resolvePending submits approval evidence and returns the terminal result", async () => {
  let receivedPath = "";
  let receivedBody: JsonObject = {};
  let requests = 0;
  const server = await startServer(async (request, response) => {
    requests += 1;
    receivedPath = request.url ?? "";
    receivedBody = await readJsonObject(request);
    sendJson(response, 200, requests === 1 ? committedResponse(false) : pendingResponse());
  });

  try {
    const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
    const result = await client.resolvePending<{ receipt: string }>({
      pendingId,
      approved: true,
      evidence: { reviewer: "finance", ticket: "FIN-1832" },
    });

    assert.equal(receivedPath, `/v1/pending/${pendingId}/resolve`);
    assert.deepEqual(receivedBody, {
      approved: true,
      evidence: { reviewer: "finance", ticket: "FIN-1832" },
    });
    assert.equal(result.status, "committed");
    assert.equal(result.decision.effect, "allow");

    await assert.rejects(
      client.resolvePending({
        pendingId,
        approved: true,
      }),
      (error: unknown) =>
        error instanceof MasuGateProtocolError &&
        error.message === "pending resolution returned another human-pending result",
    );
  } finally {
    await server.close();
  }
});

test("cancelPending returns only the bounded cancellation acknowledgement", async () => {
  let receivedPath = "";
  let receivedBody: JsonObject = { unexpected: true };
  const server = await startServer(async (request, response) => {
    receivedPath = request.url ?? "";
    receivedBody = await readJsonObject(request);
    sendJson(response, 200, {
      kind: "cancellation",
      locator: { operation_id: operationId, pending_id: pendingId },
      accepted: true,
    });
  });

  try {
    const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
    const acknowledgement = await client.cancelPending({ pendingId });

    assert.equal(receivedPath, `/v1/pending/${pendingId}/cancel`);
    assert.deepEqual(receivedBody, {});
    assert.deepEqual(acknowledgement, {
      kind: "cancellation",
      locator: { operation_id: operationId, pending_id: pendingId },
      accepted: true,
    });
  } finally {
    await server.close();
  }
});

test("cancelPending rejects an acknowledgement for a different pending locator", async () => {
  const server = await startServer((_request, response) => {
    sendJson(response, 200, {
      kind: "cancellation",
      locator: {
        operation_id: operationId,
        pending_id: "33333333-3333-4333-8333-333333333333",
      },
      accepted: true,
    });
  });

  try {
    const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
    await assert.rejects(
      client.cancelPending({ pendingId }),
      (error: unknown) =>
        error instanceof MasuGateProtocolError &&
        error.message === "cancellation pending_id does not match the requested id",
    );
  } finally {
    await server.close();
  }
});

test("listPending returns only schema-valid durable pending locators", async () => {
  const event = pendingEvent();
  let seenPath = "";
  const server = await startServer((request, response) => {
    seenPath = request.url ?? "";
    sendJson(response, 200, {
      items: [event.pending],
      next_cursor: pendingId,
    });
  });

  try {
    const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
    const response = await client.listPending();
    assert.equal(seenPath, "/v1/pending");
    assert.deepEqual(response, {
      items: [event.pending],
      next_cursor: pendingId,
    });
  } finally {
    await server.close();
  }
});

test("legacy pending responses without resolution metadata remain readable", async () => {
  const legacy = pendingResponse();
  delete legacy["resolution_plan"];
  delete legacy["reservation_safety_certificate_digest"];
  delete legacy["reservation_entitlement_digest"];
  const server = await startServer((_request, response) => {
    sendJson(response, 200, legacy);
  });

  try {
    const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
    const pending = await client.execute({
      action: "transfer",
      args: { amount_cents: 5_000 },
      stableId: "legacy-pending",
    });
    assert.equal(pending.status, "pending");
    if (pending.status === "pending") {
      assert.equal(pending.resolution_plan, undefined);
      assert.equal(pending.reservation_safety_certificate_digest, undefined);
      assert.equal(pending.reservation_entitlement_digest, undefined);
    }
  } finally {
    await server.close();
  }
});

test("protected operational results carry no detached policy decision", async () => {
  let requests = 0;
  const server = await startServer((_request, response) => {
    requests += 1;
    sendJson(
      response,
      200,
      operationalResponse(requests === 1 ? "in_progress" : "outcome_unknown"),
    );
  });

  try {
    const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
    const executing = await client.execute({
      action: "transfer",
      args: { amount_cents: 5_000 },
      stableId: "protected-in-progress",
    });
    assert.equal(executing.status, "in_progress");
    assert.equal(executing.decision, null);

    const unknown = await client.resolvePending({ pendingId, approved: true });
    assert.equal(unknown.status, "outcome_unknown");
    assert.equal(unknown.decision, null);
  } finally {
    await server.close();
  }
});

test("pending resolution proof metadata is accepted only in complete legal shapes", async () => {
  const missingCertificate = pendingResponse();
  delete missingCertificate["reservation_safety_certificate_digest"];
  const missingEntitlement = pendingResponse();
  delete missingEntitlement["reservation_entitlement_digest"];
  const planlessCertificate = pendingResponse();
  delete planlessCertificate["resolution_plan"];
  delete planlessCertificate["reservation_entitlement_digest"];
  const planlessEntitlement = pendingResponse();
  delete planlessEntitlement["resolution_plan"];
  delete planlessEntitlement["reservation_safety_certificate_digest"];
  const revalidationCertificate = pendingResponse();
  revalidationCertificate["resolution_plan"] = "revalidate";
  delete revalidationCertificate["reservation_entitlement_digest"];
  const revalidationEntitlement = pendingResponse();
  revalidationEntitlement["resolution_plan"] = "revalidate";
  delete revalidationEntitlement["reservation_safety_certificate_digest"];
  const malformed = [
    missingCertificate,
    missingEntitlement,
    planlessCertificate,
    planlessEntitlement,
    revalidationCertificate,
    revalidationEntitlement,
  ];
  let responseIndex = 0;
  const server = await startServer((_request, response) => {
    sendJson(response, 200, malformed[responseIndex] ?? pendingResponse());
    responseIndex += 1;
  });

  try {
    const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
    for (const index of malformed.keys()) {
      await assert.rejects(
        client.execute({
          action: "transfer",
          args: { amount_cents: 5_000 },
          stableId: `malformed-pending-${index}`,
        }),
        (error: unknown) => error instanceof MasuGateProtocolError,
      );
    }
  } finally {
    await server.close();
  }
});

test("revalidation pending metadata carries neither reservation proof digest", async () => {
  const revalidation = pendingResponse();
  revalidation["resolution_plan"] = "revalidate";
  delete revalidation["reservation_safety_certificate_digest"];
  delete revalidation["reservation_entitlement_digest"];
  const server = await startServer((_request, response) => {
    sendJson(response, 200, revalidation);
  });

  try {
    const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
    const pending = await client.execute({
      action: "transfer",
      args: { amount_cents: 5_000 },
      stableId: "revalidation-pending",
    });
    assert.equal(pending.status, "pending");
    if (pending.status === "pending") {
      assert.equal(pending.resolution_plan, "revalidate");
      assert.equal(pending.reservation_safety_certificate_digest, undefined);
      assert.equal(pending.reservation_entitlement_digest, undefined);
    }
  } finally {
    await server.close();
  }
});

test("getAudit returns a typed immutable governance receipt", async () => {
  const idempotencyKey = await deriveIdempotencyKey("workflow-7:transfer-1");
  const receipt = auditReceipt(idempotencyKey);
  (receipt["request"] as JsonObject)["adapter_invocation_digest"] = "d".repeat(64);
  const server = await startServer((request, response) => {
    assert.equal(request.url, `/v1/audit/${operationId}`);
    assert.equal(request.headers.authorization, "Bearer test-token");
    sendJson(response, 200, receipt);
  });

  try {
    const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
    const audit = await client.getAudit<{ receipt: string }>(operationId);

    assert.equal(audit.status, "committed");
    assert.equal(audit.request.idempotency_key, idempotencyKey);
    assert.equal(audit.request.request_time, audit.request.timestamp);
    assert.equal(audit.request.adapter_invocation_digest, "d".repeat(64));
    assert.equal(audit.authorization_evaluations[0]?.phase, "admission");
    assert.equal(
      audit.authorization_evaluations[0]?.decision.policy_provenance[0]?.bundle_id,
      "masugate.platform.safety",
    );
    assert.equal(audit.terminal_serialization?.provider_atomic, true);
    assert.equal(audit.view_reads[0]?.scope, "team-budget:research");
    assert.equal(
      audit.policy.evaluated_policy_provenance[0]?.bundle_id,
      "masugate.platform.safety",
    );
    assert.equal(audit.policy.catalog?.policy_digest, "a".repeat(64));
    assert.equal(audit.entitlement?.entitlement_id, "entitlement-7");
    assert.equal(audit.entitlement?.authorization_digest, "c".repeat(64));
    assert.equal(audit.effect.payload.receipt, "posted-once");
    assert.equal(audit.resolution_plan, "reservation-proof");
    assert.equal(audit.reservation_safety_certificate_digest, certificateDigest);
    assert.equal(audit.reservation_entitlement_digest, entitlementDigest);
    assert.equal(audit.protected_execution?.status, "succeeded");
    assert.equal(audit.protected_execution?.entitlement_state, "consumed");
    assert.equal(audit.protected_execution?.events.at(-1)?.event_type, "terminal-position-recorded");
    assert.equal(audit.human_resolution?.actor_id, "operator:alice");
    assert.equal(audit.human_resolution?.resolved_at, "2026-07-12T16:00:00Z");
    assert.deepEqual(audit.human_resolution?.evidence, { ticket: "CAB-7" });
  } finally {
    await server.close();
  }
});

test("getAudit rejects removed legacy authorization evidence", async () => {
  const idempotencyKey = await deriveIdempotencyKey("workflow-7:transfer-1");
  const receipt = auditReceipt(idempotencyKey);
  (receipt.entitlement as JsonObject)["authorization_request_digest"] = "e".repeat(64);
  const server = await startServer((_request, response) => {
    sendJson(response, 200, receipt);
  });

  try {
    const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
    await assert.rejects(
      client.getAudit<{ receipt: string }>(operationId),
      /audit response\.entitlement\.authorization_request_digest is not allowed/,
    );
  } finally {
    await server.close();
  }
});

test("getAudit distinguishes automatic approval expiry from human resolution", async () => {
  const receipt = auditReceipt(await deriveIdempotencyKey("automatic-expiry"));
  receipt["status"] = "denied";
  receipt["decision"] = {
    effect: "deny",
    rule_id: "approval.expired",
    reason: "approval deadline elapsed",
  };
  receipt["terminal_serialization"] = {
    kind: "denial-record",
    authorization_basis: "mechanism-denial",
    provider_atomic: false,
    recorded_at: "2026-07-13T12:02:00Z",
  };
  receipt["effect"] = null;
  receipt["automatic_expiry"] = {
    expires_at: "2026-07-13T12:00:00Z",
    reason: "approval-window-expired",
  };
  delete receipt["protected_execution"];
  delete receipt["human_resolution"];
  const server = await startServer((_request, response) => sendJson(response, 200, receipt));

  try {
    const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
    const audit = await client.getAudit(operationId);
    assert.equal(audit.status, "denied");
    assert.equal(audit.human_resolution, undefined);
    assert.equal(audit.automatic_expiry?.reason, "approval-window-expired");
    assert.equal(audit.automatic_expiry?.expires_at, "2026-07-13T12:00:00Z");

    delete receipt["automatic_expiry"];
    await assert.rejects(
      client.getAudit(operationId),
      (error: unknown) =>
        error instanceof MasuGateProtocolError &&
        error.message === "approval.expired requires automatic expiry evidence",
    );

    receipt["automatic_expiry"] = {
      expires_at: "2026-07-13T12:00:00Z",
      reason: "approval-window-expired",
    };
    receipt["human_resolution"] = {
      approved: false,
      actor_id: "operator:alice",
      evidence: {},
      resolved_at: "2026-07-13T12:02:00Z",
    };
    await assert.rejects(
      client.getAudit(operationId),
      (error: unknown) =>
        error instanceof MasuGateProtocolError &&
        error.message === "automatic expiry may not claim a human resolution",
    );
  } finally {
    await server.close();
  }
});

test("getAudit parses an outcome-unknown operational receipt", async () => {
  const receipt = auditReceipt(await deriveIdempotencyKey("unknown-audit"));
  receipt["status"] = "outcome_unknown";
  receipt["decision"] = null;
  receipt["terminal_serialization"] = null;
  receipt["effect"] = null;
  delete receipt["resolution_plan"];
  delete receipt["reservation_safety_certificate_digest"];
  delete receipt["reservation_entitlement_digest"];
  delete receipt["protected_execution"];
  const server = await startServer((_request, response) => sendJson(response, 200, receipt));

  try {
    const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
    const audit = await client.getAudit(operationId);
    assert.equal(audit.status, "outcome_unknown");
    assert.equal(audit.decision, null);
    assert.equal(audit.effect, null);
  } finally {
    await server.close();
  }
});

test("getAudit verifies preserved Python canonical binding bytes without reserializing them", async () => {
  const receipt = auditReceipt(await deriveIdempotencyKey("python-canonical-binding"));
  const protectedExecution = receipt["protected_execution"] as JsonObject;
  const binding = protectedExecution["binding"] as JsonObject;
  ((receipt["request"] as JsonObject)["args"] as JsonObject)["amount_cents"] = 1;
  ((receipt["effect"] as JsonObject)["args"] as JsonObject)["amount_cents"] = 1;
  (binding["arguments"] as JsonObject)["amount_cents"] = 1;
  const canonical = (protectedExecution["binding_canonical_json"] as string).replace(
    '"amount_cents":2500',
    '"amount_cents":1.0',
  );
  const digest = createHash("sha256").update(canonical, "utf8").digest("hex");
  protectedExecution["binding_canonical_json"] = canonical;
  protectedExecution["binding_digest"] = digest;
  protectedExecution["execution_id"] = `px:${digest}`;
  (protectedExecution["receipt"] as JsonObject)["idempotency_key"] = `masugate:${digest}`;
  ((protectedExecution["events"] as JsonObject[])[0]!["evidence"] as JsonObject)["binding_digest"] = digest;
  const server = await startServer((_request, response) => sendJson(response, 200, receipt));

  try {
    const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
    const audit = await client.getAudit(operationId);
    assert.equal(audit.protected_execution?.binding_digest, digest);
    assert.match(audit.protected_execution?.binding_canonical_json ?? "", /1\.0/u);
  } finally {
    await server.close();
  }
});

test("getAudit rejects protected evidence that changes external identity", async () => {
  const receipt = auditReceipt(await deriveIdempotencyKey("identity-drift-audit"));
  const protectedExecution = receipt["protected_execution"] as JsonObject;
  const connectorReceipt = protectedExecution["receipt"] as JsonObject;
  connectorReceipt["external_operation_id"] = "remote-replacement";
  const server = await startServer((_request, response) => {
    sendJson(response, 200, receipt);
  });

  try {
    const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
    await assert.rejects(
      client.getAudit(operationId),
      (error: unknown) =>
        error instanceof MasuGateProtocolError &&
        error.message.includes("changed the external-operation identity"),
    );
  } finally {
    await server.close();
  }
});

test("getAudit rejects protected evidence without a dispatch marker", async () => {
  const receipt = auditReceipt(await deriveIdempotencyKey("missing-dispatch-audit"));
  const protectedExecution = receipt["protected_execution"] as JsonObject;
  protectedExecution["dispatch_started"] = false;
  const server = await startServer((_request, response) => {
    sendJson(response, 200, receipt);
  });

  try {
    const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
    await assert.rejects(
      client.getAudit(operationId),
      (error: unknown) =>
        error instanceof MasuGateProtocolError &&
        error.message.includes("undispatched execution"),
    );
  } finally {
    await server.close();
  }
});

test("getAudit rejects contradictory protected-execution audit statuses", async () => {
  const cases: Array<{
    name: string;
    expected: string;
    mutate: (receipt: JsonObject) => void;
  }> = [
    {
      name: "committed with a failed protected execution",
      expected: "committed audit response has contradictory protected execution status",
      mutate: (receipt) => {
        const protectedExecution = receipt["protected_execution"] as JsonObject;
        const connectorReceipt = protectedExecution["receipt"] as JsonObject;
        const events = protectedExecution["events"] as JsonObject[];
        protectedExecution["status"] = "failed";
        protectedExecution["entitlement_state"] = "released";
        connectorReceipt["outcome"] = "failed";
        events.at(-1)!["to_status"] = "failed";
      },
    },
    {
      name: "denied with a succeeded protected execution",
      expected: "denied audit response has contradictory protected execution status",
      mutate: (receipt) => {
        receipt["status"] = "denied";
        (receipt["decision"] as JsonObject)["effect"] = "deny";
        receipt["effect"] = null;
        (receipt["terminal_serialization"] as JsonObject)["kind"] = "denial-record";
      },
    },
    {
      name: "pending with any protected execution receipt",
      expected: "pending audit response must not carry protected execution",
      mutate: (receipt) => {
        receipt["status"] = "pending";
        (receipt["decision"] as JsonObject)["effect"] = "escalate";
        receipt["effect"] = null;
        receipt["terminal_serialization"] = null;
      },
    },
    {
      name: "in-progress with a terminal protected execution",
      expected: "in_progress audit response requires intent or executing protected execution",
      mutate: (receipt) => {
        receipt["status"] = "in_progress";
        receipt["decision"] = null;
        receipt["effect"] = null;
      },
    },
    {
      name: "outcome-unknown with a succeeded protected execution",
      expected: "outcome_unknown audit response has contradictory protected execution status",
      mutate: (receipt) => {
        receipt["status"] = "outcome_unknown";
        receipt["decision"] = null;
        receipt["effect"] = null;
      },
    },
  ];

  for (const scenario of cases) {
    const receipt = auditReceipt(await deriveIdempotencyKey(`contradiction:${scenario.name}`));
    scenario.mutate(receipt);
    const server = await startServer((_request, response) => sendJson(response, 200, receipt));
    try {
      const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
      await assert.rejects(
        client.getAudit(operationId),
        (error: unknown) =>
          error instanceof MasuGateProtocolError && error.message.includes(scenario.expected),
      );
    } finally {
      await server.close();
    }
  }
});

test("getAudit rejects missing, contradictory, or drifted normative audit evidence", async () => {
  const cases: Array<{
    name: string;
    expected: string;
    mutate: (receipt: JsonObject) => void;
  }> = [
    {
      name: "missing authorization evaluations",
      expected: "audit response.authorization_evaluations is required",
      mutate: (receipt) => {
        delete receipt["authorization_evaluations"];
      },
    },
    {
      name: "missing terminal serialization",
      expected: "audit response.terminal_serialization is required",
      mutate: (receipt) => {
        delete receipt["terminal_serialization"];
      },
    },
    {
      name: "missing policy provenance",
      expected: "audit response.policy.evaluated_policy_provenance is required",
      mutate: (receipt) => {
        delete (receipt["policy"] as JsonObject)["evaluated_policy_provenance"];
      },
    },
    {
      name: "committed with a denial terminal record",
      expected: "committed audit response requires effect-commit terminal serialization",
      mutate: (receipt) => {
        (receipt["terminal_serialization"] as JsonObject)["kind"] = "denial-record";
      },
    },
    {
      name: "denied with an effect terminal record",
      expected: "denied audit response requires denial-record terminal serialization",
      mutate: (receipt) => {
        receipt["status"] = "denied";
        (receipt["decision"] as JsonObject)["effect"] = "deny";
        receipt["effect"] = null;
        const protectedExecution = receipt["protected_execution"] as JsonObject;
        const connectorReceipt = protectedExecution["receipt"] as JsonObject;
        const events = protectedExecution["events"] as JsonObject[];
        protectedExecution["status"] = "failed";
        protectedExecution["entitlement_state"] = "released";
        connectorReceipt["outcome"] = "failed";
        events.at(-1)!["to_status"] = "failed";
      },
    },
    {
      name: "pending with a terminal record",
      expected: "pending audit response requires null terminal serialization",
      mutate: (receipt) => {
        receipt["status"] = "pending";
        (receipt["decision"] as JsonObject)["effect"] = "escalate";
        receipt["effect"] = null;
        delete receipt["protected_execution"];
      },
    },
    {
      name: "catalog evidence disconnected from provenance",
      expected: "audit response.policy.catalog does not match evaluated policy provenance",
      mutate: (receipt) => {
        ((receipt["policy"] as JsonObject)["catalog"] as JsonObject)["policy_digest"] =
          "0".repeat(64);
      },
    },
    {
      name: "entitlement digest disconnected from protected binding",
      expected:
        "audit response.entitlement.authorization_digest does not match protected execution binding",
      mutate: (receipt) => {
        (receipt["entitlement"] as JsonObject)["authorization_digest"] = "0".repeat(64);
      },
    },
    {
      name: "entitlement identity disconnected from protected binding",
      expected: "audit response.entitlement_id does not match protected execution binding",
      mutate: (receipt) => {
        (receipt["entitlement"] as JsonObject)["entitlement_id"] = "entitlement-other";
      },
    },
    {
      name: "protected binding payload disconnected from its digest",
      expected: "audit response.protected_execution.binding_canonical_json does not match binding payload",
      mutate: (receipt) => {
        const protectedExecution = receipt["protected_execution"] as JsonObject;
        const binding = protectedExecution["binding"] as JsonObject;
        (binding["arguments"] as JsonObject)["amount_cents"] = 999;
      },
    },
    {
      name: "connector evidence disconnected from its binding digest",
      expected:
        "audit response.protected_execution.receipt idempotency key does not match binding digest",
      mutate: (receipt) => {
        const protectedExecution = receipt["protected_execution"] as JsonObject;
        (protectedExecution["receipt"] as JsonObject)["idempotency_key"] =
          "masugate:wrong-binding";
      },
    },
    {
      name: "connector evidence names a different connector",
      expected: "audit response.protected_execution.receipt connector does not match binding",
      mutate: (receipt) => {
        const protectedExecution = receipt["protected_execution"] as JsonObject;
        (protectedExecution["receipt"] as JsonObject)["connector_id"] = "other-connector";
      },
    },
    {
      name: "terminal connector receipt has no external operation",
      expected: "audit response.protected_execution.receipt terminal outcome requires an external operation id",
      mutate: (receipt) => {
        const protectedExecution = receipt["protected_execution"] as JsonObject;
        protectedExecution["external_operation_id"] = null;
        (protectedExecution["receipt"] as JsonObject)["external_operation_id"] = null;
      },
    },
    {
      name: "request principal is disconnected from protected binding",
      expected: "audit response.request principal does not match protected execution binding",
      mutate: (receipt) => {
        ((receipt["request"] as JsonObject)["principal"] as JsonObject)["id"] = "mallory";
      },
    },
    {
      name: "request action is disconnected from protected binding",
      expected: "audit response.request action does not match protected execution binding",
      mutate: (receipt) => {
        (receipt["request"] as JsonObject)["action"] = "other.transfer";
      },
    },
    {
      name: "request arguments are disconnected from protected binding",
      expected: "audit response.request args do not match protected execution binding",
      mutate: (receipt) => {
        ((receipt["request"] as JsonObject)["args"] as JsonObject)["amount_cents"] = 99;
      },
    },
    {
      name: "request idempotency is disconnected from protected binding",
      expected: "audit response.request idempotency key does not match protected execution binding",
      mutate: (receipt) => {
        (receipt["request"] as JsonObject)["idempotency_key"] = "different-request";
      },
    },
    {
      name: "effect is disconnected from protected binding",
      expected: "audit response.effect does not match protected execution binding",
      mutate: (receipt) => {
        (receipt["effect"] as JsonObject)["action"] = "other.transfer";
      },
    },
    {
      name: "policy provenance is disconnected from protected binding",
      expected: "audit response.policy provenance does not match protected execution binding",
      mutate: (receipt) => {
        (((receipt["policy"] as JsonObject)["evaluated_policy_provenance"] as JsonObject[])[0]!)
          ["policy_declared_version"] = "2.0.0";
      },
    },
  ];

  for (const scenario of cases) {
    const receipt = auditReceipt(await deriveIdempotencyKey(`normative:${scenario.name}`));
    scenario.mutate(receipt);
    const server = await startServer((_request, response) => sendJson(response, 200, receipt));
    try {
      const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
      await assert.rejects(
        client.getAudit(operationId),
        (error: unknown) =>
          error instanceof MasuGateProtocolError && error.message.includes(scenario.expected),
      );
    } finally {
      await server.close();
    }
  }
});

test("getAudit rejects a valid receipt for a different operation", async () => {
  const receipt = auditReceipt(await deriveIdempotencyKey("mismatched-audit"));
  receipt["operation_id"] = pendingId;
  const server = await startServer((_request, response) => {
    sendJson(response, 200, receipt);
  });

  try {
    const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
    await assert.rejects(
      client.getAudit(operationId),
      (error: unknown) =>
        error instanceof MasuGateProtocolError &&
        error.message === "audit operation_id does not match the requested id",
    );
  } finally {
    await server.close();
  }
});

test("successful malformed action and audit responses are rejected structurally", async () => {
  const malformedAction = committedResponse(false);
  delete (malformedAction["decision"] as JsonObject)["policy_id"];
  const malformedAudit = auditReceipt(await deriveIdempotencyKey("malformed-audit"));
  malformedAudit["effect"] = null;
  const server = await startServer((request, response) => {
    sendJson(
      response,
      200,
      request.url === "/v1/actions" ? malformedAction : malformedAudit,
    );
  });

  try {
    const client = new MasuGateClient({ baseUrl: server.baseUrl, token: "test-token" });
    await assert.rejects(
      client.execute({ action: "transfer", args: {}, stableId: "malformed-action" }),
      (error: unknown) =>
        error instanceof MasuGateProtocolError &&
        error.message === "action response.decision.policy_id is required",
    );
    await assert.rejects(
      client.getAudit(operationId),
      (error: unknown) =>
        error instanceof MasuGateProtocolError &&
        error.message === "audit response.effect must be an object",
    );
  } finally {
    await server.close();
  }
});

test("streamPending parses chunked CRLF SSE frames and sends the resume cursor", async () => {
  let seenCursor: string | undefined;
  let seenUrl = "";
  const event = pendingEvent();
  const server = await startServer((request, response) => {
    const cursor = request.headers["last-event-id"];
    seenCursor = Array.isArray(cursor) ? cursor[0] : cursor;
    seenUrl = request.url ?? "";
    response.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
    });

    const json = JSON.stringify(event);
    const split = json.indexOf('"event_type"');
    const frame =
      ": keep-alive\r\n" +
      `id: ${event.event_id}\r\n` +
      "event: pending.created\r\n" +
      `data: ${json.slice(0, split)}\r\n` +
      `data: ${json.slice(split)}\r\n\r\n`;
    const encoded = Buffer.from(frame);
    const marker = encoded.indexOf(Buffer.from("café"));
    const firstCut = marker + Buffer.from("caf").length + 1;
    response.write(encoded.subarray(0, firstCut));
    setImmediate(() => response.end(encoded.subarray(firstCut)));
  });

  try {
    const client = new MasuGateClient({ baseUrl: `${server.baseUrl}/`, token: "test-token" });
    const received = [];
    for await (const item of client.streamPending({
      once: true,
      lastEventId: "previous-event",
    })) {
      received.push(item);
    }

    assert.equal(seenUrl, "/v1/pending/stream?once=true");
    assert.equal(seenCursor, "previous-event");
    assert.deepEqual(received, [event]);
    assert.equal(received[0]?.pending.args["note"], "café");
    assert.equal(received[0]?.pending.resolution_plan, "reservation-proof");
    assert.equal(
      received[0]?.pending.reservation_safety_certificate_digest,
      certificateDigest,
    );
    assert.equal(received[0]?.pending.reservation_entitlement_digest, entitlementDigest);
  } finally {
    await server.close();
  }
});

function committedResponse(replayed: boolean): JsonObject {
  return {
    operation_id: operationId,
    status: "committed",
    decision: {
      effect: "allow",
      policy_id: "ledger-policy",
      policy_version: "v1",
      rule_id: "within-budget",
      reason: "within budget",
    },
    payload: { receipt: "posted-once" },
    audit_ref: `/v1/audit/${operationId}`,
    replayed,
  };
}

function pendingResponse(): JsonObject {
  return {
    operation_id: operationId,
    status: "pending",
    decision: {
      effect: "escalate",
      policy_id: "ledger-policy",
      policy_version: "v1",
      rule_id: "review-large-transfer",
      reason: "human review required",
    },
    payload: {},
    pending_id: pendingId,
    resolution_plan: "reservation-proof",
    reservation_safety_certificate_digest: certificateDigest,
    reservation_entitlement_digest: entitlementDigest,
    audit_ref: `/v1/audit/${operationId}`,
    replayed: false,
  };
}

function operationalResponse(status: "in_progress" | "outcome_unknown"): JsonObject {
  return {
    operation_id: operationId,
    status,
    decision: null,
    payload: { protected_execution: { status } },
    audit_ref: `/v1/audit/${operationId}`,
    replayed: false,
  };
}

function pendingEvent(): JsonObject & {
  event_id: string;
  event_type: "pending.created";
  pending: JsonObject;
} {
  return {
    event_id: pendingId,
    event_type: "pending.created",
    occurred_at: "2026-07-12T16:00:00Z",
    pending: {
      pending_id: pendingId,
      operation_id: operationId,
      principal_id: "agent-7",
      action: "transfer",
      args: { amount_cents: 2500, note: "café" },
      created_at: "2026-07-12T16:00:00Z",
      resolution_plan: "reservation-proof",
      reservation_safety_certificate_digest: certificateDigest,
      reservation_entitlement_digest: entitlementDigest,
      decision: {
        effect: "escalate",
        policy_id: "ledger-policy",
        policy_version: "v1",
        rule_id: "review-large-transfer",
        reason: "human review required",
      },
      audit_ref: `/v1/audit/${operationId}`,
    },
  };
}

function auditReceipt(idempotencyKey: string): JsonObject {
  return {
    operation_id: operationId,
    status: "committed",
    request: {
      idempotency_key: idempotencyKey,
      principal: {
        id: "agent-7",
        attributes: { team: "research" },
      },
      action: "transfer",
      args: { receiver_id: "merchant", amount_cents: 2500 },
      timestamp: "2026-07-12T16:00:00Z",
      request_time: "2026-07-12T16:00:00Z",
      trace_id: "trace-7",
    },
    policy: {
      policy_id: "ledger-policy",
      policy_version: "v1",
      catalog: {
        policy_digest: "a".repeat(64),
        bundle_digest: "b".repeat(64),
      },
      evaluated_policies: [{ policy_id: "ledger-policy", policy_version: "v1" }],
      evaluated_policy_provenance: [
        {
          policy_id: "ledger-policy",
          policy_declared_version: "1.0.0",
          policy_runtime_version: "v1",
          policy_digest: "a".repeat(64),
          bundle_id: "masugate.platform.safety",
          bundle_version: "1.0.0",
          bundle_digest: "b".repeat(64),
          layer: "platform-safety",
          mode: "mandatory",
        },
      ],
    },
    entitlement: {
      entitlement_id: "entitlement-7",
      authorization_digest: "c".repeat(64),
    },
    decision: {
      effect: "allow",
      rule_id: "within-budget",
      reason: "within budget",
    },
    view_reads: [
      {
        function: "available_budget",
        arguments: ["research"],
        value: 10000,
        scope: "team-budget:research",
        version: 3,
        latency_ms: 0.4,
      },
    ],
    authorization_evaluations: [
      {
        phase: "admission",
        evaluated_at: "2026-07-12T16:00:00Z",
        decision: {
          effect: "allow",
          policy_id: "ledger-policy",
          policy_version: "v1",
          rule_id: "within-budget",
          reason: "within budget",
          reads: [],
          evaluated_policies: [
            { policy_id: "ledger-policy", policy_version: "v1" },
          ],
          policy_provenance: [
            {
              policy_id: "ledger-policy",
              policy_declared_version: "1.0.0",
              policy_runtime_version: "v1",
              policy_digest: "a".repeat(64),
              bundle_id: "masugate.platform.safety",
              bundle_version: "1.0.0",
              bundle_digest: "b".repeat(64),
              layer: "platform-safety",
              mode: "mandatory",
            },
          ],
        },
        certified_inputs: [],
      },
    ],
    terminal_serialization: {
      kind: "effect-commit",
      authorization_basis: "admission-evaluation",
      provider_atomic: true,
      recorded_at: "2026-07-12T16:00:00Z",
      evaluation_phase: "admission",
      evaluation_at: "2026-07-12T16:00:00Z",
    },
    human_resolution: {
      approved: true,
      actor_id: "operator:alice",
      evidence: { ticket: "CAB-7" },
      resolved_at: "2026-07-12T16:00:00Z",
    },
    resolution_plan: "reservation-proof",
    reservation_safety_certificate_digest: certificateDigest,
    reservation_entitlement_digest: entitlementDigest,
    protected_execution: protectedExecutionAudit(idempotencyKey),
    effect: {
      action: "transfer",
      args: { receiver_id: "merchant", amount_cents: 2500 },
      payload: { receipt: "posted-once" },
    },
    recorded_at: "2026-07-12T16:00:00Z",
  };
}

function protectedExecutionAudit(idempotencyKey: string): JsonObject {
  const binding: JsonObject = {
    principal_id: "agent-7",
    action: "transfer",
    arguments: { receiver_id: "merchant", amount_cents: 2500 },
    idempotency_key: idempotencyKey,
    policies: [
      {
        policy_id: "ledger-policy",
        policy_version: "1.0.0",
        policy_digest: "a".repeat(64),
        bundle_id: "masugate.platform.safety",
        bundle_version: "1.0.0",
        bundle_digest: "b".repeat(64),
      },
    ],
    provider_identity: {
      provider_id: "masugate.reference.purchase",
      implementation_version: "reference-purchase-v1",
      configuration_version: "reference-purchase-config-v1",
    },
    coordination_domain_id: "reference-domain",
    scopes: ["team-budget:research"],
    tool_call_id: "tool-call-7",
    connector_id: "reference-purchase-v1",
    entitlement_id: "entitlement-7",
    authorization_digest: "c".repeat(64),
  };
  const bindingCanonicalJson = fixtureCanonicalJson(binding);
  const digest = createHash("sha256").update(bindingCanonicalJson, "utf8").digest("hex");
  return {
    execution_id: `px:${digest}`,
    binding_digest: digest,
    binding,
    binding_canonical_json: bindingCanonicalJson,
    status: "succeeded",
    entitlement_state: "consumed",
    dispatch_started: true,
    cancel_requested: false,
    external_operation_id: "remote-7",
    lease: null,
    last_fence_token: 1,
    receipt: {
      connector_id: "reference-purchase-v1",
      evidence_id: "receipt-7",
      idempotency_key: `masugate:${digest}`,
      external_operation_id: "remote-7",
      outcome: "succeeded",
      observed_at: "2026-07-12T16:00:00Z",
      payload: { reference: "remote-7" },
    },
    result: { reference: "remote-7" },
    created_at: "2026-07-12T15:59:59Z",
    updated_at: "2026-07-12T16:00:00Z",
    events: [
      {
        sequence: 1,
        event_type: "intent-persisted",
        from_status: null,
        to_status: "intent",
        worker_id: null,
        fence_token: null,
        recorded_at: "2026-07-12T15:59:59Z",
        evidence: { binding_digest: digest },
      },
      {
        sequence: 2,
        event_type: "terminal-position-recorded",
        from_status: "executing",
        to_status: "succeeded",
        worker_id: "worker-7",
        fence_token: 1,
        recorded_at: "2026-07-12T16:00:00Z",
        evidence: { entitlement_state: "consumed" },
      },
    ],
  };
}

function fixtureCanonicalJson(value: JsonObject): string {
  const encode = (item: JsonValue): string => {
    if (item === null || typeof item !== "object") return JSON.stringify(item);
    if (Array.isArray(item)) return `[${item.map(encode).join(",")}]`;
    return `{${Object.keys(item).sort().map((key) =>
      `${JSON.stringify(key)}:${encode(item[key]!)}`).join(",")}}`;
  };
  return encode(value);
}

async function readJsonObject(request: IncomingMessage): Promise<JsonObject> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array));
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as JsonObject;
}

function sendJson(response: ServerResponse, status: number, body: JsonObject): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

async function startServer(
  handler: (request: IncomingMessage, response: ServerResponse) => void | Promise<void>,
): Promise<{ baseUrl: string; close: () => Promise<void> }> {
  const server = createServer((request, response) => {
    void Promise.resolve(handler(request, response)).catch((error: unknown) => {
      response.destroy(error instanceof Error ? error : new Error(String(error)));
    });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: async () => {
      server.close();
      await once(server, "close");
    },
  };
}
