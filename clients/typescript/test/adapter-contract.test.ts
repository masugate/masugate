import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  HOST_ADAPTER_CONTRACT_VERSION,
  ScriptedAdapterResponder,
  canonicalAdapterEnvelope,
  canonicalGovernedRouteManifest,
  canonicalGovernedRouteManifestV2,
  createAdapterInvocation,
  requireAdapterActionName,
  requireAdapterArgumentName,
  validateAdapterCancellationEnvelope,
  validateAdapterLifecycleEnvelope,
  validateAdapterReceiptEnvelope,
  validateGovernedRouteManifest,
  validateGovernedRouteManifestV2,
  validateOperationLocator,
} from "../src/index.js";

function invocation(action: string) {
  return createAdapterInvocation({
    principal: { id: "adapter:buyer" },
    source: { namespace: "canary", id: "call-1" },
    adapter: {
      id: "masugate.canary",
      contract_version: HOST_ADAPTER_CONTRACT_VERSION,
      capabilities: ["locator", "receipt", "cancellation"],
    },
    action: { name: action, arguments: { amount: 7 } },
  });
}

function protocolExample(name: string): unknown {
  return JSON.parse(
    readFileSync(
      new URL(`../../../../protocol/examples/${name}`, import.meta.url),
      "utf8",
    ),
  );
}

function countedSchemaBomb(depth: number, reads: { count: number }): Record<string, unknown> {
  const wrap = (value: Record<string, unknown>): Record<string, unknown> => new Proxy(value, {
    get(target, property, receiver) {
      reads.count += 1;
      return Reflect.get(target, property, receiver);
    },
  });
  if (depth === 0) return wrap({ type: "string", maxLength: 1 });
  const properties: Record<string, unknown> = {};
  for (let index = 0; index < 8; index += 1) {
    properties[`field_${index}`] = countedSchemaBomb(depth - 1, reads);
  }
  return wrap({
    type: "object",
    properties: wrap(properties),
    required: Object.keys(properties),
    additionalProperties: false,
  });
}

function goldenVectors(): Record<string, unknown> {
  return protocolExample("host-adapter-golden-vectors.json") as Record<string, unknown>;
}

function canonicalExpected(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalExpected).join(",")}]`;
  return `{${Object.keys(value as Record<string, unknown>)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalExpected((value as Record<string, unknown>)[key])}`)
    .join(",")}}`;
}

function goldenInvocation(): Record<string, unknown> {
  return structuredClone(goldenVectors()["invocation"] as Record<string, unknown>);
}

function goldenLifecycle(name: string): Record<string, unknown> {
  const vectors = goldenVectors();
  const lifecycle = (vectors["lifecycle"] as Record<string, unknown>[]).find(
    (item) => item["name"] === name,
  );
  if (lifecycle === undefined) throw new Error(`missing lifecycle vector: ${name}`);
  return {
    kind: "lifecycle",
    invocation: goldenInvocation(),
    result: structuredClone(lifecycle["result"]),
    locator: structuredClone(lifecycle["locator"]),
  };
}

test("scripted responder presents allow, deny, pending, locator, cancellation, and receipt", async () => {
  for (const [action, status] of [["canary.allow", "committed"], ["canary.deny", "denied"]] as const) {
    const result = await new ScriptedAdapterResponder().submit(invocation(action));
    assert.equal(result.result.status, status);
    assert.match(result.result.operation_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.match(result.result.audit_ref, /^\/v1\/audit\//);
    assert.deepEqual(result.locator, { operation_id: result.result.operation_id });
  }
  const responder = new ScriptedAdapterResponder();
  const pending = await responder.submit(invocation("canary.pending"));
  assert.equal(pending.result.status, "pending");
  if (pending.result.status !== "pending") throw new Error("expected pending fixture");
  const pendingLocator = {
    operation_id: pending.locator.operation_id,
    pending_id: pending.result.pending_id,
  };
  assert.equal((await responder.locate(pending.locator))?.result.status, "pending");
  assert.equal((await responder.cancel(pendingLocator)).accepted, true);
  assert.equal((await responder.receipt(pending.locator))?.marker, "cancellation-requested");
  assert.equal((await responder.submit(invocation("canary.pending"))).result.replayed, true);
});

test("contract rejects model-supplied authority fields", () => {
  assert.throws(
    () => createAdapterInvocation({
      ...invocation("canary.allow"),
      action: { name: "canary.allow", arguments: { principal_id: "spoof" } },
    }),
    /reserved/,
  );
});

test("one canonical reserved-name rule rejects authority aliases", () => {
  for (const name of [
    "adapter_id",
    "adapter_capabilities",
    "contract_version",
    "invocation_id",
    "p_r_i_n_c_i_p_a_l",
    "retry_authority",
    "receipt_ref",
    "source_id",
    "source_namespace",
    "Tool-Call-ID",
    "constructor",
    "prototype",
  ]) {
    assert.throws(() => requireAdapterArgumentName(name), /canonical|reserved/);
  }
  assert.equal(requireAdapterArgumentName("request_ref"), "request_ref");
});

test("v1 argument names remain compatible with generated host prefixes", () => {
  const parsedInvocation = createAdapterInvocation({
    ...invocation("canary.allow"),
    action: { name: "canary.allow", arguments: { model_id: "model-1" } },
  });
  assert.deepEqual(parsedInvocation.action.arguments, { model_id: "model-1" });

  const manifest = structuredClone(goldenVectors()["manifest"]) as Record<string, unknown>;
  const route = (manifest["routes"] as Record<string, unknown>[])[0]!;
  const arguments_ = route["arguments"] as Record<string, unknown>;
  arguments_["model_id"] = "string";
  const parsedManifest = validateGovernedRouteManifest(manifest);
  assert.equal(parsedManifest.routes[0]!.arguments.model_id, "string");
});

test("action names are canonical before an adapter advertises them", () => {
  assert.equal(requireAdapterActionName("spend.purchase"), "spend.purchase");
  assert.throws(() => requireAdapterActionName("bad action"), /canonical identifier/);
  assert.throws(() => requireAdapterActionName(""), /canonical identifier/);
});

test("contract rejects action arguments outside the GAP scalar value set", () => {
  assert.throws(
    () => createAdapterInvocation({
      ...invocation("canary.allow"),
      action: {
        name: "canary.allow",
        arguments: { amount: 1.5 } as never,
      },
    }),
    /must be a string, integer, or boolean/,
  );
  assert.throws(
    () => createAdapterInvocation({
      ...invocation("canary.allow"),
      action: {
        name: "canary.allow",
        arguments: { amount: Number.MAX_SAFE_INTEGER + 1 },
      },
    }),
    /must be a string, integer, or boolean/,
  );
});

test("runtime invocation validation rejects schema-invalid JavaScript values", () => {
  const numericPrincipal = structuredClone(invocation("canary.allow"));
  numericPrincipal.principal.id = 123 as never;
  assert.throws(() => createAdapterInvocation(numericPrincipal), /principal.id/);

  const numericAction = structuredClone(invocation("canary.allow"));
  numericAction.action.name = 123 as never;
  assert.throws(() => createAdapterInvocation(numericAction), /action.name/);

  const sparseCapabilities = structuredClone(invocation("canary.allow"));
  sparseCapabilities.adapter.capabilities = new Array(1) as never;
  assert.throws(
    () => createAdapterInvocation(sparseCapabilities),
    /must not contain sparse entries/,
  );

  const duplicateCapabilities = structuredClone(invocation("canary.allow"));
  duplicateCapabilities.adapter.capabilities = ["locator", "locator"];
  assert.throws(
    () => createAdapterInvocation(duplicateCapabilities),
    /must not contain duplicates/,
  );

  const scalarArguments = structuredClone(invocation("canary.allow"));
  scalarArguments.action.arguments = 7 as never;
  assert.throws(() => createAdapterInvocation(scalarArguments), /arguments must be an object/);

  const extraEnvelopeField = {
    ...invocation("canary.allow"),
    trusted_override: true,
  };
  assert.throws(
    () => createAdapterInvocation(extraEnvelopeField as never),
    /trusted_override is not allowed/,
  );
});

test("trusted source identity is immutable across replayed request content", async () => {
  const responder = new ScriptedAdapterResponder();
  await responder.submit(invocation("canary.allow"));

  await assert.rejects(
    responder.submit(invocation("canary.deny")),
    /already bound to a different canonical request/,
  );
  await assert.rejects(
    responder.submit(createAdapterInvocation({
      ...invocation("canary.allow"),
      action: { name: "canary.allow", arguments: { amount: 8 } },
    })),
    /already bound to a different canonical request/,
  );
});

test("semantic validation binds lifecycle and cancellation identities", async () => {
  const responder = new ScriptedAdapterResponder();
  const pending = await responder.submit(invocation("canary.pending"));

  assert.throws(
    () => validateAdapterLifecycleEnvelope({
      ...pending,
      locator: { ...pending.locator, operation_id: "00000000-0000-4000-8000-100000000099" },
    }),
    /operation_id must match/,
  );
  assert.throws(
    () => validateAdapterLifecycleEnvelope({
      ...pending,
      locator: { ...pending.locator, pending_id: "00000000-0000-4000-8000-200000000099" },
    }),
    /pending_id must match/,
  );

  const committed = await new ScriptedAdapterResponder().submit(invocation("canary.allow"));
  const terminalResult = committed.result;
  assert.equal(terminalResult.status, "committed");
  if (terminalResult.status !== "committed") throw new Error("expected committed fixture");
  assert.throws(
    () => validateAdapterCancellationEnvelope({
      kind: "cancellation",
      locator: {
        operation_id: committed.result.operation_id,
      },
      accepted: false,
    }),
    /must include pending_id/,
  );
  assert.throws(
    () => validateAdapterCancellationEnvelope({
      kind: "cancellation",
      locator: pending.locator,
      accepted: true,
      terminal_result: terminalResult,
    }),
    /must not carry a terminal result/,
  );
  assert.throws(
    () => validateAdapterCancellationEnvelope({
      kind: "cancellation",
      locator: {
        operation_id: "00000000-0000-4000-8000-100000000099",
        pending_id: pending.locator.pending_id,
      },
      accepted: false,
      terminal_result: terminalResult,
    }),
    /operation_id must match/,
  );
});

test("runtime validators enforce the complete normative lifecycle shapes", async () => {
  const responder = new ScriptedAdapterResponder();
  const committed = await responder.submit(invocation("canary.allow"));

  const missingPayload = structuredClone(committed) as unknown as Record<string, unknown>;
  delete (missingPayload["result"] as Record<string, unknown>)["payload"];
  assert.throws(
    () => validateAdapterLifecycleEnvelope(missingPayload),
    /payload must be an object/,
  );

  assert.throws(
    () => validateAdapterLifecycleEnvelope({
      ...committed,
      result: { ...committed.result, operation_id: "not-a-uuid" },
      locator: { operation_id: "not-a-uuid" },
    }),
    /must be a UUID/,
  );

  assert.throws(
    () => validateAdapterLifecycleEnvelope({
      ...committed,
      result: {
        ...committed.result,
        audit_ref: "/v1/audit/00000000-0000-4000-8000-100000000099",
      },
    }),
    /must identify the same operation/,
  );

  const sparsePolicies = structuredClone(committed);
  if (sparsePolicies.result.decision === null) throw new Error("expected policy decision");
  sparsePolicies.result.decision.evaluated_policies = new Array(1) as never;
  assert.throws(
    () => validateAdapterLifecycleEnvelope(sparsePolicies),
    /evaluated_policies must not be sparse/,
  );

  const sparsePayload = structuredClone(committed);
  sparsePayload.result.payload = { nested: new Array(1) as never };
  assert.throws(
    () => validateAdapterLifecycleEnvelope(sparsePayload),
    /payload\.nested must not be sparse/,
  );

  assert.throws(
    () => validateAdapterCancellationEnvelope({
      kind: "cancellation",
      locator: {
        operation_id: committed.result.operation_id,
        pending_id: "00000000-0000-4000-8000-200000000099",
      },
      accepted: false,
      terminal_result: { operation_id: committed.result.operation_id },
    }),
    /status is invalid/,
  );

  const receipt = await responder.receipt(committed.locator);
  assert.ok(receipt);
  assert.throws(
    () => validateAdapterReceiptEnvelope({ ...receipt, audit_ref: "bad" }),
    /audit reference/,
  );
  assert.throws(
    () => validateAdapterReceiptEnvelope({
      ...receipt,
      audit_ref: "/v1/audit/00000000-0000-4000-8000-100000000099",
    }),
    /must identify the same operation/,
  );
  assert.throws(
    () => validateAdapterReceiptEnvelope({ ...receipt, marker: "" }),
    /non-empty string/,
  );
  assert.throws(
    () => validateOperationLocator({ operation_id: "not-a-uuid" }),
    /must be a UUID/,
  );
});

test("SDK validators accept the exact normative protocol examples", () => {
  assert.doesNotThrow(() =>
    validateAdapterLifecycleEnvelope(protocolExample("host-adapter-lifecycle.json"))
  );
  assert.doesNotThrow(() =>
    validateAdapterCancellationEnvelope(protocolExample("host-adapter-cancellation.json"))
  );
  assert.doesNotThrow(() =>
    validateAdapterReceiptEnvelope(protocolExample("host-adapter-receipt.json"))
  );
});

test("cross-language golden vectors cover routes, trust fields, and every lifecycle state", () => {
  const invocation = createAdapterInvocation(goldenInvocation() as never);
  assert.deepEqual(invocation.adapter.capabilities, ["cancellation", "locator", "receipt"]);
  assert.equal(canonicalAdapterEnvelope(goldenInvocation() as never), canonicalExpected(invocation));

  const vectors = goldenVectors();
  const manifest = validateGovernedRouteManifest(vectors["manifest"]);
  assert.equal(canonicalGovernedRouteManifest(vectors["manifest"]), canonicalExpected(manifest));

  for (const status of ["committed", "denied", "pending", "in_progress", "outcome_unknown"]) {
    const parsed = validateAdapterLifecycleEnvelope(goldenLifecycle(status));
    assert.equal(parsed.result.status, status);
    assert.equal(canonicalAdapterEnvelope(goldenLifecycle(status) as never), canonicalExpected(parsed));
  }
  assert.equal(
    canonicalAdapterEnvelope(vectors["cancellation"] as never),
    canonicalExpected(vectors["cancellation"]),
  );
  assert.equal(
    canonicalAdapterEnvelope(vectors["receipt"] as never),
    canonicalExpected(vectors["receipt"]),
  );

  const canonicalization = vectors["canonicalization"] as Record<string, unknown>;
  const numericUnicode = goldenLifecycle("committed");
  (numericUnicode["result"] as Record<string, unknown>)["payload"] = structuredClone(
    canonicalization["payload"],
  );
  assert.ok(
    canonicalAdapterEnvelope(numericUnicode as never).includes(
      `"payload":${canonicalization["expected_payload_json"] as string}`,
    ),
  );

  const unsafeIntegralFloat = structuredClone(numericUnicode) as unknown as Record<
    string,
    unknown
  >;
  (unsafeIntegralFloat["result"] as Record<string, unknown>)["payload"] = {
    amount: Number.MAX_SAFE_INTEGER + 1,
  };
  assert.throws(
    () => validateAdapterLifecycleEnvelope(unsafeIntegralFloat),
    /JavaScript-safe/,
  );

  const unpairedSurrogate = structuredClone(numericUnicode) as unknown as Record<string, unknown>;
  (unpairedSurrogate["result"] as Record<string, unknown>)["payload"] = {
    invalid: "\ud800",
  };
  assert.throws(
    () => canonicalAdapterEnvelope(unpairedSurrogate as never),
    /unpaired surrogate/,
  );
});

test("v2 route projection canonicalizes without private deployment binding fields", () => {
  const manifest = protocolExample("governed-route-manifest-v2-route-fixture.json");
  const parsed = validateGovernedRouteManifestV2(manifest);
  const canonical = canonicalGovernedRouteManifestV2(manifest);

  assert.equal(canonical, canonicalExpected(parsed));
  assert.equal(canonical.includes("credential_refs"), false);
  assert.equal(canonical.includes("allowed_destinations"), false);
});

test("v2 route projection rejects transactional capabilities and production profiles", () => {
  const manifest = structuredClone(
    protocolExample("governed-route-manifest-v2-route-fixture.json"),
  ) as Record<string, unknown>;
  const route = (manifest["routes"] as Record<string, unknown>[])[0]!;
  route["owner"] = { provider_id: "route-fixture-provider-v1", position: "transactional" };

  assert.throws(
    () => validateGovernedRouteManifestV2(manifest),
    /transactional route cannot require connector capabilities/,
  );

  route["required_connector_capabilities"] = [];
  route["maturity"] = "production-profile";
  assert.throws(
    () => validateGovernedRouteManifestV2(manifest),
    /production-profile requires protected-external/,
  );
});

test("v2 route projection rejects duplicate actions under distinct host tools", () => {
  const manifest = structuredClone(
    protocolExample("governed-route-manifest-v2-route-fixture.json"),
  ) as Record<string, unknown>;
  const routes = manifest["routes"] as Record<string, unknown>[];
  const alias = structuredClone(routes[0]!);
  alias["host_tool"] = "reference_notify_alias";
  const inputSchema = alias["input_schema"] as Record<string, unknown>;
  const properties = inputSchema["properties"] as Record<string, Record<string, unknown>>;
  properties["recipient"]!["maxLength"] = 319;
  routes.push(alias);
  assert.throws(() => validateGovernedRouteManifestV2(manifest), /must not repeat action/);
});

test("v2 route projection bounds route, capability, and canonical breadth", () => {
  const manifest = structuredClone(
    protocolExample("governed-route-manifest-v2-route-fixture.json"),
  ) as Record<string, unknown>;
  const route = (manifest["routes"] as Record<string, unknown>[])[0]!;
  manifest["routes"] = Array.from({ length: 65 }, (_value, index) => ({
    ...structuredClone(route),
    host_tool: `reference_notify_${index}`,
    action: `reference.notify_${index}`,
  }));
  assert.throws(() => validateGovernedRouteManifestV2(manifest), /routes must contain at most 64 entries/);

  const capabilityManifest = structuredClone(
    protocolExample("governed-route-manifest-v2-route-fixture.json"),
  ) as Record<string, unknown>;
  const capabilityRoute = (capabilityManifest["routes"] as Record<string, unknown>[])[0]!;
  capabilityRoute["required_connector_capabilities"] = Array.from(
    { length: 65 },
    (_value, index) => `capability_${index}`,
  );
  assert.throws(
    () => validateGovernedRouteManifestV2(capabilityManifest),
    /required_connector_capabilities must contain at most 64/,
  );

  assert.throws(
    () => validateGovernedRouteManifestV2(protocolExample("governed-route-manifest-v2-route-fixture.json"), { maxManifestCanonicalBytes: 1 }),
    /canonical form exceeds configured limit/,
  );
});

test("v2 route schemas stop before expanding a schema bomb", () => {
  const manifest = structuredClone(
    protocolExample("governed-route-manifest-v2-route-fixture.json"),
  ) as Record<string, unknown>;
  const route = (manifest["routes"] as Record<string, unknown>[])[0]!;
  const reads = { count: 0 };
  route["input_schema"] = countedSchemaBomb(5, reads);

  assert.throws(
    () => validateGovernedRouteManifestV2(manifest, { maxSchemaCanonicalBytes: 1 }),
    /canonical form exceeds configured limit/,
  );
  assert.ok(reads.count < 100);
});

test("v2 route schemas reject explicit null numeric bounds", () => {
  const mutate = (bound: "minLength" | "minItems" | "minimum" | "maximum"): void => {
    const manifest = structuredClone(
      protocolExample("governed-route-manifest-v2-route-fixture.json"),
    ) as Record<string, unknown>;
    const route = (manifest["routes"] as Record<string, unknown>[])[0]!;
    const input = route["input_schema"] as Record<string, unknown>;
    const properties = input["properties"] as Record<string, Record<string, unknown>>;
    const target = bound === "minLength"
      ? properties["recipient"]!
      : bound === "minItems"
        ? ((properties["metadata"]!)["properties"] as Record<string, Record<string, unknown>>)["labels"]!
        : ((properties["metadata"]!)["properties"] as Record<string, Record<string, unknown>>)["priority"]!;
    target[bound] = null;
    assert.throws(() => validateGovernedRouteManifestV2(manifest), /invalid integer bounds/);
  };

  mutate("minLength");
  mutate("minItems");
  mutate("minimum");
  mutate("maximum");
});

test("v2 route projection rejects trust and compound credential field names", () => {
  const vectors = protocolExample("operation-pack-v2-field-vectors.json") as {
    invalid_model_fields: { name: string; message: string }[];
  };
  for (const { name: fieldName, message } of vectors.invalid_model_fields) {
    const manifest = structuredClone(
      protocolExample("governed-route-manifest-v2-route-fixture.json"),
    ) as Record<string, unknown>;
    const route = (manifest["routes"] as Record<string, unknown>[])[0]!;
    const inputSchema = route["input_schema"] as Record<string, unknown>;
    const properties = inputSchema["properties"] as Record<string, unknown>;
    properties[fieldName] = { type: "string", maxLength: 16 };
    assert.throws(() => validateGovernedRouteManifestV2(manifest), new RegExp(message));
  }
});

test("v2 route projection rejects sparse route, artifact, and capability arrays", () => {
  const sparseRoutes = structuredClone(
    protocolExample("governed-route-manifest-v2-route-fixture.json"),
  ) as Record<string, unknown>;
  sparseRoutes["routes"] = new Array(1);
  assert.throws(() => validateGovernedRouteManifestV2(sparseRoutes), /routes must not be sparse/);

  const sparseArtifacts = structuredClone(
    protocolExample("governed-route-manifest-v2-route-fixture.json"),
  ) as Record<string, unknown>;
  const artifactRoute = (sparseArtifacts["routes"] as Record<string, unknown>[])[0]!;
  artifactRoute["artifact_fields"] = new Array(1);
  assert.throws(
    () => validateGovernedRouteManifestV2(sparseArtifacts),
    /artifact_fields must not be sparse/,
  );

  const sparseCapabilities = structuredClone(
    protocolExample("governed-route-manifest-v2-route-fixture.json"),
  ) as Record<string, unknown>;
  const capabilityRoute = (sparseCapabilities["routes"] as Record<string, unknown>[])[0]!;
  capabilityRoute["required_connector_capabilities"] = new Array(1);
  assert.throws(
    () => validateGovernedRouteManifestV2(sparseCapabilities),
    /required_connector_capabilities must not be sparse/,
  );
});

test("cross-language golden vectors reject safe-integer, trust-name, and identity drift", () => {
  const vectors = goldenVectors();
  for (const vector of vectors["invalid"] as Record<string, unknown>[]) {
    const input = vector["input"] as Record<string, unknown>;
    assert.throws(() => {
      if (vector["kind"] === "invocation") {
        const invocation = goldenInvocation();
        (invocation["action"] as Record<string, unknown>)["arguments"] = input["arguments"];
        createAdapterInvocation(invocation as never);
        return;
      }
      if (vector["kind"] === "lifecycle") {
        const envelope = goldenLifecycle(input["result"] as string);
        envelope["locator"] = input["locator"];
        validateAdapterLifecycleEnvelope(envelope);
        return;
      }
      if (vector["kind"] === "manifest") {
        validateGovernedRouteManifest(input);
        return;
      }
      throw new Error(`unknown vector kind: ${String(vector["kind"])}`);
    });
  }
});

test("scripted responder state is isolated from caller mutation", async () => {
  const responder = new ScriptedAdapterResponder();
  const first = await responder.submit(invocation("canary.allow"));
  const operationId = first.locator.operation_id;

  first.locator.operation_id = "caller-mutated";
  first.invocation.action.arguments["amount"] = 99;
  first.result.payload["amount"] = 99;

  const replay = await responder.submit(invocation("canary.allow"));
  assert.equal(replay.locator.operation_id, operationId);
  assert.equal(replay.invocation.action.arguments["amount"], 7);
  assert.equal(replay.result.payload["amount"], 7);
  assert.equal(replay.result.replayed, true);

  const located = await responder.locate({ operation_id: operationId });
  assert.ok(located);
  located.result.payload["amount"] = 101;
  assert.equal(
    (await responder.locate({ operation_id: operationId }))?.result.payload["amount"],
    7,
  );
});

test("canonical serialization uses locale-independent ordinal key order", async () => {
  const base = await new ScriptedAdapterResponder().submit(invocation("canary.allow"));
  const first = structuredClone(base);
  const second = structuredClone(base);
  first.result.payload = { "ä": 1, "a\u0308": 2 };
  second.result.payload = { "a\u0308": 2, "ä": 1 };

  assert.equal(canonicalAdapterEnvelope(first), canonicalAdapterEnvelope(second));
});
