import type {
  ActionArguments,
  ActionResult,
  CommittedActionResult,
  DeniedActionResult,
  JsonObject,
  JsonValue,
  PendingActionResult,
  TerminalActionResult,
} from "./index.js";

/** Stable name for the framework-neutral host-adapter contract. */
export const HOST_ADAPTER_CONTRACT_VERSION = "masugate.host-adapter.v1";
/** Stable version for trusted host-tool to MasuGate action route declarations. */
export const GOVERNED_ROUTE_MANIFEST_VERSION = "masugate.governed-route-manifest.v1";
export type AdapterCapability = "cancellation" | "locator" | "pending-presentation" | "receipt";
export type GovernedArgumentKind = "string" | "integer" | "boolean";
export type GovernedExecutionOwner =
  | { provider_id: string; position: "transactional"; connector_id?: never }
  | { provider_id: string; position: "protected-external"; connector_id: string };
export interface GovernedToolRoute {
  host_tool: string;
  action: string;
  arguments: Record<string, GovernedArgumentKind>;
  owner: GovernedExecutionOwner;
}
export interface GovernedRouteManifest {
  contract_version: typeof GOVERNED_ROUTE_MANIFEST_VERSION;
  routes: GovernedToolRoute[];
}

export interface AuthenticatedAdapterPrincipal {
  /** Adapter-derived identity. Model arguments may not supply this value. */
  id: string;
}
export interface SourceInvocation {
  /** Namespace and call identity are derived from trusted host context. */
  namespace: string;
  id: string;
}
export interface AdapterProvenance {
  id: string;
  contract_version: typeof HOST_ADAPTER_CONTRACT_VERSION;
  capabilities: AdapterCapability[];
}
export interface CanonicalGovernedAction {
  name: string;
  arguments: ActionArguments;
}
/** The only record a host adapter may submit to GAP. */
export interface AdapterInvocation {
  principal: AuthenticatedAdapterPrincipal;
  source: SourceInvocation;
  adapter: AdapterProvenance;
  action: CanonicalGovernedAction;
}
export interface NonPendingOperationLocator {
  operation_id: string;
  pending_id?: never;
}
export interface PendingOperationLocator {
  operation_id: string;
  pending_id: string;
}
export type OperationLocator = NonPendingOperationLocator | PendingOperationLocator;
export type AdapterOperationalStatus = "in_progress" | "outcome_unknown";
export interface AdapterOperationalResult {
  operation_id: string;
  status: AdapterOperationalStatus;
  decision: null;
  payload: JsonObject;
  audit_ref: string;
  replayed: boolean;
  pending_id?: never;
}
export type AdapterLifecycleResult = ActionResult | AdapterOperationalResult;
interface AdapterLifecycleEnvelopeBase<
  Result extends AdapterLifecycleResult,
  Locator extends OperationLocator,
> {
  kind: "lifecycle";
  invocation: AdapterInvocation;
  result: Result;
  locator: Locator;
}
export type AdapterLifecycleEnvelope =
  | AdapterLifecycleEnvelopeBase<PendingActionResult, PendingOperationLocator>
  | AdapterLifecycleEnvelopeBase<
      CommittedActionResult | DeniedActionResult | AdapterOperationalResult,
      NonPendingOperationLocator
    >;
interface AdapterCancellationEnvelopeBase {
  kind: "cancellation";
  locator: PendingOperationLocator;
}
export interface AcceptedAdapterCancellationEnvelope extends AdapterCancellationEnvelopeBase {
  accepted: true;
  terminal_result?: never;
}
export interface RejectedAdapterCancellationEnvelope extends AdapterCancellationEnvelopeBase {
  accepted: false;
  terminal_result?: TerminalActionResult;
}
export type AdapterCancellationEnvelope =
  | AcceptedAdapterCancellationEnvelope
  | RejectedAdapterCancellationEnvelope;
export interface AdapterReceiptEnvelope {
  kind: "receipt";
  locator: OperationLocator;
  audit_ref: string;
  status: AdapterLifecycleResult["status"];
  marker: string;
}
export type AdapterEnvelope =
  | AdapterInvocation
  | AdapterLifecycleEnvelope
  | AdapterCancellationEnvelope
  | AdapterReceiptEnvelope;
export interface HostAdapterResponder {
  submit(invocation: AdapterInvocation): Promise<AdapterLifecycleEnvelope>;
  locate(locator: OperationLocator): Promise<AdapterLifecycleEnvelope | undefined>;
  cancel(locator: PendingOperationLocator): Promise<AdapterCancellationEnvelope>;
  receipt(locator: OperationLocator): Promise<AdapterReceiptEnvelope | undefined>;
}

const IDENTIFIER = /^[A-Za-z0-9._:/-]+$/;
const ADAPTER_CAPABILITIES = new Set<AdapterCapability>([
  "cancellation", "locator", "pending-presentation", "receipt",
]);
export const RESERVED_ADAPTER_ARGUMENT_NAMES = [
  "adapter", "adaptercapabilities", "adapterid", "agentid", "auditref", "authorization",
  "connectorid", "contractversion", "credential", "decision", "effect",
  "executionposition", "idempotencykey", "invocationid", "locator", "operationid",
  "pendingid", "policyid", "policyversion", "principal", "principalid", "principalref",
  "providerid", "receipt", "receiptref", "replayed", "retry", "retryauthority", "ruleid",
  "runid", "sessionid", "sessionkey", "sourceid", "sourceinvocation", "sourcenamespace",
  "stableid", "token", "toolcallid", "traceid",
] as const;
const RESERVED_ARGUMENT_NAMES = new Set<string>(RESERVED_ADAPTER_ARGUMENT_NAMES);
const UNSAFE_OBJECT_KEYS = new Set<string>(["__proto__", "prototype", "constructor"]);
const ADAPTER_ARGUMENT_NAME = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/;
const UUID = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;
const AUDIT_REF = /^\/v1\/audit\/[^/]+$/;
const SHA256 = /^[0-9a-f]{64}$/;
const LIFECYCLE_STATUSES = new Set<AdapterLifecycleResult["status"]>([
  "committed", "denied", "pending", "in_progress", "outcome_unknown",
]);

function requireRecord(value: unknown, field: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(field + " must be an object");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(field + " must be a plain JSON object");
  }
  return value as Record<string, unknown>;
}
function requireExactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  field: string,
): void {
  const unexpected = Object.keys(value).find((key) => !allowed.includes(key));
  if (unexpected !== undefined) {
    throw new TypeError(field + "." + unexpected + " is not allowed");
  }
}
function requireString(value: unknown, field: string, allowEmpty = false): string {
  if (typeof value !== "string" || (!allowEmpty && value.length === 0)) {
    throw new TypeError(field + " must be " + (allowEmpty ? "a string" : "a non-empty string"));
  }
  return value;
}
function requireUuid(value: unknown, field: string): string {
  const text = requireString(value, field);
  if (!UUID.test(text)) throw new TypeError(field + " must be a UUID");
  return text;
}
function requireAuditRef(value: unknown, field: string, operationId: string): string {
  const text = requireString(value, field);
  if (!AUDIT_REF.test(text)) throw new TypeError(field + " must be a GAP audit reference");
  if (text !== `/v1/audit/${operationId}`) {
    throw new TypeError(field + " must identify the same operation");
  }
  return text;
}
function requireDenseArray(value: readonly unknown[], field: string): void {
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) throw new TypeError(field + " must not be sparse");
  }
}
function jsonValue(value: unknown, field: string): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError(`${field} must be a finite JSON number`);
    }
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new TypeError(`${field} integer must be JavaScript-safe`);
    }
    return value;
  }
  if (Array.isArray(value)) {
    requireDenseArray(value, field);
    return value.map((item, index) => jsonValue(item, `${field}[${index}]`));
  }
  const source = requireRecord(value, field);
  return Object.fromEntries(
    Object.entries(source).map(([key, item]) => [key, jsonValue(item, `${field}.${key}`)]),
  );
}
function jsonObject(value: unknown, field: string): JsonObject {
  const source = requireRecord(value, field);
  return Object.fromEntries(
    Object.entries(source).map(([key, item]) => [key, jsonValue(item, `${field}.${key}`)]),
  );
}
export function requireIdentifier(value: unknown, field: string, maxLength = 256): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > maxLength ||
    !IDENTIFIER.test(value)
  ) {
    throw new TypeError(field + " must be a non-empty canonical identifier");
  }
  return value;
}
export function requireAdapterActionName(name: string): string {
  return requireIdentifier(name, "action.name", 255);
}
export function requireAdapterArgumentName(name: string): string {
  if (name.length > 256 || !ADAPTER_ARGUMENT_NAME.test(name)) {
    throw new TypeError(
      "adapter argument name must already be canonical lower_snake_case",
    );
  }
  if (UNSAFE_OBJECT_KEYS.has(name)) {
    throw new TypeError("adapter argument name uses a reserved unsafe object key");
  }
  if (RESERVED_ARGUMENT_NAMES.has(name.replaceAll("_", ""))) {
    throw new TypeError("adapter argument name uses a reserved trust-boundary name");
  }
  return name;
}

/**
 * Build a canonical invocation and reject model-controlled authority fields.
 * Identity, invocation identity, adapter provenance, and operation locators
 * are established outside the model argument object.
 */
export function createAdapterInvocation(input: AdapterInvocation): AdapterInvocation {
  const root = requireRecord(input, "adapter invocation");
  requireExactKeys(root, ["principal", "source", "adapter", "action"], "adapter invocation");
  const principal = requireRecord(root["principal"], "principal");
  const source = requireRecord(root["source"], "source");
  const adapter = requireRecord(root["adapter"], "adapter");
  const action = requireRecord(root["action"], "action");
  requireExactKeys(principal, ["id"], "principal");
  requireExactKeys(source, ["namespace", "id"], "source");
  requireExactKeys(adapter, ["id", "contract_version", "capabilities"], "adapter");
  requireExactKeys(action, ["name", "arguments"], "action");

  const principalId = requireIdentifier(principal["id"], "principal.id");
  const sourceNamespace = requireIdentifier(source["namespace"], "source.namespace");
  const sourceId = requireIdentifier(source["id"], "source.id");
  const adapterId = requireIdentifier(adapter["id"], "adapter.id");
  if (adapter["contract_version"] !== HOST_ADAPTER_CONTRACT_VERSION) {
    throw new TypeError("adapter.contract_version is unsupported");
  }
  const rawCapabilities = adapter["capabilities"];
  if (!Array.isArray(rawCapabilities)) {
    throw new TypeError("adapter.capabilities must be an array");
  }
  const capabilities: AdapterCapability[] = [];
  for (let index = 0; index < rawCapabilities.length; index += 1) {
    if (!Object.hasOwn(rawCapabilities, index)) {
      throw new TypeError("adapter.capabilities must not contain sparse entries");
    }
    const capability = rawCapabilities[index];
    if (
      typeof capability !== "string" ||
      !ADAPTER_CAPABILITIES.has(capability as AdapterCapability)
    ) {
      throw new TypeError("adapter.capabilities contains an unsupported capability");
    }
    if (capabilities.includes(capability as AdapterCapability)) {
      throw new TypeError("adapter.capabilities must not contain duplicates");
    }
    capabilities.push(capability as AdapterCapability);
  }
  const actionName = requireAdapterActionName(action["name"] as string);
  const rawArguments = requireRecord(action["arguments"], "action.arguments");
  const arguments_: ActionArguments = {};
  for (const [name, value] of Object.entries(rawArguments)) {
    requireAdapterArgumentName(name);
    if (
      typeof value !== "string" &&
      typeof value !== "boolean" &&
      !(typeof value === "number" && Number.isSafeInteger(value))
    ) {
      throw new TypeError("action.arguments." + name + " must be a string, integer, or boolean");
    }
    arguments_[name] = value;
  }
  return {
    principal: { id: principalId },
    source: { namespace: sourceNamespace, id: sourceId },
    adapter: {
      id: adapterId,
      contract_version: HOST_ADAPTER_CONTRACT_VERSION,
      capabilities: capabilities.sort(),
    },
    action: { name: actionName, arguments: arguments_ },
  };
}

/**
 * Validate the trusted deployment manifest that maps a host-visible tool and
 * its exact scalar schema to one canonical governed action and owner binding.
 * It is configuration, never model-supplied tool input.
 */
export function validateGovernedRouteManifest(value: unknown): GovernedRouteManifest {
  const manifest = requireRecord(value, "governed route manifest");
  requireExactKeys(manifest, ["contract_version", "routes"], "governed route manifest");
  if (manifest["contract_version"] !== GOVERNED_ROUTE_MANIFEST_VERSION) {
    throw new TypeError("governed route manifest.contract_version is unsupported");
  }
  const rawRoutes = manifest["routes"];
  if (!Array.isArray(rawRoutes) || rawRoutes.length === 0) {
    throw new TypeError("governed route manifest.routes must be a non-empty array");
  }
  requireDenseArray(rawRoutes, "governed route manifest.routes");
  const routeNames = new Set<string>();
  const routes = rawRoutes.map((rawRoute, index) => {
    const context = `governed route manifest.routes[${index}]`;
    const route = requireRecord(rawRoute, context);
    requireExactKeys(route, ["host_tool", "action", "arguments", "owner"], context);
    const host_tool = requireIdentifier(route["host_tool"], `${context}.host_tool`);
    if (routeNames.has(host_tool)) {
      throw new TypeError("governed route manifest.routes must not repeat host_tool");
    }
    routeNames.add(host_tool);
    const action = requireAdapterActionName(route["action"] as string);
    const rawArguments = requireRecord(route["arguments"], `${context}.arguments`);
    const arguments_: Record<string, GovernedArgumentKind> = {};
    for (const [name, kind] of Object.entries(rawArguments)) {
      requireAdapterArgumentName(name);
      if (kind !== "string" && kind !== "integer" && kind !== "boolean") {
        throw new TypeError(`${context}.arguments.${name} must be string, integer, or boolean`);
      }
      arguments_[name] = kind;
    }
    const rawOwner = requireRecord(route["owner"], `${context}.owner`);
    requireExactKeys(
      rawOwner,
      ["provider_id", "position", "connector_id"],
      `${context}.owner`,
    );
    const provider_id = requireIdentifier(rawOwner["provider_id"], `${context}.owner.provider_id`);
    const position = rawOwner["position"];
    let owner: GovernedExecutionOwner;
    if (position === "transactional") {
      if (rawOwner["connector_id"] !== undefined) {
        throw new TypeError(`${context}.owner transactional position cannot name connector_id`);
      }
      owner = { provider_id, position };
    } else if (position === "protected-external") {
      owner = {
        provider_id,
        position,
        connector_id: requireIdentifier(rawOwner["connector_id"], `${context}.owner.connector_id`),
      };
    } else {
      throw new TypeError(`${context}.owner.position is invalid`);
    }
    return { host_tool, action, arguments: arguments_, owner };
  });
  routes.sort((left, right) => left.host_tool < right.host_tool ? -1 : left.host_tool > right.host_tool ? 1 : 0);
  return { contract_version: GOVERNED_ROUTE_MANIFEST_VERSION, routes };
}

/** Deterministic byte representation for cross-language route-manifest vectors. */
export function canonicalGovernedRouteManifest(value: unknown): string {
  return canonicalJson(validateGovernedRouteManifest(value) as unknown as JsonValue);
}
export function operationLocator(result: AdapterLifecycleResult): OperationLocator {
  return result.status === "pending"
    ? { operation_id: result.operation_id, pending_id: result.pending_id }
    : { operation_id: result.operation_id };
}

export function validateOperationLocator(value: unknown): OperationLocator {
  const locator = requireRecord(value, "adapter locator");
  requireExactKeys(locator, ["operation_id", "pending_id"], "adapter locator");
  const operationId = requireUuid(locator["operation_id"], "adapter locator.operation_id");
  if (locator["pending_id"] === undefined) return { operation_id: operationId };
  return {
    operation_id: operationId,
    pending_id: requireUuid(locator["pending_id"], "adapter locator.pending_id"),
  };
}

function validateDecision(value: unknown, expectedEffect: "allow" | "deny" | "escalate") {
  const decision = requireRecord(value, "adapter lifecycle result.decision");
  requireExactKeys(
    decision,
    ["effect", "policy_id", "policy_version", "rule_id", "reason", "evaluated_policies"],
    "adapter lifecycle result.decision",
  );
  if (decision["effect"] !== expectedEffect) {
    throw new TypeError(`adapter lifecycle decision effect must be ${expectedEffect}`);
  }
  const canonical = {
    effect: expectedEffect,
    policy_id: requireString(decision["policy_id"], "adapter lifecycle decision.policy_id"),
    policy_version: requireString(
      decision["policy_version"], "adapter lifecycle decision.policy_version", true,
    ),
    rule_id: requireString(decision["rule_id"], "adapter lifecycle decision.rule_id"),
    reason: requireString(decision["reason"], "adapter lifecycle decision.reason", true),
  };
  const rawEvaluated = decision["evaluated_policies"];
  if (rawEvaluated === undefined) return canonical;
  if (!Array.isArray(rawEvaluated)) {
    throw new TypeError("adapter lifecycle decision.evaluated_policies must be an array");
  }
  requireDenseArray(rawEvaluated, "adapter lifecycle decision.evaluated_policies");
  const seen = new Set<string>();
  const evaluated_policies = rawEvaluated.map((item, index) => {
    const policy = requireRecord(item, `adapter lifecycle decision.evaluated_policies[${index}]`);
    requireExactKeys(
      policy,
      ["policy_id", "policy_version"],
      `adapter lifecycle decision.evaluated_policies[${index}]`,
    );
    const parsed = {
      policy_id: requireString(
        policy["policy_id"], `adapter lifecycle decision.evaluated_policies[${index}].policy_id`,
      ),
      policy_version: requireString(
        policy["policy_version"],
        `adapter lifecycle decision.evaluated_policies[${index}].policy_version`,
        true,
      ),
    };
    const key = JSON.stringify([parsed.policy_id, parsed.policy_version]);
    if (seen.has(key)) {
      throw new TypeError("adapter lifecycle decision.evaluated_policies must be unique");
    }
    seen.add(key);
    return parsed;
  });
  return { ...canonical, evaluated_policies };
}

function validateLifecycleResult(value: unknown): AdapterLifecycleResult {
  const result = requireRecord(value, "adapter lifecycle result");
  requireExactKeys(
    result,
    [
      "operation_id", "pending_id", "status", "decision", "payload",
      "resolution_plan", "reservation_safety_certificate_digest",
      "reservation_entitlement_digest", "audit_ref", "replayed",
    ],
    "adapter lifecycle result",
  );
  const operation_id = requireUuid(
    result["operation_id"], "adapter lifecycle result.operation_id",
  );
  const status = result["status"];
  if (typeof status !== "string" || !LIFECYCLE_STATUSES.has(status as AdapterLifecycleResult["status"])) {
    throw new TypeError("adapter lifecycle result.status is invalid");
  }
  const payload = jsonObject(result["payload"], "adapter lifecycle result.payload");
  const audit_ref = requireAuditRef(
    result["audit_ref"], "adapter lifecycle result.audit_ref", operation_id,
  );
  if (typeof result["replayed"] !== "boolean") {
    throw new TypeError("adapter lifecycle result.replayed must be boolean");
  }
  const replayed = result["replayed"];
  const pendingFields = [
    "pending_id", "resolution_plan", "reservation_safety_certificate_digest",
    "reservation_entitlement_digest",
  ] as const;
  if (status !== "pending" && pendingFields.some((field) => result[field] !== undefined)) {
    throw new TypeError("non-pending adapter lifecycle result must not carry pending metadata");
  }
  if (status === "in_progress" || status === "outcome_unknown") {
    if (result["decision"] !== null) {
      throw new TypeError("operational adapter lifecycle result.decision must be null");
    }
    return { operation_id, status, decision: null, payload, audit_ref, replayed };
  }
  const expectedEffect = status === "committed" ? "allow" : status === "denied" ? "deny" : "escalate";
  const decision = validateDecision(result["decision"], expectedEffect);
  if (status === "committed") {
    return { operation_id, status, decision, payload, audit_ref, replayed } as CommittedActionResult;
  }
  if (status === "denied") {
    return { operation_id, status, decision, payload, audit_ref, replayed } as DeniedActionResult;
  }
  const pending_id = requireUuid(result["pending_id"], "adapter lifecycle result.pending_id");
  const plan = result["resolution_plan"];
  const safety = result["reservation_safety_certificate_digest"];
  const entitlement = result["reservation_entitlement_digest"];
  if (plan === undefined) {
    if (safety !== undefined || entitlement !== undefined) {
      throw new TypeError("adapter lifecycle reservation digests require resolution_plan");
    }
    return { operation_id, pending_id, status, decision, payload, audit_ref, replayed } as PendingActionResult;
  }
  if (plan !== "revalidate" && plan !== "scoped-hold" && plan !== "reservation-proof") {
    throw new TypeError("adapter lifecycle result.resolution_plan is invalid");
  }
  if (plan === "reservation-proof") {
    if (typeof safety !== "string" || !SHA256.test(safety) ||
        typeof entitlement !== "string" || !SHA256.test(entitlement)) {
      throw new TypeError("adapter lifecycle reservation-proof digests must be SHA-256 values");
    }
    return {
      operation_id, pending_id, status, decision, payload, audit_ref, replayed,
      resolution_plan: plan,
      reservation_safety_certificate_digest: safety,
      reservation_entitlement_digest: entitlement,
    } as PendingActionResult;
  }
  if (safety !== undefined || entitlement !== undefined) {
    throw new TypeError("non-proof adapter lifecycle result must not carry reservation digests");
  }
  return {
    operation_id, pending_id, status, decision, payload, audit_ref, replayed,
    resolution_plan: plan,
  } as PendingActionResult;
}

export function validateAdapterLifecycleEnvelope(
  value: unknown,
): AdapterLifecycleEnvelope {
  const envelope = requireRecord(value, "adapter lifecycle");
  requireExactKeys(envelope, ["kind", "invocation", "result", "locator"], "adapter lifecycle");
  if (envelope["kind"] !== "lifecycle") throw new TypeError("adapter lifecycle kind is invalid");
  const invocation = createAdapterInvocation(envelope["invocation"] as AdapterInvocation);
  const result = validateLifecycleResult(envelope["result"]);
  const locator = validateOperationLocator(envelope["locator"]);
  if (result.operation_id !== locator.operation_id) {
    throw new TypeError("adapter lifecycle result and locator operation_id must match");
  }
  if (result.status === "pending") {
    if (locator.pending_id !== result.pending_id) {
      throw new TypeError("adapter lifecycle result and locator pending_id must match");
    }
  } else if (locator.pending_id !== undefined) {
    throw new TypeError("non-pending adapter lifecycle must not carry a pending locator");
  }
  return { kind: "lifecycle", invocation, result, locator } as AdapterLifecycleEnvelope;
}
export function createAdapterLifecycleEnvelope(
  invocation: AdapterInvocation,
  result: AdapterLifecycleResult,
): AdapterLifecycleEnvelope {
  return validateAdapterLifecycleEnvelope({
    kind: "lifecycle",
    invocation,
    result,
    locator: operationLocator(result),
  });
}
export function validateAdapterCancellationEnvelope(
  value: unknown,
): AdapterCancellationEnvelope {
  const envelope = requireRecord(value, "adapter cancellation");
  requireExactKeys(
    envelope, ["kind", "locator", "accepted", "terminal_result"], "adapter cancellation",
  );
  if (envelope["kind"] !== "cancellation" || typeof envelope["accepted"] !== "boolean") {
    throw new TypeError("adapter cancellation is malformed");
  }
  const locator = validateOperationLocator(envelope["locator"]);
  if (locator.pending_id === undefined) {
    throw new TypeError("adapter cancellation locator must include pending_id");
  }
  const pendingLocator: PendingOperationLocator = locator;
  const accepted = envelope["accepted"];
  if (accepted && envelope["terminal_result"] !== undefined) {
    throw new TypeError("accepted adapter cancellation must not carry a terminal result");
  }
  if (envelope["terminal_result"] === undefined) {
    return {
      kind: "cancellation", locator: pendingLocator, accepted,
    } as AdapterCancellationEnvelope;
  }
  const terminal = validateLifecycleResult(envelope["terminal_result"]);
  if (terminal.status !== "committed" && terminal.status !== "denied") {
    throw new TypeError("adapter cancellation terminal_result must be committed or denied");
  }
  if (terminal.operation_id !== pendingLocator.operation_id) {
    throw new TypeError("adapter cancellation result and locator operation_id must match");
  }
  return {
    kind: "cancellation", locator: pendingLocator, accepted: false, terminal_result: terminal,
  };
}

export function validateAdapterReceiptEnvelope(value: unknown): AdapterReceiptEnvelope {
  const receipt = requireRecord(value, "adapter receipt");
  requireExactKeys(
    receipt, ["kind", "locator", "audit_ref", "status", "marker"], "adapter receipt",
  );
  if (receipt["kind"] !== "receipt") throw new TypeError("adapter receipt kind is invalid");
  const status = receipt["status"];
  if (typeof status !== "string" || !LIFECYCLE_STATUSES.has(status as AdapterLifecycleResult["status"])) {
    throw new TypeError("adapter receipt.status is invalid");
  }
  const locator = validateOperationLocator(receipt["locator"]);
  return {
    kind: "receipt",
    locator,
    audit_ref: requireAuditRef(
      receipt["audit_ref"], "adapter receipt.audit_ref", locator.operation_id,
    ),
    status: status as AdapterLifecycleResult["status"],
    marker: requireString(receipt["marker"], "adapter receipt.marker"),
  };
}
/** Deterministic semantic representation for conformance tests. */
export function canonicalAdapterEnvelope(envelope: AdapterEnvelope): string {
  let canonical: AdapterEnvelope;
  if ("kind" in envelope && envelope.kind === "lifecycle") {
    canonical = validateAdapterLifecycleEnvelope(envelope);
  } else if ("kind" in envelope && envelope.kind === "cancellation") {
    canonical = validateAdapterCancellationEnvelope(envelope);
  } else if ("kind" in envelope && envelope.kind === "receipt") {
    canonical = validateAdapterReceiptEnvelope(envelope);
  } else {
    canonical = createAdapterInvocation(envelope as AdapterInvocation);
  }
  return canonicalJson(canonical as unknown as JsonValue);
}
export function canonicalJson(value: JsonValue): string {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") return canonicalString(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${canonicalString(key)}:${canonicalJson(value[key] as JsonValue)}`)
    .join(",")}}`;
}
function canonicalString(value: string): string {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 < value.length) {
        const next = value.charCodeAt(index + 1);
        if (next >= 0xdc00 && next <= 0xdfff) {
          index += 1;
          continue;
        }
      }
      throw new TypeError("canonical JSON strings must not contain unpaired surrogate code units");
    }
    if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError("canonical JSON strings must not contain unpaired surrogate code units");
    }
  }
  return JSON.stringify(value);
}

/**
 * Deterministic no-I/O responder for conformance. It neither evaluates policy,
 * invokes providers, retains durable work, nor performs native host effects.
 */
export class ScriptedAdapterResponder implements HostAdapterResponder {
  readonly #records = new Map<string, {
    binding: string;
    lifecycle: AdapterLifecycleEnvelope;
  }>();
  readonly #cancelled = new Set<string>();

  async submit(invocation: AdapterInvocation): Promise<AdapterLifecycleEnvelope> {
    const canonical = createAdapterInvocation(invocation);
    const key = JSON.stringify([
      canonical.principal.id,
      canonical.source.namespace,
      canonical.source.id,
    ]);
    const binding = canonicalAdapterEnvelope(canonical);
    const prior = this.#records.get(key);
    if (prior !== undefined) {
      if (prior.binding !== binding) {
        throw new TypeError("source invocation is already bound to a different canonical request");
      }
      return structuredClone(createAdapterLifecycleEnvelope(
        prior.lifecycle.invocation,
        { ...prior.lifecycle.result, replayed: true } as AdapterLifecycleResult,
      ));
    }
    const suffix = canonical.action.name.startsWith("canary.")
      ? canonical.action.name.slice("canary.".length) : "";
    const operationId = this.#fixtureId("1");
    let result: ActionResult;
    if (suffix === "allow") result = this.#result(operationId, "committed", canonical.action.arguments);
    else if (suffix === "deny") result = this.#result(operationId, "denied", canonical.action.arguments);
    else if (suffix === "pending") result = this.#pendingResult(operationId, canonical.action.arguments);
    else throw new TypeError("scripted responder accepts only canary.allow, canary.deny, or canary.pending");
    const lifecycle = createAdapterLifecycleEnvelope(canonical, result);
    const stored = structuredClone(lifecycle);
    this.#records.set(key, { binding, lifecycle: stored });
    return structuredClone(stored);
  }

  async locate(locator: OperationLocator): Promise<AdapterLifecycleEnvelope | undefined> {
    const record = [...this.#records.values()].map(({ lifecycle }) => lifecycle).find((candidate) =>
      candidate.locator.operation_id === locator.operation_id &&
      candidate.locator.pending_id === locator.pending_id,
    );
    return record?.invocation.adapter.capabilities.includes("locator")
      ? structuredClone(record)
      : undefined;
  }
  async cancel(locator: PendingOperationLocator): Promise<AdapterCancellationEnvelope> {
    const lifecycle = [...this.#records.values()].map(({ lifecycle }) => lifecycle).find((record) =>
      record.locator.operation_id === locator.operation_id &&
      record.locator.pending_id === locator.pending_id,
    );
    if (!lifecycle?.invocation.adapter.capabilities.includes("cancellation")) {
      return { kind: "cancellation", locator, accepted: false };
    }
    if (lifecycle.result.status === "committed" || lifecycle.result.status === "denied") {
      return validateAdapterCancellationEnvelope({
        kind: "cancellation", locator, accepted: false,
        terminal_result: structuredClone(lifecycle.result as TerminalActionResult),
      });
    }
    if (lifecycle.result.status !== "pending") {
      return { kind: "cancellation", locator, accepted: false };
    }
    this.#cancelled.add(locator.operation_id);
    return { kind: "cancellation", locator, accepted: true };
  }
  async receipt(locator: OperationLocator): Promise<AdapterReceiptEnvelope | undefined> {
    const lifecycle = [...this.#records.values()].map(({ lifecycle }) => lifecycle).find((record) =>
      record.locator.operation_id === locator.operation_id &&
      record.locator.pending_id === locator.pending_id,
    );
    if (lifecycle === undefined || !lifecycle.invocation.adapter.capabilities.includes("receipt")) return undefined;
    return {
      kind: "receipt", locator: structuredClone(lifecycle.locator),
      audit_ref: lifecycle.result.audit_ref,
      status: lifecycle.result.status,
      marker: this.#cancelled.has(locator.operation_id) ? "cancellation-requested" : "scripted",
    };
  }
  #result(operationId: string, status: "committed" | "denied", payload: ActionArguments): ActionResult {
    const effect = status === "committed" ? "allow" : "deny";
    return {
      operation_id: operationId, status,
      decision: {
        effect, policy_id: "contract-canary", policy_version: "v1",
        rule_id: "canary-" + effect, reason: "scripted adapter conformance outcome",
      },
      payload: { ...payload }, audit_ref: "/v1/audit/" + operationId, replayed: false,
    } as ActionResult;
  }
  #fixtureId(prefix: "1" | "2"): string {
    return "00000000-0000-4000-8000-" + prefix + (this.#records.size + 1).toString(16).padStart(11, "0");
  }
  #pendingResult(operationId: string, payload: ActionArguments): PendingActionResult {
    return {
      operation_id: operationId, status: "pending",
      pending_id: this.#fixtureId("2"),
      decision: {
        effect: "escalate", policy_id: "contract-canary", policy_version: "v1",
        rule_id: "canary-pending", reason: "scripted adapter conformance outcome",
      },
      payload: { ...payload }, audit_ref: "/v1/audit/" + operationId, replayed: false,
      resolution_plan: "revalidate",
    };
  }
}
