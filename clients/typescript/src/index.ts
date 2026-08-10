/** JSON values accepted by the Governed Action Protocol. */
import { validateAdapterCancellationEnvelope } from "./adapter-contract.js";
import type { AdapterCancellationEnvelope } from "./adapter-contract.js";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export interface JsonObject {
  [key: string]: JsonValue;
}

/** Scalar values accepted by the current `masugated` action contract. */
export type ActionArgument = string | number | boolean;
export type ActionArguments = Record<string, ActionArgument>;
export type PendingResolutionPlan = "revalidate" | "scoped-hold" | "reservation-proof";

export interface PendingResolutionMetadata {
  resolution_plan?: PendingResolutionPlan;
  reservation_safety_certificate_digest?: string;
  reservation_entitlement_digest?: string;
}

export interface EvaluatedPolicy {
  policy_id: string;
  policy_version: string;
}

interface DecisionBase<Effect extends "allow" | "deny" | "escalate"> {
  effect: Effect;
  policy_id: string;
  policy_version: string;
  rule_id: string;
  reason: string;
  evaluated_policies?: EvaluatedPolicy[];
}

export type AllowDecision = DecisionBase<"allow">;
export type DenyDecision = DecisionBase<"deny">;
export type EscalateDecision = DecisionBase<"escalate">;
export type ActionDecision = AllowDecision | DenyDecision | EscalateDecision;

interface ActionResultBase<
  Status extends "committed" | "denied" | "pending" | "in_progress" | "outcome_unknown",
  Decision extends ActionDecision | null,
  Payload extends JsonObject,
> {
  operation_id: string;
  status: Status;
  decision: Decision;
  payload: Payload;
  audit_ref: string;
  replayed: boolean;
}

export interface CommittedActionResult<Payload extends JsonObject = JsonObject>
  extends ActionResultBase<"committed", AllowDecision, Payload> {
  pending_id?: never;
}

export interface DeniedActionResult<Payload extends JsonObject = JsonObject>
  extends ActionResultBase<"denied", DenyDecision, Payload> {
  pending_id?: never;
}

export interface PendingActionResult<Payload extends JsonObject = JsonObject>
  extends ActionResultBase<"pending", EscalateDecision, Payload>,
    PendingResolutionMetadata {
  pending_id: string;
}

export interface InProgressActionResult<Payload extends JsonObject = JsonObject>
  extends ActionResultBase<"in_progress", null, Payload> {
  pending_id?: never;
}

export interface OutcomeUnknownActionResult<Payload extends JsonObject = JsonObject>
  extends ActionResultBase<"outcome_unknown", null, Payload> {
  pending_id?: never;
}

export type ActionResult<Payload extends JsonObject = JsonObject> =
  | CommittedActionResult<Payload>
  | DeniedActionResult<Payload>
  | PendingActionResult<Payload>
  | InProgressActionResult<Payload>
  | OutcomeUnknownActionResult<Payload>;

export type TerminalActionResult<Payload extends JsonObject = JsonObject> =
  | CommittedActionResult<Payload>
  | DeniedActionResult<Payload>;

export type ResolvedActionResult<Payload extends JsonObject = JsonObject> =
  | TerminalActionResult<Payload>
  | InProgressActionResult<Payload>
  | OutcomeUnknownActionResult<Payload>;

export interface PendingDecision {
  effect: "escalate";
  policy_id: string;
  policy_version: string;
  rule_id: string;
  reason: string;
}

export interface PendingOperation extends PendingResolutionMetadata {
  pending_id: string;
  operation_id: string;
  principal_id: string;
  action: string;
  args: JsonObject;
  created_at: string;
  decision: PendingDecision;
  audit_ref: string;
}

export interface PendingList {
  items: PendingOperation[];
  next_cursor: string;
}

/** Owner-scoped durable lookup for a pending locator after host restart. */
export type PendingLookup<Payload extends JsonObject = JsonObject> =
  | { kind: "pending"; pending: PendingOperation }
  | { kind: "terminal"; result: ResolvedActionResult<Payload> };

export interface PendingEvent {
  event_id: string;
  event_type: "pending.created";
  occurred_at: string;
  pending: PendingOperation;
}

export type PrincipalAttribute = string | number | boolean;

export interface ProtectedArtifactMetadata {
  reference: string;
  content_digest: string;
  content_bytes: number;
  media_type: string;
  classification: string;
  expires_at: string;
  inspector_version: string;
}

export interface CertifiedRequest {
  idempotency_key: string;
  principal: {
    id: string;
    attributes: Record<string, PrincipalAttribute>;
  };
  action: string;
  args: JsonObject;
  timestamp: string;
  request_time: string;
  trace_id?: string | null;
  adapter_invocation_digest?: string;
  protected_artifacts?: Record<string, ProtectedArtifactMetadata>;
}

export interface PolicyReceipt {
  policy_id: string;
  policy_version: string;
  evaluated_policies: EvaluatedPolicy[];
  evaluated_policy_provenance: PolicyProvenance[];
  catalog?: PolicyCatalog;
}

export interface PolicyCatalog {
  policy_digest: string;
  bundle_digest: string;
}

export interface AuditEntitlement {
  entitlement_id: string;
  authorization_digest: string;
}

export interface PolicyProvenance {
  policy_id: string;
  policy_declared_version: string;
  policy_runtime_version: string;
  policy_digest: string;
  bundle_id: string;
  bundle_version: string;
  bundle_digest: string;
  layer: "platform-safety" | "deployment-regulatory" | "owner";
  mode: "mandatory" | "configurable";
}

export interface ViewRead {
  function: string;
  arguments: JsonValue[];
  value: JsonValue;
  scope: string;
  version: number;
  latency_ms: number;
}

export interface AppliedEffect<Payload extends JsonObject = JsonObject> {
  action: string;
  args: JsonObject;
  payload: Payload;
}

export interface CertifiedInputEvidence {
  name: string;
  value: JsonValue;
  value_type: "Bool" | "Int" | "String" | "Duration";
  stability: "admission-stable" | "resolution-volatile";
  stability_proof: "request-bound-immutable-v1" | null;
  source_id: string;
  source_version: string;
  contract_version: string;
  observed_at: string;
  certified_at: string;
  freshness_ttl_seconds: number;
  expires_at: string;
  phase: "admission" | "resolution";
}

export interface AuthorizationEvaluation {
  phase: "admission" | "resolution";
  evaluated_at: string;
  decision: AuthorizationDecision;
  certified_inputs: CertifiedInputEvidence[];
}

export type AuthorizationDecision = ActionDecision & {
  policy_provenance: PolicyProvenance[];
};

export interface TerminalSerialization {
  kind: "effect-commit" | "denial-record";
  authorization_basis: string;
  provider_atomic: boolean;
  recorded_at: string;
  evaluation_phase?: "admission" | "resolution";
  evaluation_at?: string;
}

export interface HumanResolution {
  approved: boolean;
  evidence: JsonObject;
  actor_id?: string;
  resolved_at?: string;
}

export interface AutomaticExpiry {
  expires_at: string;
  reason: "approval-window-expired";
}

export type ProtectedExecutionStatus =
  | "intent"
  | "executing"
  | "succeeded"
  | "failed"
  | "outcome_unknown";

export type ProtectedEntitlementState = "held" | "consumed" | "released" | "quarantined";
export type ProtectedConnectorOutcome = "succeeded" | "failed" | "unknown";

export interface ProtectedConnectorEvidence {
  connector_id: string;
  evidence_id: string;
  idempotency_key: string;
  external_operation_id: string | null;
  outcome: ProtectedConnectorOutcome;
  observed_at: string;
  payload: JsonObject;
}

export interface ProtectedExecutionAuditEvent {
  sequence: number;
  event_type: string;
  from_status: ProtectedExecutionStatus | null;
  to_status: ProtectedExecutionStatus;
  worker_id: string | null;
  fence_token: number | null;
  recorded_at: string;
  evidence: JsonObject;
}

export interface ProtectedExecutionAudit {
  execution_id: string;
  binding_digest: string;
  binding: JsonObject;
  binding_canonical_json: string;
  status: ProtectedExecutionStatus;
  entitlement_state: ProtectedEntitlementState;
  dispatch_started: boolean;
  cancel_requested: boolean;
  external_operation_id: string | null;
  lease: { owner: string; fence_token: number; expires_at: string } | null;
  last_fence_token: number;
  receipt: ProtectedConnectorEvidence | null;
  result: JsonObject;
  created_at: string;
  updated_at: string;
  events: ProtectedExecutionAuditEvent[];
}

interface AuditRecordBase<
  Status extends "committed" | "denied" | "pending" | "in_progress" | "outcome_unknown",
  Effect extends "allow" | "deny" | "escalate" | null,
> extends PendingResolutionMetadata {
  operation_id: string;
  status: Status;
  request: CertifiedRequest;
  policy: PolicyReceipt;
  decision: Effect extends null
    ? null
    : {
        effect: Exclude<Effect, null>;
        rule_id: string;
        reason: string;
      };
  view_reads: ViewRead[];
  authorization_evaluations: AuthorizationEvaluation[];
  terminal_serialization: TerminalSerialization | null;
  human_resolution?: HumanResolution;
  automatic_expiry?: AutomaticExpiry;
  protected_execution?: ProtectedExecutionAudit;
  entitlement?: AuditEntitlement;
  recorded_at: string;
}

export interface CommittedAuditRecord<Payload extends JsonObject = JsonObject>
  extends AuditRecordBase<"committed", "allow"> {
  effect: AppliedEffect<Payload>;
}

export interface DeniedAuditRecord extends AuditRecordBase<"denied", "deny"> {
  effect: null;
}

export interface PendingAuditRecord extends AuditRecordBase<"pending", "escalate"> {
  effect: null;
}

export interface InProgressAuditRecord extends AuditRecordBase<"in_progress", null> {
  effect: null;
}

export interface OutcomeUnknownAuditRecord
  extends AuditRecordBase<"outcome_unknown", null> {
  effect: null;
}

export type AuditRecord<Payload extends JsonObject = JsonObject> =
  | CommittedAuditRecord<Payload>
  | DeniedAuditRecord
  | PendingAuditRecord
  | InProgressAuditRecord
  | OutcomeUnknownAuditRecord;

export interface MasuGateClientOptions {
  /** Base URL of `masugated`, optionally including a deployment path prefix. */
  baseUrl: string;
  /** Opaque bearer credential mapped to a principal by `masugated`. */
  token: string;
  /**
   * Optional expected subject for the bearer credential. When set, `masugated`
   * rejects the request before policy evaluation if the credential is mapped
   * to a different principal.
   */
  principalId?: string;
  /** Optional fetch-compatible transport, primarily for controlled runtimes and tests. */
  fetch?: typeof globalThis.fetch;
}

export interface ExecuteOptions {
  action: string;
  args: ActionArguments;
  /** Stable identifier for this logical action. Reuse it only for exact retries. */
  stableId: string;
  /** Per-invocation authenticated subject assertion for host-adapter calls. */
  expectedPrincipal?: string;
  /** Canonical masugate.host-adapter.v1 JSON bound durably to idempotent replay. */
  adapterInvocation?: string;
  /**
   * Expected server-owned execution binding. When present, `masugated` rejects an
   * unknown or mismatched provider/position/connector before policy or effect
   * execution. Transactional effects have no connector.
   */
  owner?: {
    providerId: string;
  } & (
    | {
        position: "transactional";
        connectorId?: never;
      }
    | {
        position: "protected-external";
        connectorId: string;
      }
  );
  traceId?: string;
  signal?: AbortSignal;
}

/** Server-certified metadata for one opaque connector ecosystem operation payload. */
export interface StagedArtifact {
  reference: string;
  content_digest: string;
  content_bytes: number;
  media_type: string;
  classification: string;
  expires_at: string;
}

export interface StageArtifactOptions {
  action: string;
  field: string;
  /** Raw bytes; the SDK performs the only base64 encoding. */
  content: Uint8Array;
  mediaType: string;
  /** Reuse the logical action's stable id for exact staging retries. */
  stableId: string;
  /** Canonical masugate.host-adapter.v1 invocation for the declared action. */
  adapterInvocation: string;
  signal?: AbortSignal;
}

export interface ResolvePendingOptions {
  pendingId: string;
  approved: boolean;
  evidence?: JsonObject;
  signal?: AbortSignal;
}

export interface StreamPendingOptions {
  /** Close after replaying the current durable unresolved snapshot. */
  once?: boolean;
  /** Resume after this at-least-once event cursor. */
  lastEventId?: string;
  signal?: AbortSignal;
}

export interface RequestOptions {
  signal?: AbortSignal;
}

/** Options for a bounded operator cancellation of one durable pending locator. */
export interface CancelPendingOptions extends RequestOptions {
  pendingId: string;
}

export {
  GOVERNED_ROUTE_MANIFEST_VERSION,
  HOST_ADAPTER_CONTRACT_VERSION,
  RESERVED_ADAPTER_ARGUMENT_NAMES,
  ScriptedAdapterResponder,
  canonicalAdapterEnvelope,
  canonicalGovernedRouteManifest,
  createAdapterLifecycleEnvelope,
  createAdapterInvocation,
  operationLocator,
  requireAdapterActionName,
  requireAdapterArgumentName,
  validateGovernedRouteManifest,
  validateAdapterCancellationEnvelope,
  validateAdapterLifecycleEnvelope,
  validateAdapterReceiptEnvelope,
  validateOperationLocator,
} from "./adapter-contract.js";
export {
  DEFAULT_ROUTE_MANIFEST_CANONICAL_BYTES,
  DEFAULT_ROUTE_SCHEMA_CANONICAL_BYTES,
  GOVERNED_ROUTE_MANIFEST_V2_VERSION,
  MAX_GOVERNED_ROUTE_MANIFEST_ROUTES,
  MAX_ROUTE_ARTIFACT_FIELDS,
  MAX_ROUTE_CONNECTOR_CAPABILITIES,
  canonicalAnyGovernedRouteManifest,
  canonicalGovernedRouteManifestV2,
  validateAnyGovernedRouteManifest,
  validateGovernedRouteManifestV2,
} from "./operation-contract.js";
export type {
  AnyGovernedRouteManifest,
  GovernedRouteManifestV2,
  GovernedRouteV2,
} from "./operation-contract.js";
export type {
  AcceptedAdapterCancellationEnvelope,
  AdapterCapability,
  AdapterCancellationEnvelope,
  AdapterEnvelope,
  AdapterInvocation,
  AdapterLifecycleEnvelope,
  AdapterLifecycleResult,
  AdapterOperationalResult,
  AdapterOperationalStatus,
  AdapterReceiptEnvelope,
  AuthenticatedAdapterPrincipal,
  HostAdapterResponder,
  GovernedArgumentKind,
  GovernedExecutionOwner,
  GovernedRouteManifest,
  GovernedToolRoute,
  NonPendingOperationLocator,
  OperationLocator,
  PendingOperationLocator,
  RejectedAdapterCancellationEnvelope,
  SourceInvocation,
} from "./adapter-contract.js";

/** A non-2xx response using the Governed Action Protocol error envelope. */
export class MasuGateHttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: JsonValue | undefined;

  constructor(
    message: string,
    options: { status: number; code: string; details?: JsonValue },
  ) {
    super(message);
    this.name = "MasuGateHttpError";
    this.status = options.status;
    this.code = options.code;
    this.details = options.details;
  }
}

/** A successful HTTP response that violates the expected wire contract. */
export class MasuGateProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MasuGateProtocolError";
  }
}

const IDEMPOTENCY_PREFIX = "masugate:v1:";
const MAX_ARTIFACT_BYTES = 8 * 1024 * 1024;

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= value.length) return true;
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

async function sha256Hex(value: string): Promise<string> {
  const webCrypto = globalThis.crypto as Crypto | undefined;
  if (webCrypto?.subtle === undefined) {
    throw new TypeError("Web Crypto crypto.subtle is unavailable");
  }
  const digest = await webCrypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}

/** Compare parsed JSON without attempting to recreate foreign canonical bytes. */
function jsonValuesEqual(left: JsonValue, right: JsonValue): boolean {
  if (left === null || right === null || typeof left !== "object" || typeof right !== "object") {
    return Object.is(left, right);
  }
  if (Array.isArray(left) || Array.isArray(right)) {
    return Array.isArray(left) && Array.isArray(right) && left.length === right.length &&
      left.every((item, index) => jsonValuesEqual(item, right[index]!));
  }
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  return leftKeys.length === rightKeys.length && leftKeys.every(
    (key, index) => key === rightKeys[index] && jsonValuesEqual(left[key]!, right[key]!),
  );
}

/**
 * Deterministically hash and namespace a caller-owned stable id for `masugated`.
 *
 * SHA-256 over the UTF-8 stable id produces the same bounded key in every SDK.
 */
export async function deriveIdempotencyKey(stableId: string): Promise<string> {
  if (stableId.length === 0) {
    throw new TypeError("stableId must not be empty");
  }
  return `${IDEMPOTENCY_PREFIX}${await sha256Hex(stableId)}`;
}

/** Zero-runtime-dependency client for the `masugated` HTTP service. */
export class MasuGateClient {
  readonly #baseUrl: string;
  readonly #token: string;
  readonly #principalId: string | undefined;
  readonly #fetch: typeof globalThis.fetch;

  constructor(options: MasuGateClientOptions) {
    if (options.token.length === 0) {
      throw new TypeError("token must not be empty");
    }
    if (
      options.principalId !== undefined &&
      (options.principalId.trim().length === 0 || options.principalId.trim() !== options.principalId)
    ) {
      throw new TypeError("principalId must be a non-empty, trimmed string");
    }

    let baseUrl: URL;
    try {
      baseUrl = new URL(options.baseUrl);
    } catch (error) {
      throw new TypeError("baseUrl must be an absolute URL", { cause: error });
    }
    if (baseUrl.protocol !== "http:" && baseUrl.protocol !== "https:") {
      throw new TypeError("baseUrl must use http or https");
    }
    baseUrl.search = "";
    baseUrl.hash = "";

    const fetchImplementation = options.fetch ?? globalThis.fetch;
    if (typeof fetchImplementation !== "function") {
      throw new TypeError("global fetch is unavailable; Node.js 20 or newer is required");
    }

    this.#baseUrl = baseUrl.toString().replace(/\/$/u, "");
    this.#token = options.token;
    this.#principalId = options.principalId;
    this.#fetch = fetchImplementation.bind(globalThis);
  }

  /** Execute an effect under policy. This is never a detached authorization check. */
  async execute<Payload extends JsonObject = JsonObject>(
    options: ExecuteOptions,
  ): Promise<ActionResult<Payload>> {
    if (options.action.length === 0) {
      throw new TypeError("action must not be empty");
    }
    validateActionArguments(options.args);

    const body: {
      action: string;
      args: JsonObject;
      idempotency_key: string;
      trace_id?: string;
      adapter_invocation?: string;
    } = {
      action: options.action,
      args: options.args,
      idempotency_key: await deriveIdempotencyKey(options.stableId),
    };
    if (options.traceId !== undefined) {
      body.trace_id = options.traceId;
    }
    if (options.adapterInvocation !== undefined) {
      if (
        hasUnpairedSurrogate(options.adapterInvocation)
        || Array.from(options.adapterInvocation).length === 0
        || Array.from(options.adapterInvocation).length > 16_384
      ) {
        throw new TypeError("adapterInvocation must be a non-empty canonical string of at most 16384 characters");
      }
      body.adapter_invocation = options.adapterInvocation;
    }

    const ownerHeaders: Record<string, string> = {};
    if (options.expectedPrincipal !== undefined) {
      requireIdentifier("expectedPrincipal", options.expectedPrincipal);
      ownerHeaders["MasuGate-Expected-Principal"] = options.expectedPrincipal;
    }
    if (options.owner !== undefined) {
      requireIdentifier("owner.providerId", options.owner.providerId);
      ownerHeaders["MasuGate-Expected-Provider"] = options.owner.providerId;
      ownerHeaders["MasuGate-Expected-Position"] = options.owner.position;
      if (options.owner.position === "protected-external") {
        requireIdentifier("owner.connectorId", options.owner.connectorId);
        ownerHeaders["MasuGate-Expected-Connector"] = options.owner.connectorId;
      }
    }

    return this.#requestJson(
      "/v1/actions",
      this.#jsonRequest("POST", body, options.signal, ownerHeaders),
      parseActionResult<Payload>,
    );
  }

  /**
   * Stage declared bytes before the matching connector ecosystem protected handoff.
   *
   * The returned reference is opaque and cannot be passed to `execute`.
   * Only the trusted server resolves it from authenticated binding facts when
   * it builds the provider/connector handoff.
   */
  async stageArtifact(options: StageArtifactOptions): Promise<StagedArtifact> {
    requireIdentifier("action", options.action);
    requireIdentifier("field", options.field);
    requireIdentifier("mediaType", options.mediaType);
    if (!(options.content instanceof Uint8Array)) {
      throw new TypeError("content must be a Uint8Array");
    }
    if (options.content.byteLength > MAX_ARTIFACT_BYTES) {
      throw new TypeError("content exceeds the connector ecosystem artifact byte limit");
    }
    const adapterInvocationCodePoints = Array.from(options.adapterInvocation).length;
    if (
      hasUnpairedSurrogate(options.adapterInvocation)
      || adapterInvocationCodePoints === 0
      || adapterInvocationCodePoints > 16_384
    ) {
      throw new TypeError(
        "adapterInvocation must be a non-empty canonical string of at most 16384 characters",
      );
    }
    const body = {
      action: options.action,
      field: options.field,
      idempotency_key: await deriveIdempotencyKey(options.stableId),
      media_type: options.mediaType,
      content_base64: base64Encode(options.content),
      adapter_invocation: options.adapterInvocation,
    };
    return this.#requestJson(
      "/v1/artifacts",
      this.#jsonRequest("POST", body, options.signal),
      parseStagedArtifact,
    );
  }

  /** Submit a human resolution; `masugated` re-enters enforcement before executing. */
  async resolvePending<Payload extends JsonObject = JsonObject>(
    options: ResolvePendingOptions,
  ): Promise<ResolvedActionResult<Payload>> {
    requireIdentifier("pendingId", options.pendingId);
    const body: { approved: boolean; evidence?: JsonObject } = {
      approved: options.approved,
    };
    if (options.evidence !== undefined) {
      body.evidence = options.evidence;
    }

    return this.#requestJson(
      `/v1/pending/${encodeURIComponent(options.pendingId)}/resolve`,
      this.#jsonRequest("POST", body, options.signal),
      parseResolvedActionResult<Payload>,
    );
  }

  /** Fetch the durable pending snapshot used by native-approval reconciliation. */
  async listPending(options: RequestOptions = {}): Promise<PendingList> {
    const request: RequestInit = {
      method: "GET",
      headers: this.#headers(true),
    };
    if (options.signal !== undefined) {
      request.signal = options.signal;
    }
    return this.#requestJson("/v1/pending", request, parsePendingList);
  }

  /**
   * Fetch one caller-owned locator, including a terminal replay once it has
   * left the unresolved list. This read has no approval or effect authority.
   */
  async getPending<Payload extends JsonObject = JsonObject>(
    pendingId: string,
    options: RequestOptions = {},
  ): Promise<PendingLookup<Payload>> {
    requireIdentifier("pendingId", pendingId);
    const request: RequestInit = {
      method: "GET",
      headers: this.#headers(true),
    };
    if (options.signal !== undefined) {
      request.signal = options.signal;
    }
    return this.#requestJson(
      `/v1/pending/${encodeURIComponent(pendingId)}`,
      request,
      parsePendingLookup<Payload>,
    );
  }

  /**
   * Ask MasuGate to cancel one pending locator.  An accepted acknowledgement is
   * deliberately nonterminal; callers must re-read the locator or receipt.
   */
  async cancelPending(options: CancelPendingOptions): Promise<AdapterCancellationEnvelope> {
    requireIdentifier("pendingId", options.pendingId);
    return this.#requestJson(
      `/v1/pending/${encodeURIComponent(options.pendingId)}/cancel`,
      this.#jsonRequest("POST", {}, options.signal),
      (value) => {
        const cancellation = validateAdapterCancellationEnvelope(value);
        if (cancellation.locator.pending_id !== options.pendingId) {
          throw new MasuGateProtocolError("cancellation pending_id does not match the requested id");
        }
        return cancellation;
      },
    );
  }

  /**
   * Iterate `pending.created` Server-Sent Events.
   *
   * Delivery is at least once. Consumers should persist and deduplicate by
   * `event_id`, then reconnect with `lastEventId` when needed.
   */
  async *streamPending(
    options: StreamPendingOptions = {},
  ): AsyncGenerator<PendingEvent, void, undefined> {
    if (options.lastEventId !== undefined) {
      requireIdentifier("lastEventId", options.lastEventId);
    }

    const headers: Record<string, string> = {
      Accept: "text/event-stream",
      Authorization: `Bearer ${this.#token}`,
    };
    if (this.#principalId !== undefined) {
      headers["MasuGate-Expected-Principal"] = this.#principalId;
    }
    if (options.lastEventId !== undefined) {
      headers["Last-Event-ID"] = options.lastEventId;
    }
    const request: RequestInit = { method: "GET", headers };
    if (options.signal !== undefined) {
      request.signal = options.signal;
    }

    const suffix = options.once === true ? "?once=true" : "";
    const response = await this.#fetch(
      `${this.#baseUrl}/v1/pending/stream${suffix}`,
      request,
    );
    if (!response.ok) {
      throw await httpError(response);
    }
    if (response.body === null) {
      throw new MasuGateProtocolError("pending stream response has no body");
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    const parser = new PendingEventSseParser();
    let completed = false;
    try {
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) {
          completed = true;
          for (const event of parser.push(decoder.decode(), true)) {
            yield event;
          }
          return;
        }
        for (const event of parser.push(decoder.decode(chunk.value, { stream: true }))) {
          yield event;
        }
      }
    } finally {
      if (!completed) {
        try {
          await reader.cancel();
        } catch {
          // Preserve the consumer's original return/throw while cancelling.
        }
      }
      reader.releaseLock();
    }
  }

  /** Fetch the immutable governance receipt for an operation. */
  async getAudit<Payload extends JsonObject = JsonObject>(
    operationId: string,
    options: RequestOptions = {},
  ): Promise<AuditRecord<Payload>> {
    requireIdentifier("operationId", operationId);
    const request: RequestInit = {
      method: "GET",
      headers: this.#headers(false),
    };
    if (options.signal !== undefined) {
      request.signal = options.signal;
    }
    const record = await this.#requestJson(
      `/v1/audit/${encodeURIComponent(operationId)}`,
      request,
      parseAuditRecord<Payload>,
    );
    if (record.operation_id !== operationId) {
      throw new MasuGateProtocolError("audit operation_id does not match the requested id");
    }
    return record;
  }

  #headers(json: boolean): Record<string, string> {
    const headers: Record<string, string> = {
      Accept: "application/json",
      Authorization: `Bearer ${this.#token}`,
    };
    if (json) {
      headers["Content-Type"] = "application/json";
    }
    if (this.#principalId !== undefined) {
      headers["MasuGate-Expected-Principal"] = this.#principalId;
    }
    return headers;
  }

  #jsonRequest(
    method: "POST",
    body: object,
    signal: AbortSignal | undefined,
    additionalHeaders: Readonly<Record<string, string>> = {},
  ): RequestInit {
    const request: RequestInit = {
      method,
      headers: { ...this.#headers(true), ...additionalHeaders },
      body: JSON.stringify(body),
    };
    if (signal !== undefined) {
      request.signal = signal;
    }
    return request;
  }

  async #requestJson<Result>(
    path: string,
    request: RequestInit,
    parse: (value: unknown) => Result | Promise<Result>,
  ): Promise<Result> {
    const response = await this.#fetch(`${this.#baseUrl}${path}`, request);
    if (!response.ok) {
      throw await httpError(response);
    }
    return await parse(await responseJson(response));
  }
}

function requireIdentifier(name: string, value: string): void {
  if (value.length === 0) {
    throw new TypeError(`${name} must not be empty`);
  }
}

function base64Encode(content: Uint8Array): string {
  if (typeof globalThis.btoa !== "function") {
    throw new TypeError("base64 encoding is unavailable; Node.js 20 or a browser is required");
  }
  let binary = "";
  // Avoid spreading an unbounded byte array into String.fromCharCode.
  for (let offset = 0; offset < content.length; offset += 8192) {
    binary += String.fromCharCode(...content.subarray(offset, offset + 8192));
  }
  return globalThis.btoa(binary);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOwn(record: Record<string, unknown>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, key);
}

function validateActionArguments(args: ActionArguments): void {
  if (!isObject(args)) {
    throw new TypeError("args must be an object of scalar values");
  }
  for (const [key, value] of Object.entries(args)) {
    if (typeof value === "string" || typeof value === "boolean") {
      continue;
    }
    if (typeof value === "number" && Number.isSafeInteger(value)) {
      continue;
    }
    throw new TypeError(
      `args.${key} must be a string, boolean, or safe integer`,
    );
  }
}

function contractObject(
  value: unknown,
  context: string,
  allowed: readonly string[],
  required: readonly string[],
): Record<string, unknown> {
  if (!isObject(value)) {
    throw new MasuGateProtocolError(`${context} must be an object`);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      throw new MasuGateProtocolError(`${context}.${key} is not allowed`);
    }
  }
  for (const key of required) {
    if (!hasOwn(value, key)) {
      throw new MasuGateProtocolError(`${context}.${key} is required`);
    }
  }
  return value;
}

function requireString(
  record: Record<string, unknown>,
  key: string,
  context: string,
  nonEmpty = false,
  maximumLength?: number,
): string {
  const value = record[key];
  if (typeof value !== "string" || (nonEmpty && value.length === 0)) {
    throw new MasuGateProtocolError(
      `${context}.${key} must be ${nonEmpty ? "a non-empty" : "a"} string`,
    );
  }
  if (maximumLength !== undefined && value.length > maximumLength) {
    throw new MasuGateProtocolError(
      `${context}.${key} must be a string no longer than ${maximumLength} characters`,
    );
  }
  return value;
}

function requireUuid(
  record: Record<string, unknown>,
  key: string,
  context: string,
): string {
  const value = requireString(record, key, context, true);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(value)) {
    throw new MasuGateProtocolError(`${context}.${key} must be a UUID`);
  }
  return value;
}

function requireDateTime(
  record: Record<string, unknown>,
  key: string,
  context: string,
): string {
  const value = requireString(record, key, context, true);
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})$/u.exec(
      value,
    );
  if (match === null) {
    throw new MasuGateProtocolError(`${context}.${key} must be an RFC 3339 date-time`);
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const zone = match[7] ?? "";
  const daysInMonth = [
    31,
    isLeapYear(year) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  const maximumDay = daysInMonth[month - 1];
  const offsetHour = zone === "Z" ? 0 : Number(zone.slice(1, 3));
  const offsetMinute = zone === "Z" ? 0 : Number(zone.slice(4, 6));
  if (
    month < 1 ||
    month > 12 ||
    maximumDay === undefined ||
    day < 1 ||
    day > maximumDay ||
    hour > 23 ||
    minute > 59 ||
    second > 60 ||
    offsetHour > 23 ||
    offsetMinute > 59
  ) {
    throw new MasuGateProtocolError(`${context}.${key} must be an RFC 3339 date-time`);
  }
  return value;
}

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function requireAuditRef(
  record: Record<string, unknown>,
  key: string,
  context: string,
): string {
  const value = requireString(record, key, context, true);
  if (!/^\/v1\/audit\/[^/]+$/u.test(value)) {
    throw new MasuGateProtocolError(`${context}.${key} must be an audit reference`);
  }
  return value;
}

function parseJsonValue(value: unknown, context: string): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new MasuGateProtocolError(`${context} must contain only finite JSON numbers`);
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => parseJsonValue(item, `${context}[${index}]`));
  }
  if (isObject(value)) {
    return parseJsonObject(value, context);
  }
  throw new MasuGateProtocolError(`${context} must be a JSON value`);
}

function parseJsonObject(value: unknown, context: string): JsonObject {
  if (!isObject(value)) {
    throw new MasuGateProtocolError(`${context} must be an object`);
  }
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      parseJsonValue(item, `${context}.${key}`),
    ]),
  );
}

function parseEvaluatedPolicies(value: unknown, context: string): EvaluatedPolicy[] {
  if (!Array.isArray(value)) {
    throw new MasuGateProtocolError(`${context} must be an array`);
  }
  const seen = new Set<string>();
  return value.map((item, index) => {
    const itemContext = `${context}[${index}]`;
    const policy = contractObject(
      item,
      itemContext,
      ["policy_id", "policy_version"],
      ["policy_id", "policy_version"],
    );
    const parsed = {
      policy_id: requireString(policy, "policy_id", itemContext, true),
      policy_version: requireString(policy, "policy_version", itemContext),
    };
    const identity = JSON.stringify([parsed.policy_id, parsed.policy_version]);
    if (seen.has(identity)) {
      throw new MasuGateProtocolError(`${context} must not contain duplicate policies`);
    }
    seen.add(identity);
    return parsed;
  });
}

function parsePolicyProvenance(value: unknown, context: string): PolicyProvenance[] {
  if (!Array.isArray(value)) {
    throw new MasuGateProtocolError(`${context} must be an array`);
  }
  const seen = new Set<string>();
  return value.map((item, index) => {
    const itemContext = `${context}[${index}]`;
    const record = contractObject(
      item,
      itemContext,
      [
        "policy_id",
        "policy_declared_version",
        "policy_runtime_version",
        "policy_digest",
        "bundle_id",
        "bundle_version",
        "bundle_digest",
        "layer",
        "mode",
      ],
      [
        "policy_id",
        "policy_declared_version",
        "policy_runtime_version",
        "policy_digest",
        "bundle_id",
        "bundle_version",
        "bundle_digest",
        "layer",
        "mode",
      ],
    );
    const policyDigest = requireString(record, "policy_digest", itemContext, true);
    const bundleDigest = requireString(record, "bundle_digest", itemContext, true);
    if (!/^[0-9a-f]{64}$/.test(policyDigest) || !/^[0-9a-f]{64}$/.test(bundleDigest)) {
      throw new MasuGateProtocolError(`${itemContext} digests must be lowercase SHA-256`);
    }
    const layer = requireString(record, "layer", itemContext, true);
    if (layer !== "platform-safety" && layer !== "deployment-regulatory" && layer !== "owner") {
      throw new MasuGateProtocolError(`${itemContext}.layer is invalid`);
    }
    const mode = requireString(record, "mode", itemContext, true);
    const expectedMode = layer === "owner" ? "configurable" : "mandatory";
    if (mode !== expectedMode) {
      throw new MasuGateProtocolError(`${itemContext}.mode must be ${expectedMode}`);
    }
    const parsed: PolicyProvenance = {
      policy_id: requireString(record, "policy_id", itemContext, true),
      policy_declared_version: requireString(
        record,
        "policy_declared_version",
        itemContext,
        true,
      ),
      policy_runtime_version: requireString(
        record,
        "policy_runtime_version",
        itemContext,
        true,
      ),
      policy_digest: policyDigest,
      bundle_id: requireString(record, "bundle_id", itemContext, true),
      bundle_version: requireString(record, "bundle_version", itemContext, true),
      bundle_digest: bundleDigest,
      layer,
      mode,
    };
    const identity = JSON.stringify([parsed.bundle_id, parsed.policy_id]);
    if (seen.has(identity)) {
      throw new MasuGateProtocolError(`${context} must not contain duplicate provenance`);
    }
    seen.add(identity);
    return parsed;
  });
}

function parseActionDecision(value: unknown): ActionDecision {
  const context = "action response.decision";
  const decision = contractObject(
    value,
    context,
    [
      "effect",
      "policy_id",
      "policy_version",
      "rule_id",
      "reason",
      "evaluated_policies",
    ],
    ["effect", "policy_id", "policy_version", "rule_id", "reason"],
  );
  const effect = requireString(decision, "effect", context);
  const common = {
    policy_id: requireString(decision, "policy_id", context, true),
    policy_version: requireString(decision, "policy_version", context),
    rule_id: requireString(decision, "rule_id", context, true),
    reason: requireString(decision, "reason", context),
  };
  const evaluated = hasOwn(decision, "evaluated_policies")
    ? parseEvaluatedPolicies(decision["evaluated_policies"], `${context}.evaluated_policies`)
    : undefined;
  if (effect === "allow") {
    return evaluated === undefined
      ? { effect, ...common }
      : { effect, ...common, evaluated_policies: evaluated };
  }
  if (effect === "deny") {
    return evaluated === undefined
      ? { effect, ...common }
      : { effect, ...common, evaluated_policies: evaluated };
  }
  if (effect === "escalate") {
    return evaluated === undefined
      ? { effect, ...common }
      : { effect, ...common, evaluated_policies: evaluated };
  }
  throw new MasuGateProtocolError(`${context}.effect is invalid`);
}

function parsePendingResolutionMetadata(
  record: Record<string, unknown>,
  context: string,
): PendingResolutionMetadata {
  const hasPlan = hasOwn(record, "resolution_plan");
  const hasDigest = hasOwn(record, "reservation_safety_certificate_digest");
  const hasEntitlementDigest = hasOwn(record, "reservation_entitlement_digest");
  if (!hasPlan) {
    if (hasDigest || hasEntitlementDigest) {
      throw new MasuGateProtocolError(
        `${context} reservation proof digests require resolution_plan`,
      );
    }
    // Compatibility with servers predating explicit pending-resolution metadata.
    return {};
  }
  const plan = requireString(record, "resolution_plan", context, true);
  if (plan !== "revalidate" && plan !== "scoped-hold" && plan !== "reservation-proof") {
    throw new MasuGateProtocolError(`${context}.resolution_plan is invalid`);
  }
  let digest: string | undefined;
  if (hasDigest) {
    digest = requireString(record, "reservation_safety_certificate_digest", context, true);
    if (!/^[0-9a-f]{64}$/u.test(digest)) {
      throw new MasuGateProtocolError(
        `${context}.reservation_safety_certificate_digest must be a 64-character lowercase hexadecimal digest`,
      );
    }
  }
  let entitlementDigest: string | undefined;
  if (hasEntitlementDigest) {
    entitlementDigest = requireString(record, "reservation_entitlement_digest", context, true);
    if (!/^[0-9a-f]{64}$/u.test(entitlementDigest)) {
      throw new MasuGateProtocolError(
        `${context}.reservation_entitlement_digest must be a 64-character lowercase hexadecimal digest`,
      );
    }
  }
  if (
    plan === "reservation-proof" &&
    (digest === undefined || entitlementDigest === undefined)
  ) {
    throw new MasuGateProtocolError(
      `${context} reservation proof requires both safety-certificate and entitlement digests`,
    );
  }
  if (
    plan !== "reservation-proof" &&
    (digest !== undefined || entitlementDigest !== undefined)
  ) {
    throw new MasuGateProtocolError(
      `${context} reservation proof digests are forbidden for ${plan}`,
    );
  }
  return digest === undefined || entitlementDigest === undefined
    ? { resolution_plan: plan }
    : {
        resolution_plan: plan,
        reservation_safety_certificate_digest: digest,
        reservation_entitlement_digest: entitlementDigest,
      };
}

function parseActionResult<Payload extends JsonObject>(value: unknown): ActionResult<Payload> {
  const response = contractObject(
    value,
    "action response",
    [
      "operation_id",
      "status",
      "decision",
      "payload",
      "pending_id",
      "resolution_plan",
      "reservation_safety_certificate_digest",
      "reservation_entitlement_digest",
      "audit_ref",
      "replayed",
    ],
    ["operation_id", "status", "decision", "payload", "audit_ref", "replayed"],
  );
  const status = requireString(response, "status", "action response");
  const operationId = requireUuid(response, "operation_id", "action response");
  const auditRef = requireAuditRef(response, "audit_ref", "action response");
  const payload = parseJsonObject(response["payload"], "action response.payload") as Payload;
  const replayed = response["replayed"];
  if (typeof replayed !== "boolean") {
    throw new MasuGateProtocolError("action response.replayed must be a boolean");
  }
  if (status === "in_progress" || status === "outcome_unknown") {
    if (response["decision"] !== null) {
      throw new MasuGateProtocolError(
        `${status} action response must carry a null decision`,
      );
    }
    if (
      hasOwn(response, "pending_id") ||
      hasOwn(response, "resolution_plan") ||
      hasOwn(response, "reservation_safety_certificate_digest") ||
      hasOwn(response, "reservation_entitlement_digest")
    ) {
      throw new MasuGateProtocolError(
        `${status} action response must not include pending metadata`,
      );
    }
    return {
      operation_id: operationId,
      status,
      decision: null,
      payload,
      audit_ref: auditRef,
      replayed,
    };
  }
  const decision = parseActionDecision(response["decision"]);
  if (status === "committed") {
    if (decision.effect !== "allow") {
      throw new MasuGateProtocolError("committed action response must carry an allow decision");
    }
    if (
      hasOwn(response, "pending_id") ||
      hasOwn(response, "resolution_plan") ||
      hasOwn(response, "reservation_safety_certificate_digest") ||
      hasOwn(response, "reservation_entitlement_digest")
    ) {
      throw new MasuGateProtocolError(
        "committed action response must not include pending metadata",
      );
    }
    return {
      operation_id: operationId,
      status,
      decision,
      payload,
      audit_ref: auditRef,
      replayed,
    };
  }
  if (status === "denied") {
    if (decision.effect !== "deny") {
      throw new MasuGateProtocolError("denied action response must carry a deny decision");
    }
    if (
      hasOwn(response, "pending_id") ||
      hasOwn(response, "resolution_plan") ||
      hasOwn(response, "reservation_safety_certificate_digest") ||
      hasOwn(response, "reservation_entitlement_digest")
    ) {
      throw new MasuGateProtocolError("denied action response must not include pending metadata");
    }
    return {
      operation_id: operationId,
      status,
      decision,
      payload,
      audit_ref: auditRef,
      replayed,
    };
  }
  if (status === "pending") {
    if (decision.effect !== "escalate") {
      throw new MasuGateProtocolError("pending action response must carry an escalate decision");
    }
    const resolutionMetadata = parsePendingResolutionMetadata(response, "action response");
    return {
      operation_id: operationId,
      status,
      decision,
      payload,
      pending_id: requireUuid(response, "pending_id", "action response"),
      audit_ref: auditRef,
      replayed,
      ...resolutionMetadata,
    };
  }
  throw new MasuGateProtocolError("action response.status is invalid");
}

function parseStagedArtifact(value: unknown): StagedArtifact {
  const context = "artifact response";
  const artifact = contractObject(
    value,
    context,
    ["reference", "content_digest", "content_bytes", "media_type", "classification", "expires_at"],
    ["reference", "content_digest", "content_bytes", "media_type", "classification", "expires_at"],
  );
  const reference = requireString(artifact, "reference", context, true);
  if (!reference.startsWith("art:")) {
    throw new MasuGateProtocolError(`${context}.reference must be an opaque art: reference`);
  }
  const contentDigest = requireString(artifact, "content_digest", context, true);
  if (!/^[0-9a-f]{64}$/u.test(contentDigest)) {
    throw new MasuGateProtocolError(`${context}.content_digest must be a lowercase SHA-256 digest`);
  }
  const contentBytes = artifact["content_bytes"];
  if (
    typeof contentBytes !== "number" ||
    !Number.isInteger(contentBytes) ||
    contentBytes < 0
  ) {
    throw new MasuGateProtocolError(`${context}.content_bytes must be a non-negative integer`);
  }
  const mediaType = requireString(artifact, "media_type", context, true);
  if (!mediaType.includes("/") || /\s/u.test(mediaType)) {
    throw new MasuGateProtocolError(`${context}.media_type must be a normalized media type`);
  }
  return {
    reference,
    content_digest: contentDigest,
    content_bytes: contentBytes,
    media_type: mediaType,
    classification: requireString(artifact, "classification", context, true, 255),
    expires_at: requireDateTime(artifact, "expires_at", context),
  };
}

function parseResolvedActionResult<Payload extends JsonObject>(
  value: unknown,
): ResolvedActionResult<Payload> {
  const result = parseActionResult<Payload>(value);
  if (result.status === "pending") {
    throw new MasuGateProtocolError("pending resolution returned another human-pending result");
  }
  return result;
}

function parseCertifiedRequest(value: unknown): CertifiedRequest {
  const context = "audit response.request";
  const request = contractObject(
    value,
    context,
    [
      "idempotency_key",
      "principal",
      "action",
      "args",
      "timestamp",
      "request_time",
      "trace_id",
      "adapter_invocation_digest",
      "protected_artifacts",
    ],
    ["idempotency_key", "principal", "action", "args", "timestamp"],
  );
  const principalContext = `${context}.principal`;
  const principal = contractObject(
    request["principal"],
    principalContext,
    ["id", "attributes"],
    ["id", "attributes"],
  );
  const attributesContext = `${principalContext}.attributes`;
  const rawAttributes = principal["attributes"];
  if (!isObject(rawAttributes)) {
    throw new MasuGateProtocolError(`${attributesContext} must be an object`);
  }
  const attributeEntries: Array<[string, PrincipalAttribute]> = [];
  for (const [key, attribute] of Object.entries(rawAttributes)) {
    if (
      typeof attribute !== "string" &&
      typeof attribute !== "boolean" &&
      !(typeof attribute === "number" && Number.isSafeInteger(attribute))
    ) {
      throw new MasuGateProtocolError(
        `${attributesContext}.${key} must be a string, boolean, or safe integer`,
      );
    }
    attributeEntries.push([key, attribute]);
  }
  const attributes = Object.fromEntries(attributeEntries);
  const timestamp = requireDateTime(request, "timestamp", context);
  const base: CertifiedRequest = {
    idempotency_key: requireString(request, "idempotency_key", context, true),
    principal: {
      id: requireString(principal, "id", principalContext, true),
      attributes,
    },
    action: requireString(request, "action", context, true),
    args: parseJsonObject(request["args"], `${context}.args`),
    timestamp,
    request_time: hasOwn(request, "request_time")
      ? requireDateTime(request, "request_time", context)
      : timestamp,
  };
  const trace = hasOwn(request, "trace_id")
    ? (() => {
        const traceId = request["trace_id"];
        if (traceId !== null && typeof traceId !== "string") {
          throw new MasuGateProtocolError(`${context}.trace_id must be a string or null`);
        }
        return { trace_id: traceId };
      })()
    : {};
  const provenance = hasOwn(request, "adapter_invocation_digest")
    ? {
        adapter_invocation_digest: requireHexDigest(
          request,
          "adapter_invocation_digest",
          context,
        ),
      }
    : {};
  const artifacts = hasOwn(request, "protected_artifacts")
    ? { protected_artifacts: parseProtectedArtifacts(request["protected_artifacts"], `${context}.protected_artifacts`) }
    : {};
  return { ...base, ...trace, ...provenance, ...artifacts };
}

function parseProtectedArtifacts(
  value: unknown,
  context: string,
): Record<string, ProtectedArtifactMetadata> {
  if (!isObject(value)) throw new MasuGateProtocolError(`${context} must be an object`);
  const parsed: Record<string, ProtectedArtifactMetadata> = {};
  for (const [field, value_] of Object.entries(value)) {
    const itemContext = `${context}.${field}`;
    const item = contractObject(
      value_,
      itemContext,
      [
        "reference",
        "content_digest",
        "content_bytes",
        "media_type",
        "classification",
        "expires_at",
        "inspector_version",
      ],
      [
        "reference",
        "content_digest",
        "content_bytes",
        "media_type",
        "classification",
        "expires_at",
        "inspector_version",
      ],
    );
    const reference = requireString(item, "reference", itemContext, true);
    if (!reference.startsWith("art:")) {
      throw new MasuGateProtocolError(`${itemContext}.reference must be an opaque art: reference`);
    }
    const contentBytes = requireInteger(item, "content_bytes", itemContext, 0);
    parsed[field] = {
      reference,
      content_digest: requireHexDigest(item, "content_digest", itemContext),
      content_bytes: contentBytes,
      media_type: requireString(item, "media_type", itemContext, true),
      classification: requireString(item, "classification", itemContext, true, 255),
      expires_at: requireDateTime(item, "expires_at", itemContext),
      inspector_version: requireString(item, "inspector_version", itemContext, true, 255),
    };
  }
  return parsed;
}

function parsePolicyReceipt(value: unknown): PolicyReceipt {
  const context = "audit response.policy";
  const policy = contractObject(
    value,
    context,
    [
      "policy_id",
      "policy_version",
      "evaluated_policies",
      "evaluated_policy_provenance",
      "catalog",
    ],
    ["policy_id", "policy_version", "evaluated_policies", "evaluated_policy_provenance"],
  );
  return {
    policy_id: requireString(policy, "policy_id", context, true),
    policy_version: requireString(policy, "policy_version", context),
    evaluated_policies: parseEvaluatedPolicies(
      policy["evaluated_policies"],
      `${context}.evaluated_policies`,
    ),
    evaluated_policy_provenance: parsePolicyProvenance(
      policy["evaluated_policy_provenance"],
      `${context}.evaluated_policy_provenance`,
    ),
    ...(hasOwn(policy, "catalog")
      ? { catalog: parsePolicyCatalog(policy["catalog"]) }
      : {}),
  };
}

function requireHexDigest(
  record: Record<string, unknown>,
  key: string,
  context: string,
): string {
  const digest = requireString(record, key, context, true);
  if (!/^[0-9a-f]{64}$/u.test(digest)) {
    throw new MasuGateProtocolError(
      `${context}.${key} must be a 64-character lowercase hexadecimal digest`,
    );
  }
  return digest;
}

function parsePolicyCatalog(value: unknown): PolicyCatalog {
  const context = "audit response.policy.catalog";
  const catalog = contractObject(
    value,
    context,
    ["policy_digest", "bundle_digest"],
    ["policy_digest", "bundle_digest"],
  );
  return {
    policy_digest: requireHexDigest(catalog, "policy_digest", context),
    bundle_digest: requireHexDigest(catalog, "bundle_digest", context),
  };
}

function parseAuditEntitlement(value: unknown): AuditEntitlement {
  const context = "audit response.entitlement";
  const entitlement = contractObject(
    value,
    context,
    ["entitlement_id", "authorization_digest"],
    ["entitlement_id", "authorization_digest"],
  );
  return {
    entitlement_id: requireString(entitlement, "entitlement_id", context, true),
    authorization_digest: requireHexDigest(
      entitlement,
      "authorization_digest",
      context,
    ),
  };
}

function validateAuditProvenance(
  policy: PolicyReceipt,
  entitlement: AuditEntitlement | undefined,
  protectedExecution: ProtectedExecutionAudit | undefined,
): void {
  const catalog = policy.catalog;
  if (
    catalog !== undefined &&
    !policy.evaluated_policy_provenance.some(
      (provenance) =>
        provenance.policy_digest === catalog.policy_digest &&
        provenance.bundle_digest === catalog.bundle_digest,
    )
  ) {
    throw new MasuGateProtocolError(
      "audit response.policy.catalog does not match evaluated policy provenance",
    );
  }
  if (entitlement === undefined || protectedExecution === undefined) {
    return;
  }
  if (protectedExecution.binding["entitlement_id"] !== entitlement.entitlement_id) {
    throw new MasuGateProtocolError(
      "audit response.entitlement_id does not match protected execution binding",
    );
  }
  if (
    protectedExecution.binding["authorization_digest"] !== entitlement.authorization_digest
  ) {
    throw new MasuGateProtocolError(
      "audit response.entitlement.authorization_digest does not match protected execution binding",
    );
  }
}

function protectedBindingPolicyRows(binding: JsonObject): string[] {
  const value = binding["policies"];
  if (!Array.isArray(value)) {
    throw new MasuGateProtocolError("audit response.protected_execution.binding.policies must be an array");
  }
  return value.map((item, index) => {
    const context = `audit response.protected_execution.binding.policies[${index}]`;
    const policy = contractObject(
      item,
      context,
      ["policy_id", "policy_version", "policy_digest", "bundle_id", "bundle_version", "bundle_digest"],
      ["policy_id", "policy_version", "policy_digest", "bundle_id", "bundle_version", "bundle_digest"],
    );
    return JSON.stringify([
      requireString(policy, "policy_id", context, true),
      requireString(policy, "policy_version", context, true),
      requireHexDigest(policy, "policy_digest", context),
      requireString(policy, "bundle_id", context, true),
      requireString(policy, "bundle_version", context, true),
      requireHexDigest(policy, "bundle_digest", context),
    ]);
  }).sort();
}

function validateProtectedExecutionBinding(
  request: CertifiedRequest,
  policy: PolicyReceipt,
  effect: AppliedEffect | null,
  protectedExecution: ProtectedExecutionAudit | undefined,
): void {
  if (protectedExecution === undefined) return;
  const binding = protectedExecution.binding;
  if (binding["principal_id"] !== request.principal.id) {
    throw new MasuGateProtocolError(
      "audit response.request principal does not match protected execution binding",
    );
  }
  if (binding["action"] !== request.action) {
    throw new MasuGateProtocolError(
      "audit response.request action does not match protected execution binding",
    );
  }
  if (!jsonValuesEqual(binding["arguments"]!, request.args)) {
    throw new MasuGateProtocolError(
      "audit response.request args do not match protected execution binding",
    );
  }
  if (binding["idempotency_key"] !== request.idempotency_key) {
    throw new MasuGateProtocolError(
      "audit response.request idempotency key does not match protected execution binding",
    );
  }
  if (
    effect !== null &&
    (effect.action !== binding["action"] || !jsonValuesEqual(effect.args, binding["arguments"]!))
  ) {
    throw new MasuGateProtocolError("audit response.effect does not match protected execution binding");
  }
  if (policy.evaluated_policy_provenance.length > 0) {
    const expected = policy.evaluated_policy_provenance.map((item) => JSON.stringify([
      item.policy_id,
      item.policy_declared_version,
      item.policy_digest,
      item.bundle_id,
      item.bundle_version,
      item.bundle_digest,
    ])).sort();
    const actual = protectedBindingPolicyRows(binding);
    if (actual.length !== expected.length || actual.some((item, index) => item !== expected[index])) {
      throw new MasuGateProtocolError(
        "audit response.policy provenance does not match protected execution binding",
      );
    }
  }
}

type ParsedAuditDecision =
  | { effect: "allow"; rule_id: string; reason: string }
  | { effect: "deny"; rule_id: string; reason: string }
  | { effect: "escalate"; rule_id: string; reason: string };

function parseAuditDecision(value: unknown): ParsedAuditDecision {
  const context = "audit response.decision";
  const decision = contractObject(
    value,
    context,
    ["effect", "rule_id", "reason"],
    ["effect", "rule_id", "reason"],
  );
  const effect = requireString(decision, "effect", context);
  const common = {
    rule_id: requireString(decision, "rule_id", context, true),
    reason: requireString(decision, "reason", context),
  };
  if (effect === "allow" || effect === "deny" || effect === "escalate") {
    return { effect, ...common };
  }
  throw new MasuGateProtocolError(`${context}.effect is invalid`);
}

function parseViewReads(value: unknown): ViewRead[] {
  const context = "audit response.view_reads";
  if (!Array.isArray(value)) {
    throw new MasuGateProtocolError(`${context} must be an array`);
  }
  return value.map((item, index) => {
    const itemContext = `${context}[${index}]`;
    const read = contractObject(
      item,
      itemContext,
      ["function", "arguments", "value", "scope", "version", "latency_ms"],
      ["function", "arguments", "value", "scope", "version", "latency_ms"],
    );
    if (!Array.isArray(read["arguments"])) {
      throw new MasuGateProtocolError(`${itemContext}.arguments must be an array`);
    }
    const version = read["version"];
    if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 0) {
      throw new MasuGateProtocolError(`${itemContext}.version must be a non-negative integer`);
    }
    const latency = read["latency_ms"];
    if (typeof latency !== "number" || !Number.isFinite(latency) || latency < 0) {
      throw new MasuGateProtocolError(`${itemContext}.latency_ms must be non-negative`);
    }
    return {
      function: requireString(read, "function", itemContext, true),
      arguments: read["arguments"].map((argument, argumentIndex) =>
        parseJsonValue(argument, `${itemContext}.arguments[${argumentIndex}]`),
      ),
      value: parseJsonValue(read["value"], `${itemContext}.value`),
      scope: requireString(read, "scope", itemContext, true),
      version,
      latency_ms: latency,
    };
  });
}

function parseAppliedEffect<Payload extends JsonObject>(
  value: unknown,
): AppliedEffect<Payload> {
  const context = "audit response.effect";
  const effect = contractObject(
    value,
    context,
    ["action", "args", "payload"],
    ["action", "args", "payload"],
  );
  return {
    action: requireString(effect, "action", context, true),
    args: parseJsonObject(effect["args"], `${context}.args`),
    payload: parseJsonObject(effect["payload"], `${context}.payload`) as Payload,
  };
}

function parseCertifiedInput(value: unknown, context: string): CertifiedInputEvidence {
  const input = contractObject(
    value,
    context,
    [
      "name", "value", "value_type", "stability", "stability_proof",
      "source_id", "source_version", "contract_version", "observed_at",
      "certified_at", "freshness_ttl_seconds", "expires_at", "phase",
    ],
    [
      "name", "value", "value_type", "stability", "stability_proof",
      "source_id", "source_version", "contract_version", "observed_at",
      "certified_at", "freshness_ttl_seconds", "expires_at", "phase",
    ],
  );
  const valueType = requireString(input, "value_type", context);
  const stability = requireString(input, "stability", context);
  const phase = requireString(input, "phase", context);
  const proof = input["stability_proof"];
  const ttl = input["freshness_ttl_seconds"];
  if (!["Bool", "Int", "String", "Duration"].includes(valueType)) {
    throw new MasuGateProtocolError(`${context}.value_type is invalid`);
  }
  if (!["admission-stable", "resolution-volatile"].includes(stability)) {
    throw new MasuGateProtocolError(`${context}.stability is invalid`);
  }
  if (!["admission", "resolution"].includes(phase)) {
    throw new MasuGateProtocolError(`${context}.phase is invalid`);
  }
  if (proof !== null && proof !== "request-bound-immutable-v1") {
    throw new MasuGateProtocolError(`${context}.stability_proof is invalid`);
  }
  if ((stability === "admission-stable") !== (proof === "request-bound-immutable-v1")) {
    throw new MasuGateProtocolError(
      `${context}.stability_proof does not prove the declared stability`,
    );
  }
  if (typeof ttl !== "number" || !Number.isSafeInteger(ttl) || ttl <= 0) {
    throw new MasuGateProtocolError(`${context}.freshness_ttl_seconds must be positive`);
  }
  return {
    name: requireString(input, "name", context, true),
    value: parseJsonValue(input["value"], `${context}.value`),
    value_type: valueType as CertifiedInputEvidence["value_type"],
    stability: stability as CertifiedInputEvidence["stability"],
    stability_proof: proof as CertifiedInputEvidence["stability_proof"],
    source_id: requireString(input, "source_id", context, true),
    source_version: requireString(input, "source_version", context, true),
    contract_version: requireString(input, "contract_version", context, true),
    observed_at: requireDateTime(input, "observed_at", context),
    certified_at: requireDateTime(input, "certified_at", context),
    freshness_ttl_seconds: ttl,
    expires_at: requireDateTime(input, "expires_at", context),
    phase: phase as CertifiedInputEvidence["phase"],
  };
}

function parseAuthorizationEvaluations(value: unknown): AuthorizationEvaluation[] {
  const context = "audit response.authorization_evaluations";
  if (!Array.isArray(value)) {
    throw new MasuGateProtocolError(`${context} must be an array`);
  }
  return value.map((item, index) => {
    const itemContext = `${context}[${index}]`;
    const evaluation = contractObject(
      item,
      itemContext,
      ["phase", "evaluated_at", "decision", "certified_inputs"],
      ["phase", "evaluated_at", "decision", "certified_inputs"],
    );
    const phase = requireString(evaluation, "phase", itemContext);
    if (phase !== "admission" && phase !== "resolution") {
      throw new MasuGateProtocolError(`${itemContext}.phase is invalid`);
    }
    const decisionContext = `${itemContext}.decision`;
    const rawDecision = contractObject(
      evaluation["decision"],
      decisionContext,
      [
        "effect",
        "policy_id",
        "policy_version",
        "rule_id",
        "reason",
        "reads",
        "evaluated_policies",
        "policy_provenance",
      ],
      ["effect", "policy_id", "policy_version", "rule_id", "reason"],
    );
    const effect = requireString(rawDecision, "effect", decisionContext);
    if (effect !== "allow" && effect !== "deny" && effect !== "escalate") {
      throw new MasuGateProtocolError(`${decisionContext}.effect is invalid`);
    }
    const inputs = evaluation["certified_inputs"];
    if (!Array.isArray(inputs)) {
      throw new MasuGateProtocolError(`${itemContext}.certified_inputs must be an array`);
    }
    return {
      phase,
      evaluated_at: requireDateTime(evaluation, "evaluated_at", itemContext),
      decision: {
        effect,
        policy_id: requireString(rawDecision, "policy_id", decisionContext, true),
        policy_version: hasOwn(rawDecision, "policy_version")
          ? requireString(rawDecision, "policy_version", decisionContext)
          : "",
        rule_id: requireString(rawDecision, "rule_id", decisionContext, true),
        reason: requireString(rawDecision, "reason", decisionContext),
        evaluated_policies: hasOwn(rawDecision, "evaluated_policies")
          ? parseEvaluatedPolicies(rawDecision["evaluated_policies"], `${decisionContext}.evaluated_policies`)
          : [],
        policy_provenance: hasOwn(rawDecision, "policy_provenance")
          ? parsePolicyProvenance(rawDecision["policy_provenance"], `${decisionContext}.policy_provenance`)
          : [],
      },
      certified_inputs: inputs.map((input, inputIndex) =>
        parseCertifiedInput(input, `${itemContext}.certified_inputs[${inputIndex}]`),
      ),
    };
  });
}

function parseTerminalSerialization(value: unknown): TerminalSerialization | null {
  if (value === null || value === undefined) return null;
  const context = "audit response.terminal_serialization";
  const terminal = contractObject(
    value,
    context,
    ["kind", "authorization_basis", "provider_atomic", "recorded_at", "evaluation_phase", "evaluation_at"],
    ["kind", "authorization_basis", "provider_atomic", "recorded_at"],
  );
  const kind = requireString(terminal, "kind", context);
  if (kind !== "effect-commit" && kind !== "denial-record") {
    throw new MasuGateProtocolError(`${context}.kind is invalid`);
  }
  const providerAtomic = terminal["provider_atomic"];
  if (typeof providerAtomic !== "boolean") {
    throw new MasuGateProtocolError(`${context}.provider_atomic must be a boolean`);
  }
  const parsed: TerminalSerialization = {
    kind,
    authorization_basis: requireString(terminal, "authorization_basis", context, true),
    provider_atomic: providerAtomic,
    recorded_at: requireDateTime(terminal, "recorded_at", context),
  };
  if (hasOwn(terminal, "evaluation_phase")) {
    const phase = requireString(terminal, "evaluation_phase", context);
    if (phase !== "admission" && phase !== "resolution") {
      throw new MasuGateProtocolError(`${context}.evaluation_phase is invalid`);
    }
    parsed.evaluation_phase = phase;
  }
  if (hasOwn(terminal, "evaluation_at")) {
    parsed.evaluation_at = requireDateTime(terminal, "evaluation_at", context);
  }
  return parsed;
}

function parseProtectedStatus(value: unknown, context: string): ProtectedExecutionStatus {
  if (
    value !== "intent" &&
    value !== "executing" &&
    value !== "succeeded" &&
    value !== "failed" &&
    value !== "outcome_unknown"
  ) {
    throw new MasuGateProtocolError(`${context} must be a protected-execution status`);
  }
  return value;
}

function parseProtectedEntitlement(
  value: unknown,
  context: string,
): ProtectedEntitlementState {
  if (value !== "held" && value !== "consumed" && value !== "released" && value !== "quarantined") {
    throw new MasuGateProtocolError(`${context} must be a protected entitlement state`);
  }
  return value;
}

function requireInteger(
  record: Record<string, unknown>,
  key: string,
  context: string,
  minimum: number,
): number {
  const value = record[key];
  if (typeof value !== "number" || !Number.isInteger(value) || value < minimum) {
    throw new MasuGateProtocolError(`${context}.${key} must be an integer >= ${minimum}`);
  }
  return value;
}

function parseProtectedConnectorEvidence(
  value: unknown,
  context: string,
): ProtectedConnectorEvidence {
  const evidence = contractObject(
    value,
    context,
    [
      "connector_id",
      "evidence_id",
      "idempotency_key",
      "external_operation_id",
      "outcome",
      "observed_at",
      "payload",
    ],
    [
      "connector_id",
      "evidence_id",
      "idempotency_key",
      "external_operation_id",
      "outcome",
      "observed_at",
      "payload",
    ],
  );
  const outcome = evidence["outcome"];
  if (outcome !== "succeeded" && outcome !== "failed" && outcome !== "unknown") {
    throw new MasuGateProtocolError(`${context}.outcome must be a connector outcome`);
  }
  const operationId = evidence["external_operation_id"];
  if (operationId !== null && (typeof operationId !== "string" || operationId.length === 0)) {
    throw new MasuGateProtocolError(`${context}.external_operation_id must be a string or null`);
  }
  return {
    connector_id: requireString(evidence, "connector_id", context, true),
    evidence_id: requireString(evidence, "evidence_id", context, true),
    idempotency_key: requireString(evidence, "idempotency_key", context, true),
    external_operation_id: operationId,
    outcome,
    observed_at: requireDateTime(evidence, "observed_at", context),
    payload: parseJsonObject(evidence["payload"], `${context}.payload`),
  };
}

function parseProtectedExecutionEvent(
  value: unknown,
  context: string,
): ProtectedExecutionAuditEvent {
  const event = contractObject(
    value,
    context,
    [
      "sequence",
      "event_type",
      "from_status",
      "to_status",
      "worker_id",
      "fence_token",
      "recorded_at",
      "evidence",
    ],
    [
      "sequence",
      "event_type",
      "from_status",
      "to_status",
      "worker_id",
      "fence_token",
      "recorded_at",
      "evidence",
    ],
  );
  const fromStatus = event["from_status"];
  const workerId = event["worker_id"];
  const fenceToken = event["fence_token"];
  if (workerId !== null && (typeof workerId !== "string" || workerId.length === 0)) {
    throw new MasuGateProtocolError(`${context}.worker_id must be a string or null`);
  }
  if (fenceToken !== null && (typeof fenceToken !== "number" || !Number.isInteger(fenceToken) || fenceToken < 1)) {
    throw new MasuGateProtocolError(`${context}.fence_token must be a positive integer or null`);
  }
  return {
    sequence: requireInteger(event, "sequence", context, 1),
    event_type: requireString(event, "event_type", context, true),
    from_status:
      fromStatus === null ? null : parseProtectedStatus(fromStatus, `${context}.from_status`),
    to_status: parseProtectedStatus(event["to_status"], `${context}.to_status`),
    worker_id: workerId,
    fence_token: fenceToken,
    recorded_at: requireDateTime(event, "recorded_at", context),
    evidence: parseJsonObject(event["evidence"], `${context}.evidence`),
  };
}

async function parseProtectedExecution(value: unknown): Promise<ProtectedExecutionAudit> {
  const context = "audit response.protected_execution";
  const record = contractObject(
    value,
    context,
    [
      "execution_id",
      "binding_digest",
      "binding",
      "binding_canonical_json",
      "status",
      "entitlement_state",
      "dispatch_started",
      "cancel_requested",
      "external_operation_id",
      "lease",
      "last_fence_token",
      "receipt",
      "result",
      "created_at",
      "updated_at",
      "events",
    ],
    [
      "execution_id",
      "binding_digest",
      "binding",
      "binding_canonical_json",
      "status",
      "entitlement_state",
      "dispatch_started",
      "cancel_requested",
      "external_operation_id",
      "lease",
      "last_fence_token",
      "receipt",
      "result",
      "created_at",
      "updated_at",
      "events",
    ],
  );
  const digest = requireString(record, "binding_digest", context, true);
  const executionId = requireString(record, "execution_id", context, true);
  if (!/^[0-9a-f]{64}$/u.test(digest) || executionId !== `px:${digest}`) {
    throw new MasuGateProtocolError(`${context} execution identity does not match binding digest`);
  }
  const binding = parseJsonObject(record["binding"], `${context}.binding`);
  const bindingCanonicalJson = requireString(record, "binding_canonical_json", context, true);
  let canonicalBinding: JsonObject;
  try {
    canonicalBinding = parseJsonObject(
      JSON.parse(bindingCanonicalJson),
      `${context}.binding_canonical_json`,
    );
  } catch (error) {
    if (error instanceof MasuGateProtocolError) {
      throw error;
    }
    throw new MasuGateProtocolError(`${context}.binding_canonical_json must encode a JSON object`);
  }
  if (!jsonValuesEqual(binding, canonicalBinding)) {
    throw new MasuGateProtocolError(`${context}.binding_canonical_json does not match binding payload`);
  }
  if ((await sha256Hex(bindingCanonicalJson)) !== digest) {
    throw new MasuGateProtocolError(`${context}.binding digest does not match binding payload`);
  }
  const status = parseProtectedStatus(record["status"], `${context}.status`);
  const entitlementState = parseProtectedEntitlement(
    record["entitlement_state"],
    `${context}.entitlement_state`,
  );
  const dispatchStarted = record["dispatch_started"];
  const cancelRequested = record["cancel_requested"];
  if (typeof dispatchStarted !== "boolean" || typeof cancelRequested !== "boolean") {
    throw new MasuGateProtocolError(`${context} dispatch/cancel markers must be boolean`);
  }
  const externalOperationId = record["external_operation_id"];
  if (
    externalOperationId !== null &&
    (typeof externalOperationId !== "string" || externalOperationId.length === 0)
  ) {
    throw new MasuGateProtocolError(`${context}.external_operation_id must be a string or null`);
  }
  const lastFenceToken = requireInteger(record, "last_fence_token", context, 0);
  const leaseValue = record["lease"];
  let lease: ProtectedExecutionAudit["lease"] = null;
  if (leaseValue !== null) {
    const leaseRecord = contractObject(
      leaseValue,
      `${context}.lease`,
      ["owner", "fence_token", "expires_at"],
      ["owner", "fence_token", "expires_at"],
    );
    lease = {
      owner: requireString(leaseRecord, "owner", `${context}.lease`, true),
      fence_token: requireInteger(leaseRecord, "fence_token", `${context}.lease`, 1),
      expires_at: requireDateTime(leaseRecord, "expires_at", `${context}.lease`),
    };
    if (lease.fence_token !== lastFenceToken) {
      throw new MasuGateProtocolError(`${context}.lease fence must equal the last fence`);
    }
  }
  const receiptValue = record["receipt"];
  const receipt =
    receiptValue === null
      ? null
      : parseProtectedConnectorEvidence(receiptValue, `${context}.receipt`);
  const eventValues = record["events"];
  if (!Array.isArray(eventValues)) {
    throw new MasuGateProtocolError(`${context}.events must be an array`);
  }
  const events = eventValues.map((event, index) =>
    parseProtectedExecutionEvent(event, `${context}.events[${index}]`),
  );
  if (events.some((event, index) => event.sequence !== index + 1)) {
    throw new MasuGateProtocolError(`${context}.events must be an ordered contiguous audit trail`);
  }
  if (events.length > 0 && events.at(-1)?.to_status !== status) {
    throw new MasuGateProtocolError(`${context}.status must match the last audit event`);
  }
  const expectedEntitlement: Record<ProtectedExecutionStatus, ProtectedEntitlementState> = {
    intent: "held",
    executing: "held",
    succeeded: "consumed",
    failed: "released",
    outcome_unknown: "quarantined",
  };
  if (entitlementState !== expectedEntitlement[status]) {
    throw new MasuGateProtocolError(`${context}.entitlement_state contradicts status`);
  }
  if (!dispatchStarted && (receipt !== null || externalOperationId !== null)) {
    throw new MasuGateProtocolError(
      `${context} undispatched execution cannot carry external-operation evidence`,
    );
  }
  if (receipt !== null && receipt.external_operation_id !== externalOperationId) {
    throw new MasuGateProtocolError(`${context}.receipt changed the external-operation identity`);
  }
  if (receipt !== null && receipt.idempotency_key !== `masugate:${digest}`) {
    throw new MasuGateProtocolError(`${context}.receipt idempotency key does not match binding digest`);
  }
  const bindingConnectorId = binding["connector_id"];
  if (typeof bindingConnectorId !== "string" || bindingConnectorId.length === 0) {
    throw new MasuGateProtocolError(`${context}.binding.connector_id must be a non-empty string`);
  }
  if (receipt !== null && receipt.connector_id !== bindingConnectorId) {
    throw new MasuGateProtocolError(`${context}.receipt connector does not match binding`);
  }
  if (receipt !== null && receipt.outcome !== "unknown" && receipt.external_operation_id === null) {
    throw new MasuGateProtocolError(
      `${context}.receipt terminal outcome requires an external operation id`,
    );
  }
  if (status === "outcome_unknown" && !dispatchStarted) {
    throw new MasuGateProtocolError(`${context}.outcome_unknown requires a dispatch marker`);
  }
  if (status === "succeeded" && (receipt === null || receipt.outcome !== "succeeded")) {
    throw new MasuGateProtocolError(`${context}.succeeded requires success evidence`);
  }
  if (
    status === "failed" &&
    dispatchStarted &&
    (receipt === null || receipt.outcome !== "failed")
  ) {
    throw new MasuGateProtocolError(`${context}.post-dispatch failure requires failure evidence`);
  }
  return {
    execution_id: executionId,
    binding_digest: digest,
    binding,
    binding_canonical_json: bindingCanonicalJson,
    status,
    entitlement_state: entitlementState,
    dispatch_started: dispatchStarted,
    cancel_requested: cancelRequested,
    external_operation_id: externalOperationId,
    lease,
    last_fence_token: lastFenceToken,
    receipt,
    result: parseJsonObject(record["result"], `${context}.result`),
    created_at: requireDateTime(record, "created_at", context),
    updated_at: requireDateTime(record, "updated_at", context),
    events,
  };
}

function parseHumanResolution(value: unknown): HumanResolution {
  const context = "audit response.human_resolution";
  const resolution = contractObject(
    value,
    context,
    ["approved", "actor_id", "evidence", "resolved_at"],
    ["approved", "evidence"],
  );
  if (typeof resolution["approved"] !== "boolean") {
    throw new MasuGateProtocolError(`${context}.approved must be a boolean`);
  }
  const hasActor = hasOwn(resolution, "actor_id");
  const hasTime = hasOwn(resolution, "resolved_at");
  if (hasActor !== hasTime) {
    throw new MasuGateProtocolError(`${context}.actor_id and resolved_at must appear together`);
  }
  return {
    approved: resolution["approved"],
    evidence: parseJsonObject(resolution["evidence"], `${context}.evidence`),
    ...(hasActor
      ? {
          actor_id: requireString(resolution, "actor_id", context, true),
          resolved_at: requireDateTime(resolution, "resolved_at", context),
        }
      : {}),
  };
}

function parseAutomaticExpiry(value: unknown): AutomaticExpiry {
  const context = "audit response.automatic_expiry";
  const expiry = contractObject(value, context, ["expires_at", "reason"], ["expires_at", "reason"]);
  if (expiry["reason"] !== "approval-window-expired") {
    throw new MasuGateProtocolError(`${context}.reason must be approval-window-expired`);
  }
  return {
    expires_at: requireDateTime(expiry, "expires_at", context),
    reason: "approval-window-expired",
  };
}

async function parseAuditRecord<Payload extends JsonObject>(
  value: unknown,
): Promise<AuditRecord<Payload>> {
  const record = contractObject(
    value,
    "audit response",
    [
      "operation_id",
      "status",
      "request",
      "policy",
      "decision",
      "view_reads",
      "authorization_evaluations",
      "terminal_serialization",
      "human_resolution",
      "automatic_expiry",
      "protected_execution",
      "entitlement",
      "resolution_plan",
      "reservation_safety_certificate_digest",
      "reservation_entitlement_digest",
      "effect",
      "recorded_at",
    ],
    [
      "operation_id",
      "status",
      "request",
      "policy",
      "decision",
      "view_reads",
      "authorization_evaluations",
      "terminal_serialization",
      "effect",
      "recorded_at",
    ],
  );
  const operationId = requireUuid(record, "operation_id", "audit response");
  const status = requireString(record, "status", "audit response");
  const request = parseCertifiedRequest(record["request"]);
  const policy = parsePolicyReceipt(record["policy"]);
  const operational = status === "in_progress" || status === "outcome_unknown";
  if (operational && record["decision"] !== null) {
    throw new MasuGateProtocolError(`${status} audit response must carry a null decision`);
  }
  const decision = operational ? null : parseAuditDecision(record["decision"]);
  const effect = record["effect"] === null
    ? null
    : parseAppliedEffect<Payload>(record["effect"]);
  const viewReads = parseViewReads(record["view_reads"]);
  const authorizationEvaluations = parseAuthorizationEvaluations(
    record["authorization_evaluations"],
  );
  const terminalSerialization = parseTerminalSerialization(
    record["terminal_serialization"],
  );
  const humanResolution = hasOwn(record, "human_resolution")
    ? parseHumanResolution(record["human_resolution"])
    : undefined;
  const automaticExpiry = hasOwn(record, "automatic_expiry")
    ? parseAutomaticExpiry(record["automatic_expiry"])
    : undefined;
  if (automaticExpiry !== undefined) {
    if (status !== "denied" || decision === null || decision.rule_id !== "approval.expired") {
      throw new MasuGateProtocolError(
        "automatic expiry requires a denied receipt with approval.expired",
      );
    }
    if (humanResolution !== undefined) {
      throw new MasuGateProtocolError("automatic expiry may not claim a human resolution");
    }
  }
  if (decision !== null && decision.rule_id === "approval.expired" && automaticExpiry === undefined) {
    throw new MasuGateProtocolError("approval.expired requires automatic expiry evidence");
  }
  const protectedExecution = hasOwn(record, "protected_execution")
    ? await parseProtectedExecution(record["protected_execution"])
    : undefined;
  const entitlement = hasOwn(record, "entitlement")
    ? parseAuditEntitlement(record["entitlement"])
    : undefined;
  validateAuditProvenance(policy, entitlement, protectedExecution);
  const recordedAt = requireDateTime(record, "recorded_at", "audit response");
  const resolutionMetadata = parsePendingResolutionMetadata(record, "audit response");

  if (
    status === "committed" &&
    (terminalSerialization === null || terminalSerialization.kind !== "effect-commit")
  ) {
    throw new MasuGateProtocolError(
      "committed audit response requires effect-commit terminal serialization",
    );
  }
  if (
    status === "denied" &&
    (terminalSerialization === null || terminalSerialization.kind !== "denial-record")
  ) {
    throw new MasuGateProtocolError(
      "denied audit response requires denial-record terminal serialization",
    );
  }
  if (status === "pending" && terminalSerialization !== null) {
    throw new MasuGateProtocolError(
      "pending audit response requires null terminal serialization",
    );
  }

  if (status === "pending" && protectedExecution !== undefined) {
    throw new MasuGateProtocolError("pending audit response must not carry protected execution");
  }
  if (protectedExecution !== undefined) {
    const expectedStatus: Record<
      "committed" | "denied" | "outcome_unknown",
      ProtectedExecutionStatus
    > = {
      committed: "succeeded",
      denied: "failed",
      outcome_unknown: "outcome_unknown",
    };
    if (
      status === "in_progress" &&
      protectedExecution.status !== "intent" &&
      protectedExecution.status !== "executing"
    ) {
      throw new MasuGateProtocolError(
        "in_progress audit response requires intent or executing protected execution",
      );
    }
    if (
      (status === "committed" || status === "denied" || status === "outcome_unknown") &&
      protectedExecution.status !== expectedStatus[status]
    ) {
      throw new MasuGateProtocolError(
        `${status} audit response has contradictory protected execution status`,
      );
    }
  }
  validateProtectedExecutionBinding(request, policy, effect, protectedExecution);

  const optionalReceiptFields = {
    ...(humanResolution === undefined ? {} : { human_resolution: humanResolution }),
    ...(automaticExpiry === undefined ? {} : { automatic_expiry: automaticExpiry }),
    ...(protectedExecution === undefined
      ? {}
      : { protected_execution: protectedExecution }),
    ...(entitlement === undefined ? {} : { entitlement }),
  };

  if (operational) {
    if (terminalSerialization !== null || record["effect"] !== null) {
      throw new MasuGateProtocolError(
        `${status} audit response must carry null terminal serialization and effect`,
      );
    }
    if (
      hasOwn(record, "resolution_plan") ||
      hasOwn(record, "reservation_safety_certificate_digest") ||
      hasOwn(record, "reservation_entitlement_digest")
    ) {
      throw new MasuGateProtocolError(
        `${status} audit response must not include pending metadata`,
      );
    }
    return {
      operation_id: operationId,
      status,
      request,
      policy,
      decision: null,
      view_reads: viewReads,
      authorization_evaluations: authorizationEvaluations,
      terminal_serialization: null,
      ...optionalReceiptFields,
      effect: null,
      recorded_at: recordedAt,
    };
  }
  if (decision === null) {
    throw new MasuGateProtocolError("decided audit response must carry a policy decision");
  }

  if (status === "committed") {
    if (decision.effect !== "allow") {
      throw new MasuGateProtocolError("committed audit response must carry an allow decision");
    }
    if (effect === null) {
      throw new MasuGateProtocolError("audit response.effect must be an object");
    }
    return {
      operation_id: operationId,
      status,
      request,
      policy,
      decision,
      view_reads: viewReads,
      authorization_evaluations: authorizationEvaluations,
      terminal_serialization: terminalSerialization,
      ...optionalReceiptFields,
      effect,
      recorded_at: recordedAt,
      ...resolutionMetadata,
    };
  }
  if (status === "denied") {
    if (decision.effect !== "deny" || record["effect"] !== null) {
      throw new MasuGateProtocolError("denied audit response must carry a deny and null effect");
    }
    return {
      operation_id: operationId,
      status,
      request,
      policy,
      decision,
      view_reads: viewReads,
      authorization_evaluations: authorizationEvaluations,
      terminal_serialization: terminalSerialization,
      ...optionalReceiptFields,
      effect: null,
      recorded_at: recordedAt,
      ...resolutionMetadata,
    };
  }
  if (status === "pending") {
    if (decision.effect !== "escalate" || record["effect"] !== null) {
      throw new MasuGateProtocolError(
        "pending audit response must carry an escalate and null effect",
      );
    }
    return {
      operation_id: operationId,
      status,
      request,
      policy,
      decision,
      view_reads: viewReads,
      authorization_evaluations: authorizationEvaluations,
      terminal_serialization: terminalSerialization,
      ...optionalReceiptFields,
      effect: null,
      recorded_at: recordedAt,
      ...resolutionMetadata,
    };
  }
  throw new MasuGateProtocolError("audit response.status is invalid");
}

async function responseJson(response: Response): Promise<unknown> {
  const text = await response.text();
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    throw new MasuGateProtocolError(`response is not valid JSON: ${errorMessage(error)}`);
  }
}

async function httpError(response: Response): Promise<MasuGateHttpError> {
  let value: unknown;
  try {
    value = await responseJson(response);
  } catch {
    return new MasuGateHttpError(`masugated returned HTTP ${response.status}`, {
      status: response.status,
      code: "http_error",
    });
  }

  if (isObject(value) && isObject(value["error"])) {
    const error = value["error"];
    const code = typeof error["code"] === "string" ? error["code"] : "http_error";
    const message =
      typeof error["message"] === "string"
        ? error["message"]
        : `masugated returned HTTP ${response.status}`;
    const details = error["details"];
    if (details === undefined) {
      return new MasuGateHttpError(message, { status: response.status, code });
    }
    return new MasuGateHttpError(message, {
      status: response.status,
      code,
      details: details as JsonValue,
    });
  }

  return new MasuGateHttpError(`masugated returned HTTP ${response.status}`, {
    status: response.status,
    code: "http_error",
  });
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

class PendingEventSseParser {
  #buffer = "";
  #data: string[] = [];
  #eventType = "";
  #eventId: string | undefined;

  push(text: string, final = false): PendingEvent[] {
    this.#buffer += text;
    const events: PendingEvent[] = [];
    let offset = 0;

    while (offset < this.#buffer.length) {
      const lineEnd = findLineEnd(this.#buffer, offset);
      if (lineEnd === -1) {
        break;
      }
      const terminator = this.#buffer[lineEnd];
      if (terminator === "\r" && lineEnd + 1 === this.#buffer.length && !final) {
        break;
      }
      const width =
        terminator === "\r" && this.#buffer[lineEnd + 1] === "\n" ? 2 : 1;
      const event = this.#line(this.#buffer.slice(offset, lineEnd));
      if (event !== undefined) {
        events.push(event);
      }
      offset = lineEnd + width;
    }
    this.#buffer = this.#buffer.slice(offset);

    if (final) {
      if (this.#buffer.length > 0) {
        const event = this.#line(this.#buffer);
        if (event !== undefined) {
          events.push(event);
        }
        this.#buffer = "";
      }
      const event = this.#dispatch();
      if (event !== undefined) {
        events.push(event);
      }
    }

    return events;
  }

  #line(line: string): PendingEvent | undefined {
    if (line.length === 0) {
      return this.#dispatch();
    }
    if (line.startsWith(":")) {
      return undefined;
    }

    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) {
      value = value.slice(1);
    }

    if (field === "data") {
      this.#data.push(value);
    } else if (field === "event") {
      this.#eventType = value;
    } else if (field === "id" && !value.includes("\0")) {
      this.#eventId = value;
    }
    return undefined;
  }

  #dispatch(): PendingEvent | undefined {
    if (this.#data.length === 0) {
      this.#eventType = "";
      this.#eventId = undefined;
      return undefined;
    }

    const data = this.#data.join("\n");
    this.#data = [];
    const eventType = this.#eventType;
    this.#eventType = "";
    const eventId = this.#eventId;
    this.#eventId = undefined;

    let decoded: unknown;
    try {
      decoded = JSON.parse(data) as unknown;
    } catch (error) {
      throw new MasuGateProtocolError(`pending event data is not valid JSON: ${errorMessage(error)}`);
    }
    const event = parsePendingEvent(decoded);
    if (eventType !== "" && eventType !== event.event_type) {
      throw new MasuGateProtocolError(
        `SSE event type ${eventType} does not match data event_type ${event.event_type}`,
      );
    }
    if (eventId === undefined) {
      throw new MasuGateProtocolError("pending SSE event is missing its id field");
    }
    if (eventId !== event.event_id) {
      throw new MasuGateProtocolError(
        `SSE id ${eventId} does not match data event_id ${event.event_id}`,
      );
    }
    return event;
  }
}

function findLineEnd(value: string, start: number): number {
  for (let index = start; index < value.length; index += 1) {
    const character = value[index];
    if (character === "\r" || character === "\n") {
      return index;
    }
  }
  return -1;
}

function parsePendingOperation(value: unknown, context: string): PendingOperation {
  const pending = contractObject(
    value,
    context,
    [
      "pending_id",
      "operation_id",
      "principal_id",
      "action",
      "args",
      "created_at",
      "resolution_plan",
      "reservation_safety_certificate_digest",
      "reservation_entitlement_digest",
      "decision",
      "audit_ref",
    ],
    [
      "pending_id",
      "operation_id",
      "principal_id",
      "action",
      "args",
      "created_at",
      "decision",
      "audit_ref",
    ],
  );
  const decisionContext = `${context}.decision`;
  const resolutionMetadata = parsePendingResolutionMetadata(pending, context);
  const decision = contractObject(
    pending["decision"],
    decisionContext,
    ["effect", "policy_id", "policy_version", "rule_id", "reason"],
    ["effect", "policy_id", "policy_version", "rule_id", "reason"],
  );
  if (decision["effect"] !== "escalate") {
    throw new MasuGateProtocolError(`${decisionContext}.effect must be escalate`);
  }
  return {
    pending_id: requireUuid(pending, "pending_id", context),
    operation_id: requireUuid(pending, "operation_id", context),
    principal_id: requireString(pending, "principal_id", context, true),
    action: requireString(pending, "action", context, true),
    args: parseJsonObject(pending["args"], `${context}.args`),
    created_at: requireDateTime(pending, "created_at", context),
    decision: {
      effect: "escalate",
      policy_id: requireString(decision, "policy_id", decisionContext, true),
      policy_version: requireString(decision, "policy_version", decisionContext),
      rule_id: requireString(decision, "rule_id", decisionContext, true),
      reason: requireString(decision, "reason", decisionContext),
    },
    audit_ref: requireAuditRef(pending, "audit_ref", context),
    ...resolutionMetadata,
  };
}

function parsePendingList(value: unknown): PendingList {
  const list = contractObject(
    value,
    "pending list response",
    ["items", "next_cursor"],
    ["items", "next_cursor"],
  );
  if (!Array.isArray(list["items"])) {
    throw new MasuGateProtocolError("pending list response.items must be an array");
  }
  return {
    items: list["items"].map((item, index) =>
      parsePendingOperation(item, `pending list response.items[${index}]`),
    ),
    next_cursor: requireString(list, "next_cursor", "pending list response", true),
  };
}

function parsePendingLookup<Payload extends JsonObject = JsonObject>(
  value: unknown,
): PendingLookup<Payload> {
  const lookup = contractObject(
    value,
    "pending lookup response",
    ["kind", "pending", "result"],
    ["kind"],
  );
  if (lookup["kind"] === "pending") {
    if (hasOwn(lookup, "result") || !hasOwn(lookup, "pending")) {
      throw new MasuGateProtocolError("pending lookup response.pending shape is invalid");
    }
    return {
      kind: "pending",
      pending: parsePendingOperation(lookup["pending"], "pending lookup response.pending"),
    };
  }
  if (lookup["kind"] === "terminal") {
    if (hasOwn(lookup, "pending") || !hasOwn(lookup, "result")) {
      throw new MasuGateProtocolError("pending lookup response.result shape is invalid");
    }
    return {
      kind: "terminal",
      result: parseResolvedActionResult<Payload>(lookup["result"]),
    };
  }
  throw new MasuGateProtocolError("pending lookup response.kind must be pending or terminal");
}

function parsePendingEvent(value: unknown): PendingEvent {
  const event = contractObject(
    value,
    "pending event",
    ["event_id", "event_type", "occurred_at", "pending"],
    ["event_id", "event_type", "occurred_at", "pending"],
  );
  const eventId = requireString(event, "event_id", "pending event", true);
  if (event["event_type"] !== "pending.created") {
    throw new MasuGateProtocolError("pending event.event_type must be pending.created");
  }
  return {
    event_id: eventId,
    event_type: "pending.created",
    occurred_at: requireDateTime(event, "occurred_at", "pending event"),
    pending: parsePendingOperation(event["pending"], "pending event.pending"),
  };
}
