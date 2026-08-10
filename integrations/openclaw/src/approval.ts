import {
  MasuGateClient,
  type AuditRecord,
  type PendingOperation,
  type ResolvePendingOptions,
  type ResolvedActionResult,
} from "@masugate/client";

import { governedRouteManifest, type MasuGateOpenClawConfig } from "./config.js";

/**
 * The only two decisions that attest a human choice in MasuGate's resolver
 * record. OpenClaw reports timeout, cancellation, and unexpected outcomes to
 * the callback as lifecycle facts, not as a person rejecting the operation.
 */
export type NativeApprovalDecision = "allow-once" | "deny";

export interface MasuGateApprovalClient {
  listPending(options?: { signal?: AbortSignal }): Promise<{ items: PendingOperation[] }>;
  getPending?(pendingId: string, options?: { signal?: AbortSignal }): Promise<
    | { kind: "pending"; pending: PendingOperation }
    | { kind: "terminal"; result: ResolvedActionResult }
  >;
  resolvePending(options: ResolvePendingOptions): Promise<ResolvedActionResult>;
  getAudit?(operationId: string, options?: { signal?: AbortSignal }): Promise<AuditRecord>;
}

export type MasuGateApprovalClientFactory = (input: {
  baseUrl: string;
  token: string;
  principalId?: string;
}) => MasuGateApprovalClient;

export interface PreparedNativeApproval {
  pending: PendingOperation;
  agentId: string;
  sessionKey: string;
  sessionId: string;
  expiresAt: number;
}

type StoredResolution = {
  decision: NativeApprovalDecision;
  result: Promise<ResolvedActionResult>;
};

type PreparedApprovalResult = {
  approval?: PreparedNativeApproval;
  expired: boolean;
  remainingMs: number;
};

type TrustedApprovalBinding = Pick<
  PreparedNativeApproval,
  "agentId" | "sessionKey" | "sessionId"
>;

function isTerminalResolution(result: ResolvedActionResult): boolean {
  return result.status === "committed" || result.status === "denied";
}

type InFlightPreparation = {
  agentId: string;
  sessionKey: string;
  sessionId: string;
  result: Promise<PreparedApprovalResult>;
};

function tokenFor(
  environment: Readonly<Record<string, string | undefined>>,
  name: string,
  purpose: string,
): string {
  const token = environment[name];
  if (token === undefined || token.length === 0) {
    throw new Error(`${purpose} credential environment variable ${name} is missing`);
  }
  return token;
}

function defaultClientFactory(input: {
  baseUrl: string;
  token: string;
  principalId?: string;
}): MasuGateApprovalClient {
  return new MasuGateClient(input);
}

/**
 * Binds a transient OpenClaw native-approval presentation to a MasuGate-owned
 * durable pending locator. The bridge never creates an entitlement, invents
 * an approval, or invokes a protected connector: the only resolution action
 * is the ordinary MasuGate pending-resolution endpoint.
 */
export class NativeApprovalBridge {
  readonly #config: MasuGateOpenClawConfig;
  readonly #environment: Readonly<Record<string, string | undefined>>;
  readonly #createClient: MasuGateApprovalClientFactory;
  readonly #now: () => number;
  readonly #prepared = new Map<string, PreparedNativeApproval>();
  readonly #terminalBindings = new Map<string, TrustedApprovalBinding>();
  readonly #preparing = new Map<string, InFlightPreparation>();
  readonly #resolutions = new Map<string, StoredResolution>();
  readonly #resolutionDecisions = new Map<string, NativeApprovalDecision>();

  constructor(options: {
    config: MasuGateOpenClawConfig;
    environment: Readonly<Record<string, string | undefined>>;
    createClient?: MasuGateApprovalClientFactory;
    now?: () => number;
  }) {
    if (options.config.nativeApproval === undefined) {
      throw new Error("native approval bridge requires plugin config.nativeApproval");
    }
    this.#config = options.config;
    this.#environment = options.environment;
    this.#createClient = options.createClient ?? defaultClientFactory;
    this.#now = options.now ?? Date.now;
  }

  async prepare(options: {
    pendingId: string;
    agentId: string;
    sessionKey: string;
    sessionId: string;
    signal?: AbortSignal;
  }): Promise<PreparedApprovalResult> {
    const actionTokenName = this.#config.agents[options.agentId];
    if (actionTokenName === undefined) {
      throw new Error(`OpenClaw agent ${options.agentId} has no MasuGate credential binding`);
    }
    const actionClient = this.#createClient({
      baseUrl: this.#config.masugatedBaseUrl,
      token: tokenFor(this.#environment, actionTokenName, "MasuGate action"),
      principalId: `openclaw:${options.agentId}`,
    });
    const existing = this.#prepared.get(options.pendingId);
    if (existing !== undefined) {
      this.#assertTrustedBinding(existing, options);
      // The native callback is intentionally asynchronous in the pinned
      // Gateway. A MasuGate restart can therefore leave this presentation object
      // alive while its first resolver request returns an in-progress or
      // transient result. Re-read only the exact audited native decision
      // before a same-session retry; this is evidence recovery, never a new
      // approval authority.
      const decision = await this.#nativeDecisionFromAudit(
        actionClient,
        {
          operationId: existing.pending.operation_id,
          pendingId: existing.pending.pending_id,
          ...existing,
        },
        options.signal,
      );
      if (decision !== undefined) {
        this.#resolutionDecisions.set(existing.pending.pending_id, decision);
      }
      return this.#preparedResult(existing);
    }
    const inFlight = this.#preparing.get(options.pendingId);
    if (inFlight !== undefined) {
      this.#assertTrustedBinding(inFlight, options);
      return inFlight.result;
    }
    // Install the owner and promise before awaiting listPending().  A second
    // presentation for the same locator therefore either shares this exact
    // binding or fails immediately; it cannot race to overwrite it later.
    const result = this.#prepareFirst(options, actionClient);
    this.#preparing.set(options.pendingId, {
      agentId: options.agentId,
      sessionKey: options.sessionKey,
      sessionId: options.sessionId,
      result,
    });
    try {
      return await result;
    } finally {
      if (this.#preparing.get(options.pendingId)?.result === result) {
        this.#preparing.delete(options.pendingId);
      }
    }
  }

  async #prepareFirst(options: {
    pendingId: string;
    agentId: string;
    sessionKey: string;
    sessionId: string;
    signal?: AbortSignal;
  }, actionClient: MasuGateApprovalClient): Promise<PreparedApprovalResult> {
    const snapshot = await actionClient.listPending(
      options.signal === undefined ? {} : { signal: options.signal },
    );
    let pending = snapshot.items.find(
      (item) => item.pending_id === options.pendingId,
    );
    if (pending === undefined) {
      if (actionClient.getPending !== undefined) {
        const lookup = await actionClient.getPending(
          options.pendingId,
          options.signal === undefined ? {} : { signal: options.signal },
        );
        if (lookup.kind === "pending") {
          pending = lookup.pending;
        } else {
          return this.#recoverTerminalNativeResolution(
            actionClient,
            lookup.result,
            options,
          );
        }
      }
    }
    if (pending === undefined) {
      throw new Error("unknown, terminal, or foreign MasuGate pending locator");
    }
    if (pending.principal_id !== `openclaw:${options.agentId}`) {
      throw new Error("MasuGate pending locator belongs to a different OpenClaw agent");
    }
    if (
      !governedRouteManifest(this.#config).routes.some(
        (route) => route.action === pending.action,
      )
    ) {
      throw new Error("MasuGate pending locator names an undeclared governed action");
    }
    const createdAt = Date.parse(pending.created_at);
    if (!Number.isSafeInteger(createdAt)) {
      throw new Error("MasuGate pending locator has an invalid durable creation time");
    }
    const approvalConfig = this.#config.nativeApproval;
    if (approvalConfig === undefined) {
      throw new Error("native approval bridge lost its configured timeout");
    }
    const approval = {
      pending,
      agentId: options.agentId,
      sessionKey: options.sessionKey,
      sessionId: options.sessionId,
      expiresAt: createdAt + approvalConfig.timeoutMs,
    };
    this.#prepared.set(options.pendingId, approval);
    const decision = await this.#nativeDecisionFromAudit(
      actionClient,
      {
        operationId: approval.pending.operation_id,
        pendingId: approval.pending.pending_id,
        ...approval,
      },
      options.signal,
    );
    if (decision !== undefined) {
      this.#resolutionDecisions.set(approval.pending.pending_id, decision);
    }
    return this.#preparedResult(approval);
  }

  async #recoverTerminalNativeResolution(
    actionClient: MasuGateApprovalClient,
    result: ResolvedActionResult,
    options: {
      pendingId: string;
      agentId: string;
      sessionKey: string;
      sessionId: string;
      signal?: AbortSignal;
    },
  ): Promise<PreparedApprovalResult> {
    if (!isTerminalResolution(result)) {
      throw new Error("MasuGate terminal locator lookup returned a nonterminal result");
    }
    const decision = await this.#nativeDecisionFromAudit(
      actionClient,
      {
        operationId: result.operation_id,
        pendingId: options.pendingId,
        agentId: options.agentId,
        sessionKey: options.sessionKey,
        sessionId: options.sessionId,
      },
      options.signal,
    );
    if (decision === undefined) {
      throw new Error("terminal MasuGate locator lacks matching native approval evidence");
    }
    this.#terminalBindings.set(options.pendingId, {
      agentId: options.agentId,
      sessionKey: options.sessionKey,
      sessionId: options.sessionId,
    });
    this.#resolutionDecisions.set(options.pendingId, decision);
    this.#resolutions.set(options.pendingId, { decision, result: Promise.resolve(result) });
    return { expired: false, remainingMs: 0 };
  }

  async #nativeDecisionFromAudit(
    actionClient: MasuGateApprovalClient,
    binding: TrustedApprovalBinding & { operationId: string; pendingId: string },
    signal: AbortSignal | undefined,
  ): Promise<NativeApprovalDecision | undefined> {
    // The pinned host may execute the asynchronous native callback in a
    // different tool runtime from the later resume turn.  Its transient map
    // is therefore only an optimization.  Rehydrate a decision exclusively
    // from MasuGate's authenticated audit record, and only when every trusted
    // host binding field agrees with the current presentation.
    if (actionClient.getAudit === undefined) {
      return;
    }
    const record = await actionClient.getAudit(
      binding.operationId,
      signal === undefined ? {} : { signal },
    );
    const human = record.human_resolution;
    if (human === undefined) {
      return;
    }
    const evidence = human.evidence;
    if (evidence["source"] !== "openclaw-native-approval") {
      throw new Error("MasuGate pending locator already has a non-native human resolution");
    }
    const decision = evidence["decision"];
    const exactBinding =
      evidence["agent_id"] === binding.agentId &&
      evidence["pending_id"] === binding.pendingId &&
      evidence["session_key"] === binding.sessionKey &&
      evidence["session_id"] === binding.sessionId;
    if (decision !== "allow-once" && decision !== "deny") {
      throw new Error("MasuGate native approval evidence has an unsupported decision");
    }
    if (!exactBinding || (decision === "allow-once" ? !human.approved : human.approved)) {
      throw new Error("MasuGate native approval evidence does not match this trusted session");
    }
    return decision;
  }

  #preparedResult(approval: PreparedNativeApproval): PreparedApprovalResult {
    // The native host UI must not remain actionable beyond the durable MasuGate
    // deadline.  MasuGate still performs the authoritative expiry check when a
    // resolver callback races this display timeout.
    const remainingMs = Math.max(0, approval.expiresAt - this.#now());
    return { approval, expired: remainingMs === 0, remainingMs };
  }

  #assertTrustedBinding(
    binding: Pick<PreparedNativeApproval, "agentId" | "sessionKey" | "sessionId">,
    options: Pick<PreparedNativeApproval, "agentId" | "sessionKey" | "sessionId">,
  ): void {
    if (binding.agentId !== options.agentId) {
      throw new Error("MasuGate pending locator is bound to a different trusted OpenClaw agent");
    }
    if (binding.sessionKey !== options.sessionKey) {
      throw new Error("MasuGate pending locator is bound to a different trusted OpenClaw session");
    }
    if (binding.sessionId !== options.sessionId) {
      throw new Error("MasuGate pending locator is bound to a different trusted OpenClaw session epoch");
    }
  }

  resolve(
    approval: PreparedNativeApproval,
    decision: NativeApprovalDecision,
  ): Promise<ResolvedActionResult> {
    // Keep this check at the runtime boundary as well as in the TypeScript
    // type. A pinned host plugin callback can report timeout/cancelled, and
    // serializing either as ``approved: false`` would create false
    // human-resolution evidence in an authoritative MasuGate receipt.
    if (decision !== "allow-once" && decision !== "deny") {
      throw new Error("only an explicit native allow-once or deny may resolve MasuGate approval");
    }
    const existing = this.#resolutions.get(approval.pending.pending_id);
    if (existing !== undefined) {
      if (existing.decision !== decision) {
        throw new Error("native approval delivered conflicting resolutions for one MasuGate locator");
      }
      return existing.result;
    }
    const selectedDecision = this.#resolutionDecisions.get(approval.pending.pending_id);
    if (selectedDecision !== undefined && selectedDecision !== decision) {
      throw new Error("native approval delivered conflicting resolutions for one MasuGate locator");
    }
    const approvalConfig = this.#config.nativeApproval;
    if (approvalConfig === undefined) {
      throw new Error("native approval bridge lost its configured resolver");
    }
    const resolver = this.#createClient({
      baseUrl: this.#config.masugatedBaseUrl,
      token: tokenFor(
        this.#environment,
        approvalConfig.resolverTokenEnv,
        "MasuGate native-approval resolver",
      ),
    });
    const result = resolver.resolvePending({
      pendingId: approval.pending.pending_id,
      approved: decision === "allow-once",
      evidence: {
        agent_id: approval.agentId,
        decision,
        pending_id: approval.pending.pending_id,
        session_id: approval.sessionId,
        session_key: approval.sessionKey,
        source: "openclaw-native-approval",
      },
    });
    const pendingId = approval.pending.pending_id;
    this.#resolutionDecisions.set(pendingId, decision);
    this.#resolutions.set(pendingId, { decision, result });
    // Only terminal MasuGate receipts are safe same-session replay results.  A
    // rejected request, in-progress lease observation, or outcome-unknown
    // recovery snapshot is not a durable native decision; retain the selected
    // decision for conflict detection but let an identical retry reconsult
    // MasuGate after recovery settles the persisted handoff.
    void result.then(
      (value) => {
        if (!isTerminalResolution(value) && this.#resolutions.get(pendingId)?.result === result) {
          this.#resolutions.delete(pendingId);
        }
      },
      () => {
        if (this.#resolutions.get(pendingId)?.result === result) {
          this.#resolutions.delete(pendingId);
        }
      },
    );
    return result;
  }

  resolution(pendingId: string): Promise<ResolvedActionResult> | undefined {
    return this.#resolutions.get(pendingId)?.result;
  }

  /**
   * Return a completed terminal result only after binding it to the trusted
   * caller that originally presented this locator.  The action-facing pending
   * list deliberately drops terminal rows, so a same-Gateway replay cannot
   * re-run ``prepare()`` before consulting this cache.  A missing prepared
   * binding (for example after a Gateway restart) is never treated as a cache
   * hit and must start a fresh native presentation.
   */
  async terminalResolutionFor(options: {
    pendingId: string;
    agentId: string;
    sessionKey: string;
    sessionId: string;
  }): Promise<ResolvedActionResult | undefined> {
    const prepared = this.#prepared.get(options.pendingId) ?? this.#terminalBindings.get(options.pendingId);
    const stored = this.#resolutions.get(options.pendingId);
    if (prepared === undefined || stored === undefined) {
      return undefined;
    }
    this.#assertTrustedBinding(prepared, options);
    const result = await stored.result;
    return isTerminalResolution(result) ? result : undefined;
  }

  /**
   * Return the one native decision already bound to this prepared locator.
   *
   * This is deliberately not durable authority: callers must first prepare
   * the locator under the same trusted OpenClaw identity, then submit the
   * returned decision back to MasuGate.  It lets a retry reconsult MasuGate after an
   * in-progress/outcome-unknown recovery receipt without presenting a second
   * human choice for the same recorded decision.
   */
  selectedDecision(pendingId: string): NativeApprovalDecision | undefined {
    return this.#resolutionDecisions.get(pendingId);
  }
}
