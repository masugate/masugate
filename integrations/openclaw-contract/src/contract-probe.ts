import { createHash } from "node:crypto";

import { Type } from "typebox";
import {
  definePluginEntry,
  type OpenClawPluginApi,
  type OpenClawPluginToolContext,
  type PluginNextTurnInjectionEnqueueResult,
} from "openclaw/plugin-sdk/plugin-entry";
import { jsonResult } from "openclaw/plugin-sdk/tool-results";

export const CONTRACT_PROBE_TOOL = "masugate_contract_probe";
export const NATIVE_APPROVAL_TIMEOUT_MS = 600_000;

export type ContractProbeInput = {
  amount: number;
  principal?: string;
  idempotencyKey?: string;
  runId?: string;
};

export type TrustedInvocationIdentity = {
  agentId: string;
  sessionNamespace: string;
  sessionId: string;
  toolCallId: string;
  principal: string;
  idempotencyKey: string;
  traceId: string;
};

export type ProtectedExecutionRequest = {
  identity: TrustedInvocationIdentity;
  input: {
    amount: number;
  };
  /**
   * The host cancellation signal is forwarded to MasuGate.  Cancellation before
   * dispatch prevents this callback; after dispatch it is an uncertain-result
   * boundary, not proof that a protected effect did not commit.
   */
  signal?: AbortSignal;
};

export type ContractProbeOptions<TResult> = {
  executeProtected: (request: ProtectedExecutionRequest) => Promise<TResult>;
  onApprovalResolution?: (
    resolution: "allow-once" | "allow-always" | "deny" | "timeout" | "cancelled",
    identity: TrustedInvocationIdentity,
  ) => Promise<void> | void;
};

export type ApprovalResumeRequest = {
  sessionKey: string;
  pendingId: string;
  ttlMs: number;
};

type HookIdentityInput = {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  toolCallId?: string;
};

function requireTrustedString(value: string | undefined, field: string): string {
  const normalized = value?.trim();
  if (!normalized) {
    throw new Error(`missing trusted OpenClaw ${field}`);
  }
  if (normalized.length > 256) {
    throw new Error(`invalid trusted OpenClaw ${field}`);
  }
  return normalized;
}

function requireOpaqueIdentifier(value: string | undefined, field: string): string {
  const normalized = requireTrustedString(value, field);
  if (normalized.length > 128 || !/^[A-Za-z0-9._:-]+$/.test(normalized)) {
    throw new Error(`invalid ${field}`);
  }
  return normalized;
}

export function deriveTrustedInvocationIdentity(
  context: Pick<
    OpenClawPluginToolContext,
    "agentId" | "sessionId" | "sessionKey"
  >,
  toolCallId: string,
): TrustedInvocationIdentity {
  const agentId = requireTrustedString(context.agentId, "agentId");
  const sessionNamespace = requireTrustedString(context.sessionKey, "sessionKey");
  // OpenClaw retains sessionKey across /new, daily reset, and idle expiry.
  // sessionId is the invocation generation that prevents a later transcript
  // from colliding with a recycled tool-call id in that stable namespace.
  const sessionId = requireTrustedString(context.sessionId, "sessionId");
  const trustedToolCallId = requireTrustedString(toolCallId, "toolCallId");
  const canonicalInvocation = JSON.stringify([
    "openclaw",
    2,
    agentId,
    sessionNamespace,
    sessionId,
    trustedToolCallId,
  ]);
  const invocationDigest = createHash("sha256").update(canonicalInvocation, "utf8").digest("hex");

  return {
    agentId,
    sessionNamespace,
    sessionId,
    toolCallId: trustedToolCallId,
    principal: `openclaw:${agentId}`,
    idempotencyKey: `openclaw:v2:${invocationDigest}`,
    traceId: `openclaw:v2:trace:${invocationDigest}`,
  };
}

function deriveHookIdentity(
  event: { toolCallId?: string },
  context: HookIdentityInput,
): TrustedInvocationIdentity {
  if (event.toolCallId && context.toolCallId && event.toolCallId !== context.toolCallId) {
    throw new Error("conflicting trusted OpenClaw toolCallId values");
  }
  return deriveTrustedInvocationIdentity(
    {
      ...(context.agentId ? { agentId: context.agentId } : {}),
      ...(context.sessionId ? { sessionId: context.sessionId } : {}),
      ...(context.sessionKey ? { sessionKey: context.sessionKey } : {}),
    },
    event.toolCallId ?? context.toolCallId ?? "",
  );
}

export async function enqueueApprovalResume(
  api: Pick<OpenClawPluginApi, "session">,
  request: ApprovalResumeRequest,
): Promise<PluginNextTurnInjectionEnqueueResult> {
  const sessionKey = requireTrustedString(request.sessionKey, "sessionKey");
  const pendingId = requireOpaqueIdentifier(request.pendingId, "MasuGate pendingId");
  if (!Number.isSafeInteger(request.ttlMs) || request.ttlMs <= 0) {
    throw new Error("approval resume ttlMs must be a positive safe integer");
  }
  return api.session.workflow.enqueueNextTurnInjection({
    sessionKey,
    text:
      `MasuGate pending operation ${pendingId} still requires a decision. ` +
      "Use the MasuGate-owned resume tool; do not infer approval or repeat the external effect.",
    idempotencyKey: `masugate-approval-resume:${pendingId}`,
    placement: "prepend_context",
    ttlMs: request.ttlMs,
    metadata: {
      kind: "masugate-approval-resume",
      pendingId,
    },
  });
}

export function createContractProbe<TResult>(
  options: ContractProbeOptions<TResult>,
): ReturnType<typeof definePluginEntry> {
  return definePluginEntry({
    id: "masugate-contract-probe",
    name: "MasuGate Contract Probe",
    description: "Probes the pinned trusted-identity and MasuGate-owned result contract.",
    register(api) {
      api.registerTool(
        (context) => ({
          name: CONTRACT_PROBE_TOOL,
          label: "MasuGate contract probe",
          description: "Exercise the MasuGate-owned OpenClaw compatibility path.",
          parameters: Type.Object({
            amount: Type.Number(),
            principal: Type.Optional(Type.String()),
            idempotencyKey: Type.Optional(Type.String()),
            runId: Type.Optional(Type.String()),
          }),
          async execute(toolCallId, rawInput, signal) {
            if (signal?.aborted) {
              throw signal.reason ?? new Error("contract probe cancelled");
            }
            const input = rawInput as ContractProbeInput;
            const identity = deriveTrustedInvocationIdentity(context, toolCallId);
            const protectedResult = await options.executeProtected({
              identity,
              input: { amount: input.amount },
              ...(signal === undefined ? {} : { signal }),
            });
            // The MasuGate-owned tool returns the authoritative protected result
            // unchanged.  Do not wrap a denied or pending outcome in a
            // misleading outer "committed" status.
            return jsonResult(protectedResult);
          },
        }),
        { name: CONTRACT_PROBE_TOOL, optional: true },
      );

      api.on("before_tool_call", async (event, context) => {
        if (event.toolName !== CONTRACT_PROBE_TOOL) {
          return;
        }

        let identity: TrustedInvocationIdentity;
        try {
          identity = deriveHookIdentity(event, context);
        } catch (error) {
          return {
            block: true,
            blockReason: error instanceof Error ? error.message : String(error),
          };
        }

        return {
          requireApproval: {
            title: "Run governed MasuGate probe",
            description: `Authorize ${identity.principal} for this bounded test call.`,
            severity: "warning",
            timeoutMs: NATIVE_APPROVAL_TIMEOUT_MS,
            timeoutBehavior: "deny",
            allowedDecisions: ["allow-once", "deny"],
            pluginId: "masugate-contract-probe",
            async onResolution(resolution) {
              await options.onApprovalResolution?.(resolution, identity);
            },
          },
        };
      });
    },
  });
}

const contractProbe: ReturnType<typeof definePluginEntry> = createContractProbe({
  async executeProtected(request) {
    return {
      probe: true,
      idempotencyKey: request.identity.idempotencyKey,
      amount: request.input.amount,
    };
  },
});

export default contractProbe;
