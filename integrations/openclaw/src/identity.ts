import { createHash } from "node:crypto";

import type { OpenClawPluginToolContext } from "openclaw/plugin-sdk/plugin-entry";

export interface TrustedInvocationIdentity {
  agentId: string;
  principalId: string;
  sessionNamespace: string;
  sessionId: string;
  toolCallId: string;
  stableId: string;
  traceId: string;
}

function trustedString(value: string | undefined, field: string): string {
  const normalized = value?.trim();
  if (!normalized) {
    throw new Error(`missing trusted OpenClaw ${field}`);
  }
  if (normalized.length > 256 || !/^[A-Za-z0-9._:@/-]+$/u.test(normalized)) {
    throw new Error(`invalid trusted OpenClaw ${field}`);
  }
  return normalized;
}

export function deriveTrustedInvocationIdentity(
  context: Pick<OpenClawPluginToolContext, "agentId" | "sessionId" | "sessionKey">,
  toolCallId: string,
): TrustedInvocationIdentity {
  const agentId = trustedString(context.agentId, "agentId");
  const sessionNamespace = trustedString(context.sessionKey, "sessionKey");
  // sessionKey survives transcript generations. sessionId is therefore a
  // required invocation epoch, not optional trace decoration.
  const sessionId = trustedString(context.sessionId, "sessionId");
  const trustedToolCallId = trustedString(toolCallId, "toolCallId");
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
    principalId: `openclaw:${agentId}`,
    sessionNamespace,
    sessionId,
    toolCallId: trustedToolCallId,
    stableId: `openclaw:v2:${invocationDigest}`,
    traceId: `openclaw:v2:trace:${invocationDigest}`,
  };
}
