import {
  MasuGateClient,
  validateAnyGovernedRouteManifest,
  type ActionArguments,
  type ActionResult,
  type JsonObject,
  type PendingOperation,
} from "@masugate/client";
import {
  AdapterCapabilities,
  GovernedRouteParser,
  GovernedToolRuntime,
  TrustedInvocation,
  type GovernedActionClient,
} from "@masugate/adapter-core";
import { Type, type TSchema } from "typebox";
import {
  definePluginEntry,
  type OpenClawPluginApi,
  type OpenClawPluginToolContext,
} from "openclaw/plugin-sdk/plugin-entry";
import { jsonResult } from "openclaw/plugin-sdk/tool-results";

import {
  governedRouteManifest,
  parsePluginConfig,
  type MasuGateOpenClawConfig,
} from "./config.js";
import {
  NativeApprovalBridge,
  type MasuGateApprovalClientFactory,
} from "./approval.js";
import { deriveTrustedInvocationIdentity } from "./identity.js";

export const MASUGATE_GOVERNED_TOOL = "masugate_governed_action";
export const MASUGATE_RESUME_PENDING_TOOL = "masugate_resume_pending";

/** Public GAP wire shapes; the adapter must not maintain a divergent copy. */
export type MasuGateActionArguments = ActionArguments;
export type MasuGateActionResult = ActionResult;

/** The public GAP execute surface used by the governed-tool runtime. */
export type MasuGateActionClient = Pick<GovernedActionClient, "execute">;

export interface MasuGateOpenClawPluginOptions {
  env?: Readonly<Record<string, string | undefined>>;
  createClient?: (input: {
    baseUrl: string;
    token: string;
    principalId: string;
  }) => MasuGateActionClient;
  createApprovalClient?: MasuGateApprovalClientFactory;
  now?: () => number;
}

type ToolInput = {
  route: string;
  args: MasuGateActionArguments;
};

type ResumeInput = {
  pendingId: string;
};

function parseToolInput(raw: unknown): ToolInput {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("MasuGate governed tool input must be an object");
  }
  const input = raw as Record<string, unknown>;
  const keys = Object.keys(input);
  if (keys.some((key) => key !== "route" && key !== "args")) {
    throw new Error("MasuGate governed tool accepts only route and args");
  }
  if (typeof input["route"] !== "string" || input["route"].length === 0) {
    throw new Error("MasuGate governed tool route must be a non-empty string");
  }
  if (typeof input["args"] !== "object" || input["args"] === null || Array.isArray(input["args"])) {
    throw new Error("MasuGate governed tool args must be an object");
  }
  return { route: input["route"], args: input["args"] as MasuGateActionArguments };
}

function parseResumeInput(raw: unknown): ResumeInput {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("MasuGate pending resume input must be an object");
  }
  const input = raw as Record<string, unknown>;
  if (Object.keys(input).length !== 1 || !Object.hasOwn(input, "pending_id")) {
    throw new Error("MasuGate pending resume accepts only pending_id");
  }
  const pendingId = input["pending_id"];
  if (
    typeof pendingId !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      pendingId,
    )
  ) {
    throw new Error("MasuGate pending resume requires a canonical pending_id");
  }
  return { pendingId };
}

function boundedSchemaToTypeBox(schema: Record<string, unknown>): TSchema {
  switch (schema["type"]) {
    case "string":
      return Type.String({
        minLength: schema["minLength"] as number,
        maxLength: schema["maxLength"] as number,
      });
    case "integer":
      return Type.Integer({
        minimum: schema["minimum"] as number,
        maximum: schema["maximum"] as number,
      });
    case "boolean":
      return Type.Boolean();
    case "array":
      return Type.Array(boundedSchemaToTypeBox(schema["items"] as Record<string, unknown>), {
        minItems: schema["minItems"] as number,
        maxItems: schema["maxItems"] as number,
      });
    case "object": {
      const properties: Record<string, TSchema> = Object.create(null) as Record<string, TSchema>;
      const required = new Set(schema["required"] as string[]);
      for (const [name, child] of Object.entries(schema["properties"] as Record<string, unknown>)) {
        const parsed = boundedSchemaToTypeBox(child as Record<string, unknown>);
        properties[name] = required.has(name) ? parsed : Type.Optional(parsed);
      }
      return Type.Object(properties, { additionalProperties: false });
    }
    default:
      throw new Error("MasuGate v2 route has an unsupported bounded schema");
  }
}

/** Generate the exact model-visible TypeBox schema for a trusted v1 or v2 route manifest. */
export function governedRouteParameters(manifest: unknown): TSchema {
  const parsed = validateAnyGovernedRouteManifest(manifest);
  if (parsed.contract_version === "masugate.governed-route-manifest.v1") {
    const choices = parsed.routes.map((route) => {
      const argumentSchemas: Record<string, TSchema> = Object.create(null) as Record<
        string,
        TSchema
      >;
      for (const [name, kind] of Object.entries(route.arguments)) {
        argumentSchemas[name] =
          kind === "string" ? Type.String() : kind === "boolean" ? Type.Boolean() : Type.Integer();
      }
      return Type.Object(
        {
          route: Type.Literal(route.host_tool),
          args: Type.Object(argumentSchemas, { additionalProperties: false }),
        },
        { additionalProperties: false },
      );
    });
    return choices.length === 1 ? choices[0]! : Type.Union(choices);
  }

  const choices = parsed.routes.map((route) => {
    return Type.Object(
      {
        route: Type.Literal(route.host_tool),
        args: boundedSchemaToTypeBox(route.input_schema as Record<string, unknown>),
      },
      { additionalProperties: false },
    );
  });
  return choices.length === 1 ? choices[0]! : Type.Union(choices);
}

function tokenForAgent(
  config: MasuGateOpenClawConfig,
  agentId: string,
  env: Readonly<Record<string, string | undefined>>,
): string {
  const tokenEnv = config.agents[agentId];
  if (tokenEnv === undefined) {
    throw new Error(`OpenClaw agent ${agentId} has no MasuGate credential binding`);
  }
  const token = env[tokenEnv];
  if (token === undefined || token.length === 0) {
    throw new Error(`MasuGate credential environment variable ${tokenEnv} is missing`);
  }
  return token;
}

function createTool(
  context: OpenClawPluginToolContext,
  config: MasuGateOpenClawConfig,
  manifest: unknown,
  routes: GovernedRouteParser,
  options: MasuGateOpenClawPluginOptions,
  onPending?: (pendingId: string, sessionKey: string) => Promise<void>,
) {
  return {
    name: MASUGATE_GOVERNED_TOOL,
    label: "MasuGate governed action",
    description:
      "Execute one deployment-declared action through MasuGate. Return its authoritative terminal, human-pending, or protected operational result; never repeat it with a native tool.",
    parameters: governedRouteParameters(manifest),
    async execute(toolCallId: string, rawInput: unknown, signal?: AbortSignal) {
      if (signal?.aborted) {
        throw signal.reason ?? new Error("MasuGate governed action cancelled");
      }
      const identity = deriveTrustedInvocationIdentity(context, toolCallId);
      const input = parseToolInput(rawInput);
      // Reject a quarantined route through the shared manifest before looking
      // up credentials or constructing an HTTP client.
      routes.select(input.route);
      const env = options.env ?? process.env;
      const token = tokenForAgent(config, identity.agentId, env);
      const createClient =
        options.createClient ??
        ((clientInput: { baseUrl: string; token: string; principalId: string }) =>
          new MasuGateClient(clientInput));
      const client = createClient({
        baseUrl: config.masugatedBaseUrl,
        token,
        principalId: identity.principalId,
      });
      // OpenClaw owns context extraction and this established v2 identity
      // derivation. The shared core owns route selection, exact scalar
      // validation, certified owner assertions, canonical provenance, and
      // authoritative lifecycle classification.
      const runtime = new GovernedToolRuntime(
        client as GovernedActionClient,
        routes,
        new TrustedInvocation({
          principalId: identity.principalId,
          sourceNamespace: "openclaw",
          sourceId: identity.stableId,
          stableId: identity.stableId,
          traceId: identity.traceId,
          adapter: new AdapterCapabilities("masugate.openclaw", [
            "locator",
            "pending-presentation",
          ]),
        }),
      );
      const lifecycle = signal === undefined
        ? await runtime.invoke(input.route, input.args)
        : await runtime.invoke(input.route, input.args, { signal });
      const result = lifecycle.result;
      if (result.status === "pending" && onPending !== undefined) {
        await onPending(result.pending_id, identity.sessionNamespace);
      }
      return jsonResult(result);
    },
  };
}

function createResumeTool(
  context: OpenClawPluginToolContext,
  bridge: NativeApprovalBridge,
) {
  return {
    name: MASUGATE_RESUME_PENDING_TOOL,
    label: "MasuGate approval resume",
    description:
      "Present native allow-once or deny for one durable MasuGate pending operation. " +
      "This tool never creates a replacement action or directly invokes a provider.",
    parameters: Type.Object(
      { pending_id: Type.String({ minLength: 36, maxLength: 36 }) },
      { additionalProperties: false },
    ),
    async execute(toolCallId: string, rawInput: unknown, signal?: AbortSignal) {
      if (signal?.aborted) {
        throw signal.reason ?? new Error("MasuGate pending resume cancelled");
      }
      const input = parseResumeInput(rawInput);
      // A terminal cache is only a same-session replay optimization.  Always
      // derive trusted caller identity and re-check the durable locator's
      // in-memory binding before returning it; otherwise a different session
      // that learns a pending UUID could read another session's resolution.
      const trusted = deriveTrustedInvocationIdentity(context, toolCallId);
      const cachedTerminal = await bridge.terminalResolutionFor({
        pendingId: input.pendingId,
        agentId: trusted.agentId,
        sessionKey: trusted.sessionNamespace,
        sessionId: trusted.sessionId,
      });
      if (cachedTerminal !== undefined) {
        return jsonResult(cachedTerminal);
      }
      const prepared = await bridge.prepare({
        pendingId: input.pendingId,
        agentId: trusted.agentId,
        sessionKey: trusted.sessionNamespace,
        sessionId: trusted.sessionId,
        ...(signal === undefined ? {} : { signal }),
      });
      const selectedDecision = bridge.selectedDecision(input.pendingId);
      const existing = bridge.resolution(input.pendingId);
      if (existing !== undefined) {
        return jsonResult(await existing);
      }
      const approval = prepared.approval;
      if (approval === undefined) {
        // A fresh Gateway runtime may discover a terminal locator through the
        // owner-scoped MasuGate lookup while the pre-hook is already returning.
        // Never synthesize a prompt or decision in that race: re-read only the
        // exact trusted terminal cache populated from its audited binding.
        const terminal = await bridge.terminalResolutionFor({
          pendingId: input.pendingId,
          agentId: trusted.agentId,
          sessionKey: trusted.sessionNamespace,
          sessionId: trusted.sessionId,
        });
        if (terminal !== undefined) {
          return jsonResult(terminal);
        }
        throw new Error("MasuGate terminal lookup did not retain its trusted native binding");
      }
      // A recorded native decision is a same-session presentation fact, not a
      // terminal result.  Re-submit that exact decision to the durable MasuGate
      // resolver after a nonterminal recovery observation; never ask the
      // person to decide a second time for the same locator.
      if (selectedDecision !== undefined) {
        return jsonResult(await bridge.resolve(approval, selectedDecision));
      }
      if (prepared.expired) {
        // Host timeout/cancellation is not a human denial. Do not create a
        // false ``human_resolution`` just to make this tool return a terminal
        // envelope; the durable MasuGate deadline remains authoritative and will
        // settle through its automatic-expiry path.
        throw new Error("MasuGate native approval presentation expired; await durable automatic expiry");
      }
      return jsonResult({
        status: "pending",
        pending_id: approval.pending.pending_id,
        operation_id: approval.pending.operation_id,
        reason: "native approval is required for the durable MasuGate pending operation",
      });
    },
  };
}

function canonicalApprovalArguments(argumentsValue: JsonObject): string {
  // Current governed route arguments are scalar, but sort defensively so the
  // native record remains stable if a future declared route gains nested JSON.
  const sort = (value: unknown): unknown => {
    if (Array.isArray(value)) {
      return value.map(sort);
    }
    if (typeof value === "object" && value !== null) {
      return Object.fromEntries(
        Object.entries(value as Record<string, unknown>)
          .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
          .map(([key, nested]) => [key, sort(nested)]),
      );
    }
    return value;
  };
  return JSON.stringify(sort(argumentsValue));
}

function nativeApprovalDescription(pending: PendingOperation): string {
  return [
    "MasuGate has durably prepared this exact protected operation:",
    `Principal: ${pending.principal_id}`,
    `Action: ${pending.action}`,
    `Arguments: ${canonicalApprovalArguments(pending.args)}`,
    `Pending locator: ${pending.pending_id}`,
    `Audit record: ${pending.audit_ref}`,
    "Allow once records this choice with MasuGate and authorizes MasuGate to attempt the protected effect once. It does not invoke a local native tool.",
  ].join("\n");
}

async function enqueueApprovalResume(
  api: Pick<OpenClawPluginApi, "session">,
  { sessionKey, pendingId, ttlMs }: { sessionKey: string; pendingId: string; ttlMs: number },
): Promise<void> {
  await api.session.workflow.enqueueNextTurnInjection({
    sessionKey,
    text:
      `MasuGate pending operation ${pendingId} still requires a decision. ` +
      "Use masugate_resume_pending; do not infer approval or repeat the protected effect.",
    idempotencyKey: `masugate-approval-resume:${pendingId}`,
    placement: "prepend_context",
    ttlMs,
    metadata: { kind: "masugate-approval-resume", pendingId },
  });
}

export function createMasuGateOpenClawPlugin(
  options: MasuGateOpenClawPluginOptions = {},
): ReturnType<typeof definePluginEntry> {
  return definePluginEntry({
    id: "masugate",
    name: "MasuGate",
    description: "Trusted OpenClaw adapter for MasuGate-owned governed actions.",
    register(api: OpenClawPluginApi) {
      const rawConfig = api.pluginConfig;
      if (
        typeof rawConfig !== "object" ||
        rawConfig === null ||
        Array.isArray(rawConfig) ||
        Object.keys(rawConfig).length === 0
      ) {
        api.logger.warn("MasuGate plugin is unconfigured; no governed tools were registered");
        return;
      }
      // A configured deployment is parsed synchronously during plugin load so
      // malformed or incomplete ownership is quarantined before any agent run.
      const config = parsePluginConfig(rawConfig);
      const manifest = governedRouteManifest(config);
      const routes = new GovernedRouteParser(manifest);
      const environment = options.env ?? process.env;
      const bridge = config.nativeApproval === undefined
        ? undefined
        : new NativeApprovalBridge({
            config,
            environment,
            ...(options.createApprovalClient === undefined
              ? {}
              : { createClient: options.createApprovalClient }),
            ...(options.now === undefined ? {} : { now: options.now }),
          });
      api.registerTool(
        (context) => createTool(
          context,
          config,
          manifest,
          routes,
          options,
          bridge === undefined
            ? undefined
            : async (pendingId, sessionKey) => {
                try {
                  await enqueueApprovalResume(api, {
                    sessionKey,
                    pendingId,
                    ttlMs: config.nativeApproval!.timeoutMs,
                  });
                } catch (error) {
                  api.logger.warn(
                    `MasuGate native-approval reminder enqueue failed for ${pendingId}: ${String(error)}`,
                  );
                }
              },
        ),
        {
          name: MASUGATE_GOVERNED_TOOL,
          optional: true,
        },
      );
      if (bridge === undefined) {
        return;
      }
      api.registerTool(
        (context) => createResumeTool(context, bridge),
        { name: MASUGATE_RESUME_PENDING_TOOL, optional: true },
      );
      api.on("before_tool_call", async (event, context) => {
        if (event.toolName !== MASUGATE_RESUME_PENDING_TOOL) {
          return;
        }
        try {
          const input = parseResumeInput(event.params);
          const trusted = deriveTrustedInvocationIdentity(
            context,
            event.toolCallId ?? context.toolCallId ?? "",
          );
          // This hook runs before the tool's execute path.  Preserve the same
          // exact identity check for an already-terminal locator here, so a
          // host retry cannot manufacture another native approval merely
          // because MasuGate has removed the terminal row from listPending().
          // terminalResolutionFor rejects a foreign principal/session before
          // reporting the cache hit.
          const terminal = await bridge.terminalResolutionFor({
            pendingId: input.pendingId,
            agentId: trusted.agentId,
            sessionKey: trusted.sessionNamespace,
            sessionId: trusted.sessionId,
          });
          if (terminal !== undefined) {
            return;
          }
          const prepared = await bridge.prepare({
            pendingId: input.pendingId,
            agentId: trusted.agentId,
            sessionKey: trusted.sessionNamespace,
            sessionId: trusted.sessionId,
          });
          const approval = prepared.approval;
          if (approval === undefined) {
            // The terminal lookup above populated an exact audited binding.
            // Let execute return that authoritative result without requesting
            // another native approval.
            return;
          }
          if (prepared.expired) {
            // Preserve an already recorded decision for MasuGate's authoritative
            // deadline check. A timeout/cancellation is not a human denial,
            // so MasuGate must settle the durable entitlement through automatic
            // expiry rather than receive a fabricated resolver decision.
            const selectedDecision = bridge.selectedDecision(input.pendingId);
            if (selectedDecision !== undefined) {
              return;
            }
            return {
              block: true,
              blockReason:
                "MasuGate approval window expired without a human decision; durable automatic expiry will settle it",
            };
          }
          // The original native callback already recorded a decision for this
          // exact trusted session.  Let the resume tool reconsult MasuGate with
          // it, rather than showing an apparently fresh allow/deny dialog.
          if (bridge.selectedDecision(input.pendingId) !== undefined) {
            return;
          }
          return {
            requireApproval: {
              title: "Approve governed MasuGate operation",
              description: nativeApprovalDescription(approval.pending),
              severity: "warning",
              timeoutMs: prepared.remainingMs,
              timeoutBehavior: "deny",
              allowedDecisions: ["allow-once", "deny"],
              pluginId: "masugate",
              async onResolution(resolution) {
                // The pinned host reports timeout/cancelled separately from a
                // human ``deny``. They fail closed at the host boundary but
                // must not be represented as an operator rejection in MasuGate.
                if (resolution !== "allow-once" && resolution !== "deny") {
                  return;
                }
                await bridge.resolve(approval, resolution);
              },
            },
          };
        } catch (error) {
          return {
            block: true,
            blockReason: error instanceof Error ? error.message : String(error),
          };
        }
      });
    },
  });
}

const masugateOpenClawPlugin: ReturnType<typeof definePluginEntry> = createMasuGateOpenClawPlugin();

export default masugateOpenClawPlugin;
