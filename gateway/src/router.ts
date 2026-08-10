import { JSONPath } from "jsonpath-plus";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";

import { AUDIT_TOOL_NAME } from "./manifest.js";
import type {
  GatewayCallContext,
  GatewayManifest,
  GovernedRoute,
  JsonObject,
  JsonScalar,
  MasuGatedActionResult,
  MasuGatedClient,
  Upstream,
} from "./types.js";

export class GatewayError extends Error {
  override readonly name = "GatewayError";
}

const AUDIT_TOOL: Tool = {
  name: AUDIT_TOOL_NAME,
  description:
    "Read a MasuGate governance receipt by operation_id. This tool cannot approve or resolve pending work.",
  inputSchema: {
    type: "object",
    properties: {
      operation_id: {
        type: "string",
        minLength: 1,
        description: "The server-assigned MasuGate operation id.",
      },
    },
    required: ["operation_id"],
    additionalProperties: false,
  },
  annotations: {
    title: "Get MasuGate audit receipt",
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
};

function normalizeScalar(value: unknown, location: string): JsonScalar {
  if (typeof value === "string" || typeof value === "boolean") {
    return value;
  }
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return value;
  }
  throw new GatewayError(`${location} must resolve to a string, integer, or boolean`);
}

function stableIdForCall(
  toolName: string,
  route: GovernedRoute,
  toolArguments: Record<string, unknown>,
): string {
  const value: unknown = JSONPath({
    path: route.stableIdPath,
    json: toolArguments,
    wrap: false,
  });
  if (typeof value === "string" && value.length > 0) {
    return `mcp-tool\u0000${toolName}\u0000string\u0000${value}`;
  }
  if (typeof value === "number" && Number.isSafeInteger(value)) {
    return `mcp-tool\u0000${toolName}\u0000integer\u0000${String(value)}`;
  }
  throw new GatewayError(
    `governed.${toolName}.stable_id (${route.stableIdPath}) must resolve to a non-empty string or safe integer`,
  );
}

function mapArguments(
  toolName: string,
  route: GovernedRoute,
  toolArguments: Record<string, unknown>,
): Record<string, JsonScalar> {
  const mapped: Record<string, JsonScalar> = {};
  for (const [argument, path] of Object.entries(route.args)) {
    const value: unknown = JSONPath({ path, json: toolArguments, wrap: false });
    if (value === undefined) {
      throw new GatewayError(
        `governed tool ${JSON.stringify(toolName)} is missing value for ${argument} at ${path}`,
      );
    }
    mapped[argument] = normalizeScalar(
      value,
      `governed.${toolName}.args.${argument} (${path})`,
    );
  }
  return mapped;
}

function textResult(text: string, structuredContent: JsonObject, isError = false): CallToolResult {
  return {
    content: [{ type: "text", text }],
    structuredContent,
    ...(isError ? { isError: true } : {}),
  };
}

function committedResult(result: Extract<MasuGatedActionResult, { status: "committed" }>): CallToolResult {
  // Execute-not-check: this payload is the output of the effect masugated already
  // committed. Calling the upstream tool here would be a detached allow and
  // could apply the effect twice.
  return textResult(JSON.stringify(result.payload), result.payload);
}

function deniedResult(result: Extract<MasuGatedActionResult, { status: "denied" }>): CallToolResult {
  const { decision } = result;
  const structured: JsonObject = {
    status: "denied",
    operation_id: result.operation_id,
    audit_ref: result.audit_ref,
    decision: {
      effect: "deny",
      policy_id: decision.policy_id,
      policy_version: decision.policy_version,
      rule_id: decision.rule_id,
      reason: decision.reason,
    },
  };
  return textResult(
    `Denied by MasuGate policy ${decision.policy_id}, rule ${decision.rule_id}: ${decision.reason} (audit: ${result.audit_ref})`,
    structured,
    true,
  );
}

function pendingResult(result: Extract<MasuGatedActionResult, { status: "pending" }>): CallToolResult {
  const structured: JsonObject = {
    status: "pending",
    pending_id: result.pending_id,
    operation_id: result.operation_id,
    audit_ref: result.audit_ref,
  };
  return textResult(
    `Pending MasuGate approval: pending_id=${result.pending_id}, operation_id=${result.operation_id}, audit=${result.audit_ref}`,
    structured,
  );
}

function auditOperationId(args: Record<string, unknown>): string {
  const keys = Object.keys(args);
  if (keys.length !== 1 || keys[0] !== "operation_id") {
    throw new GatewayError(`${AUDIT_TOOL_NAME} requires only operation_id`);
  }
  const operationId = args["operation_id"];
  if (typeof operationId !== "string" || operationId === "") {
    throw new GatewayError(`${AUDIT_TOOL_NAME}.operation_id must be a non-empty string`);
  }
  return operationId;
}

function governedToolDescriptor(tool: Tool): Tool {
  // A governed call has three legal result shapes (committed payload, policy
  // denial, or pending marker). The upstream's outputSchema describes only its
  // direct success result, and the gateway does not implement MCP task handles.
  // Strip both claims for governed routes. Input metadata remains upstream's;
  // passthrough descriptors are returned untouched.
  const {
    outputSchema: _upstreamOnlyOutputSchema,
    execution: _unsupportedTaskExecution,
    ...descriptor
  } = tool;
  return descriptor;
}

export class GatewayRouter {
  readonly #passthrough: ReadonlySet<string>;
  readonly #declared: ReadonlySet<string>;
  readonly #tools = new Map<string, Tool>();
  #initializing?: Promise<void>;

  constructor(
    readonly manifest: GatewayManifest,
    readonly upstream: Upstream,
    readonly masugated: MasuGatedClient,
  ) {
    this.#passthrough = new Set(manifest.passthrough);
    this.#declared = new Set([
      ...manifest.passthrough,
      ...Object.keys(manifest.governed),
    ]);
  }

  async initialize(): Promise<void> {
    this.#initializing ??= this.#loadTools();
    await this.#initializing;
  }

  async #loadTools(): Promise<void> {
    const tools = await this.upstream.listTools();
    const available = new Map<string, Tool>();
    for (const tool of tools) {
      if (tool.name === AUDIT_TOOL_NAME) {
        throw new GatewayError(
          `upstream tool ${AUDIT_TOOL_NAME} conflicts with the reserved MasuGate control tool`,
        );
      }
      if (available.has(tool.name)) {
        throw new GatewayError(`upstream returned duplicate tool ${JSON.stringify(tool.name)}`);
      }
      available.set(tool.name, tool);
    }
    for (const declared of this.#declared) {
      const tool = available.get(declared);
      if (tool === undefined) {
        throw new GatewayError(
          `manifest declares tool ${JSON.stringify(declared)}, but the upstream does not expose it`,
        );
      }
      if (
        this.#passthrough.has(declared) &&
        tool.execution?.taskSupport === "required"
      ) {
        throw new GatewayError(
          `passthrough tool ${JSON.stringify(declared)} requires MCP task execution, but the gateway does not advertise or handle MCP tasks`,
        );
      }
      this.#tools.set(
        declared,
        Object.hasOwn(this.manifest.governed, declared)
          ? governedToolDescriptor(tool)
          : tool,
      );
    }
  }

  async listTools(): Promise<Tool[]> {
    await this.initialize();
    return [...this.#tools.values(), AUDIT_TOOL];
  }

  async callTool(
    name: string,
    args: Record<string, unknown> | undefined,
    context: GatewayCallContext,
  ): Promise<CallToolResult> {
    await this.initialize();
    if (name === AUDIT_TOOL_NAME) {
      const operationId = auditOperationId(args ?? {});
      const audit = await this.masugated.getAudit(operationId);
      return textResult(
        `MasuGate audit receipt for ${operationId}: ${JSON.stringify(audit)}`,
        audit,
      );
    }
    if (this.#passthrough.has(name)) {
      return this.upstream.callTool(name, args);
    }
    const route = this.manifest.governed[name];
    if (route === undefined) {
      throw new GatewayError(
        `tool ${JSON.stringify(name)} is not declared governed or passthrough; refusing to call it`,
      );
    }
    const toolArguments = args ?? {};
    const mappedArgs = mapArguments(name, route, toolArguments);
    const stableId = stableIdForCall(name, route, toolArguments);
    const requestId = String(context.requestId);
    const result = await this.masugated.execute({
      action: route.action,
      args: mappedArgs,
      stableId,
      traceId: `mcp:${requestId}`,
    });
    switch (result.status) {
      case "committed":
        return committedResult(result);
      case "denied":
        return deniedResult(result);
      case "pending":
        return pendingResult(result);
    }
    throw new GatewayError("unexpected MasuGate result status");
  }
}
