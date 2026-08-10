import type {
  ActionArgument,
  ActionResult,
  JsonObject as MasuGateJsonObject,
  JsonValue as MasuGateJsonValue,
} from "@masugate/client";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";

export type JsonScalar = ActionArgument;
export type JsonValue = MasuGateJsonValue;
export type JsonObject = MasuGateJsonObject;
export type MasuGatedActionResult = ActionResult<JsonObject>;

export interface Upstream {
  listTools(): Promise<Tool[]>;
  callTool(name: string, args?: Record<string, unknown>): Promise<CallToolResult>;
  close?(): Promise<void>;
}

export interface MasuGatedExecuteRequest {
  action: string;
  args: Record<string, JsonScalar>;
  stableId: string;
  traceId?: string;
}

/** Gateway-owned seam; production adapts the published @masugate/client SDK. */
export interface MasuGatedClient {
  execute(request: MasuGatedExecuteRequest): Promise<MasuGatedActionResult>;
  getAudit(operationId: string): Promise<JsonObject>;
}

export interface GovernedRoute {
  action: string;
  args: Readonly<Record<string, string>>;
  stableIdPath: string;
}

export interface UpstreamManifest {
  command: string;
  args: readonly string[];
  cwd?: string;
  env: Readonly<Record<string, string>>;
}

export interface MasuGatedManifest {
  baseUrl: string;
  tokenEnv: string;
}

export interface GatewayManifest {
  version: 1;
  upstream: UpstreamManifest;
  masugated: MasuGatedManifest;
  governed: Readonly<Record<string, GovernedRoute>>;
  passthrough: readonly string[];
}

export interface GatewayCallContext {
  requestId: string | number;
}

export { type CallToolResult, type Tool };
