import {
  validateGovernedRouteManifestV2,
  type AnyGovernedRouteManifest,
  type GovernedRouteManifest,
  type GovernedRouteManifestV2,
} from "@masugate/client";

export type GovernedExecutionOwner =
  | {
      providerId: string;
      position: "transactional";
      connectorId?: never;
    }
  | {
      providerId: string;
      position: "protected-external";
      connectorId: string;
    };

export interface GovernedRoute {
  action: string;
  arguments: Readonly<Record<string, "string" | "integer" | "boolean">>;
  owner: GovernedExecutionOwner;
}

export interface NativeApprovalConfig {
  resolverTokenEnv: string;
  timeoutMs: number;
}

export interface MasuGateOpenClawConfig {
  masugatedBaseUrl: string;
  agents: Readonly<Record<string, string>>;
  routes?: Readonly<Record<string, GovernedRoute>>;
  compiledRouteManifest?: GovernedRouteManifestV2;
  nativeApproval?: NativeApprovalConfig;
}

/**
 * Translate the deployed OpenClaw configuration shape into the public,
 * framework-neutral route manifest. The input remains plugin configuration;
 * model calls never control this manifest.
 */
export function governedRouteManifest(config: MasuGateOpenClawConfig): AnyGovernedRouteManifest {
  if (config.compiledRouteManifest !== undefined) {
    return config.compiledRouteManifest;
  }
  if (config.routes === undefined) {
    throw new Error("plugin configuration must contain routes or compiledRouteManifest");
  }
  return {
    contract_version: "masugate.governed-route-manifest.v1",
    routes: Object.entries(config.routes).map(([routeId, route]) => ({
      host_tool: routeId,
      action: route.action,
      arguments: { ...route.arguments },
      owner: route.owner.position === "transactional"
        ? {
            provider_id: route.owner.providerId,
            position: "transactional",
          }
        : {
            provider_id: route.owner.providerId,
            position: "protected-external",
            connector_id: route.owner.connectorId,
          },
    })),
  } as GovernedRouteManifest;
}

function record(value: unknown, location: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${location} must be an object`);
  }
  return value as Record<string, unknown>;
}

function nonEmpty(value: unknown, location: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${location} must be a non-empty string`);
  }
  return value.trim();
}

function safeKey(value: unknown, location: string): string {
  const key = nonEmpty(value, location);
  if (key === "__proto__" || key === "prototype" || key === "constructor") {
    throw new Error(`${location} uses a reserved object key`);
  }
  return key;
}

const RESERVED_TRUST_ARGUMENTS = new Set([
  "agentid",
  "authorization",
  "connectorid",
  "credential",
  "executionposition",
  "idempotencykey",
  "principal",
  "principalid",
  "principalref",
  "providerid",
  "runid",
  "sessionid",
  "sessionkey",
  "stableid",
  "token",
  "toolcallid",
  "traceid",
]);

function safeArgumentName(value: unknown, location: string): string {
  const name = safeKey(value, location);
  const trustName = name.replaceAll("_", "").replaceAll("-", "").toLowerCase();
  if (RESERVED_TRUST_ARGUMENTS.has(trustName)) {
    throw new Error(`${location} uses a reserved trust-boundary name`);
  }
  return name;
}

function assignUnique<T>(
  target: Record<string, T>,
  key: string,
  value: T,
  location: string,
): void {
  if (Object.hasOwn(target, key)) {
    throw new Error(`${location} normalizes to duplicate key ${key}`);
  }
  target[key] = value;
}

function baseUrl(value: unknown): string {
  const raw = nonEmpty(value, "plugin config.masugatedBaseUrl");
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch (error) {
    throw new Error("plugin config.masugatedBaseUrl must be an absolute URL", { cause: error });
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("plugin config.masugatedBaseUrl must use http or https");
  }
  if (parsed.username || parsed.password) {
    throw new Error("plugin config.masugatedBaseUrl must not embed credentials");
  }
  return raw;
}

function exactKeys(value: Record<string, unknown>, allowed: readonly string[], location: string): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) {
      throw new Error(`${location}.${key} is not allowed`);
    }
  }
}

function nativeApproval(value: unknown): NativeApprovalConfig {
  const approval = record(value, "plugin config.nativeApproval");
  exactKeys(approval, ["resolverTokenEnv", "timeoutMs"], "plugin config.nativeApproval");
  const timeoutMs = approval["timeoutMs"];
  if (
    typeof timeoutMs !== "number" ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs <= 0 ||
    timeoutMs > 600_000
  ) {
    throw new Error("plugin config.nativeApproval.timeoutMs must be a safe integer at most 600000");
  }
  return {
    resolverTokenEnv: safeKey(
      approval["resolverTokenEnv"],
      "plugin config.nativeApproval.resolverTokenEnv",
    ),
    timeoutMs,
  };
}

export function parsePluginConfig(value: unknown): MasuGateOpenClawConfig {
  const root = record(value, "plugin config");
  exactKeys(
    root,
    ["masugatedBaseUrl", "agents", "routes", "compiledRouteManifest", "nativeApproval"],
    "plugin config",
  );
  const agentsInput = record(root["agents"], "plugin config.agents");
  const hasRoutes = Object.hasOwn(root, "routes");
  const hasCompiledRouteManifest = Object.hasOwn(root, "compiledRouteManifest");
  if (hasRoutes === hasCompiledRouteManifest) {
    throw new Error("plugin config requires exactly one of routes or compiledRouteManifest");
  }
  if (Object.keys(agentsInput).length === 0) {
    throw new Error("plugin config requires at least one agent");
  }
  const agents: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const [agentId, tokenEnv] of Object.entries(agentsInput)) {
    const normalizedAgentId = safeKey(agentId, "plugin config agent id");
    assignUnique(
      agents,
      normalizedAgentId,
      nonEmpty(tokenEnv, `plugin config.agents.${agentId}`),
      "plugin config agent id",
    );
  }
  let routes: Record<string, GovernedRoute> | undefined;
  let compiledRouteManifest: GovernedRouteManifestV2 | undefined;
  if (hasRoutes) {
    const routesInput = record(root["routes"], "plugin config.routes");
    if (Object.keys(routesInput).length === 0) {
      throw new Error("plugin config.routes must contain at least one governed route");
    }
    routes = Object.create(null) as Record<string, GovernedRoute>;
    for (const [routeId, rawRoute] of Object.entries(routesInput)) {
      const route = record(rawRoute, `plugin config.routes.${routeId}`);
      exactKeys(route, ["action", "arguments", "owner"], `plugin config.routes.${routeId}`);
      const argumentInput = record(
        route["arguments"],
        `plugin config.routes.${routeId}.arguments`,
      );
      const arguments_: Record<string, "string" | "integer" | "boolean"> = Object.create(
        null,
      ) as Record<string, "string" | "integer" | "boolean">;
      for (const [name, rawKind] of Object.entries(argumentInput)) {
        const argumentName = safeArgumentName(
          name,
          `plugin config.routes.${routeId}.argument name`,
        );
        if (rawKind !== "string" && rawKind !== "integer" && rawKind !== "boolean") {
          throw new Error(
            `plugin config.routes.${routeId}.arguments.${argumentName} must be string, integer, or boolean`,
          );
        }
        assignUnique(
          arguments_,
          argumentName,
          rawKind,
          `plugin config.routes.${routeId}.argument name`,
        );
      }
      const owner = record(route["owner"], `plugin config.routes.${routeId}.owner`);
      exactKeys(
        owner,
        ["providerId", "position", "connectorId"],
        `plugin config.routes.${routeId}.owner`,
      );
      const providerId = nonEmpty(
        owner["providerId"],
        `plugin config.routes.${routeId}.owner.providerId`,
      );
      const position = owner["position"];
      let executionOwner: GovernedExecutionOwner;
      if (position === "transactional") {
        if (owner["connectorId"] !== undefined) {
          throw new Error(
            `plugin config.routes.${routeId}.owner transactional position cannot name connectorId`,
          );
        }
        executionOwner = { providerId, position };
      } else if (position === "protected-external") {
        executionOwner = {
          providerId,
          position,
          connectorId: nonEmpty(
            owner["connectorId"],
            `plugin config.routes.${routeId}.owner.connectorId`,
          ),
        };
      } else {
        throw new Error(
          `plugin config.routes.${routeId}.owner.position must be transactional or protected-external`,
        );
      }
      const normalizedRouteId = safeKey(routeId, "plugin config route id");
      assignUnique(
        routes,
        normalizedRouteId,
        {
          action: nonEmpty(route["action"], `plugin config.routes.${routeId}.action`),
          arguments: arguments_,
          owner: executionOwner,
        },
        "plugin config route id",
      );
    }
  } else {
    compiledRouteManifest = validateGovernedRouteManifestV2(root["compiledRouteManifest"]);
  }
  const approvalInput = root["nativeApproval"];
  const parsedApproval = approvalInput === undefined ? undefined : nativeApproval(approvalInput);
  if (
    parsedApproval !== undefined &&
    Object.values(agents).some((tokenEnv) => tokenEnv === parsedApproval.resolverTokenEnv)
  ) {
    throw new Error(
      "plugin config.nativeApproval.resolverTokenEnv must differ from every action credential environment variable",
    );
  }
  const parsed = {
    masugatedBaseUrl: baseUrl(root["masugatedBaseUrl"]),
    agents,
    ...(parsedApproval === undefined ? {} : { nativeApproval: parsedApproval }),
  };
  if (routes === undefined) {
    if (compiledRouteManifest === undefined) {
      throw new Error("plugin config compiledRouteManifest was not parsed");
    }
    return { ...parsed, compiledRouteManifest };
  }
  return { ...parsed, routes };
}
