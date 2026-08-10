import { JSONPath } from "jsonpath-plus";
import { parseDocument } from "yaml";

import type {
  GatewayManifest,
  GovernedRoute,
  MasuGatedManifest,
  UpstreamManifest,
} from "./types.js";

export const AUDIT_TOOL_NAME = "masugate_audit_get";

const TOP_LEVEL_KEYS = new Set([
  "version",
  "upstream",
  "masugated",
  "governed",
  "passthrough",
]);
const UPSTREAM_KEYS = new Set(["command", "args", "cwd", "env"]);
const MASUGATED_KEYS = new Set(["base_url", "token_env"]);
const ROUTE_KEYS = new Set(["action", "args", "stable_id"]);

// Governance mappings must select one exact value. Filters, recursive descent,
// wildcards, unions, and script expressions are intentionally excluded: they
// make normalization ambiguous and turn trusted configuration into executable
// expressions. This remains standard JSONPath for object keys and array slots.
const EXACT_JSON_PATH =
  /^\$(?:(?:\.[A-Za-z_][A-Za-z0-9_-]*)|(?:\[['"][^'"\\\]]+['"]\])|(?:\[\d+\]))*$/;

export class ManifestError extends Error {
  override readonly name = "ManifestError";
}

function fail(path: string, message: string): never {
  throw new ManifestError(`${path}: ${message}`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function objectAt(value: unknown, path: string): Record<string, unknown> {
  if (!isRecord(value)) {
    fail(path, "must be an object");
  }
  return value;
}

function rejectUnknownKeys(
  value: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  path: string,
): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) {
      fail(`${path}.${key}`, "unknown field");
    }
  }
}

function nonEmptyString(value: unknown, path: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    fail(path, "must be a non-empty string");
  }
  return value;
}

function stringArray(value: unknown, path: string): string[] {
  if (!Array.isArray(value)) {
    fail(path, "must be an array of strings");
  }
  return value.map((item, index) => nonEmptyString(item, `${path}[${index}]`));
}

function stringMap(value: unknown, path: string): Record<string, string> {
  const raw = objectAt(value, path);
  const mapped: Record<string, string> = {};
  for (const [key, item] of Object.entries(raw)) {
    if (key.trim() === "") {
      fail(path, "contains an empty key");
    }
    mapped[key] = nonEmptyString(item, `${path}.${key}`);
  }
  return mapped;
}

function parseUpstream(value: unknown): UpstreamManifest {
  const raw = objectAt(value, "upstream");
  rejectUnknownKeys(raw, UPSTREAM_KEYS, "upstream");
  const command = nonEmptyString(raw["command"], "upstream.command");
  const args = raw["args"] === undefined ? [] : stringArray(raw["args"], "upstream.args");
  const env = raw["env"] === undefined ? {} : stringMap(raw["env"], "upstream.env");
  const cwd =
    raw["cwd"] === undefined ? undefined : nonEmptyString(raw["cwd"], "upstream.cwd");
  return cwd === undefined ? { command, args, env } : { command, args, env, cwd };
}

function parseMasuGated(value: unknown): MasuGatedManifest {
  const raw = objectAt(value, "masugated");
  rejectUnknownKeys(raw, MASUGATED_KEYS, "masugated");
  const baseUrl = nonEmptyString(raw["base_url"], "masugated.base_url").replace(/\/+$/, "");
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    fail("masugated.base_url", "must be an absolute http(s) URL");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    fail("masugated.base_url", "must use http or https");
  }
  return {
    baseUrl,
    tokenEnv: nonEmptyString(raw["token_env"], "masugated.token_env"),
  };
}

export function validateJsonPath(path: string, location: string): void {
  if (!EXACT_JSON_PATH.test(path)) {
    fail(
      location,
      "must be an exact JSONPath (for example $.amount or $.items[0].sku)",
    );
  }
  try {
    JSONPath({ path, json: {}, wrap: false });
  } catch (error) {
    fail(location, `invalid JSONPath: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function parseGoverned(value: unknown): Record<string, GovernedRoute> {
  const raw = objectAt(value, "governed");
  const routes: Record<string, GovernedRoute> = {};
  for (const [toolName, routeValue] of Object.entries(raw)) {
    nonEmptyString(toolName, "governed tool name");
    if (toolName === AUDIT_TOOL_NAME) {
      fail(`governed.${toolName}`, "reserved for the read-only MasuGate audit control tool");
    }
    const route = objectAt(routeValue, `governed.${toolName}`);
    rejectUnknownKeys(route, ROUTE_KEYS, `governed.${toolName}`);
    const action = nonEmptyString(route["action"], `governed.${toolName}.action`);
    const stableIdPath = nonEmptyString(
      route["stable_id"],
      `governed.${toolName}.stable_id`,
    );
    validateJsonPath(stableIdPath, `governed.${toolName}.stable_id`);
    if (route["args"] === undefined) {
      fail(`governed.${toolName}.args`, "is required (use {} for an action with no arguments)");
    }
    const args = stringMap(route["args"], `governed.${toolName}.args`);
    for (const [argument, jsonPath] of Object.entries(args)) {
      validateJsonPath(jsonPath, `governed.${toolName}.args.${argument}`);
    }
    routes[toolName] = { action, args, stableIdPath };
  }
  return routes;
}

export function parseManifest(source: string): GatewayManifest {
  const document = parseDocument(source, {
    prettyErrors: true,
    uniqueKeys: true,
  });
  if (document.errors.length > 0) {
    const message = document.errors.map((error) => error.message).join("; ");
    throw new ManifestError(`invalid YAML: ${message}`);
  }
  const raw = objectAt(document.toJS({ maxAliasCount: 20 }), "manifest");
  rejectUnknownKeys(raw, TOP_LEVEL_KEYS, "manifest");
  if (raw["version"] !== 1) {
    fail("version", "must be 1");
  }
  const upstream = parseUpstream(raw["upstream"]);
  const masugated = parseMasuGated(raw["masugated"]);
  const governed = parseGoverned(raw["governed"]);
  const passthrough = stringArray(raw["passthrough"], "passthrough");
  const seen = new Set<string>();
  for (const toolName of passthrough) {
    if (toolName === AUDIT_TOOL_NAME) {
      fail("passthrough", `${AUDIT_TOOL_NAME} is a reserved control tool`);
    }
    if (seen.has(toolName)) {
      fail("passthrough", `contains duplicate tool ${JSON.stringify(toolName)}`);
    }
    seen.add(toolName);
    if (Object.hasOwn(governed, toolName)) {
      fail(
        "manifest",
        `tool ${JSON.stringify(toolName)} cannot be both governed and passthrough`,
      );
    }
  }
  return { version: 1, upstream, masugated, governed, passthrough };
}
