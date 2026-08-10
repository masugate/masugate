/** Additive public validators for `masugate.governed-route-manifest.v2`. */

import {
  GOVERNED_ROUTE_MANIFEST_VERSION,
  canonicalGovernedRouteManifest,
  canonicalJson,
  requireAdapterArgumentName,
  requireIdentifier,
  validateGovernedRouteManifest,
  type GovernedRouteManifest,
} from "./adapter-contract.js";
import type { JsonValue } from "./index.js";

export const GOVERNED_ROUTE_MANIFEST_V2_VERSION = "masugate.governed-route-manifest.v2";
export const DEFAULT_ROUTE_SCHEMA_CANONICAL_BYTES = 65_536;
export const DEFAULT_ROUTE_MANIFEST_CANONICAL_BYTES = 1_048_576;
export const MAX_GOVERNED_ROUTE_MANIFEST_ROUTES = 64;
export const MAX_ROUTE_ARTIFACT_FIELDS = 128;
export const MAX_ROUTE_CONNECTOR_CAPABILITIES = 64;

export interface GovernedRouteV2 {
  host_tool: string;
  action: string;
  input_schema: Record<string, JsonValue>;
  public_result_schema: Record<string, JsonValue>;
  artifact_fields: string[];
  owner:
    | { provider_id: string; position: "transactional" }
    | { provider_id: string; position: "protected-external"; connector_id: string };
  required_connector_capabilities: string[];
  maturity: "reference-effect" | "production-profile";
  compatibility: { route_manifest: typeof GOVERNED_ROUTE_MANIFEST_V2_VERSION; connector_contract: "masugate.connector.v1" };
}

export interface GovernedRouteManifestV2 {
  contract_version: typeof GOVERNED_ROUTE_MANIFEST_V2_VERSION;
  pack: { id: string; version: string; digest: string };
  routes: GovernedRouteV2[];
}

export type AnyGovernedRouteManifest = GovernedRouteManifest | GovernedRouteManifestV2;
const SECRET_MODEL_FIELD_PARTS = new Set([
  "credential", "credentials", "secret", "secrets", "token", "tokens", "password",
  "apikey", "privatekey", "accesskey",
]);
const SECRET_MODEL_FIELD_COMPOUNDS = new Set(["api_key", "private_key", "access_key"]);
const UTF8_ENCODER = new TextEncoder();

function modelField(value: unknown, field: string): string {
  if (typeof value !== "string") throw new TypeError(`${field} must be a model field`);
  const parsed = requireAdapterArgumentName(value);
  if (parsed === "runtime" || parsed.startsWith("model_")) {
    throw new TypeError(`${field} uses a reserved generated-host name`);
  }
  const parts = parsed.split("_");
  if (
    parts.some((part) => SECRET_MODEL_FIELD_PARTS.has(part)) ||
    parts.slice(0, -1).some((part, index) => SECRET_MODEL_FIELD_COMPOUNDS.has(`${part}_${parts[index + 1]}`))
  ) {
    throw new TypeError(`${field} cannot name secret or credential material`);
  }
  return parsed;
}

function denseArray(value: unknown, field: string): unknown[] {
  if (!Array.isArray(value)) throw new TypeError(`${field} must be an array`);
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) throw new TypeError(`${field} must not be sparse`);
  }
  return value;
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

function ownEntriesAtMost(
  value: Record<string, unknown>,
  maximum: number,
  field: string,
): [string, unknown][] {
  const entries: [string, unknown][] = [];
  for (const key in value) {
    if (!Object.hasOwn(value, key)) continue;
    if (entries.length === maximum) throw new TypeError(`${field} must contain at most ${maximum} entries`);
    entries.push([key, value[key]]);
  }
  return entries;
}

function exact(value: Record<string, unknown>, allowed: readonly string[], field: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...allowed].sort();
  if (actual.length !== expected.length || actual.some((item, index) => item !== expected[index])) {
    throw new TypeError(`${field} must contain exactly: ${expected.join(", ")}`);
  }
}

function digest(value: unknown, field: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) {
    throw new TypeError(`${field} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function integer(value: unknown, field: string, minimum: number, maximum: number): number {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw new TypeError(`${field} has invalid integer bounds`);
  }
  return value;
}

function schema(
  value: unknown,
  field: string,
  limit: number,
  objectRoot = false,
): Record<string, JsonValue> {
  let remaining = limit;
  const consume = (amount: number): void => {
    remaining -= amount;
    if (remaining < 0) throw new TypeError(`${field} canonical form exceeds configured limit`);
  };
  const canonicalBytes = (input: JsonValue): number => UTF8_ENCODER.encode(canonicalJson(input)).length;
  const visit = (raw: unknown, context: string, depth: number): Record<string, JsonValue> => {
    if (depth > 8) throw new TypeError(`${context} exceeds maximum schema nesting`);
    const node = record(raw, context);
    ownEntriesAtMost(node, 5, context);
    const kind = node["type"];
    if (kind === "object") {
      exact(node, ["type", "properties", "required", "additionalProperties"], context);
      if (node["additionalProperties"] !== false) throw new TypeError(`${context}.additionalProperties must be false`);
      const rawProperties = record(node["properties"], `${context}.properties`);
      const entries = ownEntriesAtMost(rawProperties, 128, `${context}.properties`);
      if (entries.length === 0 || entries.length > 128) throw new TypeError(`${context}.properties must contain 1 through 128 fields`);
      if (!Array.isArray(node["required"])) throw new TypeError(`${context}.required must be an array`);
      if (node["required"].length > entries.length) throw new TypeError(`${context}.required must name unique declared properties`);
      const propertyItems = entries.map(([name, child]) => [modelField(name, `${context}.properties key`), child] as const);
      const propertyNames = new Set(propertyItems.map(([name]) => name));
      const required: string[] = [];
      for (const [index, name] of node["required"].entries()) {
        if (typeof name !== "string") throw new TypeError(`${context}.required[${index}] must be a field`);
        const parsed = modelField(name, `${context}.required[${index}]`);
        if (!propertyNames.has(parsed) || required.includes(parsed)) {
          throw new TypeError(`${context}.required must name unique declared properties`);
        }
        required.push(parsed);
      }
      required.sort();
      consume(
        canonicalBytes({ type: "object", properties: {}, required, additionalProperties: false })
          + propertyItems.reduce((total, [name]) => total + canonicalBytes(name) + 1, 0)
          + propertyItems.length - 1,
      );
      const properties: Record<string, JsonValue> = {};
      for (const [name, child] of propertyItems) {
        properties[name] = visit(child, `${context}.properties.${name}`, depth + 1);
      }
      return { type: "object", properties, required, additionalProperties: false };
    }
    if (kind === "array") {
      const allowed = new Set(["type", "items", "minItems", "maxItems"]);
      if (Object.keys(node).some((key) => !allowed.has(key)) || !("items" in node) || !("maxItems" in node)) {
        throw new TypeError(`${context} array schemas must be explicitly bounded`);
      }
      const maximum = integer(node["maxItems"], `${context}.maxItems`, 0, 1024);
      const minimum = Object.hasOwn(node, "minItems")
        ? integer(node["minItems"], `${context}.minItems`, 0, maximum)
        : 0;
      consume(canonicalBytes({ type: "array", items: null, minItems: minimum, maxItems: maximum }) - "null".length);
      return { type: "array", items: visit(node["items"], `${context}.items`, depth + 1), minItems: minimum, maxItems: maximum };
    }
    if (kind === "string") {
      const allowed = new Set(["type", "minLength", "maxLength"]);
      if (Object.keys(node).some((key) => !allowed.has(key)) || !("maxLength" in node)) throw new TypeError(`${context} strings must declare maxLength`);
      const maximum = integer(node["maxLength"], `${context}.maxLength`, 0, 65_536);
      const minimum = Object.hasOwn(node, "minLength")
        ? integer(node["minLength"], `${context}.minLength`, 0, maximum)
        : 0;
      const parsed = { type: "string", minLength: minimum, maxLength: maximum } as const;
      consume(canonicalBytes(parsed));
      return parsed;
    }
    if (kind === "integer") {
      const allowed = new Set(["type", "minimum", "maximum"]);
      if (Object.keys(node).some((key) => !allowed.has(key))) throw new TypeError(`${context} integers permit only safe bounds`);
      const minimum = Object.hasOwn(node, "minimum")
        ? integer(node["minimum"], `${context}.minimum`, -9_007_199_254_740_991, 9_007_199_254_740_991)
        : -9_007_199_254_740_991;
      const maximum = Object.hasOwn(node, "maximum")
        ? integer(node["maximum"], `${context}.maximum`, minimum, 9_007_199_254_740_991)
        : 9_007_199_254_740_991;
      const parsed = { type: "integer", minimum, maximum } as const;
      consume(canonicalBytes(parsed));
      return parsed;
    }
    if (kind === "boolean" && Object.keys(node).length === 1) {
      const parsed = { type: "boolean" } as const;
      consume(canonicalBytes(parsed));
      return parsed;
    }
    throw new TypeError(`${context}.type is unsupported`);
  };
  const parsed = visit(value, field, 0);
  if (objectRoot && parsed["type"] !== "object") throw new TypeError(`${field} must be an object schema`);
  if (canonicalBytes(parsed) > limit) {
    throw new TypeError(`${field} canonical form exceeds configured limit`);
  }
  return parsed;
}

export function validateGovernedRouteManifestV2(
  value: unknown,
  options: { maxSchemaCanonicalBytes?: number; maxManifestCanonicalBytes?: number } = {},
): GovernedRouteManifestV2 {
  const limit = options.maxSchemaCanonicalBytes ?? DEFAULT_ROUTE_SCHEMA_CANONICAL_BYTES;
  if (!Number.isInteger(limit) || limit <= 0) throw new TypeError("schema canonical byte limit must be positive");
  const manifestLimit = options.maxManifestCanonicalBytes ?? DEFAULT_ROUTE_MANIFEST_CANONICAL_BYTES;
  if (!Number.isInteger(manifestLimit) || manifestLimit <= 0) throw new TypeError("route manifest canonical byte limit must be positive");
  const manifest = record(value, "governed route manifest v2");
  exact(manifest, ["contract_version", "pack", "routes"], "governed route manifest v2");
  if (manifest["contract_version"] !== GOVERNED_ROUTE_MANIFEST_V2_VERSION) throw new TypeError("governed route manifest v2.contract_version is unsupported");
  const rawPack = record(manifest["pack"], "governed route manifest v2.pack");
  exact(rawPack, ["id", "version", "digest"], "governed route manifest v2.pack");
  const pack = { id: requireIdentifier(rawPack["id"], "governed route manifest v2.pack.id"), version: requireIdentifier(rawPack["version"], "governed route manifest v2.pack.version"), digest: digest(rawPack["digest"], "governed route manifest v2.pack.digest") };
  const rawRoutes = denseArray(manifest["routes"], "governed route manifest v2.routes");
  if (rawRoutes.length === 0) throw new TypeError("governed route manifest v2.routes must be a non-empty array");
  if (rawRoutes.length > MAX_GOVERNED_ROUTE_MANIFEST_ROUTES) throw new TypeError(`governed route manifest v2.routes must contain at most ${MAX_GOVERNED_ROUTE_MANIFEST_ROUTES} entries`);
  const seenHostTools = new Set<string>();
  const seenActions = new Set<string>();
  const routes = rawRoutes.map((rawRoute, index) => {
    const field = `governed route manifest v2.routes[${index}]`;
    const route = record(rawRoute, field);
    exact(route, ["host_tool", "action", "input_schema", "public_result_schema", "artifact_fields", "owner", "required_connector_capabilities", "maturity", "compatibility"], field);
    const host_tool = requireIdentifier(route["host_tool"], `${field}.host_tool`);
    if (seenHostTools.has(host_tool)) throw new TypeError("governed route manifest v2.routes must not repeat host_tool");
    seenHostTools.add(host_tool);
    const action = requireIdentifier(route["action"], `${field}.action`, 255);
    if (seenActions.has(action)) throw new TypeError("governed route manifest v2.routes must not repeat action");
    seenActions.add(action);
    const ownerRaw = record(route["owner"], `${field}.owner`);
    let owner: GovernedRouteV2["owner"];
    if (ownerRaw["position"] === "transactional") {
      exact(ownerRaw, ["provider_id", "position"], `${field}.owner`);
      owner = { provider_id: requireIdentifier(ownerRaw["provider_id"], `${field}.owner.provider_id`), position: "transactional" };
    } else if (ownerRaw["position"] === "protected-external") {
      exact(ownerRaw, ["provider_id", "position", "connector_id"], `${field}.owner`);
      owner = { provider_id: requireIdentifier(ownerRaw["provider_id"], `${field}.owner.provider_id`), position: "protected-external", connector_id: requireIdentifier(ownerRaw["connector_id"], `${field}.owner.connector_id`) };
    } else throw new TypeError(`${field}.owner.position is invalid`);
    const artifactRaw = denseArray(route["artifact_fields"], `${field}.artifact_fields`);
    const capabilitiesRaw = denseArray(
      route["required_connector_capabilities"],
      `${field}.required_connector_capabilities`,
    );
    if (artifactRaw.length > MAX_ROUTE_ARTIFACT_FIELDS) throw new TypeError(`${field}.artifact_fields must contain at most ${MAX_ROUTE_ARTIFACT_FIELDS} entries`);
    if (capabilitiesRaw.length > MAX_ROUTE_CONNECTOR_CAPABILITIES) throw new TypeError(`${field}.required_connector_capabilities must contain at most ${MAX_ROUTE_CONNECTOR_CAPABILITIES} entries`);
    const artifact_fields = artifactRaw.map((name) => {
      if (typeof name !== "string") throw new TypeError(`${field}.artifact_fields must contain fields`);
      return modelField(name, `${field}.artifact_fields`);
    });
    const required_connector_capabilities = capabilitiesRaw.map((name) => requireIdentifier(name, `${field}.required_connector_capabilities`));
    if (new Set(artifact_fields).size !== artifact_fields.length || new Set(required_connector_capabilities).size !== required_connector_capabilities.length) throw new TypeError(`${field} arrays must not contain duplicates`);
    if (owner.position === "transactional" && required_connector_capabilities.length > 0) throw new TypeError(`${field} transactional route cannot require connector capabilities`);
    if (route["maturity"] !== "reference-effect" && route["maturity"] !== "production-profile") throw new TypeError(`${field}.maturity is invalid`);
    if (route["maturity"] === "production-profile" && owner.position !== "protected-external") throw new TypeError(`${field}.production-profile requires protected-external position`);
    const compatibility = record(route["compatibility"], `${field}.compatibility`);
    exact(compatibility, ["route_manifest", "connector_contract"], `${field}.compatibility`);
    if (compatibility["route_manifest"] !== GOVERNED_ROUTE_MANIFEST_V2_VERSION || compatibility["connector_contract"] !== "masugate.connector.v1") throw new TypeError(`${field}.compatibility is unsupported`);
    const input_schema = schema(route["input_schema"], `${field}.input_schema`, limit, true);
    const properties = input_schema["properties"] as Record<string, JsonValue>;
    if (artifact_fields.some((name) => !(name in properties))) throw new TypeError(`${field}.artifact_fields must name input properties`);
    if (artifact_fields.length > 0) {
      if (owner.position !== "protected-external") throw new TypeError(`${field}.artifact_fields require protected-external position`);
      const required = input_schema["required"] as string[];
      for (const artifact of artifact_fields) {
        const propertySchema = properties[artifact] as Record<string, JsonValue>;
        if (!required.includes(artifact) || propertySchema["type"] !== "string") {
          throw new TypeError(`${field}.artifact_fields must be required bounded string properties`);
        }
      }
    }
    return { host_tool, action, input_schema, public_result_schema: schema(route["public_result_schema"], `${field}.public_result_schema`, limit), artifact_fields, owner, required_connector_capabilities, maturity: route["maturity"], compatibility: { route_manifest: GOVERNED_ROUTE_MANIFEST_V2_VERSION, connector_contract: "masugate.connector.v1" } } as GovernedRouteV2;
  });
  routes.sort((left, right) => left.host_tool < right.host_tool ? -1 : left.host_tool > right.host_tool ? 1 : 0);
  const parsed: GovernedRouteManifestV2 = {
    contract_version: GOVERNED_ROUTE_MANIFEST_V2_VERSION,
    pack,
    routes,
  };
  if (new TextEncoder().encode(canonicalJson(parsed as unknown as JsonValue)).length > manifestLimit) {
    throw new TypeError("governed route manifest v2 canonical form exceeds configured limit");
  }
  return parsed;
}

export function validateAnyGovernedRouteManifest(value: unknown): AnyGovernedRouteManifest {
  if (record(value, "governed route manifest")["contract_version"] === GOVERNED_ROUTE_MANIFEST_VERSION) {
    return validateGovernedRouteManifest(value);
  }
  return validateGovernedRouteManifestV2(value);
}

export function canonicalGovernedRouteManifestV2(value: unknown): string {
  return canonicalJson(validateGovernedRouteManifestV2(value) as unknown as JsonValue);
}

export function canonicalAnyGovernedRouteManifest(value: unknown): string {
  if (record(value, "governed route manifest")["contract_version"] === GOVERNED_ROUTE_MANIFEST_VERSION) {
    return canonicalGovernedRouteManifest(value);
  }
  return canonicalGovernedRouteManifestV2(value);
}
