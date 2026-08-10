/** Framework-neutral, replacement-only runtime over the public MasuGate TypeScript SDK. */

import {
  canonicalAdapterEnvelope,
  canonicalAnyGovernedRouteManifest,
  createAdapterInvocation,
  operationLocator,
  MasuGateHttpError,
  validateOperationLocator,
  validateAnyGovernedRouteManifest,
  type ActionArguments,
  type ActionResult,
  type AdapterCancellationEnvelope,
  type AdapterCapability,
  type AdapterInvocation,
  type AuditRecord,
  type ExecuteOptions,
  type GovernedArgumentKind,
  type OperationLocator,
  type PendingLookup,
  type StagedArtifact,
} from "@masugate/client";

const SAFE_INTEGER_MIN = -9_007_199_254_740_991;
const SAFE_INTEGER_MAX = 9_007_199_254_740_991;
const CAPABILITIES = new Set<AdapterCapability>([
  "cancellation", "locator", "pending-presentation", "receipt",
]);

export class AdapterCoreError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AdapterCoreError";
  }
}
export class AdapterModelArgumentsError extends AdapterCoreError {
  constructor(message: string) {
    super(message);
    this.name = "AdapterModelArgumentsError";
  }
}
export class ChangedInvocationConflictError extends AdapterCoreError {
  constructor(message: string) {
    super(message);
    this.name = "ChangedInvocationConflictError";
  }
}
export class PendingLocatorMismatchError extends AdapterCoreError {
  constructor(message: string) {
    super(message);
    this.name = "PendingLocatorMismatchError";
  }
}
export class UnsupportedAdapterCapabilityError extends AdapterCoreError {
  constructor(message: string) {
    super(message);
    this.name = "UnsupportedAdapterCapabilityError";
  }
}
export class UnknownGovernedToolError extends AdapterCoreError {
  constructor(message: string) {
    super(message);
    this.name = "UnknownGovernedToolError";
  }
}

export class AdapterCapabilities {
  readonly adapterId: string;
  readonly capabilities: readonly AdapterCapability[];

  constructor(adapterId: string, capabilities: readonly AdapterCapability[]) {
    if (typeof adapterId !== "string" || adapterId.length === 0) {
      throw new AdapterCoreError("adapterId must be non-empty");
    }
    if (new Set(capabilities).size !== capabilities.length) {
      throw new AdapterCoreError("adapter capabilities must not contain duplicates");
    }
    if (capabilities.some((capability) => !CAPABILITIES.has(capability))) {
      throw new AdapterCoreError("adapter capabilities contain an unsupported value");
    }
    this.adapterId = adapterId;
    this.capabilities = [...capabilities];
  }

  require(capability: AdapterCapability): void {
    if (!this.capabilities.includes(capability)) {
      throw new UnsupportedAdapterCapabilityError(
        `adapter does not declare required capability: ${capability}`,
      );
    }
  }
}

export interface GovernedToolSpec {
  hostTool: string;
  action: string;
  arguments?: Record<string, GovernedArgumentKind>;
  owner: NonNullable<ExecuteOptions["owner"]>;
  inputSchema?: Record<string, unknown>;
  publicResultSchema?: Record<string, unknown>;
  artifactFields?: readonly string[];
}

export class TrustedInvocation {
  readonly principalId: string;
  readonly sourceNamespace: string;
  readonly sourceId: string;
  readonly adapter: AdapterCapabilities;
  readonly #stableId?: string;
  readonly #traceId?: string;

  constructor(options: {
    principalId: string;
    sourceNamespace: string;
    sourceId: string;
    adapter: AdapterCapabilities;
    /**
     * A host-derived replay identity that predates adapter-core. This is
     * never model input; it preserves a deployed host's idempotency domain
     * while routing its invocation through this shared runtime.
     */
    stableId?: string;
    /** A host-derived trace identity paired with ``stableId``. */
    traceId?: string;
  }) {
    if (
      typeof options.principalId !== "string" || options.principalId.length === 0 ||
      typeof options.sourceNamespace !== "string" || options.sourceNamespace.length === 0 ||
      typeof options.sourceId !== "string" || options.sourceId.length === 0
    ) {
      throw new AdapterCoreError("trusted principal and source values must be non-empty strings");
    }
    this.principalId = options.principalId;
    this.sourceNamespace = options.sourceNamespace;
    this.sourceId = options.sourceId;
    this.adapter = options.adapter;
    if (
      options.stableId !== undefined &&
      (typeof options.stableId !== "string" || options.stableId.length === 0)
    ) {
      throw new AdapterCoreError("trusted stableId must be a non-empty string when provided");
    }
    if (
      options.traceId !== undefined &&
      (typeof options.traceId !== "string" || options.traceId.length === 0)
    ) {
      throw new AdapterCoreError("trusted traceId must be a non-empty string when provided");
    }
    if (options.stableId !== undefined) this.#stableId = options.stableId;
    if (options.traceId !== undefined) this.#traceId = options.traceId;
  }

  adapterInvocation(spec: GovernedToolSpec, arguments_: ActionArguments): AdapterInvocation {
    return createAdapterInvocation({
      principal: { id: this.principalId },
      source: { namespace: this.sourceNamespace, id: this.sourceId },
      adapter: {
        id: this.adapter.adapterId,
        contract_version: "masugate.host-adapter.v1",
        capabilities: [...this.adapter.capabilities],
      },
      action: { name: spec.action, arguments: arguments_ },
    });
  }

  get stableId(): string {
    return this.#stableId ?? `adapter-core:v1:${JSON.stringify([
      this.principalId,
      this.sourceNamespace,
      this.sourceId,
    ])}`;
  }

  get traceId(): string | undefined {
    return this.#traceId;
  }

  get bindingKey(): string {
    return JSON.stringify([this.principalId, this.sourceNamespace, this.sourceId]);
  }
}

export class GovernedRouteParser {
  readonly canonicalManifest: string;
  readonly #routes = new Map<string, GovernedToolSpec>();

  constructor(manifest: unknown) {
    const parsed = validateAnyGovernedRouteManifest(manifest);
    this.canonicalManifest = canonicalAnyGovernedRouteManifest(parsed);
    if (parsed.contract_version === "masugate.governed-route-manifest.v1") {
      for (const route of parsed.routes) {
        const owner: NonNullable<ExecuteOptions["owner"]> = route.owner.position === "transactional"
          ? { providerId: route.owner.provider_id, position: "transactional" }
          : {
              providerId: route.owner.provider_id,
              position: "protected-external",
              connectorId: route.owner.connector_id,
            };
        this.#routes.set(route.host_tool, {
          hostTool: route.host_tool,
          action: route.action,
          arguments: { ...route.arguments },
          owner,
        });
      }
    } else {
      for (const route of parsed.routes) {
        const owner: NonNullable<ExecuteOptions["owner"]> = route.owner.position === "transactional"
          ? { providerId: route.owner.provider_id, position: "transactional" }
          : {
              providerId: route.owner.provider_id,
              position: "protected-external",
              connectorId: route.owner.connector_id,
            };
        this.#routes.set(route.host_tool, {
          hostTool: route.host_tool,
          action: route.action,
          inputSchema: route.input_schema as Record<string, unknown>,
          publicResultSchema: route.public_result_schema as Record<string, unknown>,
          artifactFields: [...route.artifact_fields],
          owner,
        });
      }
    }
  }

  select(hostTool: string): GovernedToolSpec {
    const route = this.#routes.get(hostTool);
    if (route === undefined) throw new UnknownGovernedToolError(`unknown governed tool: ${hostTool}`);
    return route;
  }
}

export interface GovernedLifecycle {
  status: ActionResult["status"];
  result: ActionResult;
  locator: OperationLocator;
  nativeEffectPermitted: false;
  retryAsNewAction: false;
}
export interface PendingPresentation {
  status: "pending";
  operationId: string;
  pendingId: string;
  nativeEffectPermitted: false;
  retryAsNewAction: false;
}

export interface GovernedActionClient {
  execute(options: ExecuteOptions): Promise<ActionResult>;
  stageArtifact(options: {
    action: string;
    field: string;
    content: Uint8Array;
    mediaType: string;
    stableId: string;
    adapterInvocation: string;
    signal?: AbortSignal;
  }): Promise<StagedArtifact>;
  getPending(pendingId: string): Promise<PendingLookup>;
  cancelPending(options: { pendingId: string }): Promise<AdapterCancellationEnvelope>;
  getAudit(operationId: string): Promise<AuditRecord>;
}

/** Optional transport controls retained by a framework-neutral invocation. */
export interface GovernedInvocationOptions {
  signal?: AbortSignal;
}

export function classifyLifecycle(result: ActionResult): GovernedLifecycle {
  return {
    status: result.status,
    result,
    locator: operationLocator(result),
    nativeEffectPermitted: false,
    retryAsNewAction: false,
  };
}

export class GovernedToolRuntime {
  constructor(
    private readonly client: GovernedActionClient,
    readonly routes: GovernedRouteParser,
    readonly invocation: TrustedInvocation,
  ) {}

  async invoke(
    hostTool: string,
    modelArguments: unknown,
    options: GovernedInvocationOptions = {},
  ): Promise<GovernedLifecycle> {
    const spec = this.routes.select(hostTool);
    const arguments_ = validateModelArguments(spec, modelArguments);
    const envelope = this.invocation.adapterInvocation(spec, arguments_);
    const canonical = canonicalAdapterEnvelope(envelope);
    for (const field of spec.artifactFields ?? []) {
      const content = arguments_[field];
      if (typeof content !== "string") {
        throw new AdapterModelArgumentsError(
          "connector ecosystem artifact fields currently require bounded string content",
        );
      }
      await this.client.stageArtifact({
        action: spec.action,
        field,
        content: new TextEncoder().encode(content),
        mediaType: "text/plain",
        stableId: this.invocation.stableId,
        adapterInvocation: canonical,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
    }
    return classifyLifecycle(await this.client.execute({
      action: spec.action,
      args: arguments_,
      stableId: this.invocation.stableId,
      ...(this.invocation.traceId === undefined ? {} : { traceId: this.invocation.traceId }),
      owner: spec.owner,
      expectedPrincipal: this.invocation.principalId,
      adapterInvocation: canonical,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    }));
  }

  async resumePending(locator: unknown): Promise<GovernedLifecycle | PendingPresentation> {
    this.invocation.adapter.require("locator");
    this.invocation.adapter.require("pending-presentation");
    let expected: OperationLocator;
    try {
      expected = validateOperationLocator(locator);
    } catch {
      throw new PendingLocatorMismatchError("pending resume requires a valid pending locator");
    }
    if (!("pending_id" in expected)) {
      throw new PendingLocatorMismatchError("pending resume requires an operation and pending id");
    }
    const lookup = await this.client.getPending(expected.pending_id);
    if (lookup.kind === "terminal") {
      const presentation = classifyLifecycle(lookup.result);
      if (presentation.locator.operation_id !== expected.operation_id) {
        throw new PendingLocatorMismatchError("pending terminal result belongs to another operation");
      }
      return presentation;
    }
    if (
      lookup.pending.pending_id !== expected.pending_id ||
      lookup.pending.operation_id !== expected.operation_id
    ) {
      throw new PendingLocatorMismatchError("pending read did not return the requested operation locator");
    }
    return {
      status: "pending",
      operationId: lookup.pending.operation_id,
      pendingId: expected.pending_id,
      nativeEffectPermitted: false,
      retryAsNewAction: false,
    };
  }

  async cancelPending(locator: unknown): Promise<AdapterCancellationEnvelope> {
    this.invocation.adapter.require("locator");
    this.invocation.adapter.require("cancellation");
    let expected: OperationLocator;
    try {
      expected = validateOperationLocator(locator);
    } catch {
      throw new PendingLocatorMismatchError("pending cancellation requires a valid pending locator");
    }
    if (!("pending_id" in expected)) {
      throw new PendingLocatorMismatchError("pending cancellation requires an operation and pending id");
    }
    const cancellation = await this.client.cancelPending({ pendingId: expected.pending_id });
    if (
      cancellation.locator.operation_id !== expected.operation_id ||
      cancellation.locator.pending_id !== expected.pending_id
    ) {
      throw new PendingLocatorMismatchError(
        "pending cancellation did not return the requested operation locator",
      );
    }
    return cancellation;
  }

  async getReceipt(locator: unknown): Promise<AuditRecord> {
    this.invocation.adapter.require("locator");
    this.invocation.adapter.require("receipt");
    let expected: OperationLocator;
    try {
      expected = validateOperationLocator(locator);
    } catch {
      throw new PendingLocatorMismatchError("receipt requires a valid operation locator");
    }
    const receipt = await this.client.getAudit(expected.operation_id);
    if (receipt.operation_id !== expected.operation_id) {
      throw new PendingLocatorMismatchError("receipt belongs to another operation");
    }
    return receipt;
  }
}

export interface AdapterCoreConformanceFixture {
  manifest: unknown;
  trustedInvocation: {
    principalId: string;
    sourceNamespace: string;
    sourceId: string;
    adapterId: string;
    capabilities: readonly AdapterCapability[];
  };
  modelArguments: Record<string, unknown>;
  canonicalRouteManifest: string;
  canonicalTrustedInvocation: string;
  conformanceVersion: "masugate.adapter-core-conformance.v1";
  scenarios: readonly { id: string; expected: string }[];
}

/** Language-neutral report emitted by the shared conformance scenario corpus. */
export interface AdapterCoreConformanceReport {
  conformanceVersion: string;
  passedCaseIds: readonly string[];
}

/** Supplies one configured public GAP client for each versioned scenario. */
export type AdapterCoreConformanceClientFactory = (scenarioId: string) => GovernedActionClient;

/** Published package asset for host bindings to load into the shared runner. */
export const adapterCoreConformanceFixtureUrl = new URL(
  "./adapter-core-conformance.json",
  import.meta.url,
);

/** Parse the JSON fixture distributed at ``@masugate/adapter-core/conformance-fixture.json``. */
export function parseAdapterCoreConformanceFixture(value: unknown): AdapterCoreConformanceFixture {
  const root = conformanceRecord(value, "adapter core conformance fixture");
  const trusted = conformanceRecord(root["trusted_invocation"], "trusted_invocation");
  const capabilities = trusted["capabilities"];
  const modelArguments = conformanceRecord(root["model_arguments"], "model_arguments");
  const conformanceVersion = conformanceString(root["conformance_version"], "conformance_version");
  if (conformanceVersion !== "masugate.adapter-core-conformance.v1") {
    throw new AdapterCoreError("adapter core conformance version is unsupported");
  }
  const scenarios = conformanceScenarios(root["scenarios"]);
  if (!Array.isArray(capabilities) || capabilities.some((capability) => typeof capability !== "string")) {
    throw new AdapterCoreError("trusted_invocation.capabilities must be an array of strings");
  }
  return {
    manifest: root["manifest"],
    trustedInvocation: {
      principalId: conformanceString(trusted["principal_id"], "trusted_invocation.principal_id"),
      sourceNamespace: conformanceString(
        trusted["source_namespace"], "trusted_invocation.source_namespace",
      ),
      sourceId: conformanceString(trusted["source_id"], "trusted_invocation.source_id"),
      adapterId: conformanceString(trusted["adapter_id"], "trusted_invocation.adapter_id"),
      capabilities: capabilities as AdapterCapability[],
    },
    modelArguments,
    canonicalRouteManifest: conformanceString(
      root["canonical_route_manifest"], "canonical_route_manifest",
    ),
    canonicalTrustedInvocation: conformanceString(
      root["canonical_trusted_invocation"], "canonical_trusted_invocation",
    ),
    conformanceVersion,
    scenarios,
  };
}

/** Create the common runtime against either a fake responder or a real ``masugated`` client. */
export function createAdapterCoreConformanceRuntime(
  client: GovernedActionClient,
  fixture: AdapterCoreConformanceFixture,
  options: { sourceId?: string } = {},
): GovernedToolRuntime {
  return new GovernedToolRuntime(
    client,
    new GovernedRouteParser(fixture.manifest),
    new TrustedInvocation({
      principalId: fixture.trustedInvocation.principalId,
      sourceNamespace: fixture.trustedInvocation.sourceNamespace,
      sourceId: options.sourceId ?? fixture.trustedInvocation.sourceId,
      adapter: new AdapterCapabilities(
        fixture.trustedInvocation.adapterId,
        fixture.trustedInvocation.capabilities,
      ),
    }),
  );
}

/** Assert the byte-canonical portion of the shared fixture for a runtime. */
export function assertAdapterCoreConformanceCanonicalBytes(
  runtime: GovernedToolRuntime,
  fixture: AdapterCoreConformanceFixture,
): void {
  const route = runtime.routes.select("purchase");
  const invocation = runtime.invocation.adapterInvocation(
    route,
    fixture.modelArguments as ActionArguments,
  );
  if (runtime.routes.canonicalManifest !== fixture.canonicalRouteManifest) {
    throw new AdapterCoreError("conformance route canonical bytes differ from the shared fixture");
  }
  if (canonicalAdapterEnvelope(invocation) !== fixture.canonicalTrustedInvocation) {
    throw new AdapterCoreError("conformance trusted-invocation bytes differ from the shared fixture");
  }
}

/** Run the portable scenario corpus against a fake responder or real `masugated` client. */
export async function runAdapterCoreConformance(
  clientFactory: AdapterCoreConformanceClientFactory,
  fixture: AdapterCoreConformanceFixture,
): Promise<AdapterCoreConformanceReport> {
  const expected = [
    ["canonical-bytes", "match"],
    ["forged-fields", "rejected"],
    ["exact-retry", "same-operation"],
    ["changed-content", "conflict"],
    ["distinct-calls", "distinct-operations"],
    ["lifecycle-committed", "committed"],
    ["lifecycle-denied", "denied"],
    ["lifecycle-pending", "pending"],
    ["lifecycle-in-progress", "in_progress"],
    ["lifecycle-outcome-unknown", "outcome_unknown"],
    ["pending-resume", "same-locator"],
    ["pending-terminal", "same-operation"],
    ["locator-checks", "mismatch-rejected"],
    ["capability-gates", "unsupported-rejected"],
  ];
  if (
    fixture.scenarios.length !== expected.length ||
    fixture.scenarios.some(
      (scenario, index) => scenario.id !== expected[index]?.[0] ||
        scenario.expected !== expected[index]?.[1],
    )
  ) {
    throw new AdapterCoreError("adapter core conformance scenarios are unsupported");
  }

  const runtimeFor = (
    scenario: string,
    options: { sourceId?: string; capabilities?: readonly AdapterCapability[] } = {},
  ): GovernedToolRuntime => {
    const client = clientFactory(scenario);
    if (options.capabilities === undefined) {
      return options.sourceId === undefined
        ? createAdapterCoreConformanceRuntime(client, fixture)
        : createAdapterCoreConformanceRuntime(client, fixture, { sourceId: options.sourceId });
    }
    return new GovernedToolRuntime(
      client,
      new GovernedRouteParser(fixture.manifest),
      new TrustedInvocation({
        principalId: fixture.trustedInvocation.principalId,
        sourceNamespace: fixture.trustedInvocation.sourceNamespace,
        sourceId: options.sourceId ?? fixture.trustedInvocation.sourceId,
        adapter: new AdapterCapabilities(
          fixture.trustedInvocation.adapterId,
          options.capabilities,
        ),
      }),
    );
  };

  assertAdapterCoreConformanceCanonicalBytes(runtimeFor("canonical-bytes"), fixture);

  const forgedRuntime = runtimeFor("forged-fields");
  for (const name of ["principal_id", "owner", "locator", "pending_id"]) {
    await assertRejectsAdapterModelArguments(
      forgedRuntime.invoke("purchase", { ...fixture.modelArguments, [name]: "model-controlled" }),
      name,
    );
  }

  const retryRuntime = runtimeFor("exact-retry");
  const first = await retryRuntime.invoke("purchase", fixture.modelArguments);
  const replay = await retryRuntime.invoke("purchase", fixture.modelArguments);
  if (replay.result.operation_id !== first.result.operation_id || !replay.result.replayed) {
    throw new AdapterCoreError("exact retry did not replay one authoritative operation");
  }

  const changedRuntime = runtimeFor("changed-content");
  await changedRuntime.invoke("purchase", fixture.modelArguments);
  let changed = false;
  try {
    await changedRuntime.invoke("purchase", { ...fixture.modelArguments, amount_cents: 1251 });
  } catch (error) {
    changed = error instanceof ChangedInvocationConflictError ||
      (error instanceof MasuGateHttpError && error.status === 409 && error.code === "resource_conflict");
    if (!changed) throw error;
  }
  if (!changed) {
    throw new AdapterCoreError("changed content did not conflict for one trusted invocation");
  }

  const distinctClient = clientFactory("distinct-calls");
  const firstDistinct = createAdapterCoreConformanceRuntime(
    distinctClient, fixture, { sourceId: "call-001" },
  );
  const secondDistinct = createAdapterCoreConformanceRuntime(
    distinctClient, fixture, { sourceId: "call-002" },
  );
  const firstOperation = await firstDistinct.invoke("purchase", fixture.modelArguments);
  const secondOperation = await secondDistinct.invoke("purchase", fixture.modelArguments);
  if (firstOperation.result.operation_id === secondOperation.result.operation_id) {
    throw new AdapterCoreError("distinct trusted calls reused one authoritative operation");
  }

  for (const status of [
    "committed", "denied", "pending", "in_progress", "outcome_unknown",
  ] as const) {
    const presentation = await runtimeFor(`lifecycle-${status}`).invoke(
      "purchase", fixture.modelArguments,
    );
    if (
      presentation.status !== status ||
      presentation.nativeEffectPermitted !== false ||
      presentation.retryAsNewAction !== false
    ) {
      throw new AdapterCoreError(`${status} did not remain a replacement-only lifecycle`);
    }
  }

  const pendingRuntime = runtimeFor("pending-resume");
  const pending = await pendingRuntime.invoke("purchase", fixture.modelArguments);
  if (pending.result.status !== "pending") {
    throw new AdapterCoreError("pending scenario did not return a pending locator");
  }
  const resumed = await pendingRuntime.resumePending(pending.locator);
  if (
    resumed.status !== "pending" ||
    !("pendingId" in resumed) ||
    resumed.operationId !== pending.result.operation_id ||
    resumed.pendingId !== pending.result.pending_id
  ) {
    throw new AdapterCoreError("pending resume did not preserve the original locator");
  }

  const terminalRuntime = runtimeFor("pending-terminal");
  const terminalPending = await terminalRuntime.invoke("purchase", fixture.modelArguments);
  const terminal = await terminalRuntime.resumePending(terminalPending.locator);
  if (
    !("result" in terminal) ||
    terminal.result.operation_id !== terminalPending.result.operation_id
  ) {
    throw new AdapterCoreError("pending terminal read did not preserve the operation");
  }

  const mismatchRuntime = runtimeFor("locator-checks");
  const mismatchPending = await mismatchRuntime.invoke("purchase", fixture.modelArguments);
  await assertRejectsLocatorMismatch(mismatchRuntime.resumePending(mismatchPending.locator));
  await assertRejectsLocatorMismatch(mismatchRuntime.cancelPending(mismatchPending.locator));
  await assertRejectsLocatorMismatch(mismatchRuntime.getReceipt(mismatchPending.locator));

  const noCapabilities = runtimeFor("capability-gates", { capabilities: [] });
  const locator: OperationLocator = {
    operation_id: "00000000-0000-4000-8000-000000000001",
    pending_id: "11111111-1111-4111-8111-111111111111",
  };
  await assertRejectsUnsupportedCapability(noCapabilities.resumePending(locator));
  await assertRejectsUnsupportedCapability(noCapabilities.cancelPending(locator));
  await assertRejectsUnsupportedCapability(noCapabilities.getReceipt(locator));
  return {
    conformanceVersion: fixture.conformanceVersion,
    passedCaseIds: fixture.scenarios.map((scenario) => scenario.id),
  };
}

async function assertRejectsAdapterModelArguments(
  operation: Promise<unknown>,
  name: string,
): Promise<void> {
  try {
    await operation;
  } catch (error) {
    if (error instanceof AdapterModelArgumentsError) return;
    throw error;
  }
  throw new AdapterCoreError(`model arguments could forge ${name}`);
}

async function assertRejectsLocatorMismatch(operation: Promise<unknown>): Promise<void> {
  try {
    await operation;
  } catch (error) {
    if (error instanceof PendingLocatorMismatchError) return;
    throw error;
  }
  throw new AdapterCoreError("control-plane locator mismatch was accepted");
}

async function assertRejectsUnsupportedCapability(operation: Promise<unknown>): Promise<void> {
  try {
    await operation;
  } catch (error) {
    if (error instanceof UnsupportedAdapterCapabilityError) return;
    throw error;
  }
  throw new AdapterCoreError("undeclared control-plane capability was accepted");
}

function validateModelArguments(spec: GovernedToolSpec, value: unknown): ActionArguments {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new AdapterModelArgumentsError("model arguments must be an object");
  }
  if (spec.arguments === undefined) {
    if (spec.inputSchema === undefined) {
      throw new AdapterCoreError("v2 governed route is missing inputSchema");
    }
    return validateV2ScalarArguments(spec.inputSchema, value as Record<string, unknown>);
  }
  const supplied = value as Record<string, unknown>;
  const suppliedNames = Object.keys(supplied);
  const declaredNames = Object.keys(spec.arguments);
  const unexpected = suppliedNames.filter((name) => !declaredNames.includes(name)).sort();
  const missing = declaredNames.filter((name) => !suppliedNames.includes(name)).sort();
  if (unexpected.length > 0 || missing.length > 0) {
    const problems = [
      unexpected.length > 0 ? `unexpected model arguments: ${unexpected.join(", ")}` : "",
      missing.length > 0 ? `missing model arguments: ${missing.join(", ")}` : "",
    ].filter(Boolean);
    throw new AdapterModelArgumentsError(problems.join("; "));
  }
  const parsed: ActionArguments = {};
  for (const [name, kind] of Object.entries(spec.arguments)) {
    const argument = supplied[name];
    if (kind === "string" && typeof argument === "string") {
      parsed[name] = argument;
    } else if (kind === "boolean" && typeof argument === "boolean") {
      parsed[name] = argument;
    } else if (
      kind === "integer" &&
      typeof argument === "number" &&
      Number.isInteger(argument) &&
      argument >= SAFE_INTEGER_MIN &&
      argument <= SAFE_INTEGER_MAX
    ) {
      parsed[name] = argument;
    } else {
      throw new AdapterModelArgumentsError(`model argument ${name} must be ${kind}`);
    }
  }
  return parsed;
}

function validateV2ScalarArguments(
  schema: Record<string, unknown>,
  supplied: Record<string, unknown>,
): ActionArguments {
  const properties = schema["properties"];
  const required = schema["required"];
  if (!isRecord(properties) || !Array.isArray(required) || required.some((name) => typeof name !== "string")) {
    throw new AdapterCoreError("v2 governed route has malformed bounded schema");
  }
  const declaredNames = Object.keys(properties);
  const suppliedNames = Object.keys(supplied);
  const unexpected = suppliedNames.filter((name) => !declaredNames.includes(name)).sort();
  const missing = required.filter((name) => !suppliedNames.includes(name)).sort();
  if (unexpected.length > 0 || missing.length > 0) {
    const problems = [
      unexpected.length > 0 ? `unexpected model arguments: ${unexpected.join(", ")}` : "",
      missing.length > 0 ? `missing model arguments: ${missing.join(", ")}` : "",
    ].filter(Boolean);
    throw new AdapterModelArgumentsError(problems.join("; "));
  }
  const parsed: ActionArguments = {};
  for (const name of suppliedNames) {
    const fieldSchema = properties[name];
    if (!isRecord(fieldSchema) || typeof fieldSchema["type"] !== "string") {
      throw new AdapterCoreError(`v2 governed route schema for ${name} is malformed`);
    }
    const value = supplied[name];
    switch (fieldSchema["type"]) {
      case "string": {
        if (typeof value !== "string") {
          throw new AdapterModelArgumentsError(`model argument ${name} must be string`);
        }
        if (hasUnpairedSurrogate(value)) {
          throw new AdapterModelArgumentsError(`model argument ${name} contains an unpaired surrogate`);
        }
        const minimum = fieldSchema["minLength"];
        const maximum = fieldSchema["maxLength"];
        const codePoints = Array.from(value).length;
        if (
          (typeof minimum === "number" && codePoints < minimum) ||
          (typeof maximum === "number" && codePoints > maximum)
        ) {
          throw new AdapterModelArgumentsError(`model argument ${name} violates string bounds`);
        }
        parsed[name] = value;
        break;
      }
      case "integer": {
        if (
          typeof value !== "number" || !Number.isSafeInteger(value) ||
          (typeof fieldSchema["minimum"] === "number" && value < fieldSchema["minimum"]) ||
          (typeof fieldSchema["maximum"] === "number" && value > fieldSchema["maximum"])
        ) {
          throw new AdapterModelArgumentsError(`model argument ${name} violates integer bounds`);
        }
        parsed[name] = value;
        break;
      }
      case "boolean":
        if (typeof value !== "boolean") {
          throw new AdapterModelArgumentsError(`model argument ${name} must be boolean`);
        }
        parsed[name] = value;
        break;
      default:
        throw new AdapterModelArgumentsError(
          "nested v2 route inputs require an operation-specific protected-payload bridge",
        );
    }
  }
  return parsed;
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      if (index + 1 >= value.length) return true;
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && !Array.isArray(value) && typeof value === "object";
}

function conformanceRecord(value: unknown, field: string): Record<string, unknown> {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new AdapterCoreError(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

function conformanceString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new AdapterCoreError(`${field} must be a non-empty string`);
  }
  return value;
}

function conformanceScenarios(value: unknown): readonly { id: string; expected: string }[] {
  if (!Array.isArray(value)) throw new AdapterCoreError("scenarios must be an array");
  return value.map((raw, index) => {
    const scenario = conformanceRecord(raw, `scenarios[${index}]`);
    const keys = Object.keys(scenario).sort();
    if (keys.length !== 2 || keys[0] !== "expected" || keys[1] !== "id") {
      throw new AdapterCoreError(`scenarios[${index}] has unsupported fields`);
    }
    return {
      id: conformanceString(scenario["id"], `scenarios[${index}].id`),
      expected: conformanceString(scenario["expected"], `scenarios[${index}].expected`),
    };
  });
}
