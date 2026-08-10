import {
  MasuGateClient,
  type AuditRecord,
  type JsonObject,
} from "@masugate/client";

import type {
  MasuGatedActionResult,
  MasuGatedClient,
  MasuGatedExecuteRequest,
} from "./types.js";

/**
 * Adapts the published TypeScript SDK to the gateway-owned interface.
 *
 * All HTTP behavior, deep response validation, error-envelope mapping, and
 * `masugate:v1` idempotency hashing stay canonical in `@masugate/client`; the gateway
 * only supplies MCP normalization and outcome-to-MCP mapping.
 */
export class MasuGateSdkAdapter implements MasuGatedClient {
  constructor(readonly client: Pick<MasuGateClient, "execute" | "getAudit">) {}

  async execute(request: MasuGatedExecuteRequest): Promise<MasuGatedActionResult> {
    const options = {
      action: request.action,
      args: request.args,
      stableId: request.stableId,
      ...(request.traceId === undefined ? {} : { traceId: request.traceId }),
    };
    return this.client.execute<JsonObject>(options);
  }

  async getAudit(operationId: string): Promise<JsonObject> {
    const receipt: AuditRecord = await this.client.getAudit(operationId);
    // AuditRecord has been deeply validated by @masugate/client. The spread gives
    // the MCP structured-content boundary an ordinary JSON record without
    // weakening the SDK parser's public AuditRecord type.
    return { ...receipt } as unknown as JsonObject;
  }
}

export function createMasuGatedClient(baseUrl: string, token: string): MasuGatedClient {
  return new MasuGateSdkAdapter(new MasuGateClient({ baseUrl, token }));
}

export {
  MasuGateHttpError,
  MasuGateProtocolError,
  deriveIdempotencyKey,
} from "@masugate/client";
