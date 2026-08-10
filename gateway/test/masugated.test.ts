import {
  MasuGateClient,
  MasuGateHttpError,
  MasuGateProtocolError,
  deriveIdempotencyKey,
} from "@masugate/client";
import { describe, expect, it } from "vitest";

import { MasuGateSdkAdapter } from "../src/masugated.js";

const OPERATION_ID = "8b52f5e2-d704-4bd1-bbf4-284e2a5c6c48";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function committedResponse(): Record<string, unknown> {
  return {
    operation_id: OPERATION_ID,
    status: "committed",
    decision: {
      effect: "allow",
      policy_id: "budget",
      policy_version: "v1",
      rule_id: "allow_default",
      reason: "allowed",
    },
    payload: { receipt: "r1" },
    audit_ref: `/v1/audit/${OPERATION_ID}`,
    replayed: false,
  };
}

describe("MasuGateSdkAdapter", () => {
  it("delegates HTTP validation and canonical idempotency to @masugate/client", async () => {
    const requests: Array<{ input: RequestInfo | URL; init?: RequestInit }> = [];
    const fakeFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      requests.push(init === undefined ? { input } : { input, init });
      return jsonResponse(committedResponse());
    }) as typeof fetch;
    const adapter = new MasuGateSdkAdapter(
      new MasuGateClient({ baseUrl: "http://masugated.test/", token: "secret", fetch: fakeFetch }),
    );

    const result = await adapter.execute({
      action: "transfer",
      args: { receiver_id: "merchant", amount_cents: 100 },
      stableId: "mcp-tool\u0000purchase\u0000string\u0000logical-op:α",
      traceId: "mcp:1",
    });

    expect(result.status).toBe("committed");
    expect(String(requests[0]?.input)).toBe("http://masugated.test/v1/actions");
    expect(requests[0]?.init?.headers).toMatchObject({
      Authorization: "Bearer secret",
      "Content-Type": "application/json",
    });
    const body = JSON.parse(String(requests[0]?.init?.body)) as Record<string, unknown>;
    expect(body).toEqual({
      action: "transfer",
      args: { receiver_id: "merchant", amount_cents: 100 },
      idempotency_key: await deriveIdempotencyKey(
        "mcp-tool\u0000purchase\u0000string\u0000logical-op:α",
      ),
      trace_id: "mcp:1",
    });
  });

  it("rejects malformed success responses through the SDK deep parser", async () => {
    const malformed = committedResponse();
    delete (malformed["decision"] as Record<string, unknown>)["policy_id"];
    const fakeFetch = (async () => jsonResponse(malformed)) as typeof fetch;
    const adapter = new MasuGateSdkAdapter(
      new MasuGateClient({ baseUrl: "http://masugated.test", token: "secret", fetch: fakeFetch }),
    );

    await expect(
      adapter.execute({ action: "transfer", args: {}, stableId: "logical-1" }),
    ).rejects.toBeInstanceOf(MasuGateProtocolError);
  });

  it("preserves the SDK HTTP error mapping", async () => {
    const fakeFetch = (async () =>
      jsonResponse(
        { error: { code: "unauthorized", message: "invalid bearer token" } },
        401,
      )) as typeof fetch;
    const adapter = new MasuGateSdkAdapter(
      new MasuGateClient({ baseUrl: "http://masugated.test", token: "bad", fetch: fakeFetch }),
    );

    const error: unknown = await adapter.getAudit(OPERATION_ID).catch(
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(MasuGateHttpError);
    expect(error).toMatchObject({
      status: 401,
      code: "unauthorized",
      message: "invalid bearer token",
    });
  });
});
