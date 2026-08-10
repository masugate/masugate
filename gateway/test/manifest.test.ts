import { describe, expect, it } from "vitest";

import { ManifestError, parseManifest } from "../src/manifest.js";

const VALID = `
version: 1
upstream:
  command: node
  args: [server.mjs]
  env:
    API_TOKEN: \${UPSTREAM_TOKEN}
masugated:
  base_url: http://127.0.0.1:8000/
  token_env: MASUGATED_TOKEN
governed:
  purchase:
    action: transfer
    stable_id: $.request_id
    args:
      receiver_id: $.merchant.id
      amount_cents: $.items[0].amount
passthrough: [search]
`;

describe("parseManifest", () => {
  it("parses one upstream, governed mappings, and passthrough tools", () => {
    const parsed = parseManifest(VALID);
    expect(parsed.upstream.command).toBe("node");
    expect(parsed.upstream.env).toEqual({ API_TOKEN: "${UPSTREAM_TOKEN}" });
    expect(parsed.masugated).toEqual({
      baseUrl: "http://127.0.0.1:8000",
      tokenEnv: "MASUGATED_TOKEN",
    });
    expect(parsed.governed["purchase"]?.args).toEqual({
      receiver_id: "$.merchant.id",
      amount_cents: "$.items[0].amount",
    });
    expect(parsed.governed["purchase"]?.stableIdPath).toBe("$.request_id");
  });

  it("reports malformed YAML clearly", () => {
    expect(() => parseManifest("version: 1\ngoverned: [")).toThrowError(
      /invalid YAML/i,
    );
  });

  it("rejects governed/passthrough overlap", () => {
    expect(() => parseManifest(VALID.replace("[search]", "[purchase]"))).toThrowError(
      /cannot be both governed and passthrough/,
    );
  });

  it("rejects a route with no argument mapping", () => {
    expect(() =>
      parseManifest(VALID.replace("    args:\n      receiver_id: $.merchant.id\n      amount_cents: $.items[0].amount\n", "")),
    ).toThrowError(/purchase\.args: is required/);
  });

  it("requires an exact stable-id mapping", () => {
    expect(() => parseManifest(VALID.replace("    stable_id: $.request_id\n", ""))).toThrowError(
      /purchase\.stable_id/,
    );
    expect(() =>
      parseManifest(VALID.replace("stable_id: $.request_id", "stable_id: $..request_id")),
    ).toThrowError(/must be an exact JSONPath/);
  });

  it("rejects ambiguous or executable JSONPath", () => {
    expect(() => parseManifest(VALID.replace("$.merchant.id", "$..id"))).toThrowError(
      /must be an exact JSONPath/,
    );
    expect(() =>
      parseManifest(VALID.replace("$.merchant.id", "$.items[?(@.price > 1)]")),
    ).toThrowError(/must be an exact JSONPath/);
  });

  it("rejects duplicates and unknown fields", () => {
    expect(() => parseManifest(VALID.replace("[search]", "[search, search]"))).toThrowError(
      /duplicate tool/,
    );
    expect(() => parseManifest(`${VALID}\nmagic: true\n`)).toThrowError(/unknown field/);
  });

  it("uses a typed manifest error", () => {
    expect(() => parseManifest("version: 2")).toThrow(ManifestError);
  });
});
