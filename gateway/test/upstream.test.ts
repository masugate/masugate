import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { McpStdioUpstream } from "../src/upstream.js";

describe("McpStdioUpstream", () => {
  it("lists and calls a real stdio child through the official SDK transport", async () => {
    // Vitest executes transformed modules from a temporary SSR directory, so
    // import.meta.url is not a stable base for a spawned fixture path.
    const fixture = resolve(process.cwd(), "test/fixtures/upstream.mjs");
    const upstream = new McpStdioUpstream({
      command: process.execPath,
      args: [fixture],
      env: {},
    });
    try {
      await expect(upstream.listTools()).resolves.toMatchObject([
        { name: "echo", description: "stdio echo fixture" },
      ]);
      await expect(upstream.callTool("echo", { text: "over stdio" })).resolves.toMatchObject({
        content: [{ type: "text", text: "over stdio" }],
        structuredContent: { echoed: "over stdio" },
      });
    } finally {
      await upstream.close();
    }
  });
});
