import { createInterface } from "node:readline";

// A deliberately tiny wire fixture. The production client side is the
// official SDK's StdioClientTransport; the separate in-memory smoke test uses
// the official SDK on both sides. Keeping this child dependency-free makes the
// process-spawn/stdio test robust across Vitest's transformed module loader.
const input = createInterface({ input: process.stdin, terminal: false });

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

input.on("line", (line) => {
  const request = JSON.parse(line);
  if (request.method === "notifications/initialized") {
    return;
  }
  if (request.method === "initialize") {
    send({
      jsonrpc: "2.0",
      id: request.id,
      result: {
        protocolVersion: request.params.protocolVersion,
        capabilities: { tools: {} },
        serverInfo: { name: "masugate-gateway-test-upstream", version: "0.1.1" },
      },
    });
    return;
  }
  if (request.method === "tools/list") {
    send({
      jsonrpc: "2.0",
      id: request.id,
      result: {
        tools: [
          {
            name: "echo",
            description: "stdio echo fixture",
            inputSchema: {
              type: "object",
              properties: { text: { type: "string" } },
              required: ["text"],
            },
          },
        ],
      },
    });
    return;
  }
  if (request.method === "tools/call" && request.params.name === "echo") {
    const text = request.params.arguments?.text;
    send({
      jsonrpc: "2.0",
      id: request.id,
      result: {
        content: [{ type: "text", text: String(text) }],
        structuredContent: { echoed: text },
      },
    });
    return;
  }
  send({
    jsonrpc: "2.0",
    id: request.id,
    error: { code: -32602, message: "unknown fixture request" },
  });
});
