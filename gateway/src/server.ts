import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ErrorCode,
  ListToolsRequestSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

import { GatewayError, GatewayRouter } from "./router.js";

function protocolError(error: unknown): never {
  if (error instanceof McpError) {
    throw error;
  }
  if (error instanceof GatewayError) {
    throw new McpError(ErrorCode.InvalidParams, error.message);
  }
  throw error;
}

export function createGatewayServer(router: GatewayRouter): Server {
  const server = new Server(
    { name: "masugate-mcp-gateway", version: "0.1.1" },
    {
      capabilities: { tools: {} },
      instructions:
        "Declared governed tools execute through MasuGate. masugate_audit_get is read-only and cannot approve pending work.",
    },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    try {
      return { tools: await router.listTools() };
    } catch (error) {
      return protocolError(error);
    }
  });

  server.setRequestHandler(CallToolRequestSchema, async (request, extra) => {
    try {
      return await router.callTool(
        request.params.name,
        request.params.arguments,
        { requestId: extra.requestId },
      );
    } catch (error) {
      return protocolError(error);
    }
  });

  return server;
}

export async function connectGatewayServer(
  router: GatewayRouter,
  transport: Transport,
): Promise<Server> {
  // Validate every manifest route against the upstream before advertising a
  // server. A typo therefore fails startup instead of becoming a bypass later.
  await router.initialize();
  const server = createGatewayServer(router);
  await server.connect(transport);
  return server;
}

export async function runStdioGateway(router: GatewayRouter): Promise<Server> {
  return connectGatewayServer(router, new StdioServerTransport());
}
