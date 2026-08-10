import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import {
  getDefaultEnvironment,
  StdioClientTransport,
} from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  CallToolResultSchema,
  type CallToolResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js";

import type { Upstream, UpstreamManifest } from "./types.js";

const ENV_REFERENCE = /^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$/;

export function resolveUpstreamEnvironment(
  configured: Readonly<Record<string, string>>,
  source: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const result = getDefaultEnvironment();
  for (const [name, configuredValue] of Object.entries(configured)) {
    const match = ENV_REFERENCE.exec(configuredValue);
    if (match === null) {
      result[name] = configuredValue;
      continue;
    }
    const sourceName = match[1];
    if (sourceName === undefined || source[sourceName] === undefined) {
      throw new Error(
        `upstream.env.${name} references missing environment variable ${sourceName ?? ""}`,
      );
    }
    result[name] = source[sourceName];
  }
  return result;
}

export class McpStdioUpstream implements Upstream {
  readonly #client = new Client(
    { name: "masugate-mcp-gateway-upstream", version: "0.1.0" },
    { capabilities: {} },
  );
  readonly #transport: StdioClientTransport;
  #connected = false;

  constructor(manifest: UpstreamManifest, environment: NodeJS.ProcessEnv = process.env) {
    const parameters = {
      command: manifest.command,
      args: [...manifest.args],
      env: resolveUpstreamEnvironment(manifest.env, environment),
      stderr: "pipe" as const,
      ...(manifest.cwd === undefined ? {} : { cwd: manifest.cwd }),
    };
    this.#transport = new StdioClientTransport(parameters);
    this.#transport.stderr?.pipe(process.stderr);
  }

  async connect(): Promise<void> {
    if (!this.#connected) {
      await this.#client.connect(this.#transport);
      this.#connected = true;
    }
  }

  async listTools(): Promise<Tool[]> {
    await this.connect();
    const tools: Tool[] = [];
    let cursor: string | undefined;
    do {
      const result = await this.#client.listTools(cursor === undefined ? {} : { cursor });
      tools.push(...result.tools);
      cursor = result.nextCursor;
    } while (cursor !== undefined);
    return tools;
  }

  async callTool(name: string, args?: Record<string, unknown>): Promise<CallToolResult> {
    await this.connect();
    const params = args === undefined ? { name } : { name, arguments: args };
    const result = await this.#client.callTool(
      params,
      CallToolResultSchema,
    );
    const parsed = CallToolResultSchema.safeParse(result);
    if (!parsed.success) {
      throw new Error(
        `upstream tool ${JSON.stringify(name)} returned an unsupported task handle`,
      );
    }
    return parsed.data;
  }

  async close(): Promise<void> {
    if (this.#connected) {
      this.#connected = false;
      await this.#client.close();
    }
  }
}
