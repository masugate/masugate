#!/usr/bin/env node

import { readFile } from "node:fs/promises";

import { parseManifest } from "./manifest.js";
import { GatewayRouter } from "./router.js";
import { createMasuGatedClient } from "./masugated.js";
import { runStdioGateway } from "./server.js";
import { McpStdioUpstream } from "./upstream.js";

const USAGE = "Usage: masugate-mcp-gateway --manifest <gateway.yaml>";

function manifestPath(argv: readonly string[]): string {
  if (argv.length === 1 && (argv[0] === "--help" || argv[0] === "-h")) {
    process.stderr.write(`${USAGE}\n`);
    process.exitCode = 0;
    return "";
  }
  if (argv.length !== 2 || (argv[0] !== "--manifest" && argv[0] !== "-m")) {
    throw new Error(USAGE);
  }
  const path = argv[1];
  if (path === undefined || path === "") {
    throw new Error(USAGE);
  }
  return path;
}

export async function main(
  argv: readonly string[] = process.argv.slice(2),
  environment: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  const path = manifestPath(argv);
  if (path === "") {
    return;
  }
  const manifest = parseManifest(await readFile(path, "utf8"));
  const token = environment[manifest.masugated.tokenEnv];
  if (token === undefined || token === "") {
    throw new Error(
      `masugated token environment variable ${manifest.masugated.tokenEnv} is missing or empty`,
    );
  }
  const upstream = new McpStdioUpstream(manifest.upstream, environment);
  const router = new GatewayRouter(
    manifest,
    upstream,
    createMasuGatedClient(manifest.masugated.baseUrl, token),
  );
  try {
    const server = await runStdioGateway(router);
    server.onclose = () => {
      void upstream.close();
    };
    const shutdown = (): void => {
      void Promise.all([server.close(), upstream.close()]).finally(() => {
        process.exitCode = 0;
      });
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  } catch (error) {
    await upstream.close();
    throw error;
  }
}

void main().catch((error: unknown) => {
  process.stderr.write(
    `masugate-mcp-gateway: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 1;
});
