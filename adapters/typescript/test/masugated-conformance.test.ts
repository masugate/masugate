import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { createServer } from "node:net";
import test from "node:test";

import { MasuGateClient, MasuGateHttpError, type ActionArguments } from "@masugate/client";

import {
  createAdapterCoreConformanceRuntime,
  parseAdapterCoreConformanceFixture,
} from "../src/index.js";

const fixture = parseAdapterCoreConformanceFixture(JSON.parse(await readFile(
  new URL("../../../../protocol/examples/adapter-core-conformance.json", import.meta.url),
  "utf8",
)));

async function unusedPort(): Promise<number> {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("expected TCP address");
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  return address.port;
}

const MASUGATED_STARTUP_TIMEOUT_MS = 10_000;
const MASUGATED_STARTUP_POLL_INTERVAL_MS = 25;

async function waitForMasuGated(baseUrl: string, process: ChildProcess): Promise<void> {
  let stderr = "";
  let startupError: Error | undefined;
  process.stderr?.on("data", (chunk: Buffer) => { stderr += chunk.toString(); });
  process.once("error", (error: Error) => { startupError = error; });
  const deadline = Date.now() + MASUGATED_STARTUP_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (startupError !== undefined) {
      throw new Error(`could not start masugated fixture: ${startupError.message}`);
    }
    if (process.exitCode !== null) throw new Error(`masugated fixture exited: ${stderr}`);
    try {
      const response = await fetch(`${baseUrl}/openapi.json`);
      if (response.ok) return;
    } catch {
      // The TCP listener is still starting.
    }
    await new Promise((resolve) => setTimeout(resolve, MASUGATED_STARTUP_POLL_INTERVAL_MS));
  }
  throw new Error(
    `timed out waiting ${MASUGATED_STARTUP_TIMEOUT_MS}ms for real masugated fixture: ` +
      (stderr.trim() || "<no stderr>"),
  );
}

async function stop(process: ChildProcess): Promise<void> {
  if (process.exitCode !== null) return;
  process.kill("SIGTERM");
  await Promise.race([
    once(process, "exit"),
    new Promise((resolve) => setTimeout(resolve, 5_000)),
  ]);
  if (process.exitCode === null) process.kill("SIGKILL");
}

test("adapter core uses the real masugated HTTP boundary from TypeScript", async () => {
  const port = await unusedPort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const python = process.env["MASUGATE_CONFORMANCE_PYTHON"] ?? "python";
  const fixtureServer = new URL(
    "../../../conformance/masugated_fixture_server.py",
    import.meta.url,
  );
  const child = spawn(python, [fixtureServer.pathname, "--port", String(port)], {
    stdio: ["ignore", "ignore", "pipe"],
  });
  try {
    await waitForMasuGated(baseUrl, child);
    const client = new MasuGateClient({ baseUrl, token: "adapter-token" });
    const runtime = createAdapterCoreConformanceRuntime(client, fixture);
    await assert.rejects(
      client.execute({
        action: "spend.purchase",
        args: fixture.modelArguments as ActionArguments,
        stableId: "adapter:strict-body-stripped",
        owner: runtime.routes.select("purchase").owner,
        expectedPrincipal: "adapter:buyer",
      }),
      (error: unknown) => error instanceof MasuGateHttpError && error.status === 400 &&
        error.code === "invalid_request",
    );
    const first = await runtime.invoke("purchase", fixture.modelArguments);
    const replay = await runtime.invoke("purchase", fixture.modelArguments);
    assert.equal(first.status, "committed");
    assert.equal(replay.result.replayed, true);
    assert.equal(replay.result.operation_id, first.result.operation_id);
    await assert.rejects(
      runtime.invoke("purchase", { ...fixture.modelArguments, amount_cents: 1251 }),
      (error: unknown) => error instanceof MasuGateHttpError && error.status === 409,
    );
  } finally {
    await stop(child);
  }
});

test("real masugated rejects a trusted principal that differs from its bearer", async () => {
  const port = await unusedPort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const python = process.env["MASUGATE_CONFORMANCE_PYTHON"] ?? "python";
  const fixtureServer = new URL(
    "../../../conformance/masugated_fixture_server.py",
    import.meta.url,
  );
  const child = spawn(python, [fixtureServer.pathname, "--port", String(port)], {
    stdio: ["ignore", "ignore", "pipe"],
  });
  try {
    await waitForMasuGated(baseUrl, child);
    const client = new MasuGateClient({ baseUrl, token: "wrong-token" });
    const runtime = createAdapterCoreConformanceRuntime(client, fixture);
    await assert.rejects(
      runtime.invoke("purchase", fixture.modelArguments),
      (error: unknown) => error instanceof MasuGateHttpError && error.status === 401,
    );
  } finally {
    await stop(child);
  }
});
