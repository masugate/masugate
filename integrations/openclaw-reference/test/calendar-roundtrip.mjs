import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createOpenClawCodingTools } from "openclaw/plugin-sdk/agent-harness";

const baseUrl = process.argv[2];
const mode = process.env.MASUGATE_CALENDAR_ROUNDTRIP_MODE ?? "full";
assert.ok(baseUrl, "MasuGate reference-calendar base URL is required");

const here = dirname(fileURLToPath(import.meta.url));
const pluginRoot = resolve(here, "..", "..", "openclaw");
process.env.MASUGATE_CALENDAR_TOKEN = "calendar-token";
process.env.MASUGATE_CALENDAR_BLOCKED_TOKEN = "calendar-blocked-token";

const config = {
  masugatedBaseUrl: baseUrl,
  agents: {
    "calendar-alpha": "MASUGATE_CALENDAR_TOKEN",
    "calendar-blocked": "MASUGATE_CALENDAR_BLOCKED_TOKEN",
  },
  compiledRouteManifest: JSON.parse(process.env.MASUGATE_CALENDAR_ROUTE_MANIFEST ?? ""),
};

function eventArguments(durationMinutes = 30) {
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone: "America/New_York",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    weekday: "short",
    timeZoneName: "longOffset",
  });
  let date = new Date(Date.now() + 24 * 60 * 60 * 1000);
  let parts = formatter.formatToParts(date);
  while (["Sat", "Sun"].includes(parts.find((part) => part.type === "weekday")?.value)) {
    date = new Date(date.getTime() + 24 * 60 * 60 * 1000);
    parts = formatter.formatToParts(date);
  }
  const part = (type) => parts.find((item) => item.type === type)?.value;
  const offset = part("timeZoneName")?.replace("GMT", "");
  assert.ok(offset, "New York formatter must provide an RFC3339 offset");
  const day = `${part("year")}-${part("month")}-${part("day")}`;
  const endHour = 10 + Math.floor(durationMinutes / 60);
  const endMinute = String(durationMinutes % 60).padStart(2, "0");
  return {
    title: "OpenClaw calendar matrix",
    description: "real governed calendar worker",
    start_at: `${day}T10:00:00${offset}`,
    end_at: `${day}T${String(endHour).padStart(2, "0")}:${endMinute}:00${offset}`,
    timezone: "America/New_York",
  };
}

function governedTool(agentId = "calendar-alpha") {
  const tool = createOpenClawCodingTools({
    agentId,
    sessionId: `calendar_connector_worker-calendar-${agentId}-session`,
    sessionKey: `agent:${agentId}:main`,
    config: {
      plugins: {
        allow: ["masugate"],
        load: { paths: [pluginRoot] },
        entries: { masugate: { enabled: true, config } },
      },
      tools: { allow: ["masugate_governed_action"] },
    },
    cwd: pluginRoot,
    workspaceDir: pluginRoot,
  }).find((candidate) => candidate.name === "masugate_governed_action");
  assert.ok(tool, "real OpenClaw resolver must select the governed Calendar tool");
  return tool;
}

await assert.rejects(
  governedTool().execute("openclaw-calendar-raw-43", { route: "calendar_raw", args: {} }, undefined, undefined),
);
await assert.rejects(
  governedTool().execute(
    "openclaw-calendar-native-create-43",
    { route: "calendar_create", args: { native_event_id: "untrusted" } },
    undefined,
    undefined,
  ),
);

if (mode === "resume-pending") {
  const resumed = await governedTool().execute(
    "openclaw-calendar-pending-43",
    { route: "calendar_create", args: eventArguments(90) },
    undefined,
    undefined,
  );
  process.stdout.write(`MASUGATE_RESULT:${JSON.stringify({ resumed: resumed.details })}\n`);
  process.exit(0);
}

const input = { route: "calendar_create", args: eventArguments() };
const first = await governedTool().execute("openclaw-calendar-call-43", input, undefined, undefined);
const replay = await governedTool().execute("openclaw-calendar-call-43", input, undefined, undefined);
const denied = await governedTool("calendar-blocked").execute(
  "openclaw-calendar-denied-43",
  input,
  undefined,
  undefined,
);
const pendingInput = { route: "calendar_create", args: eventArguments(90) };
const pending = await governedTool().execute(
  "openclaw-calendar-pending-43",
  pendingInput,
  undefined,
  undefined,
);
const pendingReplay = await governedTool().execute(
  "openclaw-calendar-pending-43",
  pendingInput,
  undefined,
  undefined,
);
const eventRef = first.details.payload.event_ref;
assert.equal(typeof eventRef, "string", "calendar create must return the protected event reference");
const cancellation = { route: "calendar_cancel", args: { event_ref: eventRef } };
const cancelled = await governedTool().execute(
  "openclaw-calendar-cancel-43",
  cancellation,
  undefined,
  undefined,
);
const cancelReplay = await governedTool().execute(
  "openclaw-calendar-cancel-43",
  cancellation,
  undefined,
  undefined,
);
process.stdout.write(
  `MASUGATE_RESULT:${JSON.stringify({
    first: first.details,
    replay: replay.details,
    denied: denied.details,
    pending: pending.details,
    pendingReplay: pendingReplay.details,
    cancelled: cancelled.details,
    cancelReplay: cancelReplay.details,
  })}\n`,
);
