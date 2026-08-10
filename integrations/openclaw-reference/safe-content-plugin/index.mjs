import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { jsonResult } from "openclaw/plugin-sdk/tool-results";

export const MASUGATE_REFERENCE_CONTENT_TOOL = "masugate_reference_content";

const BASE_URL = "http://safe-content:8080";
const DOCUMENTS = Object.freeze({
  procurement: "/reference/procurement",
  travel: "/reference/travel",
});

function record(value, location) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${location} must be an object`);
  }
  return value;
}

function exactKeys(value, expected, location) {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${location} has an undeclared key`);
  }
}

export function parseReferenceContentConfig(value) {
  const config = record(value, "reference-content plugin config");
  exactKeys(config, ["safeContentBaseUrl", "documents"], "reference-content plugin config");
  if (config.safeContentBaseUrl !== BASE_URL) {
    throw new Error("reference-content plugin must use the fixed safe-content endpoint");
  }
  const documents = record(config.documents, "reference-content plugin documents");
  exactKeys(documents, Object.keys(DOCUMENTS), "reference-content plugin documents");
  for (const [name, path] of Object.entries(DOCUMENTS)) {
    if (documents[name] !== path) {
      throw new Error(`reference-content plugin document ${name} is not the fixed bounded path`);
    }
  }
  return Object.freeze({ baseUrl: BASE_URL, documents: DOCUMENTS });
}

function parseInput(value) {
  const input = record(value, "reference-content tool input");
  exactKeys(input, ["document"], "reference-content tool input");
  if (input.document !== "procurement" && input.document !== "travel") {
    throw new Error("reference-content tool document must be one bounded document");
  }
  return input.document;
}

function createTool(config, fetchImpl) {
  return {
    name: MASUGATE_REFERENCE_CONTENT_TOOL,
    label: "MasuGate reference content",
    description:
      "Read one fixed, non-consequential document from the reference safe-content service. This tool accepts no URL, host, or network option.",
    parameters: {
      type: "object",
      additionalProperties: false,
      required: ["document"],
      properties: {
        document: { enum: ["procurement", "travel"] },
      },
    },
    async execute(_toolCallId, rawInput, signal) {
      const document = parseInput(rawInput);
      const response = await fetchImpl(`${config.baseUrl}${config.documents[document]}`, {
        method: "GET",
        redirect: "error",
        signal,
      });
      if (!response.ok) {
        throw new Error(`safe-content service rejected ${document}: ${response.status}`);
      }
      const contentType = response.headers.get("content-type") ?? "";
      if (!contentType.startsWith("text/plain")) {
        throw new Error("safe-content service must return text/plain");
      }
      const content = await response.text();
      if (content.length === 0 || content.length > 4096) {
        throw new Error("safe-content response has an invalid bounded size");
      }
      return jsonResult({ document, content });
    },
  };
}

export function createReferenceSafeContentPlugin(options = {}) {
  return definePluginEntry({
    id: "masugate-reference-content",
    name: "MasuGate reference content",
    description: "Deployment-owned bounded content tool for the MasuGate OpenClaw reference profile.",
    register(api) {
      const config = parseReferenceContentConfig(api.pluginConfig);
      api.registerTool(() => createTool(config, options.fetchImpl ?? globalThis.fetch), {
        name: MASUGATE_REFERENCE_CONTENT_TOOL,
        optional: true,
      });
    },
  });
}

export default createReferenceSafeContentPlugin();
