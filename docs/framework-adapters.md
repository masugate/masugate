# Framework adapters

**Audience:** application developers and artifact reviewers. Start with
[Architecture](architecture.md) and the package README linked below. These are
replacement-only, exact-version research profiles: generated MasuGate tools
must replace the consequential framework tools rather than wrap or coexist
with them.

## Supported profiles

| Profile | Package | Exact host boundary | Executable example |
|---|---|---|---|
| Shared adapter runtime | `masugate-adapter-core` | MasuGate client plus a deployment-owned trusted invocation | [Conformance kit](../adapters/python/README.md#conformance-kit) |
| LangChain and LangGraph | `masugate-langchain` | LangChain `1.3.14`; LangGraph `1.2.9` | [Generated `ToolNode` tools](../adapters/langchain/README.md) |
| Microsoft Agent Framework | `masugate-agent-framework` | Agent Framework Core `1.12.0` | [Generated function toolset](../adapters/agent-framework/README.md) |
| CrewAI | `masugate-crewai` | CrewAI and CrewAI Core `1.15.6` | [Generated `BaseTool` toolset](../adapters/crewai/README.md) |
| MCP and OpenClaw | `@masugate/mcp-gateway`; `@masugate/openclaw` | stdio MCP; OpenClaw `2026.7.1` | [Gateway README](../gateway/README.md) and [OpenClaw README](../integrations/openclaw/README.md) |

The package catalog and compatibility matrix list every release artifact and
format: [`release/package-catalog.json`](../release/package-catalog.json) and
[`release/compatibility-matrix.json`](../release/compatibility-matrix.json).
They are release metadata, not an authorization to upload packages.

## Installation boundary

From a prepared local release directory, install the exact wheel set selected
for the profile and its declared dependencies. For example, the shared adapter
runtime uses the client and core wheels:

```sh
python -m pip install --no-index --no-deps \
  /path/to/release/python/masugate-client/masugate_client-0.1.1-py3-none-any.whl \
  /path/to/release/python/masugate-adapter-core/masugate_adapter_core-0.1.1-py3-none-any.whl
```

Install the verified framework runtime separately before its adapter package.
The `requirements.txt` file in each framework adapter records the exact
framework input where one is required. Do not substitute a newer framework
version or use an arbitrary native consequential tool; those cases are outside
the tested boundary.

## Trusted context is deployment-owned

Each binding takes trusted identity and replay context from the integration
host, never from a model-visible tool argument. In particular:

- LangChain/LangGraph uses `LangGraphTrustedContext` with a principal and graph
  thread generation.
- Agent Framework uses `MafTrustedContext` with a principal and session
  generation.
- CrewAI uses `CrewAITrustedContext` with a principal and crew generation.

Each linked package README constructs that context and registers only the
generated MasuGate tools. A pending lifecycle result is not a framework-level
approval: resolve it through MasuGate, then re-read the exact MasuGate
locator as documented by the adapter.

Version: `0.1.1` (research preview). Next:
[Connectors](connectors.md).
