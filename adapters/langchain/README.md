# `masugate-langchain`

> Current reference-release claims and exclusions: [Claims and limitations](../../docs/claims-and-limitations.md).

`masugate-langchain` is the pinned LangChain/LangGraph binding for the shared
MasuGate adapter runtime.  It supports LangChain `1.3.14` and LangGraph `1.2.9`.
It generates typed replacement tools from a MasuGate governed-route manifest; it
does not wrap or call a framework-native consequential implementation.

The deploying application supplies `LangGraphTrustedContext` through the
hidden LangChain `ToolRuntime.context` channel.  Its principal, durable graph
thread identifier, and thread generation are trusted deployment values.  The
adapter combines those values with LangChain's public `tool_call_id`, hashes
the canonical tuple, and submits that stable source identity to MasuGate.  Tool
arguments cannot provide or override any of those values.

```python
from langgraph.prebuilt import ToolNode
from masugate_langchain import LangGraphTrustedContext, create_langchain_governed_tools

tools = create_langchain_governed_tools(masugate_client, governed_route_manifest)
node = ToolNode(list(tools.values()))

context = LangGraphTrustedContext(
    principal_id="buyer:42",
    thread_id="purchase-thread-7",
    thread_generation="deployment-issued-generation-3",
)
# Invoke the LangGraph node with ``context=context``.  The model sees only the
# manifest's declared arguments; the context and injected ToolRuntime are not
# tool-schema fields.
```

When MasuGate reports `pending`, the replacement tool calls LangGraph
`interrupt()` with the exact MasuGate locator.  Resuming the graph does not approve
the operation: the adapter ignores the resume payload and re-reads the same
locator from MasuGate.  A terminal result therefore remains MasuGate-authoritative;
native LangChain/LangGraph HITL is presentation only.

The strong profile requires the deployment to register the generated MasuGate tool
instead of any raw consequential tool.  It does not claim to repair arbitrary
LangGraph state reducers or mediate effects exposed outside that tool set.

```bash
PYTHONPATH=src:clients/python/src:adapters/python/src:adapters/langchain/src \
  .venv/bin/python -m pytest adapters/langchain/tests
```
