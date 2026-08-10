# Reusing the protocol contract suite

Provide a `ContractTransport` that sends black-box HTTP requests plus
`ContractCases` whose first action commits and whose second action is denied by
the target's configured policy. Then await `run_contract_suite(transport,
cases)`. The suite imports no `masugated` internals and can therefore exercise any
HTTP implementation of the Governed Action Protocol.

The MCP gateway is a different wire surface (`tools/list` / `tools/call` rather
than these HTTP paths), so it has its own MCP contract suite under `gateway/`.
Those tests still assert the same semantic invariants: governed effects enter
through `masugated`, committed provider payloads are never treated as detached
allow tokens, and deny/pending outcomes remain machine-readable.
