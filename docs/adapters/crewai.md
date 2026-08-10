# CrewAI adapter profile

`masugate-crewai` supports the bounded `crewai==1.15.6` artifact recorded in
its package metadata and hash-pinned `requirements.txt`. This is a tested
research-artifact compatibility boundary, not support for other CrewAI
versions or arbitrary CrewAI applications.

The adapter creates MasuGate-owned `BaseTool` replacements from a governed
route manifest. Generated tool execution re-enters the governed runtime; it
does not call a consequential native-tool path or treat a CrewAI hook as an
approval. The adapter disables tool-result caching so retries re-read the
authoritative lifecycle.

Trusted context supplies the principal, crew identity, crew generation, and
source namespace outside model-provided arguments. A governed tool has one
logical invocation per active `Task.id`: a retry of the same task/tool pair
replays the original operation, while changed arguments fail closed. A
workflow that needs two independent calls to one governed tool must use
distinct tasks.

Checkpoint restoration requires a newly constructed toolset and explicit
`reattach_restored_crewai_tools` before resuming. A pending lifecycle remains
a MasuGate lifecycle record with its original locator; resolving it is a
separate governed operation, not a CrewAI approval mechanism.

Run the package tests in
[`adapters/crewai/tests/test_crewai_runtime.py`](../../adapters/crewai/tests/test_crewai_runtime.py)
with the exact package pins. The tests cover generated tool construction,
retry and changed-content conflict, complete mediation, checkpoint
reattachment, pending re-query, and the shared adapter conformance path.

Version: `0.1.0` (research preview). Next: [Framework adapters](../framework-adapters.md).
