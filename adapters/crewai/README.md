# `masugate-crewai`

> Current reference-release claims and exclusions: [Claims and limitations](../../docs/claims-and-limitations.md).

`masugate-crewai` is a replacement-only MasuGate binding for the exact
`crewai==1.15.6` and `crewai-core==1.15.6` artifacts. It generates MasuGate-owned
CrewAI `BaseTool` replacements from a governed-route manifest; it neither
wraps nor calls a native consequential tool.

CrewAI 1.15.6 does not make a per-tool-call ID available to `BaseTool._run`.
The bounded profile instead combines the deployment-owned principal, crew id,
and crew generation with CrewAI's active `Task.id` and the generated tool
name. A retry or resume of that task/tool pair therefore replays one MasuGate
operation. Changed arguments conflict in MasuGate. A task may issue only one
logical call to each governed tool: use a distinct CrewAI task for a second
intended call to the same tool. This is an exact-artifact behavior profile,
not a compatibility promise for another CrewAI release or for arbitrary tool
call patterns.

Install the verified CrewAI wheel first, then the adapter:

```bash
pip install --no-deps --require-hashes -r requirements.txt
pip install masugate-crewai
```

The deployment supplies the trusted context while constructing the toolset;
none of its fields are tool arguments. Register only the generated tools for
their governed names, then verify the list that will be given to the CrewAI
agent or task.

```python
from crewai import Agent, Crew
from masugate_crewai import CrewAITrustedContext, create_crewai_governed_toolset

context = CrewAITrustedContext(
    principal_id="buyer:42",
    crew_id="deployment-crew-7",
    crew_generation="deployment-issued-generation-3",
)
toolset = create_crewai_governed_toolset(
    masugate_client,
    governed_route_manifest,
    context,
)
tools = list(toolset.tools)
toolset.validate_complete_mediation(tools)
agent = Agent(
    role="Buyer",
    goal="Purchase approved goods",
    backstory="Uses only deployment-registered tools.",
    tools=tools,
)
```

The generated tools disable CrewAI's result cache so a retry always re-enters
MasuGate instead of returning a cached lifecycle. They require an active CrewAI
task; direct `BaseTool.run()` outside that context fails closed. CrewAI
before/after hooks may observe or detect bypasses, but are not an
authorization path and never execute an effect for this profile.

CrewAI checkpoints serialize generated tool models but omit their private MasuGate
bindings. After `Crew.from_checkpoint(...)`, construct a fresh toolset from the
same deployment-owned context and reattach it before the crew resumes. The
helper replaces only restored MasuGate-generated tools and keeps each restored
`Task.id`, which preserves the task/tool MasuGate replay identity. Validate the
tool list again after reattachment; a raw same-named tool remains a mediation
error rather than being silently converted.

```python
from masugate_crewai import reattach_restored_crewai_tools

restored_crew = Crew.from_checkpoint(checkpoint_config)
restarted_toolset = create_crewai_governed_toolset(
    masugate_client,
    governed_route_manifest,
    context,
)
reattach_restored_crewai_tools(restored_crew, restarted_toolset)
for task in restored_crew.tasks:
    restarted_toolset.validate_complete_mediation(task.tools)
```

For a `pending` result, the replacement returns a normal `masugate.lifecycle.v1`
object with the exact MasuGate locator. Application UI may present it, but it must
not interpret a CrewAI hook or human response as a MasuGate decision. After a
separately authorized MasuGate resolution, the application may re-read the same
locator without passing an approval value:

```python
latest = await toolset.resume_pending(pending_lifecycle["locator"])
```

The exact-artifact profile and upgrade gate are recorded in
[the CrewAI adapter profile](../../docs/adapters/crewai.md).

```bash
PYTHONPATH=src:clients/python/src:adapters/python/src:adapters/crewai/src \
  .venv/bin/python -m pytest adapters/crewai/tests
```
