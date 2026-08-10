# `masugate-agent-framework`

> Current reference-release claims and exclusions: [Claims and limitations](../../docs/claims-and-limitations.md).

`masugate-agent-framework` is a replacement-only MasuGate binding for the exact
`agent-framework-core==1.12.0` artifact. It creates typed MAF `FunctionTool`
replacements from a MasuGate governed-route manifest and a function middleware
that returns MasuGate's lifecycle without calling the generated tool's native path.

The profile relies on an **implementation-defined MAF ABI**: this exact
release writes the provider/model function call ID to
`FunctionInvocationContext.metadata["call_id"]` before function middleware
runs. The adapter combines that ID with deployment-owned principal, session,
and session-generation values to derive its stable MasuGate invocation identity.
It is not a compatibility promise for another MAF release or an assertion that
`metadata["call_id"]` is a supported public MAF API.

Install the verified MAF wheel first, then the package:

```bash
pip install --no-deps --require-hashes -r requirements.txt
pip install masugate-agent-framework
```

The profile must register only the generated tools and function middleware on a
MAF function-invoking chat client, plus `toolset.agent_middleware` on the
`Agent`. The agent middleware rejects a fabricated native MAF approval response
before MAF can turn it into a model-visible native rejection. The application
creates an `AgentSession` and passes the matching, deployment-owned
`MafTrustedContext` through `function_invocation_kwargs`; it is never a
model-visible tool argument.

```python
from agent_framework import Agent, AgentSession
from masugate_agent_framework import (
    TRUSTED_CONTEXT_KEY,
    MafTrustedContext,
    create_maf_governed_toolset,
)

toolset = create_maf_governed_toolset(masugate_client, governed_route_manifest)
session = AgentSession(session_id="deployment-issued-session-7")
# Construct the provider's MAF FunctionInvocationLayer client with
# ``middleware=[toolset.middleware]`` before creating the agent.
agent = Agent(
    client=maf_function_invoking_client,
    tools=toolset.tools,
    middleware=[toolset.agent_middleware],
)

context = MafTrustedContext(
    principal_id="buyer:42",
    session_id=session.session_id,
    session_generation="deployment-issued-generation-3",
)
result = await agent.run(
    "Purchase the approved item.",
    session=session,
    function_invocation_kwargs={TRUSTED_CONTEXT_KEY: context},
)
```

For a `pending` MasuGate result, middleware returns a normal MasuGate lifecycle result
whose locator can be presented by the application UI. It deliberately does
**not** emit MAF's `function_approval_request`, because MAF Core handles a
native `approved=False` response before function middleware can run. Do not
send `Content.to_function_approval_response()` to resume this profile.

After any separately authorized MasuGate resolution, re-query the exact locator
through the toolset instead. This operation has no approval boolean and only
reads MasuGate's current lifecycle; MasuGate remains the sole authority that can make
the operation terminal.

```python
# `pending_locator` is the `locator` in the returned MasuGate pending lifecycle.
latest = await toolset.resume_pending(session, context, pending_locator)
```

The original consequential function is not registered. A manually fabricated
MAF native approval response is outside this profile and must never be shown
as a MasuGate denial or approval.

Every MAF upgrade is blocked until the artifact lock, this adapter's real-host
tests, the shared conformance suite, and the documented retry, locator-requery,
and restored-session behavior all pass again. If any one fails, deployments
must stay on the verified artifact or disable this profile rather than silently
using the newer MAF runtime.

```bash
PYTHONPATH=src:clients/python/src:adapters/python/src:adapters/agent-framework/src \
  .venv/bin/python -m pytest adapters/agent-framework/tests
```
