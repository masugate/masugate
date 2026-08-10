"""Small real-``masugated`` process used by the TypeScript adapter-core conformance test.

It deliberately supplies only a deterministic coordinator fixture.  The HTTP
service, authenticated action assertions, request parsing, and replay boundary
are the actual production ``masugated`` implementation rather than a Node mock.
"""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import replace
from typing import Any, cast

import uvicorn

from masugate.errors import ResourceError
from masugate.model import ActionRequest, DecisionEffect, OperationResult, PolicyDecision
from masugate.masugated import ActionOwnerBinding, create_app
from masugate.provider_assembly import EffectExecutionPosition


class _Coordinator:
    def __init__(self) -> None:
        self.calls = 0
        self._bindings: dict[str, tuple[object, ...]] = {}
        self._results: dict[str, OperationResult] = {}

    async def execute(self, request: ActionRequest) -> OperationResult:
        binding = (
            request.principal.id,
            request.action,
            tuple(sorted(request.arguments.items())),
            request.adapter_invocation_digest,
        )
        previous = self._bindings.setdefault(request.idempotency_key, binding)
        if previous != binding:
            raise ResourceError("idempotency key is already bound to a different request")
        existing = self._results.get(request.idempotency_key)
        if existing is not None:
            return replace(existing, replayed=True)
        self.calls += 1
        result = OperationResult(
            operation_id=f"00000000-0000-4000-8000-{self.calls:012d}",
            decision=PolicyDecision(
                effect=DecisionEffect.ALLOW,
                policy_id="adapter-core-conformance",
                policy_version="v1",
                rule_id="allow",
                reason="real masugated fixture",
            ),
            committed=True,
            payload={"effect_count": self.calls},
        )
        self._results[request.idempotency_key] = result
        return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    app = create_app(
        _Coordinator(),  # type: ignore[arg-type]
        cast(Any, object()),
        {"adapter-token": "adapter:buyer", "wrong-token": "adapter:other"},
        action_owners={
            "spend.purchase": ActionOwnerBinding(
                provider_id="spend-v1",
                position=EffectExecutionPosition.PROTECTED_EXTERNAL,
                connector_id="purchase-v1",
            )
        },
        adapter_invocation_principals={"adapter:buyer", "adapter:other"},
    )
    config = uvicorn.Config(app, host="127.0.0.1", port=args.port, log_level="warning")
    asyncio.run(uvicorn.Server(config).serve())


if __name__ == "__main__":  # pragma: no cover - driven from the Node test process.
    main()
