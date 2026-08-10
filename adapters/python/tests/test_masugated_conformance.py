"""Adapter-core conformance against the real public ``masugated`` ASGI boundary."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from masugate.errors import ResourceError
from masugate.model import ActionRequest, DecisionEffect, OperationResult, PolicyDecision
from masugate.masugated import ActionOwnerBinding, create_app
from masugate.provider_assembly import EffectExecutionPosition
from masugate_client import MasuGateAPIError, MasuGateClient

from masugate_adapter_core import (
    create_adapter_core_conformance_runtime,
    load_adapter_core_conformance_fixture,
)

FIXTURE_PATH = Path(__file__).parents[3] / "protocol" / "examples" / "adapter-core-conformance.json"
FIXTURE = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


class _Coordinator:
    def __init__(self) -> None:
        self.calls = 0
        self.results: dict[str, OperationResult] = {}
        self.bindings: dict[str, tuple[object, ...]] = {}

    async def execute(self, request: ActionRequest) -> OperationResult:
        binding = (
            request.principal.id,
            request.action,
            tuple(sorted(request.arguments.items())),
            request.adapter_invocation_digest,
        )
        previous = self.bindings.setdefault(request.idempotency_key, binding)
        if previous != binding:
            raise ResourceError("idempotency key is already bound to a different request")
        existing = self.results.get(request.idempotency_key)
        if existing is not None:
            return replace(existing, replayed=True)
        self.calls += 1
        result = OperationResult(
            operation_id=request.operation_id,
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
        self.results[request.idempotency_key] = result
        return result


async def test_conformance_runtime_uses_real_masugated_once_per_logical_action() -> None:
    coordinator = _Coordinator()
    app = create_app(
        coordinator,  # type: ignore[arg-type]
        cast(Any, object()),
        {"adapter-token": "adapter:buyer"},
        action_owners={
            "spend.purchase": ActionOwnerBinding(
                provider_id="spend-v1",
                position=EffectExecutionPosition.PROTECTED_EXTERNAL,
                connector_id="purchase-v1",
            )
        },
        adapter_invocation_principals={"adapter:buyer"},
    )
    async with MasuGateClient(
        "http://masugated.test",
        "adapter-token",
        principal_id="adapter:buyer",
        transport=httpx.ASGITransport(app=app),
    ) as client:
        fixture = load_adapter_core_conformance_fixture()
        runtime = create_adapter_core_conformance_runtime(client, fixture)
        arguments = cast(dict[str, object], FIXTURE["model_arguments"])
        with pytest.raises(MasuGateAPIError) as stripped:
            await client.execute(
                "spend.purchase",
                cast(dict[str, str | bool | int], arguments),
                "adapter:strict-body-stripped",
                owner=runtime.routes.select("purchase").owner,
            )
        first = await runtime.invoke("purchase", arguments)
        replay = await runtime.invoke("purchase", arguments)
        recreated = create_adapter_core_conformance_runtime(client, fixture)
        with pytest.raises(MasuGateAPIError) as conflict:
            await recreated.invoke("purchase", {**arguments, "amount_cents": 1251})

    assert first.status == "committed"
    assert stripped.value.status_code == 400
    assert stripped.value.code == "invalid_request"
    assert replay.result.replayed is True
    assert replay.result.operation_id == first.result.operation_id
    assert coordinator.calls == 1
    assert conflict.value.status_code == 409
    assert conflict.value.code == "resource_conflict"


async def test_conformance_runtime_rejects_untrusted_bearer_principal() -> None:
    coordinator = _Coordinator()
    app = create_app(
        coordinator,  # type: ignore[arg-type]
        cast(Any, object()),
        {"wrong-token": "adapter:other"},
        action_owners={
            "spend.purchase": ActionOwnerBinding(
                provider_id="spend-v1",
                position=EffectExecutionPosition.PROTECTED_EXTERNAL,
                connector_id="purchase-v1",
            )
        },
        adapter_invocation_principals={"adapter:other"},
    )
    async with MasuGateClient(
        "http://masugated.test",
        "wrong-token",
        transport=httpx.ASGITransport(app=app),
    ) as client:
        runtime = create_adapter_core_conformance_runtime(client)
        with pytest.raises(MasuGateAPIError) as rejected:
            await runtime.invoke("purchase", cast(dict[str, object], FIXTURE["model_arguments"]))

    assert rejected.value.status_code == 401
    assert rejected.value.code == "unauthorized"
    assert coordinator.calls == 0
