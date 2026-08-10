"""Strict wire-model checks for the Governed Action Protocol boundary."""

from __future__ import annotations

import json
from typing import Any, cast

import httpx
import pytest
from masugate_client import canonical_adapter_envelope, create_adapter_invocation
from pydantic import ValidationError

from masugate.coordinator import AsyncGovernedCoordinator
from masugate.model import DecisionEffect, OperationResult, PolicyDecision
from masugate.masugated.app import ActionBody, ActionOwnerBinding, ResolveBody, create_app
from masugate.provider_assembly import EffectExecutionPosition


@pytest.mark.parametrize("approved", ["yes", "false", "no", 1, 0, 1.0])
def test_resolution_approval_rejects_coercible_non_boole(approved: object) -> None:
    with pytest.raises(ValidationError):
        ResolveBody.model_validate({"approved": approved})


def test_action_scalars_reject_float_to_bool_or_int_coercion() -> None:
    with pytest.raises(ValidationError):
        ActionBody.model_validate(
            {
                "action": "transfer",
                "args": {"amount_cents": 1.0},
                "idempotency_key": "logical-call-1",
            }
        )


@pytest.mark.parametrize("amount", [9_007_199_254_740_992, -9_007_199_254_740_992])
def test_action_scalars_reject_unsafe_integers(amount: int) -> None:
    with pytest.raises(ValidationError, match="JavaScript-safe integer"):
        ActionBody.model_validate(
            {
                "action": "transfer",
                "args": {"amount_cents": amount},
                "idempotency_key": "logical-call-1",
            }
        )


async def test_action_endpoint_rejects_unsafe_integer_arguments() -> None:
    app = create_app(cast(Any, object()), cast(Any, object()), {"agent-token": "openclaw:a"})
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://masugated.test",
    ) as client:
        response = await client.post(
            "/v1/actions",
            headers={"Authorization": "Bearer agent-token"},
            json={
                "action": "transfer",
                "args": {"amount_cents": 9_007_199_254_740_992},
                "idempotency_key": "logical-call-1",
            },
        )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_request"


def test_json_evidence_preserves_numeric_and_boolean_types() -> None:
    body = ResolveBody.model_validate(
        {
            "approved": True,
            "evidence": {"score": 1.0, "attempt": 1, "reviewed": False},
        }
    )

    assert type(body.evidence["score"]) is float
    assert type(body.evidence["attempt"]) is int
    assert type(body.evidence["reviewed"]) is bool


def test_app_rejects_empty_token_configuration_at_startup() -> None:
    with pytest.raises(ValueError, match="bearer tokens"):
        create_app(cast(Any, object()), cast(Any, object()), {"": "agent"})


async def test_empty_bearer_header_is_never_authenticated() -> None:
    app = create_app(cast(Any, object()), cast(Any, object()), {})
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://masugated.test",
    ) as client:
        response = await client.get(
            "/v1/pending",
            headers={"Authorization": "Bearer "},
        )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"


async def test_expected_principal_mismatch_fails_before_execution() -> None:
    app = create_app(cast(Any, object()), cast(Any, object()), {"agent-token": "openclaw:a"})
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://masugated.test",
    ) as client:
        response = await client.post(
            "/v1/actions",
            headers={
                "Authorization": "Bearer agent-token",
                "MasuGate-Expected-Principal": "openclaw:b",
            },
            json={
                "action": "spend.purchase",
                "args": {"amount_cents": 1},
                "idempotency_key": "call-1",
            },
        )

    assert response.status_code == 401
    assert response.json()["error"] == {
        "code": "unauthorized",
        "message": "bearer token principal does not match expected principal",
    }


async def test_expected_action_owner_is_server_certified_before_execution() -> None:
    app = create_app(
        cast(Any, object()),
        cast(Any, object()),
        {"agent-token": "openclaw:a"},
        action_owners={
            "spend.purchase": ActionOwnerBinding(
                provider_id="spend-v1",
                position=EffectExecutionPosition.PROTECTED_EXTERNAL,
                connector_id="purchase-v1",
            )
        },
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://masugated.test",
    ) as client:
        response = await client.post(
            "/v1/actions",
            headers={
                "Authorization": "Bearer agent-token",
                "MasuGate-Expected-Provider": "attacker-provider",
                "MasuGate-Expected-Position": "protected-external",
                "MasuGate-Expected-Connector": "purchase-v1",
            },
            json={
                "action": "spend.purchase",
                "args": {"amount_cents": 1},
                "idempotency_key": "call-owner-mismatch",
            },
        )

    assert response.status_code == 409
    assert response.json()["error"]["message"] == "action execution owner mismatch: spend.purchase"


async def test_action_assertion_principals_preserve_header_only_adapter_integration_contract() -> (
    None
):
    class Coordinator:
        async def execute(self, request: Any) -> OperationResult:
            return OperationResult(
                operation_id=request.operation_id,
                decision=PolicyDecision(
                    effect=DecisionEffect.ALLOW,
                    policy_id="test",
                    policy_version="v1",
                    rule_id="allow",
                    reason="test",
                ),
                committed=True,
            )

    owner = ActionOwnerBinding(
        provider_id="spend-v1",
        position=EffectExecutionPosition.PROTECTED_EXTERNAL,
        connector_id="purchase-v1",
    )
    app = create_app(
        cast(AsyncGovernedCoordinator, Coordinator()),
        cast(Any, object()),
        {"agent-token": "openclaw:a"},
        action_owners={"spend.purchase": owner},
        action_assertion_principals={"openclaw:a"},
    )
    headers = {
        "Authorization": "Bearer agent-token",
        "MasuGate-Expected-Principal": "openclaw:a",
        "MasuGate-Expected-Provider": "spend-v1",
        "MasuGate-Expected-Position": "protected-external",
        "MasuGate-Expected-Connector": "purchase-v1",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://masugated.test",
    ) as client:
        response = await client.post(
            "/v1/actions",
            headers=headers,
            json={
                "action": "spend.purchase",
                "args": {"amount_cents": 1},
                "idempotency_key": "call-adapter-integration-contract",
            },
        )

    assert response.status_code == 200
    with pytest.raises(ValueError, match="must be disjoint"):
        create_app(
            cast(AsyncGovernedCoordinator, Coordinator()),
            cast(Any, object()),
            {"agent-token": "openclaw:a"},
            action_assertion_principals={"openclaw:a"},
            adapter_invocation_principals={"openclaw:a"},
        )


async def test_required_adapter_assertions_cannot_be_stripped() -> None:
    app = create_app(
        cast(Any, object()),
        cast(Any, object()),
        {"agent-token": "openclaw:a"},
        action_owners={
            "spend.purchase": ActionOwnerBinding(
                provider_id="spend-v1",
                position=EffectExecutionPosition.PROTECTED_EXTERNAL,
                connector_id="purchase-v1",
            )
        },
        adapter_invocation_principals={"openclaw:a"},
    )
    body = {
        "action": "spend.purchase",
        "args": {"amount_cents": 1},
        "idempotency_key": "call-stripped",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://masugated.test",
    ) as client:
        no_assertions = await client.post(
            "/v1/actions",
            headers={"Authorization": "Bearer agent-token"},
            json=body,
        )
        owner_stripped = await client.post(
            "/v1/actions",
            headers={
                "Authorization": "Bearer agent-token",
                "MasuGate-Expected-Principal": "openclaw:a",
            },
            json=body,
        )
        adapter_stripped = await client.post(
            "/v1/actions",
            headers={
                "Authorization": "Bearer agent-token",
                "MasuGate-Expected-Principal": "openclaw:a",
                "MasuGate-Expected-Provider": "spend-v1",
                "MasuGate-Expected-Position": "protected-external",
                "MasuGate-Expected-Connector": "purchase-v1",
            },
            json=body,
        )

    assert no_assertions.status_code == 401
    assert no_assertions.json()["error"]["message"] == (
        "missing required expected principal assertion"
    )
    assert owner_stripped.status_code == 400
    assert owner_stripped.json()["error"]["message"] == (
        "missing required adapter invocation assertion"
    )
    assert adapter_stripped.status_code == 400
    assert adapter_stripped.json()["error"] == {
        "code": "invalid_request",
        "message": "missing required adapter invocation assertion",
    }


async def test_adapter_assertion_uses_the_normative_envelope_constraints() -> None:
    class Coordinator:
        async def execute(self, request: Any) -> OperationResult:
            return OperationResult(
                operation_id=request.operation_id,
                decision=PolicyDecision(
                    effect=DecisionEffect.ALLOW,
                    policy_id="test",
                    policy_version="v1",
                    rule_id="allow",
                    reason="test",
                ),
                committed=True,
            )

    app = create_app(
        cast(AsyncGovernedCoordinator, Coordinator()),
        cast(Any, object()),
        {"agent-token": "openclaw:a"},
        action_owners={
            "spend.purchase": ActionOwnerBinding(
                provider_id="spend-v1",
                position=EffectExecutionPosition.PROTECTED_EXTERNAL,
                connector_id="purchase-v1",
            )
        },
        adapter_invocation_principals={"openclaw:a"},
    )
    body = {
        "action": "spend.purchase",
        "args": {"amount_cents": 1},
        "idempotency_key": "call-invalid-envelope",
    }
    canonical = canonical_adapter_envelope(
        create_adapter_invocation(
            {
                "principal": {"id": "openclaw:a"},
                "source": {"namespace": "openclaw", "id": "call-1"},
                "adapter": {
                    "id": "masugate.openclaw",
                    "contract_version": "masugate.host-adapter.v1",
                    "capabilities": ["cancellation", "receipt"],
                },
                "action": {"name": "spend.purchase", "arguments": {"amount_cents": 1}},
            }
        )
    )
    envelope = json.loads(canonical)
    long_identifier = json.loads(canonical)
    long_identifier["adapter"]["id"] = "a" * 257
    reserved_argument = json.loads(canonical)
    reserved_argument["action"]["arguments"] = {"principal_id": 1}
    unsorted_capabilities = json.loads(canonical)
    unsorted_capabilities["adapter"]["capabilities"] = ["receipt", "cancellation"]
    headers = {
        "Authorization": "Bearer agent-token",
        "MasuGate-Expected-Principal": "openclaw:a",
        "MasuGate-Expected-Provider": "spend-v1",
        "MasuGate-Expected-Position": "protected-external",
        "MasuGate-Expected-Connector": "purchase-v1",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://masugated.test",
    ) as client:
        accepted_body = {
            **body,
            "adapter_invocation": json.dumps(envelope, separators=(",", ":"), sort_keys=True),
        }
        accepted_shape = await client.post(
            "/v1/actions",
            headers=headers,
            json=accepted_body,
        )
        long_rejected = await client.post(
            "/v1/actions",
            headers=headers,
            json={
                **body,
                "adapter_invocation": json.dumps(
                    long_identifier, separators=(",", ":"), sort_keys=True
                ),
            },
        )
        reserved_rejected = await client.post(
            "/v1/actions",
            headers=headers,
            json={
                **body,
                "args": {"principal_id": 1},
                "adapter_invocation": json.dumps(
                    reserved_argument, separators=(",", ":"), sort_keys=True
                ),
            },
        )
        unsorted_rejected = await client.post(
            "/v1/actions",
            headers=headers,
            json={
                **body,
                "adapter_invocation": json.dumps(
                    unsorted_capabilities, separators=(",", ":"), sort_keys=True
                ),
            },
        )

    # The valid envelope crosses the coordinator boundary, while every
    # malformed variant is stopped at the adapter boundary.
    assert accepted_shape.status_code == 200
    statuses = [
        long_rejected.status_code,
        reserved_rejected.status_code,
        unsorted_rejected.status_code,
    ]
    assert statuses == [400, 400, 400]
