"""End-to-end ``masugated`` HTTP tests (steps 1.2--1.4).

These use HTTPX's ASGI transport but a real PostgreSQL provider: the boundary,
coordinator, durable idempotency, pending lifecycle, audit record, and effects
all run exactly as they do behind uvicorn.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from masugate.contracts import ContractRegistry
from masugate.coordinator import AsyncGovernedCoordinator
from masugate.language import PolicyCompiler, parse_policy
from masugate.model import ActionRequest, Principal, MasuGateMode, Scalar, TypeName
from masugate.policy import AsyncPolicyRuntime, PolicySet
from masugate.principals import PrincipalRegistry
from masugate.masugated import ActionOwnerBinding, create_app
from masugate.provider_assembly import EffectExecutionPosition
from masugate.resources.postgres import AsyncPostgresLedger

pytestmark = pytest.mark.postgres

TRANSACTION_POLICY = """
policy transaction_guard on transfer {
  deny insufficient_funds when
    accounts.balance(principal.id) < args.amount_cents;
  deny daily_team_budget when
    ledger.sum_sent_by_team(principal.team, 24h) + args.amount_cents > 100000;
  allow otherwise;
}
"""

SCOPED_HOLD_POLICY = """
policy approval_guard on transfer {
  deny insufficient_funds when
    accounts.balance(principal.id) < args.amount_cents;
  deny daily_team_budget when
    ledger.sum_sent_by_team(principal.team, 24h) + args.amount_cents > 100000;
  escalate needs_approval when args.amount_cents > 4000;
  allow otherwise;
}
"""

RESERVATION_POLICY = """
policy reservation_approval_guard on transfer {
  deny daily_team_budget when
    args.amount_cents > ledger.available_team_budget(principal.team, 24h);
  escalate needs_approval when args.amount_cents > 4000;
  allow otherwise;
}
"""

PRINCIPALS: dict[str, dict[str, Scalar]] = {
    "alice": {"team": "research"},
    "bob": {"team": "research"},
    "operator": {"team": "operations", "masugate_operator": True},
    "openclaw:agent-alpha": {"team": "research"},
}
TOKENS = {
    "alice-token": "alice",
    "bob-token": "bob",
    "operator-token": "operator",
}


def _stack(
    ledger: AsyncPostgresLedger,
    policy: str,
    mode: MasuGateMode,
    *,
    token_principals: dict[str, str] | None = None,
    action_owners: dict[str, ActionOwnerBinding] | None = None,
    action_assertion_principals: set[str] | None = None,
    adapter_invocation_principals: set[str] | None = None,
) -> tuple[AsyncGovernedCoordinator, Any]:
    registry = ContractRegistry()
    ledger.install_contracts(registry)
    policies = PolicySet()
    compiler = PolicyCompiler(registry, {"team": TypeName.STRING})
    policies.add(compiler.compile(parse_policy(policy)))
    coordinator = AsyncGovernedCoordinator(
        registry,
        AsyncPolicyRuntime(registry, policies),
        ledger,
        PrincipalRegistry(PRINCIPALS),
        mode=mode,
    )
    return coordinator, create_app(
        coordinator,
        ledger,
        TOKENS if token_principals is None else token_principals,
        operator_principals={"operator"},
        action_owners=action_owners,
        action_assertion_principals=action_assertion_principals or set(),
        adapter_invocation_principals=adapter_invocation_principals or set(),
    )


def _auth(token: str = "alice-token") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _action(key: str, *, amount: int, receiver: str = "receiver") -> dict[str, Any]:
    return {
        "action": "transfer",
        "args": {"receiver_id": receiver, "amount_cents": amount},
        "idempotency_key": key,
        "trace_id": f"trace-{key}",
    }


def _adapter_invocation(
    *,
    principal_id: str,
    adapter_id: str = "masugate.adapter.test",
    amount: int = 1_000,
    receiver: str = "receiver",
) -> str:
    """Canonical enough ASCII fixture for the server's adapter assertion boundary."""

    return json.dumps(
        {
            "action": {
                "arguments": {"amount_cents": amount, "receiver_id": receiver},
                "name": "transfer",
            },
            "adapter": {
                "capabilities": [],
                "contract_version": "masugate.host-adapter.v1",
                "id": adapter_id,
            },
            "principal": {"id": principal_id},
            "source": {"id": "call-001", "namespace": "adapter-test"},
        },
        separators=(",", ":"),
        sort_keys=True,
    )


async def _seed(ledger: AsyncPostgresLedger, spent: int) -> None:
    for account_id, team, balance in (
        ("seed", "research", 500_000),
        ("sink", "external", 0),
        ("alice", "research", 100_000),
        ("bob", "research", 100_000),
        ("receiver", "external", 0),
        ("receiver-b", "external", 0),
    ):
        await ledger.create_account(account_id, team, balance)
    if spent:
        request = ActionRequest(
            operation_id="seed-operation",
            idempotency_key="seed-operation",
            principal=Principal(id="seed", attributes={"team": "research"}),
            action="transfer",
            arguments={"receiver_id": "sink", "amount_cents": spent},
        )
        async with ledger.open_session(write=True) as session:
            await ledger.acquire_scoped_locks(
                session,
                ledger.transfer_footprint(request).all_scopes,
            )
            await ledger.execute_transfer(session, request)


async def test_actions_commit_deny_idempotency_and_audit(
    pg_ledger: AsyncPostgresLedger,
) -> None:
    await _seed(pg_ledger, 90_000)
    _coordinator, app = _stack(pg_ledger, TRANSACTION_POLICY, MasuGateMode.TRANSACTION)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://masugated.test",
    ) as client:
        body = _action("stable-step-1", amount=1_000)
        first = await client.post("/v1/actions", json=body, headers=_auth())
        assert first.status_code == 200, first.text
        committed = first.json()
        assert committed["status"] == "committed"
        assert committed["decision"]["effect"] == "allow"
        assert committed["audit_ref"].endswith(committed["operation_id"])
        assert not committed["replayed"]

        # The server generates a fresh candidate operation id, but durable
        # idempotency returns the original result and executes the effect once.
        replay = await client.post("/v1/actions", json=body, headers=_auth())
        assert replay.status_code == 200
        replayed = replay.json()
        assert replayed["operation_id"] == committed["operation_id"]
        assert replayed["replayed"] is True
        async with pg_ledger.open_session(write=False) as session:
            receiver_balance, _version = await pg_ledger.balance_view(session, "receiver")
        assert receiver_balance == 1_000

        receipt_response = await client.get(committed["audit_ref"], headers=_auth())
        assert receipt_response.status_code == 200
        receipt = receipt_response.json()
        assert receipt["policy"]["policy_id"] == committed["decision"]["policy_id"]
        assert receipt["decision"]["rule_id"] == committed["decision"]["rule_id"]
        assert receipt["effect"]["action"] == "transfer"
        budget_read = next(
            read for read in receipt["view_reads"] if read["function"] == "ledger.sum_sent_by_team"
        )
        assert budget_read["value"] == 90_000
        assert budget_read["scope"] == "team-budget:research"
        assert isinstance(budget_read["version"], int)

        denied_response = await client.post(
            "/v1/actions",
            json=_action("over-budget", amount=20_000),
            headers=_auth(),
        )
        assert denied_response.status_code == 200
        denied = denied_response.json()
        assert denied["status"] == "denied"
        assert denied["decision"]["effect"] == "deny"
        assert denied["decision"]["rule_id"] == "daily_team_budget"
        denied_receipt = (await client.get(denied["audit_ref"], headers=_auth())).json()
        assert denied_receipt["effect"] is None


async def test_idempotency_is_principal_scoped_and_rejects_request_drift(
    pg_ledger: AsyncPostgresLedger,
) -> None:
    await _seed(pg_ledger, 0)
    _coordinator, app = _stack(pg_ledger, TRANSACTION_POLICY, MasuGateMode.TRANSACTION)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://masugated.test",
    ) as client:
        shared_key = "shared-caller-key"
        alice = await client.post(
            "/v1/actions",
            json=_action(shared_key, amount=1_000),
            headers=_auth("alice-token"),
        )
        bob = await client.post(
            "/v1/actions",
            json=_action(shared_key, amount=2_000, receiver="receiver-b"),
            headers=_auth("bob-token"),
        )

        assert alice.status_code == bob.status_code == 200
        assert alice.json()["status"] == bob.json()["status"] == "committed"
        assert alice.json()["operation_id"] != bob.json()["operation_id"]
        assert not alice.json()["replayed"] and not bob.json()["replayed"]
        assert await pg_ledger.balance("receiver") == 1_000
        assert await pg_ledger.balance("receiver-b") == 2_000
        drift = await client.post(
            "/v1/actions",
            json=_action(shared_key, amount=3_000, receiver="receiver-b"),
            headers=_auth("alice-token"),
        )
        assert drift.status_code == 409
        assert drift.json()["error"]["code"] == "resource_conflict"
        assert "different request" in drift.json()["error"]["message"]
        assert await pg_ledger.balance("receiver-b") == 2_000


async def test_adapter_assertion_is_authenticated_and_durably_bound_to_idempotency(
    pg_ledger: AsyncPostgresLedger,
) -> None:
    await _seed(pg_ledger, 0)
    _coordinator, app = _stack(
        pg_ledger,
        TRANSACTION_POLICY,
        MasuGateMode.TRANSACTION,
        action_owners={
            "transfer": ActionOwnerBinding(
                provider_id="ledger-v1", position=EffectExecutionPosition.TRANSACTIONAL
            )
        },
        adapter_invocation_principals={"alice"},
    )
    headers = {
        **_auth(),
        "MasuGate-Expected-Principal": "alice",
        "MasuGate-Expected-Provider": "ledger-v1",
        "MasuGate-Expected-Position": "transactional",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://masugated.test"
    ) as client:
        body = _action("adapter-bound", amount=1_000)
        body["adapter_invocation"] = _adapter_invocation(principal_id="alice")
        first = await client.post("/v1/actions", json=body, headers=headers)
        replay = await client.post("/v1/actions", json=body, headers=headers)
        changed_assertion = await client.post(
            "/v1/actions",
            json={
                **body,
                "adapter_invocation": _adapter_invocation(principal_id="alice", adapter_id="other"),
            },
            headers=headers,
        )
        forged_principal = await client.post(
            "/v1/actions",
            json={
                **_action("forged-principal", amount=1_000),
                "adapter_invocation": _adapter_invocation(principal_id="bob"),
            },
            headers=headers,
        )

    assert first.status_code == replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert changed_assertion.status_code == 409
    assert changed_assertion.json()["error"]["code"] == "resource_conflict"
    assert forged_principal.status_code == 400
    assert await pg_ledger.balance("receiver") == 1_000


async def test_strict_adapter_replay_refuses_unbound_record(
    pg_ledger: AsyncPostgresLedger,
) -> None:
    """A provenance-free record cannot satisfy a strict adapter replay."""

    await _seed(pg_ledger, 0)
    await pg_ledger.create_account("openclaw:agent-alpha", "research", 100_000)
    _legacy_coordinator, legacy_app = _stack(
        pg_ledger,
        TRANSACTION_POLICY,
        MasuGateMode.TRANSACTION,
        token_principals={"openclaw-token": "openclaw:agent-alpha"},
        action_owners={
            "transfer": ActionOwnerBinding(
                provider_id="ledger-v1", position=EffectExecutionPosition.TRANSACTIONAL
            )
        },
    )
    _strict_coordinator, strict_app = _stack(
        pg_ledger,
        TRANSACTION_POLICY,
        MasuGateMode.TRANSACTION,
        token_principals={"openclaw-token": "openclaw:agent-alpha"},
        action_owners={
            "transfer": ActionOwnerBinding(
                provider_id="ledger-v1", position=EffectExecutionPosition.TRANSACTIONAL
            )
        },
        adapter_invocation_principals={"openclaw:agent-alpha"},
    )
    key = "unbound-strict-replay"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=legacy_app), base_url="http://masugated.test"
    ) as client:
        first = await client.post(
            "/v1/actions",
            json=_action(key, amount=1_000),
            headers={"Authorization": "Bearer openclaw-token"},
        )
    assert first.status_code == 200, first.text

    body = _action(key, amount=1_000)
    body["adapter_invocation"] = _adapter_invocation(principal_id="openclaw:agent-alpha")
    headers = {
        "Authorization": "Bearer openclaw-token",
        "MasuGate-Expected-Principal": "openclaw:agent-alpha",
        "MasuGate-Expected-Provider": "ledger-v1",
        "MasuGate-Expected-Position": "transactional",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=strict_app), base_url="http://masugated.test"
    ) as client:
        replay = await client.post("/v1/actions", json=body, headers=headers)

    assert replay.status_code == 409
    assert replay.json()["error"]["code"] == "resource_conflict"
    assert await pg_ledger.balance("receiver") == 1_000


async def test_pending_reservations_allow_same_wire_key_for_distinct_principals(
    pg_ledger: AsyncPostgresLedger,
) -> None:
    await _seed(pg_ledger, 0)
    _coordinator, app = _stack(pg_ledger, RESERVATION_POLICY, MasuGateMode.RESERVATION)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://masugated.test",
    ) as client:
        alice = await client.post(
            "/v1/actions",
            json=_action("shared-pending-key", amount=5_000),
            headers=_auth("alice-token"),
        )
        bob = await client.post(
            "/v1/actions",
            json=_action("shared-pending-key", amount=5_000, receiver="receiver-b"),
            headers=_auth("bob-token"),
        )

        assert alice.status_code == bob.status_code == 200
        assert alice.json()["status"] == bob.json()["status"] == "pending"
        assert alice.json()["pending_id"] != bob.json()["pending_id"]
        drift = await client.post(
            "/v1/actions",
            json=_action("shared-pending-key", amount=6_000),
            headers=_auth("alice-token"),
        )
        assert drift.status_code == 409
        async with pg_ledger.open_session(write=False) as session:
            pending_rows = await (
                await session.connection.execute(
                    "SELECT principal_id FROM pending_operations "
                    "WHERE idempotency_key = %s ORDER BY principal_id",
                    ("shared-pending-key",),
                )
            ).fetchall()
            reservation_rows = await (
                await session.connection.execute(
                    "SELECT principal_id FROM reservations "
                    "WHERE idempotency_key = %s ORDER BY principal_id",
                    ("shared-pending-key",),
                )
            ).fetchall()
        assert [row["principal_id"] for row in pending_rows] == ["alice", "bob"]
        assert [row["principal_id"] for row in reservation_rows] == ["alice", "bob"]


async def test_pending_and_audit_visibility_requires_owner_or_operator(
    pg_ledger: AsyncPostgresLedger,
) -> None:
    await _seed(pg_ledger, 0)
    _coordinator, app = _stack(pg_ledger, SCOPED_HOLD_POLICY, MasuGateMode.SCOPED_HOLD)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://masugated.test",
    ) as client:
        pending_response = await client.post(
            "/v1/actions",
            json=_action("private-approval", amount=5_000),
            headers=_auth("alice-token"),
        )
        pending = pending_response.json()
        assert pending_response.status_code == 200 and pending["status"] == "pending"
        pending_id = pending["pending_id"]
        audit_ref = pending["audit_ref"]

        alice_list = await client.get("/v1/pending", headers=_auth("alice-token"))
        alice_stream = await client.get(
            "/v1/pending/stream?once=true",
            headers=_auth("alice-token"),
        )
        assert [item["pending_id"] for item in alice_list.json()["items"]] == [pending_id]
        assert f"id: {pending_id}" in alice_stream.text
        assert (await client.get(audit_ref, headers=_auth("alice-token"))).status_code == 200
        alice_lookup = await client.get(f"/v1/pending/{pending_id}", headers=_auth("alice-token"))
        assert alice_lookup.json() == {"kind": "pending", "pending": alice_list.json()["items"][0]}

        bob_list = await client.get("/v1/pending", headers=_auth("bob-token"))
        bob_stream = await client.get(
            "/v1/pending/stream?once=true",
            headers=_auth("bob-token"),
        )
        bob_audit = await client.get(audit_ref, headers=_auth("bob-token"))
        bob_lookup = await client.get(f"/v1/pending/{pending_id}", headers=_auth("bob-token"))
        bob_resolve = await client.post(
            f"/v1/pending/{pending_id}/resolve",
            json={"approved": True},
            headers=_auth("bob-token"),
        )
        owner_self_approve = await client.post(
            f"/v1/pending/{pending_id}/resolve",
            json={"approved": True},
            headers=_auth("alice-token"),
        )
        assert bob_list.json() == {"items": [], "next_cursor": "0"}
        assert "event: pending.created" not in bob_stream.text
        assert bob_audit.status_code == bob_lookup.status_code == bob_resolve.status_code == 404
        assert owner_self_approve.status_code == 404

        operator_list = await client.get("/v1/pending", headers=_auth("operator-token"))
        operator_stream = await client.get(
            "/v1/pending/stream?once=true",
            headers=_auth("operator-token"),
        )
        operator_audit = await client.get(audit_ref, headers=_auth("operator-token"))
        resolved = await client.post(
            f"/v1/pending/{pending_id}/resolve",
            json={"approved": True, "evidence": {"reviewer": "operator"}},
            headers=_auth("operator-token"),
        )
        assert [item["pending_id"] for item in operator_list.json()["items"]] == [pending_id]
        assert f"id: {pending_id}" in operator_stream.text
        assert operator_audit.status_code == 200
        assert resolved.status_code == 200 and resolved.json()["status"] == "committed"
        terminal_lookup = await client.get(
            f"/v1/pending/{pending_id}", headers=_auth("alice-token")
        )
        assert terminal_lookup.json() == {"kind": "terminal", "result": resolved.json()}


async def test_http_trust_boundary_and_error_envelopes(
    pg_ledger: AsyncPostgresLedger,
) -> None:
    await _seed(pg_ledger, 0)
    _coordinator, app = _stack(pg_ledger, TRANSACTION_POLICY, MasuGateMode.TRANSACTION)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://masugated.test",
    ) as client:
        no_auth = await client.post("/v1/actions", json=_action("no-auth", amount=1_000))
        assert no_auth.status_code == 401
        assert no_auth.json()["error"]["code"] == "unauthorized"

        # Identity/time/operation id are not merely ignored: the closed schema
        # rejects them, making the server-owned trust boundary visible.
        forged = _action("forged", amount=1_000)
        forged.update(
            {
                "principal_ref": "bob",
                "principal": {"id": "bob", "attributes": {"team": "other"}},
                "timestamp": "2000-01-01T00:00:00Z",
                "operation_id": "chosen-by-caller",
            }
        )
        rejected = await client.post("/v1/actions", json=forged, headers=_auth())
        assert rejected.status_code == 422
        assert rejected.json()["error"]["code"] == "invalid_request"

        missing = await client.get("/v1/audit/not-real", headers=_auth())
        assert missing.status_code == 404
        assert missing.json() == {
            "error": {"code": "not_found", "message": "unknown operation: not-real"}
        }


async def test_scoped_hold_pending_list_sse_competitor_and_resolution(
    pg_ledger: AsyncPostgresLedger,
) -> None:
    await _seed(pg_ledger, 95_000)
    _coordinator, app = _stack(pg_ledger, SCOPED_HOLD_POLICY, MasuGateMode.SCOPED_HOLD)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://masugated.test",
    ) as client:
        pending_response = await client.post(
            "/v1/actions",
            json=_action("approval-1", amount=5_000),
            headers=_auth(),
        )
        assert pending_response.status_code == 200
        pending = pending_response.json()
        assert pending["status"] == "pending"
        assert pending["decision"]["effect"] == "escalate"
        assert pending["pending_id"] == pending["operation_id"]

        # Retrying a still-pending action replays the same marker; it does not
        # attempt a duplicate insert or create a second hold.
        replay = await client.post(
            "/v1/actions",
            json=_action("approval-1", amount=5_000),
            headers=_auth(),
        )
        assert replay.json()["operation_id"] == pending["operation_id"]
        assert replay.json()["replayed"] is True

        listed = (await client.get("/v1/pending", headers=_auth())).json()["items"]
        assert [item["pending_id"] for item in listed] == [pending["pending_id"]]

        # The SSE endpoint replays the durable snapshot before waiting for live
        # events. `once=true` makes that catch-up batch finite for HTTP clients.
        stream = await client.get("/v1/pending/stream?once=true", headers=_auth())
        assert stream.status_code == 200
        assert "event: pending.created" in stream.text
        assert f"id: {pending['pending_id']}" in stream.text

        competitor = await client.post(
            "/v1/actions",
            json=_action("competitor", amount=3_000, receiver="receiver-b"),
            headers=_auth("bob-token"),
        )
        assert competitor.json()["status"] == "denied"
        assert competitor.json()["decision"]["rule_id"] == "scope_held"

        resolved_response = await client.post(
            f"/v1/pending/{pending['pending_id']}/resolve",
            json={"approved": True, "evidence": {"ticket": "CAB-42"}},
            headers=_auth("operator-token"),
        )
        assert resolved_response.status_code == 200, resolved_response.text
        resolved = resolved_response.json()
        assert resolved["status"] == "committed"
        assert resolved["decision"]["effect"] == "allow"
        assert resolved["payload"]["approval_evidence"] == {"ticket": "CAB-42"}

        # Resolution is idempotent too: a delivery retry returns the durable
        # terminal result rather than treating the now-resolved pending id as
        # unknown or executing the effect again.
        resolved_replay = await client.post(
            f"/v1/pending/{pending['pending_id']}/resolve",
            json={"approved": True, "evidence": {"ticket": "CAB-42"}},
            headers=_auth("operator-token"),
        )
        assert resolved_replay.status_code == 200, resolved_replay.text
        replayed_terminal = resolved_replay.json()
        assert replayed_terminal["operation_id"] == resolved["operation_id"]
        assert replayed_terminal["status"] == "committed"
        assert replayed_terminal["replayed"] is True
        assert (await client.get("/v1/pending", headers=_auth())).json() == {
            "items": [],
            "next_cursor": "0",
        }


async def test_pending_cancellation_acknowledges_then_replays_terminal_receipt(
    pg_ledger: AsyncPostgresLedger,
) -> None:
    """Cancellation is bounded acknowledgement, never detached effect authority."""

    await _seed(pg_ledger, 95_000)
    _coordinator, app = _stack(pg_ledger, SCOPED_HOLD_POLICY, MasuGateMode.SCOPED_HOLD)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://masugated.test",
    ) as client:
        pending_response = await client.post(
            "/v1/actions",
            json=_action("cancel-approval", amount=5_000),
            headers=_auth(),
        )
        pending = pending_response.json()
        assert pending_response.status_code == 200 and pending["status"] == "pending"

        denied = await client.post(
            f"/v1/pending/{pending['pending_id']}/cancel",
            headers=_auth(),
        )
        assert denied.status_code == 404

        acknowledged = await client.post(
            f"/v1/pending/{pending['pending_id']}/cancel",
            headers=_auth("operator-token"),
        )
        assert acknowledged.status_code == 200, acknowledged.text
        assert acknowledged.json() == {
            "kind": "cancellation",
            "locator": {
                "operation_id": pending["operation_id"],
                "pending_id": pending["pending_id"],
            },
            "accepted": True,
        }

        terminal = await client.get(f"/v1/pending/{pending['pending_id']}", headers=_auth())
        assert terminal.status_code == 200
        replay = terminal.json()
        assert replay["kind"] == "terminal"
        assert replay["result"]["status"] == "denied"
        assert replay["result"]["decision"]["effect"] == "deny"
        assert replay["result"]["audit_ref"] == f"/v1/audit/{pending['operation_id']}"

        receipt = await client.get(replay["result"]["audit_ref"], headers=_auth())
        assert receipt.status_code == 200
        receipt_body = receipt.json()
        assert receipt_body["status"] == "denied"
        assert receipt_body["terminal_serialization"] is not None

        repeated = await client.post(
            f"/v1/pending/{pending['pending_id']}/cancel",
            headers=_auth("operator-token"),
        )
        assert repeated.status_code == 200
        assert repeated.json()["accepted"] is False
        assert repeated.json()["terminal_result"]["status"] == "denied"


async def test_transaction_pending_revalidates_to_stale_approval_deny(
    pg_ledger: AsyncPostgresLedger,
) -> None:
    """The complementary pending path: no escrow/hold, so approval revalidates."""

    await _seed(pg_ledger, 95_000)
    _coordinator, app = _stack(
        pg_ledger,
        SCOPED_HOLD_POLICY,
        MasuGateMode.TRANSACTION,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://masugated.test",
    ) as client:
        pending = (
            await client.post(
                "/v1/actions",
                json=_action("revalidate-approval", amount=5_000),
                headers=_auth(),
            )
        ).json()
        assert pending["status"] == "pending"

        # Transaction mode has no hold: an allowed same-scope op can advance
        # policy state while the human decision is outstanding.
        competitor = (
            await client.post(
                "/v1/actions",
                json=_action("revalidate-competitor", amount=3_000, receiver="receiver-b"),
                headers=_auth("bob-token"),
            )
        ).json()
        assert competitor["status"] == "committed"

        resolved = (
            await client.post(
                f"/v1/pending/{pending['pending_id']}/resolve",
                json={"approved": True, "evidence": {"reviewer": "operator"}},
                headers=_auth("operator-token"),
            )
        ).json()
        assert resolved["status"] == "denied"
        assert resolved["decision"]["rule_id"].endswith(".stale_approval")


async def test_reservation_pending_holds_capacity_then_consumes_on_approval(
    pg_ledger: AsyncPostgresLedger,
) -> None:
    await _seed(pg_ledger, 95_000)
    _coordinator, app = _stack(pg_ledger, RESERVATION_POLICY, MasuGateMode.RESERVATION)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://masugated.test",
    ) as client:
        pending_response = await client.post(
            "/v1/actions",
            json=_action("reserved-approval", amount=5_000),
            headers=_auth(),
        )
        assert pending_response.status_code == 200, pending_response.text
        pending = pending_response.json()
        assert pending["status"] == "pending"
        async with pg_ledger.open_session(write=False) as session:
            durable_pending = await pg_ledger.load_pending_operation(session, pending["pending_id"])
        assert durable_pending is not None
        reservation_id = durable_pending.reservation_id
        assert reservation_id is not None

        # The reservation consumes the final 5k of availability while the
        # approval waits, so a same-scope competitor is cleanly denied.
        competitor = await client.post(
            "/v1/actions",
            json=_action("reserve-competitor", amount=1_000, receiver="receiver-b"),
            headers=_auth("bob-token"),
        )
        assert competitor.json()["status"] == "denied"
        assert competitor.json()["decision"]["rule_id"] == "daily_team_budget"

        resolved_response = await client.post(
            f"/v1/pending/{pending['pending_id']}/resolve",
            json={"approved": True, "evidence": {"reviewer": "operator"}},
            headers=_auth("operator-token"),
        )
        assert resolved_response.status_code == 200, resolved_response.text
        resolved = resolved_response.json()
        assert resolved["status"] == "committed"
        async with pg_ledger.open_session(write=False) as session:
            row = await (
                await session.connection.execute(
                    "SELECT state FROM reservations WHERE reservation_id = %s",
                    (reservation_id,),
                )
            ).fetchone()
        assert row is not None and row["state"] == "consumed"
