"""HTTP boundary tests for the bounded reference spend reference spend service."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import datetime, timedelta
from hashlib import sha256
from importlib import import_module
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
import pytest
from masugate_client import canonical_adapter_envelope, create_adapter_invocation

from masugate.model import JsonValue, Scalar
from masugate.protected_execution import (
    ConnectorContractError,
    PolicyBinding,
    PostgresProtectedExecutionStore,
    ProtectedExecutionAuthority,
    ProtectedExecutionBinding,
    ProtectedExecutionRunner,
    SqliteProtectedExecutionStore,
    canonical_json,
)
from masugate.providers import (
    HttpReferencePurchaseApi,
    PostgresSpendOutboxStore,
    ReferencePurchaseConnector,
    ReferencePurchaseCredentialManifest,
    SpendHandoffState,
    SpendOperationStatus,
    SpendPolicy,
    SpendPurchaseRequest,
    SpendPurchaseService,
    SpendResolution,
    SqliteReferencePurchaseApi,
    SqliteSpendOutboxStore,
)
from masugate.providers import spend as spend_module
from masugate_openclaw_reference import (
    ReferenceSpendResource as OpenClawResource,
)
from masugate_openclaw_reference import (
    build_postgres_reference_spend_resource as build_postgres_openclaw_resource,
)
from masugate_openclaw_reference import (
    create_reference_purchase_api_app,
    create_spend_reference_app,
)

jsonschema: Any = import_module("jsonschema")


def _validate_protocol(schema_name: str, value: object) -> None:
    schema_path = Path(__file__).parents[1] / "protocol" / "schemas" / schema_name
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    ).validate(value)


def _assert_protected_binding_integrity(audit: dict[str, Any]) -> None:
    protected = audit["protected_execution"]
    assert isinstance(protected, dict)
    binding = protected["binding"]
    assert isinstance(binding, dict)
    canonical_binding = protected["binding_canonical_json"]
    assert canonical_binding == canonical_json(binding)
    digest = sha256(canonical_binding.encode("utf-8")).hexdigest()
    assert protected["binding_digest"] == digest
    assert protected["execution_id"] == f"px:{digest}"
    receipt = protected["receipt"]
    assert isinstance(receipt, dict)
    assert receipt["idempotency_key"] == f"masugate:{digest}"
    events = protected["events"]
    assert isinstance(events, list)
    intent = events[0]
    assert isinstance(intent, dict)
    evidence = intent["evidence"]
    assert isinstance(evidence, dict)
    assert evidence["binding_digest"] == digest


async def _stack(
    tmp_path: Path,
    *,
    unknown_after_commit_once: bool = False,
) -> tuple[httpx.AsyncClient, SqliteReferencePurchaseApi]:
    policy = SpendPolicy(budget_limit_cents=1_000, approval_threshold_cents=500)
    api = SqliteReferencePurchaseApi(
        tmp_path / "purchase-api.sqlite",
        unknown_after_commit_once=unknown_after_commit_once,
    )
    service = SpendPurchaseService(
        SqliteSpendOutboxStore(tmp_path / "spend.sqlite", policy),
        ProtectedExecutionRunner(
            SqliteProtectedExecutionStore(tmp_path / "protected.sqlite"),
            ReferencePurchaseConnector(api),
            ProtectedExecutionAuthority(
                action="spend.purchase",
                provider_identity=policy.provider_identity,
                coordination_domain_id="masugate.spend.reference.domain.v1",
                connector_id="reference-purchase-v1",
            ),
            worker_id="reference-http-worker",
        ),
        policy,
    )
    resource = OpenClawResource(
        service=service,
        principals={
            "openclaw:buyer-alpha": {
                "team": "research",
                "masugate_require_adapter_invocation": True,
            },
            "operator": {"team": "operations", "masugate_operator": True},
        },
        token_principals={
            "buyer-token": "openclaw:buyer-alpha",
            "operator-token": "operator",
        },
        operator_principals={"operator"},
    )
    await resource.initialize()
    return (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_spend_reference_app(resource)),
            base_url="http://reference.test",
        ),
        api,
    )


def _action(key: str, *, amount: int, request_ref: str = "request-1") -> dict[str, object]:
    args = {
        "amount_cents": amount,
        "merchant_id": "office-supply",
        "request_ref": request_ref,
    }
    return {
        "action": "spend.purchase",
        "args": args,
        "idempotency_key": key,
        "trace_id": f"trace:{key}",
        "adapter_invocation": canonical_adapter_envelope(
            create_adapter_invocation(
                {
                    "principal": {"id": "openclaw:buyer-alpha"},
                    "source": {"namespace": "openclaw", "id": f"call:{key}"},
                    "adapter": {
                        "id": "masugate.openclaw",
                        "contract_version": "masugate.host-adapter.v1",
                        "capabilities": ["cancellation", "receipt"],
                    },
                    "action": {"name": "spend.purchase", "arguments": args},
                }
            )
        ),
    }


def _headers(*, owner: bool = True, token: str = "buyer-token") -> dict[str, str]:
    headers = {"Authorization": f"Bearer {token}"}
    if owner:
        headers.update(
            {
                "MasuGate-Expected-Principal": "openclaw:buyer-alpha",
                "MasuGate-Expected-Provider": "masugate.spend.reference",
                "MasuGate-Expected-Position": "protected-external",
                "MasuGate-Expected-Connector": "reference-purchase-v1",
            }
        )
    return headers


def _credential_manifest(
    service_token: str = "connector-service-secret",
    *,
    masugate_tokens: tuple[str, ...] = ("buyer-token", "operator-token"),
) -> ReferencePurchaseCredentialManifest:
    return ReferencePurchaseCredentialManifest.from_credentials(
        connector_service_token=service_token,
        masugate_bearer_credentials=masugate_tokens,
    )


async def test_reference_action_protocol_commits_once_and_exposes_receipt(tmp_path: Path) -> None:
    client, api = await _stack(tmp_path)
    async with client:
        first = await client.post(
            "/v1/actions",
            json=_action("masugate:v1:http-committed", amount=100),
            headers=_headers(),
        )
        assert first.status_code == 200, first.text
        committed = first.json()
        _validate_protocol("action-response.schema.json", committed)
        assert committed["status"] == "committed"
        assert committed["decision"]["effect"] == "allow"
        assert committed["replayed"] is False
        UUID(committed["operation_id"])
        assert committed["payload"]["protected_execution"]["status"] == "succeeded"
        assert len(committed["payload"]["policy_catalog"]["policy_digest"]) == 64
        assert len(committed["payload"]["policy_catalog"]["bundle_digest"]) == 64
        reads = committed["payload"]["authorization"]["reads"]
        assert reads == [
            {
                "arguments": ["research"],
                "function": "spend.available_cents",
                "scope": "spend:team:research",
                "value": 1_000,
                "version": 0,
            }
        ]

        duplicate = await client.post(
            "/v1/actions",
            json=_action("masugate:v1:http-committed", amount=100),
            headers=_headers(),
        )
        assert duplicate.status_code == 200
        assert duplicate.json()["operation_id"] == committed["operation_id"]
        assert duplicate.json()["replayed"] is True
        assert await api.effect_count() == 1

        receipt = await client.get(committed["audit_ref"], headers=_headers())
        assert receipt.status_code == 200
        audited = receipt.json()
        _validate_protocol("audit.schema.json", audited)
        assert audited["protected_execution"]["receipt"]["outcome"] == "succeeded"
        assert audited["protected_execution"]["lease"] is None
        assert audited["protected_execution"]["last_fence_token"] >= 1
        assert audited["protected_execution"]["events"]
        assert audited["status"] == "committed"
        assert audited["decision"]["effect"] == "allow"
        assert {
            key: value for key, value in audited["view_reads"][0].items() if key != "latency_ms"
        } == reads[0]
        assert audited["view_reads"][0]["latency_ms"] >= 0
        provenance = audited["policy"]["evaluated_policy_provenance"][0]
        assert (
            provenance["policy_digest"] == committed["payload"]["policy_catalog"]["policy_digest"]
        )
        assert (
            provenance["bundle_digest"] == committed["payload"]["policy_catalog"]["bundle_digest"]
        )
        assert (
            audited["protected_execution"]["binding"]["authorization_digest"]
            == committed["payload"]["authorization_digest"]
        )
        adapter_invocation = _action("masugate:v1:http-committed", amount=100)[
            "adapter_invocation"
        ]
        assert isinstance(adapter_invocation, str)
        assert (
            audited["request"]["adapter_invocation_digest"]
            == sha256(adapter_invocation.encode()).hexdigest()
        )
        _assert_protected_binding_integrity(audited)


async def test_reference_ask_first_resolution_and_action_assertions(tmp_path: Path) -> None:
    client, api = await _stack(tmp_path)
    async with client:
        unauthorized = await client.post(
            "/v1/actions",
            json=_action("masugate:v1:missing-assertions", amount=600),
            headers=_headers(owner=False),
        )
        assert unauthorized.status_code == 401

        missing_provenance = _action("masugate:v1:missing-provenance", amount=100)
        missing_provenance.pop("adapter_invocation")
        missing = await client.post(
            "/v1/actions",
            json=missing_provenance,
            headers=_headers(),
        )
        assert missing.status_code == 400
        assert "adapter invocation" in missing.json()["error"]["message"]

        bound = _action("masugate:v1:provenance-bound", amount=100)
        accepted = await client.post("/v1/actions", json=bound, headers=_headers())
        assert accepted.status_code == 200, accepted.text
        altered = dict(bound)
        envelope = json.loads(str(bound["adapter_invocation"]))
        envelope["source"]["id"] = "call:altered"
        altered["adapter_invocation"] = json.dumps(
            envelope,
            separators=(",", ":"),
            sort_keys=True,
        )
        altered_replay = await client.post("/v1/actions", json=altered, headers=_headers())
        assert altered_replay.status_code == 409

        mismatch = await client.post(
            "/v1/actions",
            json=_action("masugate:v1:bad-owner", amount=600),
            headers={**_headers(), "MasuGate-Expected-Connector": "wrong-connector"},
        )
        assert mismatch.status_code == 409

        pending_response = await client.post(
            "/v1/actions",
            json=_action("masugate:v1:needs-approval", amount=600),
            headers=_headers(),
        )
        assert pending_response.status_code == 200
        pending = pending_response.json()
        assert pending["status"] == "pending"
        assert pending["decision"]["effect"] == "escalate"
        UUID(pending["pending_id"])
        assert await api.effect_count() == 1

        listed = await client.get("/v1/pending", headers=_headers())
        assert listed.status_code == 200, listed.text
        _validate_protocol("pending-list.schema.json", listed.json())
        assert listed.json() == {
            "items": [
                {
                    "pending_id": pending["pending_id"],
                    "operation_id": pending["operation_id"],
                    "principal_id": "openclaw:buyer-alpha",
                    "action": "spend.purchase",
                    "args": {
                        "amount_cents": 600,
                        "merchant_id": "office-supply",
                        "request_ref": "request-1",
                    },
                    "created_at": listed.json()["items"][0]["created_at"],
                    "decision": {
                        "effect": "escalate",
                        "policy_id": "spend_budget_guard",
                        "policy_version": pending["decision"]["policy_version"],
                        "rule_id": "ask_first.pending",
                        "reason": "approval required before protected dispatch",
                    },
                    "audit_ref": pending["audit_ref"],
                }
            ],
            "next_cursor": pending["pending_id"],
        }

        pending_lookup = await client.get(
            f"/v1/pending/{pending['pending_id']}", headers=_headers()
        )
        assert pending_lookup.status_code == 200, pending_lookup.text
        assert pending_lookup.json() == {"kind": "pending", "pending": listed.json()["items"][0]}

        agent_resolution = await client.post(
            f"/v1/pending/{pending['pending_id']}/resolve",
            json={"approved": True},
            headers=_headers(),
        )
        assert agent_resolution.status_code == 404

        resolved = await client.post(
            f"/v1/pending/{pending['pending_id']}/resolve",
            json={
                "approved": True,
                "evidence": {
                    "agent_id": "buyer-alpha",
                    "decision": "allow-once",
                    "session_id": "session-approval-1",
                    "session_key": "agent:buyer-alpha:approval",
                    "source": "openclaw-native-approval",
                },
            },
            headers=_headers(owner=False, token="operator-token"),
        )
        assert resolved.status_code == 200, resolved.text
        assert resolved.json()["status"] == "committed"
        assert await api.effect_count() == 2

        terminal_lookup = await client.get(
            f"/v1/pending/{pending['pending_id']}", headers=_headers()
        )
        assert terminal_lookup.status_code == 200, terminal_lookup.text
        assert terminal_lookup.json() == {"kind": "terminal", "result": resolved.json()}

        duplicate_resolution = await client.post(
            f"/v1/pending/{pending['pending_id']}/resolve",
            json={
                "approved": True,
                "evidence": {
                    "agent_id": "buyer-alpha",
                    "decision": "allow-once",
                    "session_id": "session-approval-1",
                    "session_key": "agent:buyer-alpha:approval",
                    "source": "openclaw-native-approval",
                },
            },
            headers=_headers(owner=False, token="operator-token"),
        )
        assert duplicate_resolution.status_code == 200, duplicate_resolution.text
        assert duplicate_resolution.json()["status"] == "committed"
        assert await api.effect_count() == 2

        audit = await client.get(pending["audit_ref"], headers=_headers())
        assert audit.status_code == 200
        resolution = audit.json()["human_resolution"]
        _validate_protocol("audit.schema.json", audit.json())
        assert resolution == {
            "actor_id": "operator",
            "approved": True,
            "evidence": {
                "agent_id": "buyer-alpha",
                "decision": "allow-once",
                "session_id": "session-approval-1",
                "session_key": "agent:buyer-alpha:approval",
                "source": "openclaw-native-approval",
            },
            "resolved_at": resolution["resolved_at"],
        }


async def test_reference_pending_cancellation_is_operator_scoped_and_replay_safe(
    tmp_path: Path,
) -> None:
    client, api = await _stack(tmp_path)
    async with client:
        pending_response = await client.post(
            "/v1/actions",
            json=_action("masugate:v1:cancel-pending", amount=600),
            headers=_headers(),
        )
        assert pending_response.status_code == 200, pending_response.text
        pending = pending_response.json()
        assert pending["status"] == "pending"

        unauthorized = await client.post(
            f"/v1/pending/{pending['pending_id']}/cancel",
            headers=_headers(),
        )
        assert unauthorized.status_code == 404

        acknowledged = await client.post(
            f"/v1/pending/{pending['pending_id']}/cancel",
            headers=_headers(owner=False, token="operator-token"),
        )
        assert acknowledged.status_code == 200, acknowledged.text
        _validate_protocol("host-adapter-lifecycle.schema.json", acknowledged.json())
        assert acknowledged.json() == {
            "kind": "cancellation",
            "locator": {
                "operation_id": pending["operation_id"],
                "pending_id": pending["pending_id"],
            },
            "accepted": True,
        }
        assert await api.effect_count() == 0

        terminal = await client.get(f"/v1/pending/{pending['pending_id']}", headers=_headers())
        assert terminal.status_code == 200, terminal.text
        assert terminal.json()["kind"] == "terminal"
        assert terminal.json()["result"]["status"] == "denied"

        repeated = await client.post(
            f"/v1/pending/{pending['pending_id']}/cancel",
            headers=_headers(owner=False, token="operator-token"),
        )
        assert repeated.status_code == 200, repeated.text
        _validate_protocol("host-adapter-lifecycle.schema.json", repeated.json())
        assert repeated.json()["accepted"] is False
        assert repeated.json()["terminal_result"]["status"] == "denied"


async def test_expiry_audit_is_automatic_not_human_resolution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, api = await _stack(tmp_path)
    async with client:
        pending_response = await client.post(
            "/v1/actions",
            json=_action("masugate:v1:automatic-expiry", amount=600),
            headers=_headers(),
        )
        assert pending_response.status_code == 200, pending_response.text
        pending = pending_response.json()
        assert pending["status"] == "pending"
        listed = await client.get("/v1/pending", headers=_headers())
        assert listed.status_code == 200, listed.text
        created_at = datetime.fromisoformat(listed.json()["items"][0]["created_at"])
        expires_at = created_at + timedelta(seconds=600)
        monkeypatch.setattr(spend_module, "_utc_now", lambda: expires_at)

        expired_list = await client.get("/v1/pending", headers=_headers())
        assert expired_list.status_code == 200, expired_list.text
        assert expired_list.json()["items"] == []
        audit = await client.get(pending["audit_ref"], headers=_headers())
        assert audit.status_code == 200, audit.text
        receipt = audit.json()
        _validate_protocol("audit.schema.json", receipt)
        assert receipt["status"] == "denied"
        assert receipt["decision"]["rule_id"] == "approval.expired"
        assert receipt["automatic_expiry"] == {
            "expires_at": expires_at.isoformat(),
            "reason": "approval-window-expired",
        }
        assert "human_resolution" not in receipt
        without_expiry = dict(receipt)
        del without_expiry["automatic_expiry"]
        with pytest.raises(jsonschema.ValidationError):
            _validate_protocol("audit.schema.json", without_expiry)
        false_human_expiry = dict(receipt)
        false_human_expiry["human_resolution"] = {
            "actor_id": "operator",
            "approved": False,
            "evidence": {},
            "resolved_at": expires_at.isoformat(),
        }
        with pytest.raises(jsonschema.ValidationError):
            _validate_protocol("audit.schema.json", false_human_expiry)
        assert await api.effect_count() == 0


async def test_resolution_returns_truthful_outcome_unknown_without_false_escalation(
    tmp_path: Path,
) -> None:
    client, api = await _stack(tmp_path, unknown_after_commit_once=True)
    async with client:
        pending_response = await client.post(
            "/v1/actions",
            json=_action("masugate:v1:unknown-after-resolution", amount=600),
            headers=_headers(),
        )
        pending = pending_response.json()
        assert pending["status"] == "pending"

        resolved = await client.post(
            f"/v1/pending/{pending['pending_id']}/resolve",
            json={"approved": True, "evidence": {"ticket": "CAB-unknown"}},
            headers=_headers(owner=False, token="operator-token"),
        )

        assert resolved.status_code == 200, resolved.text
        unknown = resolved.json()
        _validate_protocol("action-response.schema.json", unknown)
        assert unknown["status"] == "outcome_unknown"
        assert unknown["decision"] is None
        assert "pending_id" not in unknown
        assert await api.effect_count() == 1
        audit = await client.get(unknown["audit_ref"], headers=_headers())
        assert audit.status_code == 200
        _validate_protocol("audit.schema.json", audit.json())
        assert audit.json()["status"] == "outcome_unknown"
        assert audit.json()["decision"] is None


async def test_reference_capacity_denial_is_durable_not_a_later_retry_authority(
    tmp_path: Path,
) -> None:
    client, api = await _stack(tmp_path)
    async with client:
        committed = await client.post(
            "/v1/actions",
            json=_action("masugate:v1:capacity-first", amount=400),
            headers=_headers(),
        )
        assert committed.json()["status"] == "committed"

        denied = await client.post(
            "/v1/actions",
            json=_action("masugate:v1:capacity-denied", amount=700),
            headers=_headers(),
        )
        assert denied.status_code == 200
        assert denied.json()["status"] == "denied"
        assert denied.json()["replayed"] is False

        same_callback = await client.post(
            "/v1/actions",
            json=_action("masugate:v1:capacity-denied", amount=700),
            headers=_headers(),
        )
        assert same_callback.status_code == 200
        assert same_callback.json()["status"] == "denied"
        assert same_callback.json()["operation_id"] == denied.json()["operation_id"]
        assert same_callback.json()["replayed"] is True
        assert await api.effect_count() == 1


async def test_operator_credential_cannot_submit_an_action(tmp_path: Path) -> None:
    client, api = await _stack(tmp_path)
    async with client:
        response = await client.post(
            "/v1/actions",
            json=_action("masugate:v1:operator-action", amount=100),
            headers=_headers(owner=False, token="operator-token"),
        )

    assert response.status_code == 401
    assert await api.effect_count() == 0


async def test_authenticated_network_purchase_connector_is_a_real_service_boundary(
    tmp_path: Path,
) -> None:
    policy = SpendPolicy(budget_limit_cents=1_000, approval_threshold_cents=500)
    backend = SqliteReferencePurchaseApi(tmp_path / "network-purchase.sqlite")
    await backend.initialize()
    manifest = _credential_manifest()
    purchase_app = create_reference_purchase_api_app(
        backend,
        service_token="connector-service-secret",
        credential_manifest=manifest,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=purchase_app),
        base_url="http://purchase.test",
    ) as purchase_client:
        remote_api = HttpReferencePurchaseApi(
            "http://purchase.test",
            service_token="connector-service-secret",
            credential_manifest=manifest,
            client=purchase_client,
        )
        service = SpendPurchaseService(
            SqliteSpendOutboxStore(tmp_path / "spend.sqlite", policy),
            ProtectedExecutionRunner(
                SqliteProtectedExecutionStore(tmp_path / "protected.sqlite"),
                ReferencePurchaseConnector(remote_api),
                ProtectedExecutionAuthority(
                    action="spend.purchase",
                    provider_identity=policy.provider_identity,
                    coordination_domain_id="masugate.spend.reference.domain.v1",
                    connector_id="reference-purchase-v1",
                ),
                worker_id="network-reference-worker",
            ),
            policy,
        )
        resource = OpenClawResource(
            service=service,
            principals={
                "openclaw:buyer-alpha": {
                    "team": "research",
                    "masugate_require_adapter_invocation": True,
                },
                "operator": {"team": "operations", "masugate_operator": True},
            },
            token_principals={
                "buyer-token": "openclaw:buyer-alpha",
                "operator-token": "operator",
            },
            operator_principals={"operator"},
        )
        await resource.initialize()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_spend_reference_app(resource)),
            base_url="http://reference.test",
        ) as client:
            response = await client.post(
                "/v1/actions",
                json=_action("masugate:v1:network", amount=100),
                headers=_headers(),
            )
        unauthorized = await purchase_client.get("/v1/health")

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "committed"
    assert unauthorized.status_code == 401
    assert await backend.effect_count() == 1


def test_purchase_service_bootstrap_rejects_a_token_outside_the_shared_manifest(
    tmp_path: Path,
) -> None:
    backend = SqliteReferencePurchaseApi(tmp_path / "bootstrap-purchase.sqlite")
    manifest = _credential_manifest()

    with pytest.raises(ValueError, match="does not match the credential manifest"):
        create_reference_purchase_api_app(
            backend,
            service_token="buyer-token",
            credential_manifest=manifest,
        )


async def test_http_connector_rejects_a_different_server_manifest(tmp_path: Path) -> None:
    backend = SqliteReferencePurchaseApi(tmp_path / "manifest-purchase.sqlite")
    server_manifest = _credential_manifest(masugate_tokens=("buyer-token", "operator-token"))
    client_manifest = _credential_manifest(masugate_tokens=("different-masugate-token",))
    app = create_reference_purchase_api_app(
        backend,
        service_token="connector-service-secret",
        credential_manifest=server_manifest,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://purchase.test",
    ) as purchase_client:
        remote = HttpReferencePurchaseApi(
            "http://purchase.test",
            service_token="connector-service-secret",
            credential_manifest=client_manifest,
            client=purchase_client,
        )
        with pytest.raises(ConnectorContractError, match="health contract"):
            await remote.initialize()


def test_reference_resource_requires_manifest_to_name_its_exact_bearer_set(
    tmp_path: Path,
) -> None:
    policy = SpendPolicy(budget_limit_cents=1_000, approval_threshold_cents=500)
    remote = HttpReferencePurchaseApi(
        "http://purchase.test",
        service_token="connector-service-secret",
        credential_manifest=_credential_manifest(masugate_tokens=("different-masugate-token",)),
    )
    service = SpendPurchaseService(
        SqliteSpendOutboxStore(tmp_path / "manifest-spend.sqlite", policy),
        ProtectedExecutionRunner(
            SqliteProtectedExecutionStore(tmp_path / "manifest-protected.sqlite"),
            ReferencePurchaseConnector(remote),
            ProtectedExecutionAuthority(
                action="spend.purchase",
                provider_identity=policy.provider_identity,
                coordination_domain_id="masugate.spend.reference.domain.v1",
                connector_id="reference-purchase-v1",
            ),
            worker_id="manifest-worker",
        ),
        policy,
    )
    with pytest.raises(ValueError, match="manifest does not match"):
        OpenClawResource(
            service=service,
            principals={
                "openclaw:buyer-alpha": {
                    "team": "research",
                    "masugate_require_adapter_invocation": True,
                },
                "operator": {"team": "operations", "masugate_operator": True},
            },
            token_principals={
                "buyer-token": "openclaw:buyer-alpha",
                "operator-token": "operator",
            },
            operator_principals={"operator"},
        )


async def test_reference_lifespan_closes_only_the_owned_http_client(tmp_path: Path) -> None:
    manifest = _credential_manifest()

    def health_response(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "status": "ok",
                "credential_manifest_digest": manifest.digest,
            },
        )

    def resource_for(remote: HttpReferencePurchaseApi, suffix: str) -> OpenClawResource:
        policy = SpendPolicy(budget_limit_cents=1_000, approval_threshold_cents=500)
        return OpenClawResource(
            service=SpendPurchaseService(
                SqliteSpendOutboxStore(tmp_path / f"{suffix}-spend.sqlite", policy),
                ProtectedExecutionRunner(
                    SqliteProtectedExecutionStore(tmp_path / f"{suffix}-protected.sqlite"),
                    ReferencePurchaseConnector(remote),
                    ProtectedExecutionAuthority(
                        action="spend.purchase",
                        provider_identity=policy.provider_identity,
                        coordination_domain_id="masugate.spend.reference.domain.v1",
                        connector_id="reference-purchase-v1",
                    ),
                    worker_id=f"{suffix}-worker",
                ),
                policy,
            ),
            principals={
                "openclaw:buyer-alpha": {
                    "team": "research",
                    "masugate_require_adapter_invocation": True,
                },
                "operator": {"team": "operations", "masugate_operator": True},
            },
            token_principals={
                "buyer-token": "openclaw:buyer-alpha",
                "operator-token": "operator",
            },
            operator_principals={"operator"},
        )

    owned_api = HttpReferencePurchaseApi(
        "http://purchase.test",
        service_token="connector-service-secret",
        credential_manifest=manifest,
    )
    owned_client = httpx.AsyncClient(
        base_url="http://purchase.test",
        transport=httpx.MockTransport(health_response),
    )
    owned_api._owned_client = owned_client
    owned_app = create_spend_reference_app(resource_for(owned_api, "owned"))
    async with owned_app.router.lifespan_context(owned_app):
        assert not owned_client.is_closed
    assert owned_client.is_closed

    external_client = httpx.AsyncClient(
        base_url="http://purchase.test",
        transport=httpx.MockTransport(health_response),
    )
    external_api = HttpReferencePurchaseApi(
        "http://purchase.test",
        service_token="connector-service-secret",
        credential_manifest=manifest,
        client=external_client,
    )
    external_app = create_spend_reference_app(resource_for(external_api, "external"))
    async with external_app.router.lifespan_context(external_app):
        assert not external_client.is_closed
    assert not external_client.is_closed
    await external_client.aclose()


@pytest.mark.postgres
async def test_postgres_reference_resource_restarts_with_durable_policy_evidence(
    reference_postgres_dsn: str,
    tmp_path: Path,
) -> None:
    policy = SpendPolicy(budget_limit_cents=1_000, approval_threshold_cents=500)
    purchase_api = SqliteReferencePurchaseApi(tmp_path / "postgres-purchase.sqlite")

    def resource(worker_id: str) -> OpenClawResource:
        service = SpendPurchaseService(
            PostgresSpendOutboxStore(reference_postgres_dsn, policy),
            ProtectedExecutionRunner(
                PostgresProtectedExecutionStore(reference_postgres_dsn),
                ReferencePurchaseConnector(purchase_api),
                ProtectedExecutionAuthority(
                    action="spend.purchase",
                    provider_identity=policy.provider_identity,
                    coordination_domain_id="masugate.spend.reference.domain.v1",
                    connector_id="reference-purchase-v1",
                ),
                worker_id=worker_id,
            ),
            policy,
        )
        return OpenClawResource(
            service=service,
            principals={
                "openclaw:buyer-alpha": {
                    "team": "research",
                    "masugate_require_adapter_invocation": True,
                },
                "operator": {"team": "operations", "masugate_operator": True},
            },
            token_principals={
                "buyer-token": "openclaw:buyer-alpha",
                "operator-token": "operator",
            },
            operator_principals={"operator"},
        )

    first_resource = resource("postgres-reference-one")
    await first_resource.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_spend_reference_app(first_resource)),
        base_url="http://reference.test",
    ) as client:
        first = await client.post(
            "/v1/actions",
            json=_action("masugate:v1:postgres-restart", amount=100),
            headers=_headers(),
        )
    assert first.status_code == 200, first.text
    first_payload = first.json()

    restarted = resource("postgres-reference-two")
    await restarted.initialize()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_spend_reference_app(restarted)),
        base_url="http://reference.test",
    ) as client:
        audit = await client.get(first_payload["audit_ref"], headers=_headers())

    assert audit.status_code == 200, audit.text
    assert audit.json()["policy"]["catalog"] == first_payload["payload"]["policy_catalog"]
    assert (
        audit.json()["entitlement"]["authorization_digest"]
        == first_payload["payload"]["authorization_digest"]
    )
    _assert_protected_binding_integrity(audit.json())
    assert await purchase_api.effect_count() == 1


@pytest.mark.postgres
async def test_postgres_startup_recovers_only_a_durable_approved_handoff(
    reference_postgres_dsn: str,
    tmp_path: Path,
) -> None:
    """Cover crashes immediately before and after the approval outbox commit."""

    policy = SpendPolicy(budget_limit_cents=1_000, approval_threshold_cents=500)
    purchase_api = SqliteReferencePurchaseApi(tmp_path / "handoff-recovery.sqlite")

    def resource(worker_id: str) -> OpenClawResource:
        return build_postgres_openclaw_resource(
            dsn=reference_postgres_dsn,
            purchase_api=purchase_api,
            policy=policy,
            worker_id=worker_id,
            principals={
                "openclaw:buyer-alpha": {
                    "team": "research",
                    "masugate_require_adapter_invocation": True,
                },
                "operator": {"team": "operations", "masugate_operator": True},
            },
            token_principals={
                "buyer-token": "openclaw:buyer-alpha",
                "operator-token": "operator",
            },
            fleet_roster={"agents": {"buyer-alpha": "MASUGATE_BUYER_ALPHA_TOKEN"}},
            plugin_config={"agents": {"buyer-alpha": "MASUGATE_BUYER_ALPHA_TOKEN"}},
            environment={"MASUGATE_BUYER_ALPHA_TOKEN": "buyer-token"},
            operator_principals={"operator"},
        )

    first = resource("postgres-handoff-before")
    await first.initialize()
    pending = await first.service.submit(
        SpendPurchaseRequest(
            principal_id="openclaw:buyer-alpha",
            team_id="research",
            amount_cents=600,
            merchant_id="office-supply",
            request_ref="postgres-handoff-recovery",
            idempotency_key="masugate:v1:postgres-handoff-recovery",
            tool_call_id="postgres-handoff-recovery",
        )
    )
    assert pending.status is SpendOperationStatus.PENDING
    assert pending.entitlement is not None
    entitlement_id = pending.entitlement.entitlement_id
    assert await first.service.store.get_handoff(entitlement_id) is None

    # A restart before the approval transaction commits must not manufacture a
    # handoff or call the connector.
    before_handoff_restart = resource("postgres-handoff-before-restart")
    await before_handoff_restart.initialize()
    assert await before_handoff_restart.service.store.get_handoff(entitlement_id) is None
    assert await purchase_api.effect_count() == 0

    # This is the durable point at the end of approve(), immediately before
    # dispatch(). The following restart must be the only component that creates
    # the generic intent and calls the connector.
    entitlement = await before_handoff_restart.service.store.get_entitlement(entitlement_id)
    resolution = SpendResolution(
        approved=True,
        actor_id="operator",
        evidence={"decision": "approved for recovery test"},
    )
    handoff = await before_handoff_restart.service.store.create_handoff(
        entitlement_id,
        before_handoff_restart.service._binding(replace(entitlement, resolution=resolution)),
        resolution=resolution,
    )
    assert handoff.state is SpendHandoffState.OUTBOX
    assert await purchase_api.effect_count() == 0

    after_handoff_restart = resource("postgres-handoff-after-restart")
    await after_handoff_restart.initialize()
    recovered_handoff = await after_handoff_restart.service.store.get_handoff(entitlement_id)
    assert recovered_handoff is not None
    assert recovered_handoff.state is SpendHandoffState.SUCCEEDED
    assert await purchase_api.effect_count() == 1

    replay = await after_handoff_restart.service.resolve_pending(
        pending.entitlement.pending_id,
        approved=True,
        resolver_id="operator",
        evidence={"decision": "approved for recovery test"},
    )
    assert replay.status is SpendOperationStatus.COMMITTED
    assert await purchase_api.effect_count() == 1


@pytest.mark.postgres
@pytest.mark.gateway_recovery_acceptance
async def test_gateway_recovery_postgres_native_approval_hold_expiry_recovery_and_audit(
    reference_postgres_dsn: str,
    tmp_path: Path,
) -> None:
    """Exercise the durable native-approval boundary on the real deployment DB.

    This acceptance gate deliberately drives only MasuGate's durable resolver
    endpoint semantics.  OpenClaw's native dialog remains a bounded
    presentation adapter: its trusted agent/session evidence is supplied here
    exactly as the pinned plugin emits it, then asserted in the terminal
    receipt.  The separate pinned-host Docker crash matrix remains an explicit
    deployment acceptance item rather than an untested implication of this
    PostgreSQL gate.
    """

    policy = SpendPolicy(budget_limit_cents=1_000, approval_threshold_cents=500)
    purchase_api = SqliteReferencePurchaseApi(tmp_path / "gateway_recovery-purchase.sqlite")
    principals: dict[str, dict[str, Scalar]] = {
        "openclaw:buyer-alpha": {
            "team": "research",
            "masugate_require_adapter_invocation": True,
        },
        "operator": {"team": "operations", "masugate_operator": True},
    }
    tokens = {
        "buyer-token": "openclaw:buyer-alpha",
        "operator-token": "operator",
    }
    native_approval = {
        "agents": {"buyer-alpha": "MASUGATE_BUYER_ALPHA_TOKEN"},
        "nativeApproval": {
            "resolverTokenEnv": "MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN",
            "timeoutMs": 600_000,
        },
    }
    environment = {
        "MASUGATE_BUYER_ALPHA_TOKEN": "buyer-token",
        "MASUGATE_NATIVE_APPROVAL_RESOLVER_TOKEN": "operator-token",
    }

    def resource(worker_id: str) -> OpenClawResource:
        return build_postgres_openclaw_resource(
            dsn=reference_postgres_dsn,
            purchase_api=purchase_api,
            policy=policy,
            worker_id=worker_id,
            principals=principals,
            token_principals=tokens,
            fleet_roster={"agents": {"buyer-alpha": "MASUGATE_BUYER_ALPHA_TOKEN"}},
            plugin_config=native_approval,
            environment=environment,
            operator_principals={"operator"},
        )

    first = resource("gateway_recovery-postgres-first")
    restarted: OpenClawResource | None = None
    await first.initialize()
    try:
        held = await first.service.submit(
            SpendPurchaseRequest(
                principal_id="openclaw:buyer-alpha",
                team_id="research",
                amount_cents=600,
                merchant_id="office-supply",
                request_ref="gateway_recovery-expiry",
                idempotency_key="masugate:v1:gateway_recovery-expiry",
                tool_call_id="gateway_recovery-expiry",
            )
        )
        assert held.status is SpendOperationStatus.PENDING
        assert held.entitlement is not None

        # The held entitlement owns 600 cents, so a second same-budget
        # escalation is denied before any native resolver may decide it.
        competitor = await first.service.submit(
            SpendPurchaseRequest(
                principal_id="openclaw:buyer-alpha",
                team_id="research",
                amount_cents=600,
                merchant_id="office-supply",
                request_ref="gateway_recovery-competitor",
                idempotency_key="masugate:v1:gateway_recovery-competitor",
                tool_call_id="gateway_recovery-competitor",
            )
        )
        assert competitor.status is SpendOperationStatus.DENIED

        deadline = held.entitlement.created_at + timedelta(seconds=policy.approval_timeout_seconds)
        expired = await first.service.expire_pending(now=deadline)
        assert len(expired) == 1
        assert expired[0].status is SpendOperationStatus.DENIED
        assert await purchase_api.effect_count() == 0

        expiry_app = create_spend_reference_app(first)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=expiry_app),
            base_url="http://reference.test",
        ) as client:
            expiry_audit = await client.get(
                f"/v1/audit/{held.entitlement.operation_id}",
                headers={"Authorization": "Bearer operator-token"},
            )
        assert expiry_audit.status_code == 200, expiry_audit.text
        expiry_receipt = expiry_audit.json()
        _validate_protocol("audit.schema.json", expiry_receipt)
        assert expiry_receipt["decision"]["rule_id"] == "approval.expired"
        assert expiry_receipt["automatic_expiry"]["reason"] == "approval-window-expired"
        assert "human_resolution" not in expiry_receipt

        pending = await first.service.submit(
            SpendPurchaseRequest(
                principal_id="openclaw:buyer-alpha",
                team_id="research",
                amount_cents=600,
                merchant_id="office-supply",
                request_ref="gateway_recovery-approved",
                idempotency_key="masugate:v1:gateway_recovery-approved",
                tool_call_id="gateway_recovery-approved",
            )
        )
        assert pending.status is SpendOperationStatus.PENDING
        assert pending.entitlement is not None
        native_evidence: dict[str, JsonValue] = {
            "agent_id": "buyer-alpha",
            "decision": "allow-once",
            "pending_id": pending.entitlement.pending_id,
            "session_id": "gateway_recovery-session-generation",
            "session_key": "agent:buyer-alpha:gateway_recovery",
            "source": "openclaw-native-approval",
        }

        # Two callbacks for the same displayed native approval race through
        # PostgreSQL.  The durable resolution and outbox converge to one
        # protected effect; no callback receives detached authority.
        resolved, replayed = await asyncio.gather(
            first.service.resolve_pending(
                pending.entitlement.pending_id,
                approved=True,
                resolver_id="operator",
                evidence=native_evidence,
            ),
            first.service.resolve_pending(
                pending.entitlement.pending_id,
                approved=True,
                resolver_id="operator",
                evidence=native_evidence,
            ),
        )
        assert resolved.status in {
            SpendOperationStatus.COMMITTED,
            SpendOperationStatus.IN_PROGRESS,
        }
        assert replayed.status in {
            SpendOperationStatus.COMMITTED,
            SpendOperationStatus.IN_PROGRESS,
        }
        # A callback may observe the other worker's unexpired protected lease
        # as in-progress.  It is not a second authority; startup recovery
        # below settles the same persisted handoff to its one terminal effect.
        assert await purchase_api.effect_count() <= 1

        # A new deployment process recovers the same durable handoff, and an
        # idempotent resolver retry remains one external effect.
        restarted = resource("gateway_recovery-postgres-restarted")
        await restarted.initialize()
        after_restart = await restarted.service.resolve_pending(
            pending.entitlement.pending_id,
            approved=True,
            resolver_id="operator",
            evidence=native_evidence,
        )
        assert after_restart.status is SpendOperationStatus.COMMITTED
        assert await purchase_api.effect_count() == 1

        audit_app = create_spend_reference_app(restarted)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=audit_app),
            base_url="http://reference.test",
        ) as client:
            audit = await client.get(
                f"/v1/audit/{pending.entitlement.operation_id}",
                headers={"Authorization": "Bearer operator-token"},
            )
        assert audit.status_code == 200, audit.text
        receipt = audit.json()
        _validate_protocol("audit.schema.json", receipt)
        _assert_protected_binding_integrity(receipt)
        assert receipt["human_resolution"] == {
            "actor_id": "operator",
            "approved": True,
            "evidence": native_evidence,
            "resolved_at": receipt["human_resolution"]["resolved_at"],
        }
        assert receipt["human_resolution"]["evidence"]["agent_id"] == "buyer-alpha"
    finally:
        if restarted is not None:
            await restarted.close()
        await first.close()


def test_postgres_reference_factory_requires_matching_plugin_roster(tmp_path: Path) -> None:
    principals: dict[str, dict[str, Scalar]] = {
        "openclaw:buyer-alpha": {
            "team": "research",
            "masugate_require_adapter_invocation": True,
        },
        "operator": {"team": "operations", "masugate_operator": True},
    }
    tokens = {
        "buyer-secret": "openclaw:buyer-alpha",
        "operator-secret": "operator",
    }
    roster: dict[str, object] = {"agents": {"buyer-alpha": "MASUGATE_BUYER_ALPHA_TOKEN"}}
    plugin_config: dict[str, object] = {"agents": {"buyer-alpha": "MASUGATE_BUYER_ALPHA_TOKEN"}}

    resource = build_postgres_openclaw_resource(
        dsn="postgresql://not-opened",
        purchase_api=SqliteReferencePurchaseApi(tmp_path / "purchase-api.sqlite"),
        policy=SpendPolicy(budget_limit_cents=1_000, approval_threshold_cents=500),
        worker_id="reference-factory-worker",
        principals=principals,
        token_principals=tokens,
        fleet_roster=roster,
        plugin_config=plugin_config,
        environment={"MASUGATE_BUYER_ALPHA_TOKEN": "buyer-secret"},
        operator_principals={"operator"},
    )
    assert resource.owner.provider_id == "masugate.spend.reference"

    with pytest.raises(ValueError, match="distinct from every MasuGate bearer credential"):
        ReferencePurchaseCredentialManifest.from_credentials(
            connector_service_token="buyer-secret",
            masugate_bearer_credentials=tuple(tokens),
        )

    plugin_config["agents"] = {"buyer-alpha": "MASUGATE_WRONG_TOKEN"}
    with pytest.raises(ValueError, match="does not match plugin credential bindings"):
        build_postgres_openclaw_resource(
            dsn="postgresql://not-opened",
            purchase_api=SqliteReferencePurchaseApi(tmp_path / "other-api.sqlite"),
            policy=SpendPolicy(budget_limit_cents=1_000, approval_threshold_cents=500),
            worker_id="reference-factory-worker",
            principals=principals,
            token_principals=tokens,
            fleet_roster=roster,
            plugin_config=plugin_config,
            environment={"MASUGATE_BUYER_ALPHA_TOKEN": "buyer-secret"},
            operator_principals={"operator"},
        )


async def test_authenticated_connector_rejects_a_malformed_binding_payload(
    tmp_path: Path,
) -> None:
    policy = SpendPolicy(budget_limit_cents=1_000, approval_threshold_cents=500)
    backend = SqliteReferencePurchaseApi(tmp_path / "malformed-purchase.sqlite")
    await backend.initialize()
    app = create_reference_purchase_api_app(
        backend,
        service_token="connector-service-secret",
        credential_manifest=_credential_manifest(),
    )
    binding = ProtectedExecutionBinding(
        principal_id="openclaw:buyer-alpha",
        action="spend.purchase",
        arguments={"amount_cents": 100, "merchant_id": "office-supply", "request_ref": "x"},
        idempotency_key="masugate:v1:malformed-binding",
        policies=(
            PolicyBinding(
                policy_id="spend_budget_guard",
                policy_version="v1",
                policy_digest="a" * 64,
                bundle_id="test-bundle",
                bundle_version="v1",
                bundle_digest="b" * 64,
            ),
        ),
        provider_identity=policy.provider_identity,
        coordination_domain_id="masugate.spend.reference.domain.v1",
        scopes=("spend:team:research",),
        tool_call_id="malformed-binding-call",
        connector_id="reference-purchase-v1",
        entitlement_id="entitlement:malformed-binding",
        authorization_digest="c" * 64,
    )
    payload = binding.payload()
    payload["arguments"] = None

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://purchase.test",
    ) as client:
        response = await client.post(
            "/v1/purchases/execute",
            json={"binding": payload, "fence_token": 1, "idempotency_key": binding.idempotency_key},
            headers={"Authorization": "Bearer connector-service-secret"},
        )

    assert response.status_code == 409, response.text
    assert await backend.effect_count() == 0
