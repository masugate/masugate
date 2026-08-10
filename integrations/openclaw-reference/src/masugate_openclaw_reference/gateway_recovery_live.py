"""Process entry points and deterministic crash hooks for the gateway recovery live gate.

This module is deliberately deployment-owned.  It is not imported by the
reusable ``masugate`` package and exists solely to make the pinned OpenClaw Docker
acceptance matrix exercise the same PostgreSQL reference resource as the
reference spend/2.4 tests.  The pause hooks model process death at the three durable
handoff boundaries; the oracle kills the process rather than releasing them.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Literal, cast

import uvicorn
from fastapi import FastAPI

from masugate.model import Scalar
from masugate.protected_execution import ConnectorEvidence, ProtectedExecutionBinding
from masugate.providers import (
    HttpReferencePurchaseApi,
    ReferencePurchaseCredentialManifest,
    SpendHandoff,
    SpendOutboxStore,
    SpendPolicy,
    SpendResolution,
    SqliteReferencePurchaseApi,
)
from masugate_openclaw_reference.deployment import build_postgres_reference_spend_resource
from masugate_openclaw_reference.purchase_api import create_reference_purchase_api_app

_ROLE = Literal["masugated", "purchase"]
_HAZARDS = frozenset({"before-handoff", "after-handoff", "after-provider"})
_CREDENTIAL_MANIFEST_ENV = "MASUGATE_REFERENCE_CREDENTIAL_MANIFEST_JSON"


def _required(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value or value.strip() != value:
        raise RuntimeError(f"{name} must be a non-empty environment value")
    return value


def _state_root() -> Path:
    root = Path(_required("MASUGATE_GATEWAY_RECOVERY_STATE_ROOT"))
    if not root.is_absolute():
        raise RuntimeError("MASUGATE_GATEWAY_RECOVERY_STATE_ROOT must be absolute")
    root.mkdir(parents=True, exist_ok=True)
    return root


def _hazard() -> str | None:
    value = os.environ.get("MASUGATE_GATEWAY_RECOVERY_HAZARD", "").strip()
    if not value:
        return None
    if value not in _HAZARDS:
        raise RuntimeError(f"unknown gateway recovery crash hazard: {value}")
    return value


def _claim_one_shot_hazard(hazard: str) -> bool:
    """Atomically reserve one named crash point in the disposable state root."""

    claimed = _state_root() / f"gateway_recovery-{hazard}.claimed"
    try:
        with claimed.open("x", encoding="utf-8") as handle:
            handle.write("claimed\n")
    except FileExistsError:
        return False
    return True


async def _pause_at(hazard: str) -> None:
    """Publish a durable observability marker and wait only for the test kill.

    A named hazard is deliberately one-shot per disposable live state root.
    The durable claim is written *before* pausing, so a restart recovers past
    that boundary rather than re-arming the same artificial crash forever.
    The live oracle never creates the matching release file: the first process
    that reaches a claimed marker must be killed, proving recovery from the
    real boundary instead of timing a synthetic exception.
    """

    if not _claim_one_shot_hazard(hazard):
        return
    marker = _state_root() / f"gateway_recovery-{hazard}.ready"
    marker.write_text("ready\n", encoding="utf-8")
    release = _state_root() / f"gateway_recovery-{hazard}.release"
    while not release.exists():
        await asyncio.sleep(0.05)


class _HandoffPauseStore:
    """Delegate the real PostgreSQL store while exposing handoff crash points."""

    def __init__(self, store: SpendOutboxStore, hazard: str | None) -> None:
        self._store = store
        self._hazard = hazard

    def __getattr__(self, name: str) -> object:
        return getattr(self._store, name)

    async def create_handoff(
        self,
        entitlement_id: str,
        binding: ProtectedExecutionBinding,
        *,
        resolution: SpendResolution | None = None,
    ) -> SpendHandoff:
        if self._hazard == "before-handoff":
            await _pause_at("before-handoff")
        handoff = await self._store.create_handoff(entitlement_id, binding, resolution=resolution)
        if self._hazard == "after-handoff":
            await _pause_at("after-handoff")
        return handoff


class _ProviderPauseApi:
    """Delegate the real authenticated purchase API with an after-effect hook."""

    def __init__(self, api: HttpReferencePurchaseApi, hazard: str | None) -> None:
        self._api = api
        self._hazard = hazard

    @property
    def credential_fingerprint(self) -> str:
        return self._api.credential_fingerprint

    @property
    def credential_manifest(self) -> ReferencePurchaseCredentialManifest:
        return self._api.credential_manifest

    async def initialize(self) -> None:
        await self._api.initialize()

    async def close(self) -> None:
        await self._api.close()

    async def execute(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        fence_token: int,
    ) -> ConnectorEvidence:
        evidence = await self._api.execute(
            binding,
            idempotency_key=idempotency_key,
            fence_token=fence_token,
        )
        if self._hazard == "after-provider":
            await _pause_at("after-provider")
        return evidence

    async def query_status(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        external_operation_id: str | None,
    ) -> ConnectorEvidence:
        return await self._api.query_status(
            binding,
            idempotency_key=idempotency_key,
            external_operation_id=external_operation_id,
        )

    async def cancel(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        external_operation_id: str | None,
    ) -> ConnectorEvidence:
        return await self._api.cancel(
            binding,
            idempotency_key=idempotency_key,
            external_operation_id=external_operation_id,
        )


def _credential_manifest() -> ReferencePurchaseCredentialManifest:
    """Load the non-secret connector/action identity manifest.

    The protected purchase process receives this already-computed manifest,
    rather than the Gateway's buyer or native-resolver credentials merely to
    derive their fingerprints at startup.
    """

    try:
        raw = json.loads(_required(_CREDENTIAL_MANIFEST_ENV))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{_CREDENTIAL_MANIFEST_ENV} must be valid JSON") from exc
    if not isinstance(raw, dict) or set(raw) != {
        "connector_credential_fingerprint",
        "masugate_bearer_credential_fingerprints",
    }:
        raise RuntimeError(f"{_CREDENTIAL_MANIFEST_ENV} has an invalid shape")
    connector = raw["connector_credential_fingerprint"]
    bearers = raw["masugate_bearer_credential_fingerprints"]
    if (
        not isinstance(connector, str)
        or not isinstance(bearers, list)
        or any(not isinstance(value, str) for value in bearers)
    ):
        raise RuntimeError(f"{_CREDENTIAL_MANIFEST_ENV} has invalid credential fingerprints")
    try:
        return ReferencePurchaseCredentialManifest(
            connector_credential_fingerprint=connector,
            masugate_bearer_credential_fingerprints=tuple(bearers),
        )
    except ValueError as exc:
        raise RuntimeError(
            f"{_CREDENTIAL_MANIFEST_ENV} is not a valid credential manifest"
        ) from exc


def _purchase_credentials() -> tuple[str, ReferencePurchaseCredentialManifest]:
    connector = _required("REFERENCE_PURCHASE_SERVICE_TOKEN")
    manifest = _credential_manifest()
    if not manifest.validates_connector_credential(connector):
        raise RuntimeError("reference purchase connector credential does not match its manifest")
    return connector, manifest


def _reference_demo_demo_enabled() -> bool:
    """Return whether this explicit deployment enables the second demo buyer.

    The extra fleet identity exists only for the disposable reference demonstration
    procurement race.  Keeping it opt-in preserves the reviewed 2.4
    acceptance topology exactly, rather than silently widening its fleet.
    """

    value = os.environ.get("MASUGATE_REFERENCE_DEMO_DEMO", "")
    if value not in {"", "1"}:
        raise RuntimeError("MASUGATE_REFERENCE_DEMO_DEMO must be empty or the literal 1")
    return value == "1"


def _masugated_credentials() -> (
    tuple[str, str | None, str, str, ReferencePurchaseCredentialManifest]
):
    buyer = _required("MASUGATE_BUYER_ALPHA_TOKEN")
    beta = _required("MASUGATE_BUYER_BETA_TOKEN") if _reference_demo_demo_enabled() else None
    resolver = _required("MASUGATE_RESOLVER_TOKEN")
    connector, manifest = _purchase_credentials()
    bearer_credentials = (buyer, resolver) if beta is None else (buyer, beta, resolver)
    expected = ReferencePurchaseCredentialManifest.from_credentials(
        connector_service_token=connector,
        masugate_bearer_credentials=bearer_credentials,
    )
    if manifest != expected:
        raise RuntimeError(
            "gateway recovery credential manifest does not match MasuGate deployment credentials"
        )
    return buyer, beta, resolver, connector, manifest


def _purchase_state_root() -> Path:
    root = Path(_required("MASUGATE_GATEWAY_RECOVERY_PURCHASE_STATE_ROOT"))
    if not root.is_absolute():
        raise RuntimeError("MASUGATE_GATEWAY_RECOVERY_PURCHASE_STATE_ROOT must be absolute")
    root.mkdir(parents=True, exist_ok=True)
    return root


def _purchase_app() -> FastAPI:
    connector, manifest = _purchase_credentials()
    return create_reference_purchase_api_app(
        SqliteReferencePurchaseApi(_purchase_state_root() / "reference-purchases.sqlite"),
        service_token=connector,
        credential_manifest=manifest,
    )


def _masugated_app() -> FastAPI:
    buyer, beta, resolver, connector, manifest = _masugated_credentials()
    agents = {"buyer-alpha": "MASUGATE_BUYER_ALPHA_TOKEN"}
    principals: dict[str, dict[str, Scalar]] = {
        "openclaw:buyer-alpha": {
            "team": "research",
            "masugate_require_adapter_invocation": True,
        },
        "operator": {"team": "operations", "masugate_operator": True},
    }
    token_principals = {buyer: "openclaw:buyer-alpha", resolver: "operator"}
    if beta is not None:
        agents["buyer-beta"] = "MASUGATE_BUYER_BETA_TOKEN"
        principals["openclaw:buyer-beta"] = {
            "team": "research",
            "masugate_require_adapter_invocation": True,
        }
        token_principals[beta] = "openclaw:buyer-beta"
    plugin_config: dict[str, object] = {
        "masugatedBaseUrl": "http://masugated:8000",
        "agents": agents,
        "routes": {
            "purchase": {
                "action": "spend.purchase",
                "arguments": {
                    "amount_cents": "integer",
                    "merchant_id": "string",
                    "request_ref": "string",
                },
                "owner": {
                    "providerId": "masugate.spend.reference",
                    "position": "protected-external",
                    "connectorId": "reference-purchase-v1",
                },
            }
        },
        "nativeApproval": {"resolverTokenEnv": "MASUGATE_RESOLVER_TOKEN", "timeoutMs": 600_000},
    }
    resource = build_postgres_reference_spend_resource(
        dsn=_required("MASUGATE_POSTGRES_DSN"),
        purchase_api=_ProviderPauseApi(
            HttpReferencePurchaseApi(
                "http://reference-purchase:8081",
                service_token=connector,
                credential_manifest=manifest,
            ),
            _hazard(),
        ),
        policy=SpendPolicy(
            budget_limit_cents=10_000,
            approval_threshold_cents=500,
            approval_timeout_seconds=600,
        ),
        worker_id="gateway_recovery-pinned-gateway-runner",
        principals=principals,
        token_principals=token_principals,
        fleet_roster={"agents": agents},
        plugin_config=plugin_config,
        environment=os.environ,
        operator_principals={"operator"},
    )
    # The interface is intentionally structural: only create_handoff is
    # wrapped, and every other provider operation remains the real store.
    resource.service.store = cast(
        SpendOutboxStore, _HandoffPauseStore(resource.service.store, _hazard())
    )
    from masugate_openclaw_reference.deployment import create_spend_reference_app

    return create_spend_reference_app(resource)


def main(argv: list[str] | None = None) -> None:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1 or arguments[0] not in {"masugated", "purchase"}:
        raise SystemExit(
            "usage: python -m masugate_openclaw_reference.gateway_recovery_live "
            "{masugated|purchase}"
        )
    role = cast(_ROLE, arguments[0])
    app = _masugated_app() if role == "masugated" else _purchase_app()
    uvicorn.run(app, host="0.0.0.0", port=8000 if role == "masugated" else 8081)


if __name__ == "__main__":
    main()
