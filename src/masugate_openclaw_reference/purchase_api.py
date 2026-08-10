"""Authenticated network adapter for the bounded reference purchase connector.

The provider package owns the connector protocol and local oracle.  This thin
FastAPI process turns that protocol into a separately deployable service while
keeping the bearer token strictly server-to-server: agent action credentials
never reach this application.
"""

from __future__ import annotations

import secrets
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from masugate.errors import ContractError
from masugate.model import JsonValue
from masugate.protected_execution import ConnectorContractError, ConnectorOutcomeUnknown
from masugate.providers import (
    ReferencePurchaseApi,
    ReferencePurchaseCredentialManifest,
    reference_purchase_binding_from_payload,
    reference_purchase_evidence_payload,
)


class _ServiceUnauthorized(Exception):
    """A caller did not present the deployment-local connector credential."""


def _error(code: str, message: str) -> dict[str, JsonValue]:
    return {"error": {"code": code, "message": message}}


def _payload(
    body: Mapping[str, JsonValue],
) -> tuple[dict[str, JsonValue], str, int | None, str | None]:
    binding = body.get("binding")
    idempotency_key = body.get("idempotency_key")
    fence_token = body.get("fence_token")
    external_operation_id = body.get("external_operation_id")
    if not isinstance(binding, dict) or not isinstance(idempotency_key, str):
        raise ContractError("reference purchase request has malformed binding identity")
    if fence_token is not None and (type(fence_token) is not int or fence_token < 0):
        raise ContractError("reference purchase request has malformed fence token")
    if external_operation_id is not None and not isinstance(external_operation_id, str):
        raise ContractError("reference purchase request has malformed external operation identity")
    return (
        binding,
        idempotency_key,
        fence_token,
        external_operation_id,
    )


def create_reference_purchase_api_app(
    api: ReferencePurchaseApi,
    *,
    service_token: str,
    credential_manifest: ReferencePurchaseCredentialManifest,
) -> FastAPI:
    """Expose a private authenticated transport for one reference connector."""

    if (
        not isinstance(service_token, str)
        or not service_token
        or service_token.strip() != service_token
    ):
        raise ValueError("reference purchase service token must be non-empty")
    if not isinstance(credential_manifest, ReferencePurchaseCredentialManifest):
        raise TypeError("reference purchase service needs a credential manifest")
    if not credential_manifest.validates_connector_credential(service_token):
        raise ValueError("reference purchase service token does not match the credential manifest")

    def authenticate(authorization: str | None) -> None:
        if authorization is None or not authorization.startswith("Bearer "):
            raise _ServiceUnauthorized("missing connector service credential")
        token = authorization.removeprefix("Bearer ")
        if not token or not secrets.compare_digest(token, service_token):
            raise _ServiceUnauthorized("invalid connector service credential")

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            await api.initialize()
            yield
        finally:
            await api.close()

    app = FastAPI(
        title="masugate-reference-purchase-api",
        version="2.2.0",
        lifespan=lifespan,
    )

    @app.exception_handler(_ServiceUnauthorized)
    async def unauthorized(_request: Request, exc: _ServiceUnauthorized) -> JSONResponse:
        return JSONResponse(status_code=401, content=_error("unauthorized", str(exc)))

    @app.exception_handler(ContractError)
    async def contract_error(_request: Request, exc: ContractError) -> JSONResponse:
        return JSONResponse(status_code=409, content=_error("connector_conflict", str(exc)))

    @app.exception_handler(ConnectorContractError)
    async def connector_error(_request: Request, exc: ConnectorContractError) -> JSONResponse:
        return JSONResponse(status_code=409, content=_error("connector_contract", str(exc)))

    @app.get("/v1/health")
    async def health(authorization: Annotated[str | None, Header()] = None) -> dict[str, str]:
        authenticate(authorization)
        return {
            "status": "ok",
            "credential_manifest_digest": credential_manifest.digest,
        }

    @app.post("/v1/purchases/execute")
    async def execute(
        body: dict[str, JsonValue],
        authorization: Annotated[str | None, Header()] = None,
    ) -> JSONResponse:
        authenticate(authorization)
        raw_binding, idempotency_key, fence_token, _ = _payload(body)
        if fence_token is None:
            raise ContractError("reference purchase execute requires a fence token")
        binding = reference_purchase_binding_from_payload(raw_binding)
        try:
            evidence = await api.execute(
                binding,
                idempotency_key=idempotency_key,
                fence_token=fence_token,
            )
        except ConnectorOutcomeUnknown as exc:
            return JSONResponse(
                status_code=202,
                content={"external_operation_id": exc.external_operation_id},
            )
        return JSONResponse(status_code=200, content=reference_purchase_evidence_payload(evidence))

    @app.post("/v1/purchases/query-status")
    async def query_status(
        body: dict[str, JsonValue],
        authorization: Annotated[str | None, Header()] = None,
    ) -> JSONResponse:
        authenticate(authorization)
        raw_binding, idempotency_key, _, external_operation_id = _payload(body)
        evidence = await api.query_status(
            reference_purchase_binding_from_payload(raw_binding),
            idempotency_key=idempotency_key,
            external_operation_id=external_operation_id,
        )
        return JSONResponse(status_code=200, content=reference_purchase_evidence_payload(evidence))

    @app.post("/v1/purchases/cancel")
    async def cancel(
        body: dict[str, JsonValue],
        authorization: Annotated[str | None, Header()] = None,
    ) -> JSONResponse:
        authenticate(authorization)
        raw_binding, idempotency_key, _, external_operation_id = _payload(body)
        evidence = await api.cancel(
            reference_purchase_binding_from_payload(raw_binding),
            idempotency_key=idempotency_key,
            external_operation_id=external_operation_id,
        )
        return JSONResponse(status_code=200, content=reference_purchase_evidence_payload(evidence))

    return app


__all__ = ["create_reference_purchase_api_app"]
