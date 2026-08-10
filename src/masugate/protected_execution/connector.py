"""Trusted connector protocol for the bounded protected-execution external path."""

from __future__ import annotations

from typing import Protocol

from masugate_connector_sdk import ConnectorCapabilities

from masugate.protected_execution.model import ConnectorEvidence, ProtectedExecutionBinding


class ProtectedConnector(Protocol):
    """Provider-owned adapter; methods perform network I/O outside DB transactions."""

    connector_id: str
    capabilities: ConnectorCapabilities

    async def execute(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        fence_token: int,
    ) -> ConnectorEvidence: ...

    async def query_status(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        external_operation_id: str | None,
    ) -> ConnectorEvidence: ...

    async def cancel(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        external_operation_id: str | None,
    ) -> ConnectorEvidence: ...


__all__ = ["ConnectorCapabilities", "ProtectedConnector"]
