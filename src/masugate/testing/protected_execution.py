"""Connector and lifecycle conformance kit for protected execution recovery."""

from __future__ import annotations

import sqlite3
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Protocol

from masugate.contracts import ProviderIdentity
from masugate.protected_execution import (
    ConnectorCapabilities,
    ConnectorContractError,
    ConnectorEvidence,
    ConnectorOutcome,
    ConnectorOutcomeUnknown,
    EntitlementState,
    PolicyBinding,
    ProtectedConnector,
    ProtectedExecutionAuthority,
    ProtectedExecutionBinding,
    ProtectedExecutionRecord,
    ProtectedExecutionRunner,
    ProtectedExecutionStatus,
    ProtectedExecutionStore,
    SqliteProtectedExecutionStore,
)


class ProtectedExecutionConformanceError(AssertionError):
    """A connector/lifecycle integration violated the crash-safety contract."""


class ConformanceConnector(ProtectedConnector, Protocol):
    dispatch_count: int
    effect_count: int


class ProtectedExecutionConformanceProbe(Protocol):
    name: str

    def store(self, path: Path) -> ProtectedExecutionStore: ...

    def success_connector(self) -> ConformanceConnector: ...

    def unknown_connector(self) -> ConformanceConnector: ...

    def runner(
        self,
        store: ProtectedExecutionStore,
        connector: ConformanceConnector,
        *,
        worker_id: str,
    ) -> ProtectedExecutionRunner: ...


@dataclass(frozen=True)
class ProtectedExecutionConformanceReport:
    probe_name: str
    checks: tuple[str, ...]


def conformance_binding(suffix: str) -> ProtectedExecutionBinding:
    return ProtectedExecutionBinding(
        principal_id="conformance-agent",
        action="reference.purchase",
        arguments={"item": "paper", "quantity": 1},
        idempotency_key=f"conformance-operation:{suffix}",
        policies=(
            PolicyBinding(
                policy_id="conformance_guard",
                policy_version="1.0.0",
                policy_digest="c" * 64,
                bundle_id="masugate.conformance",
                bundle_version="1.0.0",
                bundle_digest="d" * 64,
            ),
        ),
        provider_identity=ProviderIdentity(
            provider_id="masugate.reference.purchase",
            implementation_version="reference-purchase-v1",
            configuration_version="reference-purchase-config-v1",
        ),
        coordination_domain_id="reference-domain",
        scopes=("budget:conformance", "item:paper"),
        tool_call_id=f"conformance-tool:{suffix}",
        connector_id="reference-purchase-v1",
        entitlement_id=f"conformance-entitlement:{suffix}",
    )


def conformance_authority() -> ProtectedExecutionAuthority:
    binding = conformance_binding("authority")
    return ProtectedExecutionAuthority(
        action=binding.action,
        provider_identity=binding.provider_identity,
        coordination_domain_id=binding.coordination_domain_id,
        connector_id=binding.connector_id,
    )


class ReferenceProtectedConnector:
    connector_id = "reference-purchase-v1"
    capabilities = ConnectorCapabilities(True, True, True)

    def __init__(self, *, unknown: bool = False) -> None:
        self.unknown = unknown
        self.dispatch_count = 0
        self.effect_count = 0
        self._evidence: dict[str, ConnectorEvidence] = {}
        self._highest_fence: dict[str, int] = {}

    def _receipt(
        self,
        binding: ProtectedExecutionBinding,
        outcome: ConnectorOutcome,
        fence_token: int,
    ) -> ConnectorEvidence:
        return ConnectorEvidence(
            connector_id=self.connector_id,
            evidence_id=f"conformance-receipt:{fence_token}:{outcome.value}",
            idempotency_key=binding.provider_idempotency_key,
            external_operation_id=f"conformance-remote:{binding.digest[:16]}",
            outcome=outcome,
            observed_at=datetime(2026, 7, 13, 13, 0, tzinfo=UTC),
            payload={"fence_token": fence_token, "outcome": outcome.value},
        )

    async def execute(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        fence_token: int,
    ) -> ConnectorEvidence:
        if idempotency_key != binding.provider_idempotency_key:
            raise ConnectorContractError("connector received wrong idempotency key")
        highest = self._highest_fence.get(idempotency_key)
        if highest is not None and fence_token < highest:
            raise ConnectorContractError("connector rejected stale fence")
        self._highest_fence[idempotency_key] = max(fence_token, highest or fence_token)
        existing = self._evidence.get(idempotency_key)
        if existing is not None:
            return existing
        self.dispatch_count += 1
        if self.unknown:
            raise ConnectorOutcomeUnknown("conformance unknown outcome")
        evidence = self._receipt(binding, ConnectorOutcome.SUCCEEDED, fence_token)
        self._evidence[idempotency_key] = evidence
        self.effect_count += 1
        return evidence

    async def query_status(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        external_operation_id: str | None,
    ) -> ConnectorEvidence:
        del external_operation_id
        existing = self._evidence.get(idempotency_key)
        if existing is not None:
            return existing
        return ConnectorEvidence(
            connector_id=self.connector_id,
            evidence_id="conformance-status:unknown",
            idempotency_key=binding.provider_idempotency_key,
            external_operation_id=None,
            outcome=ConnectorOutcome.UNKNOWN,
            observed_at=datetime(2026, 7, 13, 13, 1, tzinfo=UTC),
            payload={"status": "unknown"},
        )

    async def cancel(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        external_operation_id: str | None,
    ) -> ConnectorEvidence:
        del external_operation_id
        existing = self._evidence.get(idempotency_key)
        if existing is not None:
            return existing
        return ConnectorEvidence(
            connector_id=self.connector_id,
            evidence_id="conformance-cancel:unknown",
            idempotency_key=binding.provider_idempotency_key,
            external_operation_id=None,
            outcome=ConnectorOutcome.UNKNOWN,
            observed_at=datetime(2026, 7, 13, 13, 1, tzinfo=UTC),
            payload={"cancellation": "unknown"},
        )


class ReferenceProtectedExecutionProbe:
    name = "reference-protected-execution"

    def store(self, path: Path) -> ProtectedExecutionStore:
        return SqliteProtectedExecutionStore(path)

    def success_connector(self) -> ConformanceConnector:
        return ReferenceProtectedConnector()

    def unknown_connector(self) -> ConformanceConnector:
        return ReferenceProtectedConnector(unknown=True)

    def runner(
        self,
        store: ProtectedExecutionStore,
        connector: ConformanceConnector,
        *,
        worker_id: str,
    ) -> ProtectedExecutionRunner:
        return ProtectedExecutionRunner(
            store,
            connector,
            conformance_authority(),
            worker_id=worker_id,
            lease_duration=timedelta(seconds=10),
            clock=lambda: datetime(2026, 7, 13, 13, 2, tzinfo=UTC),
        )


class _BadIdempotencyConnector(ReferenceProtectedConnector):
    async def execute(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        fence_token: int,
    ) -> ConnectorEvidence:
        self._evidence.pop(idempotency_key, None)
        return await super().execute(
            binding,
            idempotency_key=idempotency_key,
            fence_token=fence_token,
        )


class BadIdempotencyProbe(ReferenceProtectedExecutionProbe):
    name = "bad-idempotency"

    def success_connector(self) -> ConformanceConnector:
        return _BadIdempotencyConnector()


class _BadFenceConnector(ReferenceProtectedConnector):
    async def execute(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        fence_token: int,
    ) -> ConnectorEvidence:
        self._highest_fence.pop(idempotency_key, None)
        return await super().execute(
            binding,
            idempotency_key=idempotency_key,
            fence_token=fence_token,
        )


class BadFenceProbe(ReferenceProtectedExecutionProbe):
    name = "bad-fence"

    def success_connector(self) -> ConformanceConnector:
        return _BadFenceConnector()


class _FalseFailureConnector(ReferenceProtectedConnector):
    async def query_status(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        external_operation_id: str | None,
    ) -> ConnectorEvidence:
        del idempotency_key, external_operation_id
        return self._receipt(binding, ConnectorOutcome.FAILED, 2)


class FalseFailureProbe(ReferenceProtectedExecutionProbe):
    name = "false-failure"

    def success_connector(self) -> ConformanceConnector:
        return _FalseFailureConnector()


class _ExternalOperationDriftConnector(ReferenceProtectedConnector):
    async def query_status(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        external_operation_id: str | None,
    ) -> ConnectorEvidence:
        evidence = await super().query_status(
            binding,
            idempotency_key=idempotency_key,
            external_operation_id=external_operation_id,
        )
        return replace(
            evidence,
            evidence_id=f"{evidence.evidence_id}:identity-drift",
            external_operation_id="conformance-remote:replacement",
        )


class ExternalOperationDriftProbe(ReferenceProtectedExecutionProbe):
    name = "external-operation-drift"

    def success_connector(self) -> ConformanceConnector:
        return _ExternalOperationDriftConnector()


class _UnknownReleaseStore(SqliteProtectedExecutionStore):
    async def mark_outcome_unknown(
        self,
        execution_id: str,
        *,
        worker_id: str,
        fence_token: int,
        now: datetime,
        reason: str,
        external_operation_id: str | None = None,
    ) -> ProtectedExecutionRecord:
        await super().mark_outcome_unknown(
            execution_id,
            worker_id=worker_id,
            fence_token=fence_token,
            now=now,
            reason=reason,
            external_operation_id=external_operation_id,
        )
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                "UPDATE protected_executions SET entitlement_state = 'released' "
                "WHERE execution_id = ?",
                (execution_id,),
            )
            connection.commit()
        finally:
            connection.close()
        return await self.get(execution_id)


class UnknownReleaseProbe(ReferenceProtectedExecutionProbe):
    name = "unknown-release"

    def store(self, path: Path) -> ProtectedExecutionStore:
        return _UnknownReleaseStore(path)


class _UnknownRetryRunner(ProtectedExecutionRunner):
    async def start(
        self,
        binding: ProtectedExecutionBinding,
    ) -> ProtectedExecutionRecord:
        record = await super().start(binding)
        if record.status is ProtectedExecutionStatus.OUTCOME_UNKNOWN:
            with suppress(ConnectorOutcomeUnknown):
                await self.connector.execute(
                    binding,
                    idempotency_key=binding.provider_idempotency_key,
                    fence_token=record.fence_token + 1,
                )
        return record


class UnknownRetryProbe(ReferenceProtectedExecutionProbe):
    name = "unknown-retry"

    def runner(
        self,
        store: ProtectedExecutionStore,
        connector: ConformanceConnector,
        *,
        worker_id: str,
    ) -> ProtectedExecutionRunner:
        return _UnknownRetryRunner(
            store,
            connector,
            conformance_authority(),
            worker_id=worker_id,
            clock=lambda: datetime(2026, 7, 13, 13, 2, tzinfo=UTC),
        )


async def run_protected_execution_conformance(
    probe: ProtectedExecutionConformanceProbe,
) -> ProtectedExecutionConformanceReport:
    checks: list[str] = []
    try:
        direct = probe.success_connector()
        if not (direct.capabilities.idempotent_dispatch and direct.capabilities.status_query):
            raise ProtectedExecutionConformanceError(
                "connector must support idempotent dispatch and status query"
            )
        binding = conformance_binding("connector")
        first = await direct.execute(
            binding,
            idempotency_key=binding.provider_idempotency_key,
            fence_token=2,
        )
        replay = await direct.execute(
            binding,
            idempotency_key=binding.provider_idempotency_key,
            fence_token=2,
        )
        if first != replay or direct.effect_count != 1:
            raise ProtectedExecutionConformanceError("connector ignored idempotency")
        checks.append("idempotent-dispatch")
        try:
            await direct.execute(
                binding,
                idempotency_key=binding.provider_idempotency_key,
                fence_token=1,
            )
        except ConnectorContractError:
            pass
        else:
            raise ProtectedExecutionConformanceError("connector accepted a stale fence")
        checks.append("stale-fence-rejection")
        status = await direct.query_status(
            binding,
            idempotency_key=binding.provider_idempotency_key,
            external_operation_id=first.external_operation_id,
        )
        if status.outcome is not first.outcome:
            raise ProtectedExecutionConformanceError("connector reported false terminal status")
        checks.append("truthful-status")
        if status.external_operation_id != first.external_operation_id:
            raise ProtectedExecutionConformanceError(
                "connector changed external-operation identity"
            )
        checks.append("external-operation-identity")

        with TemporaryDirectory(prefix="masugate-protected-conformance-") as directory:
            success_store = probe.store(Path(directory) / "success.sqlite3")
            await success_store.initialize()
            success_connector = probe.success_connector()
            success_runner = probe.runner(
                success_store,
                success_connector,
                worker_id="conformance-success",
            )
            success = await success_runner.start(conformance_binding("success"))
            if (
                success.status is not ProtectedExecutionStatus.SUCCEEDED
                or success.entitlement_state is not EntitlementState.CONSUMED
            ):
                raise ProtectedExecutionConformanceError(
                    "successful connector did not consume exactly one entitlement"
                )
            checks.append("success-accounting")

            unknown_store = probe.store(Path(directory) / "unknown.sqlite3")
            await unknown_store.initialize()
            unknown_connector = probe.unknown_connector()
            unknown_runner = probe.runner(
                unknown_store,
                unknown_connector,
                worker_id="conformance-unknown",
            )
            unknown_binding = conformance_binding("unknown")
            unknown = await unknown_runner.start(unknown_binding)
            replayed = await unknown_runner.start(unknown_binding)
            reconciled = await unknown_runner.reconcile(unknown.execution_id)
            if any(
                record.status is not ProtectedExecutionStatus.OUTCOME_UNKNOWN
                or record.entitlement_state is not EntitlementState.QUARANTINED
                for record in (unknown, replayed, reconciled)
            ):
                raise ProtectedExecutionConformanceError(
                    "uncertain outcome released or terminalized its entitlement"
                )
            if unknown_connector.dispatch_count != 1:
                raise ProtectedExecutionConformanceError(
                    "uncertain outcome was automatically redispatched"
                )
            checks.append("unknown-quarantine-no-retry")
    except ProtectedExecutionConformanceError:
        raise
    except Exception as exc:
        raise ProtectedExecutionConformanceError(
            f"protected execution probe {probe.name!r} failed: {type(exc).__name__}"
        ) from exc
    return ProtectedExecutionConformanceReport(probe_name=probe.name, checks=tuple(checks))


__all__ = [
    "BadFenceProbe",
    "BadIdempotencyProbe",
    "ConformanceConnector",
    "ExternalOperationDriftProbe",
    "FalseFailureProbe",
    "ProtectedExecutionConformanceError",
    "ProtectedExecutionConformanceProbe",
    "ProtectedExecutionConformanceReport",
    "ReferenceProtectedConnector",
    "ReferenceProtectedExecutionProbe",
    "UnknownReleaseProbe",
    "UnknownRetryProbe",
    "conformance_authority",
    "conformance_binding",
    "run_protected_execution_conformance",
]
