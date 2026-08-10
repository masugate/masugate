"""Connector-only execution bridge for committed protected handoffs.

The worker deliberately composes the established fenced protected-execution
runner instead of adding a second lifecycle.  Its additional durable handoff
record supplies only deployment-certified connector configuration, sealed
artifact metadata, and mounted credential references; no API route or model
input can invoke an operation connector directly.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import sqlite3
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast

from masugate_connector_sdk import (
    SDK_CONTRACT_VERSION,
    ArtifactDescriptor,
    ConnectorAmbiguousOutcome,
    ConnectorCapabilities,
    ConnectorInvocation,
    OperationConnector,
    validate_operation_connector,
)
from masugate_connector_sdk import (
    ArtifactReader as ConnectorArtifactReader,
)
from masugate_connector_sdk import (
    ConnectorEvidence as ConnectorEvidence,
)
from masugate_connector_sdk import (
    ConnectorOutcome as ConnectorOutcome,
)

from masugate.contracts import ProviderIdentity
from masugate.errors import ContractError
from masugate.model import JsonValue
from masugate.protected_execution import (
    ConnectorEvidence as ProtectedConnectorEvidence,
)
from masugate.protected_execution import (
    ConnectorOutcome as ProtectedConnectorOutcome,
)
from masugate.protected_execution import (
    ProtectedConnector,
    ProtectedExecutionAuthority,
    ProtectedExecutionBinding,
    ProtectedExecutionError,
    ProtectedExecutionRecord,
    ProtectedExecutionRecovery,
    ProtectedExecutionRunner,
    ProtectedExecutionStatus,
    ProtectedExecutionStore,
    RecoveryReport,
    SqliteProtectedExecutionStore,
)
from masugate.protected_execution.model import PolicyBinding

from .artifacts import (
    ArtifactBinding,
    ArtifactMetadata,
    ArtifactStore,
    ArtifactUnavailable,
    SqliteArtifactStore,
)
from .artifacts import (
    ArtifactReader as StoredArtifactReader,
)
from .compiler import (
    CompiledOperationRoutes,
    ConnectorRegistry,
    load_connector_registry,
    load_registered_connector,
)
from .schema import canonical_json, require_digest, require_identifier, require_model_field
from .secrets import MountedFileSecretResolver, SecretResolver


class ConnectorWorkerError(ContractError):
    """Trusted worker composition or handoff validation failed closed."""


_WORKER_BOOTSTRAP_VERSION = "masugate.connector-worker-bootstrap.v1"


def _aware(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value


def _unique_identifiers(values: Iterable[str], field: str) -> tuple[str, ...]:
    parsed = tuple(require_identifier(value, field) for value in values)
    if len(set(parsed)) != len(parsed):
        raise ValueError(f"{field} must be unique")
    return tuple(sorted(parsed))


def _payload_strings(value: JsonValue) -> Iterator[str]:
    """Yield unescaped connector-owned JSON strings, including object keys."""

    if type(value) is str:
        yield value
    elif isinstance(value, Mapping):
        for key, nested in value.items():
            # SDK validation has already rejected non-string keys, but keeping
            # this check local makes the redaction boundary robust to a future
            # SDK implementation change.
            if type(key) is str:
                yield key
            yield from _payload_strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _payload_strings(nested)


def _binding_from_payload(payload: Mapping[str, JsonValue]) -> ProtectedExecutionBinding:
    provider = cast(dict[str, JsonValue], payload["provider_identity"])
    raw_policies = cast(list[JsonValue], payload["policies"])
    return ProtectedExecutionBinding(
        principal_id=cast(str, payload["principal_id"]),
        action=cast(str, payload["action"]),
        arguments=cast(dict[str, JsonValue], payload["arguments"]),
        idempotency_key=cast(str, payload["idempotency_key"]),
        policies=tuple(
            PolicyBinding(
                policy_id=cast(str, policy["policy_id"]),
                policy_version=cast(str, policy["policy_version"]),
                policy_digest=cast(str, policy["policy_digest"]),
                bundle_id=cast(str, policy["bundle_id"]),
                bundle_version=cast(str, policy["bundle_version"]),
                bundle_digest=cast(str, policy["bundle_digest"]),
            )
            for raw_policy in raw_policies
            for policy in [cast(dict[str, JsonValue], raw_policy)]
        ),
        provider_identity=ProviderIdentity(
            provider_id=cast(str, provider["provider_id"]),
            implementation_version=cast(str, provider["implementation_version"]),
            configuration_version=cast(str, provider["configuration_version"]),
        ),
        coordination_domain_id=cast(str, payload["coordination_domain_id"]),
        scopes=tuple(cast(list[str], payload["scopes"])),
        tool_call_id=cast(str, payload["tool_call_id"]),
        connector_id=cast(str, payload["connector_id"]),
        entitlement_id=cast(str, payload["entitlement_id"]),
        authorization_digest=cast(str | None, payload.get("authorization_digest")),
    )


def _artifact_binding_from_payload(payload: Mapping[str, JsonValue]) -> ArtifactBinding:
    return ArtifactBinding(
        principal_id=cast(str, payload["principal_id"]),
        action=cast(str, payload["action"]),
        idempotency_key=cast(str, payload["idempotency_key"]),
        adapter_invocation_digest=cast(str, payload["adapter_invocation_digest"]),
        field=cast(str, payload["field"]),
    )


@dataclass(frozen=True, slots=True)
class HandoffArtifact:
    """One sealed payload plus the authenticated staging identity that owns it."""

    binding: ArtifactBinding
    metadata: ArtifactMetadata

    def __post_init__(self) -> None:
        if type(self.binding) is not ArtifactBinding or type(self.metadata) is not ArtifactMetadata:
            raise TypeError("handoff artifact needs an ArtifactBinding and ArtifactMetadata")
        if self.metadata.binding_digest != self.binding.digest:
            raise ValueError("handoff artifact metadata does not match its staging binding")

    def payload(self) -> dict[str, JsonValue]:
        return {
            "binding": self.binding.payload(),
            "metadata": {
                "binding_digest": self.metadata.binding_digest,
                "classification": self.metadata.classification,
                "content_bytes": self.metadata.content_bytes,
                "content_digest": self.metadata.content_digest,
                "expires_at": self.metadata.expires_at.isoformat(),
                "inspector_version": self.metadata.inspector_version,
                "media_type": self.metadata.media_type,
                "reference": self.metadata.artifact_id,
            },
        }


@dataclass(frozen=True, slots=True)
class ConnectorWorkerDeployment:
    """Worker-only projection of one verified protected operation route.

    The factory binds the worker to the same private operation deployment
    binding and closed connector registry checked at ``masugated`` startup.  This
    prevents a caller from assembling a worker with an arbitrary connector
    digest, credential reference, or destination allowlist.
    """

    action: str
    connector_id: str
    connector_package_id: str
    connector_package_version: str
    connector_entry_point: str
    connector_sdk_contract_version: str
    connector_capabilities: ConnectorCapabilities
    connector_configuration_digest: str
    artifact_fields: tuple[str, ...]
    credential_refs: tuple[str, ...]
    allowed_destinations: tuple[str, ...]

    def __post_init__(self) -> None:
        require_identifier(self.action, "connector worker deployment action", max_length=255)
        for field_name in (
            "connector_id",
            "connector_package_id",
            "connector_package_version",
            "connector_entry_point",
            "connector_sdk_contract_version",
        ):
            require_identifier(
                getattr(self, field_name), f"connector worker deployment {field_name}"
            )
        if self.connector_sdk_contract_version != SDK_CONTRACT_VERSION:
            raise ValueError("connector worker deployment SDK contract is unsupported")
        if type(self.connector_capabilities) is not ConnectorCapabilities:
            raise TypeError("connector worker deployment needs ConnectorCapabilities")
        require_digest(
            self.connector_configuration_digest,
            "connector worker deployment configuration digest",
        )
        object.__setattr__(
            self,
            "artifact_fields",
            tuple(
                sorted(
                    require_model_field(field, "connector worker deployment artifact field")
                    for field in self.artifact_fields
                )
            ),
        )
        if len(set(self.artifact_fields)) != len(self.artifact_fields):
            raise ValueError("connector worker deployment artifact fields must be unique")
        object.__setattr__(
            self,
            "credential_refs",
            _unique_identifiers(
                self.credential_refs, "connector worker deployment credential refs"
            ),
        )
        object.__setattr__(
            self,
            "allowed_destinations",
            _unique_identifiers(
                self.allowed_destinations, "connector worker deployment destinations"
            ),
        )

    @classmethod
    def from_compiled_route(
        cls,
        compiled: CompiledOperationRoutes,
        connector_registry: ConnectorRegistry,
        *,
        action: str,
    ) -> ConnectorWorkerDeployment:
        """Derive one worker deployment without accepting host-controlled config."""

        if type(compiled) is not CompiledOperationRoutes:
            raise TypeError("connector worker needs CompiledOperationRoutes")
        if type(connector_registry) is not ConnectorRegistry:
            raise TypeError("connector worker needs ConnectorRegistry")
        if canonical_json(compiled.route_manifest) != compiled.canonical_route_manifest:
            raise ConnectorWorkerError(
                "connector worker compiled route manifest was modified after compilation"
            )
        action_name = require_identifier(action, "connector worker action", max_length=255)
        operation = next(
            (item for item in compiled.operation_pack.actions if item.action == action_name),
            None,
        )
        route = next(
            (item for item in compiled.deployment_binding.routes if item.action == action_name),
            None,
        )
        if operation is None or route is None:
            raise ConnectorWorkerError(
                "connector worker action is not in compiled operation routes"
            )
        if operation.owner_position != "protected-external" or route.connector is None:
            raise ConnectorWorkerError("connector workers require a protected-external operation")
        try:
            registered = connector_registry.get(route.connector.connector_id)
        except ContractError as exc:
            raise ConnectorWorkerError("connector worker names an unregistered connector") from exc
        if (
            registered.version != route.connector.version
            or registered.implementation_digest != route.connector.implementation_digest
            or registered.configuration_digest != route.connector.configuration_digest
            or registered.credential_refs != route.connector.credential_refs
            or registered.allowed_destinations != route.connector.allowed_destinations
        ):
            raise ConnectorWorkerError("connector worker deployment configuration drifted")
        if not set(operation.required_connector_capabilities) <= registered.capabilities:
            raise ConnectorWorkerError("connector worker lacks a route-required capability")
        return cls(
            action=action_name,
            connector_id=route.connector.connector_id,
            connector_package_id=registered.package_id,
            connector_package_version=registered.package_version,
            connector_entry_point=registered.entry_point,
            connector_sdk_contract_version=registered.sdk_contract_version,
            connector_capabilities=registered.capability_profile,
            connector_configuration_digest=route.connector.configuration_digest,
            artifact_fields=operation.artifact_fields,
            credential_refs=route.connector.credential_refs,
            allowed_destinations=route.connector.allowed_destinations,
        )


def _handoff_artifact_from_payload(payload: Mapping[str, JsonValue]) -> HandoffArtifact:
    raw_binding = cast(dict[str, JsonValue], payload["binding"])
    raw_metadata = cast(dict[str, JsonValue], payload["metadata"])
    return HandoffArtifact(
        binding=_artifact_binding_from_payload(raw_binding),
        metadata=ArtifactMetadata(
            artifact_id=cast(str, raw_metadata["reference"]),
            binding_digest=cast(str, raw_metadata["binding_digest"]),
            content_digest=cast(str, raw_metadata["content_digest"]),
            content_bytes=cast(int, raw_metadata["content_bytes"]),
            media_type=cast(str, raw_metadata["media_type"]),
            classification=cast(str, raw_metadata["classification"]),
            expires_at=datetime.fromisoformat(cast(str, raw_metadata["expires_at"])),
            inspector_version=cast(str, raw_metadata["inspector_version"]),
        ),
    )


async def resolve_handoff_artifact(
    artifact_store: ArtifactStore,
    binding: ArtifactBinding,
    *,
    now: datetime,
) -> HandoffArtifact:
    """Resolve provider handoff metadata from binding facts, never model input."""

    metadata = await artifact_store.lookup(binding, now=now)
    return HandoffArtifact(binding=binding, metadata=metadata)


@dataclass(frozen=True, slots=True)
class ConnectorHandoff:
    """One provider-committed protected handoff with sealed artifact metadata."""

    binding: ProtectedExecutionBinding
    artifacts: Mapping[str, HandoffArtifact]
    connector_configuration_digest: str
    created_at: datetime

    def __post_init__(self) -> None:
        if type(self.binding) is not ProtectedExecutionBinding:
            raise TypeError("connector handoff needs a ProtectedExecutionBinding")
        _aware(self.created_at, "connector handoff created_at")
        require_digest(
            self.connector_configuration_digest, "connector handoff configuration digest"
        )
        artifacts: dict[str, HandoffArtifact] = {}
        for field, artifact in self.artifacts.items():
            require_model_field(field, "connector handoff artifact field")
            if type(artifact) is not HandoffArtifact:
                raise TypeError("connector handoff artifacts must be HandoffArtifact")
            if (
                artifact.binding.principal_id != self.binding.principal_id
                or artifact.binding.action != self.binding.action
                or artifact.binding.idempotency_key != self.binding.idempotency_key
                or artifact.binding.field != field
            ):
                raise ValueError(
                    "connector handoff artifact does not match the protected execution"
                )
            artifacts[field] = artifact
        object.__setattr__(self, "artifacts", MappingProxyType(dict(sorted(artifacts.items()))))

    def payload(self) -> dict[str, JsonValue]:
        return {
            "artifacts": {field: artifact.payload() for field, artifact in self.artifacts.items()},
            "binding": self.binding.payload(),
            "connector_configuration_digest": self.connector_configuration_digest,
            "created_at": self.created_at.isoformat(),
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.payload()).encode("utf-8")).hexdigest()


class ConnectorHandoffStore(Protocol):
    """Durable source of work accepted by one connector worker."""

    async def initialize(self) -> None: ...

    async def record_committed(self, handoff: ConnectorHandoff) -> ConnectorHandoff: ...

    async def get(self, execution_id: str) -> ConnectorHandoff: ...

    async def committed(self) -> tuple[ConnectorHandoff, ...]: ...


class SqliteConnectorHandoffStore:
    """Reference durable outbox for worker-owned execution context."""

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise TypeError("connector handoff store path must be a Path")
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    async def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS connector_handoffs (
                    execution_id TEXT PRIMARY KEY,
                    binding_digest TEXT NOT NULL UNIQUE,
                    handoff_digest TEXT NOT NULL UNIQUE,
                    handoff_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            connection.commit()
        finally:
            connection.close()

    @staticmethod
    def _decode(row: sqlite3.Row) -> ConnectorHandoff:
        try:
            payload = json.loads(cast(str, row["handoff_json"]))
        except json.JSONDecodeError as exc:
            raise ConnectorWorkerError("durable connector handoff JSON is malformed") from exc
        if not isinstance(payload, dict) or set(payload) != {
            "artifacts",
            "binding",
            "connector_configuration_digest",
            "created_at",
        }:
            raise ConnectorWorkerError("durable connector handoff has an invalid shape")
        raw_artifacts = payload["artifacts"]
        if not isinstance(raw_artifacts, dict) or any(
            type(field) is not str or not isinstance(raw, dict)
            for field, raw in raw_artifacts.items()
        ):
            raise ConnectorWorkerError("durable connector handoff artifacts are malformed")
        handoff = ConnectorHandoff(
            binding=_binding_from_payload(cast(dict[str, JsonValue], payload["binding"])),
            artifacts={
                field: _handoff_artifact_from_payload(cast(dict[str, JsonValue], raw))
                for field, raw in raw_artifacts.items()
            },
            connector_configuration_digest=cast(str, payload["connector_configuration_digest"]),
            created_at=datetime.fromisoformat(cast(str, payload["created_at"])),
        )
        if handoff.binding.execution_id != row["execution_id"]:
            raise ConnectorWorkerError("durable connector handoff execution id drifted")
        if (
            handoff.binding.digest != row["binding_digest"]
            or handoff.digest != row["handoff_digest"]
        ):
            raise ConnectorWorkerError("durable connector handoff digest drifted")
        return handoff

    async def record_committed(self, handoff: ConnectorHandoff) -> ConnectorHandoff:
        if type(handoff) is not ConnectorHandoff:
            raise TypeError("connector handoff store needs a ConnectorHandoff")
        encoded = canonical_json(handoff.payload())
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM connector_handoffs WHERE execution_id = ?",
                (handoff.binding.execution_id,),
            ).fetchone()
            if existing is not None:
                persisted = self._decode(existing)
                if persisted.digest != handoff.digest:
                    raise ConnectorWorkerError(
                        "protected execution already has a different committed connector handoff"
                    )
                return persisted
            connection.execute(
                """
                INSERT INTO connector_handoffs(
                    execution_id, binding_digest, handoff_digest, handoff_json, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    handoff.binding.execution_id,
                    handoff.binding.digest,
                    handoff.digest,
                    encoded,
                    handoff.created_at.isoformat(),
                ),
            )
        return handoff

    async def get(self, execution_id: str) -> ConnectorHandoff:
        require_identifier(execution_id, "connector execution id")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM connector_handoffs WHERE execution_id = ?", (execution_id,)
            ).fetchone()
            if row is None:
                raise ConnectorWorkerError("protected execution has no committed connector handoff")
            return self._decode(row)

    async def committed(self) -> tuple[ConnectorHandoff, ...]:
        with self._transaction() as connection:
            rows = connection.execute(
                "SELECT * FROM connector_handoffs ORDER BY created_at, execution_id"
            ).fetchall()
            return tuple(self._decode(row) for row in rows)


class _ConnectorArtifactReader:
    """Public SDK wrapper for one sealed MasuGate reader.

    The wrapper is the deliberate type boundary: external packages can read
    verified bytes and certified metadata but cannot discover the store,
    staging binding, filesystem path, or internal artifact implementation.
    """

    def __init__(self, reader: StoredArtifactReader, *, maximum_bytes: int) -> None:
        if type(maximum_bytes) is not int or maximum_bytes <= 0:
            raise ValueError("connector artifact reader maximum bytes must be positive")
        self._reader = reader
        self._maximum_bytes = maximum_bytes
        metadata = reader.metadata
        self._metadata = ArtifactDescriptor(
            reference=metadata.artifact_id,
            content_digest=metadata.content_digest,
            content_bytes=metadata.content_bytes,
            media_type=metadata.media_type,
            classification=metadata.classification,
            expires_at=metadata.expires_at,
        )

    @property
    def metadata(self) -> ArtifactDescriptor:
        return self._metadata

    async def read(self, *, maximum_bytes: int | None = None) -> bytes:
        if maximum_bytes is not None and (type(maximum_bytes) is not int or maximum_bytes <= 0):
            raise ConnectorWorkerError("connector artifact reader maximum bytes must be positive")
        # The connector can ask for a stricter bound, never a larger one.  The
        # underlying store verifies the complete certified object before it
        # returns bytes, so a partial/truncated reader can never mask a digest
        # or length mismatch.
        limit = (
            self._maximum_bytes
            if maximum_bytes is None
            else min(maximum_bytes, self._maximum_bytes)
        )
        return await self._reader.read(maximum_bytes=limit)


class _WorkerConnectorAdapter:
    """Legacy runner SPI adapter; all context comes from :class:`ConnectorWorker`."""

    def __init__(self, worker: ConnectorWorker) -> None:
        self._worker = worker

    @property
    def connector_id(self) -> str:
        return self._worker.deployment.connector_id

    @property
    def capabilities(self) -> ConnectorCapabilities:
        return self._worker.connector_capabilities

    async def execute(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        fence_token: int,
    ) -> ProtectedConnectorEvidence:
        context = await self._worker._context(binding, idempotency_key, fence_token)
        try:
            evidence = await self._worker.connector.execute(context)
        except ConnectorAmbiguousOutcome as exc:
            from masugate.protected_execution import ConnectorOutcomeUnknown

            raise ConnectorOutcomeUnknown(
                str(exc), external_operation_id=exc.external_operation_id
            ) from exc
        return self._worker._validate_evidence(evidence, context)

    async def query_status(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        external_operation_id: str | None,
    ) -> ProtectedConnectorEvidence:
        record = await self._worker.execution_store.get(binding.execution_id)
        context = await self._worker._context(
            binding,
            idempotency_key,
            record.fence_token,
            include_artifacts=False,
            idempotency_started_at=record.created_at,
        )
        try:
            evidence = await self._worker.connector.query_status(
                context, external_operation_id=external_operation_id
            )
        except ConnectorAmbiguousOutcome as exc:
            from masugate.protected_execution import ConnectorOutcomeUnknown

            raise ConnectorOutcomeUnknown(
                str(exc), external_operation_id=exc.external_operation_id
            ) from exc
        return self._worker._validate_evidence(evidence, context)

    async def cancel(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        external_operation_id: str | None,
    ) -> ProtectedConnectorEvidence:
        # The generic runner claims a fresh cancellation fence immediately
        # before calling this adapter.  Read that durable claim rather than
        # fabricating ``0`` so fence-aware remote connectors can reject stale
        # cancellation work just as they do dispatch work.
        record = await self._worker.execution_store.get(binding.execution_id)
        context = await self._worker._context(
            binding,
            idempotency_key,
            record.fence_token,
            include_artifacts=False,
            idempotency_started_at=record.created_at,
        )
        try:
            evidence = await self._worker.connector.cancel(
                context, external_operation_id=external_operation_id
            )
        except ConnectorAmbiguousOutcome as exc:
            from masugate.protected_execution import ConnectorOutcomeUnknown

            raise ConnectorOutcomeUnknown(
                str(exc), external_operation_id=exc.external_operation_id
            ) from exc
        return self._worker._validate_evidence(evidence, context)


class ConnectorWorker:
    """Run one exact connector action from provider-committed handoffs only."""

    def __init__(
        self,
        *,
        execution_store: ProtectedExecutionStore,
        handoff_store: ConnectorHandoffStore,
        artifact_store: ArtifactStore,
        secret_resolver: SecretResolver,
        authority: ProtectedExecutionAuthority,
        deployment: ConnectorWorkerDeployment,
        worker_id: str,
        lease_duration: timedelta = timedelta(seconds=30),
        clock: Callable[[], datetime] | None = None,
        connector: OperationConnector | None = None,
        connector_loader: Callable[[], OperationConnector] | None = None,
    ) -> None:
        if (connector is None) == (connector_loader is None):
            raise TypeError("connector worker needs exactly one connector or deferred loader")
        if connector is not None:
            try:
                connector = validate_operation_connector(connector)
            except (TypeError, ValueError) as exc:
                raise ConnectorWorkerError(
                    "operation connector violates the public SDK contract"
                ) from exc
        if type(deployment) is not ConnectorWorkerDeployment:
            raise TypeError("connector worker needs a ConnectorWorkerDeployment")
        if deployment.connector_id != authority.connector_id:
            raise ConnectorWorkerError("worker connector does not match the protected authority")
        if (
            authority.action != deployment.action
            or authority.connector_id != deployment.connector_id
        ):
            raise ConnectorWorkerError("worker deployment does not match the protected authority")
        if connector is not None:
            if connector.connector_id != deployment.connector_id:
                raise ConnectorWorkerError(
                    "worker connector does not match the protected authority"
                )
            if connector.sdk_contract_version != deployment.connector_sdk_contract_version:
                raise ConnectorWorkerError("worker connector SDK contract drifted")
            if connector.capabilities != deployment.connector_capabilities:
                raise ConnectorWorkerError("worker connector capability profile drifted")
        if not deployment.connector_capabilities.fencing:
            raise ConnectorWorkerError("operation connector must support fencing")
        if not deployment.connector_capabilities.idempotent_dispatch:
            raise ConnectorWorkerError("operation connector must support idempotent dispatch")
        self.execution_store = execution_store
        self.handoff_store = handoff_store
        self.artifact_store = artifact_store
        self.secret_resolver = secret_resolver
        self._connector = connector
        self._connector_loader = connector_loader
        self.connector_capabilities = deployment.connector_capabilities
        self.authority = authority
        self.deployment = deployment
        self.artifact_fields = deployment.artifact_fields
        self.credential_refs = deployment.credential_refs
        self.allowed_destinations = deployment.allowed_destinations
        self.connector_configuration_digest = deployment.connector_configuration_digest
        adapter = _WorkerConnectorAdapter(self)
        if clock is None:
            self.runner = ProtectedExecutionRunner(
                execution_store,
                cast(ProtectedConnector, adapter),
                authority,
                worker_id=worker_id,
                lease_duration=lease_duration,
            )
        else:
            self.runner = ProtectedExecutionRunner(
                execution_store,
                cast(ProtectedConnector, adapter),
                authority,
                worker_id=worker_id,
                lease_duration=lease_duration,
                clock=clock,
            )
        self.runner.bind_dispatch_admission(self._require_committed_handoff)

    @property
    def connector(self) -> OperationConnector:
        """Load external package code only after committed-work admission.

        The registry constructor stores a closed loader rather than importing
        an entry point. The adapter reaches this property only after the
        runner has admitted the durable handoff, verified artifacts, and
        resolved the trusted deployment facts.
        """

        if self._connector is None:
            assert self._connector_loader is not None
            try:
                loaded = validate_operation_connector(self._connector_loader())
            except (TypeError, ValueError, ContractError) as exc:
                raise ConnectorWorkerError(
                    "registered connector violates the public SDK contract"
                ) from exc
            if (
                loaded.connector_id != self.deployment.connector_id
                or loaded.sdk_contract_version != self.deployment.connector_sdk_contract_version
                or loaded.capabilities != self.connector_capabilities
            ):
                raise ConnectorWorkerError("registered connector drifted after handoff admission")
            self._connector = loaded
        return self._connector

    @classmethod
    def from_registered_connector(
        cls,
        *,
        execution_store: ProtectedExecutionStore,
        handoff_store: ConnectorHandoffStore,
        artifact_store: ArtifactStore,
        secret_resolver: SecretResolver,
        authority: ProtectedExecutionAuthority,
        deployment: ConnectorWorkerDeployment,
        connector_registry: ConnectorRegistry,
        worker_id: str,
        lease_duration: timedelta = timedelta(seconds=30),
        clock: Callable[[], datetime] | None = None,
    ) -> ConnectorWorker:
        """Build a worker from its closed registry entry, never a module string."""

        if type(deployment) is not ConnectorWorkerDeployment:
            raise TypeError("registered connector worker needs a ConnectorWorkerDeployment")
        if type(connector_registry) is not ConnectorRegistry:
            raise TypeError("registered connector worker needs a ConnectorRegistry")
        registered = connector_registry.get(deployment.connector_id)
        if (
            deployment.connector_package_id != registered.package_id
            or deployment.connector_package_version != registered.package_version
            or deployment.connector_entry_point != registered.entry_point
            or deployment.connector_sdk_contract_version != registered.sdk_contract_version
            or deployment.connector_capabilities != registered.capability_profile
            or deployment.connector_configuration_digest != registered.configuration_digest
            or deployment.credential_refs != registered.credential_refs
            or deployment.allowed_destinations != registered.allowed_destinations
        ):
            raise ConnectorWorkerError("registered connector worker deployment drifted")
        return cls(
            execution_store=execution_store,
            handoff_store=handoff_store,
            artifact_store=artifact_store,
            secret_resolver=secret_resolver,
            connector_loader=lambda: load_registered_connector(
                connector_registry, deployment.connector_id
            ),
            authority=authority,
            deployment=deployment,
            worker_id=worker_id,
            lease_duration=lease_duration,
            clock=clock,
        )

    async def initialize(self) -> None:
        """Initialize only worker-owned durable stores before serving work."""

        await self.execution_store.initialize()
        await self.handoff_store.initialize()
        await self.artifact_store.initialize()

    def _validate_handoff(self, handoff: ConnectorHandoff) -> None:
        binding = handoff.binding
        try:
            self.authority.validate(binding)
        except ValueError as exc:
            raise ConnectorWorkerError(
                "connector handoff does not match the assembled authority"
            ) from exc
        if tuple(handoff.artifacts) != self.artifact_fields:
            raise ConnectorWorkerError(
                "connector handoff artifacts do not match the installed pack"
            )
        if handoff.connector_configuration_digest != self.connector_configuration_digest:
            raise ConnectorWorkerError("connector handoff configuration drifted")
        total_bytes = sum(
            artifact.metadata.content_bytes for artifact in handoff.artifacts.values()
        )
        if total_bytes > self.connector_capabilities.max_payload_bytes:
            raise ConnectorWorkerError("connector handoff exceeds connector payload capability")
        for artifact in handoff.artifacts.values():
            if artifact.binding.principal_id != binding.principal_id:
                raise ConnectorWorkerError("connector handoff artifact binding drifted")

    async def record_committed_handoff(
        self,
        handoff: ConnectorHandoff,
        *,
        now: datetime,
    ) -> ProtectedExecutionRecord:
        """Persist one provider-created handoff before its generic intent exists.

        This is a composition API for provider outboxes, not an HTTP surface.
        A crash after this write is recoverable because the durable handoff is
        the only source from which :meth:`recover` may create a missing intent.
        """

        _aware(now, "committed connector handoff now")
        self._validate_handoff(handoff)
        await self.handoff_store.record_committed(handoff)
        return await self.execution_store.create_intent(handoff.binding, now=now)

    async def _require_committed_handoff(self, binding: ProtectedExecutionBinding) -> None:
        handoff = await self.handoff_store.get(binding.execution_id)
        if handoff.binding.digest != binding.digest:
            raise ConnectorWorkerError("committed connector handoff binding drifted")
        self._validate_handoff(handoff)
        # Verify every artifact and credential before the runner makes
        # dispatch_started durable. A missing/expired input therefore cannot
        # be mistaken for a possibly delivered connector operation.
        now = self.runner.clock()
        for _field, artifact in handoff.artifacts.items():
            reader = await self.artifact_store.open(
                artifact.metadata.artifact_id,
                binding=artifact.binding,
                now=now,
                expected_metadata=artifact.metadata,
            )
            # Admission must consume and hash the sealed bytes before
            # dispatch_started becomes durable. A later connector read is a
            # defense-in-depth re-check, not the first integrity decision.
            await reader.read(maximum_bytes=self.connector_capabilities.max_payload_bytes)
        for reference in self.credential_refs:
            self.secret_resolver.resolve(reference)
        # Profile drift is also a pre-dispatch admission failure: the known
        # local mismatch proves no connector request was attempted. Do this
        # only after the immutable handoff's sealed inputs have been verified.
        self._require_runtime_configuration_digest()

    async def _context(
        self,
        binding: ProtectedExecutionBinding,
        idempotency_key: str,
        fence_token: int,
        *,
        include_artifacts: bool = True,
        idempotency_started_at: datetime | None = None,
    ) -> ConnectorInvocation:
        handoff = await self.handoff_store.get(binding.execution_id)
        if handoff.binding.digest != binding.digest:
            raise ConnectorWorkerError("committed connector handoff binding drifted")
        self._validate_handoff(handoff)
        now = self.runner.clock()
        readers: dict[str, ConnectorArtifactReader] = {}
        if include_artifacts:
            for field, artifact in handoff.artifacts.items():
                readers[field] = _ConnectorArtifactReader(
                    await self.artifact_store.open(
                        artifact.metadata.artifact_id,
                        binding=artifact.binding,
                        now=now,
                        expected_metadata=artifact.metadata,
                    ),
                    maximum_bytes=self.connector_capabilities.max_payload_bytes,
                )
        secrets = {
            reference: self.secret_resolver.resolve(reference) for reference in self.credential_refs
        }
        return ConnectorInvocation(
            action=binding.action,
            arguments=binding.arguments,
            execution_id=binding.execution_id,
            binding_digest=binding.digest,
            connector_id=binding.connector_id,
            artifacts=readers,
            secrets=secrets,
            allowed_destinations=self.allowed_destinations,
            idempotency_key=idempotency_key,
            fence_token=fence_token,
            idempotency_started_at=idempotency_started_at,
            connector_configuration_digest=self.connector_configuration_digest,
        )

    def _require_runtime_configuration_digest(self) -> None:
        """Reject a connector profile that drifted from its committed deployment.

        Most connector packages have no runtime profile digest, so this remains
        an optional public SPI attribute. Exact profiles that do expose one are
        checked for every dispatch, status query, and cancellation context,
        including work resumed after a process restart.
        """

        try:
            runtime_digest = getattr(self.connector, "configuration_digest", None)
        except (TypeError, ValueError) as exc:
            raise ConnectorWorkerError("connector runtime configuration is unavailable") from exc
        if runtime_digest is None:
            return
        if type(runtime_digest) is not str:
            raise ConnectorWorkerError("connector runtime configuration digest is malformed")
        try:
            require_digest(runtime_digest, "connector runtime configuration digest")
        except (TypeError, ValueError) as exc:
            raise ConnectorWorkerError(
                "connector runtime configuration digest is malformed"
            ) from exc
        if runtime_digest != self.connector_configuration_digest:
            raise ConnectorWorkerError("connector runtime configuration drifted")

    def _validate_evidence(
        self,
        evidence: object,
        context: ConnectorInvocation,
    ) -> ProtectedConnectorEvidence:
        if type(evidence) is not ConnectorEvidence:
            raise ConnectorWorkerError("operation connector returned malformed evidence")
        if evidence.connector_id != context.connector_id:
            raise ConnectorWorkerError("operation connector evidence names the wrong connector")
        if evidence.idempotency_key != context.idempotency_key:
            raise ConnectorWorkerError(
                "operation connector evidence names the wrong idempotency key"
            )
        if (
            evidence.outcome is not ConnectorOutcome.UNKNOWN
            and evidence.external_operation_id is None
        ):
            raise ConnectorWorkerError("terminal connector evidence needs an external operation id")
        encoded = canonical_json(dict(evidence.payload)).encode("utf-8")
        if len(encoded) > self.connector_capabilities.max_result_bytes:
            raise ConnectorWorkerError("operation connector result exceeds configured limit")
        public_evidence_strings = (
            evidence.evidence_id,
            *(() if evidence.external_operation_id is None else (evidence.external_operation_id,)),
            *_payload_strings(cast(JsonValue, evidence.payload)),
        )
        for secret in context.secrets.values():
            value = secret.read()
            renderings = (value, base64.b64encode(value), value.hex().encode("ascii"))
            if any(
                rendering and rendering in field.encode("utf-8")
                for rendering in renderings
                for field in public_evidence_strings
            ):
                raise ConnectorWorkerError("operation connector attempted to disclose a secret")
        return ProtectedConnectorEvidence(
            connector_id=evidence.connector_id,
            evidence_id=evidence.evidence_id,
            idempotency_key=evidence.idempotency_key,
            external_operation_id=evidence.external_operation_id,
            outcome=ProtectedConnectorOutcome(evidence.outcome.value),
            observed_at=evidence.observed_at,
            payload=evidence.payload,
        )

    async def dispatch(self, execution_id: str) -> ProtectedExecutionRecord:
        """Dispatch exactly one already committed durable handoff."""

        handoff = await self.handoff_store.get(execution_id)
        self._validate_handoff(handoff)
        return await self.runner.start(handoff.binding)

    async def reconcile(self, execution_id: str) -> ProtectedExecutionRecord:
        """Reconcile one committed handoff; it never performs a blind redispatch."""

        handoff = await self.handoff_store.get(execution_id)
        self._validate_handoff(handoff)
        return await self.runner.reconcile(execution_id)

    async def cancel(self, execution_id: str) -> ProtectedExecutionRecord:
        """Cancel only through the established fenced protected lifecycle."""

        handoff = await self.handoff_store.get(execution_id)
        self._validate_handoff(handoff)
        return await self.runner.cancel(execution_id)

    async def recover(self) -> RecoveryReport:
        """Restore committed handoffs after a worker restart."""

        handoffs = await self.handoff_store.committed()
        execution_ids: list[str] = []
        pre_dispatch_failures: list[ProtectedExecutionRecord] = []
        now = self.runner.clock()
        for handoff in handoffs:
            self._validate_handoff(handoff)
            execution_ids.append(handoff.binding.execution_id)
            try:
                record = await self.execution_store.get(handoff.binding.execution_id)
            except ProtectedExecutionError:
                record = await self.execution_store.create_intent(handoff.binding, now=now)
            # A live dispatch lease may already be about to set its durable
            # dispatch marker.  Recovery never fences that owner.  An intent,
            # or an expired pre-dispatch lease, has a proof that no connector
            # call occurred and can safely be terminalized if its artifact is
            # irretrievably unavailable.
            if record.dispatch_started or record.status not in {
                ProtectedExecutionStatus.INTENT,
                ProtectedExecutionStatus.EXECUTING,
            }:
                continue
            if (
                record.status is ProtectedExecutionStatus.EXECUTING
                and record.lease_expires_at is not None
                and record.lease_expires_at > now
            ):
                continue
            try:
                await self._require_committed_handoff(handoff.binding)
            except ArtifactUnavailable:
                failed, terminal = await self.execution_store.fail_pre_dispatch(
                    record.execution_id,
                    now=now,
                    reason="artifact-unavailable-before-dispatch",
                )
                if failed:
                    pre_dispatch_failures.append(terminal)
        report = await ProtectedExecutionRecovery(self.runner).recover(execution_ids=execution_ids)
        return RecoveryReport(
            scanned=report.scanned,
            recovered=tuple(pre_dispatch_failures) + report.recovered,
            skipped=report.skipped,
            errors=report.errors,
        )


def _bootstrap_mapping(value: object, field: str, keys: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ConnectorWorkerError(f"connector worker bootstrap {field} has an invalid shape")
    return cast(dict[str, object], value)


def _bootstrap_string(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise ConnectorWorkerError(f"connector worker bootstrap {field} must be a non-empty string")
    return value


def _bootstrap_capabilities(value: object) -> ConnectorCapabilities:
    raw = _bootstrap_mapping(
        value,
        "deployment.connector_capabilities",
        frozenset(
            {
                "ambiguity_handling",
                "cancellation",
                "fencing",
                "idempotent_dispatch",
                "max_payload_bytes",
                "max_result_bytes",
                "status_query",
            }
        ),
    )
    try:
        return ConnectorCapabilities(
            idempotent_dispatch=cast(bool, raw["idempotent_dispatch"]),
            status_query=cast(bool, raw["status_query"]),
            cancellation=cast(bool, raw["cancellation"]),
            fencing=cast(bool, raw["fencing"]),
            max_payload_bytes=cast(int, raw["max_payload_bytes"]),
            max_result_bytes=cast(int, raw["max_result_bytes"]),
            ambiguity_handling=cast(str | None, raw["ambiguity_handling"]),
        )
    except (TypeError, ValueError) as exc:
        raise ConnectorWorkerError("connector worker bootstrap capabilities are invalid") from exc


def _bootstrap_worker(path: Path) -> ConnectorWorker:
    """Build one closed worker from a deployment-mounted bootstrap document.

    This is intentionally a file-only startup surface. It exposes no network
    execution API, accepts no module/factory name, and can reach code only
    through the exact entry point sealed in the registry document.
    """

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConnectorWorkerError("connector worker bootstrap is unreadable") from exc
    root = _bootstrap_mapping(
        raw,
        "document",
        frozenset(
            {
                "artifact_store_path",
                "authority",
                "connector_registry",
                "contract_version",
                "deployment",
                "execution_store_path",
                "handoff_store_path",
                "secret_mount",
                "worker_id",
            }
        ),
    )
    if root["contract_version"] != _WORKER_BOOTSTRAP_VERSION:
        raise ConnectorWorkerError("connector worker bootstrap contract version is unsupported")
    authority_raw = _bootstrap_mapping(
        root["authority"],
        "authority",
        frozenset(
            {
                "action",
                "connector_id",
                "coordination_domain_id",
                "provider_identity",
            }
        ),
    )
    provider_raw = _bootstrap_mapping(
        authority_raw["provider_identity"],
        "authority.provider_identity",
        frozenset({"configuration_version", "implementation_version", "provider_id"}),
    )
    deployment_raw = _bootstrap_mapping(
        root["deployment"],
        "deployment",
        frozenset(
            {
                "action",
                "allowed_destinations",
                "artifact_fields",
                "connector_capabilities",
                "connector_configuration_digest",
                "connector_entry_point",
                "connector_id",
                "connector_package_id",
                "connector_package_version",
                "connector_sdk_contract_version",
                "credential_refs",
            }
        ),
    )
    secret_raw = _bootstrap_mapping(
        root["secret_mount"], "secret_mount", frozenset({"allowed_files", "root"})
    )
    allowed_files = secret_raw["allowed_files"]
    if not isinstance(allowed_files, dict) or any(
        type(reference) is not str or type(filename) is not str
        for reference, filename in allowed_files.items()
    ):
        raise ConnectorWorkerError("connector worker bootstrap secret files are invalid")
    for field in ("artifact_fields", "credential_refs", "allowed_destinations"):
        values = deployment_raw[field]
        if not isinstance(values, list) or any(type(value) is not str for value in values):
            raise ConnectorWorkerError(f"connector worker bootstrap deployment.{field} is invalid")
    authority = ProtectedExecutionAuthority(
        action=_bootstrap_string(authority_raw["action"], "authority.action"),
        provider_identity=ProviderIdentity(
            _bootstrap_string(
                provider_raw["provider_id"], "authority.provider_identity.provider_id"
            ),
            _bootstrap_string(
                provider_raw["implementation_version"],
                "authority.provider_identity.implementation_version",
            ),
            _bootstrap_string(
                provider_raw["configuration_version"],
                "authority.provider_identity.configuration_version",
            ),
        ),
        coordination_domain_id=_bootstrap_string(
            authority_raw["coordination_domain_id"], "authority.coordination_domain_id"
        ),
        connector_id=_bootstrap_string(authority_raw["connector_id"], "authority.connector_id"),
    )
    deployment = ConnectorWorkerDeployment(
        action=_bootstrap_string(deployment_raw["action"], "deployment.action"),
        connector_id=_bootstrap_string(deployment_raw["connector_id"], "deployment.connector_id"),
        connector_package_id=_bootstrap_string(
            deployment_raw["connector_package_id"], "deployment.connector_package_id"
        ),
        connector_package_version=_bootstrap_string(
            deployment_raw["connector_package_version"], "deployment.connector_package_version"
        ),
        connector_entry_point=_bootstrap_string(
            deployment_raw["connector_entry_point"], "deployment.connector_entry_point"
        ),
        connector_sdk_contract_version=_bootstrap_string(
            deployment_raw["connector_sdk_contract_version"],
            "deployment.connector_sdk_contract_version",
        ),
        connector_capabilities=_bootstrap_capabilities(deployment_raw["connector_capabilities"]),
        connector_configuration_digest=_bootstrap_string(
            deployment_raw["connector_configuration_digest"],
            "deployment.connector_configuration_digest",
        ),
        artifact_fields=tuple(cast(list[str], deployment_raw["artifact_fields"])),
        credential_refs=tuple(cast(list[str], deployment_raw["credential_refs"])),
        allowed_destinations=tuple(cast(list[str], deployment_raw["allowed_destinations"])),
    )
    try:
        registry = load_connector_registry(root["connector_registry"])
    except (TypeError, ValueError) as exc:
        raise ConnectorWorkerError("connector worker bootstrap registry is invalid") from exc
    return ConnectorWorker.from_registered_connector(
        execution_store=SqliteProtectedExecutionStore(
            Path(_bootstrap_string(root["execution_store_path"], "execution_store_path"))
        ),
        handoff_store=SqliteConnectorHandoffStore(
            Path(_bootstrap_string(root["handoff_store_path"], "handoff_store_path"))
        ),
        artifact_store=SqliteArtifactStore(
            _bootstrap_string(root["artifact_store_path"], "artifact_store_path")
        ),
        secret_resolver=MountedFileSecretResolver(
            Path(_bootstrap_string(secret_raw["root"], "secret_mount.root")),
            cast(dict[str, str], allowed_files),
        ),
        authority=authority,
        deployment=deployment,
        connector_registry=registry,
        worker_id=_bootstrap_string(root["worker_id"], "worker_id"),
    )


async def _serve_committed_handoffs(path: Path, *, once: bool, poll_seconds: float) -> None:
    worker = _bootstrap_worker(path)
    await worker.initialize()
    report = await worker.recover()

    def report_payload(value: RecoveryReport) -> dict[str, JsonValue]:
        payload: dict[str, JsonValue] = {
            "recovered": len(value.recovered),
            "scanned": value.scanned,
        }
        if value.errors:
            payload["errors"] = [
                {"execution_id": execution_id, "error": error}
                for execution_id, error in value.errors
            ]
        return payload

    print(json.dumps(report_payload(report), sort_keys=True), flush=True)
    if once:
        return
    while True:
        await asyncio.sleep(poll_seconds)
        report = await worker.recover()
        if report.errors:
            print(json.dumps(report_payload(report), sort_keys=True), flush=True)


def main() -> None:
    """Run only deployment-mounted, committed-handoff worker composition."""

    parser = argparse.ArgumentParser(
        description="MasuGate connector-worker composition entry point"
    )
    parser.add_argument("--version", action="store_true", help="print the worker API version")
    parser.add_argument(
        "--serve-committed-handoffs",
        action="store_true",
        help="recover/claim committed handoffs from a closed bootstrap document",
    )
    parser.add_argument("--bootstrap", type=Path, help="read-only worker bootstrap JSON path")
    parser.add_argument("--once", action="store_true", help="run one recovery pass then exit")
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    args = parser.parse_args()
    if args.version:
        print("masugate-connector-worker.v1")
        return
    if not args.serve_committed_handoffs or args.bootstrap is None:
        parser.error("worker serving requires --serve-committed-handoffs and --bootstrap")
    if not 0.1 <= args.poll_seconds <= 60:
        parser.error("--poll-seconds must be between 0.1 and 60")
    asyncio.run(
        _serve_committed_handoffs(args.bootstrap, once=args.once, poll_seconds=args.poll_seconds)
    )


__all__ = [
    "ConnectorHandoff",
    "ConnectorHandoffStore",
    "ConnectorWorker",
    "ConnectorWorkerDeployment",
    "ConnectorWorkerError",
    "HandoffArtifact",
    "SqliteConnectorHandoffStore",
    "resolve_handoff_artifact",
]


if __name__ == "__main__":  # pragma: no cover - exercised by Compose acceptance
    main()
