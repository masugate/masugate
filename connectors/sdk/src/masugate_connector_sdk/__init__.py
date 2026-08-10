"""Stable, server-internal-free connector author contract.

This package deliberately depends only on the Python standard library. MasuGate's
worker adapts these public types to its private protected-execution records;
connector packages must not import those records directly.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol, cast

SDK_CONTRACT_VERSION = "masugate.connector-sdk.v1"

type JsonPrimitive = str | int | float | bool | None
type JsonValue = JsonPrimitive | list[JsonValue] | dict[str, JsonValue]
type ConnectorResult = Mapping[str, JsonValue]


class ConnectorSDKError(ValueError):
    """A connector violated the stable public author contract."""


class ConnectorAmbiguousOutcome(ConnectorSDKError):
    """A connector cannot prove whether its remote effect occurred."""

    def __init__(self, message: str, *, external_operation_id: str | None = None) -> None:
        super().__init__(message)
        if external_operation_id is not None:
            _identifier(external_operation_id, "external_operation_id")
        self.external_operation_id = external_operation_id


def _identifier(value: object, field_name: str, *, maximum_length: int = 255) -> str:
    if not (
        type(value) is str
        and 0 < len(value) <= maximum_length
        and value.strip() == value
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise ConnectorSDKError(f"{field_name} must be a canonical identifier")
    return value


def _digest(value: object, field_name: str) -> str:
    parsed = _identifier(value, field_name)
    if len(parsed) != 64 or any(character not in "0123456789abcdef" for character in parsed):
        raise ConnectorSDKError(f"{field_name} must be a lowercase SHA-256 digest")
    return parsed


def _aware(value: object, field_name: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ConnectorSDKError(f"{field_name} must be timezone-aware")
    return value


def _json_value(value: object, field_name: str) -> JsonValue:
    if value is None or type(value) in {bool, int, str}:
        return cast(JsonValue, value)
    if type(value) is float:
        if not math.isfinite(value):
            raise ConnectorSDKError(f"{field_name} contains a non-finite float")
        return value
    if isinstance(value, list):
        return [_json_value(item, f"{field_name}[]") for item in value]
    if isinstance(value, dict):
        parsed: dict[str, JsonValue] = {}
        for key, item in value.items():
            if type(key) is not str or not key:
                raise ConnectorSDKError(f"{field_name} contains an invalid object key")
            parsed[key] = _json_value(item, f"{field_name}.{key}")
        return parsed
    raise ConnectorSDKError(f"{field_name} contains unsupported value {type(value).__name__}")


@dataclass(frozen=True, slots=True)
class ConnectorCapabilities:
    """Exact dispatch/recovery and byte-bound profile declared by a connector."""

    idempotent_dispatch: bool
    status_query: bool
    cancellation: bool
    fencing: bool = True
    max_payload_bytes: int = 8 * 1024 * 1024
    max_result_bytes: int = 1 * 1024 * 1024
    ambiguity_handling: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("idempotent_dispatch", "status_query", "cancellation", "fencing"):
            if type(getattr(self, field_name)) is not bool:
                raise ConnectorSDKError(f"connector capability {field_name} must be bool")
        for field_name in ("max_payload_bytes", "max_result_bytes"):
            if type(getattr(self, field_name)) is not int or getattr(self, field_name) <= 0:
                raise ConnectorSDKError(
                    f"connector capability {field_name} must be a positive integer"
                )
        if self.ambiguity_handling is None:
            object.__setattr__(
                self,
                "ambiguity_handling",
                "status-query" if self.status_query else "quarantine",
            )
        if self.ambiguity_handling not in {"status-query", "quarantine"}:
            raise ConnectorSDKError("connector capability ambiguity_handling is invalid")
        if self.status_query != (self.ambiguity_handling == "status-query"):
            raise ConnectorSDKError(
                "connector status-query capability conflicts with ambiguity handling"
            )

    @property
    def names(self) -> frozenset[str]:
        """Public capability labels used by operation-pack route requirements."""

        names: set[str] = set()
        if self.idempotent_dispatch:
            names.add("idempotent-dispatch")
        if self.status_query:
            names.add("status-query")
        if self.cancellation:
            names.add("cancellation")
        if self.fencing:
            names.add("fencing")
        return frozenset(names)

    def payload(self) -> dict[str, JsonValue]:
        return {
            "ambiguity_handling": cast(str, self.ambiguity_handling),
            "cancellation": self.cancellation,
            "fencing": self.fencing,
            "idempotent_dispatch": self.idempotent_dispatch,
            "max_payload_bytes": self.max_payload_bytes,
            "max_result_bytes": self.max_result_bytes,
            "status_query": self.status_query,
        }


class ConnectorOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ConnectorEvidence:
    """Connector-authored bounded evidence before MasuGate's private audit projection."""

    connector_id: str
    evidence_id: str
    idempotency_key: str
    external_operation_id: str | None
    outcome: ConnectorOutcome
    observed_at: datetime
    payload: ConnectorResult = field(default_factory=dict)

    def __post_init__(self) -> None:
        for field_name in ("connector_id", "evidence_id", "idempotency_key"):
            _identifier(getattr(self, field_name), field_name)
        if self.external_operation_id is not None:
            _identifier(self.external_operation_id, "external_operation_id")
        if type(self.outcome) is not ConnectorOutcome:
            raise ConnectorSDKError("connector evidence outcome must be a ConnectorOutcome")
        _aware(self.observed_at, "connector evidence observed_at")
        payload = {
            key: _json_value(value, f"connector evidence payload.{key}")
            for key, value in self.payload.items()
            if type(key) is str and key
        }
        if len(payload) != len(self.payload):
            raise ConnectorSDKError("connector evidence payload names must be non-empty strings")
        object.__setattr__(self, "payload", MappingProxyType(deepcopy(payload)))


@dataclass(frozen=True, slots=True)
class ArtifactDescriptor:
    """Certified metadata for one opaque payload; it deliberately has no path."""

    reference: str
    content_digest: str
    content_bytes: int
    media_type: str
    classification: str
    expires_at: datetime

    def __post_init__(self) -> None:
        _identifier(self.reference, "artifact reference")
        _digest(self.content_digest, "artifact content_digest")
        if type(self.content_bytes) is not int or self.content_bytes < 0:
            raise ConnectorSDKError("artifact content_bytes must be a non-negative integer")
        _identifier(self.media_type, "artifact media_type", maximum_length=128)
        _identifier(self.classification, "artifact classification")
        _aware(self.expires_at, "artifact expires_at")


class ArtifactReader(Protocol):
    """Connector-only verified byte reader; neither paths nor stores are exposed."""

    @property
    def metadata(self) -> ArtifactDescriptor: ...

    async def read(self, *, maximum_bytes: int | None = None) -> bytes: ...


@dataclass(frozen=True, slots=True)
class SecretHandle:
    """Non-printing credential bytes scoped to one trusted connector process."""

    _value: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self._value, bytes) or not self._value:
            raise ConnectorSDKError("secret handle must contain bytes")

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self._value).hexdigest()

    def read(self) -> bytes:
        return bytes(self._value)

    def __repr__(self) -> str:
        return f"SecretHandle(fingerprint={self.fingerprint!r}, redacted=True)"


@dataclass(frozen=True, slots=True)
class ConnectorInvocation:
    """Immutable public context; intentionally excludes MasuGate runtime internals."""

    action: str
    arguments: Mapping[str, JsonValue]
    execution_id: str
    binding_digest: str
    connector_id: str
    idempotency_key: str
    fence_token: int
    artifacts: Mapping[str, ArtifactReader]
    secrets: Mapping[str, SecretHandle]
    allowed_destinations: tuple[str, ...]
    # The worker supplies the durable protected-intent creation time only on
    # reconciliation. An exact connector may use it to bound an idempotent
    # retry when the remote operation id was lost with the response.
    idempotency_started_at: datetime | None = None
    # The worker's committed deployment-profile digest. Connectors with a
    # runtime profile must compare this before using configuration that is
    # loaded at dispatch or reconciliation time.
    connector_configuration_digest: str | None = None

    def __post_init__(self) -> None:
        for field_name in ("action", "execution_id", "connector_id", "idempotency_key"):
            _identifier(getattr(self, field_name), field_name)
        _digest(self.binding_digest, "binding_digest")
        if type(self.fence_token) is not int or self.fence_token < 0:
            raise ConnectorSDKError("fence_token must be a non-negative integer")
        if self.idempotency_started_at is not None:
            _aware(self.idempotency_started_at, "idempotency_started_at")
        if self.connector_configuration_digest is not None:
            _digest(self.connector_configuration_digest, "connector_configuration_digest")
        arguments = {
            _identifier(name, "connector argument name"): _json_value(value, f"arguments.{name}")
            for name, value in self.arguments.items()
        }
        if len(arguments) != len(self.arguments):
            raise ConnectorSDKError("connector arguments must have unique canonical names")
        artifacts: dict[str, ArtifactReader] = {}
        for name, reader in self.artifacts.items():
            _identifier(name, "artifact field")
            if not callable(getattr(reader, "read", None)) or not hasattr(reader, "metadata"):
                raise ConnectorSDKError("connector artifact reader is malformed")
            artifacts[name] = reader
        secrets: dict[str, SecretHandle] = {}
        for name, secret in self.secrets.items():
            _identifier(name, "secret reference")
            if type(secret) is not SecretHandle:
                raise ConnectorSDKError("connector secret must be a SecretHandle")
            secrets[name] = secret
        destinations = tuple(
            _identifier(item, "allowed destination") for item in self.allowed_destinations
        )
        if len(set(destinations)) != len(destinations):
            raise ConnectorSDKError("allowed destinations must be unique")
        object.__setattr__(self, "arguments", MappingProxyType(deepcopy(arguments)))
        object.__setattr__(self, "artifacts", MappingProxyType(dict(sorted(artifacts.items()))))
        object.__setattr__(self, "secrets", MappingProxyType(dict(sorted(secrets.items()))))
        object.__setattr__(self, "allowed_destinations", tuple(sorted(destinations)))


class OperationConnector(Protocol):
    """The complete public connector SPI implemented by external packages."""

    connector_id: str
    sdk_contract_version: str
    capabilities: ConnectorCapabilities

    async def execute(self, invocation: ConnectorInvocation) -> ConnectorEvidence: ...

    async def query_status(
        self,
        invocation: ConnectorInvocation,
        *,
        external_operation_id: str | None,
    ) -> ConnectorEvidence: ...

    async def cancel(
        self,
        invocation: ConnectorInvocation,
        *,
        external_operation_id: str | None,
    ) -> ConnectorEvidence: ...


def validate_operation_connector(value: object) -> OperationConnector:
    """Validate an entry-point object without importing any MasuGate internals."""

    for attribute in ("connector_id", "sdk_contract_version", "capabilities"):
        if not hasattr(value, attribute):
            raise ConnectorSDKError(f"connector entry point lacks {attribute}")
    connector = cast(OperationConnector, value)
    _identifier(connector.connector_id, "connector_id")
    if connector.sdk_contract_version != SDK_CONTRACT_VERSION:
        raise ConnectorSDKError("connector SDK contract version is unsupported")
    if type(connector.capabilities) is not ConnectorCapabilities:
        raise ConnectorSDKError("connector capabilities must be ConnectorCapabilities")
    for method in ("execute", "query_status", "cancel"):
        if not callable(getattr(value, method, None)):
            raise ConnectorSDKError(f"connector entry point lacks callable {method}")
    return connector


__all__ = [
    "SDK_CONTRACT_VERSION",
    "ArtifactDescriptor",
    "ArtifactReader",
    "ConnectorAmbiguousOutcome",
    "ConnectorCapabilities",
    "ConnectorEvidence",
    "ConnectorInvocation",
    "ConnectorOutcome",
    "ConnectorResult",
    "ConnectorSDKError",
    "JsonValue",
    "OperationConnector",
    "SecretHandle",
    "validate_operation_connector",
]
