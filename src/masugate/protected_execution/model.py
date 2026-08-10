"""Immutable records for durable protected external execution."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import cast

from masugate.contracts import ProviderIdentity
from masugate.model import JsonValue


def _canonical_identity(value: object, field_name: str) -> str:
    if not (
        type(value) is str
        and 0 < len(value) <= 255
        and value.strip() == value
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise ValueError(f"{field_name} must be a canonical identity")
    return value


def _sha256(value: object, field_name: str) -> str:
    text = _canonical_identity(value, field_name)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return text


def _aware(value: object, field_name: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    return value


def _json_value(value: object, field_name: str) -> JsonValue:
    if value is None or type(value) in {bool, int, str}:
        return cast(JsonValue, value)
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError(f"{field_name} contains a non-finite float")
        return value
    if isinstance(value, list):
        return [_json_value(item, f"{field_name}[]") for item in value]
    if isinstance(value, dict):
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError(f"{field_name} contains a non-string object key")
            result[key] = _json_value(item, f"{field_name}.{key}")
        return result
    raise TypeError(f"{field_name} contains unsupported value {type(value).__name__}")


def canonical_json(value: JsonValue) -> str:
    """Encode a JSON value in the binding/evidence canonical form."""

    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


class ProtectedExecutionStatus(StrEnum):
    INTENT = "intent"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    OUTCOME_UNKNOWN = "outcome_unknown"


class EntitlementState(StrEnum):
    HELD = "held"
    CONSUMED = "consumed"
    RELEASED = "released"
    QUARANTINED = "quarantined"


class ConnectorOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ProtectedExecutionAuthority:
    """Trusted deployment-assembly identity allowed to create one external intent."""

    action: str
    provider_identity: ProviderIdentity
    coordination_domain_id: str
    connector_id: str

    def __post_init__(self) -> None:
        for name in ("action", "coordination_domain_id", "connector_id"):
            _canonical_identity(getattr(self, name), name)
        if type(self.provider_identity) is not ProviderIdentity:
            raise TypeError("protected execution authority needs a ProviderIdentity")

    def validate(self, binding: ProtectedExecutionBinding) -> None:
        if binding.action != self.action:
            raise ValueError("protected execution binding names an unauthorized action")
        if binding.provider_identity != self.provider_identity:
            raise ValueError("protected execution binding names an unauthorized provider")
        if binding.coordination_domain_id != self.coordination_domain_id:
            raise ValueError("protected execution binding names an unauthorized domain")
        if binding.connector_id != self.connector_id:
            raise ValueError("protected execution binding names an unauthorized connector")


@dataclass(frozen=True, order=True)
class PolicyBinding:
    """Exact policy/bundle identity used by the protected authorization."""

    policy_id: str
    policy_version: str
    policy_digest: str
    bundle_id: str
    bundle_version: str
    bundle_digest: str

    def __post_init__(self) -> None:
        for name in ("policy_id", "policy_version", "bundle_id", "bundle_version"):
            _canonical_identity(getattr(self, name), name)
        _sha256(self.policy_digest, "policy_digest")
        _sha256(self.bundle_digest, "bundle_digest")

    def payload(self) -> dict[str, JsonValue]:
        return {
            "bundle_digest": self.bundle_digest,
            "bundle_id": self.bundle_id,
            "bundle_version": self.bundle_version,
            "policy_digest": self.policy_digest,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
        }


@dataclass(frozen=True)
class ProtectedExecutionBinding:
    """Immutable identity of one authorized external tool execution."""

    principal_id: str
    action: str
    arguments: Mapping[str, JsonValue]
    idempotency_key: str
    policies: tuple[PolicyBinding, ...]
    provider_identity: ProviderIdentity
    coordination_domain_id: str
    scopes: tuple[str, ...]
    tool_call_id: str
    connector_id: str
    entitlement_id: str
    # A provider-owned immutable authorization record may carry state-read
    # versions and resolution evidence that do not belong in the public action
    # arguments.  The digest binds that record to the generic intent without
    # overloading a policy or bundle digest with unrelated state.
    authorization_digest: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "principal_id",
            "action",
            "idempotency_key",
            "coordination_domain_id",
            "tool_call_id",
            "connector_id",
            "entitlement_id",
        ):
            _canonical_identity(getattr(self, name), name)
        if type(self.provider_identity) is not ProviderIdentity:
            raise TypeError("provider_identity must be a ProviderIdentity")
        if self.authorization_digest is not None:
            _sha256(self.authorization_digest, "authorization_digest")
        if not self.policies:
            raise ValueError("protected execution must bind at least one policy")
        policies = tuple(sorted(self.policies))
        if len(set(policies)) != len(policies):
            raise ValueError("protected execution policies contain duplicates")
        scopes = tuple(sorted(self.scopes))
        if not scopes or any(type(scope) is not str or not scope for scope in scopes):
            raise ValueError("protected execution must bind non-empty scopes")
        if len(set(scopes)) != len(scopes):
            raise ValueError("protected execution scopes contain duplicates")
        arguments = {
            key: _json_value(value, f"arguments.{key}")
            for key, value in self.arguments.items()
            if type(key) is str and key
        }
        if len(arguments) != len(self.arguments):
            raise ValueError("protected execution argument names must be non-empty strings")
        object.__setattr__(self, "arguments", MappingProxyType(deepcopy(arguments)))
        object.__setattr__(self, "policies", policies)
        object.__setattr__(self, "scopes", scopes)

    def payload(self) -> dict[str, JsonValue]:
        return {
            "action": self.action,
            "arguments": dict(self.arguments),
            "connector_id": self.connector_id,
            "coordination_domain_id": self.coordination_domain_id,
            "entitlement_id": self.entitlement_id,
            "idempotency_key": self.idempotency_key,
            "policies": [policy.payload() for policy in self.policies],
            "principal_id": self.principal_id,
            "provider_identity": {
                "configuration_version": self.provider_identity.configuration_version,
                "implementation_version": self.provider_identity.implementation_version,
                "provider_id": self.provider_identity.provider_id,
            },
            "scopes": list(self.scopes),
            "tool_call_id": self.tool_call_id,
            **(
                {}
                if self.authorization_digest is None
                else {"authorization_digest": self.authorization_digest}
            ),
        }

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.payload()).encode("utf-8")).hexdigest()

    @property
    def execution_id(self) -> str:
        return f"px:{self.digest}"

    @property
    def provider_idempotency_key(self) -> str:
        return f"masugate:{self.digest}"


@dataclass(frozen=True)
class ConnectorEvidence:
    """Provider-owned evidence about an attempted external operation."""

    connector_id: str
    evidence_id: str
    idempotency_key: str
    external_operation_id: str | None
    outcome: ConnectorOutcome
    observed_at: datetime
    payload: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in ("connector_id", "evidence_id", "idempotency_key"):
            _canonical_identity(getattr(self, name), name)
        if self.external_operation_id is not None:
            _canonical_identity(self.external_operation_id, "external_operation_id")
        if type(self.outcome) is not ConnectorOutcome:
            raise TypeError("connector evidence outcome must be a ConnectorOutcome")
        _aware(self.observed_at, "connector evidence observed_at")
        payload = {
            key: _json_value(value, f"evidence.payload.{key}")
            for key, value in self.payload.items()
            if type(key) is str and key
        }
        if len(payload) != len(self.payload):
            raise ValueError("connector evidence payload names must be non-empty strings")
        object.__setattr__(self, "payload", MappingProxyType(deepcopy(payload)))

    def validate_for(
        self,
        binding: ProtectedExecutionBinding,
        *,
        expected_external_operation_id: str | None = None,
    ) -> None:
        if self.connector_id != binding.connector_id:
            raise ValueError("connector evidence names the wrong connector")
        if self.idempotency_key != binding.provider_idempotency_key:
            raise ValueError("connector evidence names the wrong idempotency key")
        if self.outcome is not ConnectorOutcome.UNKNOWN and self.external_operation_id is None:
            raise ValueError("terminal connector evidence needs an external operation id")
        if (
            expected_external_operation_id is not None
            and self.external_operation_id is not None
            and self.external_operation_id != expected_external_operation_id
        ):
            raise ValueError("connector evidence changed the external-operation identity")

    def payload_json(self) -> dict[str, JsonValue]:
        return {
            "connector_id": self.connector_id,
            "evidence_id": self.evidence_id,
            "external_operation_id": self.external_operation_id,
            "idempotency_key": self.idempotency_key,
            "observed_at": self.observed_at.isoformat(),
            "outcome": self.outcome.value,
            "payload": dict(self.payload),
        }


@dataclass(frozen=True)
class ProtectedExecutionRecord:
    execution_id: str
    binding: ProtectedExecutionBinding
    binding_digest: str
    status: ProtectedExecutionStatus
    entitlement_state: EntitlementState
    dispatch_started: bool
    cancel_requested: bool
    external_operation_id: str | None
    lease_owner: str | None
    fence_token: int
    lease_expires_at: datetime | None
    receipt: ConnectorEvidence | None
    result: Mapping[str, JsonValue]
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        _canonical_identity(self.execution_id, "execution_id")
        _sha256(self.binding_digest, "binding_digest")
        if self.execution_id != self.binding.execution_id:
            raise ValueError("execution id does not match immutable binding")
        if self.binding_digest != self.binding.digest:
            raise ValueError("binding digest does not match immutable binding")
        if type(self.status) is not ProtectedExecutionStatus:
            raise TypeError("status must be a ProtectedExecutionStatus")
        if type(self.entitlement_state) is not EntitlementState:
            raise TypeError("entitlement_state must be an EntitlementState")
        if type(self.dispatch_started) is not bool or type(self.cancel_requested) is not bool:
            raise TypeError("dispatch/cancel flags must be bools")
        if type(self.fence_token) is not int or self.fence_token < 0:
            raise ValueError("fence_token must be a non-negative integer")
        if self.lease_owner is not None:
            _canonical_identity(self.lease_owner, "lease_owner")
        if self.lease_expires_at is not None:
            _aware(self.lease_expires_at, "lease_expires_at")
        if self.external_operation_id is not None:
            _canonical_identity(self.external_operation_id, "external_operation_id")
        if not self.dispatch_started and (
            self.receipt is not None or self.external_operation_id is not None
        ):
            raise ValueError("undispatched execution cannot carry external-operation evidence")
        if self.receipt is not None:
            self.receipt.validate_for(
                self.binding,
                expected_external_operation_id=self.external_operation_id,
            )
            if self.receipt.external_operation_id != self.external_operation_id:
                raise ValueError("receipt does not match the durable external-operation identity")
        if self.status is ProtectedExecutionStatus.INTENT:
            if self.entitlement_state is not EntitlementState.HELD or self.dispatch_started:
                raise ValueError("intent must retain a held, undispatched entitlement")
        elif self.status is ProtectedExecutionStatus.SUCCEEDED:
            if (
                not self.dispatch_started
                or self.entitlement_state is not EntitlementState.CONSUMED
                or self.receipt is None
                or self.receipt.outcome is not ConnectorOutcome.SUCCEEDED
            ):
                raise ValueError("succeeded execution needs success evidence and consumption")
        elif self.status is ProtectedExecutionStatus.FAILED:
            if self.entitlement_state is not EntitlementState.RELEASED:
                raise ValueError("failed execution must release its entitlement")
            if self.dispatch_started and (
                self.receipt is None or self.receipt.outcome is not ConnectorOutcome.FAILED
            ):
                raise ValueError("post-dispatch failure needs connector failure evidence")
        elif self.status is ProtectedExecutionStatus.OUTCOME_UNKNOWN and (
            self.entitlement_state is not EntitlementState.QUARANTINED or not self.dispatch_started
        ):
            raise ValueError("unknown outcome must retain quarantined dispatch protection")
        if self.status in {
            ProtectedExecutionStatus.SUCCEEDED,
            ProtectedExecutionStatus.FAILED,
        } and (self.lease_owner is not None or self.lease_expires_at is not None):
            raise ValueError("terminal execution cannot retain a worker lease")
        _aware(self.created_at, "created_at")
        _aware(self.updated_at, "updated_at")
        result = {
            key: _json_value(value, f"result.{key}")
            for key, value in self.result.items()
            if type(key) is str and key
        }
        if len(result) != len(self.result):
            raise ValueError("result names must be non-empty strings")
        object.__setattr__(self, "result", MappingProxyType(deepcopy(result)))


@dataclass(frozen=True)
class ProtectedExecutionEvent:
    sequence: int
    execution_id: str
    event_type: str
    from_status: ProtectedExecutionStatus | None
    to_status: ProtectedExecutionStatus
    worker_id: str | None
    fence_token: int | None
    recorded_at: datetime
    evidence: Mapping[str, JsonValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or self.sequence <= 0:
            raise ValueError("event sequence must be positive")
        _canonical_identity(self.execution_id, "execution_id")
        _canonical_identity(self.event_type, "event_type")
        if self.worker_id is not None:
            _canonical_identity(self.worker_id, "worker_id")
        _aware(self.recorded_at, "recorded_at")
        event_evidence = {
            key: _json_value(value, f"event.evidence.{key}")
            for key, value in self.evidence.items()
            if type(key) is str and key
        }
        if len(event_evidence) != len(self.evidence):
            raise ValueError("event evidence names must be non-empty strings")
        object.__setattr__(self, "evidence", MappingProxyType(deepcopy(event_evidence)))


__all__ = [
    "ConnectorEvidence",
    "ConnectorOutcome",
    "EntitlementState",
    "PolicyBinding",
    "ProtectedExecutionAuthority",
    "ProtectedExecutionBinding",
    "ProtectedExecutionEvent",
    "ProtectedExecutionRecord",
    "ProtectedExecutionStatus",
    "canonical_json",
]
