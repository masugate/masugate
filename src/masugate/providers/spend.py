"""Framework-neutral spend reservations and protected purchase dispatch.

This is the reference spend reference vertical's provider-owned half.  It has no
agent-host imports or assumptions: callers supply already-certified principal,
team, idempotency, and tool-call identities.  The store atomically records a
budget entitlement and an immutable protected-execution outbox item before a
connector can run.  The outbox, rather than a callback or model request
reference, is the only dispatch source.

The SQLite implementation is the local/reference oracle.  Its schema and
transition rules intentionally use only the small durable outbox surface that
a PostgreSQL reference deployment will use; connector I/O is never performed
inside a store transaction.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import sqlite3
from collections.abc import (
    AsyncIterator,
    Awaitable,
    Callable,
    Collection,
    Coroutine,
    Iterator,
    Mapping,
)
from contextlib import AbstractAsyncContextManager, asynccontextmanager, contextmanager
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast
from uuid import UUID, uuid5

import httpx
import psycopg
from psycopg import Connection
from psycopg.rows import dict_row

from masugate.contracts import (
    EffectContract,
    GovernanceViewContract,
    ProviderIdentity,
    ReservationViewKind,
)
from masugate.errors import ContractError
from masugate.model import (
    ActionRequest,
    ConsistencyGuarantee,
    DecisionEffect,
    Duration,
    JsonValue,
    PendingResolutionPlan,
    PolicyDecision,
    PolicyProvenance,
    Principal,
    ResourceFootprint,
    Scalar,
    TypeName,
    ViewRead,
)
from masugate.protected_execution import (
    ConnectorCapabilities,
    ConnectorContractError,
    ConnectorEvidence,
    ConnectorOutcome,
    ConnectorOutcomeUnknown,
    PolicyBinding,
    ProtectedExecutionAuthority,
    ProtectedExecutionBinding,
    ProtectedExecutionBusy,
    ProtectedExecutionError,
    ProtectedExecutionEvent,
    ProtectedExecutionRecord,
    ProtectedExecutionRecovery,
    ProtectedExecutionRunner,
    ProtectedExecutionStatus,
    ProtectedExecutionStore,
)
from masugate.provider_assembly import (
    CoordinationDomain,
    EffectBinding,
    EffectExecutionPosition,
    ProtectedExecutionRegistration,
    ProtectedExternalExecutor,
    ProviderModule,
)

if TYPE_CHECKING:
    from masugate.catalog import PolicyCatalog
    from masugate.policy import PolicyRuntime

_ACTION = "spend.purchase"
_CONNECTOR_ID = "reference-purchase-v1"
_MODULE_ID = "spend"
_DOMAIN_ID = "masugate.spend.reference.domain.v1"
_SCOPE_DERIVATION_ID = "masugate.spend.reference.scopes.v1"
_IMPLEMENTATION_VERSION = "masugate.spend.reference-v1"
_OPERATION_NAMESPACE = UUID("c950ab5a-4f61-4ac5-a3d3-b8a867be29d5")


class SpendEntitlementState(StrEnum):
    """Provider accounting state for one budget reservation."""

    HELD = "held"
    CONSUMED = "consumed"
    RELEASED = "released"
    QUARANTINED = "quarantined"
    DENIED = "denied"


class SpendHandoffState(StrEnum):
    """Durable outbox state, independent from the runner's own lifecycle."""

    OUTBOX = "outbox"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    OUTCOME_UNKNOWN = "outcome_unknown"


class SpendOperationStatus(StrEnum):
    """Truthful bounded result of the reference purchase service."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMMITTED = "committed"
    DENIED = "denied"
    OUTCOME_UNKNOWN = "outcome_unknown"


class SpendConflictError(ContractError):
    """A caller tried to reuse an immutable entitlement identity differently."""


class _SpendApprovalExpiredError(SpendConflictError):
    """An approved presentation reached the durable handoff after its deadline."""

    def __init__(self, observed_at: datetime) -> None:
        super().__init__("approval window expired before durable protected dispatch")
        self.observed_at = observed_at


class SpendRecoveryError(RuntimeError):
    """One or more protected records failed a provider recovery pass."""

    def __init__(self, errors: tuple[tuple[str, str], ...]) -> None:
        if not errors:
            raise ValueError("spend recovery error requires at least one failure")
        self.errors = tuple(errors)
        super().__init__(f"spend recovery failed for {len(self.errors)} protected execution(s)")


def _canonical_identity(value: object, field_name: str) -> str:
    if not (
        type(value) is str
        and 0 < len(value) <= 255
        and value.strip() == value
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise ValueError(f"{field_name} must be a canonical identity")
    return value


def _canonical_uuid(value: object, field_name: str) -> str:
    identity = _canonical_identity(value, field_name)
    try:
        parsed = UUID(identity)
    except ValueError as exc:
        raise ValueError(f"{field_name} must be a canonical UUID") from exc
    if str(parsed) != identity:
        raise ValueError(f"{field_name} must be a canonical UUID")
    return identity


def _positive_int(value: object, field_name: str) -> int:
    if type(value) is not int or value <= 0 or value > 2**63 - 1:
        raise ValueError(f"{field_name} must be a positive signed 64-bit integer")
    return value


def _canonical_json(value: JsonValue) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _digest(value: JsonValue) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _credential_fingerprint(credential: str) -> str:
    """Return a non-secret identity for a connector bearer credential."""

    return hashlib.sha256(credential.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ReferencePurchaseCredentialManifest:
    """Non-secret credential identities shared by both deployment processes.

    The manifest makes connector/action credential separation a startup
    invariant on both sides of the HTTP boundary.  It carries only SHA-256
    fingerprints, never the credentials themselves.
    """

    connector_credential_fingerprint: str
    masugate_bearer_credential_fingerprints: tuple[str, ...]

    def __post_init__(self) -> None:
        _sha256(
            self.connector_credential_fingerprint,
            "reference purchase connector credential fingerprint",
        )
        if not self.masugate_bearer_credential_fingerprints:
            raise ValueError("reference purchase manifest needs MasuGate bearer fingerprints")
        fingerprints = tuple(self.masugate_bearer_credential_fingerprints)
        for fingerprint in fingerprints:
            _sha256(fingerprint, "reference purchase MasuGate bearer credential fingerprint")
        if fingerprints != tuple(sorted(set(fingerprints))):
            raise ValueError(
                "reference purchase MasuGate bearer fingerprints must be sorted and unique"
            )
        if self.connector_credential_fingerprint in fingerprints:
            raise ValueError(
                "reference connector credential must be distinct from every "
                "MasuGate bearer credential"
            )

    @classmethod
    def from_credentials(
        cls,
        *,
        connector_service_token: str,
        masugate_bearer_credentials: Collection[str],
    ) -> ReferencePurchaseCredentialManifest:
        """Build a manifest at a trusted composition boundary from raw secrets."""

        connector = _canonical_identity(
            connector_service_token,
            "reference purchase connector service token",
        )
        bearers = tuple(
            _canonical_identity(token, "MasuGate bearer credential")
            for token in masugate_bearer_credentials
        )
        if not bearers:
            raise ValueError("reference purchase manifest needs MasuGate bearer credentials")
        return cls(
            connector_credential_fingerprint=_credential_fingerprint(connector),
            masugate_bearer_credential_fingerprints=tuple(
                sorted({_credential_fingerprint(token) for token in bearers})
            ),
        )

    @property
    def digest(self) -> str:
        return _digest(
            {
                "connector_credential_fingerprint": self.connector_credential_fingerprint,
                "masugate_bearer_credential_fingerprints": list(
                    self.masugate_bearer_credential_fingerprints
                ),
                "version": "masugate.reference-purchase-credentials.v1",
            }
        )

    def validates_connector_credential(self, credential: str) -> bool:
        return hmac.compare_digest(
            self.connector_credential_fingerprint,
            _credential_fingerprint(credential),
        )


def _sha256(value: object, field_name: str) -> str:
    digest = _canonical_identity(value, field_name)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return digest


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _advisory_key(scope: str) -> int:
    """Return a stable signed lock key without exposing a raw identifier."""

    digest = hashlib.blake2b(scope.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, byteorder="big", signed=True)


@dataclass(frozen=True)
class SpendPolicy:
    """Reference budget and approval policy owned by the spend provider."""

    budget_limit_cents: int
    approval_threshold_cents: int
    approval_timeout_seconds: int = 600
    policy_id: str = "spend_budget_guard"
    policy_version: str = "1.0.0"
    bundle_id: str = "masugate.spend.reference"
    bundle_version: str = "1.0.0"

    def __post_init__(self) -> None:
        _positive_int(self.budget_limit_cents, "budget_limit_cents")
        _positive_int(self.approval_threshold_cents, "approval_threshold_cents")
        _positive_int(self.approval_timeout_seconds, "approval_timeout_seconds")
        if self.approval_threshold_cents > self.budget_limit_cents:
            raise ValueError("approval_threshold_cents cannot exceed budget_limit_cents")
        for name in ("policy_id", "policy_version", "bundle_id", "bundle_version"):
            _canonical_identity(getattr(self, name), name)

    @property
    def configuration_digest(self) -> str:
        return _digest(
            {
                "approval_threshold_cents": self.approval_threshold_cents,
                "approval_timeout_seconds": self.approval_timeout_seconds,
                "bundle_id": self.bundle_id,
                "bundle_version": self.bundle_version,
                "budget_limit_cents": self.budget_limit_cents,
                "policy_id": self.policy_id,
                "policy_version": self.policy_version,
                "scope_derivation": _SCOPE_DERIVATION_ID,
            }
        )

    @property
    def provider_identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="masugate.spend.reference",
            implementation_version=_IMPLEMENTATION_VERSION,
            configuration_version=self.configuration_digest,
        )


@dataclass(frozen=True)
class SpendPolicyProvenance:
    """Catalog provenance that the protected binding carries with its state read.

    The source and manifest digests are pinned by the reference deployment's
    catalog.  The protected binding additionally derives a digest that includes
    the provider configuration and the exact budget version read at admission.
    """

    policy_digest: str
    bundle_digest: str

    def __post_init__(self) -> None:
        _sha256(self.policy_digest, "policy_digest")
        _sha256(self.bundle_digest, "bundle_digest")


def _scalar_payload(value: Scalar | Duration) -> JsonValue:
    if type(value) is Duration:
        return {"duration_seconds": value.seconds}
    return cast(JsonValue, value)


def _scalar_from_payload(value: JsonValue) -> Scalar | Duration:
    if isinstance(value, dict) and set(value) == {"duration_seconds"}:
        seconds = value["duration_seconds"]
        if type(seconds) is not int:
            raise SpendConflictError("durable spend duration is malformed")
        return Duration(seconds)
    if type(value) in {bool, int, str}:
        return cast(Scalar, value)
    raise SpendConflictError("durable spend scalar is malformed")


def _decision_payload(decision: PolicyDecision) -> dict[str, JsonValue]:
    """Encode policy evidence without relying on mutable catalog state."""

    return {
        "effect": decision.effect.value,
        "evaluated_policies": [
            [policy_id, policy_version] for policy_id, policy_version in decision.evaluated_policies
        ],
        "policy_id": decision.policy_id,
        "policy_provenance": [
            {
                "bundle_digest": item.bundle_digest,
                "bundle_id": item.bundle_id,
                "bundle_version": item.bundle_version,
                "layer": item.layer,
                "mode": item.mode,
                "policy_declared_version": item.policy_declared_version,
                "policy_digest": item.policy_digest,
                "policy_id": item.policy_id,
                "policy_runtime_version": item.policy_runtime_version,
            }
            for item in decision.policy_provenance
        ],
        "policy_version": decision.policy_version,
        "reads": [
            {
                "arguments": [_scalar_payload(argument) for argument in read.arguments],
                "function": read.function,
                "latency_ms": read.latency_ms,
                "scope": read.scope,
                "value": _scalar_payload(read.value),
                "version": read.version,
            }
            for read in decision.reads
        ],
        "reason": decision.reason,
        "rule_id": decision.rule_id,
    }


def _decision_from_payload(payload: Mapping[str, JsonValue]) -> PolicyDecision:
    """Decode the exact admission decision stored beside an entitlement."""

    try:
        reads: list[ViewRead] = []
        for raw_read in cast(list[JsonValue], payload.get("reads", [])):
            read = cast(dict[str, JsonValue], raw_read)
            reads.append(
                ViewRead(
                    function=cast(str, read["function"]),
                    arguments=tuple(
                        _scalar_from_payload(item)
                        for item in cast(list[JsonValue], read["arguments"])
                    ),
                    value=cast(Scalar, _scalar_from_payload(read["value"])),
                    scope=cast(str, read["scope"]),
                    version=cast(int, read["version"]),
                    latency_ms=float(cast(float | int, read["latency_ms"])),
                )
            )
        provenance: list[PolicyProvenance] = []
        for raw_provenance in cast(list[JsonValue], payload.get("policy_provenance", [])):
            item = cast(dict[str, JsonValue], raw_provenance)
            provenance.append(
                PolicyProvenance(
                    policy_id=cast(str, item["policy_id"]),
                    policy_declared_version=cast(str, item["policy_declared_version"]),
                    policy_runtime_version=cast(str, item["policy_runtime_version"]),
                    policy_digest=cast(str, item["policy_digest"]),
                    bundle_id=cast(str, item["bundle_id"]),
                    bundle_version=cast(str, item["bundle_version"]),
                    bundle_digest=cast(str, item["bundle_digest"]),
                    layer=cast(str, item["layer"]),
                    mode=cast(str, item["mode"]),
                )
            )
        evaluated: list[tuple[str, str]] = []
        for raw_evaluated in cast(list[JsonValue], payload.get("evaluated_policies", [])):
            evaluated_item = cast(list[str], raw_evaluated)
            if len(evaluated_item) != 2:
                raise ValueError("evaluated policy identity is malformed")
            evaluated.append((evaluated_item[0], evaluated_item[1]))
        return PolicyDecision(
            effect=DecisionEffect(cast(str, payload["effect"])),
            policy_id=cast(str, payload["policy_id"]),
            rule_id=cast(str, payload["rule_id"]),
            reason=cast(str, payload["reason"]),
            reads=tuple(reads),
            policy_version=cast(str, payload.get("policy_version", "")),
            evaluated_policies=tuple(evaluated),
            policy_provenance=tuple(provenance),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SpendConflictError("durable spend authorization is malformed") from exc


@dataclass(frozen=True)
class SpendResolution:
    """Immutable terminal-resolution evidence for an escalated entitlement.

    ``human`` evidence records an operator decision. ``automatic-expiry`` is
    the policy-configured deadline firing without human intervention; keeping
    it distinct prevents receipts from laundering a mechanism timeout into a
    human approval or rejection.
    """

    approved: bool
    actor_id: str
    evidence: Mapping[str, JsonValue] = field(default_factory=dict)
    resolved_at: datetime = field(default_factory=_utc_now)
    kind: Literal["human", "automatic-expiry"] = "human"

    def __post_init__(self) -> None:
        if type(self.approved) is not bool:
            raise TypeError("spend resolution approved must be bool")
        _canonical_identity(self.actor_id, "spend resolution actor_id")
        if self.kind not in {"human", "automatic-expiry"}:
            raise ValueError("spend resolution kind is unsupported")
        if self.kind == "automatic-expiry":
            if self.approved:
                raise ValueError("automatic expiry may not approve an entitlement")
            if self.actor_id != "masugate.approval-expiry":
                raise ValueError("automatic expiry must use the MasuGate expiry actor")
        elif self.actor_id == "masugate.approval-expiry":
            raise ValueError("the MasuGate expiry actor is reserved for automatic expiry")
        if type(self.resolved_at) is not datetime or self.resolved_at.tzinfo is None:
            raise ValueError("spend resolution time must be timezone-aware")
        try:
            normalized = json.loads(_canonical_json(cast(JsonValue, dict(self.evidence))))
        except (TypeError, ValueError) as exc:
            raise ValueError("spend resolution evidence must be JSON") from exc
        if not isinstance(normalized, dict):  # pragma: no cover - dict() above
            raise ValueError("spend resolution evidence must be an object")
        object.__setattr__(
            self, "evidence", MappingProxyType(cast(dict[str, JsonValue], normalized))
        )
        if self.kind == "automatic-expiry" and (
            self.evidence.get("reason") != "approval-window-expired"
            or type(self.evidence.get("expires_at")) is not str
        ):
            raise ValueError("automatic expiry requires canonical deadline evidence")

    def payload(self) -> dict[str, JsonValue]:
        return {
            "actor_id": self.actor_id,
            "approved": self.approved,
            "evidence": dict(self.evidence),
            "kind": self.kind,
            "resolved_at": _time(self.resolved_at),
        }


@dataclass(frozen=True)
class SpendAdmissionSession:
    """The store transaction whose view reads and reservation share one lock."""

    connection: Any
    reservation_team_id: str | None = None
    reservation_credit_cents: int = 0

    def __post_init__(self) -> None:
        if self.reservation_team_id is None:
            if self.reservation_credit_cents != 0:
                raise ValueError("spend reservation credit requires a team identity")
        else:
            _canonical_identity(self.reservation_team_id, "reservation_team_id")
            if type(self.reservation_credit_cents) is not int or self.reservation_credit_cents <= 0:
                raise ValueError("spend reservation credit must be a positive integer")


type SpendAuthorizer = Callable[
    [SpendPurchaseRequest, SpendAdmissionSession, datetime], PolicyDecision
]
type SpendHandoffCommitter = Callable[[SpendHandoff], Awaitable[None]]


@dataclass(frozen=True)
class SpendPurchaseRequest:
    """Trusted, already-certified purchase input.

    ``request_ref`` is a bound business argument only.  It is deliberately not
    used for replay, entitlement lookup, or external dispatch identity.
    """

    principal_id: str
    team_id: str
    amount_cents: int
    merchant_id: str
    request_ref: str
    idempotency_key: str
    tool_call_id: str
    # Reference deployment callers bind this server-verified digest whenever
    # the request originated in a host adapter. Generic provider consumers may
    # omit it, preserving their established request identity.
    adapter_invocation_digest: str | None = None

    def __post_init__(self) -> None:
        for name in (
            "principal_id",
            "team_id",
            "merchant_id",
            "request_ref",
            "idempotency_key",
            "tool_call_id",
        ):
            _canonical_identity(getattr(self, name), name)
        _positive_int(self.amount_cents, "amount_cents")
        if self.adapter_invocation_digest is not None:
            _sha256(self.adapter_invocation_digest, "adapter_invocation_digest")

    @property
    def payload(self) -> dict[str, JsonValue]:
        payload: dict[str, JsonValue] = {
            "amount_cents": self.amount_cents,
            "idempotency_key": self.idempotency_key,
            "merchant_id": self.merchant_id,
            "principal_id": self.principal_id,
            "request_ref": self.request_ref,
            "team_id": self.team_id,
            "tool_call_id": self.tool_call_id,
        }
        if self.adapter_invocation_digest is not None:
            payload["adapter_invocation_digest"] = self.adapter_invocation_digest
        return payload

    @property
    def digest(self) -> str:
        return _digest(self.payload)


@dataclass(frozen=True)
class SpendEntitlement:
    entitlement_id: str
    operation_id: str
    pending_id: str
    request: SpendPurchaseRequest
    budget_version: int
    configuration_digest: str
    authorization: PolicyDecision
    state: SpendEntitlementState
    created_at: datetime
    updated_at: datetime
    resolution: SpendResolution | None = None

    def __post_init__(self) -> None:
        _canonical_identity(self.entitlement_id, "entitlement_id")
        _canonical_uuid(self.operation_id, "operation_id")
        _canonical_uuid(self.pending_id, "pending_id")
        if type(self.budget_version) is not int or self.budget_version < 0:
            raise ValueError("budget_version must be a non-negative integer")
        _sha256(self.configuration_digest, "configuration_digest")
        if type(self.authorization) is not PolicyDecision:
            raise TypeError("spend entitlement authorization must be a PolicyDecision")
        if type(self.state) is not SpendEntitlementState:
            raise TypeError("state must be SpendEntitlementState")
        if self.resolution is not None and type(self.resolution) is not SpendResolution:
            raise TypeError("spend entitlement resolution must be a SpendResolution")
        for name in ("created_at", "updated_at"):
            value = getattr(self, name)
            if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{name} must be timezone-aware")

    @property
    def authorization_digest(self) -> str:
        """Bind generic execution to this exact durable policy evaluation."""

        return _digest(
            {
                "authorization": _decision_payload(self.authorization),
                "budget_version": self.budget_version,
                "configuration_digest": self.configuration_digest,
                "request_digest": self.request.digest,
                "resolution": (None if self.resolution is None else self.resolution.payload()),
            }
        )


def _dispatch_authorization(entitlement: SpendEntitlement) -> PolicyDecision:
    """Return the latest provider-owned decision that authorizes dispatch."""

    authorization = entitlement.authorization
    if entitlement.resolution is None:
        return authorization
    raw_revalidation = entitlement.resolution.evidence.get("masugate_revalidation_v1")
    if raw_revalidation is None:
        return authorization
    if not isinstance(raw_revalidation, dict):
        raise SpendConflictError("durable spend revalidation evidence is malformed")
    raw_decision = raw_revalidation.get("decision")
    if not isinstance(raw_decision, dict):
        raise SpendConflictError("durable spend revalidation decision is malformed")
    authorization = _decision_from_payload(raw_decision)
    if authorization.effect is DecisionEffect.DENY:
        raise SpendConflictError("denied spend revalidation cannot authorize protected dispatch")
    return authorization


@dataclass(frozen=True)
class SpendReservation:
    """Admission result that distinguishes a first request from idempotent replay."""

    entitlement: SpendEntitlement
    replayed: bool

    def __post_init__(self) -> None:
        if type(self.entitlement) is not SpendEntitlement:
            raise TypeError("reservation entitlement must be SpendEntitlement")
        if type(self.replayed) is not bool:
            raise TypeError("reservation replayed must be bool")


@dataclass(frozen=True)
class SpendHandoff:
    """One immutable outbox record bound to one spend entitlement."""

    entitlement_id: str
    binding: ProtectedExecutionBinding
    authorization_digest: str
    state: SpendHandoffState
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        _canonical_identity(self.entitlement_id, "entitlement_id")
        if self.binding.entitlement_id != self.entitlement_id:
            raise ValueError("handoff binding must name the exact entitlement")
        _sha256(self.authorization_digest, "handoff authorization_digest")
        if self.binding.authorization_digest != self.authorization_digest:
            raise ValueError("handoff binding must name the exact authorization evidence")
        if type(self.state) is not SpendHandoffState:
            raise TypeError("state must be SpendHandoffState")
        for name in ("created_at", "updated_at"):
            value = getattr(self, name)
            if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{name} must be timezone-aware")


class SpendOutboxStore(Protocol):
    """Durable provider boundary shared by the SQLite oracle and PostgreSQL path."""

    policy: SpendPolicy

    async def initialize(self) -> None: ...

    def open_policy_session(
        self,
        *,
        write: bool,
    ) -> AbstractAsyncContextManager[SpendAdmissionSession]: ...

    async def reserve(
        self,
        request: SpendPurchaseRequest,
        *,
        authorize: SpendAuthorizer | None = None,
    ) -> SpendReservation | None: ...

    async def get_entitlement(self, entitlement_id: str) -> SpendEntitlement: ...

    async def get_entitlement_by_pending_id(self, pending_id: str) -> SpendEntitlement: ...

    async def get_entitlement_by_operation_id(self, operation_id: str) -> SpendEntitlement: ...

    async def pending_entitlements(
        self,
        *,
        principal_id: str | None = None,
    ) -> tuple[SpendEntitlement, ...]: ...

    async def approved_resolutions_without_handoff(self) -> tuple[SpendEntitlement, ...]:
        """Return approved durable decisions still awaiting their first handoff."""

        ...

    async def record_approved_resolution(
        self,
        entitlement_id: str,
        resolution: SpendResolution,
        *,
        authorize: SpendAuthorizer | None = None,
        pending_plan: PendingResolutionPlan | None = None,
    ) -> SpendEntitlement:
        """Persist one pre-dispatch approval and its required revalidation."""

        ...

    async def create_handoff(
        self,
        entitlement_id: str,
        binding: ProtectedExecutionBinding,
        *,
        resolution: SpendResolution | None = None,
    ) -> SpendHandoff: ...

    async def get_handoff(self, entitlement_id: str) -> SpendHandoff | None: ...

    async def unresolved_handoffs(self) -> tuple[SpendHandoff, ...]: ...

    async def reject(
        self,
        entitlement_id: str,
        *,
        resolution: SpendResolution | None = None,
    ) -> SpendEntitlement: ...

    async def settle(
        self,
        handoff: SpendHandoff,
        protected: ProtectedExecutionRecord,
    ) -> tuple[SpendHandoff, SpendEntitlement]: ...

    async def budget(self, team_id: str) -> tuple[int, int, int]: ...


@dataclass(frozen=True)
class SpendOperation:
    """Public service result; never reports an allow as a completed purchase."""

    status: SpendOperationStatus
    entitlement: SpendEntitlement | None
    handoff: SpendHandoff | None
    protected: ProtectedExecutionRecord | None
    reason: str
    replayed: bool = False

    def __post_init__(self) -> None:
        if type(self.status) is not SpendOperationStatus:
            raise TypeError("status must be SpendOperationStatus")
        if not self.reason:
            raise ValueError("operation reason must be non-empty")
        if type(self.replayed) is not bool:
            raise TypeError("operation replayed must be bool")
        if self.status is not SpendOperationStatus.DENIED and self.entitlement is None:
            raise ValueError("non-denied operation needs an entitlement")


def _time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("durable spend time must be timezone-aware")
    return value.isoformat()


def _parse_time(value: object) -> datetime:
    if type(value) is not str:
        raise SpendConflictError("durable spend time is malformed")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SpendConflictError("durable spend time is not timezone-aware")
    return parsed


def _binding_from_payload(payload: Mapping[str, JsonValue]) -> ProtectedExecutionBinding:
    provider = cast(dict[str, JsonValue], payload["provider_identity"])
    policies = cast(list[JsonValue], payload["policies"])
    from masugate.protected_execution import PolicyBinding

    return ProtectedExecutionBinding(
        principal_id=cast(str, payload["principal_id"]),
        action=cast(str, payload["action"]),
        arguments=cast(dict[str, JsonValue], payload["arguments"]),
        idempotency_key=cast(str, payload["idempotency_key"]),
        policies=tuple(
            PolicyBinding(
                policy_id=cast(str, item["policy_id"]),
                policy_version=cast(str, item["policy_version"]),
                policy_digest=cast(str, item["policy_digest"]),
                bundle_id=cast(str, item["bundle_id"]),
                bundle_version=cast(str, item["bundle_version"]),
                bundle_digest=cast(str, item["bundle_digest"]),
            )
            for raw in policies
            for item in [cast(dict[str, JsonValue], raw)]
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
        authorization_digest=(
            None
            if payload.get("authorization_digest") is None
            else cast(str, payload["authorization_digest"])
        ),
    )


class SqliteSpendOutboxStore:
    """Atomic local/reference budget-entitlement and protected-outbox store."""

    def __init__(
        self,
        path: Path,
        policy: SpendPolicy,
        *,
        connector_id: str = _CONNECTOR_ID,
        allow_default_authorization_for_testing: bool = False,
    ) -> None:
        """Create the durable spend store.

        A production caller must supply the compiled policy authorizer to
        :meth:`reserve`.  The small imperative decision below remains useful
        to isolated provider tests, but is deliberately unavailable unless a
        test opts into it at construction time.
        """

        if type(connector_id) is not str or not connector_id:
            raise TypeError("connector_id must be a non-empty str")
        if type(allow_default_authorization_for_testing) is not bool:
            raise TypeError("allow_default_authorization_for_testing must be bool")
        self.path = path
        self.policy = policy
        self.connector_id = connector_id
        self._allow_default_authorization_for_testing = allow_default_authorization_for_testing

    def _connect(self) -> Any:
        connection = sqlite3.connect(self.path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[Any]:
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

    @contextmanager
    def _transaction_for_lock(self, lock_identity: str) -> Iterator[Any]:
        """Serialize one provider transition on its natural durable identity.

        SQLite's writer transaction already serializes all state.  The
        PostgreSQL subclass narrows this to an advisory lock, preserving
        concurrent progress for independent team budgets.
        """

        with self._transaction() as connection:
            self._lock_in_transaction(connection, lock_identity)
            yield connection

    @staticmethod
    def _lock_in_transaction(connection: Any, lock_identity: str) -> None:
        """Acquire an additional provider lock while a transaction is open.

        SQLite already serializes writers.  PostgreSQL overrides this hook
        with a transaction-scoped advisory lock so every budget mutation uses
        the same team scope as policy admission.
        """

        del connection, lock_identity

    @asynccontextmanager
    async def open_policy_session(
        self,
        *,
        write: bool,
    ) -> AsyncIterator[SpendAdmissionSession]:
        """Open a real provider transaction for assembled policy evaluation.

        Admission itself uses the narrower team-locked transaction in
        :meth:`reserve`; this public factory exists for the assembled domain
        and never lends its session to connector I/O.
        """

        del write
        with self._transaction() as connection:
            yield SpendAdmissionSession(connection)

    async def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS spend_budgets (
                    team_id TEXT PRIMARY KEY,
                    limit_cents INTEGER NOT NULL,
                    spent_cents INTEGER NOT NULL DEFAULT 0,
                    held_cents INTEGER NOT NULL DEFAULT 0,
                    version INTEGER NOT NULL DEFAULT 0,
                    CHECK(limit_cents > 0),
                    CHECK(spent_cents >= 0),
                    CHECK(held_cents >= 0),
                    CHECK(version >= 0)
                );
                CREATE TABLE IF NOT EXISTS spend_entitlements (
                    entitlement_id TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL UNIQUE,
                    pending_id TEXT NOT NULL UNIQUE,
                    request_digest TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    team_id TEXT NOT NULL REFERENCES spend_budgets(team_id),
                    idempotency_key TEXT NOT NULL,
                    tool_call_id TEXT NOT NULL UNIQUE,
                    adapter_invocation_digest TEXT,
                    amount_cents INTEGER NOT NULL,
                    merchant_id TEXT NOT NULL,
                    request_ref TEXT NOT NULL,
                    budget_version BIGINT NOT NULL,
                    configuration_digest TEXT NOT NULL,
                    authorization_json TEXT NOT NULL,
                    resolution_json TEXT,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(principal_id, idempotency_key),
                    CHECK(amount_cents > 0),
                    CHECK(state IN ('held', 'consumed', 'released', 'quarantined', 'denied'))
                );
                CREATE TABLE IF NOT EXISTS spend_handoffs (
                    entitlement_id TEXT PRIMARY KEY
                        REFERENCES spend_entitlements(entitlement_id),
                    binding_digest TEXT NOT NULL UNIQUE,
                    binding_json TEXT NOT NULL,
                    authorization_digest TEXT NOT NULL,
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    CHECK(state IN ('outbox', 'succeeded', 'failed', 'outcome_unknown'))
                );
                CREATE INDEX IF NOT EXISTS spend_handoffs_unresolved
                    ON spend_handoffs(state, updated_at);
                CREATE TABLE IF NOT EXISTS spend_provider_configuration (
                    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
                    configuration_digest TEXT NOT NULL,
                    configuration_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

            self._migrate_empty_legacy_schema(connection)
            configuration: dict[str, JsonValue] = {
                "approval_threshold_cents": self.policy.approval_threshold_cents,
                "approval_timeout_seconds": self.policy.approval_timeout_seconds,
                "bundle_id": self.policy.bundle_id,
                "bundle_version": self.policy.bundle_version,
                "budget_limit_cents": self.policy.budget_limit_cents,
                "configuration_digest": self.policy.configuration_digest,
                "policy_id": self.policy.policy_id,
                "policy_version": self.policy.policy_version,
                "scope_derivation": _SCOPE_DERIVATION_ID,
            }
            existing = connection.execute(
                "SELECT configuration_digest, configuration_json FROM spend_provider_configuration "
                "WHERE singleton_id = 1"
            ).fetchone()
            if existing is None:
                legacy_state = connection.execute(
                    "SELECT "
                    "(SELECT COUNT(*) FROM spend_budgets) + "
                    "(SELECT COUNT(*) FROM spend_entitlements) AS count"
                ).fetchone()
                assert legacy_state is not None
                if int(legacy_state["count"]) != 0:
                    raise SpendConflictError(
                        "existing spend state has no durable configuration binding; "
                        "an explicit migration is required"
                    )
                connection.execute(
                    """
                    INSERT INTO spend_provider_configuration(
                        singleton_id, configuration_digest, configuration_json, created_at
                    ) VALUES (1, ?, ?, ?)
                    """,
                    (
                        self.policy.configuration_digest,
                        _canonical_json(configuration),
                        _time(_utc_now()),
                    ),
                )
            elif cast(
                str, existing["configuration_digest"]
            ) != self.policy.configuration_digest or cast(
                str, existing["configuration_json"]
            ) != _canonical_json(configuration):
                raise SpendConflictError(
                    "durable spend provider configuration does not match this deployment; "
                    "an explicit migration is required"
                )
            budget_mismatch = connection.execute(
                "SELECT 1 FROM spend_budgets WHERE limit_cents != ? LIMIT 1",
                (self.policy.budget_limit_cents,),
            ).fetchone()
            if budget_mismatch is not None:
                raise SpendConflictError(
                    "durable team budget limit does not match the bound provider configuration"
                )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _migrate_empty_legacy_schema(connection: Any) -> None:
        """Upgrade empty reference databases, but never reinterpret live state.

        A populated pre-evidence schema cannot establish which policy decision
        or configuration admitted a hold.  Failing closed gives an operator a
        deliberate migration boundary instead of silently changing its cap.
        """

        entitlement_columns = {
            cast(str, row["name"])
            for row in connection.execute("PRAGMA table_info(spend_entitlements)").fetchall()
        }
        handoff_columns = {
            cast(str, row["name"])
            for row in connection.execute("PRAGMA table_info(spend_handoffs)").fetchall()
        }
        required_entitlement = {"configuration_digest", "authorization_json", "resolution_json"}
        required_handoff = {"authorization_digest"}
        if not (
            required_entitlement <= entitlement_columns and required_handoff <= handoff_columns
        ):
            count_row = connection.execute(
                "SELECT "
                "(SELECT COUNT(*) FROM spend_budgets) + "
                "(SELECT COUNT(*) FROM spend_entitlements) + "
                "(SELECT COUNT(*) FROM spend_handoffs) AS count"
            ).fetchone()
            assert count_row is not None
            if int(count_row["count"]) != 0:
                raise SpendConflictError(
                    "existing spend state predates durable authorization evidence; "
                    "an explicit migration is required"
                )
            if "configuration_digest" not in entitlement_columns:
                connection.execute(
                    "ALTER TABLE spend_entitlements ADD COLUMN configuration_digest TEXT"
                )
            if "authorization_json" not in entitlement_columns:
                connection.execute(
                    "ALTER TABLE spend_entitlements ADD COLUMN authorization_json TEXT"
                )
            if "resolution_json" not in entitlement_columns:
                connection.execute("ALTER TABLE spend_entitlements ADD COLUMN resolution_json TEXT")
            if "authorization_digest" not in handoff_columns:
                connection.execute(
                    "ALTER TABLE spend_handoffs ADD COLUMN authorization_digest TEXT"
                )

    @staticmethod
    def _entitlement_id(request: SpendPurchaseRequest) -> str:
        return f"ent:{request.digest}"

    @staticmethod
    def _operation_id(request: SpendPurchaseRequest) -> str:
        return str(uuid5(_OPERATION_NAMESPACE, f"operation:{request.digest}"))

    @staticmethod
    def _pending_id(request: SpendPurchaseRequest) -> str:
        return str(uuid5(_OPERATION_NAMESPACE, f"pending:{request.digest}"))

    def _decode_entitlement(self, row: sqlite3.Row) -> SpendEntitlement:
        try:
            authorization_raw = json.loads(cast(str, row["authorization_json"]))
            if not isinstance(authorization_raw, dict):
                raise ValueError("not an object")
            resolution_raw = row["resolution_json"]
            resolution: SpendResolution | None = None
            if resolution_raw is not None:
                parsed_resolution = json.loads(cast(str, resolution_raw))
                if not isinstance(parsed_resolution, dict):
                    raise ValueError("resolution is not an object")
                parsed_evidence = cast(dict[str, JsonValue], parsed_resolution["evidence"])
                kind = parsed_resolution.get("kind")
                if kind is None:
                    # 2.4 originally persisted automatic expiry with its
                    # system actor and deadline evidence but no source marker.
                    # Preserve that non-human provenance on upgrade.
                    created_at = _parse_time(cast(str, row["created_at"]))
                    deadline = created_at + timedelta(seconds=self.policy.approval_timeout_seconds)
                    resolved_at = _parse_time(cast(str, parsed_resolution["resolved_at"]))
                    legacy_expires_at = parsed_evidence.get("expires_at")
                    kind = (
                        "automatic-expiry"
                        if (
                            parsed_resolution.get("approved") is False
                            and parsed_resolution.get("actor_id") == "masugate.approval-expiry"
                            and parsed_evidence.get("reason") == "approval-window-expired"
                            and type(legacy_expires_at) is str
                            and _parse_time(legacy_expires_at) == deadline
                            and resolved_at >= deadline
                        )
                        else "human"
                    )
                resolution = SpendResolution(
                    approved=cast(bool, parsed_resolution["approved"]),
                    actor_id=cast(str, parsed_resolution["actor_id"]),
                    evidence=parsed_evidence,
                    resolved_at=_parse_time(parsed_resolution["resolved_at"]),
                    kind=cast(
                        Literal["human", "automatic-expiry"],
                        kind,
                    ),
                )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise SpendConflictError("durable spend entitlement evidence is malformed") from exc
        return SpendEntitlement(
            entitlement_id=cast(str, row["entitlement_id"]),
            operation_id=cast(str, row["operation_id"]),
            pending_id=cast(str, row["pending_id"]),
            request=SpendPurchaseRequest(
                principal_id=cast(str, row["principal_id"]),
                team_id=cast(str, row["team_id"]),
                amount_cents=int(row["amount_cents"]),
                merchant_id=cast(str, row["merchant_id"]),
                request_ref=cast(str, row["request_ref"]),
                idempotency_key=cast(str, row["idempotency_key"]),
                tool_call_id=cast(str, row["tool_call_id"]),
                adapter_invocation_digest=cast(str | None, row["adapter_invocation_digest"]),
            ),
            budget_version=int(row["budget_version"]),
            configuration_digest=cast(str, row["configuration_digest"]),
            authorization=_decision_from_payload(cast(dict[str, JsonValue], authorization_raw)),
            state=SpendEntitlementState(cast(str, row["state"])),
            created_at=_parse_time(row["created_at"]),
            updated_at=_parse_time(row["updated_at"]),
            resolution=resolution,
        )

    def _load_entitlement(
        self,
        connection: sqlite3.Connection,
        entitlement_id: str,
    ) -> SpendEntitlement:
        row = connection.execute(
            "SELECT * FROM spend_entitlements WHERE entitlement_id = ?", (entitlement_id,)
        ).fetchone()
        if row is None:
            raise SpendConflictError(f"unknown spend entitlement: {entitlement_id}")
        return self._decode_entitlement(cast(sqlite3.Row, row))

    def _decode_handoff(self, row: sqlite3.Row) -> SpendHandoff:
        raw = json.loads(cast(str, row["binding_json"]))
        if not isinstance(raw, dict):
            raise SpendConflictError("durable spend handoff binding is malformed")
        return SpendHandoff(
            entitlement_id=cast(str, row["entitlement_id"]),
            binding=_binding_from_payload(cast(dict[str, JsonValue], raw)),
            authorization_digest=cast(str, row["authorization_digest"]),
            state=SpendHandoffState(cast(str, row["state"])),
            created_at=_parse_time(row["created_at"]),
            updated_at=_parse_time(row["updated_at"]),
        )

    def _default_authorization_for_testing(
        self,
        request: SpendPurchaseRequest,
        session: SpendAdmissionSession,
        _now: datetime,
    ) -> PolicyDecision:
        """Imperative fallback reserved for explicitly opted-in provider tests.

        Production composition always supplies the compiled runtime.  This
        method cannot be reached through :meth:`reserve` unless the store was
        constructed with ``allow_default_authorization_for_testing=True``.
        Its synthetic artifact identity is never used by the reference HTTP
        composition.
        """

        row = session.connection.execute(
            """
            SELECT limit_cents, spent_cents, held_cents, version
            FROM spend_budgets WHERE team_id = ?
            """,
            (request.team_id,),
        ).fetchone()
        if row is None:  # pragma: no cover - reserve creates it first
            raise SpendConflictError("spend budget disappeared before policy evaluation")
        available = int(row["limit_cents"]) - int(row["spent_cents"]) - int(row["held_cents"])
        read = ViewRead(
            function="spend.available_cents",
            arguments=(request.team_id,),
            value=available,
            scope=f"spend:team:{request.team_id}",
            version=int(row["version"]),
            latency_ms=0.0,
        )
        if request.amount_cents > available:
            effect = DecisionEffect.DENY
            rule_id = "budget_cap"
        elif request.amount_cents >= self.policy.approval_threshold_cents:
            effect = DecisionEffect.ESCALATE
            rule_id = "ask_first"
        else:
            effect = DecisionEffect.ALLOW
            rule_id = "otherwise"
        return PolicyDecision(
            effect=effect,
            policy_id=self.policy.policy_id,
            rule_id=rule_id,
            reason=f"provider fallback rule {rule_id} evaluated to true",
            reads=(read,),
            policy_version=self.policy.policy_version,
            evaluated_policies=((self.policy.policy_id, self.policy.policy_version),),
        )

    @staticmethod
    def _capacity_denial(
        decision: PolicyDecision,
        request: SpendPurchaseRequest,
        row: Any,
    ) -> PolicyDecision:
        """Make an unexpected failed hold a durable, truthful denial record."""

        available = int(row["limit_cents"]) - int(row["spent_cents"]) - int(row["held_cents"])
        return PolicyDecision(
            effect=DecisionEffect.DENY,
            policy_id=decision.policy_id,
            rule_id="budget_cap.capacity_unavailable",
            reason="atomic budget reservation found no remaining capacity",
            reads=(
                *decision.reads,
                ViewRead(
                    function="spend.available_cents",
                    arguments=(request.team_id,),
                    value=available,
                    scope=f"spend:team:{request.team_id}",
                    version=int(row["version"]),
                    latency_ms=0.0,
                ),
            ),
            policy_version="",
            evaluated_policies=decision.evaluated_policies,
            policy_provenance=decision.policy_provenance,
        )

    def _insert_entitlement(
        self,
        connection: Any,
        request: SpendPurchaseRequest,
        *,
        budget_version: int,
        state: SpendEntitlementState,
        authorization: PolicyDecision,
        now: datetime,
    ) -> SpendEntitlement:
        entitlement_id = self._entitlement_id(request)
        connection.execute(
            """
            INSERT INTO spend_entitlements(
                entitlement_id, operation_id, pending_id, request_digest,
                principal_id, team_id,
                idempotency_key, tool_call_id, adapter_invocation_digest, amount_cents, merchant_id,
                request_ref, budget_version, configuration_digest, authorization_json,
                resolution_json, state, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?)
            """,
            (
                entitlement_id,
                self._operation_id(request),
                self._pending_id(request),
                request.digest,
                request.principal_id,
                request.team_id,
                request.idempotency_key,
                request.tool_call_id,
                request.adapter_invocation_digest,
                request.amount_cents,
                request.merchant_id,
                request.request_ref,
                budget_version,
                self.policy.configuration_digest,
                _canonical_json(_decision_payload(authorization)),
                state.value,
                _time(now),
                _time(now),
            ),
        )
        return self._load_entitlement(connection, entitlement_id)

    async def reserve(
        self,
        request: SpendPurchaseRequest,
        *,
        authorize: SpendAuthorizer | None = None,
    ) -> SpendReservation | None:
        """Evaluate policy and reserve capacity in the same locked transaction."""

        now = _utc_now()
        with self._transaction_for_lock(f"team:{request.team_id}") as connection:
            existing = connection.execute(
                """
                SELECT * FROM spend_entitlements
                WHERE principal_id = ? AND idempotency_key = ?
                """,
                (request.principal_id, request.idempotency_key),
            ).fetchone()
            if existing is not None:
                if cast(str, existing["request_digest"]) != request.digest:
                    raise SpendConflictError(
                        "trusted idempotency identity was reused with a different purchase"
                    )
                return SpendReservation(
                    entitlement=self._decode_entitlement(cast(sqlite3.Row, existing)),
                    replayed=True,
                )

            existing_call = connection.execute(
                "SELECT request_digest FROM spend_entitlements WHERE tool_call_id = ?",
                (request.tool_call_id,),
            ).fetchone()
            if existing_call is not None:
                raise SpendConflictError("trusted tool-call identity was reused")

            connection.execute(
                """
                INSERT INTO spend_budgets(team_id, limit_cents)
                VALUES (?, ?)
                ON CONFLICT(team_id) DO NOTHING
                """,
                (request.team_id, self.policy.budget_limit_cents),
            )
            if authorize is None:
                if not self._allow_default_authorization_for_testing:
                    raise SpendConflictError(
                        "spend admission requires a compiled policy authorizer; "
                        "the imperative fallback is test-only"
                    )
                authorize = self._default_authorization_for_testing
            decision = authorize(
                request,
                SpendAdmissionSession(connection),
                now,
            )
            if type(decision) is not PolicyDecision:
                raise SpendConflictError("spend policy authorizer returned malformed decision")
            before = connection.execute(
                """
                SELECT limit_cents, spent_cents, held_cents, version
                FROM spend_budgets WHERE team_id = ?
                """,
                (request.team_id,),
            ).fetchone()
            if before is None:  # pragma: no cover - inserted above in this transaction
                raise SpendConflictError("spend budget disappeared during admission")
            if decision.effect is DecisionEffect.DENY:
                entitlement = self._insert_entitlement(
                    connection,
                    request,
                    budget_version=int(before["version"]),
                    state=SpendEntitlementState.DENIED,
                    authorization=decision,
                    now=now,
                )
                return SpendReservation(entitlement=entitlement, replayed=False)

            held = connection.execute(
                """
                UPDATE spend_budgets
                SET held_cents = held_cents + ?, version = version + 1
                WHERE team_id = ?
                  AND limit_cents - spent_cents - held_cents >= ?
                RETURNING version
                """,
                (request.amount_cents, request.team_id, request.amount_cents),
            ).fetchone()
            if held is None:
                entitlement = self._insert_entitlement(
                    connection,
                    request,
                    budget_version=int(before["version"]),
                    state=SpendEntitlementState.DENIED,
                    authorization=self._capacity_denial(decision, request, before),
                    now=now,
                )
                return SpendReservation(entitlement=entitlement, replayed=False)
            entitlement = self._insert_entitlement(
                connection,
                request,
                budget_version=int(held["version"]),
                state=SpendEntitlementState.HELD,
                authorization=decision,
                now=now,
            )
            return SpendReservation(entitlement=entitlement, replayed=False)

    async def get_entitlement(self, entitlement_id: str) -> SpendEntitlement:
        with self._transaction() as connection:
            return self._load_entitlement(connection, entitlement_id)

    async def get_entitlement_by_pending_id(self, pending_id: str) -> SpendEntitlement:
        _canonical_uuid(pending_id, "pending_id")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM spend_entitlements WHERE pending_id = ?",
                (pending_id,),
            ).fetchone()
            if row is None:
                raise SpendConflictError(f"unknown spend pending id: {pending_id}")
            return self._decode_entitlement(cast(sqlite3.Row, row))

    async def get_entitlement_by_operation_id(self, operation_id: str) -> SpendEntitlement:
        _canonical_uuid(operation_id, "operation_id")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM spend_entitlements WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if row is None:
                raise SpendConflictError(f"unknown spend operation id: {operation_id}")
            return self._decode_entitlement(cast(sqlite3.Row, row))

    async def pending_entitlements(
        self,
        *,
        principal_id: str | None = None,
    ) -> tuple[SpendEntitlement, ...]:
        """Return only unresolved, undispatched escalations in durable order."""

        with self._transaction() as connection:
            rows = connection.execute(
                """
                SELECT entitlement.*
                FROM spend_entitlements AS entitlement
                LEFT JOIN spend_handoffs AS handoff
                    ON handoff.entitlement_id = entitlement.entitlement_id
                WHERE entitlement.state = 'held' AND handoff.entitlement_id IS NULL
                ORDER BY entitlement.created_at, entitlement.entitlement_id
                """
            ).fetchall()
            pending: list[SpendEntitlement] = []
            for row in rows:
                entitlement = self._decode_entitlement(cast(sqlite3.Row, row))
                if entitlement.authorization.effect is not DecisionEffect.ESCALATE:
                    continue
                if entitlement.resolution is not None:
                    # Native approval is durable before its first outbox
                    # handoff.  It is no longer presentable, but recovery may
                    # still have to create the handoff after a crash.
                    continue
                if principal_id is not None and entitlement.request.principal_id != principal_id:
                    continue
                pending.append(entitlement)
            return tuple(pending)

    async def approved_resolutions_without_handoff(self) -> tuple[SpendEntitlement, ...]:
        """Return durable native approvals that still need their first handoff.

        This deliberately excludes all unpresented approvals and every
        terminal/failed state.  A durable human decision is not itself an
        outbox authority; recovery must create and dispatch the one immutable
        handoff from this narrowly defined set.
        """

        with self._transaction() as connection:
            rows = connection.execute(
                """
                SELECT entitlement.*
                FROM spend_entitlements AS entitlement
                LEFT JOIN spend_handoffs AS handoff
                    ON handoff.entitlement_id = entitlement.entitlement_id
                WHERE entitlement.state = 'held'
                  AND entitlement.resolution_json IS NOT NULL
                  AND handoff.entitlement_id IS NULL
                ORDER BY entitlement.created_at, entitlement.entitlement_id
                """
            ).fetchall()
            approvals: list[SpendEntitlement] = []
            for row in rows:
                entitlement = self._decode_entitlement(cast(sqlite3.Row, row))
                if entitlement.authorization.effect is not DecisionEffect.ESCALATE:
                    raise SpendConflictError(
                        "only escalated entitlements may carry durable resolution evidence"
                    )
                if entitlement.resolution is None or not entitlement.resolution.approved:
                    continue
                approvals.append(entitlement)
            return tuple(approvals)

    async def record_approved_resolution(
        self,
        entitlement_id: str,
        resolution: SpendResolution,
        *,
        authorize: SpendAuthorizer | None = None,
        pending_plan: PendingResolutionPlan | None = None,
    ) -> SpendEntitlement:
        """Atomically persist native approval before any dispatch handoff.

        The deadline is enforced under the same entitlement lock that writes
        the evidence.  Therefore a crash between this write and handoff
        creation preserves one recoverable native decision without allowing a
        late approval to become executable.
        """

        if not resolution.approved or resolution.kind != "human":
            raise SpendConflictError(
                "only an approved human resolution may authorize protected dispatch"
            )
        if "masugate_revalidation_v1" in resolution.evidence:
            raise SpendConflictError("spend revalidation evidence is provider-owned")
        if (authorize is None) != (pending_plan is None):
            raise SpendConflictError(
                "spend approval must provide both authorizer and pending-resolution plan"
            )
        if pending_plan is not None and pending_plan is not PendingResolutionPlan.REVALIDATE:
            raise SpendConflictError("spend approval supports only the revalidate pending plan")
        with self._transaction_for_lock(f"entitlement:{entitlement_id}") as connection:
            now = _utc_now()
            entitlement = self._load_entitlement(connection, entitlement_id)
            if entitlement.authorization.effect is not DecisionEffect.ESCALATE:
                raise SpendConflictError("only an escalated entitlement may carry a resolution")
            if entitlement.state is not SpendEntitlementState.HELD:
                raise SpendConflictError("only a held entitlement may be approved")
            if entitlement.resolution is not None:
                if not self._same_resolution_decision(entitlement.resolution, resolution):
                    raise SpendConflictError("spend resolution evidence is immutable")
                return entitlement
            if now >= entitlement.created_at + timedelta(
                seconds=self.policy.approval_timeout_seconds
            ):
                raise _SpendApprovalExpiredError(now)
            if authorize is not None:
                self._lock_in_transaction(
                    connection,
                    f"team:{entitlement.request.team_id}",
                )
                revalidation = authorize(
                    entitlement.request,
                    SpendAdmissionSession(
                        connection,
                        reservation_team_id=entitlement.request.team_id,
                        reservation_credit_cents=entitlement.request.amount_cents,
                    ),
                    now,
                )
                if type(revalidation) is not PolicyDecision:
                    raise SpendConflictError(
                        "spend revalidation authorizer returned malformed decision"
                    )
                resolution = replace(
                    resolution,
                    evidence={
                        **dict(resolution.evidence),
                        "masugate_revalidation_v1": {
                            "decision": _decision_payload(revalidation),
                            "evaluated_at": _time(now),
                            "pending_plan": PendingResolutionPlan.REVALIDATE.value,
                        },
                    },
                )
                if revalidation.effect is DecisionEffect.DENY:
                    updated = connection.execute(
                        """
                        UPDATE spend_budgets
                        SET held_cents = held_cents - ?, version = version + 1
                        WHERE team_id = ? AND held_cents >= ?
                        """,
                        (
                            entitlement.request.amount_cents,
                            entitlement.request.team_id,
                            entitlement.request.amount_cents,
                        ),
                    ).rowcount
                    if updated != 1:
                        raise SpendConflictError(
                            "budget state cannot release a revalidation-denied entitlement"
                        )
                    connection.execute(
                        """
                        UPDATE spend_entitlements
                        SET resolution_json = ?, state = 'denied', updated_at = ?
                        WHERE entitlement_id = ?
                        """,
                        (
                            _canonical_json(resolution.payload()),
                            _time(now),
                            entitlement_id,
                        ),
                    )
                    return self._load_entitlement(connection, entitlement_id)
            connection.execute(
                """
                UPDATE spend_entitlements
                SET resolution_json = ?, updated_at = ?
                WHERE entitlement_id = ?
                """,
                (
                    _canonical_json(resolution.payload()),
                    _time(now),
                    entitlement_id,
                ),
            )
            return self._load_entitlement(connection, entitlement_id)

    @staticmethod
    def _same_resolution_decision(left: SpendResolution, right: SpendResolution) -> bool:
        """Compare immutable approval authority apart from its write timestamp."""

        left_evidence = dict(left.evidence)
        right_evidence = dict(right.evidence)
        left_evidence.pop("masugate_revalidation_v1", None)
        right_evidence.pop("masugate_revalidation_v1", None)
        return (
            left.approved == right.approved
            and left.actor_id == right.actor_id
            and left_evidence == right_evidence
            and left.kind == right.kind
        )

    def _validate_binding(
        self,
        entitlement: SpendEntitlement,
        binding: ProtectedExecutionBinding,
    ) -> None:
        request = entitlement.request
        if binding.entitlement_id != entitlement.entitlement_id:
            raise SpendConflictError("protected binding names a different entitlement")
        if binding.authorization_digest != entitlement.authorization_digest:
            raise SpendConflictError(
                "protected binding does not match durable authorization evidence"
            )
        provenance = _dispatch_authorization(entitlement).policy_provenance
        if provenance:
            expected_policies = tuple(
                sorted(
                    PolicyBinding(
                        policy_id=item.policy_id,
                        policy_version=item.policy_declared_version,
                        policy_digest=item.policy_digest,
                        bundle_id=item.bundle_id,
                        bundle_version=item.bundle_version,
                        bundle_digest=item.bundle_digest,
                    )
                    for item in provenance
                )
            )
            if binding.policies != expected_policies:
                raise SpendConflictError(
                    "protected binding does not preserve exact policy provenance"
                )
        if binding.action != _ACTION:
            raise SpendConflictError("protected binding names an undeclared spend action")
        if binding.connector_id != self.connector_id:
            raise SpendConflictError("protected binding names an undeclared purchase connector")
        if (
            binding.principal_id != request.principal_id
            or binding.idempotency_key != request.idempotency_key
            or binding.tool_call_id != request.tool_call_id
        ):
            raise SpendConflictError("protected binding does not match trusted request identity")
        expected_arguments: dict[str, JsonValue] = {
            "amount_cents": request.amount_cents,
            "merchant_id": request.merchant_id,
            "request_ref": request.request_ref,
        }
        if dict(binding.arguments) != expected_arguments:
            raise SpendConflictError(
                "protected binding does not match immutable purchase arguments"
            )
        expected_scope = f"spend:team:{request.team_id}"
        if expected_scope not in binding.scopes:
            raise SpendConflictError("protected binding omits the reserved budget scope")

    def _validate_handoff_authorization(
        self,
        entitlement: SpendEntitlement,
        handoff: SpendHandoff,
    ) -> None:
        """Require the immutable outbox authorization to match current durable evidence.

        A handoff binds the exact entitlement authorization and policy provenance
        that admitted the protected effect.  Any later durable mutation is
        evidence drift, not a reason to reinterpret a settled or replayed
        operation under new authority.
        """

        if handoff.entitlement_id != entitlement.entitlement_id:
            raise SpendConflictError("durable handoff names a different entitlement")
        if handoff.authorization_digest != entitlement.authorization_digest:
            raise SpendConflictError(
                "durable handoff does not match current authorization evidence"
            )
        self._validate_binding(entitlement, handoff.binding)

    async def create_handoff(
        self,
        entitlement_id: str,
        binding: ProtectedExecutionBinding,
        *,
        resolution: SpendResolution | None = None,
    ) -> SpendHandoff:
        """Persist the only allowed source of protected connector dispatch."""

        with self._transaction_for_lock(f"entitlement:{entitlement_id}") as connection:
            # The approval deadline is an authority boundary, not a UI hint.
            # Read it only after acquiring the entitlement lock so an approval
            # that crosses the deadline while awaiting this transaction cannot
            # persist the dispatch-authorizing outbox handoff.
            now = _utc_now()
            entitlement = self._load_entitlement(connection, entitlement_id)
            is_escalated = entitlement.authorization.effect is DecisionEffect.ESCALATE
            if is_escalated:
                if resolution is None:
                    resolution = entitlement.resolution
                if resolution is None or not resolution.approved:
                    raise SpendConflictError(
                        "an escalated entitlement requires approved resolution "
                        "before protected dispatch"
                    )
            elif resolution is not None or entitlement.resolution is not None:
                raise SpendConflictError("only an escalated entitlement may carry a resolution")
            if (
                resolution is not None
                and entitlement.resolution is not None
                and not self._same_resolution_decision(entitlement.resolution, resolution)
            ):
                raise SpendConflictError("spend resolution evidence is immutable")
            existing = connection.execute(
                "SELECT * FROM spend_handoffs WHERE entitlement_id = ?", (entitlement_id,)
            ).fetchone()
            if existing is not None:
                handoff = self._decode_handoff(cast(sqlite3.Row, existing))
                self._validate_handoff_authorization(entitlement, handoff)
                if handoff.binding.digest != binding.digest:
                    raise SpendConflictError(
                        "entitlement already has a different immutable protected handoff"
                    )
                return handoff
            if entitlement.state is not SpendEntitlementState.HELD:
                raise SpendConflictError("only a held entitlement may enter protected dispatch")
            # A resolution already persisted by ``record_approved_resolution``
            # was authorized under this same lock before the deadline.  The
            # ensuing outbox write may safely occur after that deadline; only
            # the first decision write is deadline-bound.
            if (
                is_escalated
                and entitlement.resolution is None
                and now
                >= entitlement.created_at + timedelta(seconds=self.policy.approval_timeout_seconds)
            ):
                raise _SpendApprovalExpiredError(now)
            if resolution is not None and entitlement.resolution is None:
                connection.execute(
                    """
                    UPDATE spend_entitlements
                    SET resolution_json = ?, updated_at = ?
                    WHERE entitlement_id = ?
                    """,
                    (
                        _canonical_json(resolution.payload()),
                        _time(now),
                        entitlement_id,
                    ),
                )
                entitlement = self._load_entitlement(connection, entitlement_id)
            self._validate_binding(entitlement, binding)
            connection.execute(
                """
                INSERT INTO spend_handoffs(
                    entitlement_id, binding_digest, binding_json, authorization_digest,
                    state, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 'outbox', ?, ?)
                """,
                (
                    entitlement_id,
                    binding.digest,
                    _canonical_json(binding.payload()),
                    binding.authorization_digest,
                    _time(now),
                    _time(now),
                ),
            )
            row = connection.execute(
                "SELECT * FROM spend_handoffs WHERE entitlement_id = ?", (entitlement_id,)
            ).fetchone()
            assert row is not None
            return self._decode_handoff(cast(sqlite3.Row, row))

    async def get_handoff(self, entitlement_id: str) -> SpendHandoff | None:
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM spend_handoffs WHERE entitlement_id = ?", (entitlement_id,)
            ).fetchone()
            if row is None:
                return None
            handoff = self._decode_handoff(cast(sqlite3.Row, row))
            self._validate_handoff_authorization(
                self._load_entitlement(connection, entitlement_id), handoff
            )
            return handoff

    async def unresolved_handoffs(self) -> tuple[SpendHandoff, ...]:
        with self._transaction() as connection:
            rows = connection.execute(
                """
                SELECT * FROM spend_handoffs
                WHERE state IN ('outbox', 'outcome_unknown')
                ORDER BY created_at, entitlement_id
                """
            ).fetchall()
            handoffs: list[SpendHandoff] = []
            for row in rows:
                handoff = self._decode_handoff(cast(sqlite3.Row, row))
                self._validate_handoff_authorization(
                    self._load_entitlement(connection, handoff.entitlement_id), handoff
                )
                handoffs.append(handoff)
            return tuple(handoffs)

    async def reject(
        self,
        entitlement_id: str,
        *,
        resolution: SpendResolution | None = None,
    ) -> SpendEntitlement:
        """Release a still-held entitlement before any protected dispatch source exists."""

        now = _utc_now()
        with self._transaction_for_lock(f"entitlement:{entitlement_id}") as connection:
            entitlement = self._load_entitlement(connection, entitlement_id)
            if resolution is not None:
                if resolution.approved:
                    raise SpendConflictError("an approved resolution cannot release an entitlement")
                if entitlement.resolution is not None and entitlement.resolution != resolution:
                    raise SpendConflictError("spend resolution evidence is immutable")
            handoff = connection.execute(
                "SELECT 1 FROM spend_handoffs WHERE entitlement_id = ?", (entitlement_id,)
            ).fetchone()
            if handoff is not None:
                raise SpendConflictError("a protected handoff cannot be rejected as undispatched")
            if entitlement.state in {
                SpendEntitlementState.RELEASED,
                SpendEntitlementState.DENIED,
            }:
                return entitlement
            if entitlement.state is not SpendEntitlementState.HELD:
                raise SpendConflictError("only a held entitlement may be rejected")
            # Releasing a hold changes the view read by new admissions, so it
            # must serialize with their team-scoped policy evaluation as well
            # as with duplicate resolution of this entitlement.
            self._lock_in_transaction(connection, f"team:{entitlement.request.team_id}")
            updated = connection.execute(
                """
                UPDATE spend_budgets
                SET held_cents = held_cents - ?, version = version + 1
                WHERE team_id = ? AND held_cents >= ?
                """,
                (
                    entitlement.request.amount_cents,
                    entitlement.request.team_id,
                    entitlement.request.amount_cents,
                ),
            ).rowcount
            if updated != 1:
                raise SpendConflictError("budget state cannot release the held entitlement")
            connection.execute(
                """
                UPDATE spend_entitlements SET state = 'released', updated_at = ?
                , resolution_json = COALESCE(resolution_json, ?)
                WHERE entitlement_id = ?
                """,
                (
                    _time(now),
                    None if resolution is None else _canonical_json(resolution.payload()),
                    entitlement_id,
                ),
            )
            return self._load_entitlement(connection, entitlement_id)

    async def settle(
        self,
        handoff: SpendHandoff,
        protected: ProtectedExecutionRecord,
    ) -> tuple[SpendHandoff, SpendEntitlement]:
        """Apply only trustworthy runner state to the held provider entitlement."""

        if protected.binding.digest != handoff.binding.digest:
            raise SpendConflictError("protected execution does not match the handoff binding")
        if protected.status in {
            ProtectedExecutionStatus.INTENT,
            ProtectedExecutionStatus.EXECUTING,
        }:
            raise SpendConflictError("cannot settle a nonterminal protected execution")
        target = {
            ProtectedExecutionStatus.SUCCEEDED: SpendHandoffState.SUCCEEDED,
            ProtectedExecutionStatus.FAILED: SpendHandoffState.FAILED,
            ProtectedExecutionStatus.OUTCOME_UNKNOWN: SpendHandoffState.OUTCOME_UNKNOWN,
        }[protected.status]
        now = _utc_now()
        with self._transaction_for_lock(f"entitlement:{handoff.entitlement_id}") as connection:
            current_handoff_row = connection.execute(
                "SELECT * FROM spend_handoffs WHERE entitlement_id = ?", (handoff.entitlement_id,)
            ).fetchone()
            if current_handoff_row is None:
                raise SpendConflictError("protected execution has no durable spend outbox source")
            current_handoff = self._decode_handoff(cast(sqlite3.Row, current_handoff_row))
            if current_handoff.binding.digest != handoff.binding.digest:
                raise SpendConflictError("durable handoff binding drifted")
            entitlement = self._load_entitlement(connection, handoff.entitlement_id)
            self._validate_handoff_authorization(entitlement, current_handoff)
            # Success/failure/unknown settlement mutates (or preserves) the
            # reserved team capacity.  Share the admission scope lock so a
            # terminal effect cannot race a fresh policy-state decision.
            self._lock_in_transaction(connection, f"team:{entitlement.request.team_id}")

            if current_handoff.state in {
                SpendHandoffState.SUCCEEDED,
                SpendHandoffState.FAILED,
            }:
                # A foreground request may retain an OUTCOME_UNKNOWN snapshot
                # while recovery obtains trustworthy terminal evidence and
                # settles first.  Unknown is weaker than either terminal
                # outcome; contradictory terminal outcomes remain conflicts.
                if target is SpendHandoffState.OUTCOME_UNKNOWN:
                    return current_handoff, entitlement
                if current_handoff.state is not target:
                    raise SpendConflictError(
                        "terminal protected outcome conflicts with settled budget"
                    )
                return current_handoff, entitlement

            if target is SpendHandoffState.SUCCEEDED:
                if entitlement.state not in {
                    SpendEntitlementState.HELD,
                    SpendEntitlementState.QUARANTINED,
                }:
                    raise SpendConflictError("success cannot consume a released entitlement")
                update = connection.execute(
                    """
                    UPDATE spend_budgets
                    SET held_cents = held_cents - ?,
                        spent_cents = spent_cents + ?,
                        version = version + 1
                    WHERE team_id = ? AND held_cents >= ?
                    """,
                    (
                        entitlement.request.amount_cents,
                        entitlement.request.amount_cents,
                        entitlement.request.team_id,
                        entitlement.request.amount_cents,
                    ),
                ).rowcount
                if update != 1:
                    raise SpendConflictError("budget state cannot consume held entitlement")
                entitlement_state = SpendEntitlementState.CONSUMED
            elif target is SpendHandoffState.FAILED:
                if entitlement.state not in {
                    SpendEntitlementState.HELD,
                    SpendEntitlementState.QUARANTINED,
                }:
                    raise SpendConflictError("failure cannot release a consumed entitlement")
                update = connection.execute(
                    """
                    UPDATE spend_budgets
                    SET held_cents = held_cents - ?, version = version + 1
                    WHERE team_id = ? AND held_cents >= ?
                    """,
                    (
                        entitlement.request.amount_cents,
                        entitlement.request.team_id,
                        entitlement.request.amount_cents,
                    ),
                ).rowcount
                if update != 1:
                    raise SpendConflictError("budget state cannot release held entitlement")
                entitlement_state = SpendEntitlementState.RELEASED
            else:
                # Keep the amount in held_cents.  No new purchase may use this
                # capacity until status evidence establishes success or failure.
                if entitlement.state is SpendEntitlementState.HELD:
                    entitlement_state = SpendEntitlementState.QUARANTINED
                elif entitlement.state is SpendEntitlementState.QUARANTINED:
                    entitlement_state = entitlement.state
                else:
                    raise SpendConflictError("unknown outcome cannot alter terminal entitlement")

            connection.execute(
                "UPDATE spend_entitlements SET state = ?, updated_at = ? WHERE entitlement_id = ?",
                (entitlement_state.value, _time(now), entitlement.entitlement_id),
            )
            connection.execute(
                "UPDATE spend_handoffs SET state = ?, updated_at = ? WHERE entitlement_id = ?",
                (target.value, _time(now), handoff.entitlement_id),
            )
            updated_handoff = self._decode_handoff(
                cast(
                    sqlite3.Row,
                    connection.execute(
                        "SELECT * FROM spend_handoffs WHERE entitlement_id = ?",
                        (handoff.entitlement_id,),
                    ).fetchone(),
                )
            )
            return updated_handoff, self._load_entitlement(connection, entitlement.entitlement_id)

    async def budget(self, team_id: str) -> tuple[int, int, int]:
        """Return ``(limit, spent, held)`` for testable reference accounting."""

        _canonical_identity(team_id, "team_id")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT limit_cents, spent_cents, held_cents FROM spend_budgets WHERE team_id = ?",
                (team_id,),
            ).fetchone()
            if row is None:
                return self.policy.budget_limit_cents, 0, 0
            return int(row["limit_cents"]), int(row["spent_cents"]), int(row["held_cents"])


class _PostgresSpendConnection:
    """Small DB-API compatibility layer for the reviewed SQLite transition code.

    The provider's durable state machine deliberately stays identical across the
    file-backed oracle and PostgreSQL deployment.  Only placeholder syntax,
    schema integer width, and transaction/locking mechanics differ here.
    """

    def __init__(self, raw: Connection[dict[str, Any]]) -> None:
        self.raw = raw

    def execute(self, sql: str, params: tuple[object, ...] = ()) -> Any:
        statement = sql.strip()
        if statement == "BEGIN IMMEDIATE":
            return self.raw.execute("BEGIN")
        # SQLite INTEGER is signed 64-bit; PostgreSQL INTEGER is not.  Keep
        # the portable reference schema's numerical contract when it is
        # applied to PostgreSQL.
        statement = statement.replace(" INTEGER", " BIGINT")
        return self.raw.execute(statement.replace("?", "%s"), params)

    def executescript(self, script: str) -> None:
        for statement in script.split(";"):
            if statement.strip():
                self.execute(statement)

    def commit(self) -> None:
        self.raw.commit()

    def rollback(self) -> None:
        self.raw.rollback()

    def close(self) -> None:
        self.raw.close()


class _SyncPostgresSpendOutboxStore(SqliteSpendOutboxStore):
    """Run the provider's short durable transitions against PostgreSQL."""

    def __init__(
        self,
        dsn: str,
        policy: SpendPolicy,
        *,
        connector_id: str = _CONNECTOR_ID,
        allow_default_authorization_for_testing: bool = False,
    ) -> None:
        super().__init__(
            Path(":postgres:"),
            policy,
            connector_id=connector_id,
            allow_default_authorization_for_testing=allow_default_authorization_for_testing,
        )
        self.dsn = dsn

    def _connect(self) -> _PostgresSpendConnection:
        raw = cast(
            "Connection[dict[str, Any]]",
            psycopg.connect(self.dsn, row_factory=dict_row),
        )
        return _PostgresSpendConnection(raw)

    @staticmethod
    def _migrate_empty_legacy_schema(connection: _PostgresSpendConnection) -> None:
        """PostgreSQL equivalent of the SQLite fail-closed legacy check."""

        def columns(table: str) -> set[str]:
            rows = connection.execute(
                """
                SELECT column_name AS name
                FROM information_schema.columns
                WHERE table_schema = current_schema() AND table_name = ?
                """,
                (table,),
            ).fetchall()
            return {cast(str, row["name"]) for row in rows}

        entitlement_columns = columns("spend_entitlements")
        handoff_columns = columns("spend_handoffs")
        required_entitlement = {"configuration_digest", "authorization_json", "resolution_json"}
        if not (
            required_entitlement <= entitlement_columns
            and {"authorization_digest"} <= handoff_columns
        ):
            count_row = connection.execute(
                "SELECT "
                "(SELECT COUNT(*) FROM spend_budgets) + "
                "(SELECT COUNT(*) FROM spend_entitlements) + "
                "(SELECT COUNT(*) FROM spend_handoffs) AS count"
            ).fetchone()
            assert count_row is not None
            if int(count_row["count"]) != 0:
                raise SpendConflictError(
                    "existing spend state predates durable authorization evidence; "
                    "an explicit migration is required"
                )
            if "configuration_digest" not in entitlement_columns:
                connection.execute(
                    "ALTER TABLE spend_entitlements ADD COLUMN configuration_digest TEXT"
                )
            if "authorization_json" not in entitlement_columns:
                connection.execute(
                    "ALTER TABLE spend_entitlements ADD COLUMN authorization_json TEXT"
                )
            if "resolution_json" not in entitlement_columns:
                connection.execute("ALTER TABLE spend_entitlements ADD COLUMN resolution_json TEXT")
            if "authorization_digest" not in handoff_columns:
                connection.execute(
                    "ALTER TABLE spend_handoffs ADD COLUMN authorization_digest TEXT"
                )

    @contextmanager
    def _transaction_for_lock(self, lock_identity: str) -> Iterator[_PostgresSpendConnection]:
        """Use a narrow advisory lock instead of serializing independent teams.

        ``reserve`` locks a team and terminal handoff transitions lock the
        entitlement.  Budget-row updates remain database-serialized, while
        disjoint teams are free to progress at the same time.
        """

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._lock_in_transaction(connection, lock_identity)
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _lock_in_transaction(
        connection: _PostgresSpendConnection,
        lock_identity: str,
    ) -> None:
        connection.execute(
            "SELECT pg_advisory_xact_lock(?)",
            (_advisory_key(lock_identity),),
        )


class PostgresSpendOutboxStore:
    """Async PostgreSQL facade for the durable spend entitlement/outbox store.

    Connector I/O never occurs in these transactions.  A deployment combines
    this store with :class:`~masugate.protected_execution.PostgresProtectedExecutionStore`
    using the same PostgreSQL DSN; the provider outbox remains the sole source
    from which the generic runner creates or resumes a protected intent.
    """

    def __init__(
        self,
        dsn: str,
        policy: SpendPolicy,
        *,
        connector_id: str = _CONNECTOR_ID,
        allow_default_authorization_for_testing: bool = False,
    ) -> None:
        self.dsn = dsn
        self.policy = policy
        self._sync = _SyncPostgresSpendOutboxStore(
            dsn,
            policy,
            connector_id=connector_id,
            allow_default_authorization_for_testing=allow_default_authorization_for_testing,
        )
        self.connector_id = connector_id

    async def _call[T](self, operation: Callable[[], Coroutine[Any, Any, T]]) -> T:
        def invoke() -> T:
            return asyncio.run(operation())

        return await asyncio.to_thread(invoke)

    async def initialize(self) -> None:
        await self._call(self._sync.initialize)

    @asynccontextmanager
    async def open_policy_session(
        self,
        *,
        write: bool,
    ) -> AsyncIterator[SpendAdmissionSession]:
        """Expose the same real store-owned session factory on PostgreSQL."""

        del write
        # The reference session is deliberately short and policy-only; keeping
        # it on this task avoids transferring a live DB-API transaction across
        # threads. Connector dispatch remains outside it.
        with self._sync._transaction() as connection:
            yield SpendAdmissionSession(connection)

    async def reserve(
        self,
        request: SpendPurchaseRequest,
        *,
        authorize: SpendAuthorizer | None = None,
    ) -> SpendReservation | None:
        return await self._call(lambda: self._sync.reserve(request, authorize=authorize))

    async def get_entitlement(self, entitlement_id: str) -> SpendEntitlement:
        return await self._call(lambda: self._sync.get_entitlement(entitlement_id))

    async def get_entitlement_by_pending_id(self, pending_id: str) -> SpendEntitlement:
        return await self._call(lambda: self._sync.get_entitlement_by_pending_id(pending_id))

    async def get_entitlement_by_operation_id(self, operation_id: str) -> SpendEntitlement:
        return await self._call(lambda: self._sync.get_entitlement_by_operation_id(operation_id))

    async def pending_entitlements(
        self,
        *,
        principal_id: str | None = None,
    ) -> tuple[SpendEntitlement, ...]:
        return await self._call(lambda: self._sync.pending_entitlements(principal_id=principal_id))

    async def approved_resolutions_without_handoff(self) -> tuple[SpendEntitlement, ...]:
        return await self._call(self._sync.approved_resolutions_without_handoff)

    async def record_approved_resolution(
        self,
        entitlement_id: str,
        resolution: SpendResolution,
        *,
        authorize: SpendAuthorizer | None = None,
        pending_plan: PendingResolutionPlan | None = None,
    ) -> SpendEntitlement:
        return await self._call(
            lambda: self._sync.record_approved_resolution(
                entitlement_id,
                resolution,
                authorize=authorize,
                pending_plan=pending_plan,
            )
        )

    async def create_handoff(
        self,
        entitlement_id: str,
        binding: ProtectedExecutionBinding,
        *,
        resolution: SpendResolution | None = None,
    ) -> SpendHandoff:
        return await self._call(
            lambda: self._sync.create_handoff(
                entitlement_id,
                binding,
                resolution=resolution,
            )
        )

    async def get_handoff(self, entitlement_id: str) -> SpendHandoff | None:
        return await self._call(lambda: self._sync.get_handoff(entitlement_id))

    async def unresolved_handoffs(self) -> tuple[SpendHandoff, ...]:
        return await self._call(self._sync.unresolved_handoffs)

    async def reject(
        self,
        entitlement_id: str,
        *,
        resolution: SpendResolution | None = None,
    ) -> SpendEntitlement:
        return await self._call(lambda: self._sync.reject(entitlement_id, resolution=resolution))

    async def settle(
        self,
        handoff: SpendHandoff,
        protected: ProtectedExecutionRecord,
    ) -> tuple[SpendHandoff, SpendEntitlement]:
        return await self._call(lambda: self._sync.settle(handoff, protected))

    async def budget(self, team_id: str) -> tuple[int, int, int]:
        return await self._call(lambda: self._sync.budget(team_id))


class ReferencePurchaseApi(Protocol):
    """Idempotent authenticated connector-service boundary.

    Both the local SQLite oracle and the network adapter implement this small
    surface.  The spend factory therefore never needs an in-process reference
    database object to model an external purchase service.
    """

    @property
    def credential_fingerprint(self) -> str | None:
        """Non-secret connector credential identity, or ``None`` for the local oracle."""

        ...

    @property
    def credential_manifest(self) -> ReferencePurchaseCredentialManifest | None:
        """Shared deployment manifest, or ``None`` for the local oracle."""

        ...

    async def initialize(self) -> None: ...

    async def close(self) -> None: ...

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


class SqliteReferencePurchaseApi:
    """Bounded idempotent/status-queryable reference purchase API.

    It intentionally has a separate durable database from the spend outbox,
    modelling the external service boundary without claiming a distributed
    transaction.  ``unknown_after_commit_once`` simulates lost post-dispatch
    delivery while retaining a truthful status record for reconciliation.
    """

    def __init__(
        self,
        path: Path,
        *,
        unknown_after_commit_once: bool = False,
    ) -> None:
        self.path = path
        self.unknown_after_commit_once = unknown_after_commit_once
        self._unknown_emitted: set[str] = set()

    @property
    def credential_fingerprint(self) -> None:
        """The local oracle has no bearer credential to compare at bootstrap."""

        return None

    @property
    def credential_manifest(self) -> None:
        """The local oracle has no cross-process credential manifest."""

        return None

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
                CREATE TABLE IF NOT EXISTS reference_purchases (
                    idempotency_key TEXT PRIMARY KEY,
                    binding_digest TEXT NOT NULL,
                    highest_fence_token BIGINT NOT NULL DEFAULT 0,
                    external_operation_id TEXT NOT NULL UNIQUE,
                    outcome TEXT NOT NULL,
                    evidence_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    CHECK(outcome IN ('succeeded', 'failed'))
                );
                """
            )
            columns = {
                cast(str, row["name"])
                for row in connection.execute("PRAGMA table_info(reference_purchases)").fetchall()
            }
            if "highest_fence_token" not in columns:
                connection.execute(
                    "ALTER TABLE reference_purchases "
                    "ADD COLUMN highest_fence_token BIGINT NOT NULL DEFAULT 0"
                )
            connection.commit()
        finally:
            connection.close()

    async def close(self) -> None:
        """The SQLite oracle opens no persistent client resource."""

    def _evidence(
        self,
        binding: ProtectedExecutionBinding,
        row: sqlite3.Row,
    ) -> ConnectorEvidence:
        return ConnectorEvidence(
            connector_id=_CONNECTOR_ID,
            evidence_id=cast(str, row["evidence_id"]),
            idempotency_key=binding.provider_idempotency_key,
            external_operation_id=cast(str, row["external_operation_id"]),
            outcome=ConnectorOutcome(cast(str, row["outcome"])),
            observed_at=_parse_time(row["created_at"]),
            payload={
                "amount_cents": cast(int, binding.arguments["amount_cents"]),
                "merchant_id": cast(str, binding.arguments["merchant_id"]),
            },
        )

    @staticmethod
    def _validate_binding(binding: ProtectedExecutionBinding) -> None:
        if binding.action != _ACTION or binding.connector_id != _CONNECTOR_ID:
            raise ConnectorContractError("reference purchase API received an unauthorized binding")
        if (
            binding.provider_identity.provider_id != "masugate.spend.reference"
            or binding.provider_identity.implementation_version != _IMPLEMENTATION_VERSION
            or binding.coordination_domain_id != _DOMAIN_ID
        ):
            raise ConnectorContractError(
                "reference purchase API received a foreign provider binding"
            )
        if binding.authorization_digest is None:
            raise ConnectorContractError(
                "reference purchase API requires durable authorization evidence"
            )
        if (
            len(binding.scopes) != 1
            or not binding.scopes[0].startswith("spend:team:")
            or binding.scopes[0] == "spend:team:"
        ):
            raise ConnectorContractError("reference purchase API received malformed budget scope")
        if set(binding.arguments) != {"amount_cents", "merchant_id", "request_ref"}:
            raise ConnectorContractError("reference purchase API received malformed arguments")

    async def execute(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        fence_token: int,
    ) -> ConnectorEvidence:
        self._validate_binding(binding)
        if idempotency_key != binding.provider_idempotency_key:
            raise SpendConflictError("reference purchase API received the wrong idempotency key")
        if type(fence_token) is not int or fence_token < 0:
            raise ConnectorContractError("reference purchase API received an invalid fence token")
        now = _utc_now()
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM reference_purchases WHERE idempotency_key = ?", (idempotency_key,)
            ).fetchone()
            if existing is not None:
                if cast(str, existing["binding_digest"]) != binding.digest:
                    raise SpendConflictError(
                        "reference purchase API rejects idempotency binding drift"
                    )
                highest_fence = int(existing["highest_fence_token"])
                if fence_token < highest_fence:
                    raise ConnectorContractError(
                        "reference purchase API rejects a stale connector fence"
                    )
                if fence_token > highest_fence:
                    connection.execute(
                        """
                        UPDATE reference_purchases
                        SET highest_fence_token = ?
                        WHERE idempotency_key = ? AND highest_fence_token <= ?
                        """,
                        (fence_token, idempotency_key, fence_token),
                    )
                evidence = self._evidence(binding, cast(sqlite3.Row, existing))
            else:
                outcome = (
                    ConnectorOutcome.FAILED
                    if binding.arguments["merchant_id"] == "declined-merchant"
                    else ConnectorOutcome.SUCCEEDED
                )
                external_operation_id = f"purchase:{binding.digest[:32]}"
                evidence_id = f"purchase-evidence:{binding.digest[:32]}"
                connection.execute(
                    """
                    INSERT INTO reference_purchases(
                        idempotency_key, binding_digest, highest_fence_token,
                        external_operation_id, outcome,
                        evidence_id, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        idempotency_key,
                        binding.digest,
                        fence_token,
                        external_operation_id,
                        outcome.value,
                        evidence_id,
                        _time(now),
                    ),
                )
                evidence = ConnectorEvidence(
                    connector_id=_CONNECTOR_ID,
                    evidence_id=evidence_id,
                    idempotency_key=idempotency_key,
                    external_operation_id=external_operation_id,
                    outcome=outcome,
                    observed_at=now,
                    payload={
                        "amount_cents": cast(int, binding.arguments["amount_cents"]),
                        "merchant_id": cast(str, binding.arguments["merchant_id"]),
                    },
                )
        if self.unknown_after_commit_once and idempotency_key not in self._unknown_emitted:
            self._unknown_emitted.add(idempotency_key)
            raise ConnectorOutcomeUnknown(
                "reference purchase committed before result delivery",
                external_operation_id=evidence.external_operation_id,
            )
        return evidence

    async def query_status(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        external_operation_id: str | None,
    ) -> ConnectorEvidence:
        self._validate_binding(binding)
        if idempotency_key != binding.provider_idempotency_key:
            raise SpendConflictError("reference purchase status key mismatch")
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM reference_purchases WHERE idempotency_key = ?", (idempotency_key,)
            ).fetchone()
            if row is None:
                return ConnectorEvidence(
                    connector_id=_CONNECTOR_ID,
                    evidence_id=f"purchase-status-unknown:{binding.digest[:32]}",
                    idempotency_key=idempotency_key,
                    external_operation_id=external_operation_id,
                    outcome=ConnectorOutcome.UNKNOWN,
                    observed_at=_utc_now(),
                    payload={"status": "unknown"},
                )
            if (
                external_operation_id is not None
                and cast(str, row["external_operation_id"]) != external_operation_id
            ):
                raise SpendConflictError("reference purchase status identity drift")
            if cast(str, row["binding_digest"]) != binding.digest:
                raise SpendConflictError("reference purchase status binding drift")
            return self._evidence(binding, cast(sqlite3.Row, row))

    async def cancel(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        external_operation_id: str | None,
    ) -> ConnectorEvidence:
        self._validate_binding(binding)
        # This bounded connector cannot retract an already submitted purchase.
        # Returning the authoritative known result (or unknown) preserves the
        # runner's no-guess/no-redispatch boundary.
        return await self.query_status(
            binding,
            idempotency_key=idempotency_key,
            external_operation_id=external_operation_id,
        )

    async def effect_count(self) -> int:
        with self._transaction() as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM reference_purchases").fetchone()
            assert row is not None
            return int(row["count"])


def reference_purchase_binding_from_payload(
    payload: Mapping[str, JsonValue],
) -> ProtectedExecutionBinding:
    """Decode a network-carried immutable connector binding fail-closed."""

    try:
        return _binding_from_payload(payload)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise ConnectorContractError("reference purchase binding payload is malformed") from exc


def reference_purchase_evidence_payload(evidence: ConnectorEvidence) -> dict[str, JsonValue]:
    return {
        "connector_id": evidence.connector_id,
        "evidence_id": evidence.evidence_id,
        "external_operation_id": evidence.external_operation_id,
        "idempotency_key": evidence.idempotency_key,
        "observed_at": _time(evidence.observed_at),
        "outcome": evidence.outcome.value,
        "payload": dict(evidence.payload),
    }


def reference_purchase_evidence_from_payload(
    payload: Mapping[str, JsonValue],
) -> ConnectorEvidence:
    try:
        return ConnectorEvidence(
            connector_id=cast(str, payload["connector_id"]),
            evidence_id=cast(str, payload["evidence_id"]),
            idempotency_key=cast(str, payload["idempotency_key"]),
            external_operation_id=cast(str | None, payload["external_operation_id"]),
            outcome=ConnectorOutcome(cast(str, payload["outcome"])),
            observed_at=_parse_time(payload["observed_at"]),
            payload=cast(dict[str, JsonValue], payload["payload"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ConnectorContractError("reference purchase evidence payload is malformed") from exc


class HttpReferencePurchaseApi:
    """Authenticated HTTP implementation of :class:`ReferencePurchaseApi`.

    The service token is a server-to-server deployment secret.  It is separate
    from agent action credentials and is never exposed in a bound action or
    connector receipt.  Network transport, TLS, and sandbox routing remain
    deployer concerns, while this adapter makes the ownership boundary real.
    """

    def __init__(
        self,
        base_url: str,
        *,
        service_token: str,
        credential_manifest: ReferencePurchaseCredentialManifest,
        client: httpx.AsyncClient | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        if not isinstance(base_url, str) or not base_url.startswith(("http://", "https://")):
            raise ValueError("reference purchase API base_url must be an HTTP URL")
        if (
            not isinstance(service_token, str)
            or not service_token
            or service_token.strip() != service_token
        ):
            raise ValueError("reference purchase API service token must be non-empty")
        if type(timeout_seconds) not in {int, float} or timeout_seconds <= 0:
            raise ValueError("reference purchase API timeout must be positive")
        if not isinstance(credential_manifest, ReferencePurchaseCredentialManifest):
            raise TypeError("reference purchase API needs a credential manifest")
        if not credential_manifest.validates_connector_credential(service_token):
            raise ValueError(
                "reference purchase service token does not match the credential manifest"
            )
        self.base_url = base_url.rstrip("/")
        if client is not None and str(client.base_url).rstrip("/") != self.base_url:
            raise ValueError("reference purchase API client base_url does not match")
        self._service_token = service_token
        self._credential_manifest = credential_manifest
        self._client = client
        self._owned_client: httpx.AsyncClient | None = None
        self._timeout_seconds = float(timeout_seconds)

    @property
    def credential_fingerprint(self) -> str:
        """Expose a non-secret identity for deployment-time separation checks."""

        return _credential_fingerprint(self._service_token)

    @property
    def credential_manifest(self) -> ReferencePurchaseCredentialManifest:
        return self._credential_manifest

    async def _http(self) -> httpx.AsyncClient:
        if self._client is not None:
            return self._client
        if self._owned_client is None:
            self._owned_client = httpx.AsyncClient(
                base_url=self.base_url,
                timeout=self._timeout_seconds,
            )
        return self._owned_client

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._service_token}"}

    async def _request(
        self,
        method: str,
        path: str,
        *,
        payload: Mapping[str, JsonValue] | None = None,
    ) -> tuple[int, dict[str, JsonValue]]:
        try:
            response = await (await self._http()).request(
                method,
                path,
                headers=self._headers(),
                json=payload,
            )
        except httpx.HTTPError as exc:
            raise ConnectorContractError("reference purchase service is unavailable") from exc
        try:
            body = response.json()
        except ValueError as exc:
            raise ConnectorContractError(
                "reference purchase service returned invalid JSON"
            ) from exc
        if not isinstance(body, dict):
            raise ConnectorContractError("reference purchase service returned malformed JSON")
        if response.status_code >= 400:
            raise ConnectorContractError("reference purchase service rejected connector request")
        return response.status_code, cast(dict[str, JsonValue], body)

    async def initialize(self) -> None:
        status, body = await self._request("GET", "/v1/health")
        if (
            status != 200
            or body.get("status") != "ok"
            or body.get("credential_manifest_digest") != self._credential_manifest.digest
        ):
            raise ConnectorContractError("reference purchase service health contract failed")

    async def execute(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        fence_token: int,
    ) -> ConnectorEvidence:
        status, body = await self._request(
            "POST",
            "/v1/purchases/execute",
            payload={
                "binding": binding.payload(),
                "fence_token": fence_token,
                "idempotency_key": idempotency_key,
            },
        )
        if status == 202:
            external_operation_id = body.get("external_operation_id")
            if external_operation_id is not None and type(external_operation_id) is not str:
                raise ConnectorContractError("reference purchase unknown result is malformed")
            raise ConnectorOutcomeUnknown(
                "reference purchase service reported an unknown outcome",
                external_operation_id=external_operation_id,
            )
        if status != 200:
            raise ConnectorContractError("reference purchase execute status is malformed")
        return reference_purchase_evidence_from_payload(body)

    async def query_status(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        external_operation_id: str | None,
    ) -> ConnectorEvidence:
        status, body = await self._request(
            "POST",
            "/v1/purchases/query-status",
            payload={
                "binding": binding.payload(),
                "external_operation_id": external_operation_id,
                "idempotency_key": idempotency_key,
            },
        )
        if status != 200:
            raise ConnectorContractError("reference purchase status response is malformed")
        return reference_purchase_evidence_from_payload(body)

    async def cancel(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        external_operation_id: str | None,
    ) -> ConnectorEvidence:
        status, body = await self._request(
            "POST",
            "/v1/purchases/cancel",
            payload={
                "binding": binding.payload(),
                "external_operation_id": external_operation_id,
                "idempotency_key": idempotency_key,
            },
        )
        if status != 200:
            raise ConnectorContractError("reference purchase cancellation response is malformed")
        return reference_purchase_evidence_from_payload(body)

    async def close(self) -> None:
        if self._owned_client is not None:
            await self._owned_client.aclose()
            self._owned_client = None


class ReferencePurchaseConnector:
    """ProtectedConnector adapter around the bounded reference purchase API."""

    connector_id = _CONNECTOR_ID
    capabilities = ConnectorCapabilities(
        idempotent_dispatch=True,
        status_query=True,
        cancellation=True,
    )

    def __init__(self, api: ReferencePurchaseApi) -> None:
        self.api = api

    @property
    def credential_fingerprint(self) -> str | None:
        return self.api.credential_fingerprint

    @property
    def credential_manifest(self) -> ReferencePurchaseCredentialManifest | None:
        return self.api.credential_manifest

    async def initialize(self) -> None:
        await self.api.initialize()

    async def close(self) -> None:
        close = getattr(self.api, "close", None)
        if callable(close):
            await cast(Callable[[], Awaitable[None]], close)()

    async def execute(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        fence_token: int,
    ) -> ConnectorEvidence:
        return await self.api.execute(
            binding,
            idempotency_key=idempotency_key,
            fence_token=fence_token,
        )

    async def query_status(
        self,
        binding: ProtectedExecutionBinding,
        *,
        idempotency_key: str,
        external_operation_id: str | None,
    ) -> ConnectorEvidence:
        return await self.api.query_status(
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
        return await self.api.cancel(
            binding,
            idempotency_key=idempotency_key,
            external_operation_id=external_operation_id,
        )


class SpendPurchaseService:
    """Bounded admission/approval/outbox facade for one spend provider.

    This service is framework-neutral.  A host integration is responsible for
    certifying the principal/team/tool-call tuple before calling it and for
    presenting pending approval.  The service itself owns the reservation,
    handoff, connector, accounting, and recovery boundaries.
    """

    def __init__(
        self,
        store: SpendOutboxStore,
        runner: ProtectedExecutionRunner,
        policy: SpendPolicy,
        *,
        allow_unbound_policy_for_testing: bool = False,
        handoff_committer: SpendHandoffCommitter | None = None,
        compose_dispatch_admission: bool = False,
    ) -> None:
        if store.policy != policy:
            raise ValueError("spend service store and policy must be identical")
        if type(allow_unbound_policy_for_testing) is not bool:
            raise TypeError("allow_unbound_policy_for_testing must be bool")
        if type(compose_dispatch_admission) is not bool:
            raise TypeError("compose_dispatch_admission must be bool")
        if handoff_committer is not None and not callable(handoff_committer):
            raise TypeError("spend handoff_committer must be callable")
        self.store = store
        # Dispatch is deliberately private: this provider's durable outbox is
        # the only public authority allowed to enter the generic runner.
        self._runner = runner
        self.policy = policy
        if (
            self._runner.authority.action != _ACTION
            or self._runner.authority.provider_identity != policy.provider_identity
            or self._runner.authority.coordination_domain_id != _DOMAIN_ID
        ):
            raise ValueError("spend service runner does not match the installed provider")
        self.connector_id = self._runner.authority.connector_id
        store_connector_id = getattr(store, "connector_id", self.connector_id)
        if store_connector_id != self.connector_id:
            raise ValueError("spend service store and runner connector must be identical")
        self._handoff_committer = handoff_committer
        if compose_dispatch_admission:
            self._runner.append_dispatch_admission(self._require_dispatchable_binding)
        else:
            self._runner.bind_dispatch_admission(self._require_dispatchable_binding)
        self._domain = CoordinationDomain(
            domain_id=_DOMAIN_ID,
            configuration_id=policy.configuration_digest,
            scope_derivation_id=_SCOPE_DERIVATION_ID,
            resource=self,
        )
        self._policy_provenance: SpendPolicyProvenance | None = None
        self._policy_runtime: PolicyRuntime | None = None
        self._runtime_policy_provenance: PolicyProvenance | None = None
        self._pending_plan: PendingResolutionPlan | None = None
        self._allow_unbound_policy_for_testing = allow_unbound_policy_for_testing
        self._initialized = False

    async def initialize(self) -> None:
        if self._policy_runtime is None and not self._allow_unbound_policy_for_testing:
            raise ContractError(
                "spend service requires a compiled catalog policy runtime before startup"
            )
        await self.store.initialize()
        await self._runner.store.initialize()
        initialize = getattr(self._runner.connector, "initialize", None)
        if callable(initialize):
            await cast(Callable[[], Awaitable[None]], initialize)()
        self._initialized = True

    async def close(self) -> None:
        """Release connector-owned resources without taking ownership of injected clients."""

        try:
            close = getattr(self._runner.connector, "close", None)
            if callable(close):
                await cast(Callable[[], Awaitable[None]], close)()
        finally:
            self._initialized = False

    @property
    def policy_provenance(self) -> SpendPolicyProvenance | None:
        """Return catalog provenance pinned before this service starts."""

        return self._policy_provenance

    @property
    def protected_authority(self) -> ProtectedExecutionAuthority:
        """Authority assembled for the provider-owned protected effect."""

        return self._runner.authority

    @property
    def protected_execution_store(self) -> ProtectedExecutionStore:
        """Share the deployment's durable protected-execution store without exposing dispatch."""

        return self._runner.store

    async def protected_events(
        self,
        execution_id: str,
    ) -> tuple[ProtectedExecutionEvent, ...]:
        """Return immutable audit events without exposing a dispatch surface."""

        return await self._runner.store.events(execution_id)

    def connector_credential_matches(self, credential: str) -> bool:
        """Compare a MasuGate bearer token to the connector credential without exposing either."""

        if type(credential) is not str:
            raise TypeError("connector credential comparison requires a string credential")
        fingerprint = self.connector_credential_fingerprint
        if fingerprint is None:
            return False
        return hmac.compare_digest(fingerprint, _credential_fingerprint(credential))

    @property
    def connector_credential_fingerprint(self) -> str | None:
        fingerprint = getattr(self._runner.connector, "credential_fingerprint", None)
        if fingerprint is not None:
            _sha256(fingerprint, "reference purchase connector credential fingerprint")
        return cast(str | None, fingerprint)

    @property
    def connector_credential_manifest(
        self,
    ) -> ReferencePurchaseCredentialManifest | None:
        manifest = getattr(self._runner.connector, "credential_manifest", None)
        if manifest is not None and not isinstance(manifest, ReferencePurchaseCredentialManifest):
            raise TypeError("reference purchase connector credential manifest is malformed")
        return manifest

    def bind_catalog_policy(self, catalog: PolicyCatalog) -> SpendPolicyProvenance:
        """Pin the one catalog policy this provider is allowed to execute.

        The reference service has a deliberately narrow action surface. It
        rejects a catalog that omits its policy or offers a second matching
        policy, so deployment provenance cannot silently diverge from the cap
        and review threshold enforced by this provider. Binding is startup-only
        because changing provenance after admission makes existing intents
        ambiguous.
        """

        if self._initialized:
            raise ContractError("spend catalog provenance must bind before service startup")
        matches = tuple(
            (bundle, loaded)
            for bundle in catalog.bundles
            for loaded in bundle.policies
            if (
                loaded.action == _ACTION
                and loaded.policy_id == self.policy.policy_id
                and loaded.version == self.policy.policy_version
                and bundle.bundle_id == self.policy.bundle_id
                and bundle.version == self.policy.bundle_version
            )
        )
        if len(matches) != 1:
            raise ContractError(
                "reference spend catalog must contain exactly one matching policy provenance"
            )
        bundle, loaded = matches[0]
        provenance = SpendPolicyProvenance(
            policy_digest=loaded.semantic_sha256,
            bundle_digest=bundle.digest,
        )
        if self._policy_provenance is not None and self._policy_provenance != provenance:
            raise ContractError("reference spend catalog provenance changed before startup")
        self._policy_provenance = provenance
        return provenance

    def bind_policy_runtime(self, runtime: PolicyRuntime) -> None:
        """Bind the compiled catalog evaluator that owns admission semantics."""

        if self._initialized:
            raise ContractError("spend policy runtime must bind before service startup")
        if self._policy_provenance is None:
            raise ContractError("spend catalog provenance must bind before its policy runtime")
        matches = tuple(
            (policy, provenance)
            for policy in runtime.policies.all_for_action(_ACTION)
            for provenance in (runtime.policies.provenance_for(policy),)
            if provenance is not None
            and provenance.policy_id == self.policy.policy_id
            and provenance.policy_declared_version == self.policy.policy_version
            and provenance.bundle_id == self.policy.bundle_id
            and provenance.bundle_version == self.policy.bundle_version
            and provenance.policy_digest == self._policy_provenance.policy_digest
            and provenance.bundle_digest == self._policy_provenance.bundle_digest
        )
        if len(matches) != 1:
            raise ContractError("reference spend runtime provenance conflicts with its catalog")
        _, provenance = matches[0]
        self._policy_runtime = runtime
        self._runtime_policy_provenance = provenance

    def bind_pending_plan(self, plan: PendingResolutionPlan | None) -> None:
        """Pin assembly's pending contract before the service starts."""

        if self._initialized:
            raise ContractError("spend pending plan must bind before service startup")
        if plan is not None and plan is not PendingResolutionPlan.REVALIDATE:
            raise ContractError("reference spend supports only revalidation after approval")
        if self._pending_plan is not None and self._pending_plan is not plan:
            raise ContractError("reference spend pending-resolution plan changed")
        self._pending_plan = plan

    def _require_initialized(self) -> None:
        if not self._initialized:
            raise ContractError("spend service must initialize before it accepts work")

    def _authorize(
        self,
        request: SpendPurchaseRequest,
        session: SpendAdmissionSession,
        now: datetime,
    ) -> PolicyDecision:
        """Evaluate the compiled catalog policy inside the locked budget tx."""

        runtime = self._policy_runtime
        if runtime is None:  # guarded by submit; preserves isolated store tests
            raise SpendConflictError("spend catalog policy runtime is not bound")
        provenance = (
            () if self._runtime_policy_provenance is None else (self._runtime_policy_provenance,)
        )
        action_request = ActionRequest(
            operation_id=str(uuid5(_OPERATION_NAMESPACE, f"policy:{request.digest}")),
            principal=Principal(
                id=request.principal_id,
                attributes={"team": request.team_id},
            ),
            action=_ACTION,
            arguments={
                "amount_cents": request.amount_cents,
                "merchant_id": request.merchant_id,
                "request_ref": request.request_ref,
            },
            idempotency_key=request.idempotency_key,
            timestamp=now,
            trace_id=request.tool_call_id,
        )
        try:
            decision = runtime.evaluate(
                action_request,
                session,
                evaluation_at=now,
            )
        except Exception as exc:
            # A policy/runtime failure is an admission denial, never a route
            # around the catalog.  The concrete exception class is retained in
            # durable evidence without exposing implementation detail to a caller.
            return PolicyDecision(
                effect=DecisionEffect.DENY,
                policy_id=self.policy.policy_id,
                policy_version="",
                rule_id="policy_runtime.failed",
                reason=f"compiled spend policy evaluation failed: {type(exc).__name__}",
                evaluated_policies=tuple(
                    (item.policy_id, item.policy_runtime_version) for item in provenance
                ),
                policy_provenance=provenance,
            )
        if not decision.policy_provenance:
            return PolicyDecision(
                effect=DecisionEffect.DENY,
                policy_id=self.policy.policy_id,
                policy_version="",
                rule_id="policy_runtime.unprovenanced",
                reason="compiled spend policy omitted trusted catalog provenance",
                evaluated_policies=(),
                policy_provenance=provenance,
            )
        return decision

    @asynccontextmanager
    async def open_session(self, *, write: bool) -> AsyncIterator[SpendAdmissionSession]:
        # The provider owns this coordination-domain session factory. The
        # protected-external effect never lends it to connector I/O; the actual
        # admission path additionally takes the specific team lock in reserve.
        async with self.store.open_policy_session(write=write) as session:
            yield session

    def provider_module(self) -> ProviderModule:
        """Expose exactly one protected-external effect to the deployment assembly."""

        def available(
            session: object,
            arguments: tuple[Scalar | Duration, ...],
            _scope: str,
        ) -> tuple[Scalar, int]:
            team_id = cast(str, arguments[0])
            if type(session) is not SpendAdmissionSession:
                raise ContractError("spend.available_cents requires a provider admission session")
            row = session.connection.execute(
                """
                SELECT limit_cents, spent_cents, held_cents, version
                FROM spend_budgets WHERE team_id = ?
                """,
                (team_id,),
            ).fetchone()
            if row is None:
                return self.policy.budget_limit_cents, 0
            return (
                int(row["limit_cents"])
                - int(row["spent_cents"])
                - int(row["held_cents"])
                + (
                    session.reservation_credit_cents
                    if session.reservation_team_id == team_id
                    else 0
                ),
                int(row["version"]),
            )

        def scope(arguments: tuple[Scalar | Duration, ...]) -> str:
            if len(arguments) != 1 or type(arguments[0]) is not str:
                raise ContractError("spend.available_cents requires one team identity")
            return f"spend:team:{arguments[0]}"

        view = GovernanceViewContract(
            name="spend.available_cents",
            argument_types=(TypeName.STRING,),
            return_type=TypeName.INT,
            owner=_MODULE_ID,
            consistency="scoped-policy-state",
            max_latency_ms=100,
            bounded=True,
            scope_resolver=scope,
            resolver=available,
            reservation_kind=ReservationViewKind.UNSUPPORTED,
            provider_identity=self.policy.provider_identity,
        )
        effect = EffectContract(
            action=_ACTION,
            argument_types={
                "amount_cents": TypeName.INT,
                "merchant_id": TypeName.STRING,
                "request_ref": TypeName.STRING,
            },
            owner=_MODULE_ID,
            required_guarantee=ConsistencyGuarantee.POLICY_STATE_SERIALIZABLE,
            footprint_resolver=lambda request: ResourceFootprint(
                writes=frozenset({f"spend:team:{request.principal.attributes['team']}"})
            ),
            executor=ProtectedExternalExecutor(self.connector_id),
            consumable_arg="amount_cents",
            provider_identity=self.policy.provider_identity,
        )
        return ProviderModule(
            module_id=_MODULE_ID,
            identity=self.policy.provider_identity,
            domain=self._domain,
            scope_derivation_id=_SCOPE_DERIVATION_ID,
            views=(view,),
            effects=(
                EffectBinding(
                    contract=effect,
                    position=EffectExecutionPosition.PROTECTED_EXTERNAL,
                    connector_id=self.connector_id,
                ),
            ),
            protected_executions=(ProtectedExecutionRegistration(_ACTION, self._runner),),
        )

    def _binding(self, entitlement: SpendEntitlement) -> ProtectedExecutionBinding:
        request = entitlement.request
        binding_authorization = _dispatch_authorization(entitlement)
        provenance = binding_authorization.policy_provenance
        if provenance:
            policies = tuple(
                PolicyBinding(
                    policy_id=item.policy_id,
                    policy_version=item.policy_declared_version,
                    policy_digest=item.policy_digest,
                    bundle_id=item.bundle_id,
                    bundle_version=item.bundle_version,
                    bundle_digest=item.bundle_digest,
                )
                for item in provenance
            )
        else:
            # Framework-neutral test compositions may deliberately exercise a
            # provider configuration without loading a catalog.  This is a
            # distinct provider artifact identity, never a fabricated catalog
            # digest.  The reference HTTP resource always takes the exact
            # provenance branch above.
            if not self._allow_unbound_policy_for_testing:
                raise SpendConflictError(
                    "spend protected binding has no compiled catalog provenance"
                )
            policies = (
                PolicyBinding(
                    policy_id=self.policy.policy_id,
                    policy_version=self.policy.policy_version,
                    policy_digest=_digest(
                        {
                            "artifact": "spend-provider-fallback-policy-v1",
                            "configuration_digest": entitlement.configuration_digest,
                            "policy_id": self.policy.policy_id,
                            "policy_version": self.policy.policy_version,
                        }
                    ),
                    bundle_id=self.policy.bundle_id,
                    bundle_version=self.policy.bundle_version,
                    bundle_digest=_digest(
                        {
                            "artifact": "spend-provider-fallback-bundle-v1",
                            "bundle_id": self.policy.bundle_id,
                            "bundle_version": self.policy.bundle_version,
                        }
                    ),
                ),
            )
        return ProtectedExecutionBinding(
            principal_id=request.principal_id,
            action=_ACTION,
            arguments={
                "amount_cents": request.amount_cents,
                "merchant_id": request.merchant_id,
                "request_ref": request.request_ref,
            },
            idempotency_key=request.idempotency_key,
            policies=policies,
            provider_identity=self.policy.provider_identity,
            coordination_domain_id=_DOMAIN_ID,
            scopes=(f"spend:team:{request.team_id}",),
            tool_call_id=request.tool_call_id,
            connector_id=self.connector_id,
            entitlement_id=entitlement.entitlement_id,
            authorization_digest=entitlement.authorization_digest,
        )

    @staticmethod
    def _operation(
        entitlement: SpendEntitlement,
        handoff: SpendHandoff | None,
        protected: ProtectedExecutionRecord | None,
        *,
        replayed: bool = False,
    ) -> SpendOperation:
        if protected is None and entitlement.state in {
            SpendEntitlementState.RELEASED,
            SpendEntitlementState.DENIED,
        }:
            return SpendOperation(
                status=SpendOperationStatus.DENIED,
                entitlement=entitlement,
                handoff=handoff,
                protected=None,
                reason="the bound spend entitlement was released without external dispatch",
                replayed=replayed,
            )
        if (
            protected is None
            and handoff is not None
            and handoff.state is SpendHandoffState.OUTCOME_UNKNOWN
        ):
            return SpendOperation(
                status=SpendOperationStatus.OUTCOME_UNKNOWN,
                entitlement=entitlement,
                handoff=handoff,
                protected=None,
                reason="protected execution record is unavailable; purchase remains quarantined",
                replayed=replayed,
            )
        if protected is None and handoff is None:
            return SpendOperation(
                status=SpendOperationStatus.PENDING,
                entitlement=entitlement,
                handoff=None,
                protected=None,
                reason="approval required before protected dispatch",
                replayed=replayed,
            )
        if protected is None or protected.status in {
            ProtectedExecutionStatus.INTENT,
            ProtectedExecutionStatus.EXECUTING,
        }:
            return SpendOperation(
                status=SpendOperationStatus.IN_PROGRESS,
                entitlement=entitlement,
                handoff=handoff,
                protected=protected,
                reason="protected purchase dispatch is durably in progress",
                replayed=replayed,
            )
        if protected.status is ProtectedExecutionStatus.SUCCEEDED:
            return SpendOperation(
                status=SpendOperationStatus.COMMITTED,
                entitlement=entitlement,
                handoff=handoff,
                protected=protected,
                reason="reference purchase committed with connector receipt",
                replayed=replayed,
            )
        if protected.status is ProtectedExecutionStatus.FAILED:
            return SpendOperation(
                status=SpendOperationStatus.DENIED,
                entitlement=entitlement,
                handoff=handoff,
                protected=protected,
                reason="reference purchase failed with connector evidence",
                replayed=replayed,
            )
        return SpendOperation(
            status=SpendOperationStatus.OUTCOME_UNKNOWN,
            entitlement=entitlement,
            handoff=handoff,
            protected=protected,
            reason="reference purchase outcome is quarantined pending status evidence",
            replayed=replayed,
        )

    async def _settle_latest(
        self,
        handoff: SpendHandoff,
        protected: ProtectedExecutionRecord,
    ) -> tuple[SpendHandoff, SpendEntitlement, ProtectedExecutionRecord]:
        """Settle monotonically and replace a stale unknown snapshot if recovery won."""

        settled_handoff, entitlement = await self.store.settle(handoff, protected)
        if (
            protected.status is ProtectedExecutionStatus.OUTCOME_UNKNOWN
            and settled_handoff.state in {SpendHandoffState.SUCCEEDED, SpendHandoffState.FAILED}
        ):
            latest = await self._runner.store.get(protected.execution_id)
            expected = {
                SpendHandoffState.SUCCEEDED: ProtectedExecutionStatus.SUCCEEDED,
                SpendHandoffState.FAILED: ProtectedExecutionStatus.FAILED,
            }[settled_handoff.state]
            if (
                latest.binding.digest != settled_handoff.binding.digest
                or latest.status is not expected
            ):
                raise SpendConflictError(
                    "settled spend outcome does not match authoritative protected execution"
                )
            protected = latest
        return settled_handoff, entitlement, protected

    async def submit(self, request: SpendPurchaseRequest) -> SpendOperation:
        self._require_initialized()
        reservation = await self.store.reserve(
            request,
            authorize=(None if self._policy_runtime is None else self._authorize),
        )
        if reservation is None:
            return SpendOperation(
                status=SpendOperationStatus.DENIED,
                entitlement=None,
                handoff=None,
                protected=None,
                reason="team budget capacity is unavailable",
            )
        entitlement = reservation.entitlement
        if entitlement.state is SpendEntitlementState.DENIED:
            return self._operation(entitlement, None, None, replayed=reservation.replayed)
        handoff = await self.store.get_handoff(entitlement.entitlement_id)
        if handoff is not None:
            try:
                protected = await self._runner.store.get(handoff.binding.execution_id)
            except ProtectedExecutionError:
                # A crash after the provider transaction and before generic
                # intent creation is the exact transactional-outbox gap this
                # service closes.  The persisted handoff is the sole dispatch
                # authority, so it is safe to resume from it.
                return replace(await self.dispatch(handoff), replayed=reservation.replayed)
            if protected.status not in {
                ProtectedExecutionStatus.INTENT,
                ProtectedExecutionStatus.EXECUTING,
            }:
                handoff, entitlement, protected = await self._settle_latest(handoff, protected)
            return self._operation(
                entitlement,
                handoff,
                protected,
                replayed=reservation.replayed,
            )
        if entitlement.authorization.effect is DecisionEffect.ESCALATE:
            return self._operation(entitlement, None, None, replayed=reservation.replayed)
        if entitlement.authorization.effect is not DecisionEffect.ALLOW:
            raise SpendConflictError("held spend entitlement has no dispatchable authorization")
        return replace(
            await self.approve(entitlement.entitlement_id),
            replayed=reservation.replayed,
        )

    async def approve(
        self,
        entitlement_id: str,
        *,
        resolution: SpendResolution | None = None,
    ) -> SpendOperation:
        self._require_initialized()
        entitlement = await self.store.get_entitlement(entitlement_id)
        if entitlement.state is not SpendEntitlementState.HELD:
            if entitlement.resolution is not None and entitlement.resolution.approved:
                if resolution is not None and not self._same_resolution_decision(
                    resolution, entitlement.resolution
                ):
                    raise SpendConflictError("spend resolution evidence is immutable")
                handoff = await self.store.get_handoff(entitlement_id)
                protected: ProtectedExecutionRecord | None = None
                if handoff is not None:
                    try:
                        protected = await self._runner.store.get(handoff.binding.execution_id)
                    except ProtectedExecutionError:
                        protected = None
                    if protected is not None and protected.status not in {
                        ProtectedExecutionStatus.INTENT,
                        ProtectedExecutionStatus.EXECUTING,
                    }:
                        handoff, entitlement, protected = await self._settle_latest(
                            handoff, protected
                        )
                return replace(self._operation(entitlement, handoff, protected), replayed=True)
            raise SpendConflictError("only a held entitlement may be approved")
        if entitlement.authorization.effect is DecisionEffect.DENY:
            raise SpendConflictError("a denied entitlement cannot be approved")
        if entitlement.authorization.effect is DecisionEffect.ESCALATE:
            resolution = resolution or entitlement.resolution
            if resolution is None:
                raise SpendConflictError(
                    "an escalated entitlement requires explicit approved resolution evidence"
                )
            if not resolution.approved:
                raise SpendConflictError("a rejected resolution cannot approve an entitlement")
            if entitlement.resolution is None:
                try:
                    # Persist the native decision before the separate outbox
                    # transaction.  A process death between these two writes
                    # leaves recoverable, exact approval evidence rather than
                    # losing the decision and prompting the human twice.
                    entitlement = await self.store.record_approved_resolution(
                        entitlement_id,
                        resolution,
                        authorize=(
                            self._authorize
                            if self._pending_plan is PendingResolutionPlan.REVALIDATE
                            else None
                        ),
                        pending_plan=self._pending_plan,
                    )
                except _SpendApprovalExpiredError as expired:
                    return await self.deny(
                        entitlement_id,
                        resolution=self._expiry_resolution(
                            entitlement,
                            resolved_at=expired.observed_at,
                        ),
                    )
                except SpendConflictError as exc:
                    if str(exc) != "spend resolution evidence is immutable":
                        raise
                    persisted = (await self.store.get_entitlement(entitlement_id)).resolution
                    if persisted is None or not self._same_resolution_decision(
                        persisted, resolution
                    ):
                        raise
                    entitlement = await self.store.get_entitlement(entitlement_id)
            assert entitlement.resolution is not None
            resolution = entitlement.resolution
            if entitlement.state is SpendEntitlementState.DENIED:
                return self._operation(entitlement, None, None)
        elif resolution is not None:
            raise SpendConflictError("only an escalated entitlement may carry a resolution")
        try:
            handoff = await self.store.create_handoff(
                entitlement_id,
                self._binding(entitlement),
            )
        except _SpendApprovalExpiredError as expired:
            # This compatibility path is reachable only for a legacy store
            # that combines resolution and handoff.  The current store writes
            # the native decision under its own deadline-bound transaction.
            return await self.deny(
                entitlement_id,
                resolution=self._expiry_resolution(entitlement, resolved_at=expired.observed_at),
            )
        except SpendConflictError as exc:
            # Concurrent native callbacks carry the same authoritative
            # decision/evidence but each adapter invocation obtains its own
            # wall-clock ``resolved_at`` value.  The first transaction owns
            # that timestamp.  Re-read it and retry with the durable evidence
            # rather than treating an otherwise identical callback as a
            # conflicting new authorization.
            if resolution is None or str(exc) != "spend resolution evidence is immutable":
                raise
            persisted = (await self.store.get_entitlement(entitlement_id)).resolution
            if persisted is None or not self._same_resolution_decision(persisted, resolution):
                raise
            return replace(await self.approve(entitlement_id), replayed=True)
        return await self.dispatch(handoff)

    async def deny(
        self,
        entitlement_id: str,
        *,
        resolution: SpendResolution | None = None,
    ) -> SpendOperation:
        self._require_initialized()
        existing = await self.store.get_entitlement(entitlement_id)
        if existing.authorization.effect is DecisionEffect.ESCALATE:
            resolution = resolution or existing.resolution
            if resolution is None:
                raise SpendConflictError(
                    "an escalated entitlement requires explicit rejected resolution evidence"
                )
            if resolution.approved:
                raise SpendConflictError("an approved resolution cannot deny an entitlement")
        elif resolution is not None:
            raise SpendConflictError("only an escalated entitlement may carry a resolution")
        try:
            entitlement = await self.store.reject(entitlement_id, resolution=resolution)
        except SpendConflictError as exc:
            # See approve(): two identical deny/timeout callbacks must
            # converge on the first persisted resolution timestamp.
            if resolution is None or str(exc) != "spend resolution evidence is immutable":
                raise
            persisted = (await self.store.get_entitlement(entitlement_id)).resolution
            if persisted is None or not self._same_resolution_decision(persisted, resolution):
                raise
            return replace(await self.deny(entitlement_id), replayed=True)
        reason = (
            "team budget capacity is unavailable"
            if entitlement.state is SpendEntitlementState.DENIED
            else f"approval denied; entitlement {entitlement.entitlement_id} released"
        )
        return SpendOperation(
            status=SpendOperationStatus.DENIED,
            entitlement=entitlement,
            handoff=None,
            protected=None,
            reason=reason,
        )

    async def resolve_pending(
        self,
        pending_id: str,
        *,
        approved: bool,
        resolver_id: str,
        evidence: Mapping[str, JsonValue] | None = None,
    ) -> SpendOperation:
        """Resolve only the durable entitlement addressed by a server-issued locator."""

        self._require_initialized()
        entitlement = await self.store.get_entitlement_by_pending_id(pending_id)
        if entitlement.authorization.effect is not DecisionEffect.ESCALATE:
            raise SpendConflictError("only an escalated spend entitlement may be resolved")
        now = _utc_now()
        if entitlement.resolution is None and self._approval_expired(entitlement, now):
            return await self.deny(
                entitlement.entitlement_id,
                resolution=self._expiry_resolution(entitlement, resolved_at=now),
            )
        if entitlement.resolution is not None:
            previous = entitlement.resolution
            if (
                previous.approved != approved
                or previous.actor_id != resolver_id
                or dict(previous.evidence) != dict({} if evidence is None else evidence)
            ):
                raise SpendConflictError("spend resolution evidence is immutable")
            if approved:
                return replace(await self.approve(entitlement.entitlement_id), replayed=True)
            return replace(await self.deny(entitlement.entitlement_id), replayed=True)
        resolution = SpendResolution(
            approved=approved,
            actor_id=resolver_id,
            evidence={} if evidence is None else evidence,
        )
        if approved:
            return await self.approve(entitlement.entitlement_id, resolution=resolution)
        return await self.deny(entitlement.entitlement_id, resolution=resolution)

    async def pending_entitlements(
        self,
        *,
        principal_id: str | None = None,
    ) -> tuple[SpendEntitlement, ...]:
        """Expose unresolved approvals for a presentation adapter to reconcile."""

        self._require_initialized()
        return await self.store.pending_entitlements(principal_id=principal_id)

    @staticmethod
    def _same_resolution_decision(left: SpendResolution, right: SpendResolution) -> bool:
        """Compare the authority-bearing resolution facts, not recording time.

        ``resolved_at`` is generated at the durable write boundary.  It is
        audit evidence, but cannot be part of a native callback's idempotency
        identity because duplicate callbacks are allowed to arrive at distinct
        local times.
        """

        return (
            left.approved == right.approved
            and left.actor_id == right.actor_id
            and dict(left.evidence) == dict(right.evidence)
            and left.kind == right.kind
        )

    def _approval_expired(self, entitlement: SpendEntitlement, now: datetime) -> bool:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("approval expiry check requires a timezone-aware time")
        return now >= entitlement.created_at + timedelta(
            seconds=self.policy.approval_timeout_seconds
        )

    def _expiry_resolution(
        self,
        entitlement: SpendEntitlement,
        *,
        resolved_at: datetime | None = None,
    ) -> SpendResolution:
        expires_at = entitlement.created_at + timedelta(
            seconds=self.policy.approval_timeout_seconds
        )
        return SpendResolution(
            approved=False,
            actor_id="masugate.approval-expiry",
            evidence={
                "reason": "approval-window-expired",
                "expires_at": _time(expires_at),
            },
            resolved_at=_utc_now() if resolved_at is None else resolved_at,
            kind="automatic-expiry",
        )

    async def expire_pending(self, *, now: datetime | None = None) -> tuple[SpendOperation, ...]:
        """Release expired held approvals without creating a dispatch handoff.

        The deadline is derived from the policy configuration whose digest is
        already persisted with the entitlement.  This makes a presentation
        process restart unable to extend the reservation by re-presenting its
        native UI.
        """

        self._require_initialized()
        checked_at = _utc_now() if now is None else now
        if checked_at.tzinfo is None or checked_at.utcoffset() is None:
            raise ValueError("approval expiry requires a timezone-aware time")
        expired: list[SpendOperation] = []
        for entitlement in await self.store.pending_entitlements():
            if not self._approval_expired(entitlement, checked_at):
                continue
            try:
                expired.append(
                    await self.deny(
                        entitlement.entitlement_id,
                        resolution=self._expiry_resolution(entitlement, resolved_at=checked_at),
                    )
                )
            except SpendConflictError:
                # A concurrent native resolution won the entitlement lock.
                # It is authoritative; never manufacture a second resolution.
                continue
        return tuple(expired)

    async def locate_pending(
        self,
        pending_id: str,
        *,
        principal_id: str,
        action: str,
        arguments: Mapping[str, JsonValue],
    ) -> SpendOperation:
        """Return an existing operation only after immutable locator validation.

        This path intentionally has no creation or dispatch behavior.  It is
        suitable for a later host-result-loss/resume bridge, but a fresh host
        callback must still enter through :meth:`submit` with its own trusted
        callback identity.
        """

        self._require_initialized()
        entitlement = await self.store.get_entitlement_by_pending_id(pending_id)
        expected_arguments: dict[str, JsonValue] = {
            "amount_cents": entitlement.request.amount_cents,
            "merchant_id": entitlement.request.merchant_id,
            "request_ref": entitlement.request.request_ref,
        }
        if (
            principal_id != entitlement.request.principal_id
            or action != _ACTION
            or dict(arguments) != expected_arguments
        ):
            raise SpendConflictError("pending locator does not match immutable purchase binding")
        handoff = await self.store.get_handoff(entitlement.entitlement_id)
        protected: ProtectedExecutionRecord | None = None
        if handoff is not None:
            try:
                protected = await self._runner.store.get(handoff.binding.execution_id)
            except ProtectedExecutionError:
                # The outbox remains durable but recovery, rather than a
                # locator read, is the only authority that may create intent.
                protected = None
            if protected is not None and protected.status not in {
                ProtectedExecutionStatus.INTENT,
                ProtectedExecutionStatus.EXECUTING,
            }:
                handoff, entitlement, protected = await self._settle_latest(handoff, protected)
        return self._operation(entitlement, handoff, protected)

    async def _require_dispatchable_binding(
        self,
        binding: ProtectedExecutionBinding,
    ) -> None:
        """Require the exact current provider outbox authorization for a connector call."""

        durable_handoff = await self.store.get_handoff(binding.entitlement_id)
        if durable_handoff is None:
            raise SpendConflictError("protected dispatch requires a durable spend outbox handoff")
        if (
            durable_handoff.binding.digest != binding.digest
            or durable_handoff.authorization_digest != binding.authorization_digest
        ):
            raise SpendConflictError(
                "protected dispatch binding does not match durable outbox state"
            )
        if durable_handoff.state is not SpendHandoffState.OUTBOX:
            raise SpendConflictError("only a durable outbox handoff may enter protected dispatch")
        entitlement = await self.store.get_entitlement(binding.entitlement_id)
        if durable_handoff.authorization_digest != entitlement.authorization_digest:
            raise SpendConflictError(
                "durable handoff does not match current authorization evidence"
            )
        if entitlement.state is not SpendEntitlementState.HELD:
            raise SpendConflictError("protected dispatch requires a held spend entitlement")
        if entitlement.authorization.effect is DecisionEffect.ESCALATE:
            if entitlement.resolution is None or not entitlement.resolution.approved:
                raise SpendConflictError(
                    "an escalated entitlement requires approved resolution before "
                    "protected dispatch"
                )
        elif entitlement.authorization.effect is not DecisionEffect.ALLOW:
            raise SpendConflictError("protected dispatch requires an allow authorization")

    async def dispatch(self, handoff: SpendHandoff) -> SpendOperation:
        """Drain exactly one outbox item through the generic protected runner."""

        self._require_initialized()
        durable_handoff = await self.store.get_handoff(handoff.entitlement_id)
        if durable_handoff is None:
            raise SpendConflictError("protected dispatch requires a durable spend outbox handoff")
        if (
            durable_handoff.binding.digest != handoff.binding.digest
            or durable_handoff.authorization_digest != handoff.authorization_digest
        ):
            raise SpendConflictError(
                "protected dispatch handoff does not match durable outbox state"
            )
        if durable_handoff.state is not SpendHandoffState.OUTBOX:
            raise SpendConflictError("only a durable outbox handoff may enter protected dispatch")
        handoff = durable_handoff
        await self._require_dispatchable_binding(handoff.binding)
        if self._handoff_committer is not None:
            await self._handoff_committer(handoff)
        try:
            protected = await self._runner.start(handoff.binding)
        except ProtectedExecutionBusy:
            protected = await self._runner.store.get(handoff.binding.execution_id)
        if protected.status in {
            ProtectedExecutionStatus.INTENT,
            ProtectedExecutionStatus.EXECUTING,
        }:
            entitlement = await self.store.get_entitlement(handoff.entitlement_id)
            return self._operation(entitlement, handoff, protected)
        settled_handoff, entitlement, protected = await self._settle_latest(handoff, protected)
        return self._operation(entitlement, settled_handoff, protected)

    async def recover(self) -> tuple[SpendOperation, ...]:
        """Recover outbox records without ever redispatching an unknown outcome."""

        self._require_initialized()
        recovered: list[SpendOperation] = []
        # A native approval is durable before the first handoff so the exact
        # operator decision survives a MasuGate/Gateway crash at that boundary.
        # Re-entering ``approve`` is idempotent: it uses the stored resolution
        # to create at most one outbox record, then dispatches from that record.
        for entitlement in await self.store.approved_resolutions_without_handoff():
            recovered.append(await self.approve(entitlement.entitlement_id))
        handoffs = await self.store.unresolved_handoffs()
        generic_ids: list[str] = []
        for handoff in handoffs:
            try:
                await self._runner.store.get(handoff.binding.execution_id)
            except ProtectedExecutionError:
                continue
            generic_ids.append(handoff.binding.execution_id)
        recovery_errors: tuple[tuple[str, str], ...] = ()
        if generic_ids:
            report = await ProtectedExecutionRecovery(self._runner).recover(
                execution_ids=generic_ids
            )
            recovery_errors = report.errors
        for handoff in handoffs:
            try:
                current = await self._runner.store.get(handoff.binding.execution_id)
            except ProtectedExecutionError:
                if handoff.state is SpendHandoffState.OUTCOME_UNKNOWN:
                    entitlement = await self.store.get_entitlement(handoff.entitlement_id)
                    recovered.append(self._operation(entitlement, handoff, None))
                    continue
                recovered.append(await self.dispatch(handoff))
                continue
            if current.status in {
                ProtectedExecutionStatus.INTENT,
                ProtectedExecutionStatus.EXECUTING,
            }:
                entitlement = await self.store.get_entitlement(handoff.entitlement_id)
                recovered.append(self._operation(entitlement, handoff, current))
                continue
            settled_handoff, entitlement, current = await self._settle_latest(handoff, current)
            recovered.append(self._operation(entitlement, settled_handoff, current))
        if recovery_errors:
            raise SpendRecoveryError(recovery_errors)
        return tuple(recovered)


__all__ = [
    "HttpReferencePurchaseApi",
    "PostgresSpendOutboxStore",
    "ReferencePurchaseApi",
    "ReferencePurchaseConnector",
    "ReferencePurchaseCredentialManifest",
    "SpendConflictError",
    "SpendEntitlement",
    "SpendEntitlementState",
    "SpendHandoff",
    "SpendHandoffState",
    "SpendOperation",
    "SpendOperationStatus",
    "SpendOutboxStore",
    "SpendPolicy",
    "SpendPolicyProvenance",
    "SpendPurchaseRequest",
    "SpendPurchaseService",
    "SpendRecoveryError",
    "SpendReservation",
    "SpendResolution",
    "SqliteReferencePurchaseApi",
    "SqliteSpendOutboxStore",
    "reference_purchase_binding_from_payload",
    "reference_purchase_evidence_from_payload",
    "reference_purchase_evidence_payload",
]
