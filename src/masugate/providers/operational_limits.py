"""Framework-neutral quota, egress-volume, and cross-action velocity state.

The provider owns two bounded transactional reference actions:

* ``api_spend`` consumes a configured per-service/principal quota; and
* ``http.post`` consumes a configured per-principal outbound-volume budget.

Both actions increment one durable principal lifetime action counter in their
own transaction.  The exported ``velocity`` label has no clock, window, decay,
or reset, so it is a real cross-action policy input but not a rate guarantee.
The provider records only logical
metering state and request identity; it neither performs an HTTP request nor
contacts a metered service.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Collection, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, cast

from masugate.certification import certified_input_evidence_json
from masugate.contracts import (
    EffectContract,
    EffectExecutor,
    GovernanceViewContract,
    ProviderIdentity,
    ReservationViewKind,
    ResourceSession,
)
from masugate.errors import ResourceError, RetryableResourceError
from masugate.model import (
    ActionRequest,
    AuthorizationEvaluation,
    CertificationPhase,
    CertifiedInputEvidence,
    CertifiedInputStability,
    CertifiedInputStabilityProof,
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
    request_binding_digest,
)
from masugate.protected_execution import ProtectedExecutionRunner
from masugate.provider_assembly import (
    CoordinationDomain,
    EffectBinding,
    EffectExecutionPosition,
    ProtectedExecutionRegistration,
    ProtectedExternalExecutor,
    ProviderModule,
)
from masugate.scope_versions import (
    SCOPE_VERSIONS_SCHEMA,
    advance_scope_version,
)

_MODULE_ID = "operational-limits"
_API_SPEND_ACTION = "api_spend"
_HTTP_POST_ACTION = "http.post"
_API_CONNECTOR_ID = "reference-api-runner-v1"
_HTTP_CONNECTOR_ID = "reference-http-runner-v1"
_IMPLEMENTATION_VERSION = "masugate.operational-limits-v1"
_ACTION = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$", re.ASCII)
_MAX_QUANTITY = (1 << 63) - 1
_RETRYABLE_SQLSTATES = frozenset({"40001", "40P01"})


class OperationalLimitError(ResourceError):
    """An operational-limit request, configuration, or state transition is unsafe."""


class OperationalLimitExceeded(OperationalLimitError):
    """A durable quota, egress, or velocity cap would be exceeded."""


def _resource_failure(exc: Exception) -> ResourceError:
    """Map backend failures to the coordinator's narrow retry taxonomy."""

    if isinstance(exc, ResourceError):
        return exc
    sqlstate = getattr(exc, "sqlstate", None)
    if sqlstate in _RETRYABLE_SQLSTATES or type(exc).__name__ in {
        "DeadlockDetected",
        "SerializationFailure",
    }:
        return RetryableResourceError("operational limits transaction should be retried")
    return OperationalLimitError(
        f"operational limits transaction failed closed: {type(exc).__name__}"
    )


class _SessionResource(Protocol):
    def open_session(self, *, write: bool) -> AbstractAsyncContextManager[ResourceSession]: ...


def _identity(value: object, field_name: str) -> str:
    if not (
        type(value) is str
        and 0 < len(value) <= 255
        and value.strip() == value
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise ValueError(f"{field_name} must be a canonical identity")
    return value


def _action(value: object, field_name: str = "action") -> str:
    action = _identity(value, field_name)
    if _ACTION.fullmatch(action) is None:
        raise ValueError(f"{field_name} must be a canonical action")
    return action


def _positive_quantity(value: object, field_name: str) -> int:
    if type(value) is not int or not 0 < value <= _MAX_QUANTITY:
        raise ValueError(f"{field_name} must be a positive signed 64-bit integer")
    return value


def _json(value: JsonValue) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _digest(value: JsonValue) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _idempotency_binding_digest(request: ActionRequest) -> str:
    """Bind an idempotency key to immutable governed inputs, not an attempt ID."""

    if type(request) is not ActionRequest:
        raise TypeError("idempotency binding digest requires an ActionRequest")
    payload: dict[str, JsonValue] = {
        "action": request.action,
        "arguments": dict(request.arguments),
        "idempotency_key": request.idempotency_key,
        "principal": {
            "attributes": dict(request.principal.attributes),
            "id": request.principal.id,
        },
        "resource": request.resource,
    }
    return _digest(payload)


def _time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("operational limit state time must be timezone-aware")
    return value.isoformat()


def _connection(session: ResourceSession) -> Any:
    connection = getattr(session, "connection", None)
    if connection is None or not callable(getattr(connection, "execute", None)):
        raise OperationalLimitError(
            "operational limits require a resource-owned durable SQL session"
        )
    return connection


def _scope_component(value: str) -> str:
    return f"{len(value)}:{value}"


def _advisory_key(scope: str) -> int:
    """Match the coordination resource advisory-key derivation exactly."""

    digest = hashlib.blake2b(scope.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, byteorder="big", signed=True)


def _lock(connection: Any, scopes: Collection[str]) -> None:
    """Lock all mutable logical scopes on PostgreSQL; SQLite serializes writers."""

    if not hasattr(connection, "raw"):
        return
    for scope in sorted(scopes, key=_advisory_key):
        connection.execute("SELECT pg_advisory_xact_lock(?)", (_advisory_key(scope),))


@dataclass(frozen=True)
class OperationalLimitsPolicy:
    """Immutable trusted configuration for one logical metering deployment.

    ``velocity_limit`` is a lifetime action-count cap in operational limits; it is not
    a time-windowed rate.
    """

    policy_id: str
    service_limits: tuple[tuple[str, int], ...]
    egress_limit_bytes: int
    velocity_limit: int

    def __post_init__(self) -> None:
        policy_id = _identity(self.policy_id, "operational limits policy_id")
        limits = tuple(
            (_identity(service, "quota service"), _positive_quantity(limit, "quota limit"))
            for service, limit in self.service_limits
        )
        if not limits:
            raise ValueError("operational limits policy needs at least one service limit")
        if limits != tuple(sorted(limits)) or len({service for service, _limit in limits}) != len(
            limits
        ):
            raise ValueError("operational limits service limits must be sorted and unique")
        object.__setattr__(self, "policy_id", policy_id)
        object.__setattr__(self, "service_limits", limits)
        object.__setattr__(
            self,
            "egress_limit_bytes",
            _positive_quantity(self.egress_limit_bytes, "egress_limit_bytes"),
        )
        object.__setattr__(
            self,
            "velocity_limit",
            _positive_quantity(self.velocity_limit, "velocity_limit"),
        )

    @property
    def payload(self) -> dict[str, JsonValue]:
        return {
            "egress_limit_bytes": self.egress_limit_bytes,
            "policy_id": self.policy_id,
            "service_limits": [list(item) for item in self.service_limits],
            "state_schema": "masugate.operational-limits.length-delimited-scopes.v1",
            "velocity_limit": self.velocity_limit,
        }

    @property
    def digest(self) -> str:
        return _digest(self.payload)

    @property
    def provider_identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="masugate.operational-limits",
            implementation_version=_IMPLEMENTATION_VERSION,
            configuration_version=self.digest,
        )

    def service_limit(self, service: object) -> int:
        canonical_service = _identity(service, "quota service")
        for configured_service, limit in self.service_limits:
            if configured_service == canonical_service:
                return limit
        raise OperationalLimitError(f"quota service {canonical_service!r} is not configured")


@dataclass(frozen=True)
class OperationalLimitReceipt:
    """Durable idempotent outcome of one logical metering action."""

    action: str
    principal_id: str
    operation_id: str
    request_digest: str
    quantity: int
    quota_used: int | None
    egress_volume: int | None
    velocity_count: int

    def __post_init__(self) -> None:
        _action(self.action)
        for field_name in ("principal_id", "operation_id", "request_digest"):
            _identity(getattr(self, field_name), field_name)
        _positive_quantity(self.quantity, "quantity")
        if (self.quota_used is None) == (self.egress_volume is None):
            raise ValueError("operational limit receipt must name exactly one meter total")
        for field_name in ("quota_used", "egress_volume"):
            value = getattr(self, field_name)
            if value is not None:
                _positive_quantity(value, field_name)
        _positive_quantity(self.velocity_count, "velocity_count")

    @property
    def result(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {
            "action": self.action,
            "principal_id": self.principal_id,
            "operation_id": self.operation_id,
            "quantity": self.quantity,
            "velocity_count": self.velocity_count,
        }
        if self.quota_used is not None:
            result["quota_used"] = self.quota_used
        if self.egress_volume is not None:
            result["egress_volume"] = self.egress_volume
        return result


def _scalar_payload(value: Scalar | Duration) -> JsonValue:
    if type(value) is Duration:
        return {"seconds": value.seconds}
    return cast(JsonValue, value)


def _scalar_from_payload(value: JsonValue) -> Scalar | Duration:
    if isinstance(value, dict) and set(value) == {"seconds"}:
        seconds = value["seconds"]
        if type(seconds) is not int:
            raise OperationalLimitError("durable authorization duration is malformed")
        return Duration(seconds)
    if type(value) in {bool, int, str}:
        return cast(Scalar, value)
    raise OperationalLimitError("durable authorization scalar is malformed")


def _decision_payload(decision: PolicyDecision) -> dict[str, JsonValue]:
    """Encode immutable policy provenance for durable terminal replay."""

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
    """Decode exact durable policy evidence, failing closed on corruption."""

    try:
        reads: list[ViewRead] = []
        for raw_read in cast(list[JsonValue], payload["reads"]):
            item = cast(dict[str, JsonValue], raw_read)
            reads.append(
                ViewRead(
                    function=cast(str, item["function"]),
                    arguments=tuple(
                        _scalar_from_payload(argument)
                        for argument in cast(list[JsonValue], item["arguments"])
                    ),
                    value=cast(Scalar, _scalar_from_payload(item["value"])),
                    scope=cast(str, item["scope"]),
                    version=cast(int, item["version"]),
                    latency_ms=float(cast(float | int, item["latency_ms"])),
                )
            )
        provenance = tuple(
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
            for item in (
                cast(dict[str, JsonValue], raw)
                for raw in cast(list[JsonValue], payload["policy_provenance"])
            )
        )
        evaluated = tuple(
            (pair[0], pair[1])
            for pair in (
                cast(list[str], raw) for raw in cast(list[JsonValue], payload["evaluated_policies"])
            )
        )
        if any(len(pair) != 2 for pair in evaluated):
            raise ValueError("evaluated policy identity is malformed")
        return PolicyDecision(
            effect=DecisionEffect(cast(str, payload["effect"])),
            policy_id=cast(str, payload["policy_id"]),
            rule_id=cast(str, payload["rule_id"]),
            reason=cast(str, payload["reason"]),
            reads=tuple(reads),
            policy_version=cast(str, payload["policy_version"]),
            evaluated_policies=evaluated,
            policy_provenance=provenance,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise OperationalLimitError("durable authorization decision is malformed") from exc


def _certified_input_from_payload(payload: Mapping[str, JsonValue]) -> CertifiedInputEvidence:
    try:
        value_type = TypeName(cast(str, payload["value_type"]))
        value = _scalar_from_payload(payload["value"])
        if value_type is not TypeName.DURATION:
            value = cast(Scalar, value)
        proof = payload["stability_proof"]
        return CertifiedInputEvidence(
            name=cast(str, payload["name"]),
            value=value,
            value_type=value_type,
            stability=CertifiedInputStability(cast(str, payload["stability"])),
            stability_proof=(
                CertifiedInputStabilityProof(cast(str, proof)) if proof is not None else None
            ),
            source_id=cast(str, payload["source_id"]),
            source_version=cast(str, payload["source_version"]),
            contract_version=cast(str, payload["contract_version"]),
            observed_at=datetime.fromisoformat(cast(str, payload["observed_at"])),
            certified_at=datetime.fromisoformat(cast(str, payload["certified_at"])),
            freshness_ttl=Duration(cast(int, payload["freshness_ttl_seconds"])),
            phase=CertificationPhase(cast(str, payload["phase"])),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise OperationalLimitError("durable certified input is malformed") from exc


def authorization_evaluation_payload(
    evaluation: AuthorizationEvaluation,
) -> dict[str, JsonValue]:
    return {
        "certified_inputs": [
            certified_input_evidence_json(evidence)
            for _name, evidence in sorted(evaluation.certified_inputs.items())
        ],
        "decision": _decision_payload(evaluation.decision),
        "evaluated_at": evaluation.evaluated_at.isoformat(),
        "phase": evaluation.phase.value,
    }


def authorization_evaluation_from_payload(
    payload: Mapping[str, JsonValue],
) -> AuthorizationEvaluation:
    try:
        inputs = {
            evidence.name: evidence
            for evidence in (
                _certified_input_from_payload(cast(dict[str, JsonValue], raw))
                for raw in cast(list[JsonValue], payload["certified_inputs"])
            )
        }
        return AuthorizationEvaluation(
            phase=CertificationPhase(cast(str, payload["phase"])),
            evaluated_at=datetime.fromisoformat(cast(str, payload["evaluated_at"])),
            decision=_decision_from_payload(cast(dict[str, JsonValue], payload["decision"])),
            certified_inputs=inputs,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise OperationalLimitError("durable authorization evaluation is malformed") from exc


def operational_authorization_digest(
    request: ActionRequest,
    evaluation: AuthorizationEvaluation,
    *,
    resolution: Mapping[str, JsonValue] | None = None,
) -> str:
    """Bind a protected connector handoff to exact durable authorization."""

    return _digest(
        {
            "authorization_evaluation": authorization_evaluation_payload(evaluation),
            "request_digest": request_binding_digest(request),
            "resolution": None if resolution is None else dict(resolution),
        }
    )


def action_request_payload(request: ActionRequest) -> dict[str, JsonValue]:
    """Encode the immutable request needed for restart-safe revalidation."""

    return {
        "action": request.action,
        "arguments": dict(request.arguments),
        "idempotency_key": request.idempotency_key,
        "operation_id": request.operation_id,
        "principal": {
            "attributes": dict(request.principal.attributes),
            "id": request.principal.id,
        },
        "resource": request.resource,
        "timestamp": _time(request.timestamp),
        "trace_id": request.trace_id,
    }


def action_request_from_payload(payload: Mapping[str, JsonValue]) -> ActionRequest:
    try:
        principal = cast(dict[str, JsonValue], payload["principal"])
        attributes = cast(dict[str, Scalar], principal["attributes"])
        arguments = cast(dict[str, Scalar], payload["arguments"])
        return ActionRequest(
            operation_id=cast(str, payload["operation_id"]),
            principal=Principal(
                id=cast(str, principal["id"]),
                attributes=attributes,
            ),
            action=cast(str, payload["action"]),
            arguments=arguments,
            idempotency_key=cast(str, payload["idempotency_key"]),
            timestamp=datetime.fromisoformat(cast(str, payload["timestamp"])),
            resource=cast(str | None, payload["resource"]),
            trace_id=cast(str | None, payload["trace_id"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise OperationalLimitError("durable pending request is malformed") from exc


@dataclass(frozen=True)
class OperationalAuthorizationOutcome:
    """Immutable terminal authorization evidence for one idempotency binding."""

    request_digest: str
    request_time: datetime
    decision: PolicyDecision
    authorization_evaluation: AuthorizationEvaluation
    evaluation_started_at: datetime
    evaluation_completed_at: datetime
    receipt: OperationalLimitReceipt | None
    resolution: Mapping[str, JsonValue] | None = None

    def __post_init__(self) -> None:
        _identity(self.request_digest, "request_digest")
        for field_name in (
            "request_time",
            "evaluation_started_at",
            "evaluation_completed_at",
        ):
            _time(cast(datetime, getattr(self, field_name)))
        if type(self.decision) is not PolicyDecision:
            raise TypeError("operational authorization outcome needs a policy decision")
        if type(self.authorization_evaluation) is not AuthorizationEvaluation:
            raise TypeError("operational authorization outcome needs authorization evidence")
        if self.authorization_evaluation.decision != self.decision:
            raise ValueError("operational authorization evidence has a different decision")
        if self.authorization_evaluation.evaluated_at != self.evaluation_completed_at:
            raise ValueError("operational authorization evaluation time does not match completion")
        if self.evaluation_started_at > self.evaluation_completed_at:
            raise ValueError("operational authorization evaluation completed before it started")
        if (self.decision.effect is DecisionEffect.ALLOW) != (self.receipt is not None):
            raise ValueError("operational authorization outcome has inconsistent effect receipt")
        if self.resolution is not None:
            try:
                normalized = json.loads(_json(cast(JsonValue, dict(self.resolution))))
            except (TypeError, ValueError) as exc:
                raise ValueError("operational authorization resolution must be JSON") from exc
            if not isinstance(normalized, dict):  # pragma: no cover - dict() above
                raise ValueError("operational authorization resolution must be an object")
            object.__setattr__(
                self,
                "resolution",
                cast(dict[str, JsonValue], normalized),
            )


@dataclass(frozen=True)
class OperationalPendingAuthorization:
    """Durable, nonterminal escalation awaiting an explicit resolution."""

    pending_id: str
    request: ActionRequest
    request_digest: str
    decision: PolicyDecision
    authorization_evaluation: AuthorizationEvaluation
    evaluation_started_at: datetime
    evaluation_completed_at: datetime
    pending_plan: PendingResolutionPlan
    resolution: Mapping[str, JsonValue] | None = None

    def __post_init__(self) -> None:
        _identity(self.pending_id, "pending_id")
        _identity(self.request_digest, "request_digest")
        if self.decision.effect is not DecisionEffect.ESCALATE:
            raise ValueError("operational pending authorization requires escalation")
        if self.authorization_evaluation.decision != self.decision:
            raise ValueError("operational pending evidence has a different decision")
        if self.authorization_evaluation.evaluated_at != self.evaluation_completed_at:
            raise ValueError("operational pending evaluation time does not match completion")
        if self.evaluation_started_at > self.evaluation_completed_at:
            raise ValueError("operational pending evaluation completed before it started")
        if self.pending_plan is not PendingResolutionPlan.REVALIDATE:
            raise ValueError("operational pending authorization requires revalidation")
        if self.resolution is not None:
            normalized = json.loads(_json(cast(JsonValue, dict(self.resolution))))
            object.__setattr__(self, "resolution", cast(dict[str, JsonValue], normalized))


@dataclass(frozen=True)
class _OperationDetails:
    action: str
    principal_id: str
    operation_id: str
    idempotency_key: str
    request_digest: str
    idempotency_digest: str
    quantity: int
    service: str | None


class OperationalLimitsProvider:
    """Durable service quota, egress volume, and cross-action velocity state."""

    def __init__(self, policy: OperationalLimitsPolicy, domain: CoordinationDomain) -> None:
        if type(policy) is not OperationalLimitsPolicy or type(domain) is not CoordinationDomain:
            raise TypeError("operational limits provider requires policy and coordination domain")
        self.policy = policy
        self._domain = domain
        self._resource = cast(_SessionResource, domain.resource)
        self._initialized = False

    def _require_initialized(self) -> None:
        if not self._initialized:
            raise OperationalLimitError(
                "operational limits provider must be initialized before it can use durable state"
            )

    def _quota_scope(self, service: object, principal_id: object) -> str:
        canonical_service = _identity(service, "quota service")
        principal = _identity(principal_id, "principal_id")
        return (
            "operational-limits:quota:"
            f"{_scope_component(self.policy.policy_id)}:"
            f"{_scope_component(canonical_service)}:{_scope_component(principal)}"
        )

    def _egress_scope(self, principal_id: object) -> str:
        principal = _identity(principal_id, "principal_id")
        return (
            "operational-limits:egress:"
            f"{_scope_component(self.policy.policy_id)}:{_scope_component(principal)}"
        )

    def _velocity_scope(self, principal_id: object) -> str:
        principal = _identity(principal_id, "principal_id")
        return (
            "operational-limits:velocity:"
            f"{_scope_component(self.policy.policy_id)}:{_scope_component(principal)}"
        )

    def _idempotency_scope(self, principal_id: object, idempotency_key: object) -> str:
        principal = _identity(principal_id, "principal_id")
        key = _identity(idempotency_key, "idempotency_key")
        return (
            "operational-limits:idempotency:"
            f"{_scope_component(self.policy.policy_id)}:{_scope_component(principal)}:"
            f"{_scope_component(key)}"
        )

    def _configuration_scope(self, kind: str, service: str | None = None) -> str:
        if kind not in {"quota", "egress", "velocity"}:
            raise ValueError("operational limits configuration kind is malformed")
        suffix = (
            "" if service is None else f":{_scope_component(_identity(service, 'quota service'))}"
        )
        return (
            "operational-limits:configuration:"
            f"{_scope_component(self.policy.policy_id)}:{kind}{suffix}"
        )

    async def initialize(self) -> None:
        """Create and bind the immutable operational-limits deployment state."""

        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            script = (
                SCOPE_VERSIONS_SCHEMA
                + """
                CREATE TABLE IF NOT EXISTS operational_limits_provider_configuration (
                    policy_id TEXT PRIMARY KEY,
                    configuration_digest TEXT NOT NULL,
                    configuration_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS service_quota_usage (
                    service TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    used_units BIGINT NOT NULL,
                    version BIGINT NOT NULL,
                    PRIMARY KEY(service, principal_id),
                    CHECK(used_units >= 0),
                    CHECK(version >= 0)
                );
                CREATE TABLE IF NOT EXISTS egress_volume_usage (
                    principal_id TEXT PRIMARY KEY,
                    used_bytes BIGINT NOT NULL,
                    version BIGINT NOT NULL,
                    CHECK(used_bytes >= 0),
                    CHECK(version >= 0)
                );
                CREATE TABLE IF NOT EXISTS cross_action_velocity (
                    principal_id TEXT PRIMARY KEY,
                    action_count BIGINT NOT NULL,
                    version BIGINT NOT NULL,
                    CHECK(action_count >= 0),
                    CHECK(version >= 0)
                );
                CREATE TABLE IF NOT EXISTS operational_limit_operations (
                    action TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    idempotency_digest TEXT NOT NULL,
                    quantity BIGINT NOT NULL,
                    quota_used BIGINT,
                    egress_volume BIGINT,
                    velocity_count BIGINT NOT NULL,
                    PRIMARY KEY(principal_id, idempotency_key),
                    UNIQUE(principal_id, operation_id),
                    CHECK(quantity > 0),
                    CHECK(velocity_count > 0),
                    CHECK(
                        (quota_used IS NOT NULL AND quota_used > 0 AND egress_volume IS NULL)
                        OR (egress_volume IS NOT NULL AND egress_volume > 0 AND quota_used IS NULL)
                    )
                );
                CREATE TABLE IF NOT EXISTS operational_limit_authorization_outcomes (
                    action TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    idempotency_digest TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    request_time TEXT NOT NULL,
                    evaluation_started_at TEXT NOT NULL,
                    evaluation_completed_at TEXT NOT NULL,
                    authorization_evaluation_json TEXT NOT NULL,
                    effect_committed INTEGER NOT NULL,
                    resolution_json TEXT,
                    PRIMARY KEY(principal_id, idempotency_key),
                    UNIQUE(principal_id, operation_id),
                    CHECK(effect_committed IN (0, 1))
                );
                CREATE TABLE IF NOT EXISTS operational_limit_pending_authorizations (
                    pending_id TEXT PRIMARY KEY,
                    action TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    idempotency_digest TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    evaluation_started_at TEXT NOT NULL,
                    evaluation_completed_at TEXT NOT NULL,
                    authorization_evaluation_json TEXT NOT NULL,
                    pending_plan TEXT NOT NULL,
                    state TEXT NOT NULL,
                    resolution_json TEXT,
                    created_at TEXT NOT NULL,
                    resolved_at TEXT,
                    UNIQUE(principal_id, idempotency_key),
                    UNIQUE(principal_id, operation_id),
                    CHECK(pending_plan = 'revalidate'),
                    CHECK(state IN ('pending', 'resolved')),
                    CHECK(
                        (state = 'pending' AND resolution_json IS NULL AND resolved_at IS NULL)
                        OR
                        (state = 'resolved' AND resolution_json IS NOT NULL
                            AND resolved_at IS NOT NULL)
                    )
                );
                """
            )
            execute_script = getattr(connection, "executescript", None)
            if not callable(execute_script):
                raise OperationalLimitError(
                    "operational limits resource cannot initialize SQL state"
                )
            execute_script(script)
            self._migrate_operation_identity_schema(connection)
            self._migrate_authorization_resolution_schema(connection)
            _lock(connection, {self._configuration_scope("velocity")})
            payload = _json(self.policy.payload)
            rows = connection.execute(
                "SELECT policy_id, configuration_digest, configuration_json FROM "
                "operational_limits_provider_configuration ORDER BY policy_id LIMIT 2"
            ).fetchall()
            if not rows:
                connection.execute(
                    "INSERT INTO operational_limits_provider_configuration("
                    "policy_id, configuration_digest, configuration_json, created_at"
                    ") VALUES (?, ?, ?, ?)",
                    (self.policy.policy_id, self.policy.digest, payload, _time(datetime.now(UTC))),
                )
            elif len(rows) != 1:
                raise OperationalLimitError(
                    "operational limits resource has multiple durable policy configurations"
                )
            else:
                row = rows[0]
                if (
                    row["policy_id"] != self.policy.policy_id
                    or row["configuration_digest"] != self.policy.digest
                    or row["configuration_json"] != payload
                ):
                    raise OperationalLimitError(
                        "durable operational limits configuration does not match this deployment"
                    )
        self._initialized = True

    @staticmethod
    def _operation_table_columns(connection: Any) -> set[str]:
        """Read the portable operation-table shape from either supported backend."""

        if hasattr(connection, "raw"):
            rows = connection.execute(
                """
                SELECT column_name AS name
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'operational_limit_operations'
                """
            ).fetchall()
        else:
            rows = connection.execute("PRAGMA table_info(operational_limit_operations)").fetchall()
        names: set[str] = set()
        for row in rows:
            value = row["name"]
            if isinstance(value, bytes):
                value = value.decode("utf-8")
            if type(value) is not str:
                raise OperationalLimitError("operation table has a malformed column identity")
            names.add(value)
        return names

    def _migrate_operation_identity_schema(self, connection: Any) -> None:
        """Add replay identity columns only when no old durable operation exists.

        The prior table did not persist enough information to reconstruct an
        idempotency binding safely.  Existing rows therefore require an
        explicit operator migration rather than a guessed replay identity.
        """

        columns = self._operation_table_columns(connection)
        required = {"idempotency_key", "idempotency_digest"}
        if required <= columns:
            return
        count_row = connection.execute(
            "SELECT COUNT(*) AS operation_count FROM operational_limit_operations"
        ).fetchone()
        assert count_row is not None
        if int(count_row["operation_count"]) != 0:
            raise OperationalLimitError(
                "existing operational-limit state lacks durable idempotency bindings; "
                "an explicit migration is required"
            )
        if "idempotency_key" not in columns:
            connection.execute(
                "ALTER TABLE operational_limit_operations ADD COLUMN idempotency_key TEXT"
            )
        if "idempotency_digest" not in columns:
            connection.execute(
                "ALTER TABLE operational_limit_operations ADD COLUMN idempotency_digest TEXT"
            )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS operational_limit_operations_idempotency "
            "ON operational_limit_operations(principal_id, idempotency_key)"
        )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS operational_limit_operations_operation "
            "ON operational_limit_operations(principal_id, operation_id)"
        )

    @staticmethod
    def _migrate_authorization_resolution_schema(connection: Any) -> None:
        if hasattr(connection, "raw"):
            rows = connection.execute(
                "SELECT column_name AS name FROM information_schema.columns "
                "WHERE table_schema = current_schema() "
                "AND table_name = 'operational_limit_authorization_outcomes'"
            ).fetchall()
        else:
            rows = connection.execute(
                "PRAGMA table_info(operational_limit_authorization_outcomes)"
            ).fetchall()
        columns = {cast(str, row["name"]) for row in rows}
        if "resolution_json" not in columns:
            connection.execute(
                "ALTER TABLE operational_limit_authorization_outcomes "
                "ADD COLUMN resolution_json TEXT"
            )
        # protected effects previously stored human provenance only on the matching
        # pending row.  Preserve upgrade replay fidelity by joining that exact
        # principal/idempotency identity into the terminal record once.
        connection.execute(
            "UPDATE operational_limit_authorization_outcomes AS outcome "
            "SET resolution_json = ("
            "SELECT pending.resolution_json "
            "FROM operational_limit_pending_authorizations AS pending "
            "WHERE pending.principal_id = outcome.principal_id "
            "AND pending.idempotency_key = outcome.idempotency_key "
            "AND pending.state = 'resolved'"
            ") WHERE outcome.resolution_json IS NULL AND EXISTS ("
            "SELECT 1 FROM operational_limit_pending_authorizations AS pending "
            "WHERE pending.principal_id = outcome.principal_id "
            "AND pending.idempotency_key = outcome.idempotency_key "
            "AND pending.state = 'resolved'"
            ")"
        )

    def _details(self, request: ActionRequest) -> _OperationDetails:
        if type(request) is not ActionRequest:
            raise TypeError("operational limit actions require an ActionRequest")
        action = _action(request.action)
        principal_id = _identity(request.principal.id, "principal_id")
        operation_id = _identity(request.operation_id, "operation_id")
        idempotency_key = _identity(request.idempotency_key, "idempotency_key")
        digest = request_binding_digest(request)
        idempotency_digest = _idempotency_binding_digest(request)
        if action == _API_SPEND_ACTION:
            if set(request.arguments) != {"service", "units", "request_ref"}:
                raise OperationalLimitError("api_spend arguments are malformed")
            service = _identity(request.arguments["service"], "quota service")
            self.policy.service_limit(service)
            _identity(request.arguments["request_ref"], "request_ref")
            return _OperationDetails(
                action,
                principal_id,
                operation_id,
                idempotency_key,
                digest,
                idempotency_digest,
                _positive_quantity(request.arguments["units"], "units"),
                service,
            )
        if action == _HTTP_POST_ACTION:
            if set(request.arguments) != {"destination", "payload_bytes", "content_digest"}:
                raise OperationalLimitError("http.post arguments are malformed")
            _identity(request.arguments["destination"], "destination")
            _identity(request.arguments["content_digest"], "content_digest")
            return _OperationDetails(
                action,
                principal_id,
                operation_id,
                idempotency_key,
                digest,
                idempotency_digest,
                _positive_quantity(request.arguments["payload_bytes"], "payload_bytes"),
                None,
            )
        raise OperationalLimitError("operational limits provider does not own this action")

    def _receipt(self, row: Mapping[str, object]) -> OperationalLimitReceipt:
        quota_raw = row["quota_used"]
        egress_raw = row["egress_volume"]
        return OperationalLimitReceipt(
            cast(str, row["action"]),
            cast(str, row["principal_id"]),
            cast(str, row["operation_id"]),
            cast(str, row["request_digest"]),
            int(cast(int, row["quantity"])),
            None if quota_raw is None else int(cast(int, quota_raw)),
            None if egress_raw is None else int(cast(int, egress_raw)),
            int(cast(int, row["velocity_count"])),
        )

    def _operation_scopes(self, details: _OperationDetails) -> frozenset[str]:
        if details.action == _API_SPEND_ACTION:
            assert details.service is not None
            meter_scope = self._quota_scope(details.service, details.principal_id)
        else:
            meter_scope = self._egress_scope(details.principal_id)
        return frozenset(
            {
                meter_scope,
                self._velocity_scope(details.principal_id),
                self._idempotency_scope(details.principal_id, details.idempotency_key),
            }
        )

    @staticmethod
    def map_resource_failure(exc: Exception) -> ResourceError:
        """Return the public coordinator-facing classification for one failure."""

        return _resource_failure(exc)

    def _protect_for_request(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> frozenset[str]:
        """Protect the complete policy/effect scope set in the caller's transaction.

        A transactional coordinator calls this before policy evaluation and
        retains the resource-owned session through effect commit. The effect
        path reacquires the same transaction-scoped locks defensively, which is
        idempotent on PostgreSQL and unnecessary but harmless on SQLite.
        """

        try:
            self._require_initialized()
            details = self._details(request)
            scopes = self._operation_scopes(details)
            _lock(_connection(session), scopes)
            return scopes
        except Exception as exc:
            mapped = _resource_failure(exc)
            if mapped is exc:
                raise
            raise mapped from exc

    def _load_replay_in_session(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> OperationalLimitReceipt | None:
        """Load an exact replay under the already-protected request scopes."""

        self._require_initialized()
        details = self._details(request)
        existing = (
            _connection(session)
            .execute(
                "SELECT * FROM operational_limit_operations WHERE principal_id = ? "
                "AND idempotency_key = ?",
                (details.principal_id, details.idempotency_key),
            )
            .fetchone()
        )
        if existing is None:
            return None
        if existing["idempotency_digest"] != details.idempotency_digest:
            raise OperationalLimitError(
                "operational limit idempotency key has a different immutable request"
            )
        return self._receipt(existing)

    def _load_authorization_outcome_in_session(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> OperationalAuthorizationOutcome | None:
        """Load one exact terminal authorization before certifying a retry.

        The metering receipt alone is deliberately insufficient replay
        evidence: an old receipt has no immutable context or decision proof.
        A committed receipt without its matching authorization outcome is
        therefore corrupt/legacy state and must fail closed at the composite
        boundary instead of being reauthorized with a later clock sample.
        """

        self._require_initialized()
        details = self._details(request)
        row = (
            _connection(session)
            .execute(
                "SELECT * FROM operational_limit_authorization_outcomes "
                "WHERE principal_id = ? AND idempotency_key = ?",
                (details.principal_id, details.idempotency_key),
            )
            .fetchone()
        )
        if row is None:
            return None
        if row["idempotency_digest"] != details.idempotency_digest:
            raise OperationalLimitError(
                "operational authorization idempotency key has a different immutable request"
            )
        if row["action"] != details.action:
            raise OperationalLimitError("durable operational authorization action is malformed")
        try:
            raw_evaluation = json.loads(cast(str, row["authorization_evaluation_json"]))
            if not isinstance(raw_evaluation, dict):
                raise ValueError("authorization evaluation is not an object")
            evaluation = authorization_evaluation_from_payload(
                cast(dict[str, JsonValue], raw_evaluation)
            )
            request_time = datetime.fromisoformat(cast(str, row["request_time"]))
            evaluation_started_at = datetime.fromisoformat(cast(str, row["evaluation_started_at"]))
            evaluation_completed_at = datetime.fromisoformat(
                cast(str, row["evaluation_completed_at"])
            )
            effect_committed = row["effect_committed"]
            if type(effect_committed) is not int or effect_committed not in {0, 1}:
                raise ValueError("effect_committed is malformed")
            resolution: Mapping[str, JsonValue] | None = None
            if row["resolution_json"] is not None:
                raw_resolution = json.loads(cast(str, row["resolution_json"]))
                if not isinstance(raw_resolution, dict):
                    raise ValueError("resolution is not an object")
                resolution = cast(dict[str, JsonValue], raw_resolution)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise OperationalLimitError("durable operational authorization is malformed") from exc

        receipt = self._load_replay_in_session(session, request)
        if effect_committed == 1:
            if receipt is None or receipt.request_digest != row["request_digest"]:
                raise OperationalLimitError(
                    "committed operational authorization has no matching exact receipt"
                )
        elif receipt is not None:
            raise OperationalLimitError(
                "denied operational authorization unexpectedly has a metering receipt"
            )
        return OperationalAuthorizationOutcome(
            request_digest=cast(str, row["request_digest"]),
            request_time=request_time,
            decision=evaluation.decision,
            authorization_evaluation=evaluation,
            evaluation_started_at=evaluation_started_at,
            evaluation_completed_at=evaluation_completed_at,
            receipt=receipt,
            resolution=resolution,
        )

    def _pending_id(self, details: _OperationDetails) -> str:
        return "opending:" + _digest(
            {
                "idempotency_key": details.idempotency_key,
                "principal_id": details.principal_id,
            }
        )

    def _pending_from_row(self, row: Mapping[str, object]) -> OperationalPendingAuthorization:
        try:
            raw_request = json.loads(cast(str, row["request_json"]))
            raw_evaluation = json.loads(cast(str, row["authorization_evaluation_json"]))
            raw_resolution = row["resolution_json"]
            if not isinstance(raw_request, dict) or not isinstance(raw_evaluation, dict):
                raise ValueError("pending payload is not an object")
            request = action_request_from_payload(cast(dict[str, JsonValue], raw_request))
            evaluation = authorization_evaluation_from_payload(
                cast(dict[str, JsonValue], raw_evaluation)
            )
            resolution: Mapping[str, JsonValue] | None = None
            if raw_resolution is not None:
                decoded_resolution = json.loads(cast(str, raw_resolution))
                if not isinstance(decoded_resolution, dict):
                    raise ValueError("pending resolution is not an object")
                resolution = cast(dict[str, JsonValue], decoded_resolution)
            pending = OperationalPendingAuthorization(
                pending_id=cast(str, row["pending_id"]),
                request=request,
                request_digest=cast(str, row["request_digest"]),
                decision=evaluation.decision,
                authorization_evaluation=evaluation,
                evaluation_started_at=datetime.fromisoformat(
                    cast(str, row["evaluation_started_at"])
                ),
                evaluation_completed_at=datetime.fromisoformat(
                    cast(str, row["evaluation_completed_at"])
                ),
                pending_plan=PendingResolutionPlan(cast(str, row["pending_plan"])),
                resolution=resolution,
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise OperationalLimitError(
                "durable operational pending authorization is malformed"
            ) from exc
        details = self._details(pending.request)
        if (
            details.action != row["action"]
            or details.principal_id != row["principal_id"]
            or details.operation_id != row["operation_id"]
            or details.idempotency_key != row["idempotency_key"]
            or details.idempotency_digest != row["idempotency_digest"]
            or details.request_digest != pending.request_digest
            or self._pending_id(details) != pending.pending_id
        ):
            raise OperationalLimitError("durable operational pending identity is inconsistent")
        state = row["state"]
        if (state == "pending") != (pending.resolution is None):
            raise OperationalLimitError("durable operational pending state is inconsistent")
        return pending

    def _load_pending_in_session(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> OperationalPendingAuthorization | None:
        """Load the exact pending/replayed escalation under request locks."""

        self._require_initialized()
        details = self._details(request)
        row = (
            _connection(session)
            .execute(
                "SELECT * FROM operational_limit_pending_authorizations "
                "WHERE principal_id = ? AND idempotency_key = ?",
                (details.principal_id, details.idempotency_key),
            )
            .fetchone()
        )
        if row is None:
            return None
        pending = self._pending_from_row(cast(Mapping[str, object], row))
        if _idempotency_binding_digest(pending.request) != details.idempotency_digest:
            raise OperationalLimitError(
                "operational pending idempotency key has a different immutable request"
            )
        return pending

    async def load_pending(self, pending_id: str) -> OperationalPendingAuthorization:
        """Load one durable pending locator without trusting caller action data."""

        identity = _identity(pending_id, "pending_id")
        async with self._resource.open_session(write=True) as session:
            row = (
                _connection(session)
                .execute(
                    "SELECT * FROM operational_limit_pending_authorizations WHERE pending_id = ?",
                    (identity,),
                )
                .fetchone()
            )
            if row is None:
                raise OperationalLimitError("operational pending authorization is unknown")
            return self._pending_from_row(cast(Mapping[str, object], row))

    def _record_pending_in_session(
        self,
        session: ResourceSession,
        request: ActionRequest,
        *,
        authorization_evaluation: AuthorizationEvaluation,
        evaluation_started_at: datetime,
        evaluation_completed_at: datetime,
        pending_plan: PendingResolutionPlan,
    ) -> OperationalPendingAuthorization:
        """Persist a nonterminal escalation instead of a terminal outcome."""

        if pending_plan is not PendingResolutionPlan.REVALIDATE:
            raise OperationalLimitError("operational escalation requires revalidation")
        decision = authorization_evaluation.decision
        if decision.effect is not DecisionEffect.ESCALATE:
            raise OperationalLimitError("only an escalation may create operational pending state")
        details = self._details(request)
        existing = self._load_pending_in_session(session, request)
        if existing is not None:
            return existing
        pending_id = self._pending_id(details)
        now = datetime.now(UTC)
        _connection(session).execute(
            "INSERT INTO operational_limit_pending_authorizations("
            "pending_id, action, principal_id, operation_id, idempotency_key, "
            "idempotency_digest, request_digest, request_json, evaluation_started_at, "
            "evaluation_completed_at, authorization_evaluation_json, pending_plan, state, "
            "resolution_json, created_at, resolved_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', NULL, ?, NULL)",
            (
                pending_id,
                details.action,
                details.principal_id,
                details.operation_id,
                details.idempotency_key,
                details.idempotency_digest,
                details.request_digest,
                _json(action_request_payload(request)),
                _time(evaluation_started_at),
                _time(evaluation_completed_at),
                _json(authorization_evaluation_payload(authorization_evaluation)),
                pending_plan.value,
                _time(now),
            ),
        )
        pending = self._load_pending_in_session(session, request)
        if pending is None:  # pragma: no cover - inserted in this transaction
            raise OperationalLimitError("operational pending authorization disappeared")
        return pending

    def _resolve_pending_in_session(
        self,
        session: ResourceSession,
        pending: OperationalPendingAuthorization,
        resolution: Mapping[str, JsonValue],
    ) -> OperationalPendingAuthorization:
        """Mark pending resolved in the same transaction as its terminal outcome."""

        normalized = json.loads(_json(cast(JsonValue, dict(resolution))))
        connection = _connection(session)
        row = connection.execute(
            "SELECT * FROM operational_limit_pending_authorizations WHERE pending_id = ?",
            (pending.pending_id,),
        ).fetchone()
        if row is None:
            raise OperationalLimitError("operational pending authorization is unknown")
        current = self._pending_from_row(cast(Mapping[str, object], row))
        if current.resolution is not None:
            if dict(current.resolution) != normalized:
                raise OperationalLimitError("operational pending resolution is immutable")
            return current
        now = datetime.now(UTC)
        connection.execute(
            "UPDATE operational_limit_pending_authorizations "
            "SET state = 'resolved', resolution_json = ?, resolved_at = ? "
            "WHERE pending_id = ? AND state = 'pending'",
            (_json(cast(JsonValue, normalized)), _time(now), pending.pending_id),
        )
        row = connection.execute(
            "SELECT * FROM operational_limit_pending_authorizations WHERE pending_id = ?",
            (pending.pending_id,),
        ).fetchone()
        assert row is not None
        return self._pending_from_row(cast(Mapping[str, object], row))

    def _record_authorization_outcome_in_session(
        self,
        session: ResourceSession,
        request: ActionRequest,
        *,
        decision: PolicyDecision,
        authorization_evaluation: AuthorizationEvaluation,
        evaluation_started_at: datetime,
        evaluation_completed_at: datetime,
        receipt: OperationalLimitReceipt | None,
        resolution: Mapping[str, JsonValue] | None = None,
    ) -> OperationalAuthorizationOutcome:
        """Persist the complete immutable terminal decision under its idempotency key."""

        self._require_initialized()
        details = self._details(request)
        request_digest = request_binding_digest(request)
        outcome = OperationalAuthorizationOutcome(
            request_digest=request_digest,
            request_time=request.timestamp,
            decision=decision,
            authorization_evaluation=authorization_evaluation,
            evaluation_started_at=evaluation_started_at,
            evaluation_completed_at=evaluation_completed_at,
            receipt=receipt,
            resolution=resolution,
        )
        existing = self._load_authorization_outcome_in_session(session, request)
        if existing is not None:
            if existing != outcome:
                raise OperationalLimitError("operational authorization outcome is immutable")
            return existing
        existing_receipt = self._load_replay_in_session(session, request)
        if existing_receipt is not None and receipt is None:
            raise OperationalLimitError("operational receipt lacks durable authorization evidence")
        if receipt is not None:
            if existing_receipt != receipt or receipt.request_digest != request_digest:
                raise OperationalLimitError(
                    "operational authorization outcome does not match its metering receipt"
                )
        else:
            advance_scope_version(
                _connection(session),
                self._idempotency_scope(details.principal_id, details.idempotency_key),
            )
        _connection(session).execute(
            "INSERT INTO operational_limit_authorization_outcomes("
            "action, principal_id, operation_id, idempotency_key, idempotency_digest, "
            "request_digest, request_time, evaluation_started_at, evaluation_completed_at, "
            "authorization_evaluation_json, effect_committed, resolution_json"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                details.action,
                details.principal_id,
                details.operation_id,
                details.idempotency_key,
                details.idempotency_digest,
                outcome.request_digest,
                _time(outcome.request_time),
                _time(outcome.evaluation_started_at),
                _time(outcome.evaluation_completed_at),
                _json(authorization_evaluation_payload(outcome.authorization_evaluation)),
                1 if receipt is not None else 0,
                (
                    None
                    if outcome.resolution is None
                    else _json(cast(JsonValue, dict(outcome.resolution)))
                ),
            ),
        )
        return outcome

    @staticmethod
    def _bounded_total(current: int, quantity: int, *, field_name: str) -> int:
        if current < 0 or current > _MAX_QUANTITY - quantity:
            raise OperationalLimitError(f"{field_name} exceeds signed 64-bit range")
        return current + quantity

    def _record_in_session(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> OperationalLimitReceipt:
        self._require_initialized()
        details = self._details(request)
        connection = _connection(session)
        _lock(connection, self._operation_scopes(details))
        replay = self._load_replay_in_session(session, request)
        if replay is not None:
            return replay

        velocity_scope = self._velocity_scope(details.principal_id)
        velocity_row = connection.execute(
            "SELECT action_count FROM cross_action_velocity WHERE principal_id = ?",
            (details.principal_id,),
        ).fetchone()
        current_velocity = 0 if velocity_row is None else int(velocity_row["action_count"])
        if current_velocity >= self.policy.velocity_limit:
            raise OperationalLimitExceeded("cross-action velocity cap is exhausted")
        velocity_count = self._bounded_total(
            current_velocity,
            1,
            field_name="cross-action velocity",
        )

        quota_used: int | None = None
        egress_volume: int | None = None
        if details.action == _API_SPEND_ACTION:
            assert details.service is not None
            quota_row = connection.execute(
                "SELECT used_units FROM service_quota_usage WHERE service = ? AND principal_id = ?",
                (details.service, details.principal_id),
            ).fetchone()
            current_quota = 0 if quota_row is None else int(quota_row["used_units"])
            quota_used = self._bounded_total(current_quota, details.quantity, field_name="quota")
            if quota_used > self.policy.service_limit(details.service):
                raise OperationalLimitExceeded("service quota cap is exhausted")
            quota_scope = self._quota_scope(details.service, details.principal_id)
            quota_version = advance_scope_version(connection, quota_scope)
            connection.execute(
                "INSERT INTO service_quota_usage(service, principal_id, used_units, version) "
                "VALUES (?, ?, ?, ?) ON CONFLICT(service, principal_id) DO UPDATE SET "
                "used_units = excluded.used_units, version = excluded.version",
                (details.service, details.principal_id, quota_used, quota_version),
            )
        else:
            egress_row = connection.execute(
                "SELECT used_bytes FROM egress_volume_usage WHERE principal_id = ?",
                (details.principal_id,),
            ).fetchone()
            current_egress = 0 if egress_row is None else int(egress_row["used_bytes"])
            egress_volume = self._bounded_total(
                current_egress,
                details.quantity,
                field_name="egress volume",
            )
            if egress_volume > self.policy.egress_limit_bytes:
                raise OperationalLimitExceeded("outbound egress-volume cap is exhausted")
            egress_scope = self._egress_scope(details.principal_id)
            egress_version = advance_scope_version(connection, egress_scope)
            connection.execute(
                "INSERT INTO egress_volume_usage(principal_id, used_bytes, version) "
                "VALUES (?, ?, ?) ON CONFLICT(principal_id) DO UPDATE SET "
                "used_bytes = excluded.used_bytes, version = excluded.version",
                (details.principal_id, egress_volume, egress_version),
            )

        velocity_version = advance_scope_version(connection, velocity_scope)
        connection.execute(
            "INSERT INTO cross_action_velocity(principal_id, action_count, version) "
            "VALUES (?, ?, ?) ON CONFLICT(principal_id) DO UPDATE SET "
            "action_count = excluded.action_count, version = excluded.version",
            (details.principal_id, velocity_count, velocity_version),
        )
        advance_scope_version(
            connection,
            self._idempotency_scope(details.principal_id, details.idempotency_key),
        )
        connection.execute(
            "INSERT INTO operational_limit_operations("
            "action, principal_id, operation_id, idempotency_key, request_digest, "
            "idempotency_digest, quantity, quota_used, egress_volume, velocity_count"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                details.action,
                details.principal_id,
                details.operation_id,
                details.idempotency_key,
                details.request_digest,
                details.idempotency_digest,
                details.quantity,
                quota_used,
                egress_volume,
                velocity_count,
            ),
        )
        return OperationalLimitReceipt(
            details.action,
            details.principal_id,
            details.operation_id,
            details.request_digest,
            details.quantity,
            quota_used,
            egress_volume,
            velocity_count,
        )

    def _execute_in_session(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> OperationalLimitReceipt:
        """Execute one effect while preserving typed backend failure semantics."""

        try:
            return self._record_in_session(session, request)
        except Exception as exc:
            mapped = _resource_failure(exc)
            if mapped is exc:
                raise
            raise mapped from exc

    async def _record_for_request_unchecked(
        self,
        request: ActionRequest,
    ) -> OperationalLimitReceipt:
        """Low-level provider-state exercise; production uses the composite coordinator."""

        self._require_initialized()
        async with self._resource.open_session(write=True) as session:
            return self._execute_in_session(session, request)

    def _validate_stable_scope_derivation(self) -> None:
        """Fail startup if a provider-local scope derivation is unstable.

        Provider assembly cannot infer arbitrary resolver inputs, but this
        provider owns a finite canonical scope scheme.  Check representative
        identities before exposing contracts so a mutated/non-deterministic
        derivation cannot be assembled as policy state.
        """

        derivations: tuple[Callable[[], str], ...] = (
            lambda: self._quota_scope("scope-service", "scope-principal"),
            lambda: self._egress_scope("scope-principal"),
            lambda: self._velocity_scope("scope-principal"),
            lambda: self._idempotency_scope("scope-principal", "scope-idempotency"),
            lambda: self._configuration_scope("quota", "scope-service"),
            lambda: self._configuration_scope("egress"),
            lambda: self._configuration_scope("velocity"),
        )
        for derive in derivations:
            first, second = derive(), derive()
            if first != second or not first:
                raise OperationalLimitError(
                    "operational limits scope derivation is not deterministic"
                )

    def provider_module(
        self,
        protected_runners: Mapping[str, ProtectedExecutionRunner] | None = None,
    ) -> ProviderModule:
        """Expose logical meters transactionally or behind installed runners."""

        self._validate_stable_scope_derivation()

        def quota_used(
            session: ResourceSession,
            arguments: tuple[Scalar | Duration, ...],
            _scope: str,
        ) -> tuple[Scalar, int]:
            self._require_initialized()
            if len(arguments) != 2:
                raise OperationalLimitError("quota.used requires service and principal id")
            service = _identity(arguments[0], "quota service")
            principal = _identity(arguments[1], "principal_id")
            scope = self._quota_scope(service, principal)
            row = (
                _connection(session)
                .execute(
                    "SELECT COALESCE((SELECT used_units FROM service_quota_usage "
                    "WHERE service = ? AND principal_id = ?), 0) AS used_units, "
                    "COALESCE((SELECT version FROM policy_scope_versions WHERE scope = ?), 0) "
                    "AS scope_version",
                    (service, principal, scope),
                )
                .fetchone()
            )
            if row is None:
                raise OperationalLimitError("quota view query returned no row")
            return int(row["used_units"]), int(row["scope_version"])

        def quota_limit(
            session: ResourceSession,
            arguments: tuple[Scalar | Duration, ...],
            _scope: str,
        ) -> tuple[Scalar, int]:
            self._require_initialized()
            if len(arguments) != 2:
                raise OperationalLimitError("quota.limit requires service and principal id")
            service = _identity(arguments[0], "quota service")
            principal = _identity(arguments[1], "principal_id")
            scope = self._quota_scope(service, principal)
            row = (
                _connection(session)
                .execute(
                    "SELECT COALESCE((SELECT version FROM policy_scope_versions "
                    "WHERE scope = ?), 0) AS scope_version",
                    (scope,),
                )
                .fetchone()
            )
            if row is None:
                raise OperationalLimitError("quota-limit view query returned no row")
            return self.policy.service_limit(service), int(row["scope_version"])

        def egress_volume(
            session: ResourceSession,
            arguments: tuple[Scalar | Duration, ...],
            _scope: str,
        ) -> tuple[Scalar, int]:
            self._require_initialized()
            if len(arguments) != 1:
                raise OperationalLimitError("egress.volume requires a principal id")
            principal = _identity(arguments[0], "principal_id")
            scope = self._egress_scope(principal)
            row = (
                _connection(session)
                .execute(
                    "SELECT COALESCE((SELECT used_bytes FROM egress_volume_usage "
                    "WHERE principal_id = ?), 0) AS used_bytes, "
                    "COALESCE((SELECT version FROM policy_scope_versions WHERE scope = ?), 0) "
                    "AS scope_version",
                    (principal, scope),
                )
                .fetchone()
            )
            if row is None:
                raise OperationalLimitError("egress-volume view query returned no row")
            return int(row["used_bytes"]), int(row["scope_version"])

        def egress_limit(
            session: ResourceSession,
            arguments: tuple[Scalar | Duration, ...],
            _scope: str,
        ) -> tuple[Scalar, int]:
            self._require_initialized()
            if len(arguments) != 1:
                raise OperationalLimitError("egress.limit requires a principal id")
            principal = _identity(arguments[0], "principal_id")
            scope = self._egress_scope(principal)
            row = (
                _connection(session)
                .execute(
                    "SELECT COALESCE((SELECT version FROM policy_scope_versions "
                    "WHERE scope = ?), 0) AS scope_version",
                    (scope,),
                )
                .fetchone()
            )
            if row is None:
                raise OperationalLimitError("egress-limit view query returned no row")
            return self.policy.egress_limit_bytes, int(row["scope_version"])

        def velocity_count(
            session: ResourceSession,
            arguments: tuple[Scalar | Duration, ...],
            _scope: str,
        ) -> tuple[Scalar, int]:
            self._require_initialized()
            if len(arguments) != 1:
                raise OperationalLimitError("velocity.count requires a principal id")
            principal = _identity(arguments[0], "principal_id")
            scope = self._velocity_scope(principal)
            row = (
                _connection(session)
                .execute(
                    "SELECT COALESCE((SELECT action_count FROM cross_action_velocity "
                    "WHERE principal_id = ?), 0) AS action_count, "
                    "COALESCE((SELECT version FROM policy_scope_versions WHERE scope = ?), 0) "
                    "AS scope_version",
                    (principal, scope),
                )
                .fetchone()
            )
            if row is None:
                raise OperationalLimitError("velocity view query returned no row")
            return int(row["action_count"]), int(row["scope_version"])

        def velocity_limit(
            session: ResourceSession,
            arguments: tuple[Scalar | Duration, ...],
            _scope: str,
        ) -> tuple[Scalar, int]:
            self._require_initialized()
            if len(arguments) != 1:
                raise OperationalLimitError("velocity.limit requires a principal id")
            principal = _identity(arguments[0], "principal_id")
            scope = self._velocity_scope(principal)
            row = (
                _connection(session)
                .execute(
                    "SELECT COALESCE((SELECT version FROM policy_scope_versions "
                    "WHERE scope = ?), 0) AS scope_version",
                    (scope,),
                )
                .fetchone()
            )
            if row is None:
                raise OperationalLimitError("velocity-limit view query returned no row")
            return self.policy.velocity_limit, int(row["scope_version"])

        def quota_scope(arguments: tuple[Scalar | Duration, ...]) -> str:
            if len(arguments) != 2:
                raise OperationalLimitError("quota.used requires service and principal id")
            return self._quota_scope(arguments[0], arguments[1])

        def quota_limit_scope(arguments: tuple[Scalar | Duration, ...]) -> str:
            if len(arguments) != 2:
                raise OperationalLimitError("quota.limit requires service and principal id")
            return self._quota_scope(arguments[0], arguments[1])

        def principal_scope(arguments: tuple[Scalar | Duration, ...], *, kind: str) -> str:
            if len(arguments) != 1:
                raise OperationalLimitError(f"{kind} view requires a principal id")
            if kind == "egress":
                return self._egress_scope(arguments[0])
            return self._velocity_scope(arguments[0])

        def effect_footprint(action: str) -> Callable[[ActionRequest], ResourceFootprint]:
            def resolve(request: ActionRequest) -> ResourceFootprint:
                details = self._details(request)
                if details.action != action:
                    raise OperationalLimitError("operational limits effect action mismatch")
                return ResourceFootprint(writes=self._operation_scopes(details))

            return resolve

        def execute(session: ResourceSession, request: ActionRequest) -> dict[str, JsonValue]:
            return self._execute_in_session(session, request).result

        identity = self.policy.provider_identity
        views = (
            GovernanceViewContract(
                "quota.used",
                (TypeName.STRING, TypeName.STRING),
                TypeName.INT,
                _MODULE_ID,
                "scoped-policy-state",
                100,
                True,
                quota_scope,
                quota_used,
                ReservationViewKind.UNSUPPORTED,
                provider_identity=identity,
            ),
            GovernanceViewContract(
                "quota.limit",
                (TypeName.STRING, TypeName.STRING),
                TypeName.INT,
                _MODULE_ID,
                "scoped-policy-state",
                100,
                True,
                quota_limit_scope,
                quota_limit,
                ReservationViewKind.UNSUPPORTED,
                provider_identity=identity,
            ),
            GovernanceViewContract(
                "egress.volume",
                (TypeName.STRING,),
                TypeName.INT,
                _MODULE_ID,
                "scoped-policy-state",
                100,
                True,
                lambda arguments: principal_scope(arguments, kind="egress"),
                egress_volume,
                ReservationViewKind.UNSUPPORTED,
                provider_identity=identity,
            ),
            GovernanceViewContract(
                "egress.limit",
                (TypeName.STRING,),
                TypeName.INT,
                _MODULE_ID,
                "scoped-policy-state",
                100,
                True,
                lambda arguments: principal_scope(arguments, kind="egress"),
                egress_limit,
                ReservationViewKind.UNSUPPORTED,
                provider_identity=identity,
            ),
            GovernanceViewContract(
                "velocity.count",
                (TypeName.STRING,),
                TypeName.INT,
                _MODULE_ID,
                "scoped-policy-state",
                100,
                True,
                lambda arguments: principal_scope(arguments, kind="velocity"),
                velocity_count,
                ReservationViewKind.UNSUPPORTED,
                provider_identity=identity,
            ),
            GovernanceViewContract(
                "velocity.limit",
                (TypeName.STRING,),
                TypeName.INT,
                _MODULE_ID,
                "scoped-policy-state",
                100,
                True,
                lambda arguments: principal_scope(arguments, kind="velocity"),
                velocity_limit,
                ReservationViewKind.UNSUPPORTED,
                provider_identity=identity,
            ),
        )
        runners: dict[str, ProtectedExecutionRunner] = (
            {} if protected_runners is None else dict(protected_runners)
        )
        if set(runners) - {_API_SPEND_ACTION, _HTTP_POST_ACTION}:
            raise OperationalLimitError(
                "operational limits module received an unknown protected runner"
            )
        effects = tuple(
            EffectBinding(
                EffectContract(
                    action,
                    argument_types,
                    _MODULE_ID,
                    ConsistencyGuarantee.POLICY_STATE_SERIALIZABLE,
                    effect_footprint(action),
                    (
                        cast(
                            EffectExecutor,
                            execute
                            if action not in runners
                            else ProtectedExternalExecutor(connector_id),
                        )
                    ),
                    consumable_arg=consumable_arg,
                    provider_identity=identity,
                ),
                (
                    EffectExecutionPosition.TRANSACTIONAL
                    if action not in runners
                    else EffectExecutionPosition.PROTECTED_EXTERNAL
                ),
                None if action not in runners else connector_id,
            )
            for action, argument_types, consumable_arg, connector_id in (
                (
                    _API_SPEND_ACTION,
                    {
                        "service": TypeName.STRING,
                        "units": TypeName.INT,
                        "request_ref": TypeName.STRING,
                    },
                    "units",
                    _API_CONNECTOR_ID,
                ),
                (
                    _HTTP_POST_ACTION,
                    {
                        "destination": TypeName.STRING,
                        "payload_bytes": TypeName.INT,
                        "content_digest": TypeName.STRING,
                    },
                    "payload_bytes",
                    _HTTP_CONNECTOR_ID,
                ),
            )
        )
        return ProviderModule(
            module_id=_MODULE_ID,
            identity=identity,
            domain=self._domain,
            scope_derivation_id=self._domain.scope_derivation_id,
            views=views,
            effects=effects,
            protected_executions=tuple(
                ProtectedExecutionRegistration(action, runner)
                for action, runner in sorted(runners.items())
            ),
        )


__all__ = [
    "OperationalLimitError",
    "OperationalLimitExceeded",
    "OperationalLimitReceipt",
    "OperationalLimitsPolicy",
    "OperationalLimitsProvider",
    "action_request_from_payload",
    "action_request_payload",
    "authorization_evaluation_from_payload",
    "authorization_evaluation_payload",
    "operational_authorization_digest",
]
