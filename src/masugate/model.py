"""Canonical data models shared across MasuGate components."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType

type Scalar = bool | int | str
type JsonValue = bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None


class TypeName(StrEnum):
    BOOL = "Bool"
    INT = "Int"
    STRING = "String"
    DURATION = "Duration"


class CertifiedInputStability(StrEnum):
    """Whether certified policy state may be reused after admission."""

    ADMISSION_STABLE = "admission-stable"
    RESOLUTION_VOLATILE = "resolution-volatile"


class CertifiedInputStabilityProof(StrEnum):
    """Proof families that make an admission-stable value reusable.

    core runtime prime deliberately supports only the strongest, simplest case: a
    value is a deterministic immutable property of the certified request.  A
    provider cannot obtain reservation eligibility by applying the
    ``admission-stable`` label without this proof contract.  Stability limited
    to an enforced reservation lifetime requires a future proof family.
    """

    REQUEST_BOUND_IMMUTABLE_V1 = "request-bound-immutable-v1"


class CertificationPhase(StrEnum):
    """Lifecycle phase in which an authoritative observation was certified."""

    ADMISSION = "admission"
    RESOLUTION = "resolution"


class DecisionEffect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    ESCALATE = "escalate"


class MasuGateMode(StrEnum):
    """The product's governed execution modes."""

    TRANSACTION = "masugate-transaction"
    RESERVATION = "masugate-reservation"
    SCOPED_HOLD = "masugate-scoped-hold"


class PendingResolutionPlan(StrEnum):
    """How an approved pending operation may regain an allow decision.

    ``REVALIDATE`` is the compatibility-safe default: a durable record that
    predates explicit resolution plans must never be treated as carrying a
    reservation proof merely because it has a reservation identifier.
    ``RESERVATION_PROOF`` therefore requires an explicit plan plus the safety
    certificate identity recorded alongside it.  The coordinator is
    responsible for creating and verifying that proof in core runtime prime.
    """

    REVALIDATE = "revalidate"
    SCOPED_HOLD = "scoped-hold"
    RESERVATION_PROOF = "reservation-proof"


def _is_sha256_digest(value: str | None) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_resolution_metadata(
    plan: PendingResolutionPlan,
    certificate_digest: str | None,
    entitlement_digest: str | None,
) -> None:
    if type(plan) is not PendingResolutionPlan:
        raise TypeError("resolution_plan must be a PendingResolutionPlan")
    if plan is PendingResolutionPlan.RESERVATION_PROOF:
        if not (_is_sha256_digest(certificate_digest) and _is_sha256_digest(entitlement_digest)):
            raise ValueError(
                "reservation-proof requires certificate and entitlement SHA-256 digests"
            )
        return
    if certificate_digest is not None or entitlement_digest is not None:
        raise ValueError("non-reservation pending plans cannot carry reservation proof digests")


class OperationStatus(StrEnum):
    """Lifecycle status for a governed operation."""

    COMMITTED = "committed"
    DENIED = "denied"
    PENDING = "pending"
    ABORTED = "aborted"


class ConsistencyGuarantee(StrEnum):
    BEST_EFFORT = "best-effort"
    POLICY_STATE_SERIALIZABLE = "policy-state-serializable"


@dataclass(frozen=True)
class Duration:
    seconds: int


_CERTIFIED_INPUT_NAME = re.compile(
    r"^certified\.[A-Za-z_][A-Za-z0-9_]*$",
    re.ASCII,
)


def _is_aware_datetime(value: object) -> bool:
    return type(value) is datetime and value.tzinfo is not None and value.utcoffset() is not None


def _is_canonical_identity(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 255
        and value.strip() == value
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )


def _certified_value_matches_type(
    value: Scalar | Duration,
    expected: TypeName,
) -> bool:
    if expected is TypeName.BOOL:
        return type(value) is bool
    if expected is TypeName.INT:
        return type(value) is int
    if expected is TypeName.STRING:
        return type(value) is str
    if expected is TypeName.DURATION:
        return type(value) is Duration and type(value.seconds) is int
    return False


@dataclass(frozen=True)
class CertifiedInputEvidence:
    """Immutable value and provenance issued by a trusted certifier.

    Freshness starts at the authoritative observation, not when a server later
    packages that observation.  ``expires_at`` is therefore derived from
    ``observed_at + freshness_ttl`` and cannot drift independently.
    """

    name: str
    value: Scalar | Duration
    value_type: TypeName
    stability: CertifiedInputStability
    stability_proof: CertifiedInputStabilityProof | None
    source_id: str
    source_version: str
    contract_version: str
    observed_at: datetime
    certified_at: datetime
    freshness_ttl: Duration
    phase: CertificationPhase

    def __post_init__(self) -> None:
        if type(self.name) is not str or _CERTIFIED_INPUT_NAME.fullmatch(self.name) is None:
            raise ValueError("certified input name must be a flat certified.<name> path")
        if type(self.value_type) is not TypeName:
            raise TypeError("certified input value_type must be a TypeName")
        if not _certified_value_matches_type(self.value, self.value_type):
            raise TypeError(
                f"certified input {self.name} value does not match {self.value_type.value}"
            )
        if type(self.stability) is not CertifiedInputStability:
            raise TypeError("certified input stability must be a CertifiedInputStability")
        if self.stability is CertifiedInputStability.ADMISSION_STABLE:
            if type(self.stability_proof) is not CertifiedInputStabilityProof:
                raise TypeError("admission-stable certified input requires a stability proof")
        elif self.stability_proof is not None:
            raise ValueError("resolution-volatile certified input cannot carry a stability proof")
        if type(self.phase) is not CertificationPhase:
            raise TypeError("certified input phase must be a CertificationPhase")
        for field_name in ("source_id", "source_version", "contract_version"):
            if not _is_canonical_identity(getattr(self, field_name)):
                raise ValueError(f"certified input {field_name} must be a canonical identity")
        if not _is_aware_datetime(self.observed_at):
            raise ValueError("certified input observed_at must be timezone-aware")
        if not _is_aware_datetime(self.certified_at):
            raise ValueError("certified input certified_at must be timezone-aware")
        if self.observed_at > self.certified_at:
            raise ValueError("certified input observation cannot follow certification")
        if (
            type(self.freshness_ttl) is not Duration
            or type(self.freshness_ttl.seconds) is not int
            or self.freshness_ttl.seconds <= 0
        ):
            raise ValueError("certified input freshness_ttl must be a positive Duration")
        if self.expires_at <= self.certified_at:
            raise ValueError("certified input must be fresh when it is certified")

    @property
    def expires_at(self) -> datetime:
        return self.observed_at + timedelta(seconds=self.freshness_ttl.seconds)


@dataclass(frozen=True)
class Principal:
    id: str
    attributes: Mapping[str, Scalar] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "attributes",
            MappingProxyType(dict(self.attributes)),
        )


@dataclass(frozen=True)
class ProtectedArtifactMetadata:
    """Content-free immutable payload facts retained with a governed request.

    The payload itself remains available only through the worker's verified
    reader.  This projection gives providers and the durable audit record the
    facts they need to explain which inspected bytes were authorized after the
    short-lived staging object has been garbage-collected.
    """

    reference: str
    content_digest: str
    content_bytes: int
    media_type: str
    classification: str
    expires_at: datetime
    inspector_version: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.reference, str)
            or not self.reference.startswith("art:")
            or len(self.reference) > 255
        ):
            raise ValueError("protected artifact reference must be an opaque art reference")
        if not _is_sha256_digest(self.content_digest):
            raise ValueError("protected artifact content_digest must be a SHA-256 digest")
        if type(self.content_bytes) is not int or self.content_bytes < 0:
            raise ValueError("protected artifact content_bytes must be non-negative")
        for field_name in ("media_type", "classification", "inspector_version"):
            value = getattr(self, field_name)
            if type(value) is not str or not value or value.strip() != value or len(value) > 255:
                raise ValueError(f"protected artifact {field_name} must be a bounded identifier")
        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise ValueError("protected artifact expires_at must be timezone-aware")

    def payload(self) -> dict[str, JsonValue]:
        return {
            "classification": self.classification,
            "content_bytes": self.content_bytes,
            "content_digest": self.content_digest,
            "expires_at": self.expires_at.isoformat(),
            "inspector_version": self.inspector_version,
            "media_type": self.media_type,
            "reference": self.reference,
        }


@dataclass(frozen=True)
class ActionRequest:
    operation_id: str
    principal: Principal
    action: str
    arguments: Mapping[str, Scalar]
    idempotency_key: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    resource: str | None = None
    trace_id: str | None = None
    # A server-verified digest of a canonical host-adapter invocation.  It is
    # intentionally separate from trace_id: trace metadata may change on a
    # safe retry, whereas this trusted adapter assertion must not.
    adapter_invocation_digest: str | None = None
    protected_artifacts: Mapping[str, ProtectedArtifactMetadata] = field(default_factory=dict)
    certified_inputs: Mapping[str, CertifiedInputEvidence] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "arguments",
            MappingProxyType(dict(self.arguments)),
        )
        if self.adapter_invocation_digest is not None and (
            not isinstance(self.adapter_invocation_digest, str)
            or len(self.adapter_invocation_digest) != 64
            or any(
                character not in "0123456789abcdef" for character in self.adapter_invocation_digest
            )
        ):
            raise ValueError("adapter_invocation_digest must be a lowercase SHA-256 digest")
        protected_artifacts = dict(self.protected_artifacts)
        for name, metadata in protected_artifacts.items():
            if type(name) is not str or not isinstance(metadata, ProtectedArtifactMetadata):
                raise TypeError("protected_artifacts must map names to ProtectedArtifactMetadata")
            if self.arguments.get(name) != metadata.reference:
                raise ValueError(
                    "protected artifact metadata must match the action argument reference"
                )
        object.__setattr__(self, "protected_artifacts", MappingProxyType(protected_artifacts))
        certified_inputs = dict(self.certified_inputs)
        for name, evidence in certified_inputs.items():
            if type(name) is not str or not isinstance(evidence, CertifiedInputEvidence):
                raise TypeError("certified_inputs must map names to CertifiedInputEvidence")
            if name != evidence.name:
                raise ValueError("certified_inputs mapping key must match the evidence name")
        object.__setattr__(
            self,
            "certified_inputs",
            MappingProxyType(certified_inputs),
        )


def request_binding_digest(request: ActionRequest) -> str:
    """Return a stable identity for the immutable, governed request inputs.

    Transport tracing and admission timestamps are deliberately excluded: they
    are observational metadata and may differ for a safe retry. The identity
    instead covers every caller-supplied field that can change the governed
    operation, including all action arguments and the principal attributes
    that policy can inspect.
    """

    if type(request) is not ActionRequest:
        raise TypeError("request binding digest requires an ActionRequest")
    payload: dict[str, JsonValue] = {
        "action": request.action,
        "arguments": dict(request.arguments),
        "idempotency_key": request.idempotency_key,
        "operation_id": request.operation_id,
        "principal": {
            "attributes": dict(request.principal.attributes),
            "id": request.principal.id,
        },
        "resource": request.resource,
    }
    # The original durable identity predates adapter provenance.  Omit an
    # absent digest rather than serializing ``null`` so existing rows and
    # non-adapter requests retain their historical binding.  A verified
    # adapter invocation is still immutable input when it is present.
    if request.adapter_invocation_digest is not None:
        payload["adapter_invocation_digest"] = request.adapter_invocation_digest
    if request.protected_artifacts:
        payload["protected_artifacts"] = {
            name: metadata.payload()
            for name, metadata in sorted(request.protected_artifacts.items())
        }
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ResourceFootprint:
    reads: frozenset[str] = frozenset()
    writes: frozenset[str] = frozenset()

    @property
    def all_scopes(self) -> frozenset[str]:
        return self.reads | self.writes


@dataclass(frozen=True)
class ViewRead:
    function: str
    arguments: tuple[Scalar | Duration, ...]
    value: Scalar
    scope: str
    version: int
    latency_ms: float


@dataclass(frozen=True)
class PolicyProvenance:
    """Trusted catalog identity for one evaluated compiled policy.

    ``policy_runtime_version`` is the evaluator's compact semantic version;
    ``policy_digest`` is the complete canonical-AST SHA-256 declared by the
    bundle.  Keeping both makes audit compatibility explicit without treating
    a human version label as a content identity.
    """

    policy_id: str
    policy_declared_version: str
    policy_runtime_version: str
    policy_digest: str
    bundle_id: str
    bundle_version: str
    bundle_digest: str
    layer: str
    mode: str

    def __post_init__(self) -> None:
        identities = (
            self.policy_id,
            self.policy_declared_version,
            self.policy_runtime_version,
            self.bundle_id,
            self.bundle_version,
        )
        if any(not _is_canonical_identity(value) for value in identities):
            raise ValueError("policy provenance identities must be canonical")
        if not _is_sha256_digest(self.policy_digest):
            raise ValueError("policy provenance policy_digest must be SHA-256")
        if not _is_sha256_digest(self.bundle_digest):
            raise ValueError("policy provenance bundle_digest must be SHA-256")
        if self.layer not in {"platform-safety", "deployment-regulatory", "owner"}:
            raise ValueError("policy provenance has an unknown layer")
        expected_mode = "configurable" if self.layer == "owner" else "mandatory"
        if self.mode != expected_mode:
            raise ValueError("policy provenance layer/mode combination is invalid")


@dataclass(frozen=True)
class PolicyDecision:
    effect: DecisionEffect
    policy_id: str
    rule_id: str
    reason: str
    reads: tuple[ViewRead, ...] = ()
    # Content hash of the deciding policy (0.16) — stable across identical
    # enforced logic, changes on a semantic edit. Empty for decisions not
    # produced by a compiled policy (e.g. fail-closed, capacity_unavailable).
    policy_version: str = ""
    # Every (policy_id, version) evaluated for this action under multi-policy
    # combining (0.16) — the audit trail's "which policies applied". A single
    # governing policy leaves this as just its own (id, version).
    evaluated_policies: tuple[tuple[str, str], ...] = ()
    # Complete trusted bundle/policy identities for catalog-admitted policies.
    # Legacy embedding APIs may leave this empty; the trusted loader populates
    # one entry for every evaluated policy and public audit preserves them.
    policy_provenance: tuple[PolicyProvenance, ...] = ()


@dataclass(frozen=True)
class AuthorizationEvaluation:
    """Replayable evidence for one complete protected policy evaluation."""

    phase: CertificationPhase
    evaluated_at: datetime
    decision: PolicyDecision
    certified_inputs: Mapping[str, CertifiedInputEvidence] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self.phase) is not CertificationPhase:
            raise TypeError("authorization evaluation phase must be a CertificationPhase")
        if not _is_aware_datetime(self.evaluated_at):
            raise ValueError("authorization evaluation time must be timezone-aware")
        if type(self.decision) is not PolicyDecision:
            raise TypeError("authorization evaluation decision must be a PolicyDecision")
        certified_inputs = dict(self.certified_inputs)
        for name, evidence in certified_inputs.items():
            if type(name) is not str or not isinstance(evidence, CertifiedInputEvidence):
                raise TypeError("authorization evaluation inputs must be certified evidence")
            if name != evidence.name:
                raise ValueError("authorization evaluation input key must match evidence name")
        object.__setattr__(
            self,
            "certified_inputs",
            MappingProxyType(certified_inputs),
        )


@dataclass(frozen=True)
class OperationMetrics:
    total_latency_ms: float = 0.0
    policy_eval_ms: float = 0.0
    effect_exec_ms: float = 0.0
    transaction_ms: float = 0.0
    local_lock_wait_ms: float = 0.0
    advisory_lock_wait_ms: float = 0.0
    reservation_create_ms: float = 0.0
    reservation_consume_ms: float = 0.0
    reservation_release_ms: float = 0.0
    scope_hold_wait_ms: float = 0.0
    retry_attempts: int = 0
    attempt_count: int = 1


@dataclass(frozen=True)
class OperationResult:
    operation_id: str
    decision: PolicyDecision
    committed: bool
    status: OperationStatus | None = None
    payload: dict[str, JsonValue] = field(default_factory=dict)
    metrics: OperationMetrics = field(default_factory=OperationMetrics)
    replayed: bool = False
    pending_id: str | None = None
    reservation_id: str | None = None
    resolution_plan: PendingResolutionPlan = PendingResolutionPlan.REVALIDATE
    reservation_safety_certificate_digest: str | None = None
    reservation_entitlement_digest: str | None = None
    authorization_evaluations: tuple[AuthorizationEvaluation, ...] = ()
    resolution_evidence: dict[str, JsonValue] | None = None

    def __post_init__(self) -> None:
        # Own a recursive JSON snapshot. A caller mutating an executor-owned
        # payload after construction must not rewrite a durable governance
        # result by alias.
        object.__setattr__(self, "payload", deepcopy(dict(self.payload)))
        if not all(
            type(evaluation) is AuthorizationEvaluation
            for evaluation in self.authorization_evaluations
        ):
            raise TypeError("authorization_evaluations must contain AuthorizationEvaluation values")
        if self.resolution_evidence is not None:
            object.__setattr__(
                self,
                "resolution_evidence",
                deepcopy(dict(self.resolution_evidence)),
            )
        _validate_resolution_metadata(
            self.resolution_plan,
            self.reservation_safety_certificate_digest,
            self.reservation_entitlement_digest,
        )
        if (
            self.resolution_plan is PendingResolutionPlan.RESERVATION_PROOF
            and self.reservation_id is None
        ):
            raise ValueError("reservation-proof requires a reservation id")
        if self.status is None:
            status = OperationStatus.COMMITTED if self.committed else OperationStatus.DENIED
            object.__setattr__(self, "status", status)


@dataclass(frozen=True)
class PendingOperation:
    pending_id: str
    request: ActionRequest
    decision: PolicyDecision
    mode: MasuGateMode
    reservation_id: str | None = None
    resolution_plan: PendingResolutionPlan = PendingResolutionPlan.REVALIDATE
    reservation_safety_certificate_digest: str | None = None
    reservation_entitlement_digest: str | None = None
    evidence: dict[str, JsonValue] = field(default_factory=dict)
    authorization_evaluations: tuple[AuthorizationEvaluation, ...] = ()
    # Provider-side durable-row cross-checks set this when redundant relational
    # identity disagrees with serialized JSON. It is internal fail-closed state,
    # not client-supplied approval evidence.
    integrity_error: str | None = None

    def __post_init__(self) -> None:
        if type(self.mode) is not MasuGateMode:
            raise TypeError("mode must be a MasuGateMode")
        object.__setattr__(self, "evidence", deepcopy(dict(self.evidence)))
        if not all(
            type(evaluation) is AuthorizationEvaluation
            for evaluation in self.authorization_evaluations
        ):
            raise TypeError("authorization_evaluations must contain AuthorizationEvaluation values")
        _validate_resolution_metadata(
            self.resolution_plan,
            self.reservation_safety_certificate_digest,
            self.reservation_entitlement_digest,
        )
        if self.resolution_plan is PendingResolutionPlan.RESERVATION_PROOF:
            if self.mode is not MasuGateMode.RESERVATION:
                raise ValueError("reservation-proof requires reservation mode")
            if self.reservation_id is None:
                raise ValueError("reservation-proof requires a reservation id")
