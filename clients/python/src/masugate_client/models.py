"""Typed public models for the Governed Action Protocol."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, TypeAlias

Scalar: TypeAlias = bool | int | str
JsonValue: TypeAlias = bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"] | None
DecisionEffect: TypeAlias = Literal["allow", "deny", "escalate"]
ActionStatus: TypeAlias = Literal[
    "committed", "denied", "pending", "in_progress", "outcome_unknown"
]
PendingResolutionPlan: TypeAlias = Literal["revalidate", "scoped-hold", "reservation-proof"]
ProtectedExecutionStatus: TypeAlias = Literal[
    "intent", "executing", "succeeded", "failed", "outcome_unknown"
]
ProtectedEntitlementState: TypeAlias = Literal["held", "consumed", "released", "quarantined"]
ProtectedConnectorOutcome: TypeAlias = Literal["succeeded", "failed", "unknown"]


@dataclass(frozen=True, slots=True)
class EvaluatedPolicy:
    policy_id: str
    policy_version: str


@dataclass(frozen=True, slots=True)
class PolicyProvenance:
    policy_id: str
    policy_declared_version: str
    policy_runtime_version: str
    policy_digest: str
    bundle_id: str
    bundle_version: str
    bundle_digest: str
    layer: Literal["platform-safety", "deployment-regulatory", "owner"]
    mode: Literal["mandatory", "configurable"]


@dataclass(frozen=True, slots=True)
class Decision:
    effect: DecisionEffect
    policy_id: str
    policy_version: str
    rule_id: str
    reason: str
    evaluated_policies: tuple[EvaluatedPolicy, ...] = ()
    policy_provenance: tuple[PolicyProvenance, ...] = ()


@dataclass(frozen=True, slots=True)
class ActionResult:
    operation_id: str
    status: ActionStatus
    decision: Decision | None
    payload: dict[str, JsonValue]
    audit_ref: str
    replayed: bool
    pending_id: str | None = None
    resolution_plan: PendingResolutionPlan | None = None
    reservation_safety_certificate_digest: str | None = None
    reservation_entitlement_digest: str | None = None


@dataclass(frozen=True, slots=True)
class StagedArtifact:
    """Server-certified metadata for one opaque operation payload.

    The SDK never accepts a reference, digest, classification, or retention
    value from its caller.  A reference returned here is only for trusted
    server/provider handoff, never an argument to :meth:`MasuGateClient.execute`.
    """

    reference: str
    content_digest: str
    content_bytes: int
    media_type: str
    classification: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class PendingOperation:
    pending_id: str
    operation_id: str
    principal_id: str
    action: str
    args: dict[str, JsonValue]
    created_at: datetime
    decision: Decision
    audit_ref: str
    resolution_plan: PendingResolutionPlan | None = None
    reservation_safety_certificate_digest: str | None = None
    reservation_entitlement_digest: str | None = None


@dataclass(frozen=True, slots=True)
class PendingEvent:
    event_id: str
    event_type: Literal["pending.created"]
    occurred_at: datetime
    pending: PendingOperation


@dataclass(frozen=True, slots=True)
class PendingList:
    items: tuple[PendingOperation, ...]
    next_cursor: str


@dataclass(frozen=True, slots=True)
class PendingLookup:
    """One durable pending locator, or the terminal replay that replaced it."""

    kind: Literal["pending", "terminal"]
    pending: PendingOperation | None = None
    result: ActionResult | None = None

    def __post_init__(self) -> None:
        if self.kind == "pending" and (self.pending is None or self.result is not None):
            raise ValueError("pending lookup kind requires pending and forbids result")
        if self.kind == "terminal" and (self.result is None or self.pending is not None):
            raise ValueError("terminal lookup kind requires result and forbids pending")


@dataclass(frozen=True, slots=True)
class ExpectedActionOwner:
    """The deployment-certified owner assertion for one governed action."""

    provider_id: str
    position: Literal["transactional", "protected-external"]
    connector_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.provider_id, str) or not self.provider_id.strip():
            raise ValueError("provider_id must be a non-empty string")
        if self.position == "transactional" and self.connector_id is not None:
            raise ValueError("transactional owner cannot name connector_id")
        if self.position == "protected-external" and (
            not isinstance(self.connector_id, str) or not self.connector_id.strip()
        ):
            raise ValueError("protected-external owner requires connector_id")


@dataclass(frozen=True, slots=True)
class AuditPrincipal:
    id: str
    attributes: dict[str, Scalar]


@dataclass(frozen=True, slots=True)
class ProtectedArtifactMetadata:
    """Content-free staged-payload facts retained in a durable audit receipt."""

    reference: str
    content_digest: str
    content_bytes: int
    media_type: str
    classification: str
    expires_at: datetime
    inspector_version: str


@dataclass(frozen=True, slots=True)
class AuditRequest:
    idempotency_key: str
    principal: AuditPrincipal
    action: str
    args: dict[str, JsonValue]
    timestamp: datetime
    request_time: datetime
    trace_id: str | None
    adapter_invocation_digest: str | None = None
    protected_artifacts: dict[str, ProtectedArtifactMetadata] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PolicyCatalog:
    policy_digest: str
    bundle_digest: str


@dataclass(frozen=True, slots=True)
class PolicyReceipt:
    policy_id: str
    policy_version: str
    evaluated_policies: tuple[EvaluatedPolicy, ...]
    evaluated_policy_provenance: tuple[PolicyProvenance, ...]
    catalog: PolicyCatalog | None = None


@dataclass(frozen=True, slots=True)
class AuditEntitlement:
    entitlement_id: str
    authorization_digest: str


@dataclass(frozen=True, slots=True)
class AuditDecision:
    effect: DecisionEffect
    rule_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class ViewRead:
    function: str
    arguments: tuple[JsonValue, ...]
    value: JsonValue
    scope: str
    version: int
    latency_ms: float


@dataclass(frozen=True, slots=True)
class AppliedEffect:
    action: str
    args: dict[str, JsonValue]
    payload: dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class CertifiedInputEvidence:
    name: str
    value: JsonValue
    value_type: Literal["Bool", "Int", "String", "Duration"]
    stability: Literal["admission-stable", "resolution-volatile"]
    stability_proof: Literal["request-bound-immutable-v1"] | None
    source_id: str
    source_version: str
    contract_version: str
    observed_at: datetime
    certified_at: datetime
    freshness_ttl_seconds: int
    expires_at: datetime
    phase: Literal["admission", "resolution"]


@dataclass(frozen=True, slots=True)
class AuthorizationEvaluation:
    phase: Literal["admission", "resolution"]
    evaluated_at: datetime
    decision: Decision
    certified_inputs: tuple[CertifiedInputEvidence, ...]


@dataclass(frozen=True, slots=True)
class TerminalSerialization:
    kind: Literal["effect-commit", "denial-record"]
    authorization_basis: str
    provider_atomic: bool
    recorded_at: datetime
    evaluation_phase: Literal["admission", "resolution"] | None = None
    evaluation_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class HumanResolution:
    approved: bool
    evidence: dict[str, JsonValue]
    actor_id: str | None = None
    resolved_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class AutomaticExpiry:
    """A policy-configured approval deadline elapsed without human resolution."""

    expires_at: datetime
    reason: Literal["approval-window-expired"]


@dataclass(frozen=True, slots=True)
class ProtectedConnectorEvidence:
    connector_id: str
    evidence_id: str
    idempotency_key: str
    external_operation_id: str | None
    outcome: ProtectedConnectorOutcome
    observed_at: datetime
    payload: dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class ProtectedExecutionAuditEvent:
    sequence: int
    event_type: str
    from_status: ProtectedExecutionStatus | None
    to_status: ProtectedExecutionStatus
    worker_id: str | None
    fence_token: int | None
    recorded_at: datetime
    evidence: dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class ProtectedExecutionAudit:
    execution_id: str
    binding_digest: str
    binding: dict[str, JsonValue]
    binding_canonical_json: str
    status: ProtectedExecutionStatus
    entitlement_state: ProtectedEntitlementState
    dispatch_started: bool
    cancel_requested: bool
    external_operation_id: str | None
    lease_owner: str | None
    lease_fence_token: int | None
    lease_expires_at: datetime | None
    last_fence_token: int
    receipt: ProtectedConnectorEvidence | None
    result: dict[str, JsonValue]
    created_at: datetime
    updated_at: datetime
    events: tuple[ProtectedExecutionAuditEvent, ...]


@dataclass(frozen=True, slots=True)
class AuditRecord:
    operation_id: str
    status: ActionStatus
    request: AuditRequest
    policy: PolicyReceipt
    decision: AuditDecision | None
    view_reads: tuple[ViewRead, ...]
    authorization_evaluations: tuple[AuthorizationEvaluation, ...]
    terminal_serialization: TerminalSerialization | None
    effect: AppliedEffect | None
    recorded_at: datetime
    resolution_plan: PendingResolutionPlan | None = None
    reservation_safety_certificate_digest: str | None = None
    reservation_entitlement_digest: str | None = None
    human_resolution: HumanResolution | None = None
    automatic_expiry: AutomaticExpiry | None = None
    protected_execution: ProtectedExecutionAudit | None = None
    entitlement: AuditEntitlement | None = None
