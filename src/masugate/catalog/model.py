"""Typed, declarative policy-catalog records."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from masugate.contracts import ReservationViewKind
from masugate.language.ast import PolicyDefinition
from masugate.model import ConsistencyGuarantee, PendingResolutionPlan, TypeName


class PolicyLayer(StrEnum):
    PLATFORM_SAFETY = "platform-safety"
    DEPLOYMENT_REGULATORY = "deployment-regulatory"
    OWNER = "owner"


class BundleMode(StrEnum):
    MANDATORY = "mandatory"
    CONFIGURABLE = "configurable"


class PolicyDriver(StrEnum):
    """The governance purpose a packaged policy is intended to serve."""

    ADVERSARIAL = "adversarial"
    CUSTOMER_INTENT = "customer-intent"
    REFERENCE_REGULATORY = "reference-regulatory"


class PolicyEnforcementKind(StrEnum):
    """Whether a cataloged driver policy has a runnable effect path."""

    EXECUTABLE = "executable"
    GAP = "gap"


class ResolutionKind(StrEnum):
    PROVIDER = "provider"
    GAP = "gap"


@dataclass(frozen=True)
class RequirementResolution:
    kind: ResolutionKind
    capability: str | None = None
    gap_id: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class EffectRequirement:
    action: str
    argument_types: Mapping[str, TypeName]
    owner: str
    required_guarantee: ConsistencyGuarantee
    consumable_arg: str | None
    resolution: RequirementResolution


@dataclass(frozen=True)
class ViewRequirement:
    name: str
    argument_types: tuple[TypeName, ...]
    return_type: TypeName
    owner: str
    consistency: str
    max_latency_ms: int
    bounded: bool
    reservation_kind: ReservationViewKind
    resolution: RequirementResolution


@dataclass(frozen=True)
class CertifiedInputRequirement:
    name: str
    value_type: TypeName
    resolution: RequirementResolution


@dataclass(frozen=True)
class PolicyLimitation:
    class_name: str
    statement: str


@dataclass(frozen=True)
class PolicyEnforcement:
    """A fail-closed execution declaration for a driver-specific policy."""

    kind: PolicyEnforcementKind
    gap_id: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class PolicyGovernance:
    """Runtime-bound traceability declared by a driver-specific catalog policy.

    ``limitations`` retain the source boundary in prose; this record carries
    the machine-checkable effect-domain, provider/connector, and pending-plan
    assertions which must agree with the assembled deployment.
    """

    driver: PolicyDriver
    coordination_domain: str
    provider_owner: str
    connector_id: str | None
    pending_plan: PendingResolutionPlan
    enforcement: PolicyEnforcement
    out_of_scope_classes: tuple[str, ...]


@dataclass(frozen=True)
class LoadedPolicy:
    policy_id: str
    version: str
    source: str
    semantic_sha256: str
    action: str
    required_views: tuple[str, ...]
    certified_inputs: tuple[str, ...]
    limitations: tuple[PolicyLimitation, ...]
    governance: PolicyGovernance | None
    definition: PolicyDefinition
    source_text: str


@dataclass(frozen=True)
class PolicyBundle:
    schema_version: int
    bundle_id: str
    version: str
    layer: PolicyLayer
    mode: BundleMode
    principal_attributes: Mapping[str, TypeName]
    effects: tuple[EffectRequirement, ...]
    views: tuple[ViewRequirement, ...]
    certified_inputs: tuple[CertifiedInputRequirement, ...]
    policies: tuple[LoadedPolicy, ...]
    digest: str
    root: Path


@dataclass(frozen=True)
class PolicyCatalog:
    bundles: tuple[PolicyBundle, ...]

    @property
    def policies(self) -> tuple[LoadedPolicy, ...]:
        return tuple(policy for bundle in self.bundles for policy in bundle.policies)
