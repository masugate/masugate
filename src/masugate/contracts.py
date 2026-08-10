"""Trusted contracts connecting policies to authoritative resources."""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol

from masugate.errors import ContractError
from masugate.model import (
    ActionRequest,
    CertifiedInputStability,
    CertifiedInputStabilityProof,
    ConsistencyGuarantee,
    Duration,
    JsonValue,
    ResourceFootprint,
    Scalar,
    TypeName,
)


class ResourceSession(Protocol):
    """Marker protocol for a resource-owned transaction/session."""


ViewResolver = Callable[
    [ResourceSession, tuple[Scalar | Duration, ...], str],
    "tuple[Scalar, int] | Awaitable[tuple[Scalar, int]]",
]
ScopeResolver = Callable[[tuple[Scalar | Duration, ...]], str]
EffectExecutor = Callable[
    [ResourceSession, ActionRequest],
    "dict[str, JsonValue] | Awaitable[dict[str, JsonValue]]",
]
EffectFootprintResolver = Callable[[ActionRequest], ResourceFootprint]


_CERTIFIED_INPUT_NAME = re.compile(
    r"^certified\.[A-Za-z_][A-Za-z0-9_]*$",
    re.ASCII,
)


def _canonical_identity(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 255
        and value.strip() == value
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    )


def _aware_datetime(value: object) -> bool:
    return type(value) is datetime and value.tzinfo is not None and value.utcoffset() is not None


def _supported_certified_value(value: object) -> bool:
    return type(value) in {bool, int, str, Duration} and (
        type(value) is not Duration or type(value.seconds) is int
    )


@dataclass(frozen=True)
class ProviderIdentity:
    """Versioned implementation/configuration identity for provider contracts."""

    provider_id: str
    implementation_version: str
    configuration_version: str

    def __post_init__(self) -> None:
        for field_name in (
            "provider_id",
            "implementation_version",
            "configuration_version",
        ):
            if not _canonical_identity(getattr(self, field_name)):
                raise ValueError(f"provider identity {field_name} must be canonical")


@dataclass(frozen=True)
class CertifiedInputObservation:
    """A source observation before the trusted server packages provenance."""

    value: Scalar | Duration
    source_version: str
    observed_at: datetime

    def __post_init__(self) -> None:
        if not _supported_certified_value(self.value):
            raise TypeError("certified input observation has an unsupported value")
        if not _canonical_identity(self.source_version):
            raise ValueError("source_version must be a canonical identity")
        if not _aware_datetime(self.observed_at):
            raise ValueError("observed_at must be timezone-aware")


CertifiedInputResolver = Callable[
    [ResourceSession, ActionRequest, datetime],
    "CertifiedInputObservation | Awaitable[CertifiedInputObservation]",
]


@dataclass(frozen=True)
class CertifiedInputContract:
    """Trusted resolver and versioned semantics for one ``certified.*`` fact."""

    name: str
    value_type: TypeName
    stability: CertifiedInputStability
    stability_proof: CertifiedInputStabilityProof | None
    source_id: str
    contract_version: str
    freshness_ttl: Duration
    resolver: CertifiedInputResolver
    provider_identity: ProviderIdentity | None = None
    expected_source_version: str | None = None

    def __post_init__(self) -> None:
        if (
            type(self.name) is not str
            or len(self.name) > 255
            or _CERTIFIED_INPUT_NAME.fullmatch(self.name) is None
        ):
            raise ValueError("certified input name must be a flat certified.<name> path")
        if type(self.value_type) is not TypeName:
            raise TypeError("certified input value_type must be a TypeName")
        if type(self.stability) is not CertifiedInputStability:
            raise TypeError("stability must be a CertifiedInputStability")
        if self.stability is CertifiedInputStability.ADMISSION_STABLE:
            if type(self.stability_proof) is not CertifiedInputStabilityProof:
                raise TypeError("admission-stable certified input requires a stability proof")
        elif self.stability_proof is not None:
            raise ValueError("resolution-volatile certified input cannot carry a stability proof")
        for field_name in ("source_id", "contract_version"):
            if not _canonical_identity(getattr(self, field_name)):
                raise ValueError(f"{field_name} must be a canonical identity")
        if self.expected_source_version is not None and not _canonical_identity(
            self.expected_source_version
        ):
            raise ValueError("expected_source_version must be a canonical identity")
        if (
            type(self.freshness_ttl) is not Duration
            or type(self.freshness_ttl.seconds) is not int
            or self.freshness_ttl.seconds <= 0
        ):
            raise ValueError("freshness_ttl must be a positive Duration")
        if not callable(self.resolver):
            raise TypeError("certified input resolver must be callable")


class ReservationViewKind(StrEnum):
    UNSUPPORTED = "unsupported"
    COMMIT_GUARDED = "commit-guarded"
    CONSUMED_CAPACITY = "consumed-capacity"
    AVAILABLE_CAPACITY = "available-capacity"


def _literal_matches_type(value: Scalar | Duration, expected: TypeName) -> bool:
    """Return whether a proof literal has the contract's exact scalar type."""

    if expected is TypeName.BOOL:
        return type(value) is bool
    if expected is TypeName.INT:
        return type(value) is int
    if expected is TypeName.STRING:
        return type(value) is str
    if expected is TypeName.DURATION:
        return type(value) is Duration
    return False


@dataclass(frozen=True)
class ReservationCapability:
    """Versioned provider identity for one concrete reservation algorithm.

    The strings are durable attestations by the trusted provider boundary.
    ``effect_executor`` is the live provider-owned callable: admission checks
    its exact function/owner identity against the registered effect so an
    unrelated executor cannot borrow a matching version label. Changing
    implementation, capacity configuration, scope semantics, or consumable
    mapping requires changing the corresponding identity, which invalidates
    outstanding policy certificates.
    """

    action: str
    reservation_proof: str
    implementation_version: str
    configuration_version: str
    scope_scheme: str
    consumable_arg: str
    effect_implementation_version: str
    effect_executor: EffectExecutor
    effect_atomic_with_reservation: bool
    effect_idempotent: bool

    def __post_init__(self) -> None:
        for field_name in (
            "action",
            "reservation_proof",
            "implementation_version",
            "configuration_version",
            "scope_scheme",
            "consumable_arg",
            "effect_implementation_version",
        ):
            value = getattr(self, field_name)
            if not value or value.strip() != value:
                raise ValueError(f"{field_name} must be a non-empty canonical string")
        for field_name in (
            "effect_atomic_with_reservation",
            "effect_idempotent",
        ):
            if type(getattr(self, field_name)) is not bool:
                raise TypeError(f"{field_name} must be a bool")
        if not callable(self.effect_executor):
            raise TypeError("effect_executor must be callable")


@dataclass(frozen=True)
class GovernanceViewContract:
    name: str
    argument_types: tuple[TypeName, ...]
    return_type: TypeName
    owner: str
    consistency: str
    max_latency_ms: int
    bounded: bool
    scope_resolver: ScopeResolver
    resolver: ViewResolver
    reservation_kind: ReservationViewKind = ReservationViewKind.UNSUPPORTED
    # Provider-defined proof-family identifier. Reservation admission accepts a
    # capacity view only when this non-empty id exactly matches the governed
    # effect's id, binding the syntactic proof to one provider escrow contract.
    reservation_proof: str | None = None
    # Immutable literal arguments that a reservation proof requires at the
    # corresponding call positions.  A provider whose escrow implements one
    # fixed window, for example, can bind argument 1 to ``Duration(24h)`` so a
    # syntactically monotone policy using another window cannot borrow that
    # escrow proof.
    reservation_literal_constraints: Mapping[int, Scalar | Duration] = field(default_factory=dict)
    provider_identity: ProviderIdentity | None = None

    def __post_init__(self) -> None:
        # Proof premises must not remain aliased to a caller-owned mutable map.
        object.__setattr__(
            self,
            "reservation_literal_constraints",
            MappingProxyType(dict(self.reservation_literal_constraints)),
        )


@dataclass(frozen=True)
class EffectContract:
    action: str
    argument_types: Mapping[str, TypeName]
    owner: str
    required_guarantee: ConsistencyGuarantee
    footprint_resolver: EffectFootprintResolver
    executor: EffectExecutor
    # Name of the action argument reservation mode escrows (the "consumable").
    # None means the effect declares no consumable; reservation eligibility for
    # amount-vs-capacity comparisons then cannot match (see ReservationEligibilityChecker).
    consumable_arg: str | None = None
    # Must match every capacity view used by a reservation-eligible policy.
    reservation_proof: str | None = None
    # Provider-owned implementation identity for the effect that is atomic with
    # reservation consumption. Admission matches this against the reservation
    # capability so a separately registered executor cannot borrow its escrow.
    reservation_effect_implementation: str | None = None
    provider_identity: ProviderIdentity | None = None

    def __post_init__(self) -> None:
        # ``frozen=True`` does not recursively freeze a caller-owned dict. The
        # exact action schema participates in reservation admission, so retain a
        # detached read-only snapshot rather than a mutable alias.
        object.__setattr__(
            self,
            "argument_types",
            MappingProxyType(dict(self.argument_types)),
        )


class ContractRegistry:
    def __init__(self) -> None:
        self._views: dict[str, GovernanceViewContract] = {}
        self._effects: dict[str, EffectContract] = {}
        self._certified_inputs: dict[str, CertifiedInputContract] = {}

    def register_certified_input(self, contract: CertifiedInputContract) -> None:
        if contract.name in self._certified_inputs:
            raise ContractError(f"certified input already registered: {contract.name}")
        if (
            contract.provider_identity is not None
            and type(contract.provider_identity) is not ProviderIdentity
        ):
            raise ContractError(f"certified input provider identity is malformed: {contract.name}")
        self._certified_inputs[contract.name] = contract

    def register_view(self, contract: GovernanceViewContract) -> None:
        if contract.name in self._views:
            raise ContractError(f"view already registered: {contract.name}")
        if not contract.bounded:
            raise ContractError(f"policy-callable view must be bounded: {contract.name}")
        if (
            contract.provider_identity is not None
            and type(contract.provider_identity) is not ProviderIdentity
        ):
            raise ContractError(f"view provider identity is malformed: {contract.name}")
        if contract.reservation_proof is not None and not contract.reservation_proof.strip():
            raise ContractError(f"reservation_proof must be non-empty: {contract.name}")
        if (
            contract.reservation_kind
            in {
                ReservationViewKind.AVAILABLE_CAPACITY,
                ReservationViewKind.CONSUMED_CAPACITY,
            }
            and contract.return_type is not TypeName.INT
        ):
            raise ContractError(f"reservation capacity view must return Int: {contract.name}")
        for argument_index, literal in contract.reservation_literal_constraints.items():
            if type(argument_index) is not int or not (
                0 <= argument_index < len(contract.argument_types)
            ):
                raise ContractError(
                    "reservation literal constraint index is out of range: "
                    f"{contract.name}[{argument_index!r}]"
                )
            expected_type = contract.argument_types[argument_index]
            if not _literal_matches_type(literal, expected_type):
                raise ContractError(
                    "reservation literal constraint type does not match argument: "
                    f"{contract.name}[{argument_index}] expects {expected_type.value}"
                )
        self._views[contract.name] = contract

    def register_effect(self, contract: EffectContract) -> None:
        if contract.action in self._effects:
            raise ContractError(f"effect already registered: {contract.action}")
        if (
            contract.provider_identity is not None
            and type(contract.provider_identity) is not ProviderIdentity
        ):
            raise ContractError(f"effect provider identity is malformed: {contract.action}")
        if contract.reservation_proof is not None and not contract.reservation_proof.strip():
            raise ContractError(f"reservation_proof must be non-empty: {contract.action}")
        if contract.reservation_effect_implementation is not None and (
            not contract.reservation_effect_implementation
            or contract.reservation_effect_implementation.strip()
            != contract.reservation_effect_implementation
        ):
            raise ContractError(
                f"reservation_effect_implementation must be canonical: {contract.action}"
            )
        if (contract.reservation_proof is None) != (
            contract.reservation_effect_implementation is None
        ):
            raise ContractError(
                "reservation_proof and reservation_effect_implementation "
                f"must be declared together: {contract.action}"
            )
        if contract.consumable_arg is not None and (
            contract.argument_types.get(contract.consumable_arg) is not TypeName.INT
        ):
            raise ContractError(f"consumable_arg must name an Int argument: {contract.action}")
        self._effects[contract.action] = contract

    def view(self, name: str) -> GovernanceViewContract:
        try:
            return self._views[name]
        except KeyError as exc:
            raise ContractError(f"unregistered governance view: {name}") from exc

    def certified_input(self, name: str) -> CertifiedInputContract:
        try:
            return self._certified_inputs[name]
        except KeyError as exc:
            raise ContractError(f"unregistered certified input: {name}") from exc

    def effect(self, action: str) -> EffectContract:
        try:
            return self._effects[action]
        except KeyError as exc:
            raise ContractError(f"unregistered governed effect: {action}") from exc

    def has_effect(self, action: str) -> bool:
        return action in self._effects

    def views(self) -> tuple[GovernanceViewContract, ...]:
        """Return a deterministic snapshot for trusted provider assembly."""

        return tuple(self._views[name] for name in sorted(self._views))

    def effects(self) -> tuple[EffectContract, ...]:
        """Return a deterministic snapshot for trusted provider assembly."""

        return tuple(self._effects[action] for action in sorted(self._effects))

    def certified_inputs(self) -> tuple[CertifiedInputContract, ...]:
        """Return a deterministic snapshot for trusted provider assembly."""

        return tuple(self._certified_inputs[name] for name in sorted(self._certified_inputs))
