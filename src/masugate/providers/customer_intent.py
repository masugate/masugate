"""Bounded, owner-configured intent views for the reference action catalog."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import cast

from masugate.contracts import (
    GovernanceViewContract,
    ProviderIdentity,
    ReservationViewKind,
    ResourceSession,
)
from masugate.errors import ContractError
from masugate.model import Duration, JsonValue, Scalar, TypeName
from masugate.provider_assembly import CoordinationDomain, ProviderModule

_MODULE_ID = "customer-intent"
_IMPLEMENTATION_VERSION = "masugate.customer-intent-v1"
_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$", re.ASCII)
_ACTION = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$", re.ASCII)


def _identity(value: object, field_name: str) -> str:
    if type(value) is not str or _IDENTITY.fullmatch(value) is None:
        raise ValueError(f"customer intent {field_name} must be a canonical identity")
    return value


def _action(value: object, field_name: str) -> str:
    if type(value) is not str or _ACTION.fullmatch(value) is None:
        raise ValueError(f"customer intent {field_name} must be a canonical action")
    return value


def _target(value: object, field_name: str) -> str:
    if type(value) is not str or not value or len(value) > 1_024 or "\n" in value:
        raise ValueError(f"customer intent {field_name} must be a bounded target string")
    return value


def _digest(value: JsonValue) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CustomerIntentPolicy:
    """Closed owner overrides for capability, target allowlist, and ask-first.

    The defaults are explicit owner configuration, not ambient deployment
    behavior.  Per-principal/action and per-target entries override them and
    are content-bound into the provider identity.
    """

    context_id: str
    configuration_version: str
    default_action_permitted: bool = True
    default_target_permitted: bool = True
    default_approval_required: bool = False
    action_permissions: tuple[tuple[str, str, bool], ...] = ()
    target_permissions: tuple[tuple[str, str, str, bool], ...] = ()
    approval_requirements: tuple[tuple[str, str, bool], ...] = ()

    def __post_init__(self) -> None:
        _identity(self.context_id, "context_id")
        _identity(self.configuration_version, "configuration_version")
        for name in (
            "default_action_permitted",
            "default_target_permitted",
            "default_approval_required",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"customer intent {name} must be bool")
        actions = tuple(
            (_identity(principal, "action principal"), _action(action, "action"), permitted)
            for principal, action, permitted in self.action_permissions
        )
        approvals = tuple(
            (
                _identity(principal, "approval principal"),
                _action(action, "approval action"),
                required,
            )
            for principal, action, required in self.approval_requirements
        )
        targets = tuple(
            (
                _identity(principal, "target principal"),
                _action(action, "target action"),
                _target(target, "target"),
                permitted,
            )
            for principal, action, target, permitted in self.target_permissions
        )
        if actions != tuple(sorted(actions, key=lambda item: item[:2])) or len(
            {item[:2] for item in actions}
        ) != len(actions):
            raise ValueError("customer intent action_permissions must be sorted and unique")
        if approvals != tuple(sorted(approvals, key=lambda item: item[:2])) or len(
            {item[:2] for item in approvals}
        ) != len(approvals):
            raise ValueError("customer intent approval_requirements must be sorted and unique")
        if targets != tuple(sorted(targets, key=lambda item: item[:3])) or len(
            {item[:3] for item in targets}
        ) != len(targets):
            raise ValueError("customer intent target_permissions must be sorted and unique")
        if any(type(item[-1]) is not bool for item in (*actions, *approvals, *targets)):
            raise TypeError("customer intent configured values must be bool")
        object.__setattr__(self, "action_permissions", actions)
        object.__setattr__(self, "approval_requirements", approvals)
        object.__setattr__(self, "target_permissions", targets)

    @property
    def payload(self) -> dict[str, JsonValue]:
        return {
            "action_permissions": [list(item) for item in self.action_permissions],
            "approval_requirements": [list(item) for item in self.approval_requirements],
            "configuration_version": self.configuration_version,
            "context_id": self.context_id,
            "default_action_permitted": self.default_action_permitted,
            "default_approval_required": self.default_approval_required,
            "default_target_permitted": self.default_target_permitted,
            "schema": "masugate.customer-intent.v1",
            "target_permissions": [list(item) for item in self.target_permissions],
        }

    @property
    def digest(self) -> str:
        return _digest(self.payload)

    @property
    def provider_identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="masugate.customer-intent",
            implementation_version=_IMPLEMENTATION_VERSION,
            configuration_version=self.digest,
        )

    def action_permitted(self, principal: object, action: object) -> bool:
        key = (_identity(principal, "action principal"), _action(action, "action"))
        return dict((item[:2], item[2]) for item in self.action_permissions).get(
            key, self.default_action_permitted
        )

    def target_permitted(self, principal: object, action: object, target: object) -> bool:
        key = (
            _identity(principal, "target principal"),
            _action(action, "target action"),
            _target(target, "target"),
        )
        return dict((item[:3], item[3]) for item in self.target_permissions).get(
            key, self.default_target_permitted
        )

    def approval_required(self, principal: object, action: object) -> bool:
        key = (_identity(principal, "approval principal"), _action(action, "approval action"))
        return dict((item[:2], item[2]) for item in self.approval_requirements).get(
            key, self.default_approval_required
        )


@dataclass(frozen=True)
class CustomerIntentProvider:
    """Expose typed owner configuration only inside the shared provider domain."""

    policy: CustomerIntentPolicy
    domain: CoordinationDomain

    def __post_init__(self) -> None:
        if type(self.policy) is not CustomerIntentPolicy:
            raise TypeError("customer intent provider needs CustomerIntentPolicy")
        if type(self.domain) is not CoordinationDomain:
            raise TypeError("customer intent provider needs CoordinationDomain")

    def provider_module(self) -> ProviderModule:
        version = int(self.policy.digest[:15], 16)

        def _arguments(arguments: tuple[Scalar | Duration, ...], expected: int) -> tuple[str, ...]:
            if len(arguments) != expected or any(type(item) is not str for item in arguments):
                raise ContractError("customer intent views require canonical string arguments")
            return tuple(cast(str, item) for item in arguments)

        def action_scope(arguments: tuple[Scalar | Duration, ...]) -> str:
            principal, action = _arguments(arguments, 2)
            return f"customer-intent:{self.policy.context_id}:{principal}:{action}"

        def target_scope(arguments: tuple[Scalar | Duration, ...]) -> str:
            principal, action, target = _arguments(arguments, 3)
            target_digest = hashlib.sha256(target.encode("utf-8")).hexdigest()
            return f"customer-intent:{self.policy.context_id}:{principal}:{action}:{target_digest}"

        def action_permitted(
            session: ResourceSession, arguments: tuple[Scalar | Duration, ...], scope: str
        ) -> tuple[Scalar, int]:
            del session, scope
            principal, action = _arguments(arguments, 2)
            return self.policy.action_permitted(principal, action), version

        def approval_required(
            session: ResourceSession, arguments: tuple[Scalar | Duration, ...], scope: str
        ) -> tuple[Scalar, int]:
            del session, scope
            principal, action = _arguments(arguments, 2)
            return self.policy.approval_required(principal, action), version

        def target_permitted(
            session: ResourceSession, arguments: tuple[Scalar | Duration, ...], scope: str
        ) -> tuple[Scalar, int]:
            del session, scope
            principal, action, target = _arguments(arguments, 3)
            return self.policy.target_permitted(principal, action, target), version

        identity = self.policy.provider_identity
        views = (
            GovernanceViewContract(
                name="owner.action_permitted",
                argument_types=(TypeName.STRING, TypeName.STRING),
                return_type=TypeName.BOOL,
                owner=_MODULE_ID,
                consistency="owner-configuration-v1",
                max_latency_ms=100,
                bounded=True,
                scope_resolver=action_scope,
                resolver=action_permitted,
                reservation_kind=ReservationViewKind.UNSUPPORTED,
                provider_identity=identity,
            ),
            GovernanceViewContract(
                name="owner.approval_required",
                argument_types=(TypeName.STRING, TypeName.STRING),
                return_type=TypeName.BOOL,
                owner=_MODULE_ID,
                consistency="owner-configuration-v1",
                max_latency_ms=100,
                bounded=True,
                scope_resolver=action_scope,
                resolver=approval_required,
                reservation_kind=ReservationViewKind.UNSUPPORTED,
                provider_identity=identity,
            ),
            GovernanceViewContract(
                name="owner.target_permitted",
                argument_types=(TypeName.STRING, TypeName.STRING, TypeName.STRING),
                return_type=TypeName.BOOL,
                owner=_MODULE_ID,
                consistency="owner-configuration-v1",
                max_latency_ms=100,
                bounded=True,
                scope_resolver=target_scope,
                resolver=target_permitted,
                reservation_kind=ReservationViewKind.UNSUPPORTED,
                provider_identity=identity,
            ),
        )
        return ProviderModule(
            module_id=_MODULE_ID,
            identity=identity,
            domain=self.domain,
            scope_derivation_id=self.domain.scope_derivation_id,
            views=views,
        )
