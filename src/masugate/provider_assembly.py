"""Fail-closed provider-module assembly inside one atomic coordination domain.

Catalog declarations are intentionally provider-independent.  This module is
the production boundary that binds those declarations to concrete runtime
contracts without pretending that independent resources form one transaction.
Every module in an assembly shares the same ``CoordinationDomain`` object and,
therefore, the same resource-owned ``ResourceSession`` factory.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from masugate.protected_execution.model import ProtectedExecutionAuthority
    from masugate.protected_execution.runner import ProtectedExecutionRunner

from masugate.catalog.model import (
    CertifiedInputRequirement,
    EffectRequirement,
    LoadedPolicy,
    PolicyCatalog,
    PolicyEnforcementKind,
    ViewRequirement,
)
from masugate.contracts import (
    CertifiedInputContract,
    ContractRegistry,
    EffectContract,
    GovernanceViewContract,
    ProviderIdentity,
    ResourceSession,
)
from masugate.errors import ContractError
from masugate.model import ActionRequest, JsonValue, PendingResolutionPlan

_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$", re.ASCII)


def _identity(value: object, field_name: str) -> str:
    if type(value) is not str or _IDENTITY.fullmatch(value) is None:
        raise ContractError(f"provider assembly {field_name} must be a canonical identity")
    return value


class EffectExecutionPosition(StrEnum):
    """The only two legal effect positions in a composed provider domain."""

    TRANSACTIONAL = "transactional"
    PROTECTED_EXTERNAL = "protected-external"


@dataclass(frozen=True)
class ProtectedExternalExecutor:
    """Non-callable-in-practice marker for the protected-execution lifecycle.

    ``EffectContract`` remains compiler-compatible by requiring a callable.
    This marker is the only callable accepted for a protected external effect;
    invoking it directly fails closed. Protected execution consumes the binding
    through its durable intent/runner path instead.
    """

    connector_id: str

    def __post_init__(self) -> None:
        _identity(self.connector_id, "connector id")

    def __call__(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> dict[str, JsonValue]:
        del session, request
        raise ContractError(
            "protected external effects must execute through the durable connector lifecycle"
        )


@dataclass(frozen=True, eq=False)
class CoordinationDomain:
    """One concrete atomic resource boundary shared by provider modules.

    Identity of the object is load-bearing: constructing a second object with
    the same strings cannot make two independent resources one transaction.
    """

    domain_id: str
    configuration_id: str
    scope_derivation_id: str
    resource: object

    def __post_init__(self) -> None:
        _identity(self.domain_id, "coordination-domain id")
        _identity(self.configuration_id, "coordination-domain configuration id")
        _identity(self.scope_derivation_id, "scope-derivation id")
        if self.resource is None:
            raise ContractError("provider assembly coordination domain needs a resource")
        if not callable(getattr(self.resource, "open_session", None)):
            raise ContractError(
                "provider assembly coordination-domain resource must own ResourceSession creation"
            )


@dataclass(frozen=True)
class EffectBinding:
    """One effect contract and its only legal execution position."""

    contract: EffectContract
    position: EffectExecutionPosition
    connector_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.contract) is not EffectContract:
            raise ContractError("provider effect binding has a malformed contract")
        if type(self.position) is not EffectExecutionPosition:
            raise ContractError(f"effect {self.contract.action!r} has an invalid position")
        if self.position is EffectExecutionPosition.TRANSACTIONAL:
            if self.connector_id is not None:
                raise ContractError(
                    f"transactional effect {self.contract.action!r} cannot name a connector"
                )
            if isinstance(self.contract.executor, ProtectedExternalExecutor):
                raise ContractError(
                    f"protected external effect {self.contract.action!r} cannot be transactional"
                )
            return
        connector_id = _identity(self.connector_id, "connector id")
        if not isinstance(self.contract.executor, ProtectedExternalExecutor):
            raise ContractError(
                f"protected external effect {self.contract.action!r} bypasses the durable "
                "connector lifecycle"
            )
        if self.contract.executor.connector_id != connector_id:
            raise ContractError(
                f"protected external effect {self.contract.action!r} has conflicting connector ids"
            )


@dataclass(frozen=True)
class ProtectedExecutionRegistration:
    """Concrete durable runner registered for one protected external action.

    A non-callable :class:`ProtectedExternalExecutor` is only a compiler and
    assembly marker.  This registration is the runtime evidence that the
    deployment has installed the protected-execution intent/dispatch/query
    lifecycle for the exact assembled action.
    """

    action: str
    runner: ProtectedExecutionRunner

    def __post_init__(self) -> None:
        _identity(self.action, "protected runner action")
        from masugate.protected_execution.runner import ProtectedExecutionRunner

        if not isinstance(self.runner, ProtectedExecutionRunner):
            raise ContractError(
                f"protected action {self.action!r} must register a ProtectedExecutionRunner"
            )
        capabilities = self.runner.connector.capabilities
        if not capabilities.idempotent_dispatch or not capabilities.status_query:
            raise ContractError(
                f"protected action {self.action!r} connector must support idempotent "
                "dispatch and status query"
            )


@dataclass(frozen=True)
class ProviderModule:
    """Concrete runtime contracts owned by one versioned provider module."""

    module_id: str
    identity: ProviderIdentity
    domain: CoordinationDomain
    scope_derivation_id: str
    views: tuple[GovernanceViewContract, ...] = ()
    effects: tuple[EffectBinding, ...] = ()
    certified_inputs: tuple[CertifiedInputContract, ...] = ()
    protected_executions: tuple[ProtectedExecutionRegistration, ...] = ()

    def __post_init__(self) -> None:
        _identity(self.module_id, "module id")
        if type(self.identity) is not ProviderIdentity:
            raise ContractError(f"provider module {self.module_id!r} has malformed identity")
        if type(self.domain) is not CoordinationDomain:
            raise ContractError(f"provider module {self.module_id!r} has malformed domain")
        scope_derivation_id = _identity(self.scope_derivation_id, "scope-derivation id")
        if scope_derivation_id != self.domain.scope_derivation_id:
            raise ContractError(
                f"provider module {self.module_id!r} has mismatched scope derivation"
            )
        for view_contract in self.views:
            if view_contract.owner != self.module_id:
                raise ContractError(
                    f"runtime contract {view_contract.name!r} "
                    f"has owner {view_contract.owner!r}, expected module {self.module_id!r}"
                )
            if view_contract.provider_identity != self.identity:
                raise ContractError(
                    f"runtime contract {view_contract.name!r} "
                    "does not bind the module provider identity"
                )
        for effect_binding in self.effects:
            effect_contract = effect_binding.contract
            if effect_contract.owner != self.module_id:
                raise ContractError(
                    f"runtime contract {effect_contract.action!r} "
                    f"has owner {effect_contract.owner!r}, expected module {self.module_id!r}"
                )
            if effect_contract.provider_identity != self.identity:
                raise ContractError(
                    f"runtime contract {effect_contract.action!r} "
                    "does not bind the module provider identity"
                )
        for certified_contract in self.certified_inputs:
            if certified_contract.provider_identity != self.identity:
                raise ContractError(
                    f"certified input {certified_contract.name!r} does not bind the module "
                    "provider identity"
                )
        effects_by_action = {binding.contract.action: binding for binding in self.effects}
        seen_registrations: set[str] = set()
        for registration in self.protected_executions:
            if type(registration) is not ProtectedExecutionRegistration:
                raise ContractError(
                    f"provider module {self.module_id!r} has a malformed protected registration"
                )
            if registration.action in seen_registrations:
                raise ContractError(
                    f"provider module {self.module_id!r} registers duplicate protected "
                    f"execution for {registration.action!r}"
                )
            seen_registrations.add(registration.action)
            binding = effects_by_action.get(registration.action)
            if (
                binding is None
                or binding.position is not EffectExecutionPosition.PROTECTED_EXTERNAL
            ):
                raise ContractError(
                    f"provider module {self.module_id!r} registers a runner for an action "
                    "without a protected-external effect"
                )
            authority = registration.runner.authority
            if (
                authority.action != registration.action
                or authority.provider_identity != self.identity
                or authority.coordination_domain_id != self.domain.domain_id
                or authority.connector_id != binding.connector_id
                or registration.runner.connector.connector_id != binding.connector_id
            ):
                raise ContractError(
                    f"provider module {self.module_id!r} protected runner authority does not "
                    f"match effect {registration.action!r}"
                )


@dataclass(frozen=True)
class ActionAssembly:
    """Resolved protected position for one governed action."""

    action: str
    effect_owner: str
    module_ids: tuple[str, ...]
    coordination_domain_id: str
    scope_derivation_id: str
    position: EffectExecutionPosition
    connector_id: str | None
    pending_plan: PendingResolutionPlan | None


@dataclass(frozen=True)
class ProviderAssembly:
    """Validated contracts and action positions for one domain."""

    domain: CoordinationDomain
    registry: ContractRegistry
    modules: tuple[ProviderModule, ...]
    actions: Mapping[str, ActionAssembly] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "actions", MappingProxyType(dict(self.actions)))

    def action(self, action: str) -> ActionAssembly:
        try:
            return self.actions[action]
        except KeyError as exc:
            raise ContractError(f"unassembled governed action: {action}") from exc

    def open_action_session(self, action: str) -> Any:
        """Open the action's one resource-owned protected transaction/session."""

        self.action(action)
        return self.domain.resource.open_session(write=True)  # type: ignore[attr-defined]

    def protected_execution_authority(self, action: str) -> ProtectedExecutionAuthority:
        """Return the trusted protected-execution authority for an action."""

        assembled = self.action(action)
        if assembled.position is not EffectExecutionPosition.PROTECTED_EXTERNAL:
            raise ContractError(f"action {action!r} is not a protected external effect")
        module = next(
            module for module in self.modules if module.module_id == assembled.effect_owner
        )
        # Local import avoids making the deployment-assembly primitive depend
        # on the protected-execution package at import time.
        from masugate.protected_execution.model import ProtectedExecutionAuthority

        assert assembled.connector_id is not None
        return ProtectedExecutionAuthority(
            action=action,
            provider_identity=module.identity,
            coordination_domain_id=assembled.coordination_domain_id,
            connector_id=assembled.connector_id,
        )

    def protected_execution_runner(self, action: str) -> ProtectedExecutionRunner:
        """Return the concrete installed runner for one executable action."""

        assembled = self.action(action)
        if assembled.position is not EffectExecutionPosition.PROTECTED_EXTERNAL:
            raise ContractError(f"action {action!r} is not a protected external effect")
        for module in self.modules:
            for registration in module.protected_executions:
                if registration.action == action:
                    return registration.runner
        raise ContractError(f"action {action!r} has no registered protected execution runner")


def _unique_requirements[T](
    values: Sequence[T],
    *,
    key: Callable[[T], str],
) -> dict[str, T]:
    result: dict[str, T] = {}
    for value in values:
        name = key(value)
        previous = result.setdefault(name, value)
        if previous != value:
            raise ContractError(f"catalog has conflicting declarations for {name!r}")
    return result


def _view_matches(requirement: ViewRequirement, contract: GovernanceViewContract) -> bool:
    return (
        requirement.name == contract.name
        and requirement.argument_types == contract.argument_types
        and requirement.return_type is contract.return_type
        and requirement.owner == contract.owner
        and requirement.consistency == contract.consistency
        and requirement.max_latency_ms == contract.max_latency_ms
        and requirement.bounded is contract.bounded
        and requirement.reservation_kind is contract.reservation_kind
    )


def _effect_matches(requirement: EffectRequirement, contract: EffectContract) -> bool:
    return (
        requirement.action == contract.action
        and dict(requirement.argument_types) == dict(contract.argument_types)
        and requirement.owner == contract.owner
        and requirement.required_guarantee is contract.required_guarantee
        and requirement.consumable_arg == contract.consumable_arg
    )


def _certified_matches(
    requirement: CertifiedInputRequirement,
    contract: CertifiedInputContract,
) -> bool:
    return requirement.name == contract.name and requirement.value_type is contract.value_type


def assemble_provider_domain(
    catalog: PolicyCatalog,
    modules: Sequence[ProviderModule],
) -> ProviderAssembly:
    """Bind a complete catalog to exactly one local atomic provider domain."""

    ordered = tuple(sorted(modules, key=lambda module: module.module_id))
    if not ordered:
        raise ContractError("provider assembly needs at least one module")
    module_by_id: dict[str, ProviderModule] = {}
    for module in ordered:
        if module.module_id in module_by_id:
            raise ContractError(f"duplicate provider module owner: {module.module_id}")
        module_by_id[module.module_id] = module

    domain = ordered[0].domain
    for module in ordered[1:]:
        if module.domain.domain_id != domain.domain_id:
            raise ContractError(
                f"provider modules span coordination domains {domain.domain_id!r} and "
                f"{module.domain.domain_id!r}"
            )
        if module.domain is not domain:
            raise ContractError(
                f"coordination domain {domain.domain_id!r} is represented by incompatible "
                "resource/configuration identities"
            )

    runtime_views: dict[str, tuple[ProviderModule, GovernanceViewContract]] = {}
    runtime_effects: dict[str, tuple[ProviderModule, EffectBinding]] = {}
    runtime_certified: dict[str, tuple[ProviderModule, CertifiedInputContract]] = {}
    registry = ContractRegistry()
    for module in ordered:
        for runtime_view in module.views:
            if runtime_view.name in runtime_views:
                raise ContractError(f"duplicate runtime view owner for {runtime_view.name!r}")
            runtime_views[runtime_view.name] = (module, runtime_view)
            registry.register_view(runtime_view)
        for binding in module.effects:
            action = binding.contract.action
            if action in runtime_effects:
                raise ContractError(f"duplicate runtime effect owner for {action!r}")
            runtime_effects[action] = (module, binding)
            registry.register_effect(binding.contract)
        for runtime_input in module.certified_inputs:
            if runtime_input.name in runtime_certified:
                raise ContractError(
                    f"duplicate runtime certified-input owner for {runtime_input.name!r}"
                )
            runtime_certified[runtime_input.name] = (module, runtime_input)
            registry.register_certified_input(runtime_input)

    effects = _unique_requirements(
        tuple(requirement for bundle in catalog.bundles for requirement in bundle.effects),
        key=lambda requirement: requirement.action,
    )
    views = _unique_requirements(
        tuple(requirement for bundle in catalog.bundles for requirement in bundle.views),
        key=lambda requirement: requirement.name,
    )
    certified = _unique_requirements(
        tuple(requirement for bundle in catalog.bundles for requirement in bundle.certified_inputs),
        key=lambda requirement: requirement.name,
    )

    if set(runtime_effects) != set(effects):
        missing = sorted(set(effects) - set(runtime_effects))
        extra = sorted(set(runtime_effects) - set(effects))
        raise ContractError(
            f"runtime effect ownership does not match catalog: missing={missing}, extra={extra}"
        )
    if set(runtime_views) != set(views):
        missing = sorted(set(views) - set(runtime_views))
        extra = sorted(set(runtime_views) - set(views))
        raise ContractError(
            f"runtime view ownership does not match catalog: missing={missing}, extra={extra}"
        )
    if set(runtime_certified) != set(certified):
        missing = sorted(set(certified) - set(runtime_certified))
        extra = sorted(set(runtime_certified) - set(certified))
        raise ContractError(
            "runtime certified-input ownership does not match catalog: "
            f"missing={missing}, extra={extra}"
        )

    for view_name, view_requirement in views.items():
        view_module, runtime_view = runtime_views[view_name]
        if view_requirement.owner != view_module.module_id or not _view_matches(
            view_requirement, runtime_view
        ):
            raise ContractError(
                f"runtime view {view_name!r} conflicts with its catalog declaration"
            )
    for effect_action, effect_requirement in effects.items():
        effect_module, effect_binding = runtime_effects[effect_action]
        if effect_requirement.owner != effect_module.module_id or not _effect_matches(
            effect_requirement, effect_binding.contract
        ):
            raise ContractError(
                f"runtime effect {effect_action!r} conflicts with its catalog declaration"
            )
    for input_name, input_requirement in certified.items():
        _, runtime_input = runtime_certified[input_name]
        if not _certified_matches(input_requirement, runtime_input):
            raise ContractError(
                f"runtime certified input {input_name!r} conflicts with its catalog declaration"
            )

    action_assemblies: dict[str, ActionAssembly] = {}
    policies_by_action: dict[str, list[LoadedPolicy]] = {}
    for policy in catalog.policies:
        policies_by_action.setdefault(policy.action, []).append(policy)
    for effect_action, effect_requirement in effects.items():
        effect_module, binding = runtime_effects[effect_action]
        protected_registration = next(
            (
                registration
                for registration in effect_module.protected_executions
                if registration.action == effect_action
            ),
            None,
        )
        action_modules = {effect_module.module_id}
        for policy in policies_by_action.get(effect_action, []):
            for view_name in policy.required_views:
                action_modules.add(runtime_views[view_name][0].module_id)
            for input_name in policy.certified_inputs:
                action_modules.add(runtime_certified[input_name][0].module_id)
        action_assemblies[effect_action] = ActionAssembly(
            action=effect_action,
            effect_owner=effect_requirement.owner,
            module_ids=tuple(sorted(action_modules)),
            coordination_domain_id=domain.domain_id,
            scope_derivation_id=domain.scope_derivation_id,
            position=binding.position,
            connector_id=binding.connector_id,
            pending_plan=_governance_pending_plan(
                policies_by_action.get(effect_action, ()),
                action=effect_action,
                domain_id=domain.domain_id,
                effect_owner=effect_requirement.owner,
                connector_id=binding.connector_id,
                position=binding.position,
                protected_runner_registered=protected_registration is not None,
            ),
        )

    return ProviderAssembly(
        domain=domain,
        registry=registry,
        modules=ordered,
        actions=action_assemblies,
    )


def _governance_pending_plan(
    policies: Sequence[LoadedPolicy],
    *,
    action: str,
    domain_id: str,
    effect_owner: str,
    connector_id: str | None,
    position: EffectExecutionPosition,
    protected_runner_registered: bool,
) -> PendingResolutionPlan | None:
    """Validate optional driver metadata against the concrete assembled action.

    A policy may be packaged before a protected connector exists, but it cannot
    claim a different provider, domain, or connector.  A single action also
    has one declared pending-resolution plan: all driver layers must agree on
    the safe path before an approval can later become an allow.
    """

    plans: set[PendingResolutionPlan] = set()
    for policy in policies:
        governance = policy.governance
        if governance is None:
            continue
        if governance.coordination_domain != domain_id:
            raise ContractError(
                f"policy {policy.policy_id!r} declares coordination domain "
                f"{governance.coordination_domain!r}, assembled domain is {domain_id!r}"
            )
        if governance.provider_owner != effect_owner:
            raise ContractError(
                f"policy {policy.policy_id!r} declares provider owner "
                f"{governance.provider_owner!r}, assembled owner is {effect_owner!r}"
            )
        if governance.connector_id != connector_id:
            raise ContractError(
                f"policy {policy.policy_id!r} declares connector "
                f"{governance.connector_id!r}, assembled connector is {connector_id!r}"
            )
        if governance.enforcement.kind is PolicyEnforcementKind.GAP:
            if position is not EffectExecutionPosition.PROTECTED_EXTERNAL:
                raise ContractError(
                    f"policy {policy.policy_id!r} declares an enforced gap for a "
                    "transactional action"
                )
            if protected_runner_registered:
                raise ContractError(
                    f"policy {policy.policy_id!r} declares a connector gap but action "
                    f"{action!r} has a registered protected execution runner"
                )
        elif (
            position is EffectExecutionPosition.PROTECTED_EXTERNAL
            and not protected_runner_registered
        ):
            raise ContractError(
                f"policy {policy.policy_id!r} declares executable enforcement but action "
                f"{action!r} has no registered protected execution runner"
            )
        plans.add(governance.pending_plan)
    if len(plans) > 1:
        raise ContractError(f"action {action!r} has conflicting driver pending-resolution plans")
    return next(iter(plans), None)


__all__ = [
    "ActionAssembly",
    "CoordinationDomain",
    "EffectBinding",
    "EffectExecutionPosition",
    "ProtectedExecutionRegistration",
    "ProtectedExternalExecutor",
    "ProviderAssembly",
    "ProviderModule",
    "assemble_provider_domain",
]
