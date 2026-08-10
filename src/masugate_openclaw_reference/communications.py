"""communications provider reference composition for communications and approval facts.

This deployment-layer object wires framework-neutral provider modules into the
same concrete spend coordination domain. It does not import or trust OpenClaw
approval presentation state, and it does not implement a message connector.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path

from masugate.catalog import PolicyCatalog, load_bundle
from masugate.language import PolicyCompiler, compiled_policy_version
from masugate.model import PolicyProvenance
from masugate.policy import PolicyRuntime, PolicySet
from masugate.provider_assembly import ProviderAssembly, assemble_provider_domain
from masugate.providers.communications import (
    ApprovalStateProvider,
    CommunicationsPolicy,
    CommunicationsProvider,
    PolicyApprovalState,
)
from masugate.providers.spend import SpendPurchaseService
from masugate_openclaw_reference.deployment import reference_spend_catalog


def reference_communications_catalog() -> PolicyCatalog:
    """Load mandatory reference contracts for logical communications actions."""

    root = Path(str(files("masugate.catalog").joinpath("reference_communications")))
    return PolicyCatalog(bundles=(load_bundle(root),))


def reference_communications_operational_catalog() -> PolicyCatalog:
    """Return the spend plus communications reference composition catalog."""

    return PolicyCatalog(
        bundles=reference_spend_catalog().bundles + reference_communications_catalog().bundles
    )


@dataclass
class ReferenceCommunicationsResource:
    """Mount communications and approval facts in the spend resource domain."""

    service: SpendPurchaseService
    communications_policy: CommunicationsPolicy
    approval_state: PolicyApprovalState
    _communications: CommunicationsProvider = field(init=False, repr=False)
    _approval: ApprovalStateProvider = field(init=False, repr=False)
    _catalog: PolicyCatalog = field(init=False, repr=False)
    _assembly: ProviderAssembly = field(init=False, repr=False)

    def __post_init__(self) -> None:
        spend_module = self.service.provider_module()
        self._communications = CommunicationsProvider(
            self.communications_policy,
            spend_module.domain,
        )
        self._approval = ApprovalStateProvider(self.approval_state, spend_module.domain)
        modules = (
            spend_module,
            self._communications.provider_module(),
            self._approval.provider_module(),
        )
        if any(module.domain is not spend_module.domain for module in modules):
            raise ValueError("communications modules must use the existing reference domain")

        self._catalog = reference_communications_operational_catalog()
        self.service.bind_catalog_policy(self._catalog)
        self._assembly = assemble_provider_domain(self._catalog, modules)

        policies = PolicySet()
        for bundle in self._catalog.bundles:
            compiler = PolicyCompiler(
                self._assembly.registry,
                principal_attributes=dict(bundle.principal_attributes),
            )
            for loaded in bundle.policies:
                compiled = compiler.compile(loaded.definition)
                policies.add(
                    compiled,
                    provenance=PolicyProvenance(
                        policy_id=loaded.policy_id,
                        policy_declared_version=loaded.version,
                        policy_runtime_version=compiled_policy_version(compiled),
                        policy_digest=loaded.semantic_sha256,
                        bundle_id=bundle.bundle_id,
                        bundle_version=bundle.version,
                        bundle_digest=bundle.digest,
                        layer=bundle.layer.value,
                        mode=bundle.mode.value,
                    ),
                )
        self.service.bind_policy_runtime(PolicyRuntime(self._assembly.registry, policies))

    async def initialize(self) -> None:
        """Initialize the shared spend session and both communications modules."""

        await self.service.initialize()
        await self._communications.initialize()
        await self._approval.initialize()

    async def close(self) -> None:
        await self.service.close()

    @property
    def communications(self) -> CommunicationsProvider:
        return self._communications

    @property
    def approval(self) -> ApprovalStateProvider:
        return self._approval

    @property
    def catalog(self) -> PolicyCatalog:
        return self._catalog

    @property
    def assembly(self) -> ProviderAssembly:
        return self._assembly


__all__ = [
    "ReferenceCommunicationsResource",
    "reference_communications_catalog",
    "reference_communications_operational_catalog",
]
