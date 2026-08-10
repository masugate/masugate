"""workspace provider reference composition for framework-neutral workspace claims.

The object here is deployment wiring only.  The file/workspace provider itself
is in :mod:`masugate.providers.file_workspace` and has no OpenClaw import or
assumption.  This layer proves it is mounted in the exact existing spend
resource coordination domain rather than in a look-alike database transaction.
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
from masugate.providers.file_workspace import FileWorkspaceClaims, FileWorkspacePolicy
from masugate.providers.spend import SpendPurchaseService
from masugate_openclaw_reference.deployment import reference_spend_catalog


def reference_file_workspace_catalog() -> PolicyCatalog:
    """Load the mandatory reference contracts for logical filesystem actions."""

    root = Path(str(files("masugate.catalog").joinpath("reference_workspace")))
    return PolicyCatalog(bundles=(load_bundle(root),))


def reference_operational_catalog() -> PolicyCatalog:
    """Return the current spend + workspace deployment composition catalog."""

    return PolicyCatalog(
        bundles=reference_spend_catalog().bundles + reference_file_workspace_catalog().bundles
    )


@dataclass
class ReferenceFileWorkspaceResource:
    """Mount workspace claims in the reference deployment's existing domain.

    This is deliberately not a filesystem API.  It assembles the protected
    action contracts and durable logical claim state; a later deployment step
    must supply the named protected filesystem connector before either effect
    becomes executable.
    """

    service: SpendPurchaseService
    policy: FileWorkspacePolicy
    _claims: FileWorkspaceClaims = field(init=False, repr=False)
    _catalog: PolicyCatalog = field(init=False, repr=False)
    _assembly: ProviderAssembly = field(init=False, repr=False)

    def __post_init__(self) -> None:
        spend_module = self.service.provider_module()
        self._claims = FileWorkspaceClaims(self.policy, spend_module.domain)
        workspace_module = self._claims.provider_module()
        if workspace_module.domain is not spend_module.domain:
            raise ValueError("workspace claims must use the existing reference coordination domain")

        self._catalog = reference_operational_catalog()
        self.service.bind_catalog_policy(self._catalog)
        self._assembly = assemble_provider_domain(
            self._catalog,
            (spend_module, workspace_module),
        )

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
        """Initialize the existing provider plus the workspace configuration binding."""

        await self.service.initialize()
        await self._claims.initialize()

    async def close(self) -> None:
        await self.service.close()

    @property
    def claims(self) -> FileWorkspaceClaims:
        return self._claims

    @property
    def catalog(self) -> PolicyCatalog:
        return self._catalog

    @property
    def assembly(self) -> ProviderAssembly:
        return self._assembly


__all__ = [
    "ReferenceFileWorkspaceResource",
    "reference_file_workspace_catalog",
    "reference_operational_catalog",
]
