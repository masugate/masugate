"""Complete operational reference-domain composition through protected effects.

This deployment-layer object composes spend, workspace claims,
communications/approval state, and quota/egress/velocity state in one concrete
coordination domain.  Consequential actions leave the provider transaction only
through durable protected handoffs to bounded reference connectors; those
connectors are evidence sinks, not customer host/network integrations.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field, replace
from datetime import datetime
from importlib.resources import files
from pathlib import Path
from typing import cast

from masugate.catalog import PolicyCatalog, load_bundle
from masugate.certification import (
    certify_observation,
    resolve_certified_input_observation,
    validate_certified_input_evidence,
)
from masugate.contracts import ResourceSession
from masugate.language import PolicyCompiler, compiled_policy_version
from masugate.model import (
    ActionRequest,
    AuthorizationEvaluation,
    CertificationPhase,
    DecisionEffect,
    JsonValue,
    OperationStatus,
    PendingResolutionPlan,
    PolicyDecision,
    PolicyProvenance,
    request_binding_digest,
)
from masugate.policy import PolicyRuntime, PolicySet
from masugate.protected_execution import (
    PolicyBinding,
    ProtectedExecutionAuthority,
    ProtectedExecutionBinding,
    ProtectedExecutionBusy,
    ProtectedExecutionError,
    ProtectedExecutionRecord,
    ProtectedExecutionRecovery,
    ProtectedExecutionRunner,
    ProtectedExecutionStatus,
)
from masugate.provider_assembly import (
    EffectExecutionPosition,
    ProviderAssembly,
    assemble_provider_domain,
)
from masugate.providers.certified_context import (
    CertifiedContextClock,
    CertifiedContextPolicy,
    CertifiedContextProvider,
    CertifiedContextSource,
)
from masugate.providers.communications import (
    ApprovalStateProvider,
    CommunicationsPolicy,
    CommunicationsProvider,
    PolicyApprovalState,
)
from masugate.providers.customer_intent import CustomerIntentPolicy, CustomerIntentProvider
from masugate.providers.file_workspace import FileWorkspaceClaims, FileWorkspacePolicy
from masugate.providers.operational_limits import (
    OperationalLimitError,
    OperationalLimitReceipt,
    OperationalLimitsPolicy,
    OperationalLimitsProvider,
    authorization_evaluation_payload,
    operational_authorization_digest,
)
from masugate.providers.privacy_context import (
    ConsentMarketingRule,
    PhiRecipientRule,
    PiiClassifierConfig,
    PrivacyContextPolicy,
    PrivacyContextProvider,
    PrivacyContextSource,
    PrivacyTransferRule,
)
from masugate.providers.regulatory_context import (
    ExportDestinationRule,
    PositionLimitRule,
    RegulatoryContextPolicy,
    RegulatoryContextProvider,
    RegulatoryContextSource,
    SanctionsCounterpartyRule,
    TradeWindowRule,
)
from masugate.providers.spend import SpendPurchaseService
from masugate_openclaw_reference.communications import reference_communications_catalog
from masugate_openclaw_reference.deployment import reference_spend_catalog
from masugate_openclaw_reference.effects import ReferenceEffectConnector, ReferenceEffectOutbox
from masugate_openclaw_reference.file_workspace import reference_file_workspace_catalog
from masugate_openclaw_reference.release import ensure_reference_schema_for_store


def reference_certified_context_policy() -> CertifiedContextPolicy:
    """Return the versioned capability and clock configuration for this reference domain."""

    return CertifiedContextPolicy(
        context_id="reference-certified-context",
        configuration_version="reference-context-v1",
        timezone="UTC",
        window_start_minute=0,
        window_end_minute=0,
        principal_capabilities=(
            ("openclaw:alpha", ("api_spend", "http.post")),
            ("openclaw:beta", ("api_spend", "http.post")),
            ("openclaw:gamma", ("api_spend", "http.post")),
        ),
    )


def reference_privacy_context_policy() -> PrivacyContextPolicy:
    """Return the bounded, non-authoritative reference privacy projection.

    The only inputs are exact governed action targets and immutable content
    digests.  Classification, jurisdiction, purpose, consent, and local-time
    claims carried by an agent are deliberately absent from this interface.
    """

    privacy_transfers = (
        PrivacyTransferRule("api_spend", "maps", True),
        PrivacyTransferRule("http.post", "reference-endpoint", True),
    )
    phi_recipients = (
        PhiRecipientRule("api_spend", "maps", True),
        PhiRecipientRule("http.post", "reference-endpoint", True),
    )
    consent_marketing = (
        ConsentMarketingRule("api_spend", "maps", True, "UTC", 0, 0),
        ConsentMarketingRule("http.post", "reference-endpoint", True, "UTC", 0, 0),
    )
    return PrivacyContextPolicy(
        context_id="reference-privacy-context",
        configuration_version="reference-privacy-context-v1",
        privacy_transfers=privacy_transfers,
        phi_recipients=phi_recipients,
        consent_marketing=consent_marketing,
        pii_classifier=PiiClassifierConfig(
            classifier_id="reference-pii-classifier",
            classifier_version="reference-pii-classifier-v1",
            detections=(),
        ),
    )


def reference_regulatory_context_policy() -> RegulatoryContextPolicy:
    """Return bounded, non-authoritative sanctions/trade/export configuration."""

    return RegulatoryContextPolicy(
        context_id="reference-regulatory-context",
        configuration_version="reference-regulatory-context-v1",
        sanctions_counterparties=(
            SanctionsCounterpartyRule("api_spend", "maps", "maps-service", "US", True),
            SanctionsCounterpartyRule(
                "http.post",
                "reference-endpoint",
                "reference-receiver",
                "US",
                True,
            ),
        ),
        position_limits=(
            PositionLimitRule("api_spend", "all-principals", 0, 1_000_000),
            PositionLimitRule("http.post", "all-principals", 0, 1_000_000),
        ),
        trade_windows=(
            TradeWindowRule("api_spend", "UTC", 0, 0),
            TradeWindowRule("http.post", "UTC", 0, 0),
        ),
        export_destinations=(
            ExportDestinationRule("api_spend", "maps", "EAR99", "US", True),
            ExportDestinationRule("http.post", "reference-endpoint", "EAR99", "US", True),
        ),
    )


def reference_operational_limits_catalog() -> PolicyCatalog:
    """Load mandatory contracts for logical quota and egress actions."""

    root = Path(str(files("masugate.catalog").joinpath("reference_operational_limits")))
    return PolicyCatalog(bundles=(load_bundle(root),))


def reference_customer_intent_policy() -> CustomerIntentPolicy:
    """Return the reference owner's explicit no-extra-restrictions baseline."""

    return CustomerIntentPolicy(
        context_id="reference-customer-intent",
        configuration_version="reference-customer-intent-v1",
    )


def reference_customer_intent_catalog() -> PolicyCatalog:
    """Load owner-configurable intent policies for the supported action set."""

    root = Path(str(files("masugate.catalog").joinpath("reference_customer_intent")))
    return PolicyCatalog(bundles=(load_bundle(root),))


def reference_adversarial_catalog() -> PolicyCatalog:
    """Load the mandatory compromised-agent containment policy layer."""

    root = Path(str(files("masugate.catalog").joinpath("reference_adversarial")))
    return PolicyCatalog(bundles=(load_bundle(root),))


def reference_privacy_context_catalog() -> PolicyCatalog:
    """Load the mandatory reference privacy/PHI/consent policy layer."""

    root = Path(str(files("masugate.catalog").joinpath("reference_privacy_context")))
    return PolicyCatalog(bundles=(load_bundle(root),))


def reference_regulatory_context_catalog() -> PolicyCatalog:
    """Load the mandatory reference sanctions/trade/export policy layer."""

    root = Path(str(files("masugate.catalog").joinpath("reference_regulatory_context")))
    return PolicyCatalog(bundles=(load_bundle(root),))


def reference_complete_operational_catalog() -> PolicyCatalog:
    """Return the complete certified operational deployment catalog."""

    return PolicyCatalog(
        bundles=(
            reference_adversarial_catalog().bundles
            + reference_spend_catalog().bundles
            + reference_customer_intent_catalog().bundles
            + reference_file_workspace_catalog().bundles
            + reference_communications_catalog().bundles
            + reference_operational_limits_catalog().bundles
            + reference_privacy_context_catalog().bundles
            + reference_regulatory_context_catalog().bundles
        )
    )


def _runtime_for_catalog(catalog: PolicyCatalog, assembly: ProviderAssembly) -> PolicyRuntime:
    policies = PolicySet()
    for bundle in catalog.bundles:
        compiler = PolicyCompiler(
            assembly.registry,
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
    return PolicyRuntime(assembly.registry, policies)


@dataclass(frozen=True)
class OperationalExecutionResult:
    """One terminal or replayed result from the protected operational path."""

    request_digest: str
    protected_scopes: frozenset[str]
    protected_at: datetime
    request_time: datetime | None
    decision: PolicyDecision | None
    authorization_evaluation: AuthorizationEvaluation | None
    evaluation_started_at: datetime | None
    evaluation_completed_at: datetime | None
    receipt: OperationalLimitReceipt | None
    replayed: bool
    status: OperationStatus = OperationStatus.DENIED
    pending_id: str | None = None
    pending_plan: PendingResolutionPlan | None = None
    resolution_evidence: Mapping[str, JsonValue] | None = None
    protected: ProtectedExecutionRecord | None = None

    def __post_init__(self) -> None:
        if self.status is OperationStatus.PENDING:
            if self.pending_id is None or self.pending_plan is None or self.receipt is not None:
                raise ValueError("pending operational result needs a locator and plan")
        elif self.pending_id is not None:
            raise ValueError("terminal operational result cannot carry a pending locator")
        if self.protected is None:
            if (self.status is OperationStatus.COMMITTED) != (self.receipt is not None):
                raise ValueError("operational result status does not match its receipt")
        elif (self.status is OperationStatus.COMMITTED) != (
            self.protected.status is ProtectedExecutionStatus.SUCCEEDED
        ):
            raise ValueError("operational result status does not match connector evidence")


@dataclass(frozen=True)
class OperationalResolverCredential:
    """Trusted resolver identity and the principals it may approve for."""

    resolver_id: str
    token_sha256: str
    principal_ids: frozenset[str]

    def __post_init__(self) -> None:
        if (
            not self.resolver_id
            or self.resolver_id.strip() != self.resolver_id
            or re.fullmatch(r"[\x21-\x7e]{1,255}", self.resolver_id) is None
        ):
            raise ValueError("operational resolver_id must be a canonical identity")
        if re.fullmatch(r"[0-9a-f]{64}", self.token_sha256) is None:
            raise ValueError("operational resolver credential digest is malformed")
        if not self.principal_ids or any(
            not principal_id or principal_id.strip() != principal_id
            for principal_id in self.principal_ids
        ):
            raise ValueError("operational resolver needs canonical principal scope")

    @classmethod
    def from_token(
        cls,
        resolver_id: str,
        token: str,
        *,
        principal_ids: frozenset[str],
    ) -> OperationalResolverCredential:
        if not token or token.strip() != token:
            raise ValueError("operational resolver token must be canonical")
        return cls(
            resolver_id=resolver_id,
            token_sha256=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            principal_ids=principal_ids,
        )


@dataclass
class ReferenceOperationalResource:
    """Compose every operational providers operational provider in the spend domain."""

    service: SpendPurchaseService
    workspace_policy: FileWorkspacePolicy
    communications_policy: CommunicationsPolicy
    approval_state: PolicyApprovalState
    operational_limits_policy: OperationalLimitsPolicy
    certified_context_policy: CertifiedContextPolicy = field(
        default_factory=reference_certified_context_policy
    )
    certified_context_source: CertifiedContextSource | None = None
    certified_context_clock: CertifiedContextClock | None = None
    privacy_context_policy: PrivacyContextPolicy = field(
        default_factory=reference_privacy_context_policy
    )
    privacy_context_source: PrivacyContextSource | None = None
    regulatory_context_policy: RegulatoryContextPolicy = field(
        default_factory=reference_regulatory_context_policy
    )
    regulatory_context_source: RegulatoryContextSource | None = None
    customer_intent_policy: CustomerIntentPolicy = field(
        default_factory=reference_customer_intent_policy
    )
    resolver_credentials: tuple[OperationalResolverCredential, ...] = ()
    policy_catalog: PolicyCatalog | None = None
    recovery_interval_seconds: float = 1.0
    _claims: FileWorkspaceClaims = field(init=False, repr=False)
    _communications: CommunicationsProvider = field(init=False, repr=False)
    _approval: ApprovalStateProvider = field(init=False, repr=False)
    _limits: OperationalLimitsProvider = field(init=False, repr=False)
    _context: CertifiedContextProvider = field(init=False, repr=False)
    _privacy: PrivacyContextProvider = field(init=False, repr=False)
    _regulatory: RegulatoryContextProvider = field(init=False, repr=False)
    _customer_intent: CustomerIntentProvider = field(init=False, repr=False)
    _catalog: PolicyCatalog = field(init=False, repr=False)
    _assembly: ProviderAssembly = field(init=False, repr=False)
    _runtime: PolicyRuntime = field(init=False, repr=False)
    _effect_outbox: ReferenceEffectOutbox = field(init=False, repr=False)
    _effect_connectors: dict[str, ReferenceEffectConnector] = field(init=False, repr=False)
    _effect_runners: dict[str, ProtectedExecutionRunner] = field(init=False, repr=False)
    _recovery_stop: asyncio.Event = field(init=False, repr=False)
    _recovery_task: asyncio.Task[None] | None = field(init=False, repr=False, default=None)
    _recovery_last_error: Exception | None = field(init=False, repr=False, default=None)

    def __post_init__(self) -> None:
        if (
            type(self.recovery_interval_seconds) not in {int, float}
            or self.recovery_interval_seconds <= 0
            or self.recovery_interval_seconds > 60
        ):
            raise ValueError("operational recovery interval must be between zero and sixty seconds")
        credential_digests = [item.token_sha256 for item in self.resolver_credentials]
        if len(credential_digests) != len(set(credential_digests)):
            raise ValueError("operational resolver credentials must be unique")
        self._recovery_stop = asyncio.Event()
        spend_module = self.service.provider_module()
        domain = spend_module.domain
        self._claims = FileWorkspaceClaims(self.workspace_policy, domain)
        self._communications = CommunicationsProvider(self.communications_policy, domain)
        self._approval = ApprovalStateProvider(self.approval_state, domain)
        self._limits = OperationalLimitsProvider(self.operational_limits_policy, domain)
        self._context = CertifiedContextProvider(
            self.certified_context_policy,
            domain,
            source=self.certified_context_source,
            clock=self.certified_context_clock,
        )
        self._privacy = PrivacyContextProvider(
            self.privacy_context_policy,
            domain,
            source=self.privacy_context_source,
        )
        self._regulatory = RegulatoryContextProvider(
            self.regulatory_context_policy,
            domain,
            source=self.regulatory_context_source,
        )
        self._customer_intent = CustomerIntentProvider(self.customer_intent_policy, domain)
        connector_ids = {
            "api_spend": "reference-api-runner-v1",
            "channel.post": "communications-runner-v1",
            "fs.delete": "filesystem-v1",
            "fs.write": "filesystem-v1",
            "http.post": "reference-http-runner-v1",
            "send_message": "communications-runner-v1",
        }
        provider_identities = {
            "api_spend": self.operational_limits_policy.provider_identity,
            "channel.post": self.communications_policy.provider_identity,
            "fs.delete": self.workspace_policy.provider_identity,
            "fs.write": self.workspace_policy.provider_identity,
            "http.post": self.operational_limits_policy.provider_identity,
            "send_message": self.communications_policy.provider_identity,
        }
        self._effect_outbox = ReferenceEffectOutbox(domain.resource)
        self._effect_connectors = {
            connector_id: ReferenceEffectConnector(domain.resource, connector_id)
            for connector_id in sorted(set(connector_ids.values()))
        }
        self._effect_runners = {}
        for action, connector_id in connector_ids.items():
            runner = ProtectedExecutionRunner(
                self.service.protected_execution_store,
                self._effect_connectors[connector_id],
                ProtectedExecutionAuthority(
                    action=action,
                    provider_identity=provider_identities[action],
                    coordination_domain_id=domain.domain_id,
                    connector_id=connector_id,
                ),
                worker_id=f"reference-{action.replace('.', '-')}",
            )
            runner.bind_dispatch_admission(self._effect_outbox.require_dispatchable)
            self._effect_runners[action] = runner
        modules = (
            spend_module,
            self._claims.provider_module(
                {action: self._effect_runners[action] for action in ("fs.delete", "fs.write")}
            ),
            self._communications.provider_module(
                {
                    action: self._effect_runners[action]
                    for action in ("channel.post", "send_message")
                }
            ),
            self._approval.provider_module(),
            self._limits.provider_module(
                {action: self._effect_runners[action] for action in ("api_spend", "http.post")}
            ),
            self._context.provider_module(),
            self._privacy.provider_module(),
            self._regulatory.provider_module(),
            self._customer_intent.provider_module(),
        )
        if any(module.domain is not domain for module in modules):
            raise ValueError("operational providers must use the existing reference domain")

        self._catalog = (
            reference_complete_operational_catalog()
            if self.policy_catalog is None
            else self.policy_catalog
        )
        self.service.bind_catalog_policy(self._catalog)
        self._assembly = assemble_provider_domain(self._catalog, modules)
        self.service.bind_pending_plan(self._assembly.action("spend.purchase").pending_plan)
        self._runtime = _runtime_for_catalog(self._catalog, self._assembly)
        self.service.bind_policy_runtime(self._runtime)

    async def initialize(self) -> None:
        """Initialize the shared spend resource and every provider's durable state."""

        await ensure_reference_schema_for_store(self.service.store)
        await self.service.initialize()
        await self._effect_outbox.initialize()
        for connector in self._effect_connectors.values():
            await connector.initialize()
        await self.recover_protected_effects()
        await self._claims.initialize()
        await self._communications.initialize()
        await self._approval.initialize()
        await self._limits.initialize()
        await self._context.initialize()
        await self._privacy.initialize()
        await self._regulatory.initialize()
        if self._recovery_task is None:
            self._recovery_task = asyncio.create_task(
                self._recovery_worker(),
                name="masugate-operational-effect-recovery",
            )

    async def close(self) -> None:
        self._recovery_stop.set()
        if self._recovery_task is not None:
            self._recovery_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._recovery_task
            self._recovery_task = None
        await self.service.close()

    async def _recovery_worker(self) -> None:
        while not self._recovery_stop.is_set():
            try:
                await asyncio.wait_for(
                    self._recovery_stop.wait(),
                    timeout=self.recovery_interval_seconds,
                )
                continue
            except TimeoutError:
                pass
            try:
                await self.recover_protected_effects()
                self._recovery_last_error = None
            except Exception as exc:  # retain auditable health while serving safely
                self._recovery_last_error = exc

    async def recover_protected_effects(self) -> tuple[ProtectedExecutionRecord, ...]:
        """Drain provider outboxes and reconcile ambiguous effects without redispatch."""

        handoffs = await self._effect_outbox.unresolved()
        by_action: dict[str, list[str]] = {}
        for handoff in handoffs:
            try:
                await self.service.protected_execution_store.get(handoff.binding.execution_id)
            except ProtectedExecutionError:
                continue
            by_action.setdefault(handoff.binding.action, []).append(handoff.binding.execution_id)
        errors: list[tuple[str, str]] = []
        for action, execution_ids in by_action.items():
            report = await ProtectedExecutionRecovery(
                self._assembly.protected_execution_runner(action)
            ).recover(execution_ids=execution_ids)
            errors.extend(report.errors)

        recovered: list[ProtectedExecutionRecord] = []
        for handoff in handoffs:
            try:
                current = await self.service.protected_execution_store.get(
                    handoff.binding.execution_id
                )
            except ProtectedExecutionError:
                if handoff.state == "outcome_unknown":
                    errors.append((handoff.binding.execution_id, "MissingAmbiguousExecution"))
                    continue
                try:
                    current = await self._assembly.protected_execution_runner(
                        handoff.binding.action
                    ).start(handoff.binding)
                except ProtectedExecutionBusy:
                    current = await self.service.protected_execution_store.get(
                        handoff.binding.execution_id
                    )
            if current.status not in {
                ProtectedExecutionStatus.INTENT,
                ProtectedExecutionStatus.EXECUTING,
            }:
                await self._effect_outbox.settle(current)
            recovered.append(current)
        if errors:
            details = ", ".join(f"{execution_id}:{error}" for execution_id, error in errors)
            raise OperationalLimitError(f"protected effect recovery failed: {details}")
        return tuple(recovered)

    async def _certify_for_evaluation(
        self,
        session: ResourceSession,
        request: ActionRequest,
        *,
        phase: CertificationPhase,
    ) -> tuple[ActionRequest, datetime]:
        """Resolve every declared fact at one protected evaluation point."""

        dependencies = self._runtime.certified_input_dependencies(request.action)
        observations = {}
        observation_time = self._context.certified_now(session)
        for name in dependencies:
            contract = self._assembly.registry.certified_input(name)
            observations[name] = await resolve_certified_input_observation(
                contract,
                session,
                request,
                observation_time=observation_time,
            )
        certified_at = self._context.certified_now(session)
        certified_inputs = {
            name: certify_observation(
                self._assembly.registry.certified_input(name),
                observation,
                phase,
                certified_at=certified_at,
            )
            for name, observation in observations.items()
        }
        certified_request = replace(request, certified_inputs=certified_inputs)
        for name in dependencies:
            validate_certified_input_evidence(
                self._assembly.registry.certified_input(name),
                certified_request.certified_inputs[name],
                at=certified_at,
                evaluation_phase=phase,
            )
        return certified_request, certified_at

    def _protected_binding(
        self,
        request: ActionRequest,
        evaluation: AuthorizationEvaluation,
        scopes: frozenset[str],
        *,
        resolution: Mapping[str, JsonValue] | None = None,
    ) -> ProtectedExecutionBinding:
        assembled = self._assembly.action(request.action)
        if assembled.connector_id is None:
            raise OperationalLimitError("protected operational action has no connector")
        module = next(
            module
            for module in self._assembly.modules
            if module.module_id == assembled.effect_owner
        )
        policies = tuple(
            PolicyBinding(
                policy_id=item.policy_id,
                policy_version=item.policy_declared_version,
                policy_digest=item.policy_digest,
                bundle_id=item.bundle_id,
                bundle_version=item.bundle_version,
                bundle_digest=item.bundle_digest,
            )
            for item in evaluation.decision.policy_provenance
        )
        if not policies:
            raise OperationalLimitError(
                "protected operational authorization has no catalog provenance"
            )
        return ProtectedExecutionBinding(
            principal_id=request.principal.id,
            action=request.action,
            arguments=dict(request.arguments),
            idempotency_key=request.idempotency_key,
            policies=policies,
            provider_identity=module.identity,
            coordination_domain_id=assembled.coordination_domain_id,
            scopes=tuple(scopes),
            tool_call_id=request.trace_id or request.operation_id,
            connector_id=assembled.connector_id,
            entitlement_id="opauth:" + request_binding_digest(request),
            authorization_digest=operational_authorization_digest(
                request,
                evaluation,
                resolution=resolution,
            ),
        )

    async def _dispatch_result(
        self,
        result: OperationalExecutionResult,
        binding: ProtectedExecutionBinding | None,
    ) -> OperationalExecutionResult:
        if binding is None:
            return result
        runner = self._assembly.protected_execution_runner(binding.action)
        try:
            protected = await runner.start(binding)
        except ProtectedExecutionBusy:
            protected = await self.service.protected_execution_store.get(binding.execution_id)
        if protected.status is ProtectedExecutionStatus.OUTCOME_UNKNOWN:
            try:
                protected = await runner.reconcile(binding.execution_id)
            except ProtectedExecutionBusy:
                protected = await self.service.protected_execution_store.get(binding.execution_id)
        await self._effect_outbox.settle(protected)
        if protected.status is ProtectedExecutionStatus.SUCCEEDED:
            status = OperationStatus.COMMITTED
        elif protected.status is ProtectedExecutionStatus.FAILED:
            status = OperationStatus.DENIED
        else:
            status = OperationStatus.ABORTED
        return replace(result, protected=protected, status=status)

    async def _admit_reference_effect(
        self,
        request: ActionRequest,
    ) -> tuple[OperationalExecutionResult, ProtectedExecutionBinding | None]:
        """Authorize workspace/communications state and commit one exact handoff."""

        assembled = self._assembly.action(request.action)
        if (
            assembled.effect_owner not in {"communications", "file-workspace"}
            or assembled.position is not EffectExecutionPosition.PROTECTED_EXTERNAL
            or assembled.connector_id is None
        ):
            raise OperationalLimitError(
                "the reference effect boundary accepts only installed workspace or "
                "communications actions"
            )
        effect = self._assembly.registry.effect(request.action)
        effect_scopes = effect.footprint_resolver(request).all_scopes
        async with self._assembly.open_action_session(request.action) as session:
            if assembled.effect_owner == "communications":
                protected_scopes = self._communications._protect_for_request(session, request)
            else:
                protected_scopes = self._claims._protect_for_request(session, request)
            if protected_scopes != effect_scopes:
                raise OperationalLimitError(
                    "reference effect protection omitted a declared effect scope"
                )
            outcome = self._effect_outbox.load_outcome_in_session(session, request)
            if outcome is not None:
                binding = None
                if outcome.effect_committed:
                    binding = self._effect_outbox.load_in_session(
                        session,
                        action=request.action,
                        principal_id=request.principal.id,
                        idempotency_key=request.idempotency_key,
                    )
                    if binding is None:
                        raise OperationalLimitError(
                            "committed reference authorization has no protected outbox"
                        )
                return (
                    OperationalExecutionResult(
                        request_digest=request_binding_digest(outcome.request),
                        protected_scopes=protected_scopes,
                        protected_at=outcome.request.timestamp,
                        request_time=outcome.request.timestamp,
                        decision=outcome.evaluation.decision,
                        authorization_evaluation=outcome.evaluation,
                        evaluation_started_at=outcome.evaluation_started_at,
                        evaluation_completed_at=outcome.evaluation_completed_at,
                        receipt=None,
                        replayed=True,
                        status=OperationStatus.DENIED,
                        resolution_evidence=outcome.resolution,
                    ),
                    binding,
                )
            existing = self._effect_outbox.load_in_session(
                session,
                action=request.action,
                principal_id=request.principal.id,
                idempotency_key=request.idempotency_key,
            )
            if existing is not None:
                raise OperationalLimitError(
                    "reference effect outbox lacks durable authorization evidence"
                )
            pending = self._effect_outbox.load_pending_in_session(session, request)
            if pending is not None:
                if pending.resolution is not None:
                    raise OperationalLimitError(
                        "resolved reference pending effect has no protected handoff"
                    )
                return (
                    OperationalExecutionResult(
                        request_digest=request_binding_digest(pending.request),
                        protected_scopes=protected_scopes,
                        protected_at=pending.request.timestamp,
                        request_time=pending.request.timestamp,
                        decision=pending.evaluation.decision,
                        authorization_evaluation=pending.evaluation,
                        evaluation_started_at=pending.evaluation_started_at,
                        evaluation_completed_at=pending.evaluation_completed_at,
                        receipt=None,
                        replayed=True,
                        status=OperationStatus.PENDING,
                        pending_id=pending.pending_id,
                        pending_plan=pending.pending_plan,
                    ),
                    None,
                )
            request = replace(
                request,
                timestamp=self._context.certified_now(session),
                certified_inputs={},
            )
            certified_request, evaluation_started_at = await self._certify_for_evaluation(
                session,
                request,
                phase=CertificationPhase.ADMISSION,
            )
            decision = self._runtime.evaluate(
                certified_request,
                session,
                evaluation_at=evaluation_started_at,
                evaluation_phase=CertificationPhase.ADMISSION,
            )
            evaluation_completed_at = self._context.certified_now(session)
            for name in self._runtime.certified_input_dependencies(certified_request.action):
                validate_certified_input_evidence(
                    self._assembly.registry.certified_input(name),
                    certified_request.certified_inputs[name],
                    at=evaluation_completed_at,
                    evaluation_phase=CertificationPhase.ADMISSION,
                )
            evaluation = AuthorizationEvaluation(
                phase=CertificationPhase.ADMISSION,
                evaluated_at=evaluation_completed_at,
                decision=decision,
                certified_inputs=certified_request.certified_inputs,
            )
            if decision.effect is DecisionEffect.ESCALATE:
                if assembled.pending_plan is not PendingResolutionPlan.REVALIDATE:
                    raise OperationalLimitError(
                        "reference effect escalation has no executable revalidation contract"
                    )
                pending = self._effect_outbox.record_pending_in_session(
                    session,
                    certified_request,
                    evaluation,
                    evaluation_started_at=evaluation_started_at,
                    evaluation_completed_at=evaluation_completed_at,
                    pending_plan=assembled.pending_plan,
                )
                return (
                    OperationalExecutionResult(
                        request_digest=request_binding_digest(pending.request),
                        protected_scopes=protected_scopes,
                        protected_at=pending.request.timestamp,
                        request_time=pending.request.timestamp,
                        decision=pending.evaluation.decision,
                        authorization_evaluation=pending.evaluation,
                        evaluation_started_at=pending.evaluation_started_at,
                        evaluation_completed_at=pending.evaluation_completed_at,
                        receipt=None,
                        replayed=False,
                        status=OperationStatus.PENDING,
                        pending_id=pending.pending_id,
                        pending_plan=pending.pending_plan,
                    ),
                    None,
                )
            if decision.effect is DecisionEffect.DENY:
                self._effect_outbox.record_outcome_in_session(
                    session,
                    certified_request,
                    evaluation,
                    evaluation_started_at=evaluation_started_at,
                    evaluation_completed_at=evaluation_completed_at,
                    effect_committed=False,
                )
                return (
                    OperationalExecutionResult(
                        request_digest=request_binding_digest(certified_request),
                        protected_scopes=protected_scopes,
                        protected_at=request.timestamp,
                        request_time=request.timestamp,
                        decision=decision,
                        authorization_evaluation=evaluation,
                        evaluation_started_at=evaluation_started_at,
                        evaluation_completed_at=evaluation_completed_at,
                        receipt=None,
                        replayed=False,
                        status=OperationStatus.DENIED,
                    ),
                    None,
                )
            if assembled.effect_owner == "communications":
                self._communications._record_delivery_for_request_in_session(
                    session,
                    certified_request,
                )
            binding = self._protected_binding(
                certified_request,
                evaluation,
                protected_scopes,
            )
            self._effect_outbox.record_in_session(session, binding)
            self._effect_outbox.record_outcome_in_session(
                session,
                certified_request,
                evaluation,
                evaluation_started_at=evaluation_started_at,
                evaluation_completed_at=evaluation_completed_at,
                effect_committed=True,
            )
            return (
                OperationalExecutionResult(
                    request_digest=request_binding_digest(certified_request),
                    protected_scopes=protected_scopes,
                    protected_at=request.timestamp,
                    request_time=request.timestamp,
                    decision=decision,
                    authorization_evaluation=evaluation,
                    evaluation_started_at=evaluation_started_at,
                    evaluation_completed_at=evaluation_completed_at,
                    receipt=None,
                    replayed=False,
                    status=OperationStatus.DENIED,
                ),
                binding,
            )

    async def _admit_operational(
        self,
        request: ActionRequest,
    ) -> tuple[OperationalExecutionResult, ProtectedExecutionBinding | None]:
        """Protect, certify, evaluate, and hand off one metered reference action.

        This is the production execution boundary for the two callable operational
        limits actions. It owns the trusted runtime and one resource session from
        complete-effect-footprint protection through context certification,
        policy evaluation, logical meter commit, and protected outbox creation.
        Connector dispatch happens only after that transaction commits.
        Caller-supplied timestamps and ``certified.*`` evidence are discarded
        before any policy input is resolved.
        """

        try:
            assembled = self._assembly.action(request.action)
            if (
                assembled.effect_owner != "operational-limits"
                or assembled.position is not EffectExecutionPosition.PROTECTED_EXTERNAL
            ):
                raise OperationalLimitError(
                    "the operational execution boundary accepts only installed protected "
                    "reference API/HTTP actions"
                )
            effect = self._assembly.registry.effect(request.action)
            dependency_scopes = self._runtime.dependency_scopes(request)
            effect_scopes = effect.footprint_resolver(request).all_scopes
            immutable_configuration_scopes = {
                self._assembly.registry.view(call.name).scope_resolver(
                    tuple(
                        self._runtime._evaluate_static(argument, request)
                        for argument in call.arguments
                    )
                )
                for policy in self._runtime.policies.all_for_action(request.action)
                for call in policy.host_calls
                if self._assembly.registry.view(call.name).consistency == "owner-configuration-v1"
            }
            protected_dependency_scopes = dependency_scopes - immutable_configuration_scopes
            if not protected_dependency_scopes or not protected_dependency_scopes <= effect_scopes:
                raise OperationalLimitError(
                    "operational effect footprint omits a policy dependency scope"
                )

            async with self._assembly.open_action_session(request.action) as session:
                protected_scopes = self._limits._protect_for_request(session, request)
                if protected_scopes != effect_scopes:
                    raise OperationalLimitError(
                        "operational protection omitted a declared effect scope"
                    )
                request = replace(
                    request,
                    certified_inputs={},
                )
                replay = self._limits._load_authorization_outcome_in_session(session, request)
                if replay is not None:
                    binding = None
                    if replay.receipt is not None:
                        binding = self._effect_outbox.load_in_session(
                            session,
                            action=request.action,
                            principal_id=request.principal.id,
                            idempotency_key=request.idempotency_key,
                        )
                        if binding is None:
                            raise OperationalLimitError(
                                "committed operational authorization has no protected outbox"
                            )
                    return OperationalExecutionResult(
                        request_digest=replay.request_digest,
                        protected_scopes=protected_scopes,
                        protected_at=replay.request_time,
                        request_time=replay.request_time,
                        decision=replay.decision,
                        authorization_evaluation=replay.authorization_evaluation,
                        evaluation_started_at=replay.evaluation_started_at,
                        evaluation_completed_at=replay.evaluation_completed_at,
                        receipt=replay.receipt,
                        replayed=True,
                        status=(
                            OperationStatus.COMMITTED
                            if replay.receipt is not None
                            else OperationStatus.DENIED
                        ),
                        resolution_evidence=replay.resolution,
                    ), binding

                pending = self._limits._load_pending_in_session(session, request)
                if pending is not None:
                    if pending.resolution is not None:
                        raise OperationalLimitError(
                            "resolved operational pending state lacks a terminal outcome"
                        )
                    if assembled.pending_plan is not pending.pending_plan:
                        raise OperationalLimitError(
                            "assembled operational pending plan changed after admission"
                        )
                    return OperationalExecutionResult(
                        request_digest=pending.request_digest,
                        protected_scopes=protected_scopes,
                        protected_at=pending.request.timestamp,
                        request_time=pending.request.timestamp,
                        decision=pending.decision,
                        authorization_evaluation=pending.authorization_evaluation,
                        evaluation_started_at=pending.evaluation_started_at,
                        evaluation_completed_at=pending.evaluation_completed_at,
                        receipt=None,
                        replayed=True,
                        status=OperationStatus.PENDING,
                        pending_id=pending.pending_id,
                        pending_plan=pending.pending_plan,
                    ), None

                if self._limits._load_replay_in_session(session, request) is not None:
                    raise OperationalLimitError(
                        "operational receipt lacks durable authorization evidence"
                    )
                request = replace(request, timestamp=self._context.certified_now(session))
                protected_at = request.timestamp

                certified_request, evaluation_started_at = await self._certify_for_evaluation(
                    session,
                    request,
                    phase=CertificationPhase.ADMISSION,
                )
                decision = self._runtime.evaluate(
                    certified_request,
                    session,
                    evaluation_at=evaluation_started_at,
                    evaluation_phase=CertificationPhase.ADMISSION,
                )
                evaluation_completed_at = self._context.certified_now(session)
                for name in self._runtime.certified_input_dependencies(certified_request.action):
                    validate_certified_input_evidence(
                        self._assembly.registry.certified_input(name),
                        certified_request.certified_inputs[name],
                        at=evaluation_completed_at,
                        evaluation_phase=CertificationPhase.ADMISSION,
                    )
                authorization_evaluation = AuthorizationEvaluation(
                    phase=CertificationPhase.ADMISSION,
                    evaluated_at=evaluation_completed_at,
                    decision=decision,
                    certified_inputs=certified_request.certified_inputs,
                )
                if decision.effect is DecisionEffect.ESCALATE:
                    if assembled.pending_plan is not PendingResolutionPlan.REVALIDATE:
                        raise OperationalLimitError(
                            "operational escalation has no executable revalidation contract"
                        )
                    pending = self._limits._record_pending_in_session(
                        session,
                        certified_request,
                        authorization_evaluation=authorization_evaluation,
                        evaluation_started_at=evaluation_started_at,
                        evaluation_completed_at=evaluation_completed_at,
                        pending_plan=assembled.pending_plan,
                    )
                    return OperationalExecutionResult(
                        request_digest=pending.request_digest,
                        protected_scopes=protected_scopes,
                        protected_at=protected_at,
                        request_time=pending.request.timestamp,
                        decision=pending.decision,
                        authorization_evaluation=pending.authorization_evaluation,
                        evaluation_started_at=pending.evaluation_started_at,
                        evaluation_completed_at=pending.evaluation_completed_at,
                        receipt=None,
                        replayed=False,
                        status=OperationStatus.PENDING,
                        pending_id=pending.pending_id,
                        pending_plan=pending.pending_plan,
                    ), None

                if decision.effect is DecisionEffect.DENY:
                    outcome = self._limits._record_authorization_outcome_in_session(
                        session,
                        certified_request,
                        decision=decision,
                        authorization_evaluation=authorization_evaluation,
                        evaluation_started_at=evaluation_started_at,
                        evaluation_completed_at=evaluation_completed_at,
                        receipt=None,
                    )
                    return OperationalExecutionResult(
                        request_digest=outcome.request_digest,
                        protected_scopes=protected_scopes,
                        protected_at=protected_at,
                        request_time=outcome.request_time,
                        decision=outcome.decision,
                        authorization_evaluation=outcome.authorization_evaluation,
                        evaluation_started_at=outcome.evaluation_started_at,
                        evaluation_completed_at=outcome.evaluation_completed_at,
                        receipt=None,
                        replayed=False,
                        status=OperationStatus.DENIED,
                    ), None

                receipt = self._limits._record_in_session(session, certified_request)
                outcome = self._limits._record_authorization_outcome_in_session(
                    session,
                    certified_request,
                    decision=decision,
                    authorization_evaluation=authorization_evaluation,
                    evaluation_started_at=evaluation_started_at,
                    evaluation_completed_at=evaluation_completed_at,
                    receipt=receipt,
                )
                binding = self._protected_binding(
                    certified_request,
                    authorization_evaluation,
                    protected_scopes,
                )
                self._effect_outbox.record_in_session(session, binding)
                return OperationalExecutionResult(
                    request_digest=outcome.request_digest,
                    protected_scopes=protected_scopes,
                    protected_at=protected_at,
                    request_time=outcome.request_time,
                    decision=outcome.decision,
                    authorization_evaluation=outcome.authorization_evaluation,
                    evaluation_started_at=outcome.evaluation_started_at,
                    evaluation_completed_at=outcome.evaluation_completed_at,
                    receipt=outcome.receipt,
                    replayed=False,
                    status=OperationStatus.COMMITTED,
                ), binding
        except Exception as exc:
            mapped = self._limits.map_resource_failure(exc)
            if mapped is exc:
                raise
            raise mapped from exc

    async def execute(self, request: ActionRequest) -> OperationalExecutionResult:
        """Authorize, commit the provider outbox, then dispatch outside its transaction."""

        assembled = self._assembly.action(request.action)
        if assembled.effect_owner == "operational-limits":
            result, binding = await self._admit_operational(request)
        else:
            result, binding = await self._admit_reference_effect(request)
        return await self._dispatch_result(result, binding)

    @staticmethod
    def _resolution_payload(
        *,
        approved: bool,
        actor_id: str,
        evidence: Mapping[str, JsonValue] | None,
    ) -> dict[str, JsonValue]:
        if type(approved) is not bool:
            raise TypeError("operational pending approved must be bool")
        if (
            type(actor_id) is not str
            or not actor_id
            or actor_id.strip() != actor_id
            or re.fullmatch(r"[\x21-\x7e]{1,255}", actor_id) is None
        ):
            raise ValueError("operational pending actor_id must be a canonical identity")
        try:
            normalized_evidence = json.loads(
                json.dumps(
                    {} if evidence is None else dict(evidence),
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("operational pending resolution evidence must be JSON") from exc
        if not isinstance(normalized_evidence, dict):  # pragma: no cover - dict() above
            raise ValueError("operational pending resolution evidence must be an object")
        return {
            "actor_id": actor_id,
            "approved": approved,
            "evidence": cast(dict[str, JsonValue], normalized_evidence),
            "pending_plan": PendingResolutionPlan.REVALIDATE.value,
        }

    async def _resolve_pending_admission(
        self,
        pending_id: str,
        *,
        approved: bool,
        actor_id: str,
        evidence: Mapping[str, JsonValue] | None = None,
    ) -> tuple[OperationalExecutionResult, ProtectedExecutionBinding | None]:
        """Resolve one API/HTTP escalation with durable revalidation and replay."""

        resolution = self._resolution_payload(
            approved=approved,
            actor_id=actor_id,
            evidence=evidence,
        )

        try:
            located = await self._limits.load_pending(pending_id)
            assembled = self._assembly.action(located.request.action)
            if (
                assembled.effect_owner != "operational-limits"
                or assembled.position is not EffectExecutionPosition.PROTECTED_EXTERNAL
                or assembled.pending_plan is not PendingResolutionPlan.REVALIDATE
                or located.pending_plan is not assembled.pending_plan
            ):
                raise OperationalLimitError(
                    "operational pending locator no longer has its assembled revalidation path"
                )
            effect = self._assembly.registry.effect(located.request.action)
            effect_scopes = effect.footprint_resolver(located.request).all_scopes
            async with self._assembly.open_action_session(located.request.action) as session:
                protected_scopes = self._limits._protect_for_request(session, located.request)
                if protected_scopes != effect_scopes:
                    raise OperationalLimitError(
                        "operational pending protection omitted a declared effect scope"
                    )
                pending = self._limits._load_pending_in_session(session, located.request)
                if pending is None or pending.pending_id != pending_id:
                    raise OperationalLimitError("operational pending authorization disappeared")
                terminal = self._limits._load_authorization_outcome_in_session(
                    session, pending.request
                )
                if pending.resolution is not None:
                    if dict(pending.resolution) != resolution:
                        raise OperationalLimitError(
                            "operational pending resolution evidence is immutable"
                        )
                    if terminal is None:
                        raise OperationalLimitError(
                            "resolved operational pending state lacks a terminal outcome"
                        )
                    if terminal.resolution is None or dict(terminal.resolution) != resolution:
                        raise OperationalLimitError(
                            "terminal operational resolution evidence is inconsistent"
                        )
                    binding = None
                    if terminal.receipt is not None:
                        binding = self._effect_outbox.load_in_session(
                            session,
                            action=pending.request.action,
                            principal_id=pending.request.principal.id,
                            idempotency_key=pending.request.idempotency_key,
                        )
                        if binding is None:
                            raise OperationalLimitError(
                                "resolved operational authorization has no protected outbox"
                            )
                    return OperationalExecutionResult(
                        request_digest=terminal.request_digest,
                        protected_scopes=protected_scopes,
                        protected_at=terminal.request_time,
                        request_time=terminal.request_time,
                        decision=terminal.decision,
                        authorization_evaluation=terminal.authorization_evaluation,
                        evaluation_started_at=terminal.evaluation_started_at,
                        evaluation_completed_at=terminal.evaluation_completed_at,
                        receipt=terminal.receipt,
                        replayed=True,
                        status=(
                            OperationStatus.COMMITTED
                            if terminal.receipt is not None
                            else OperationStatus.DENIED
                        ),
                        resolution_evidence=terminal.resolution,
                    ), binding
                if terminal is not None:
                    raise OperationalLimitError(
                        "active operational pending state already has a terminal outcome"
                    )

                request = replace(pending.request, certified_inputs={})
                if approved:
                    certified_request, evaluation_started_at = await self._certify_for_evaluation(
                        session,
                        request,
                        phase=CertificationPhase.RESOLUTION,
                    )
                    revalidated = self._runtime.evaluate(
                        certified_request,
                        session,
                        evaluation_at=evaluation_started_at,
                        evaluation_phase=CertificationPhase.RESOLUTION,
                    )
                    evaluation_completed_at = self._context.certified_now(session)
                    for name in self._runtime.certified_input_dependencies(
                        certified_request.action
                    ):
                        validate_certified_input_evidence(
                            self._assembly.registry.certified_input(name),
                            certified_request.certified_inputs[name],
                            at=evaluation_completed_at,
                            evaluation_phase=CertificationPhase.RESOLUTION,
                        )
                    if revalidated.effect is DecisionEffect.DENY:
                        decision = revalidated
                    else:
                        decision = replace(
                            revalidated,
                            effect=DecisionEffect.ALLOW,
                            rule_id="resolution.approved",
                            reason=(
                                "explicit approval followed a current protected "
                                "revalidation with no deny"
                            ),
                        )
                else:
                    certified_request = request
                    evaluation_started_at = self._context.certified_now(session)
                    evaluation_completed_at = evaluation_started_at
                    decision = PolicyDecision(
                        effect=DecisionEffect.DENY,
                        policy_id="masugate.pending-resolution",
                        policy_version="",
                        rule_id="resolution.denied",
                        reason="the authoritative resolver denied the pending operation",
                        evaluated_policies=pending.decision.evaluated_policies,
                        policy_provenance=pending.decision.policy_provenance,
                    )
                authorization_evaluation = AuthorizationEvaluation(
                    phase=CertificationPhase.RESOLUTION,
                    evaluated_at=evaluation_completed_at,
                    decision=decision,
                    certified_inputs=certified_request.certified_inputs,
                )
                receipt: OperationalLimitReceipt | None = None
                effect_binding: ProtectedExecutionBinding | None = None
                if decision.effect is DecisionEffect.ALLOW:
                    receipt = self._limits._record_in_session(session, certified_request)
                outcome = self._limits._record_authorization_outcome_in_session(
                    session,
                    certified_request,
                    decision=decision,
                    authorization_evaluation=authorization_evaluation,
                    evaluation_started_at=evaluation_started_at,
                    evaluation_completed_at=evaluation_completed_at,
                    receipt=receipt,
                    resolution=resolution,
                )
                if receipt is not None:
                    effect_binding = self._protected_binding(
                        certified_request,
                        authorization_evaluation,
                        protected_scopes,
                        resolution=resolution,
                    )
                    self._effect_outbox.record_in_session(session, effect_binding)
                self._limits._resolve_pending_in_session(session, pending, resolution)
                return OperationalExecutionResult(
                    request_digest=outcome.request_digest,
                    protected_scopes=protected_scopes,
                    protected_at=request.timestamp,
                    request_time=outcome.request_time,
                    decision=outcome.decision,
                    authorization_evaluation=outcome.authorization_evaluation,
                    evaluation_started_at=outcome.evaluation_started_at,
                    evaluation_completed_at=outcome.evaluation_completed_at,
                    receipt=outcome.receipt,
                    replayed=False,
                    status=(
                        OperationStatus.COMMITTED
                        if outcome.receipt is not None
                        else OperationStatus.DENIED
                    ),
                    resolution_evidence=resolution,
                ), effect_binding
        except Exception as exc:
            mapped = self._limits.map_resource_failure(exc)
            if mapped is exc:
                raise
            raise mapped from exc

    async def _resolve_reference_pending_admission(
        self,
        pending_id: str,
        *,
        approved: bool,
        actor_id: str,
        evidence: Mapping[str, JsonValue] | None,
    ) -> tuple[OperationalExecutionResult, ProtectedExecutionBinding | None]:
        resolution = self._resolution_payload(
            approved=approved,
            actor_id=actor_id,
            evidence=evidence,
        )
        located = await self._effect_outbox.load_pending(pending_id)
        assembled = self._assembly.action(located.request.action)
        if (
            assembled.effect_owner not in {"communications", "file-workspace"}
            or assembled.position is not EffectExecutionPosition.PROTECTED_EXTERNAL
            or assembled.pending_plan is not PendingResolutionPlan.REVALIDATE
            or located.pending_plan is not assembled.pending_plan
        ):
            raise OperationalLimitError(
                "reference pending locator no longer has its assembled revalidation path"
            )
        effect = self._assembly.registry.effect(located.request.action)
        effect_scopes = effect.footprint_resolver(located.request).all_scopes
        async with self._assembly.open_action_session(located.request.action) as session:
            if assembled.effect_owner == "communications":
                protected_scopes = self._communications._protect_for_request(
                    session, located.request
                )
            else:
                protected_scopes = self._claims._protect_for_request(session, located.request)
            if protected_scopes != effect_scopes:
                raise OperationalLimitError(
                    "reference pending protection omitted a declared effect scope"
                )
            pending = self._effect_outbox.load_pending_in_session(session, located.request)
            if pending is None or pending.pending_id != pending_id:
                raise OperationalLimitError("reference pending effect disappeared")
            if pending.resolution is not None:
                public_resolution = {
                    key: pending.resolution[key]
                    for key in ("actor_id", "approved", "evidence", "pending_plan")
                }
                if public_resolution != resolution:
                    raise OperationalLimitError(
                        "reference pending resolution evidence is immutable"
                    )
                outcome = self._effect_outbox.load_outcome_in_session(session, pending.request)
                if outcome is None:
                    raise OperationalLimitError(
                        "resolved reference pending effect lacks terminal authorization"
                    )
                binding = None
                if outcome.effect_committed:
                    binding = self._effect_outbox.load_in_session(
                        session,
                        action=pending.request.action,
                        principal_id=pending.request.principal.id,
                        idempotency_key=pending.request.idempotency_key,
                    )
                    if binding is None:
                        raise OperationalLimitError(
                            "approved reference pending effect has no protected outbox"
                        )
                return (
                    OperationalExecutionResult(
                        request_digest=request_binding_digest(outcome.request),
                        protected_scopes=protected_scopes,
                        protected_at=outcome.request.timestamp,
                        request_time=outcome.request.timestamp,
                        decision=outcome.evaluation.decision,
                        authorization_evaluation=outcome.evaluation,
                        evaluation_started_at=outcome.evaluation_started_at,
                        evaluation_completed_at=outcome.evaluation_completed_at,
                        receipt=None,
                        replayed=True,
                        status=OperationStatus.DENIED,
                        resolution_evidence=resolution,
                    ),
                    binding,
                )

            request = replace(pending.request, certified_inputs={})
            if approved:
                certified_request, evaluation_started_at = await self._certify_for_evaluation(
                    session,
                    request,
                    phase=CertificationPhase.RESOLUTION,
                )
                revalidated = self._runtime.evaluate(
                    certified_request,
                    session,
                    evaluation_at=evaluation_started_at,
                    evaluation_phase=CertificationPhase.RESOLUTION,
                )
                evaluation_completed_at = self._context.certified_now(session)
                for name in self._runtime.certified_input_dependencies(certified_request.action):
                    validate_certified_input_evidence(
                        self._assembly.registry.certified_input(name),
                        certified_request.certified_inputs[name],
                        at=evaluation_completed_at,
                        evaluation_phase=CertificationPhase.RESOLUTION,
                    )
                if revalidated.effect is DecisionEffect.DENY:
                    decision = revalidated
                else:
                    decision = replace(
                        revalidated,
                        effect=DecisionEffect.ALLOW,
                        rule_id="resolution.approved",
                        reason=(
                            "explicit approval followed a current protected "
                            "revalidation with no deny"
                        ),
                    )
            else:
                certified_request = request
                evaluation_started_at = self._context.certified_now(session)
                evaluation_completed_at = evaluation_started_at
                decision = PolicyDecision(
                    effect=DecisionEffect.DENY,
                    policy_id="masugate.pending-resolution",
                    policy_version="",
                    rule_id="resolution.denied",
                    reason="the authoritative resolver denied the pending operation",
                    evaluated_policies=pending.evaluation.decision.evaluated_policies,
                    policy_provenance=pending.evaluation.decision.policy_provenance,
                )
            evaluation = AuthorizationEvaluation(
                phase=CertificationPhase.RESOLUTION,
                evaluated_at=evaluation_completed_at,
                decision=decision,
                certified_inputs=certified_request.certified_inputs,
            )
            effect_binding: ProtectedExecutionBinding | None = None
            if decision.effect is DecisionEffect.ALLOW:
                if assembled.effect_owner == "communications":
                    self._communications._record_delivery_for_request_in_session(
                        session,
                        certified_request,
                    )
                effect_binding = self._protected_binding(
                    certified_request,
                    evaluation,
                    protected_scopes,
                    resolution=resolution,
                )
                self._effect_outbox.record_in_session(session, effect_binding)
            self._effect_outbox.record_outcome_in_session(
                session,
                certified_request,
                evaluation,
                evaluation_started_at=evaluation_started_at,
                evaluation_completed_at=evaluation_completed_at,
                effect_committed=effect_binding is not None,
                resolution=resolution,
            )
            durable_resolution: dict[str, JsonValue] = {
                **resolution,
                "authorization_evaluation": authorization_evaluation_payload(evaluation),
            }
            self._effect_outbox.resolve_pending_in_session(
                session,
                pending,
                durable_resolution,
            )
            return (
                OperationalExecutionResult(
                    request_digest=request_binding_digest(pending.request),
                    protected_scopes=protected_scopes,
                    protected_at=pending.request.timestamp,
                    request_time=pending.request.timestamp,
                    decision=decision,
                    authorization_evaluation=evaluation,
                    evaluation_started_at=evaluation_started_at,
                    evaluation_completed_at=evaluation_completed_at,
                    receipt=None,
                    replayed=False,
                    status=OperationStatus.DENIED,
                    resolution_evidence=resolution,
                ),
                effect_binding,
            )

    async def resolve_pending(
        self,
        pending_id: str,
        *,
        authorization: str,
        approved: bool,
        evidence: Mapping[str, JsonValue] | None = None,
    ) -> OperationalExecutionResult:
        """Authenticate a scoped resolver, commit its decision, then dispatch."""

        if not authorization or authorization.strip() != authorization:
            raise OperationalLimitError("operational resolver authorization is invalid")
        presented = hashlib.sha256(authorization.encode("utf-8")).hexdigest()
        credential = next(
            (
                candidate
                for candidate in self.resolver_credentials
                if hmac.compare_digest(candidate.token_sha256, presented)
            ),
            None,
        )
        if credential is None:
            raise OperationalLimitError("operational resolver authorization is invalid")

        if pending_id.startswith("refpending:"):
            located_principal = (
                await self._effect_outbox.load_pending(pending_id)
            ).request.principal.id
        else:
            located_principal = (await self._limits.load_pending(pending_id)).request.principal.id
        if located_principal not in credential.principal_ids:
            raise OperationalLimitError(
                "operational resolver is not authorized for the pending principal"
            )

        if pending_id.startswith("refpending:"):
            result, binding = await self._resolve_reference_pending_admission(
                pending_id,
                approved=approved,
                actor_id=credential.resolver_id,
                evidence=evidence,
            )
        else:
            result, binding = await self._resolve_pending_admission(
                pending_id,
                approved=approved,
                actor_id=credential.resolver_id,
                evidence=evidence,
            )
        return await self._dispatch_result(result, binding)

    @property
    def claims(self) -> FileWorkspaceClaims:
        return self._claims

    @property
    def communications(self) -> CommunicationsProvider:
        return self._communications

    @property
    def approval(self) -> ApprovalStateProvider:
        return self._approval

    @property
    def limits(self) -> OperationalLimitsProvider:
        return self._limits

    @property
    def privacy(self) -> PrivacyContextProvider:
        return self._privacy

    @property
    def regulatory(self) -> RegulatoryContextProvider:
        return self._regulatory

    @property
    def customer_intent(self) -> CustomerIntentProvider:
        return self._customer_intent

    @property
    def catalog(self) -> PolicyCatalog:
        return self._catalog

    @property
    def assembly(self) -> ProviderAssembly:
        return self._assembly

    async def reference_effect_count(self, action: str) -> int:
        """Return durable effects from the bounded connector for conformance."""

        assembled = self._assembly.action(action)
        if assembled.connector_id is None:
            raise OperationalLimitError("action has no reference effect connector")
        connector = self._effect_connectors.get(assembled.connector_id)
        if connector is None:
            raise OperationalLimitError("action does not use the bounded reference connector")
        return await connector.effect_count(action=action)


__all__ = [
    "OperationalExecutionResult",
    "OperationalResolverCredential",
    "ReferenceOperationalResource",
    "reference_adversarial_catalog",
    "reference_certified_context_policy",
    "reference_complete_operational_catalog",
    "reference_customer_intent_catalog",
    "reference_customer_intent_policy",
    "reference_operational_limits_catalog",
    "reference_privacy_context_catalog",
    "reference_privacy_context_policy",
    "reference_regulatory_context_catalog",
    "reference_regulatory_context_policy",
]
