"""Bounded reference spend reference service for the protected spend vertical.

``ReferenceSpendResource`` is a deployment-owned composition, not reusable
``masugate`` or ``masugated`` behavior.  It authenticates already-issued MasuGate action
credentials, validates the OpenClaw reference fleet, and delegates every
purchase transition to the framework-neutral spend provider.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
from collections.abc import AsyncIterator, Collection, Mapping
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Annotated, cast

from fastapi import FastAPI, Header, Request
from fastapi.responses import JSONResponse

from masugate.catalog import PolicyCatalog, load_bundle
from masugate.errors import ContractError
from masugate.language import PolicyCompiler, compiled_policy_version
from masugate.model import Duration, JsonValue, PolicyProvenance, Scalar, ViewRead
from masugate.policy import PolicyRuntime, PolicySet
from masugate.protected_execution import (
    PostgresProtectedExecutionStore,
    ProtectedExecutionAuthority,
    ProtectedExecutionRunner,
    protected_execution_audit,
)
from masugate.masugated.app import (
    ActionBody,
    ActionOwnerBinding,
    ResolveBody,
    _adapter_invocation_digest,
)
from masugate.provider_assembly import ProviderAssembly, assemble_provider_domain
from masugate.providers import (
    PostgresSpendOutboxStore,
    ReferencePurchaseApi,
    ReferencePurchaseConnector,
    SpendEntitlement,
    SpendEntitlementState,
    SpendOperation,
    SpendOperationStatus,
    SpendPolicy,
    SpendPurchaseRequest,
    SpendPurchaseService,
    SpendRecoveryError,
)
from masugate.providers.spend import SpendConflictError
from masugate_openclaw_reference.release import ensure_reference_schema_for_store

_FLEET_AGENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,254}$", re.ASCII)
_CREDENTIAL_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,254}$", re.ASCII)


class _Unauthorized(Exception):
    """Authentication or server-required assertion failed."""


def _error(code: str, message: str) -> dict[str, JsonValue]:
    return {"error": {"code": code, "message": message}}


def _reference_agents(raw_agents: object, *, context: str) -> dict[str, str]:
    if not isinstance(raw_agents, Mapping) or not raw_agents:
        raise ValueError(f"{context} must be a non-empty mapping")
    agents: dict[str, str] = {}
    for agent_id, environment_name in raw_agents.items():
        if not isinstance(agent_id, str) or _FLEET_AGENT_ID.fullmatch(agent_id) is None:
            raise ValueError(f"{context} agent ids must be canonical")
        if (
            not isinstance(environment_name, str)
            or _CREDENTIAL_ENV_NAME.fullmatch(environment_name) is None
        ):
            raise ValueError(f"{context} credential environment names must be canonical")
        agents[agent_id] = environment_name
    return agents


def validate_openclaw_reference_roster(
    roster: Mapping[str, object],
    principals: Mapping[str, Mapping[str, Scalar]],
    token_principals: Mapping[str, str],
    *,
    environment: Mapping[str, str | None],
    plugin_config: Mapping[str, object] | None = None,
) -> dict[str, str]:
    """Fail closed unless the bounded OpenClaw fleet has one credential identity."""

    if set(roster) != {"agents"}:
        raise ValueError("OpenClaw reference roster must contain exactly an agents mapping")
    agents = _reference_agents(roster["agents"], context="OpenClaw reference roster agents")
    if plugin_config is not None:
        plugin_agents = _reference_agents(
            plugin_config.get("agents"), context="OpenClaw plugin configuration agents"
        )
        if plugin_agents != agents:
            raise ValueError("OpenClaw reference roster does not match plugin credential bindings")
    if len(set(agents.values())) != len(agents):
        raise ValueError("OpenClaw reference roster reuses a credential environment binding")
    credentials: dict[str, str] = {}
    for agent_id, environment_name in agents.items():
        credential = environment.get(environment_name)
        if not isinstance(credential, str) or not credential or credential.strip() != credential:
            raise ValueError("OpenClaw reference roster is missing a non-empty action credential")
        credentials[agent_id] = credential
    if len(set(credentials.values())) != len(credentials):
        raise ValueError("OpenClaw reference roster reuses an action credential secret")
    expected_principals = {f"openclaw:{agent_id}" for agent_id in agents}
    configured_principals = {
        principal_id for principal_id in principals if principal_id.startswith("openclaw:")
    }
    if configured_principals != expected_principals:
        raise ValueError("OpenClaw reference roster does not match certified principals")
    adapter_invocations = {
        principal_id
        for principal_id, attributes in principals.items()
        if attributes.get("masugate_require_adapter_invocation") is True
    }
    if adapter_invocations != expected_principals:
        raise ValueError("OpenClaw reference roster does not match adapter-invocation principals")
    if any(
        principals[principal_id].get("masugate_operator") is True
        for principal_id in expected_principals
    ):
        raise ValueError("OpenClaw fleet agents cannot be operator principals")
    expected_tokens = {credentials[agent_id]: f"openclaw:{agent_id}" for agent_id in agents}
    configured_tokens = {
        token: principal_id
        for token, principal_id in token_principals.items()
        if principal_id.startswith("openclaw:")
    }
    if configured_tokens != expected_tokens:
        raise ValueError("OpenClaw reference roster does not match action credential bindings")
    if plugin_config is not None and "nativeApproval" in plugin_config:
        native_approval = plugin_config["nativeApproval"]
        if not isinstance(native_approval, Mapping) or set(native_approval) != {
            "resolverTokenEnv",
            "timeoutMs",
        }:
            raise ValueError("OpenClaw native approval configuration is malformed")
        token_env = native_approval["resolverTokenEnv"]
        timeout_ms = native_approval["timeoutMs"]
        if (
            not isinstance(token_env, str)
            or _CREDENTIAL_ENV_NAME.fullmatch(token_env) is None
            or type(timeout_ms) is not int
            or timeout_ms != 600_000
        ):
            raise ValueError("OpenClaw native approval configuration must match the 10-minute hold")
        resolver_token = environment.get(token_env)
        if (
            not isinstance(resolver_token, str)
            or not resolver_token
            or resolver_token.strip() != resolver_token
            or resolver_token in credentials.values()
        ):
            raise ValueError("OpenClaw native approval resolver needs a distinct credential")
        resolver_principal = token_principals.get(resolver_token)
        resolver_attributes = (
            None if resolver_principal is None else principals.get(resolver_principal)
        )
        if resolver_attributes is None or resolver_attributes.get("masugate_operator") is not True:
            raise ValueError("OpenClaw native approval resolver must bind a certified operator")
    return agents


def reference_spend_catalog() -> PolicyCatalog:
    """Load the packaged, bounded owner policy for the reference spend slice."""

    root = Path(str(files("masugate.catalog").joinpath("reference_spend")))
    return PolicyCatalog(bundles=(load_bundle(root),))


@dataclass
class ReferenceSpendResource:
    """One SDK-free reference composition around the spend provider.

    The OpenClaw-specific fleet check happens in this deployment package before
    construction. This object repeats the request-time subject/owner and
    canonical adapter-provenance boundary so a bearer token cannot silently
    act as another agent or strip the host invocation assertion.
    """

    service: SpendPurchaseService
    principals: Mapping[str, Mapping[str, Scalar]]
    token_principals: Mapping[str, str]
    operator_principals: Collection[str] = ()
    adapter_invocation_principals: Collection[str] = ()
    policy_catalog: PolicyCatalog | None = None
    recovery_interval_seconds: float = 1.0
    _principals: dict[str, dict[str, Scalar]] = field(init=False, repr=False)
    _tokens: dict[str, str] = field(init=False, repr=False)
    _operators: frozenset[str] = field(init=False, repr=False)
    _actions: frozenset[str] = field(init=False, repr=False)
    _assertions: frozenset[str] = field(init=False, repr=False)
    _catalog: PolicyCatalog = field(init=False, repr=False)
    _assembly: ProviderAssembly = field(init=False, repr=False)
    _owner: ActionOwnerBinding = field(init=False, repr=False)
    _action: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._principals = {
            principal_id: dict(attributes) for principal_id, attributes in self.principals.items()
        }
        if not self._principals:
            raise ValueError("reference resource needs at least one certified principal")
        if any(
            not isinstance(principal_id, str)
            or not principal_id
            or principal_id.strip() != principal_id
            for principal_id in self._principals
        ):
            raise ValueError("reference principals need canonical non-empty identifiers")
        self._tokens = {}
        for token, principal_id in self.token_principals.items():
            if (
                not isinstance(token, str)
                or not token
                or token.strip() != token
                or principal_id not in self._principals
            ):
                raise ValueError("reference token mapping is malformed")
            self._tokens[token] = principal_id
        connector_fingerprint = self.service.connector_credential_fingerprint
        connector_manifest = self.service.connector_credential_manifest
        if connector_fingerprint is not None:
            if connector_manifest is None:
                raise ValueError(
                    "credentialed reference connector requires a shared credential manifest"
                )
            actual_bearer_fingerprints = tuple(
                sorted(hashlib.sha256(token.encode("utf-8")).hexdigest() for token in self._tokens)
            )
            if (
                connector_manifest.connector_credential_fingerprint != connector_fingerprint
                or connector_manifest.masugate_bearer_credential_fingerprints
                != actual_bearer_fingerprints
            ):
                raise ValueError(
                    "reference credential manifest does not match the configured "
                    "MasuGate credentials"
                )
        elif connector_manifest is not None:
            raise ValueError("local reference connector cannot carry a network credential manifest")
        if any(self.service.connector_credential_matches(token) for token in self._tokens):
            raise ValueError(
                "reference connector credential must be distinct from every "
                "MasuGate bearer credential"
            )
        certified_operators = frozenset(
            principal_id
            for principal_id, attributes in self._principals.items()
            if attributes.get("masugate_operator") is True
        )
        requested_operators = frozenset(self.operator_principals)
        if requested_operators != certified_operators:
            raise ValueError(
                "reference operator principals must exactly match certified "
                "masugate_operator identities"
            )
        self._operators = certified_operators
        certified_actions = frozenset(
            principal_id
            for principal_id, attributes in self._principals.items()
            if attributes.get("masugate_require_adapter_invocation") is True
        )
        requested_adapter_invocations = frozenset(self.adapter_invocation_principals)
        if requested_adapter_invocations and requested_adapter_invocations != certified_actions:
            raise ValueError(
                "reference action principals must exactly match certified "
                "adapter invocation identities"
            )
        if not certified_actions:
            raise ValueError("reference resource needs at least one adapter invocation principal")
        self._actions = certified_actions
        self._assertions = certified_actions
        if self._operators & self._assertions:
            raise ValueError("reference fleet action principals cannot be operators")
        if (
            type(self.recovery_interval_seconds) not in {int, float}
            or self.recovery_interval_seconds <= 0
            or self.recovery_interval_seconds > 60
        ):
            raise ValueError("reference recovery interval must be between zero and sixty seconds")

        packaged = reference_spend_catalog()
        if self.policy_catalog is not None and (
            len(self.policy_catalog.bundles) != 1
            or len(packaged.bundles) != 1
            or self.policy_catalog.bundles[0].digest != packaged.bundles[0].digest
        ):
            raise ValueError("reference spend resource accepts only the packaged policy artifact")
        self._catalog = packaged if self.policy_catalog is None else self.policy_catalog
        spend_policies = tuple(
            (bundle, policy)
            for bundle in self._catalog.bundles
            for policy in bundle.policies
            if policy.action == "spend.purchase"
        )
        if len(spend_policies) != 1:
            raise ValueError("reference resource requires exactly one spend.purchase policy")
        if self.service.policy.approval_threshold_cents != 500:
            raise ValueError(
                "the packaged reference spend policy requires a 500-cent ask-first threshold"
            )
        if self.service.policy.approval_timeout_seconds != 600:
            raise ValueError(
                "the packaged reference spend policy requires a 10-minute approval hold"
            )
        self.service.bind_catalog_policy(self._catalog)
        module = self.service.provider_module()
        self._assembly = assemble_provider_domain(self._catalog, (module,))
        bundle, loaded_policy = spend_policies[0]
        compiled = PolicyCompiler(
            self._assembly.registry,
            principal_attributes=dict(bundle.principal_attributes),
        ).compile(loaded_policy.definition)
        policy_set = PolicySet()
        policy_set.add(
            compiled,
            provenance=PolicyProvenance(
                policy_id=loaded_policy.policy_id,
                policy_declared_version=loaded_policy.version,
                policy_runtime_version=compiled_policy_version(compiled),
                policy_digest=loaded_policy.semantic_sha256,
                bundle_id=bundle.bundle_id,
                bundle_version=bundle.version,
                bundle_digest=bundle.digest,
                layer=bundle.layer.value,
                mode=bundle.mode.value,
            ),
        )
        self.service.bind_policy_runtime(PolicyRuntime(self._assembly.registry, policy_set))
        if len(self._assembly.actions) != 1 or len(module.effects) != 1:
            raise ValueError("reference spend module must expose exactly one effect")
        binding = module.effects[0]
        self._action = binding.contract.action
        if self.service.protected_authority != self._assembly.protected_execution_authority(
            self._action
        ):
            raise ValueError("reference protected runner does not match assembled spend owner")
        self._owner = ActionOwnerBinding(
            provider_id=module.identity.provider_id,
            position=binding.position,
            connector_id=binding.connector_id,
        )

    async def initialize(self) -> None:
        # The release marker is checked before the spend or protected-execution
        # stores can create or alter a table. A legacy development database is
        # therefore refused before this service could begin serving traffic.
        await ensure_reference_schema_for_store(self.service.store)
        await self.service.initialize()
        # A persisted provider outbox is the only dispatch source.  Startup
        # recovery therefore closes the crash window before this app accepts a
        # new reference request.
        await self.service.recover()
        # The native Gateway presentation is not durable.  Expire its
        # MasuGate-owned hold from the persisted entitlement timestamp before the
        # restarted deployment exposes a new pending list or resolution path.
        await self.service.expire_pending()

    async def close(self) -> None:
        await self.service.close()

    @property
    def action(self) -> str:
        return self._action

    @property
    def owner(self) -> ActionOwnerBinding:
        return self._owner

    @property
    def catalog(self) -> PolicyCatalog:
        return self._catalog

    @property
    def assembly(self) -> ProviderAssembly:
        return self._assembly

    def authenticate(self, authorization: str | None) -> str:
        if authorization is None or not authorization.startswith("Bearer "):
            raise _Unauthorized("missing bearer token")
        token = authorization.removeprefix("Bearer ")
        if not token:
            raise _Unauthorized("missing bearer token")
        try:
            return self._tokens[token]
        except KeyError as exc:
            raise _Unauthorized("invalid bearer token") from exc

    def team_for(self, principal_id: str) -> str:
        team = self._principals[principal_id].get("team")
        if type(team) is not str:
            raise ContractError("reference action principal has no certified team identity")
        return team

    def principal_attributes(self, principal_id: str) -> dict[str, Scalar]:
        try:
            return dict(self._principals[principal_id])
        except KeyError as exc:
            raise _Unauthorized("principal is not certified by the reference fleet") from exc

    def can_resolve(self, principal_id: str) -> bool:
        return principal_id in self._operators

    def can_act(self, principal_id: str) -> bool:
        """Only roster-certified action credentials may submit purchases."""

        return principal_id in self._actions

    def adapter_invocation_required(self, principal_id: str) -> bool:
        return principal_id in self._assertions


def build_postgres_reference_spend_resource(
    *,
    dsn: str,
    purchase_api: ReferencePurchaseApi,
    policy: SpendPolicy,
    worker_id: str,
    principals: Mapping[str, Mapping[str, Scalar]],
    token_principals: Mapping[str, str],
    fleet_roster: Mapping[str, object],
    plugin_config: Mapping[str, object],
    environment: Mapping[str, str | None] | None = None,
    operator_principals: Collection[str] = (),
    adapter_invocation_principals: Collection[str] = (),
) -> ReferenceSpendResource:
    """Compose the PostgreSQL-backed reference spend deployment resource.

    The spend entitlement/outbox store and generic protected-execution store
    share one PostgreSQL DSN. Before building stores, the factory compares the
    profile roster, the actual plugin credential-environment map, certified
    principals, and bearer token bindings. The reference purchase API remains
    a separate idempotent/status-queryable service boundary; no connector call
    happens in a policy-state transaction.
    """

    from masugate.masugated.cli import _validated_principals, _validated_tokens

    certified_principals = _validated_principals(cast(Mapping[str, object], principals))
    certified_tokens = _validated_tokens(
        cast(Mapping[str, object], token_principals),
        set(certified_principals),
    )

    fleet_agents = validate_openclaw_reference_roster(
        fleet_roster,
        certified_principals,
        certified_tokens,
        environment=os.environ if environment is None else environment,
        plugin_config=plugin_config,
    )
    certified_operators = frozenset(
        principal_id
        for principal_id, attributes in certified_principals.items()
        if attributes.get("masugate_operator") is True
    )
    expected_actions = frozenset(f"openclaw:{agent_id}" for agent_id in fleet_agents)
    certified_actions = frozenset(
        principal_id
        for principal_id, attributes in certified_principals.items()
        if attributes.get("masugate_require_adapter_invocation") is True
    )
    if certified_actions != expected_actions:
        raise ValueError(
            "OpenClaw reference action principals must exactly match the certified fleet roster"
        )
    if frozenset(operator_principals) != certified_operators:
        raise ValueError(
            "OpenClaw reference operators must exactly match certified "
            "masugate_operator identities"
        )
    if (
        adapter_invocation_principals
        and frozenset(adapter_invocation_principals) != expected_actions
    ):
        raise ValueError(
            "OpenClaw reference adapter invocations must exactly match the certified fleet roster"
        )

    service = SpendPurchaseService(
        PostgresSpendOutboxStore(dsn, policy),
        ProtectedExecutionRunner(
            PostgresProtectedExecutionStore(dsn),
            ReferencePurchaseConnector(purchase_api),
            ProtectedExecutionAuthority(
                action="spend.purchase",
                provider_identity=policy.provider_identity,
                coordination_domain_id="masugate.spend.reference.domain.v1",
                connector_id="reference-purchase-v1",
            ),
            worker_id=worker_id,
        ),
        policy,
    )
    return ReferenceSpendResource(
        service=service,
        principals=certified_principals,
        token_principals=certified_tokens,
        operator_principals=certified_operators,
        adapter_invocation_principals=expected_actions,
    )


def _protected_payload(operation: SpendOperation) -> dict[str, JsonValue] | None:
    record = operation.protected
    if record is None:
        return None
    payload: dict[str, JsonValue] = {
        "binding_digest": record.binding_digest,
        "dispatch_started": record.dispatch_started,
        "entitlement_state": record.entitlement_state.value,
        "execution_id": record.execution_id,
        "external_operation_id": record.external_operation_id,
        "fence_token": record.fence_token,
        "lease": (
            None
            if record.lease_owner is None
            else {
                "expires_at": (
                    None if record.lease_expires_at is None else record.lease_expires_at.isoformat()
                ),
                "owner": record.lease_owner,
            }
        ),
        "status": record.status.value,
    }
    if record.receipt is not None:
        payload["receipt"] = record.receipt.payload_json()
    return payload


def _json_scalar(value: Scalar | Duration) -> JsonValue:
    return value.seconds if type(value) is Duration else cast(JsonValue, value)


def _operation_payload(operation: SpendOperation) -> dict[str, JsonValue]:
    entitlement = operation.entitlement
    if entitlement is None:  # Defensive: durable capacity denials have one too.
        return {"reason": operation.reason}
    payload: dict[str, JsonValue] = {
        "amount_cents": entitlement.request.amount_cents,
        "authorization_digest": entitlement.authorization_digest,
        "authorization": {
            "effect": entitlement.authorization.effect.value,
            "evaluated_policies": [
                {"policy_id": policy_id, "policy_version": policy_version}
                for policy_id, policy_version in entitlement.authorization.evaluated_policies
            ],
            "policy_id": entitlement.authorization.policy_id,
            "policy_version": entitlement.authorization.policy_version,
            "reads": [
                {
                    "arguments": [_json_scalar(argument) for argument in read.arguments],
                    "function": read.function,
                    "scope": read.scope,
                    "value": _json_scalar(read.value),
                    "version": read.version,
                }
                for read in entitlement.authorization.reads
            ],
            "reason": entitlement.authorization.reason,
            "rule_id": entitlement.authorization.rule_id,
        },
        "budget_version": entitlement.budget_version,
        "entitlement_id": entitlement.entitlement_id,
        "entitlement_state": entitlement.state.value,
        "merchant_id": entitlement.request.merchant_id,
        "request_ref": entitlement.request.request_ref,
        "team_id": entitlement.request.team_id,
    }
    if entitlement.resolution is not None:
        payload["resolution"] = entitlement.resolution.payload()
    if operation.handoff is not None:
        payload["handoff"] = {
            "binding_digest": operation.handoff.binding.digest,
            "state": operation.handoff.state.value,
        }
    protected = _protected_payload(operation)
    if protected is not None:
        payload["protected_execution"] = protected
    return payload


def _operation_json(
    operation: SpendOperation, resource: ReferenceSpendResource
) -> dict[str, JsonValue]:
    entitlement = operation.entitlement
    if entitlement is None:
        raise ContractError("reference purchase operation lacks a durable identity")
    payload = _operation_payload(operation)
    payload["policy_configuration_digest"] = entitlement.configuration_digest
    provenance = entitlement.authorization.policy_provenance
    if len(provenance) == 1:
        payload["policy_catalog"] = {
            "bundle_digest": provenance[0].bundle_digest,
            "policy_digest": provenance[0].policy_digest,
        }
    base: dict[str, JsonValue] = {
        "audit_ref": f"/v1/audit/{entitlement.operation_id}",
        "operation_id": entitlement.operation_id,
        "payload": payload,
        "replayed": operation.replayed,
    }
    if operation.status is SpendOperationStatus.COMMITTED:
        return {
            **base,
            "status": "committed",
            "decision": {
                "effect": "allow",
                "policy_id": entitlement.authorization.policy_id,
                "policy_version": entitlement.authorization.policy_version,
                "rule_id": (
                    entitlement.authorization.rule_id
                    if entitlement.authorization.effect.value == "allow"
                    else "approval.approved"
                ),
                "reason": operation.reason,
            },
        }
    if operation.status is SpendOperationStatus.DENIED:
        if entitlement.state is SpendEntitlementState.DENIED:
            rule_id = entitlement.authorization.rule_id
            reason = entitlement.authorization.reason
        elif (
            entitlement.resolution is not None and entitlement.resolution.kind == "automatic-expiry"
        ):
            rule_id = "approval.expired"
            reason = operation.reason
        elif entitlement.resolution is not None and not entitlement.resolution.approved:
            rule_id = "approval.rejected"
            reason = operation.reason
        elif operation.protected is not None:
            rule_id = "connector.failed"
            reason = operation.reason
        else:
            rule_id = "entitlement.released"
            reason = operation.reason
        return {
            **base,
            "status": "denied",
            "decision": {
                "effect": "deny",
                "policy_id": entitlement.authorization.policy_id,
                "policy_version": entitlement.authorization.policy_version,
                "rule_id": rule_id,
                "reason": reason,
            },
        }
    if operation.status is SpendOperationStatus.PENDING:
        return {
            **base,
            "status": "pending",
            "pending_id": entitlement.pending_id,
            "decision": {
                "effect": "escalate",
                "policy_id": entitlement.authorization.policy_id,
                "policy_version": entitlement.authorization.policy_version,
                "rule_id": "ask_first.pending",
                "reason": operation.reason,
            },
        }
    if operation.status in {
        SpendOperationStatus.IN_PROGRESS,
        SpendOperationStatus.OUTCOME_UNKNOWN,
    }:
        return {
            **base,
            "status": operation.status.value,
            "decision": None,
        }
    raise ContractError("reference purchase operation has an unsupported status")


def _pending_json(
    entitlement: SpendEntitlement,
    resource: ReferenceSpendResource,
    *,
    include_recorded_resolution: bool = False,
) -> dict[str, JsonValue]:
    """Encode one durable hold as the shared pending-locator contract.

    The pending *list* excludes a record once a native decision is durable.
    A direct locator lookup may still return that record between decision
    persistence and its first outbox handoff so a restarted pinned Gateway can
    rehydrate the exact decision from the bound audit record instead of
    presenting native approval a second time.
    """

    if entitlement.authorization.effect.value != "escalate":
        raise ContractError("only an escalated spend entitlement may be listed as pending")
    if entitlement.resolution is not None and not include_recorded_resolution:
        raise ContractError("a resolved spend entitlement may not be listed as pending")
    return {
        "pending_id": entitlement.pending_id,
        "operation_id": entitlement.operation_id,
        "principal_id": entitlement.request.principal_id,
        "action": resource.action,
        "args": {
            "amount_cents": entitlement.request.amount_cents,
            "merchant_id": entitlement.request.merchant_id,
            "request_ref": entitlement.request.request_ref,
        },
        "created_at": entitlement.created_at.isoformat(),
        "decision": {
            "effect": "escalate",
            "policy_id": entitlement.authorization.policy_id,
            "policy_version": entitlement.authorization.policy_version,
            "rule_id": "ask_first.pending",
            "reason": "approval required before protected dispatch",
        },
        "audit_ref": f"/v1/audit/{entitlement.operation_id}",
    }


async def _locate_reference_pending(
    resource: ReferenceSpendResource,
    entitlement: SpendEntitlement,
) -> SpendOperation:
    """Read one immutable spend locator without admitting or dispatching work."""

    return await resource.service.locate_pending(
        entitlement.pending_id,
        principal_id=entitlement.request.principal_id,
        action=resource.action,
        arguments={
            "amount_cents": entitlement.request.amount_cents,
            "merchant_id": entitlement.request.merchant_id,
            "request_ref": entitlement.request.request_ref,
        },
    )


def _cancellation_json(
    pending_id: str,
    operation: SpendOperation,
    resource: ReferenceSpendResource,
    *,
    accepted: bool,
) -> dict[str, JsonValue]:
    """Encode a bounded cancellation acknowledgement for one pending locator."""

    entitlement = operation.entitlement
    if entitlement is None:
        raise ContractError("reference cancellation lost its durable entitlement")
    payload: dict[str, JsonValue] = {
        "kind": "cancellation",
        "locator": {"operation_id": entitlement.operation_id, "pending_id": pending_id},
        "accepted": accepted,
    }
    if not accepted and operation.status in {
        SpendOperationStatus.COMMITTED,
        SpendOperationStatus.DENIED,
    }:
        payload["terminal_result"] = _operation_json(operation, resource)
    return payload


def _policy_provenance_json(item: PolicyProvenance) -> dict[str, JsonValue]:
    return {
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


def _view_read_json(read: ViewRead) -> dict[str, JsonValue]:
    return {
        "arguments": [_json_scalar(argument) for argument in read.arguments],
        "function": read.function,
        "latency_ms": read.latency_ms,
        "scope": read.scope,
        "value": _json_scalar(read.value),
        "version": read.version,
    }


def _audit_json(
    operation: SpendOperation,
    resource: ReferenceSpendResource,
    protected_audit: dict[str, JsonValue] | None,
) -> dict[str, JsonValue]:
    """Project the spend operation into the standard protocol Receipt shape."""

    entitlement = operation.entitlement
    if entitlement is None:
        raise ContractError("reference purchase audit lacks a durable entitlement")
    request_args: dict[str, JsonValue] = {
        "amount_cents": entitlement.request.amount_cents,
        "merchant_id": entitlement.request.merchant_id,
        "request_ref": entitlement.request.request_ref,
    }
    action_result = _operation_json(operation, resource)
    result_decision = action_result["decision"]
    audit_decision: dict[str, JsonValue] | None
    if result_decision is None:
        audit_decision = None
    else:
        decided = cast(dict[str, JsonValue], result_decision)
        audit_decision = {
            "effect": decided["effect"],
            "reason": decided["reason"],
            "rule_id": decided["rule_id"],
        }
    reads: list[JsonValue] = [_view_read_json(read) for read in entitlement.authorization.reads]
    provenance: list[JsonValue] = [
        _policy_provenance_json(item) for item in entitlement.authorization.policy_provenance
    ]
    evaluated: list[JsonValue] = [
        {"policy_id": policy_id, "policy_version": policy_version}
        for policy_id, policy_version in entitlement.authorization.evaluated_policies
    ]
    admission_decision: dict[str, JsonValue] = {
        "effect": entitlement.authorization.effect.value,
        "evaluated_policies": evaluated,
        "policy_id": entitlement.authorization.policy_id,
        "policy_provenance": provenance,
        "policy_version": entitlement.authorization.policy_version,
        "reads": reads,
        "reason": entitlement.authorization.reason,
        "rule_id": entitlement.authorization.rule_id,
    }
    terminal_serialization: dict[str, JsonValue] | None = None
    if operation.status in {SpendOperationStatus.COMMITTED, SpendOperationStatus.DENIED}:
        mechanism_denial = (
            operation.status is SpendOperationStatus.DENIED
            and entitlement.authorization.effect.value != "deny"
        )
        terminal_serialization = {
            "authorization_basis": (
                "mechanism-denial"
                if mechanism_denial
                else (
                    "preserved-admission-evaluation"
                    if entitlement.resolution is not None
                    else "admission-evaluation"
                )
            ),
            "kind": (
                "effect-commit"
                if operation.status is SpendOperationStatus.COMMITTED
                else "denial-record"
            ),
            "provider_atomic": False,
            "recorded_at": entitlement.updated_at.isoformat(),
        }
        if not mechanism_denial:
            terminal_serialization["evaluation_at"] = entitlement.created_at.isoformat()
            terminal_serialization["evaluation_phase"] = "admission"
    principal_attributes: dict[str, JsonValue] = {
        name: cast(JsonValue, value)
        for name, value in resource.principal_attributes(entitlement.request.principal_id).items()
    }
    request_json: dict[str, JsonValue] = {
        "action": resource.action,
        "args": request_args,
        "idempotency_key": entitlement.request.idempotency_key,
        "principal": {
            "attributes": principal_attributes,
            "id": entitlement.request.principal_id,
        },
        "request_time": entitlement.created_at.isoformat(),
        "timestamp": entitlement.created_at.isoformat(),
        "trace_id": entitlement.request.tool_call_id,
    }
    if entitlement.request.adapter_invocation_digest is not None:
        request_json["adapter_invocation_digest"] = entitlement.request.adapter_invocation_digest
    policy_json: dict[str, JsonValue] = {
        "evaluated_policies": evaluated,
        "evaluated_policy_provenance": provenance,
        "policy_id": entitlement.authorization.policy_id,
        "policy_version": entitlement.authorization.policy_version,
    }
    if len(provenance) == 1:
        policy_json["catalog"] = {
            "bundle_digest": cast(dict[str, JsonValue], provenance[0])["bundle_digest"],
            "policy_digest": cast(dict[str, JsonValue], provenance[0])["policy_digest"],
        }
    authorization_evaluations: list[JsonValue] = [
        {
            "certified_inputs": [],
            "decision": admission_decision,
            "evaluated_at": entitlement.created_at.isoformat(),
            "phase": "admission",
        }
    ]
    receipt: dict[str, JsonValue] = {
        "operation_id": entitlement.operation_id,
        "status": operation.status.value,
        "request": request_json,
        "policy": policy_json,
        "entitlement": {
            "authorization_digest": entitlement.authorization_digest,
            "entitlement_id": entitlement.entitlement_id,
        },
        "decision": audit_decision,
        "view_reads": reads,
        "authorization_evaluations": authorization_evaluations,
        "terminal_serialization": terminal_serialization,
        "effect": (
            {
                "action": resource.action,
                "args": request_args,
                "payload": _operation_payload(operation),
            }
            if operation.status is SpendOperationStatus.COMMITTED
            else None
        ),
        "recorded_at": entitlement.updated_at.isoformat(),
    }
    if entitlement.resolution is not None and entitlement.resolution.kind == "human":
        receipt["human_resolution"] = {
            "actor_id": entitlement.resolution.actor_id,
            "approved": entitlement.resolution.approved,
            "evidence": dict(entitlement.resolution.evidence),
            "resolved_at": entitlement.resolution.resolved_at.isoformat(),
        }
    elif entitlement.resolution is not None and entitlement.resolution.kind == "automatic-expiry":
        expires_at = entitlement.resolution.evidence.get("expires_at")
        reason = entitlement.resolution.evidence.get("reason")
        if type(expires_at) is not str or reason != "approval-window-expired":
            raise ContractError("automatic approval expiry evidence is malformed")
        receipt["automatic_expiry"] = {
            "expires_at": expires_at,
            "reason": reason,
        }
    if protected_audit is not None:
        receipt["protected_execution"] = protected_audit
    return receipt


def _spend_request(
    resource: ReferenceSpendResource,
    principal_id: str,
    body: ActionBody,
    *,
    adapter_invocation_digest: str | None,
) -> SpendPurchaseRequest:
    if body.action != resource.action:
        raise ContractError(f"undeclared reference action: {body.action}")
    expected = {"amount_cents", "merchant_id", "request_ref"}
    if set(body.args) != expected:
        raise ContractError(
            "spend.purchase requires exactly amount_cents, merchant_id, request_ref"
        )
    amount = body.args["amount_cents"]
    merchant = body.args["merchant_id"]
    request_ref = body.args["request_ref"]
    if type(amount) is not int or type(merchant) is not str or type(request_ref) is not str:
        raise ContractError("spend.purchase arguments have incorrect scalar types")
    tool_call_id = body.trace_id or f"tool:{body.idempotency_key}"
    return SpendPurchaseRequest(
        principal_id=principal_id,
        team_id=resource.team_for(principal_id),
        amount_cents=amount,
        merchant_id=merchant,
        request_ref=request_ref,
        idempotency_key=body.idempotency_key,
        tool_call_id=tool_call_id,
        adapter_invocation_digest=adapter_invocation_digest,
    )


def _validate_action_assertions(
    resource: ReferenceSpendResource,
    principal_id: str,
    *,
    masugate_expected_principal: str | None,
    masugate_expected_provider: str | None,
    masugate_expected_position: str | None,
    masugate_expected_connector: str | None,
) -> None:
    required = resource.adapter_invocation_required(principal_id)
    if required and masugate_expected_principal is None:
        raise _Unauthorized("missing required expected principal assertion")
    if masugate_expected_principal is not None and masugate_expected_principal != principal_id:
        raise _Unauthorized("bearer token principal does not match expected principal")
    asserted_owner = any(
        value is not None
        for value in (
            masugate_expected_provider,
            masugate_expected_position,
            masugate_expected_connector,
        )
    )
    if not (required or asserted_owner):
        return
    if (
        masugate_expected_provider != resource.owner.provider_id
        or masugate_expected_position != resource.owner.position.value
        or masugate_expected_connector != resource.owner.connector_id
    ):
        raise ContractError("action execution owner mismatch: spend.purchase")


def create_spend_reference_app(resource: ReferenceSpendResource) -> FastAPI:
    """Expose the bounded spend vertical on the established action protocol."""

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        stopped = asyncio.Event()
        worker: asyncio.Task[None] | None = None
        _app.state.spend_recovery_last_error = None

        async def recovery_worker() -> None:
            while not stopped.is_set():
                try:
                    await asyncio.wait_for(
                        stopped.wait(),
                        timeout=resource.recovery_interval_seconds,
                    )
                    continue
                except TimeoutError:
                    pass
                try:
                    await resource.service.expire_pending()
                    await resource.service.recover()
                    _app.state.spend_recovery_last_error = None
                except SpendRecoveryError as exc:
                    _app.state.spend_recovery_last_error = {
                        "error": type(exc).__name__,
                        "failures": [
                            {"execution_id": execution_id, "error": error}
                            for execution_id, error in exc.errors
                        ],
                        "message": str(exc),
                    }
                except Exception as exc:  # preserve service availability and expose evidence
                    _app.state.spend_recovery_last_error = {
                        "error": type(exc).__name__,
                        "message": str(exc),
                    }

        try:
            await resource.initialize()
            worker = asyncio.create_task(recovery_worker(), name="masugate-spend-recovery")
            yield
        finally:
            stopped.set()
            if worker is not None:
                worker.cancel()
                with suppress(asyncio.CancelledError):
                    await worker
            await resource.close()

    app = FastAPI(title="masugate-openclaw-reference", version="2.4.0", lifespan=lifespan)
    app.state.spend_recovery_last_error = None

    @app.exception_handler(_Unauthorized)
    async def unauthorized(_request: Request, exc: _Unauthorized) -> JSONResponse:
        return JSONResponse(status_code=401, content=_error("unauthorized", str(exc)))

    @app.exception_handler(ContractError)
    async def contract_error(_request: Request, exc: ContractError) -> JSONResponse:
        status = 404 if str(exc).startswith("unknown spend") else 409
        code = "not_found" if status == 404 else "resource_conflict"
        return JSONResponse(status_code=status, content=_error(code, str(exc)))

    @app.exception_handler(ValueError)
    async def value_error(_request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=400, content=_error("invalid_request", str(exc)))

    @app.post("/v1/actions")
    async def execute_action(
        body: ActionBody,
        authorization: Annotated[str | None, Header()] = None,
        masugate_expected_principal: Annotated[str | None, Header()] = None,
        masugate_expected_provider: Annotated[str | None, Header()] = None,
        masugate_expected_position: Annotated[str | None, Header()] = None,
        masugate_expected_connector: Annotated[str | None, Header()] = None,
    ) -> dict[str, JsonValue]:
        principal_id = resource.authenticate(authorization)
        if not resource.can_act(principal_id):
            raise _Unauthorized("principal is not authorized for spend.purchase")
        _validate_action_assertions(
            resource,
            principal_id,
            masugate_expected_principal=masugate_expected_principal,
            masugate_expected_provider=masugate_expected_provider,
            masugate_expected_position=masugate_expected_position,
            masugate_expected_connector=masugate_expected_connector,
        )
        if resource.adapter_invocation_required(principal_id) and body.adapter_invocation is None:
            raise ValueError("missing required adapter invocation assertion")
        adapter_invocation_digest = _adapter_invocation_digest(
            body.adapter_invocation,
            principal_id=principal_id,
            action=body.action,
            args=body.args,
        )
        operation = await resource.service.submit(
            _spend_request(
                resource,
                principal_id,
                body,
                adapter_invocation_digest=adapter_invocation_digest,
            )
        )
        return _operation_json(operation, resource)

    @app.get("/v1/health")
    async def health(
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, JsonValue]:
        resource.authenticate(authorization)
        last_error = app.state.spend_recovery_last_error
        return {
            "status": "ok" if last_error is None else "degraded",
            "spend_recovery": {"last_error": last_error},
        }

    @app.post("/v1/pending/{pending_id}/resolve")
    async def resolve_pending(
        pending_id: str,
        body: ResolveBody,
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, JsonValue]:
        principal_id = resource.authenticate(authorization)
        if not resource.can_resolve(principal_id):
            raise ContractError(f"unknown spend pending id: {pending_id}")
        await resource.service.expire_pending()
        operation = await resource.service.resolve_pending(
            pending_id,
            approved=body.approved,
            resolver_id=principal_id,
            evidence=body.evidence,
        )
        return _operation_json(operation, resource)

    @app.post("/v1/pending/{pending_id}/cancel")
    async def cancel_pending(
        pending_id: str,
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, JsonValue]:
        """Request an operator-only cancellation without native effect authority."""

        principal_id = resource.authenticate(authorization)
        if not resource.can_resolve(principal_id):
            raise ContractError(f"unknown spend pending id: {pending_id}")
        await resource.service.expire_pending()
        entitlement = await resource.service.store.get_entitlement_by_pending_id(pending_id)
        operation = await _locate_reference_pending(resource, entitlement)
        if operation.status is not SpendOperationStatus.PENDING:
            return _cancellation_json(pending_id, operation, resource, accepted=False)
        try:
            operation = await resource.service.resolve_pending(
                pending_id,
                approved=False,
                resolver_id=principal_id,
                evidence={"cancellation": "operator-requested"},
            )
        except SpendConflictError:
            # A different resolver won after the pending read. Re-read the
            # durable state instead of reporting this cancellation as accepted.
            entitlement = await resource.service.store.get_entitlement_by_pending_id(pending_id)
            if entitlement.resolution is None:
                raise
            operation = await _locate_reference_pending(resource, entitlement)
            return _cancellation_json(pending_id, operation, resource, accepted=False)
        return _cancellation_json(
            pending_id,
            operation,
            resource,
            accepted=not operation.replayed,
        )

    @app.get("/v1/pending")
    async def list_pending(
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, JsonValue]:
        principal_id = resource.authenticate(authorization)
        if not resource.can_act(principal_id) and not resource.can_resolve(principal_id):
            raise _Unauthorized("principal is not authorized to inspect pending approvals")
        await resource.service.expire_pending()
        pending = await resource.service.pending_entitlements(
            principal_id=None if resource.can_resolve(principal_id) else principal_id
        )
        return {
            "items": [_pending_json(entitlement, resource) for entitlement in pending],
            "next_cursor": pending[-1].pending_id if pending else "0",
        }

    @app.get("/v1/pending/{pending_id}", response_model=None)
    async def get_pending(
        pending_id: str,
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, JsonValue]:
        """Return one caller-owned locator, including its terminal replay.

        The native OpenClaw adapter keeps presentation state only in the
        pinned Gateway process.  After that process restarts, it may need to
        recover a settled locator without creating a new action or native
        approval.  This endpoint is that read-only recovery surface: it first
        checks the durable owner, then projects either the still-pending
        locator or the provider's existing terminal result.  It has no
        resolution or protected-effect authority.
        """

        principal_id = resource.authenticate(authorization)
        if not resource.can_act(principal_id) and not resource.can_resolve(principal_id):
            raise _Unauthorized("principal is not authorized to inspect pending approvals")
        entitlement = await resource.service.store.get_entitlement_by_pending_id(pending_id)
        if principal_id != entitlement.request.principal_id and not resource.can_resolve(
            principal_id
        ):
            raise ContractError(f"unknown spend pending id: {pending_id}")

        # Match the list endpoint's expiry behavior, then reload the complete
        # immutable locator through the service's no-create/no-dispatch query.
        await resource.service.expire_pending()
        operation = await _locate_reference_pending(resource, entitlement)
        terminal_entitlement = operation.entitlement
        if operation.status is SpendOperationStatus.PENDING:
            if terminal_entitlement is None:
                raise ContractError("reference pending lookup lost its durable entitlement")
            return {
                "kind": "pending",
                "pending": _pending_json(
                    terminal_entitlement,
                    resource,
                    include_recorded_resolution=True,
                ),
            }
        return {"kind": "terminal", "result": _operation_json(operation, resource)}

    @app.get("/v1/audit/{operation_id}")
    async def audit(
        operation_id: str,
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, JsonValue]:
        principal_id = resource.authenticate(authorization)
        entitlement = await resource.service.store.get_entitlement_by_operation_id(operation_id)
        if principal_id != entitlement.request.principal_id and not resource.can_resolve(
            principal_id
        ):
            raise ContractError(f"unknown spend operation id: {operation_id}")
        operation = await _locate_reference_pending(resource, entitlement)
        entitlement = operation.entitlement or entitlement
        protected_audit: dict[str, JsonValue] | None = None
        if operation.protected is not None:
            protected_audit = protected_execution_audit(
                operation.protected,
                await resource.service.protected_events(operation.protected.execution_id),
            )
        return _audit_json(operation, resource, protected_audit)

    return app


__all__ = [
    "ReferenceSpendResource",
    "build_postgres_reference_spend_resource",
    "create_spend_reference_app",
    "reference_spend_catalog",
    "validate_openclaw_reference_roster",
]
