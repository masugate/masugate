"""Async coordinator for policy-governed operations.

It evaluates policies, coordinates policy-state transitions, and records
receipts for terminal operations.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from collections.abc import Mapping
from contextlib import suppress
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime
from time import perf_counter
from types import MappingProxyType
from typing import cast

from masugate.certification import (
    certified_input_evidence_json,
    certify_observation,
    resolve_certified_input_observation,
    validate_certified_input_evidence,
)
from masugate.contracts import (
    CertifiedInputObservation,
    ContractRegistry,
    ReservationCapability,
    ResourceSession,
)
from masugate.errors import (
    CertificationError,
    ContractError,
    PolicyEvaluationError,
    PolicyValidationError,
    ResourceError,
    RetryableResourceError,
)
from masugate.language import ReservationEligibilityChecker
from masugate.model import (
    ActionRequest,
    AuthorizationEvaluation,
    CertificationPhase,
    CertifiedInputStability,
    DecisionEffect,
    JsonValue,
    OperationMetrics,
    OperationResult,
    OperationStatus,
    PendingOperation,
    PendingResolutionPlan,
    PolicyDecision,
    MasuGateMode,
    TypeName,
)
from masugate.policy import AsyncPolicyRuntime
from masugate.principals import PrincipalRegistry, UnknownPrincipalError
from masugate.resources.base import (
    AdmissionCertifier,
    AuthorizationEvaluationCertifier,
    GovernedResource,
    PendingOperationResource,
    ReservationResource,
    ScopedLockResource,
    ScopeHoldResource,
    encode_idempotency_scope,
)


@dataclass
class _MetricsDraft:
    policy_eval_ms: float = 0.0
    effect_exec_ms: float = 0.0
    transaction_ms: float = 0.0
    advisory_lock_wait_ms: float = 0.0
    reservation_create_ms: float = 0.0
    reservation_consume_ms: float = 0.0
    reservation_release_ms: float = 0.0
    retry_attempts: int = 0
    attempt_count: int = 1

    def to_metrics(self, total_latency_ms: float = 0.0) -> OperationMetrics:
        return OperationMetrics(
            total_latency_ms=total_latency_ms,
            policy_eval_ms=self.policy_eval_ms,
            effect_exec_ms=self.effect_exec_ms,
            transaction_ms=self.transaction_ms,
            advisory_lock_wait_ms=self.advisory_lock_wait_ms,
            reservation_create_ms=self.reservation_create_ms,
            reservation_consume_ms=self.reservation_consume_ms,
            reservation_release_ms=self.reservation_release_ms,
            retry_attempts=self.retry_attempts,
            attempt_count=self.attempt_count,
        )


class AsyncGovernedCoordinator:
    def __init__(
        self,
        registry: ContractRegistry,
        runtime: AsyncPolicyRuntime,
        resource: GovernedResource,
        principals: PrincipalRegistry,
        *,
        mode: MasuGateMode = MasuGateMode.TRANSACTION,
        action_modes: Mapping[str, MasuGateMode] | None = None,
        max_retries: int = 3,
    ) -> None:
        # Every product mode is governed, so the certified clock is mandatory:
        # without it the caller's timestamp would anchor policy windows.
        if type(mode) is not MasuGateMode:
            raise TypeError("mode must be a MasuGateMode value")
        if not isinstance(resource, AdmissionCertifier):
            raise ResourceError("governed resource must implement AdmissionCertifier")
        policies_by_action = {policy.definition.action for policy in runtime.policies.compiled()}
        configured_action_modes = dict(action_modes or {})
        unknown_actions = set(configured_action_modes) - policies_by_action
        if unknown_actions:
            raise ValueError(
                f"action_modes names actions without deployed policies: {sorted(unknown_actions)}"
            )
        if any(
            type(selected) is not MasuGateMode for selected in configured_action_modes.values()
        ):
            raise TypeError("action_modes values must be MasuGateMode values")
        selected_modes = {
            action: configured_action_modes.get(action, mode) for action in policies_by_action
        }

        if MasuGateMode.RESERVATION in selected_modes.values():
            if not (
                isinstance(resource, ReservationResource)
                and isinstance(resource, PendingOperationResource)
            ):
                raise ResourceError(
                    "MasuGateMode.RESERVATION requires a ReservationResource + "
                    "PendingOperationResource"
                )
            # Whole-action startup admission: every policy applied to an action
            # selected for reservation must share the strict monotone escrow
            # proof. One volatile/non-monotone layer routes the whole action to
            # hold or revalidation instead of creating a hybrid protocol.
            checker = ReservationEligibilityChecker(registry)
            reservation_certificates: dict[str, str] = {}
            reservation_capabilities: dict[str, ReservationCapability] = {}
            for action, selected in selected_modes.items():
                if selected is not MasuGateMode.RESERVATION:
                    continue
                action_policies = runtime.policies.all_for_action(action)
                certificates = tuple(
                    sorted(
                        (checker.validate(policy) for policy in action_policies),
                        key=lambda certificate: (
                            certificate.policy_id,
                            certificate.policy_version,
                            certificate.proof_digest,
                        ),
                    )
                )
                provenance_by_policy_id = {
                    policy.definition.name: runtime.policies.provenance_for(policy)
                    for policy in action_policies
                }
                capability = resource.reservation_capability(action)
                if capability is None:
                    raise PolicyValidationError(
                        f"reservation resource has no capability for action: {action}"
                    )
                if capability.action != action:
                    raise PolicyValidationError(
                        "reservation resource capability names the wrong action: "
                        f"expected {action}, got {capability.action}"
                    )
                effect_contract = registry.effect(action)
                if (
                    capability.effect_implementation_version
                    != effect_contract.reservation_effect_implementation
                ):
                    raise PolicyValidationError(
                        "reservation provider capability does not own the registered "
                        f"effect implementation: {action}"
                    )
                if not self._same_callable(
                    capability.effect_executor,
                    effect_contract.executor,
                ):
                    raise PolicyValidationError(
                        "reservation provider capability does not provide the "
                        f"registered effect executor: {action}"
                    )
                if not capability.effect_atomic_with_reservation:
                    raise PolicyValidationError(
                        f"reservation effect is not atomic with entitlement consumption: {action}"
                    )
                if not capability.effect_idempotent:
                    raise PolicyValidationError(
                        f"reservation effect is not durably idempotent: {action}"
                    )
                for certificate in certificates:
                    if (
                        capability.reservation_proof != certificate.reservation_proof
                        or capability.consumable_arg != certificate.consumable_arg
                    ):
                        raise PolicyValidationError(
                            f"reservation resource capability does not match policy: {action}"
                        )
                reservation_capabilities[action] = capability
                policy_certificates: list[JsonValue] = []
                for certificate in certificates:
                    policy_certificate: dict[str, JsonValue] = {
                        "policy_id": certificate.policy_id,
                        "policy_version": certificate.policy_version,
                        "proof_family": certificate.proof_family.value,
                        "reservation_proof": certificate.reservation_proof,
                        "proof_digest": certificate.proof_digest,
                    }
                    provenance = provenance_by_policy_id[certificate.policy_id]
                    if provenance is not None:
                        # Compiler certificates bind policy/provider semantics.
                        # Bundle identity becomes authoritative only when the
                        # trusted catalog is admitted, so bind it into the
                        # composed action certificate at this boundary. Keep
                        # the field absent for legacy/raw policy sets so their
                        # Certificate identity predating catalog provenance
                        # remains compatible.
                        policy_certificate["catalog_provenance"] = {
                            "bundle_digest": provenance.bundle_digest,
                            "bundle_id": provenance.bundle_id,
                            "bundle_version": provenance.bundle_version,
                            "layer": provenance.layer,
                            "mode": provenance.mode,
                            "policy_declared_version": provenance.policy_declared_version,
                            "policy_digest": provenance.policy_digest,
                            "policy_id": provenance.policy_id,
                            "policy_runtime_version": provenance.policy_runtime_version,
                        }
                    policy_certificates.append(policy_certificate)
                payload: dict[str, JsonValue] = {
                    "capability": {
                        "action": capability.action,
                        "configuration_version": capability.configuration_version,
                        "consumable_arg": capability.consumable_arg,
                        "effect_atomic_with_reservation": (
                            capability.effect_atomic_with_reservation
                        ),
                        "effect_idempotent": capability.effect_idempotent,
                        "effect_implementation_version": (capability.effect_implementation_version),
                        "implementation_version": capability.implementation_version,
                        "reservation_proof": capability.reservation_proof,
                        "scope_scheme": capability.scope_scheme,
                    },
                    "plan_schema": "masugate.pending-resolution.v1",
                    "policies": policy_certificates,
                }
                reservation_certificates[action] = hashlib.sha256(
                    json.dumps(
                        payload,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode("utf-8")
                ).hexdigest()
        else:
            reservation_certificates = {}
            reservation_capabilities = {}
        if MasuGateMode.SCOPED_HOLD in selected_modes.values() and not (
            isinstance(resource, ScopeHoldResource)
            and isinstance(resource, PendingOperationResource)
        ):
            raise ResourceError(
                "MasuGateMode.SCOPED_HOLD requires a ScopeHoldResource + PendingOperationResource"
            )
        self._registry = registry
        self._runtime = runtime
        self._resource = resource
        self._principals = principals
        self._mode = mode
        self._action_modes = MappingProxyType(configured_action_modes)
        self._reservation_certificates = MappingProxyType(reservation_certificates)
        self._reservation_capabilities = MappingProxyType(reservation_capabilities)
        self._max_retries = max_retries

    async def execute(self, request: ActionRequest) -> OperationResult:
        operation_started = perf_counter()
        draft = _MetricsDraft()

        # Certify the principal FIRST: the certified team decides which
        # team-budget scope is locked, so this must precede scope computation.
        # Asserted attributes are discarded. Unknown principal -> fail closed.
        try:
            principal = self._principals.resolve(request.principal)
        except UnknownPrincipalError as exc:
            return OperationResult(
                operation_id=request.operation_id,
                decision=PolicyDecision(
                    effect=DecisionEffect.DENY,
                    policy_id="principal-registry",
                    rule_id="unknown_principal",
                    reason=str(exc),
                ),
                committed=False,
                status=OperationStatus.DENIED,
                metrics=draft.to_metrics((perf_counter() - operation_started) * 1000),
            )
        request = replace(request, principal=principal)
        # Detach caller-owned mutable mappings before any durable digest or
        # pending record retains them.
        request = replace(
            request,
            principal=replace(principal, attributes=dict(principal.attributes)),
            arguments=dict(request.arguments),
            # ``certified.*`` is a server-owned namespace.  Python callers are
            # no more trusted than HTTP callers and cannot inject evidence.
            certified_inputs={},
        )

        effect = self._registry.effect(request.action)
        self._validate_arguments(request, effect.argument_types)

        return await self._execute_transaction(
            request,
            self._mode_for_action(request.action),
            draft,
            operation_started,
        )

    async def replay(self, request: ActionRequest) -> OperationResult | None:
        """Return an exact durable result without admitting new work.

        This narrow path exists for sealed artifacts whose content retention
        has elapsed.  It holds the normal idempotency scope, validates the
        complete request identity against the durable record, and deliberately
        never evaluates policy, creates pending work, or invokes an effect.
        A matching pending result is also a durable replay: returning its
        existing locator cannot start another external operation.
        """

        try:
            principal = self._principals.resolve(request.principal)
        except UnknownPrincipalError:
            return None
        request = replace(
            request,
            principal=replace(principal, attributes=dict(principal.attributes)),
            arguments=dict(request.arguments),
            certified_inputs={},
        )
        effect = self._registry.effect(request.action)
        self._validate_arguments(request, effect.argument_types)
        scopes = frozenset(
            {encode_idempotency_scope(request.principal.id, request.idempotency_key)}
        )
        draft = _MetricsDraft()
        async with self._resource.open_session(write=True) as session:
            await self._acquire_resource_locks(session, scopes, draft)
            existing = await self._load_durable_result(session, request)
        if existing is None:
            return None
        return self._as_replayed(existing)

    # -- governed transaction path ------------------------------------------- #

    async def _execute_transaction(
        self,
        request: ActionRequest,
        mode: MasuGateMode,
        draft: _MetricsDraft,
        operation_started: float,
    ) -> OperationResult:
        effect = self._registry.effect(request.action)
        dependency_scopes = self._runtime.dependency_scopes(request)
        effect_scopes = effect.footprint_resolver(request).all_scopes
        reservation_contract_error: str | None = None
        reservation_scopes: frozenset[str] = frozenset()
        if mode is MasuGateMode.RESERVATION:
            assert isinstance(self._resource, ReservationResource)
            reservation_contract_error = self._reservation_capability_error(request.action)
            reservation_scopes = self._resource.reservation_scopes(request)
            if reservation_contract_error is not None:
                pass
            elif not reservation_scopes:
                reservation_contract_error = "reservation provider returned no protected scopes"
            elif not dependency_scopes <= reservation_scopes:
                reservation_contract_error = (
                    "reservation scopes do not cover every policy dependency"
                )
            elif not reservation_scopes <= effect_scopes:
                reservation_contract_error = (
                    "reservation scopes are not covered by the effect footprint"
                )
        scopes = frozenset(
            dependency_scopes
            | effect_scopes
            | reservation_scopes
            | {encode_idempotency_scope(request.principal.id, request.idempotency_key)}
        )

        last_error: RetryableResourceError | None = None
        for attempt in range(self._max_retries + 1):
            draft.retry_attempts = attempt
            draft.attempt_count = attempt + 1
            try:
                result = await self._execute_atomic(
                    request,
                    scopes,
                    mode,
                    reservation_contract_error,
                    draft,
                )
                return self._attach_metrics(result, draft, operation_started)
            except RetryableResourceError as exc:
                last_error = exc
        if last_error is None:  # pragma: no cover - loop runs at least once
            raise AssertionError("unreachable retry state")
        raise last_error

    async def _execute_atomic(
        self,
        request: ActionRequest,
        scopes: frozenset[str],
        mode: MasuGateMode,
        reservation_contract_error: str | None,
        draft: _MetricsDraft,
    ) -> OperationResult:
        txn_started = perf_counter()
        async with self._resource.open_session(write=True) as session:
            await self._acquire_resource_locks(session, scopes, draft)

            # Locks held: stamp the certified admission time. Everything in
            # this operation (window reads, effect timestamps) anchors on it;
            # the caller-supplied request.timestamp is discarded.
            certifier = self._resource
            assert isinstance(certifier, AdmissionCertifier)  # enforced in __init__
            certified_now = await certifier.certify_admission(session)
            request = replace(request, timestamp=certified_now)

            existing = await self._load_durable_result(session, request)
            if existing is not None:
                result = self._as_replayed(existing)
            else:
                authorization_evaluations: tuple[AuthorizationEvaluation, ...] = ()
                if reservation_contract_error is not None:
                    decision = PolicyDecision(
                        effect=DecisionEffect.DENY,
                        policy_id="reservation",
                        rule_id="reservation_contract_mismatch",
                        reason=reservation_contract_error,
                    )
                else:
                    policy_started = perf_counter()
                    request, decision, evaluation = await self._evaluate_protected(
                        request,
                        session,
                        phase=CertificationPhase.ADMISSION,
                        acquired_scopes=scopes,
                        mode=mode,
                    )
                    if evaluation is not None:
                        authorization_evaluations = (evaluation,)
                    draft.policy_eval_ms += (perf_counter() - policy_started) * 1000
                result = await self._finish(
                    request,
                    session,
                    decision,
                    mode,
                    draft,
                    authorization_evaluations=authorization_evaluations,
                )
        draft.transaction_ms += (perf_counter() - txn_started) * 1000
        return result

    # -- shared steps --------------------------------------------------------- #

    async def _finish(
        self,
        request: ActionRequest,
        session: ResourceSession,
        decision: PolicyDecision,
        mode: MasuGateMode,
        draft: _MetricsDraft,
        *,
        authorization_evaluations: tuple[AuthorizationEvaluation, ...] = (),
    ) -> OperationResult:
        if decision.effect is DecisionEffect.ESCALATE:
            return await self._record_pending(
                request,
                session,
                decision,
                mode,
                draft,
                authorization_evaluations=authorization_evaluations,
            )

        payload: dict[str, JsonValue] = {}
        reservation_id: str | None = None
        if decision.effect is DecisionEffect.ALLOW:
            # MASUGATE_SCOPED_HOLD: a committing op must not run while a *different*
            # pending op holds one of its scopes. This check runs INSIDE the
            # advisory-locked transaction (the lock was taken in _execute_atomic),
            # so a same-scope competitor that acquires the lock after the hold is
            # created observes it and is denied — the frozen check-before-lock
            # TOCTOU (which the frozen in-process RLock masked) is closed here.
            if mode is MasuGateMode.SCOPED_HOLD:
                held = await self._scope_held(session, request)
                if held:
                    return await self._deny_scope_held(
                        request,
                        session,
                        decision,
                        mode,
                        draft,
                        authorization_evaluations=authorization_evaluations,
                    )
            # MASUGATE_RESERVATION: reserve capacity BEFORE the effect; if the escrow
            # can't hold it, the allow becomes a capacity_unavailable deny. The
            # effect runs only after the entitlement is consumed — so the
            # reserve→consume→commit path happens atomically inside this one
            # locked transaction (no stale authorization window).
            reservations: ReservationResource | None = None
            if mode is MasuGateMode.RESERVATION:
                assert isinstance(self._resource, ReservationResource)  # __init__-enforced
                reservations = self._resource
                reserve_started = perf_counter()
                reservation_id = await reservations.reserve_for_request(session, request)
                draft.reservation_create_ms += (perf_counter() - reserve_started) * 1000
                if reservation_id is None:
                    return await self._deny_capacity_unavailable(
                        request,
                        session,
                        decision,
                        mode,
                        draft,
                        authorization_evaluations=authorization_evaluations,
                    )
                if not await reservations.validate_reservation(session, reservation_id, request):
                    raise ResourceError(
                        "reservation provider did not bind the entitlement to the request"
                    )
                # Consume the held entitlement before exposing the effect. Both
                # transitions remain in the same provider transaction, so an
                # effect failure rolls the consume back. This also makes expiry
                # fail closed before a future non-database effect is invoked.
                consume_started = perf_counter()
                await reservations.consume_reservation(session, reservation_id)
                draft.reservation_consume_ms += (perf_counter() - consume_started) * 1000
            effect_started = perf_counter()
            executed = self._registry.effect(request.action).executor(session, request)
            payload = await executed if inspect.isawaitable(executed) else executed
            draft.effect_exec_ms += (perf_counter() - effect_started) * 1000
        has_reservation_entitlement = (
            mode is MasuGateMode.RESERVATION and reservation_id is not None
        )
        result = OperationResult(
            operation_id=request.operation_id,
            decision=decision,
            committed=decision.effect is DecisionEffect.ALLOW,
            status=(
                OperationStatus.COMMITTED
                if decision.effect is DecisionEffect.ALLOW
                else OperationStatus.DENIED
            ),
            payload=payload,
            metrics=draft.to_metrics(),
            reservation_id=reservation_id,
            resolution_plan=(
                self._resolution_plan(mode)
                if mode is not MasuGateMode.RESERVATION or has_reservation_entitlement
                else PendingResolutionPlan.REVALIDATE
            ),
            reservation_safety_certificate_digest=(
                self._reservation_certificates.get(request.action)
                if has_reservation_entitlement
                else None
            ),
            reservation_entitlement_digest=(
                self._reservation_entitlement_digest(request)
                if has_reservation_entitlement
                else None
            ),
            authorization_evaluations=authorization_evaluations,
        )
        await self._resource.record_result(session, request, replace(result), mode)
        return result

    async def _deny_capacity_unavailable(
        self,
        request: ActionRequest,
        session: ResourceSession,
        decision: PolicyDecision,
        mode: MasuGateMode,
        draft: _MetricsDraft,
        *,
        authorization_evaluations: tuple[AuthorizationEvaluation, ...] = (),
    ) -> OperationResult:
        # The policy allowed, but reservation capacity was unavailable at commit
        # time — a valid deny, not a stale allow. Preserve the policy's reads so
        # the audit shows what was evaluated (frozen coordinator.py:398).
        result = OperationResult(
            operation_id=request.operation_id,
            decision=PolicyDecision(
                effect=DecisionEffect.DENY,
                policy_id="reservation",
                rule_id="capacity_unavailable",
                reason="reservation capacity is unavailable",
                reads=decision.reads,
                policy_version=decision.policy_version,
                evaluated_policies=decision.evaluated_policies,
                policy_provenance=decision.policy_provenance,
            ),
            committed=False,
            status=OperationStatus.DENIED,
            metrics=draft.to_metrics(),
            # No entitlement was created, so this terminal denial does not
            # carry a pending no-revalidation plan or proof metadata.
            resolution_plan=PendingResolutionPlan.REVALIDATE,
            authorization_evaluations=authorization_evaluations,
        )
        await self._resource.record_result(session, request, replace(result), mode)
        return result

    async def _deny_scope_held(
        self,
        request: ActionRequest,
        session: ResourceSession,
        decision: PolicyDecision,
        mode: MasuGateMode,
        draft: _MetricsDraft,
        *,
        authorization_evaluations: tuple[AuthorizationEvaluation, ...] = (),
    ) -> OperationResult:
        # Policy allowed, but a pending op holds this op's scope — deny (do not
        # block for a human). A same-scope competitor is turned away while the
        # approval is outstanding, which is what preserves the pending op's
        # basis. This is the async-core scoped-hold semantics: deny-on-hold, not
        # busy-poll-until-release (the frozen 5 ms poll is gone).
        result = OperationResult(
            operation_id=request.operation_id,
            decision=PolicyDecision(
                effect=DecisionEffect.DENY,
                policy_id="scope-hold",
                rule_id="scope_held",
                reason="a pending operation holds a required scope",
                reads=decision.reads,
                policy_version=decision.policy_version,
                evaluated_policies=decision.evaluated_policies,
                policy_provenance=decision.policy_provenance,
            ),
            committed=False,
            status=OperationStatus.DENIED,
            metrics=draft.to_metrics(),
            resolution_plan=self._resolution_plan(mode),
            authorization_evaluations=authorization_evaluations,
        )
        await self._resource.record_result(session, request, replace(result), mode)
        return result

    async def _record_pending(
        self,
        request: ActionRequest,
        session: ResourceSession,
        decision: PolicyDecision,
        mode: MasuGateMode,
        draft: _MetricsDraft,
        *,
        authorization_evaluations: tuple[AuthorizationEvaluation, ...] = (),
    ) -> OperationResult:
        # Pending state is durable and created inside the same locked
        # transaction as evaluation. Reservation mode first escrows capacity;
        # scoped-hold mode instead records scope holds after the pending row.
        # Plain transaction mode uses revalidation on approval and needs no
        # extra preservation mechanism.
        if not isinstance(self._resource, PendingOperationResource):
            raise ResourceError("resource does not support pending operations")
        reservation_id: str | None = None
        if mode is MasuGateMode.RESERVATION:
            assert isinstance(self._resource, ReservationResource)  # __init__-enforced
            reserve_started = perf_counter()
            reservation_id = await self._resource.reserve_for_request(session, request)
            draft.reservation_create_ms += (perf_counter() - reserve_started) * 1000
            if reservation_id is None:
                return await self._deny_capacity_unavailable(
                    request,
                    session,
                    decision,
                    mode,
                    draft,
                    authorization_evaluations=authorization_evaluations,
                )
            if not await self._resource.validate_reservation(session, reservation_id, request):
                raise ResourceError(
                    "reservation provider did not bind the entitlement to the request"
                )
        plan = self._resolution_plan(mode)
        certificate_digest = (
            self._reservation_certificates.get(request.action)
            if plan is PendingResolutionPlan.RESERVATION_PROOF
            else None
        )
        if plan is PendingResolutionPlan.RESERVATION_PROOF and certificate_digest is None:
            raise ResourceError(
                f"reservation action has no admitted safety certificate: {request.action}"
            )
        result = OperationResult(
            operation_id=request.operation_id,
            decision=decision,
            committed=False,
            status=OperationStatus.PENDING,
            metrics=draft.to_metrics(),
            pending_id=request.operation_id,
            reservation_id=reservation_id,
            resolution_plan=plan,
            reservation_safety_certificate_digest=certificate_digest,
            reservation_entitlement_digest=(
                self._reservation_entitlement_digest(request)
                if reservation_id is not None
                else None
            ),
            authorization_evaluations=authorization_evaluations,
        )
        pending_resource = cast(PendingOperationResource, self._resource)
        await pending_resource.record_pending_operation(
            session,
            request,
            replace(result),
            mode,
        )
        if mode is MasuGateMode.SCOPED_HOLD:
            assert isinstance(self._resource, ScopeHoldResource)  # __init__-enforced
            await self._resource.create_scope_holds(
                session, request.operation_id, self._hold_scopes(request)
            )
        return result

    def _hold_scopes(self, request: ActionRequest) -> frozenset[str]:
        effect = self._registry.effect(request.action)
        return frozenset(
            self._runtime.dependency_scopes(request) | effect.footprint_resolver(request).all_scopes
        )

    async def _scope_held(self, session: ResourceSession, request: ActionRequest) -> bool:
        """Whether a different pending op holds one of this op's scopes.

        The CORRECT (default) implementation checks INSIDE the advisory-locked
        transaction — ``session`` here is the locked write session from
        ``_execute_atomic``, so a competitor that acquired the lock after the
        hold was created sees it. This is the seam the 0.14 mask-removed teeth
        variant overrides to check BEFORE the lock (the frozen order), which
        reopens the TOCTOU under a genuine race.
        """
        assert isinstance(self._resource, ScopeHoldResource)  # __init__-enforced
        return await self._resource.has_active_scope_hold(session, self._hold_scopes(request))

    def _resolution_scopes(self, pending: PendingOperation) -> frozenset[str]:
        """Current scopes plus the pending decision's durable original reads.

        Removing a policy or contract is certificate drift. Resolution still
        needs a conservative scope set so it can release reservations/holds and
        record a terminal fail-closed result instead of stranding the pending
        operation before proof verification.
        """

        scopes = {read.scope for read in pending.decision.reads}
        with suppress(ContractError, PolicyEvaluationError):
            scopes.update(self._hold_scopes(pending.request))
        return frozenset(scopes)

    async def resolve_pending(
        self,
        pending_id: str,
        *,
        approved: bool,
        evidence: dict[str, JsonValue] | None = None,
    ) -> OperationResult:
        """Resolve a pending governed operation (approve/deny).

        Reservation mode consumes the capacity held when the operation became
        pending, without re-evaluating an availability view that excludes its
        own reservation. Other modes revalidate inside a fresh locked
        transaction; a changed basis denies as ``stale_approval``. Scoped-hold
        mode additionally releases its durable holds before commit.  Like
        :meth:`execute`, resolution retries typed serialization/deadlock
        failures against a fresh transaction.  A retry that follows an
        ambiguous commit is safe: the durable resolved-result lookup returns
        the terminal operation as an idempotent replay.
        """
        operation_started = perf_counter()
        draft = _MetricsDraft()

        last_error: RetryableResourceError | None = None
        for attempt in range(self._max_retries + 1):
            draft.retry_attempts = attempt
            draft.attempt_count = attempt + 1
            try:
                return await self._resolve_pending_once(
                    pending_id,
                    approved=approved,
                    evidence=evidence or {},
                    draft=draft,
                    operation_started=operation_started,
                )
            except RetryableResourceError as exc:
                last_error = exc
        if last_error is None:  # pragma: no cover - loop runs at least once
            raise AssertionError("unreachable retry state")
        raise last_error

    async def _resolve_pending_once(
        self,
        pending_id: str,
        *,
        approved: bool,
        evidence: dict[str, JsonValue],
        draft: _MetricsDraft,
        operation_started: float,
    ) -> OperationResult:
        """Run one pending-resolution attempt in fresh resource sessions."""
        if not isinstance(self._resource, PendingOperationResource):
            raise ResourceError("resource does not support pending operations")

        async with self._resource.open_session(write=False) as session:
            pending = await self._resource.load_pending_operation(session, pending_id)
            if pending is None:
                terminal = await self._resource.load_resolved_pending_result(session, pending_id)
                if terminal is not None:
                    return self._attach_metrics(
                        self._as_replayed(terminal), draft, operation_started
                    )
        if pending is None:
            raise ResourceError(f"unknown pending operation: {pending_id}")

        try:
            current_principal = self._principals.resolve(pending.request.principal)
        except UnknownPrincipalError:
            pass
        else:
            pending = replace(
                pending,
                request=replace(
                    pending.request,
                    principal=replace(
                        current_principal,
                        attributes=dict(current_principal.attributes),
                    ),
                ),
            )

        scopes = frozenset(
            self._resolution_scopes(pending)
            | {
                encode_idempotency_scope(
                    pending.request.principal.id,
                    pending.request.idempotency_key,
                ),
                f"pending:{pending_id}",
            }
        )
        txn_started = perf_counter()
        async with self._resource.open_session(write=True) as session:
            await self._acquire_resource_locks(session, scopes, draft)
            assert isinstance(self._resource, AdmissionCertifier)
            certifier = cast(AdmissionCertifier, self._resource)
            await certifier.certify_admission(session)

            current = await self._resource.load_pending_operation(session, pending_id)
            if current is None:
                existing = await self._resource.load_result(session, pending.request)
                if existing is None:
                    raise ResourceError(f"pending operation disappeared: {pending_id}")
                return self._attach_metrics(self._as_replayed(existing), draft, operation_started)

            if current.integrity_error is not None:
                terminal = await self._deny_pending_record_invalid(
                    session,
                    current,
                    current.integrity_error,
                    draft,
                )
                terminal_request = current.request
            else:
                try:
                    current_principal = self._principals.resolve(current.request.principal)
                except UnknownPrincipalError as exc:
                    terminal = await self._deny_pending_basis_invalid(
                        session, current, str(exc), draft
                    )
                    terminal_request = current.request
                else:
                    terminal_request = replace(
                        current.request,
                        principal=replace(
                            current_principal,
                            attributes=dict(current_principal.attributes),
                        ),
                    )
                    terminal = await self._resolve_in_session(
                        session,
                        current,
                        approved,
                        evidence,
                        draft,
                        current_request=terminal_request,
                        acquired_scopes=scopes,
                    )
            terminal = replace(
                terminal,
                resolution_evidence={
                    "approved": approved,
                    "evidence": deepcopy(evidence),
                },
            )
            if (
                terminal.authorization_evaluations
                and terminal.authorization_evaluations[-1].phase is CertificationPhase.RESOLUTION
            ):
                terminal_request = replace(
                    terminal_request,
                    certified_inputs=(terminal.authorization_evaluations[-1].certified_inputs),
                )
            # Durable mode/plan metadata may be legacy, downgraded, or corrupt.
            # Releasing by the authoritative relational pending id is harmless
            # when no holds exist and prevents malformed JSON from orphaning a
            # real hold until its TTL.  Do this for every terminal resolution;
            # never make cleanup conditional on serialized metadata.
            if isinstance(self._resource, ScopeHoldResource):
                await self._resource.release_scope_holds(session, pending_id)
            durable_terminal = replace(terminal)
            pending_resource = cast(PendingOperationResource, self._resource)
            await pending_resource.resolve_pending_operation(
                session,
                pending_id,
                durable_terminal,
                deepcopy(evidence),
            )
            await self._resource.record_result(
                session,
                terminal_request,
                durable_terminal,
                current.mode,
            )
        draft.transaction_ms += (perf_counter() - txn_started) * 1000
        return self._attach_metrics(terminal, draft, operation_started)

    async def _resolve_in_session(
        self,
        session: ResourceSession,
        pending: PendingOperation,
        approved: bool,
        evidence: dict[str, JsonValue],
        draft: _MetricsDraft,
        *,
        current_request: ActionRequest | None = None,
        acquired_scopes: frozenset[str],
    ) -> OperationResult:
        resolution_request = current_request or pending.request
        authorization_evaluations = pending.authorization_evaluations
        if not approved:
            proof_error = self._reservation_proof_error(pending, resolution_request)
            released_reservation_id: str | None = None
            has_reservation_state = (
                pending.reservation_id is not None
                or pending.mode is MasuGateMode.RESERVATION
                or pending.resolution_plan is PendingResolutionPlan.RESERVATION_PROOF
            )
            if has_reservation_state:
                if not isinstance(self._resource, ReservationResource):
                    raise ResourceError("resource does not support reservations")
                released_reservation_id = await self._release_bound_reservation(
                    session, pending, draft
                )
            proof_metadata_is_valid = proof_error is None and (
                not has_reservation_state or released_reservation_id == pending.reservation_id
            )
            return OperationResult(
                operation_id=pending.request.operation_id,
                decision=PolicyDecision(
                    effect=DecisionEffect.DENY,
                    policy_id=pending.decision.policy_id,
                    rule_id=f"{pending.decision.rule_id}.rejected",
                    reason="pending operation rejected",
                    reads=pending.decision.reads,
                    policy_version=pending.decision.policy_version,
                    evaluated_policies=pending.decision.evaluated_policies,
                    policy_provenance=pending.decision.policy_provenance,
                ),
                committed=False,
                status=OperationStatus.DENIED,
                metrics=draft.to_metrics(),
                reservation_id=(
                    released_reservation_id if has_reservation_state else pending.reservation_id
                ),
                resolution_plan=(
                    pending.resolution_plan
                    if proof_metadata_is_valid
                    else PendingResolutionPlan.REVALIDATE
                ),
                reservation_safety_certificate_digest=(
                    pending.reservation_safety_certificate_digest
                    if proof_metadata_is_valid
                    else None
                ),
                reservation_entitlement_digest=(
                    pending.reservation_entitlement_digest if proof_metadata_is_valid else None
                ),
                authorization_evaluations=authorization_evaluations,
            )
        proof_error = self._reservation_proof_error(pending, resolution_request)
        if proof_error is not None:
            return await self._deny_invalid_reservation_proof(session, pending, proof_error, draft)

        if pending.resolution_plan is not PendingResolutionPlan.RESERVATION_PROOF:
            # Revalidate non-reservation approvals against CURRENT policy state
            # (the honesty path). A re-ESCALATE means "still needs approval" and
            # the human just supplied it; only a genuine DENY is stale.
            policy_started = perf_counter()
            resolution_request, decision, evaluation = await self._evaluate_protected(
                resolution_request,
                session,
                phase=CertificationPhase.RESOLUTION,
                acquired_scopes=acquired_scopes,
                mode=pending.mode,
            )
            if evaluation is not None:
                authorization_evaluations = (
                    *authorization_evaluations,
                    evaluation,
                )
            draft.policy_eval_ms += (perf_counter() - policy_started) * 1000
            if decision.effect is DecisionEffect.DENY:
                if decision.policy_id == "certification":
                    terminal_decision = decision
                else:
                    terminal_decision = PolicyDecision(
                        effect=DecisionEffect.DENY,
                        policy_id=decision.policy_id,
                        rule_id=f"{decision.rule_id}.stale_approval",
                        reason="approval resolved after policy state changed",
                        reads=decision.reads,
                        policy_version=decision.policy_version,
                        evaluated_policies=decision.evaluated_policies,
                        policy_provenance=decision.policy_provenance,
                    )
                return OperationResult(
                    operation_id=pending.request.operation_id,
                    decision=terminal_decision,
                    committed=False,
                    status=OperationStatus.DENIED,
                    metrics=draft.to_metrics(),
                    resolution_plan=pending.resolution_plan,
                    authorization_evaluations=authorization_evaluations,
                )
            terminal_decision = PolicyDecision(
                effect=DecisionEffect.ALLOW,
                policy_id=decision.policy_id,
                rule_id=f"{decision.rule_id}.approved",
                reason="pending operation approved after revalidation",
                reads=decision.reads,
                policy_version=decision.policy_version,
                evaluated_policies=decision.evaluated_policies,
                policy_provenance=decision.policy_provenance,
            )
        else:
            # Reservation mode preserved the relevant capacity at escalation,
            # so approval consumes that reservation rather than re-reading an
            # availability view that necessarily excludes the held amount.
            terminal_decision = PolicyDecision(
                effect=DecisionEffect.ALLOW,
                policy_id=pending.decision.policy_id,
                rule_id=f"{pending.decision.rule_id}.approved",
                reason="pending operation approved with reservation",
                reads=pending.decision.reads,
                policy_version=pending.decision.policy_version,
                evaluated_policies=pending.decision.evaluated_policies,
                policy_provenance=pending.decision.policy_provenance,
            )
            assert pending.reservation_id is not None
            assert isinstance(self._resource, ReservationResource)  # __init__-enforced
            if not await self._resource.validate_reservation(
                session, pending.reservation_id, pending.request
            ):
                return await self._deny_invalid_reservation_proof(
                    session,
                    pending,
                    (
                        "reservation entitlement is unavailable or does not match "
                        "the pending request"
                    ),
                    draft,
                )
            consume_started = perf_counter()
            try:
                await self._resource.consume_reservation(session, pending.reservation_id)
            except RetryableResourceError:
                # A serialization/deadlock failure aborts this attempt. Let the
                # outer resolution loop reopen a fresh transaction; converting
                # it to a durable proof denial would make a transient database
                # conflict into a false governance decision.
                raise
            except ResourceError as exc:
                return await self._deny_invalid_reservation_proof(
                    session,
                    pending,
                    f"reservation entitlement is unavailable: {exc}",
                    draft,
                )
            draft.reservation_consume_ms += (perf_counter() - consume_started) * 1000
        effect_started = perf_counter()
        executed = self._registry.effect(resolution_request.action).executor(
            session, resolution_request
        )
        payload = await executed if inspect.isawaitable(executed) else executed
        draft.effect_exec_ms += (perf_counter() - effect_started) * 1000
        return OperationResult(
            operation_id=pending.request.operation_id,
            decision=terminal_decision,
            committed=True,
            status=OperationStatus.COMMITTED,
            payload={**payload, "approval_evidence": evidence},
            metrics=draft.to_metrics(),
            reservation_id=pending.reservation_id,
            resolution_plan=pending.resolution_plan,
            reservation_safety_certificate_digest=(pending.reservation_safety_certificate_digest),
            reservation_entitlement_digest=pending.reservation_entitlement_digest,
            authorization_evaluations=authorization_evaluations,
        )

    def _reservation_proof_error(
        self,
        pending: PendingOperation,
        current_request: ActionRequest,
    ) -> str | None:
        """Return why a pending record cannot use the no-revalidation path."""

        if pending.resolution_plan is PendingResolutionPlan.RESERVATION_PROOF:
            if pending.mode is not MasuGateMode.RESERVATION:
                return "reservation proof plan is paired with a non-reservation mode"
            if pending.reservation_id is None:
                return "reservation proof plan is missing a reservation id"
            capability_error = self._reservation_capability_error(pending.request.action)
            if capability_error is not None:
                return capability_error
            expected = self._reservation_certificates.get(pending.request.action)
            if expected is None:
                return "current action plan is not reservation-proof"
            if pending.reservation_safety_certificate_digest != expected:
                return "reservation safety certificate does not match current policy contracts"
            expected_entitlement = self._reservation_entitlement_digest(current_request)
            if pending.reservation_entitlement_digest != expected_entitlement:
                return "reservation entitlement digest does not match the pending request"
            if self._mode_for_action(pending.request.action) is not MasuGateMode.RESERVATION:
                return "current action mode no longer permits reservation"
            return None
        if pending.reservation_id is not None or pending.mode is MasuGateMode.RESERVATION:
            return "raw reservation state has no verified reservation-proof plan"
        return None

    async def _deny_invalid_reservation_proof(
        self,
        session: ResourceSession,
        pending: PendingOperation,
        reason: str,
        draft: _MetricsDraft,
    ) -> OperationResult:
        released_reservation_id = await self._release_bound_reservation(session, pending, draft)
        return OperationResult(
            operation_id=pending.request.operation_id,
            decision=PolicyDecision(
                effect=DecisionEffect.DENY,
                policy_id="reservation",
                rule_id="reservation_proof_invalid",
                reason=reason,
                reads=pending.decision.reads,
                policy_version=pending.decision.policy_version,
                evaluated_policies=pending.decision.evaluated_policies,
                policy_provenance=pending.decision.policy_provenance,
            ),
            committed=False,
            status=OperationStatus.DENIED,
            metrics=draft.to_metrics(),
            reservation_id=released_reservation_id,
            # An invalid proof never leaves proof metadata that could be
            # mistaken for a verified no-revalidation terminal path.
            resolution_plan=PendingResolutionPlan.REVALIDATE,
            authorization_evaluations=pending.authorization_evaluations,
        )

    async def _deny_pending_basis_invalid(
        self,
        session: ResourceSession,
        pending: PendingOperation,
        reason: str,
        draft: _MetricsDraft,
    ) -> OperationResult:
        released_reservation_id = await self._release_bound_reservation(session, pending, draft)
        return OperationResult(
            operation_id=pending.request.operation_id,
            decision=PolicyDecision(
                effect=DecisionEffect.DENY,
                policy_id="principal-registry",
                rule_id="principal_changed.stale_approval",
                reason=reason,
                reads=pending.decision.reads,
                policy_version=pending.decision.policy_version,
                evaluated_policies=pending.decision.evaluated_policies,
                policy_provenance=pending.decision.policy_provenance,
            ),
            committed=False,
            status=OperationStatus.DENIED,
            metrics=draft.to_metrics(),
            reservation_id=released_reservation_id,
            resolution_plan=PendingResolutionPlan.REVALIDATE,
            authorization_evaluations=pending.authorization_evaluations,
        )

    async def _deny_pending_record_invalid(
        self,
        session: ResourceSession,
        pending: PendingOperation,
        reason: str,
        draft: _MetricsDraft,
    ) -> OperationResult:
        released_reservation_id = await self._release_bound_reservation(session, pending, draft)
        return OperationResult(
            operation_id=pending.request.operation_id,
            decision=PolicyDecision(
                effect=DecisionEffect.DENY,
                policy_id="pending-record",
                rule_id="pending_record_invalid",
                reason=reason,
            ),
            committed=False,
            status=OperationStatus.DENIED,
            metrics=draft.to_metrics(),
            reservation_id=released_reservation_id,
            resolution_plan=PendingResolutionPlan.REVALIDATE,
            authorization_evaluations=pending.authorization_evaluations,
        )

    async def _release_bound_reservation(
        self,
        session: ResourceSession,
        pending: PendingOperation,
        draft: _MetricsDraft,
    ) -> str | None:
        """Release only an entitlement proven to belong to ``pending``.

        Pending records are durable but still treated as untrusted input at the
        proof boundary.  In particular, a corrupted record may point at another
        operation's reservation.  Releasing by identifier alone would then free
        capacity owned by that other operation without holding its scopes.  The
        provider must first bind the identifier to the exact original request;
        an unavailable, expired, or cross-linked entitlement is left untouched.
        """

        if not isinstance(self._resource, ReservationResource):
            return None
        release_started = perf_counter()
        released_id = await self._resource.release_reservation_for_request(session, pending.request)
        if released_id is not None:
            draft.reservation_release_ms += (perf_counter() - release_started) * 1000
        return released_id

    def _mode_for_action(self, action: str) -> MasuGateMode:
        return self._action_modes.get(action, self._mode)

    @staticmethod
    def _same_callable(left: object, right: object) -> bool:
        """Compare callables without trusting a user-defined ``__eq__``.

        Re-reading an instance method creates a fresh bound-method object, so
        identity reduces to the exact function and owning instance. Plain
        functions and callable objects must be the same object.
        """

        left_function = getattr(left, "__func__", None)
        right_function = getattr(right, "__func__", None)
        left_owner = getattr(left, "__self__", None)
        right_owner = getattr(right, "__self__", None)
        if left_function is not None or right_function is not None:
            return left_function is right_function and left_owner is right_owner
        return left is right

    def _reservation_capability_error(self, action: str) -> str | None:
        """Detect provider drift from the capability admitted at startup."""

        admitted = self._reservation_capabilities.get(action)
        if admitted is None or not isinstance(self._resource, ReservationResource):
            return "current action plan has no admitted reservation capability"
        current = self._resource.reservation_capability(action)
        if current is None:
            return "reservation provider capability is unavailable"
        scalar_fields = (
            "action",
            "reservation_proof",
            "implementation_version",
            "configuration_version",
            "scope_scheme",
            "consumable_arg",
            "effect_implementation_version",
            "effect_atomic_with_reservation",
            "effect_idempotent",
        )
        if any(
            getattr(current, field_name) != getattr(admitted, field_name)
            for field_name in scalar_fields
        ) or not self._same_callable(
            current.effect_executor,
            admitted.effect_executor,
        ):
            return "reservation provider capability changed after admission"
        effect = self._registry.effect(action)
        if not self._same_callable(current.effect_executor, effect.executor):
            return "reservation provider no longer owns the registered effect executor"
        return None

    @staticmethod
    def _reservation_entitlement_digest(request: ActionRequest) -> str:
        payload: dict[str, JsonValue] = {
            "action": request.action,
            "arguments": dict(request.arguments),
            "certified_inputs": {
                name: certified_input_evidence_json(evidence)
                for name, evidence in sorted(request.certified_inputs.items())
            },
            "idempotency_key": request.idempotency_key,
            "operation_id": request.operation_id,
            "principal": {
                "attributes": dict(request.principal.attributes),
                "id": request.principal.id,
            },
            "resource": request.resource,
            "timestamp": request.timestamp.isoformat(),
        }
        if request.protected_artifacts:
            payload["protected_artifacts"] = {
                name: metadata.payload()
                for name, metadata in sorted(request.protected_artifacts.items())
            }
        return hashlib.sha256(
            json.dumps(
                payload,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _resolution_plan(mode: MasuGateMode) -> PendingResolutionPlan:
        if mode is MasuGateMode.RESERVATION:
            return PendingResolutionPlan.RESERVATION_PROOF
        if mode is MasuGateMode.SCOPED_HOLD:
            return PendingResolutionPlan.SCOPED_HOLD
        return PendingResolutionPlan.REVALIDATE

    async def _authorization_clock(self, session: ResourceSession) -> datetime:
        """Read a fresh protected evaluation clock when the provider supports it."""

        if isinstance(self._resource, AuthorizationEvaluationCertifier):
            return await self._resource.certify_authorization_evaluation(session)
        # Compatibility for provider fakes without a request clock. The
        # production provider implements the fresh clock capability; the
        # certified-input contract makes it a conformance requirement. The
        # fallback remains server-owned and after locks.
        certifier = self._resource
        assert isinstance(certifier, AdmissionCertifier)
        return await certifier.certify_admission(session)

    @staticmethod
    def _certification_denial(rule_id: str, reason: str) -> PolicyDecision:
        return PolicyDecision(
            effect=DecisionEffect.DENY,
            policy_id="certification",
            rule_id=rule_id,
            reason=reason,
        )

    async def _evaluate_protected(
        self,
        request: ActionRequest,
        session: ResourceSession,
        *,
        phase: CertificationPhase,
        acquired_scopes: frozenset[str],
        mode: MasuGateMode,
    ) -> tuple[ActionRequest, PolicyDecision, AuthorizationEvaluation | None]:
        """Resolve server facts and record one complete protected evaluation.

        Source observations are collected only after the full coordination set
        is held.  The runtime evaluates at a provisional protected clock, then
        the coordinator reads the actual completion clock and re-checks every
        evidence freshness boundary there before exposing an effect.
        """

        dependencies = self._runtime.certified_input_dependencies(request.action)
        observations: dict[str, CertifiedInputObservation] = {}
        certified_inputs = dict(request.certified_inputs)
        try:
            if dependencies:
                observation_time = await self._authorization_clock(session)
                for name in dependencies:
                    contract = self._registry.certified_input(name)
                    reuse_stable = (
                        phase is CertificationPhase.RESOLUTION
                        and contract.stability is CertifiedInputStability.ADMISSION_STABLE
                    )
                    if reuse_stable:
                        if name not in certified_inputs:
                            raise CertificationError(
                                f"missing admission-stable certified input: {name}"
                            )
                        continue
                    observations[name] = await resolve_certified_input_observation(
                        contract,
                        session,
                        request,
                        observation_time=observation_time,
                    )
                certified_at = await self._authorization_clock(session)
                for name, observation in observations.items():
                    certified_inputs[name] = certify_observation(
                        self._registry.certified_input(name),
                        observation,
                        phase,
                        certified_at=certified_at,
                    )
            else:
                # No certified evidence needs a pre-evaluation freshness
                # check.  The actual completion point is still read after the
                # complete policy evaluation below.
                certified_at = request.timestamp
            certified_request = replace(
                request,
                certified_inputs={name: certified_inputs[name] for name in dependencies},
            )
            for name in dependencies:
                validate_certified_input_evidence(
                    self._registry.certified_input(name),
                    certified_request.certified_inputs[name],
                    at=certified_at,
                    evaluation_phase=phase,
                )
        except RetryableResourceError:
            raise
        except Exception as exc:
            return (
                replace(request, certified_inputs={}),
                self._certification_denial("certified_input_invalid", str(exc)),
                None,
            )

        required_scopes = set(self._hold_scopes(certified_request))
        if mode is MasuGateMode.RESERVATION:
            assert isinstance(self._resource, ReservationResource)
            required_scopes.update(self._resource.reservation_scopes(certified_request))
        if not required_scopes <= acquired_scopes:
            return (
                certified_request,
                self._certification_denial(
                    "certification_scope_drift",
                    "certification changed the complete coordination set",
                ),
                None,
            )

        decision = await self._safe_evaluate(
            certified_request,
            session,
            evaluation_at=certified_at,
            evaluation_phase=phase,
        )
        evaluated_at = await self._authorization_clock(session)
        try:
            for name in dependencies:
                validate_certified_input_evidence(
                    self._registry.certified_input(name),
                    certified_request.certified_inputs[name],
                    at=evaluated_at,
                    evaluation_phase=phase,
                )
        except CertificationError as exc:
            return (
                certified_request,
                self._certification_denial("certified_input_invalid", str(exc)),
                None,
            )
        evaluation = AuthorizationEvaluation(
            phase=phase,
            evaluated_at=evaluated_at,
            decision=decision,
            certified_inputs=certified_request.certified_inputs,
        )
        return certified_request, decision, evaluation

    async def _safe_evaluate(
        self,
        request: ActionRequest,
        session: ResourceSession,
        *,
        evaluation_at: datetime,
        evaluation_phase: CertificationPhase,
    ) -> PolicyDecision:
        try:
            return await self._runtime.aevaluate(
                request,
                session,
                evaluation_at=evaluation_at,
                evaluation_phase=evaluation_phase,
            )
        except RetryableResourceError:
            # Transient resource failures are transaction failures, not policy
            # denials.  Let the outer bounded retry loop reopen a fresh
            # session/snapshot; durably recording fail_closed here would turn a
            # deadlock or serialization race into a false governance decision.
            raise
        except (PolicyEvaluationError, ResourceError) as exc:
            return PolicyDecision(
                effect=DecisionEffect.DENY,
                policy_id="runtime",
                rule_id="fail_closed",
                reason=str(exc),
            )

    async def _load_durable_result(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> OperationResult | None:
        existing = await self._resource.load_result(session, request)
        if existing is not None:
            return existing
        if isinstance(self._resource, PendingOperationResource):
            return await self._resource.load_pending_result(session, request)
        return None

    async def _acquire_resource_locks(
        self,
        session: ResourceSession,
        scopes: frozenset[str],
        draft: _MetricsDraft,
    ) -> None:
        if isinstance(self._resource, ScopedLockResource):
            lock_started = perf_counter()
            reported = await self._resource.acquire_scoped_locks(session, scopes)
            elapsed = (perf_counter() - lock_started) * 1000
            draft.advisory_lock_wait_ms += reported if reported is not None else elapsed

    def _validate_arguments(
        self,
        request: ActionRequest,
        expected: Mapping[str, TypeName],
    ) -> None:
        if request.arguments.keys() != expected.keys():
            raise ValueError(
                f"{request.action} arguments must be {sorted(expected)}, "
                f"got {sorted(request.arguments)}"
            )
        for name, expected_type in expected.items():
            value = request.arguments[name]
            if expected_type is TypeName.INT and (
                not isinstance(value, int) or isinstance(value, bool)
            ):
                raise ValueError(f"{name} must be Int")
            if expected_type is TypeName.STRING and not isinstance(value, str):
                raise ValueError(f"{name} must be String")
            if expected_type is TypeName.BOOL and not isinstance(value, bool):
                raise ValueError(f"{name} must be Bool")

    def _attach_metrics(
        self,
        result: OperationResult,
        draft: _MetricsDraft,
        operation_started: float,
    ) -> OperationResult:
        return replace(
            result,
            metrics=draft.to_metrics((perf_counter() - operation_started) * 1000),
        )

    @staticmethod
    def _as_replayed(result: OperationResult) -> OperationResult:
        return replace(result, replayed=True)
