"""Reusable provider conformance scaffold for certified inputs.

Providers expose their runtime contracts through :mod:`masugate.contracts`.  This
module supplies the executable certification adapter used before a provider is
accepted: a deterministic scenario plus evidence for time anchoring, protected
evaluation, certified-input stability/freshness, scopes, reads, idempotency,
reservation accounting, audit capture, and error taxonomy.  Real providers can
wrap their own test instance with ``ProviderConformanceProbe`` in step 2.4.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol

from masugate.certification import validate_certified_input_evidence
from masugate.contracts import (
    CertifiedInputContract,
    EffectContract,
    GovernanceViewContract,
    ProviderIdentity,
    ReservationViewKind,
)
from masugate.errors import CertificationError, ResourceError, RetryableResourceError
from masugate.model import (
    ActionRequest,
    CertificationPhase,
    CertifiedInputEvidence,
    CertifiedInputStability,
    CertifiedInputStabilityProof,
    ConsistencyGuarantee,
    Duration,
    JsonValue,
    Principal,
    ResourceFootprint,
    Scalar,
    TypeName,
    ViewRead,
)
from masugate.provider_assembly import EffectExecutionPosition


class ProviderConformanceError(AssertionError):
    """One provider invariant failed its executable certification scenario."""


@dataclass(frozen=True)
class ProviderConformanceScenario:
    request: ActionRequest
    server_time: datetime
    caller_times: tuple[datetime, datetime]
    protected_at: datetime


@dataclass(frozen=True)
class RequestTimeSample:
    caller_time: datetime
    server_time: datetime
    request_time: datetime
    window_anchor: datetime


@dataclass(frozen=True)
class EvaluationPointSample:
    protected_at: datetime
    evaluation_started_at: datetime
    evaluation_completed_at: datetime
    recorded_evaluation_at: datetime
    protected_policy_read_count: int


@dataclass(frozen=True)
class StabilitySample:
    contract: CertifiedInputContract
    admission_evidence: CertifiedInputEvidence
    resolution_value: Scalar | Duration
    request_bound: bool


@dataclass(frozen=True)
class EffectExercise:
    first_payload: dict[str, JsonValue]
    replay_payload: dict[str, JsonValue]
    committed_effect_count: int
    used_declared_executor: bool
    changed_request_rejected: bool


@dataclass(frozen=True)
class ReservationExercise:
    capacity: int
    quantity: int
    held_after_reserve: int
    committed_after_consume: int
    held_after_consume: int
    second_consume_changed_state: bool
    release_after_consume_changed_state: bool
    original_request_valid: bool
    cross_request_valid: bool


@dataclass(frozen=True)
class AuditCapture:
    provider_identity: ProviderIdentity
    operation_id: str
    idempotency_key: str
    view_reads: tuple[ViewRead, ...]


@dataclass(frozen=True)
class ProviderConformanceReport:
    provider_identity: ProviderIdentity
    checks: tuple[str, ...]


class CertifiedInputConformanceProbe(Protocol):
    """Applicable evidence for a provider that exports only certified inputs."""

    @property
    def identity(self) -> ProviderIdentity: ...

    @property
    def certified_input_contracts(self) -> tuple[CertifiedInputContract, ...]: ...

    def request_time_sample(
        self,
        request: ActionRequest,
        *,
        caller_time: datetime,
        server_time: datetime,
    ) -> RequestTimeSample | None: ...

    def evaluation_point_sample(self, *, protected_at: datetime) -> EvaluationPointSample: ...

    def stability_samples(
        self,
        request: ActionRequest,
        *,
        admission_at: datetime,
    ) -> tuple[StabilitySample, ...]: ...


class ProviderConformanceProbe(CertifiedInputConformanceProbe, Protocol):
    """Behavioral evidence adapter implemented by a callable provider fixture."""

    @property
    def view_contract(self) -> GovernanceViewContract: ...

    @property
    def effect_contract(self) -> EffectContract: ...

    @property
    def effect_position(self) -> EffectExecutionPosition: ...

    def derive_scopes(self, request: ActionRequest) -> frozenset[str]: ...

    def view_read(self, request: ActionRequest, scope: str) -> ViewRead | None: ...

    def effect_exercise(self, request: ActionRequest) -> EffectExercise: ...

    def reservation_exercise(self, request: ActionRequest) -> ReservationExercise | None: ...

    def audit_capture(self, request: ActionRequest, read: ViewRead) -> AuditCapture: ...

    def retryable_failure(self) -> Exception: ...

    def fail_closed_failure(self) -> Exception: ...


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProviderConformanceError(message)


def _check_contract_identities(probe: ProviderConformanceProbe) -> None:
    identity = probe.identity
    _require(type(identity) is ProviderIdentity, "provider identity is missing or malformed")
    _require(
        probe.view_contract.provider_identity == identity,
        "view configuration provenance does not match provider identity",
    )
    _require(
        probe.effect_contract.provider_identity == identity,
        "effect configuration provenance does not match provider identity",
    )
    _require(probe.view_contract.bounded, "policy-callable view is not bounded")
    _require(probe.effect_contract.executor is not None, "effect executor is missing")
    _require(
        probe.effect_position is EffectExecutionPosition.TRANSACTIONAL,
        "callable provider effect is not declared transactional",
    )


def _check_certified_input_identities(probe: CertifiedInputConformanceProbe) -> None:
    identity = probe.identity
    _require(type(identity) is ProviderIdentity, "provider identity is missing or malformed")
    contracts = probe.certified_input_contracts
    _require(bool(contracts), "certified-input provider declares no certified-input contracts")
    _require(
        all(contract.provider_identity == identity for contract in contracts),
        "certified input configuration provenance does not match provider identity",
    )


def _check_time(
    probe: CertifiedInputConformanceProbe,
    scenario: ProviderConformanceScenario,
) -> str:
    samples = tuple(
        probe.request_time_sample(
            scenario.request,
            caller_time=caller_time,
            server_time=scenario.server_time,
        )
        for caller_time in scenario.caller_times
    )
    if all(sample is None for sample in samples):
        time_check = "request-time-not-applicable"
    else:
        _require(
            all(sample is not None for sample in samples),
            "provider inconsistently declares request-time applicability",
        )
        applicable = tuple(sample for sample in samples if sample is not None)
        _require(
            all(sample.request_time == scenario.server_time for sample in applicable),
            "request time is caller-anchored instead of provider-certified",
        )
        _require(
            all(sample.window_anchor == sample.request_time for sample in applicable),
            "request-time window is not anchored to certified request time",
        )
        time_check = "request-time-window"

    evaluation = probe.evaluation_point_sample(protected_at=scenario.protected_at)
    _require(
        evaluation.protected_at
        <= evaluation.evaluation_started_at
        <= evaluation.evaluation_completed_at,
        "authorization evaluation did not occur after protection",
    )
    _require(
        evaluation.recorded_evaluation_at == evaluation.evaluation_completed_at,
        "authorization evaluation point was selected retrospectively",
    )
    _require(
        evaluation.protected_policy_read_count > 0,
        "protected evaluation did not execute a policy view read",
    )
    return time_check


def _check_stability(
    probe: CertifiedInputConformanceProbe,
    scenario: ProviderConformanceScenario,
) -> str:
    samples = probe.stability_samples(scenario.request, admission_at=scenario.server_time)
    contracts = probe.certified_input_contracts
    if not contracts:
        _require(not samples, "provider supplied samples for undeclared certified inputs")
        return "certified-inputs-not-applicable"
    _require(bool(samples), "provider omitted declared certified-input stability samples")
    contracts_by_name = {contract.name: contract for contract in contracts}
    _require(
        len(contracts_by_name) == len(contracts),
        "provider declares duplicate certified-input contracts",
    )
    _require(
        {sample.contract.name for sample in samples} == set(contracts_by_name),
        "certified-input samples do not cover the declared contracts exactly",
    )
    for sample in samples:
        contract = sample.contract
        _require(
            contract == contracts_by_name[contract.name],
            "certified-input sample does not use the declared contract",
        )
        _require(
            contract.provider_identity == probe.identity,
            "certified input configuration provenance does not match provider identity",
        )
        inside = sample.admission_evidence.expires_at - timedelta(microseconds=1)
        validate_certified_input_evidence(
            contract,
            sample.admission_evidence,
            at=inside,
            evaluation_phase=CertificationPhase.ADMISSION,
        )
        try:
            validate_certified_input_evidence(
                contract,
                sample.admission_evidence,
                at=sample.admission_evidence.expires_at,
                evaluation_phase=CertificationPhase.ADMISSION,
            )
        except CertificationError:
            pass
        else:
            raise ProviderConformanceError(
                "certified input accepted at its exclusive freshness boundary"
            )

        if contract.stability is CertifiedInputStability.ADMISSION_STABLE:
            _require(
                contract.stability_proof is CertifiedInputStabilityProof.REQUEST_BOUND_IMMUTABLE_V1,
                "admission-stable input lacks the supported proof",
            )
            _require(sample.request_bound, "admission-stable input is not request-bound")
            _require(
                sample.resolution_value == sample.admission_evidence.value,
                "admission-stable input changed across resolution",
            )
            validate_certified_input_evidence(
                contract,
                sample.admission_evidence,
                at=sample.admission_evidence.expires_at + timedelta(seconds=1),
                evaluation_phase=CertificationPhase.RESOLUTION,
            )
        else:
            _require(
                contract.stability_proof is None,
                "resolution-volatile input carries a stability proof",
            )
            with_accepted_stale = True
            try:
                validate_certified_input_evidence(
                    contract,
                    sample.admission_evidence,
                    at=sample.admission_evidence.expires_at + timedelta(seconds=1),
                    evaluation_phase=CertificationPhase.RESOLUTION,
                )
            except CertificationError:
                with_accepted_stale = False
            _require(
                not with_accepted_stale,
                "resolution-volatile input was reused after freshness expiry",
            )
    return "certified-input-freshness-stability"


def _check_data_plane(
    probe: ProviderConformanceProbe,
    scenario: ProviderConformanceScenario,
) -> tuple[ViewRead, str]:
    first_scopes = probe.derive_scopes(scenario.request)
    second_scopes = probe.derive_scopes(scenario.request)
    _require(first_scopes == second_scopes, "scope derivation is unstable")
    _require(bool(first_scopes), "scope derivation returned no scopes")
    scope = sorted(first_scopes)[0]
    read = probe.view_read(scenario.request, scope)
    _require(read is not None, "provider omitted the policy view read")
    assert read is not None
    _require(read.function == probe.view_contract.name, "audit read names the wrong view")
    _require(read.scope == scope, "view read scope does not match deterministic derivation")
    _require(type(read.version) is int and read.version >= 0, "view read version is missing")
    _require(read.latency_ms >= 0, "view read latency is invalid")
    _require(
        read.latency_ms <= probe.view_contract.max_latency_ms,
        "bounded view exceeded its declared latency",
    )

    effect = probe.effect_exercise(scenario.request)
    _require(
        effect.first_payload == effect.replay_payload and effect.committed_effect_count == 1,
        "effect is not idempotent under exact replay",
    )
    _require(
        effect.used_declared_executor,
        "conformance exercise bypassed the declared transactional executor",
    )
    _require(
        effect.changed_request_rejected,
        "effect replay is not bound to the exact immutable request",
    )

    reservation = probe.reservation_exercise(scenario.request)
    reservation_declared = (
        probe.effect_contract.reservation_proof is not None
        or probe.view_contract.reservation_kind is not ReservationViewKind.UNSUPPORTED
    )
    if not reservation_declared:
        _require(
            reservation is None,
            "provider supplied reservation evidence for unsupported contracts",
        )
        reservation_check = "reservation-not-applicable"
    else:
        _require(
            probe.effect_contract.reservation_proof is not None
            and probe.view_contract.reservation_kind is not ReservationViewKind.UNSUPPORTED,
            "reservation declarations are incomplete across view and effect",
        )
        _require(reservation is not None, "provider omitted declared reservation evidence")
        assert reservation is not None
        _require(
            0 <= reservation.held_after_reserve <= reservation.capacity,
            "reservation held capacity violates bounds",
        )
        _require(
            reservation.held_after_reserve == reservation.quantity,
            "reservation did not escrow the requested quantity",
        )
        _require(
            reservation.committed_after_consume == reservation.quantity
            and reservation.held_after_consume == 0,
            "reservation consume did not transfer held capacity exactly once",
        )
        _require(
            not reservation.second_consume_changed_state
            and not reservation.release_after_consume_changed_state,
            "reservation consume/release replay changed escrow state",
        )
        _require(
            reservation.original_request_valid and not reservation.cross_request_valid,
            "reservation entitlement is not bound to the exact request",
        )
        reservation_check = "reservation-invariants"

    audit = probe.audit_capture(scenario.request, read)
    _require(
        audit.provider_identity == probe.identity,
        "audit lost provider configuration provenance",
    )
    _require(
        audit.operation_id == scenario.request.operation_id,
        "audit captured the wrong operation",
    )
    _require(
        audit.idempotency_key == scenario.request.idempotency_key,
        "audit captured the wrong idempotency key",
    )
    _require(read in audit.view_reads, "audit omitted the exact policy read/version")
    return read, reservation_check


def _check_errors(probe: ProviderConformanceProbe) -> None:
    retryable = probe.retryable_failure()
    hard = probe.fail_closed_failure()
    _require(
        isinstance(retryable, RetryableResourceError),
        "retryable provider failure uses the wrong taxonomy",
    )
    _require(
        isinstance(hard, ResourceError) and not isinstance(hard, RetryableResourceError),
        "fail-closed provider failure uses the wrong taxonomy",
    )


def run_provider_conformance(
    probe: ProviderConformanceProbe,
    scenario: ProviderConformanceScenario,
) -> ProviderConformanceReport:
    """Run the shared provider certification checks or raise at first breach."""

    _check_contract_identities(probe)
    time_check = _check_time(probe, scenario)
    certified_input_check = _check_stability(probe, scenario)
    _read, reservation_check = _check_data_plane(probe, scenario)
    _check_errors(probe)
    return ProviderConformanceReport(
        provider_identity=probe.identity,
        checks=(
            "configuration-provenance",
            time_check,
            "protected-evaluation",
            certified_input_check,
            "deterministic-scopes",
            "bounded-versioned-reads",
            "transactional-effects",
            "idempotent-effects",
            "request-bound-effects",
            reservation_check,
            "audit-read-capture",
            "typed-errors",
        ),
    )


def run_certified_input_conformance(
    probe: CertifiedInputConformanceProbe,
    scenario: ProviderConformanceScenario,
) -> ProviderConformanceReport:
    """Run the certified-input conformance check for a certified-input-only provider.

    Context providers intentionally have neither a policy-callable view nor a
    direct effect.  Requiring fabricated contracts would weaken conformance;
    this narrow entry point instead certifies their real temporal, provenance,
    freshness, and stability behavior through the production evaluation path.
    """

    _check_certified_input_identities(probe)
    time_check = _check_time(probe, scenario)
    certified_input_check = _check_stability(probe, scenario)
    return ProviderConformanceReport(
        provider_identity=probe.identity,
        checks=(
            "configuration-provenance",
            time_check,
            "protected-evaluation",
            certified_input_check,
        ),
    )


def reference_conformance_scenario() -> ProviderConformanceScenario:
    server_time = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)
    return ProviderConformanceScenario(
        request=ActionRequest(
            operation_id="reference-provider-op",
            idempotency_key="reference-provider-op",
            principal=Principal(id="alice"),
            action="reference.write",
            arguments={"target": "report", "quantity": 4},
            timestamp=datetime(1999, 1, 1, tzinfo=UTC),
        ),
        server_time=server_time,
        caller_times=(
            datetime(1999, 1, 1, tzinfo=UTC),
            datetime(2099, 1, 1, tzinfo=UTC),
        ),
        protected_at=server_time,
    )


class ReferenceProviderProbe:
    """Small conforming fixture packaged with the reusable scaffold."""

    def __init__(self) -> None:
        self._identity = ProviderIdentity(
            provider_id="masugate.reference-provider",
            implementation_version="1.0.0",
            configuration_version="reference-config-v1",
        )
        self._view = GovernanceViewContract(
            name="reference.remaining",
            argument_types=(TypeName.STRING,),
            return_type=TypeName.INT,
            owner="masugate.reference-provider",
            consistency="scoped-policy-state",
            max_latency_ms=100,
            bounded=True,
            scope_resolver=lambda args: f"reference:{args[0]}",
            resolver=lambda session, args, scope: (10, 1),
            reservation_kind=ReservationViewKind.AVAILABLE_CAPACITY,
            reservation_proof="reference-capacity-v1",
            provider_identity=self._identity,
        )
        self._effect = EffectContract(
            action="reference.write",
            argument_types={"target": TypeName.STRING, "quantity": TypeName.INT},
            owner="masugate.reference-provider",
            required_guarantee=ConsistencyGuarantee.POLICY_STATE_SERIALIZABLE,
            footprint_resolver=lambda request: ResourceFootprint(
                writes=frozenset({f"reference:{request.arguments['target']}"})
            ),
            executor=lambda session, request: {"written": request.arguments["target"]},
            consumable_arg="quantity",
            reservation_proof="reference-capacity-v1",
            reservation_effect_implementation="reference-effect-v1",
            provider_identity=self._identity,
        )
        self._certified_inputs = (
            self._input_contract(
                name="certified.tenant",
                stability=CertifiedInputStability.ADMISSION_STABLE,
            ),
            self._input_contract(
                name="certified.risk",
                stability=CertifiedInputStability.RESOLUTION_VOLATILE,
            ),
        )

    @property
    def identity(self) -> ProviderIdentity:
        return self._identity

    @property
    def view_contract(self) -> GovernanceViewContract:
        return self._view

    @property
    def effect_contract(self) -> EffectContract:
        return self._effect

    @property
    def effect_position(self) -> EffectExecutionPosition:
        return EffectExecutionPosition.TRANSACTIONAL

    @property
    def certified_input_contracts(self) -> tuple[CertifiedInputContract, ...]:
        return self._certified_inputs

    def request_time_sample(
        self,
        request: ActionRequest,
        *,
        caller_time: datetime,
        server_time: datetime,
    ) -> RequestTimeSample:
        del request
        return RequestTimeSample(
            caller_time=caller_time,
            server_time=server_time,
            request_time=server_time,
            window_anchor=server_time,
        )

    def evaluation_point_sample(self, *, protected_at: datetime) -> EvaluationPointSample:
        started = protected_at + timedelta(microseconds=1)
        completed = protected_at + timedelta(microseconds=2)
        return EvaluationPointSample(
            protected_at=protected_at,
            evaluation_started_at=started,
            evaluation_completed_at=completed,
            recorded_evaluation_at=completed,
            protected_policy_read_count=1,
        )

    def _input_contract(
        self,
        *,
        name: str,
        stability: CertifiedInputStability,
    ) -> CertifiedInputContract:
        proof = (
            CertifiedInputStabilityProof.REQUEST_BOUND_IMMUTABLE_V1
            if stability is CertifiedInputStability.ADMISSION_STABLE
            else None
        )
        return CertifiedInputContract(
            name=name,
            value_type=TypeName.STRING,
            stability=stability,
            stability_proof=proof,
            source_id="masugate.reference-provider",
            contract_version="1.0.0",
            freshness_ttl=Duration(60),
            resolver=lambda session, request, at: None,  # type: ignore[arg-type,return-value]
            provider_identity=self._identity,
        )

    def stability_samples(
        self,
        request: ActionRequest,
        *,
        admission_at: datetime,
    ) -> tuple[StabilitySample, ...]:
        stable, volatile = self._certified_inputs

        def evidence(
            contract: CertifiedInputContract,
            value: str,
        ) -> CertifiedInputEvidence:
            return CertifiedInputEvidence(
                name=contract.name,
                value=value,
                value_type=contract.value_type,
                stability=contract.stability,
                stability_proof=contract.stability_proof,
                source_id=contract.source_id,
                source_version="reference-source-v1",
                contract_version=contract.contract_version,
                observed_at=admission_at,
                certified_at=admission_at,
                freshness_ttl=contract.freshness_ttl,
                phase=CertificationPhase.ADMISSION,
            )

        return (
            StabilitySample(
                contract=stable,
                admission_evidence=evidence(stable, request.principal.id),
                resolution_value=request.principal.id,
                request_bound=True,
            ),
            StabilitySample(
                contract=volatile,
                admission_evidence=evidence(volatile, "low"),
                resolution_value="high",
                request_bound=False,
            ),
        )

    def derive_scopes(self, request: ActionRequest) -> frozenset[str]:
        return frozenset({f"reference:{request.arguments['target']}"})

    def view_read(self, request: ActionRequest, scope: str) -> ViewRead | None:
        return ViewRead(
            function=self._view.name,
            arguments=(str(request.arguments["target"]),),
            value=10,
            scope=scope,
            version=1,
            latency_ms=0.1,
        )

    def effect_exercise(self, request: ActionRequest) -> EffectExercise:
        payload: dict[str, JsonValue] = {"written": str(request.arguments["target"])}
        return EffectExercise(payload, dict(payload), 1, True, True)

    def reservation_exercise(self, request: ActionRequest) -> ReservationExercise | None:
        quantity = int(request.arguments["quantity"])
        return ReservationExercise(
            capacity=10,
            quantity=quantity,
            held_after_reserve=quantity,
            committed_after_consume=quantity,
            held_after_consume=0,
            second_consume_changed_state=False,
            release_after_consume_changed_state=False,
            original_request_valid=True,
            cross_request_valid=False,
        )

    def audit_capture(self, request: ActionRequest, read: ViewRead) -> AuditCapture:
        return AuditCapture(
            provider_identity=self._identity,
            operation_id=request.operation_id,
            idempotency_key=request.idempotency_key,
            view_reads=(read,),
        )

    def retryable_failure(self) -> Exception:
        return RetryableResourceError("reference serialization retry")

    def fail_closed_failure(self) -> Exception:
        return ResourceError("reference hard failure")


class BadWindowProviderProbe(ReferenceProviderProbe):
    """Permanent teeth fixture: incorrectly anchors windows to caller time."""

    def request_time_sample(
        self,
        request: ActionRequest,
        *,
        caller_time: datetime,
        server_time: datetime,
    ) -> RequestTimeSample:
        del request
        return RequestTimeSample(
            caller_time=caller_time,
            server_time=server_time,
            request_time=server_time,
            window_anchor=caller_time,
        )
