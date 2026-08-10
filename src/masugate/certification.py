"""Construction and fail-closed validation of server-certified policy inputs."""

from __future__ import annotations

import inspect
from datetime import datetime
from typing import cast

from masugate.contracts import (
    CertifiedInputContract,
    CertifiedInputObservation,
    ResourceSession,
)
from masugate.errors import CertificationError
from masugate.model import (
    ActionRequest,
    CertificationPhase,
    CertifiedInputEvidence,
    CertifiedInputStability,
    Duration,
    JsonValue,
    Scalar,
    TypeName,
)


def _aware_datetime(value: object) -> bool:
    return type(value) is datetime and value.tzinfo is not None and value.utcoffset() is not None


def _value_matches_type(value: Scalar | Duration, expected: TypeName) -> bool:
    if expected is TypeName.BOOL:
        return type(value) is bool
    if expected is TypeName.INT:
        return type(value) is int
    if expected is TypeName.STRING:
        return type(value) is str
    if expected is TypeName.DURATION:
        return type(value) is Duration and type(value.seconds) is int
    return False


def certify_observation(
    contract: CertifiedInputContract,
    observation: CertifiedInputObservation,
    phase: CertificationPhase,
    *,
    certified_at: datetime,
) -> CertifiedInputEvidence:
    """Package one source observation under an active trusted contract."""

    if type(contract) is not CertifiedInputContract:
        raise CertificationError("active certified input contract is malformed")
    if type(observation) is not CertifiedInputObservation:
        raise CertificationError("certified input resolver returned a malformed observation")
    if type(phase) is not CertificationPhase:
        raise CertificationError("certification phase is malformed")
    if not _aware_datetime(certified_at):
        raise CertificationError("certified_at must be timezone-aware")
    if observation.observed_at > certified_at:
        raise CertificationError("certified input observation is in the future")
    if (
        contract.expected_source_version is not None
        and observation.source_version != contract.expected_source_version
    ):
        raise CertificationError("certified input observation source version does not match")
    if not _value_matches_type(observation.value, contract.value_type):
        raise CertificationError(f"certified input {contract.name} observation has the wrong type")
    try:
        return CertifiedInputEvidence(
            name=contract.name,
            value=observation.value,
            value_type=contract.value_type,
            stability=contract.stability,
            stability_proof=contract.stability_proof,
            source_id=contract.source_id,
            source_version=observation.source_version,
            contract_version=contract.contract_version,
            observed_at=observation.observed_at,
            certified_at=certified_at,
            freshness_ttl=contract.freshness_ttl,
            phase=phase,
        )
    except (TypeError, ValueError) as exc:
        raise CertificationError(str(exc)) from exc


async def resolve_certified_input(
    contract: CertifiedInputContract,
    session: ResourceSession,
    request: ActionRequest,
    phase: CertificationPhase,
    *,
    certified_at: datetime,
) -> CertifiedInputEvidence:
    """Resolve and package one observation from a sync or async certifier."""

    resolved = contract.resolver(session, request, certified_at)
    if inspect.isawaitable(resolved):
        observation = await resolved
    else:
        observation = resolved
    return certify_observation(
        contract,
        observation,
        phase,
        certified_at=certified_at,
    )


async def resolve_certified_input_observation(
    contract: CertifiedInputContract,
    session: ResourceSession,
    request: ActionRequest,
    *,
    observation_time: datetime,
) -> CertifiedInputObservation:
    """Obtain an authoritative observation without pre-dating packaging.

    ``observation_time`` is a server clock hint for sources that need one.  The
    coordinator reads a fresh clock after all sources return and uses that
    later value as ``certified_at`` and as the start of evaluation validation.
    """

    resolved = contract.resolver(session, request, observation_time)
    observation = await resolved if inspect.isawaitable(resolved) else resolved
    if type(observation) is not CertifiedInputObservation:
        raise CertificationError("certified input resolver returned a malformed observation")
    return observation


def validate_certified_input_evidence(
    contract: CertifiedInputContract,
    evidence: CertifiedInputEvidence,
    *,
    at: datetime,
    evaluation_phase: CertificationPhase,
) -> Scalar | Duration:
    """Validate provenance and freshness against the currently active contract.

    Evidence phase is deliberately not required to equal a single runtime-wide
    phase: resolution revalidation may combine reused admission-stable evidence
    with freshly resolved volatile evidence.  The coordinator owns that refresh
    selection; the evaluator independently refuses incoherent or stale values.
    """

    if not _aware_datetime(at):
        raise CertificationError("certified input validation time must be timezone-aware")
    if type(evaluation_phase) is not CertificationPhase:
        raise CertificationError("certified input evaluation phase is malformed")
    if type(contract) is not CertifiedInputContract:
        raise CertificationError("active certified input contract is malformed")
    if type(evidence) is not CertifiedInputEvidence:
        raise CertificationError("certified input evidence is malformed")

    # Reconstruct the immutable value to re-run every structural invariant. It
    # keeps this boundary safe even if a test double or decoder bypassed the
    # dataclass constructor with object.__setattr__.
    try:
        checked = CertifiedInputEvidence(
            name=evidence.name,
            value=evidence.value,
            value_type=evidence.value_type,
            stability=evidence.stability,
            stability_proof=evidence.stability_proof,
            source_id=evidence.source_id,
            source_version=evidence.source_version,
            contract_version=evidence.contract_version,
            observed_at=evidence.observed_at,
            certified_at=evidence.certified_at,
            freshness_ttl=evidence.freshness_ttl,
            phase=evidence.phase,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise CertificationError(f"certified input evidence is malformed: {exc}") from exc

    if checked.name != contract.name:
        raise CertificationError("certified input evidence name does not match contract")
    if checked.value_type is not contract.value_type:
        raise CertificationError("certified input evidence type does not match contract")
    if checked.stability is not contract.stability:
        raise CertificationError("certified input evidence stability does not match contract")
    if checked.stability_proof is not contract.stability_proof:
        raise CertificationError("certified input evidence stability proof does not match contract")
    if checked.source_id != contract.source_id:
        raise CertificationError("certified input evidence source does not match contract")
    if (
        contract.expected_source_version is not None
        and checked.source_version != contract.expected_source_version
    ):
        raise CertificationError("certified input evidence source version does not match contract")
    if checked.contract_version != contract.contract_version:
        raise CertificationError("certified input evidence contract version does not match")
    if checked.freshness_ttl != contract.freshness_ttl:
        raise CertificationError("certified input evidence freshness does not match contract")
    if not _value_matches_type(checked.value, contract.value_type):
        raise CertificationError("certified input evidence value has the wrong type")
    if checked.observed_at > at or checked.certified_at > at:
        raise CertificationError("certified input evidence is from the future")
    preserves_admission_value = (
        evaluation_phase is CertificationPhase.RESOLUTION
        and checked.phase is CertificationPhase.ADMISSION
        and checked.stability is CertifiedInputStability.ADMISSION_STABLE
        and checked.stability_proof is not None
    )
    if checked.expires_at <= at and not preserves_admission_value:
        raise CertificationError("certified input evidence is stale")
    return checked.value


def certified_input_evidence_json(
    evidence: CertifiedInputEvidence,
) -> dict[str, JsonValue]:
    """Return the canonical durable/audit representation of one input."""

    value: JsonValue
    if type(evidence.value) is Duration:
        value = {"seconds": evidence.value.seconds}
    else:
        value = cast(JsonValue, evidence.value)
    return {
        "name": evidence.name,
        "value": value,
        "value_type": evidence.value_type.value,
        "stability": evidence.stability.value,
        "stability_proof": (
            evidence.stability_proof.value if evidence.stability_proof is not None else None
        ),
        "source_id": evidence.source_id,
        "source_version": evidence.source_version,
        "contract_version": evidence.contract_version,
        "observed_at": evidence.observed_at.isoformat(),
        "certified_at": evidence.certified_at.isoformat(),
        "freshness_ttl_seconds": evidence.freshness_ttl.seconds,
        "expires_at": evidence.expires_at.isoformat(),
        "phase": evidence.phase.value,
    }
