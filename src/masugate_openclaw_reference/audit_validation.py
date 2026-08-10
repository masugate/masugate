"""Shared fail-closed validation for reference spend audit records.

reference artifact creates these records and release evidence replays them.  Keeping the
complete validator in the packaged reference distribution prevents later
release gates from accepting a weaker, selectively checked interpretation of
the same durable evidence.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import cast

_ACTION = "spend.purchase"
_CONNECTOR_ID = "reference-purchase-v1"
_PROVIDER_ID = "masugate.spend.reference"
_PROVIDER_IMPLEMENTATION = "masugate.spend.reference-v1"
_SCOPE = "spend:team:research"


class AuditValidationError(RuntimeError):
    """A reference spend audit failed its durable-evidence contract."""


@dataclass(frozen=True)
class SpendAuditExpectation:
    """Scenario-owned values that a spend audit must prove independently."""

    idempotency_key: str
    principal_id: str
    principal_attributes: Mapping[str, object]
    arguments: Mapping[str, object]
    trace_id: str
    admission_effect: str
    admission_rule_id: str
    admission_reason: str
    available_cents: int
    read_version: int
    budget_version: int
    terminal_decision: Mapping[str, object]
    authorization_basis: str
    operation_id: str | None = None
    human_resolution_evidence: Mapping[str, object] | None = None


@dataclass(frozen=True)
class ValidatedSpendAudit:
    """Values safely derived after the complete audit chain validates."""

    audit: dict[str, object]
    available_cents: int
    budget_version: int
    operation_id: str
    read_version: int


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise AuditValidationError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise AuditValidationError(f"{label} must be a list")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuditValidationError(f"{label} must be a non-empty string")
    return value


def _integer(value: object, label: str) -> int:
    if type(value) is not int:
        raise AuditValidationError(f"{label} must be an integer")
    return value


def _sha256_string(value: object, label: str) -> str:
    digest = _string(value, label)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise AuditValidationError(f"{label} must be a lowercase SHA-256 digest")
    return digest


def _timestamp(value: object, label: str) -> datetime:
    text = _string(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuditValidationError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise AuditValidationError(f"{label} must include a timezone")
    return parsed


def _canonical_json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


def validate_spend_authorization_anchor(value: object) -> dict[str, object]:
    """Validate the release-owned configuration and policy identity anchor."""

    anchor = _mapping(value, "spend authorization anchor")
    if set(anchor) != {"configuration_digest", "policy"}:
        raise AuditValidationError("spend authorization anchor has the wrong shape")
    configuration_digest = _sha256_string(
        anchor.get("configuration_digest"), "spend configuration digest"
    )
    policy = _mapping(anchor.get("policy"), "spend policy anchor")
    if set(policy) != {
        "bundle_digest",
        "bundle_id",
        "bundle_version",
        "layer",
        "mode",
        "policy_declared_version",
        "policy_digest",
        "policy_id",
        "policy_runtime_version",
    }:
        raise AuditValidationError("spend policy anchor has the wrong shape")
    policy_digest = _sha256_string(policy.get("policy_digest"), "spend policy digest")
    expected = {
        "bundle_digest": _sha256_string(policy.get("bundle_digest"), "spend bundle digest"),
        "bundle_id": "masugate.spend.reference",
        "bundle_version": "1.0.0",
        "layer": "owner",
        "mode": "configurable",
        "policy_declared_version": "1.0.0",
        "policy_digest": policy_digest,
        "policy_id": "spend_budget_guard",
        "policy_runtime_version": policy_digest[:16],
    }
    if policy != expected:
        raise AuditValidationError("spend policy anchor is inconsistent")
    return {"configuration_digest": configuration_digest, "policy": expected}


def authorization_digest(
    request: Mapping[str, object],
    decision: Mapping[str, object],
    *,
    budget_version: int,
    configuration_digest: str,
    resolution: Mapping[str, object] | None,
) -> str:
    """Recompute the spend provider's durable authorization binding."""

    arguments = _mapping(request.get("args"), "authorization request arguments")
    principal = _mapping(request.get("principal"), "authorization request principal")
    attributes = _mapping(principal.get("attributes"), "authorization principal attributes")
    request_payload: dict[str, object] = {
        "amount_cents": arguments.get("amount_cents"),
        "idempotency_key": request.get("idempotency_key"),
        "merchant_id": arguments.get("merchant_id"),
        "principal_id": principal.get("id"),
        "request_ref": arguments.get("request_ref"),
        "team_id": attributes.get("team"),
        "tool_call_id": request.get("trace_id"),
        "adapter_invocation_digest": request.get("adapter_invocation_digest"),
    }
    request_digest = _canonical_digest(request_payload)
    evaluated = _list(decision.get("evaluated_policies"), "authorization evaluated policies")
    evaluation_payload = {
        "effect": decision.get("effect"),
        "evaluated_policies": [
            [
                _mapping(item, "authorization evaluated policy").get("policy_id"),
                _mapping(item, "authorization evaluated policy").get("policy_version"),
            ]
            for item in evaluated
        ],
        "policy_id": decision.get("policy_id"),
        "policy_provenance": decision.get("policy_provenance"),
        "policy_version": decision.get("policy_version"),
        "reads": decision.get("reads"),
        "reason": decision.get("reason"),
        "rule_id": decision.get("rule_id"),
    }
    return _canonical_digest(
        {
            "authorization": evaluation_payload,
            "budget_version": budget_version,
            "configuration_digest": configuration_digest,
            "request_digest": request_digest,
            "resolution": None if resolution is None else dict(resolution),
        }
    )


def _validate_request(
    audit: Mapping[str, object], label: str, expected: SpendAuditExpectation
) -> tuple[str, dict[str, object], datetime, datetime]:
    operation_id = _string(audit.get("operation_id"), f"{label}.operation_id")
    if expected.operation_id is not None and operation_id != expected.operation_id:
        raise AuditValidationError(f"{label} has the wrong operation identity")
    request = _mapping(audit.get("request"), f"{label}.request")
    if set(request) != {
        "action",
        "adapter_invocation_digest",
        "args",
        "idempotency_key",
        "principal",
        "request_time",
        "timestamp",
        "trace_id",
    }:
        raise AuditValidationError(f"{label} request has an incompatible shape")
    _sha256_string(
        request.get("adapter_invocation_digest"),
        f"{label}.request.adapter_invocation_digest",
    )
    principal = _mapping(request.get("principal"), f"{label}.request.principal")
    if principal != {
        "attributes": dict(expected.principal_attributes),
        "id": expected.principal_id,
    }:
        raise AuditValidationError(f"{label} has the wrong request principal")
    if (
        request.get("action") != _ACTION
        or request.get("args") != dict(expected.arguments)
        or request.get("idempotency_key") != expected.idempotency_key
        or request.get("trace_id") != expected.trace_id
    ):
        raise AuditValidationError(f"{label} has the wrong request identity or arguments")
    request_time = _timestamp(request.get("request_time"), f"{label}.request.request_time")
    if request.get("timestamp") != request.get("request_time"):
        raise AuditValidationError(f"{label} request timestamp does not match request_time")
    recorded_at = _timestamp(audit.get("recorded_at"), f"{label}.recorded_at")
    if recorded_at < request_time:
        raise AuditValidationError(f"{label} was recorded before its trusted request")
    return operation_id, request, request_time, recorded_at


def _validate_policy_and_reads(
    audit: Mapping[str, object],
    label: str,
    *,
    anchor: Mapping[str, object],
    expected: SpendAuditExpectation,
    request_time: datetime,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    reads = _list(audit.get("view_reads"), f"{label}.view_reads")
    if len(reads) != 1:
        raise AuditValidationError(f"{label} must contain exactly one spend policy-state read")
    read = _mapping(reads[0], f"{label}.view_reads[0]")
    if set(read) != {"arguments", "function", "latency_ms", "scope", "value", "version"}:
        raise AuditValidationError(f"{label} policy-state read has an incompatible shape")
    latency = read.get("latency_ms")
    if (
        type(latency) not in {int, float}
        or not math.isfinite(cast(float, latency))
        or cast(float, latency) < 0
    ):
        raise AuditValidationError(f"{label} has an invalid policy-state read latency")
    read_without_latency = {name: value for name, value in read.items() if name != "latency_ms"}
    if read_without_latency != {
        "arguments": ["research"],
        "function": "spend.available_cents",
        "scope": _SCOPE,
        "value": expected.available_cents,
        "version": expected.read_version,
    }:
        raise AuditValidationError(f"{label} has fabricated policy-state read evidence")

    evaluations = _list(
        audit.get("authorization_evaluations"), f"{label}.authorization_evaluations"
    )
    if len(evaluations) != 1:
        raise AuditValidationError(f"{label} must contain exactly one admission evaluation")
    admission = _mapping(evaluations[0], f"{label}.authorization_evaluations[0]")
    if set(admission) != {"certified_inputs", "decision", "evaluated_at", "phase"}:
        raise AuditValidationError(f"{label} admission evaluation has an incompatible shape")
    if admission.get("phase") != "admission" or admission.get("certified_inputs") != []:
        raise AuditValidationError(f"{label} has the wrong authorization evaluation phase")
    if _timestamp(admission.get("evaluated_at"), f"{label}.admission.evaluated_at") != request_time:
        raise AuditValidationError(f"{label} admission evaluation is not bound to request time")

    policy_anchor = _mapping(anchor.get("policy"), "executed spend policy anchor")
    policy_digest = _string(policy_anchor.get("policy_digest"), "executed policy digest")
    bundle_digest = _string(policy_anchor.get("bundle_digest"), "executed bundle digest")
    runtime_version = _string(
        policy_anchor.get("policy_runtime_version"), "executed policy runtime version"
    )
    evaluated_policies = [{"policy_id": "spend_budget_guard", "policy_version": runtime_version}]
    decision = _mapping(admission.get("decision"), f"{label}.admission decision")
    expected_decision = {
        "effect": expected.admission_effect,
        "evaluated_policies": evaluated_policies,
        "policy_id": "spend_budget_guard",
        "policy_provenance": [policy_anchor],
        "policy_version": runtime_version,
        "reads": reads,
        "reason": expected.admission_reason,
        "rule_id": expected.admission_rule_id,
    }
    if decision != expected_decision:
        raise AuditValidationError(f"{label} has the wrong admission policy decision")
    outer_policy = {
        "catalog": {"bundle_digest": bundle_digest, "policy_digest": policy_digest},
        "evaluated_policies": evaluated_policies,
        "evaluated_policy_provenance": [policy_anchor],
        "policy_id": "spend_budget_guard",
        "policy_version": runtime_version,
    }
    if audit.get("policy") != outer_policy:
        raise AuditValidationError(f"{label} outer policy evidence does not match admission")
    binding_policies: list[dict[str, object]] = [
        {
            "bundle_digest": bundle_digest,
            "bundle_id": "masugate.spend.reference",
            "bundle_version": "1.0.0",
            "policy_digest": policy_digest,
            "policy_id": "spend_budget_guard",
            "policy_version": "1.0.0",
        }
    ]
    return decision, binding_policies


def _human_resolution(
    audit: Mapping[str, object],
    label: str,
    *,
    expected: SpendAuditExpectation,
    request_time: datetime,
    recorded_at: datetime,
) -> dict[str, object] | None:
    expected_evidence = expected.human_resolution_evidence
    if expected_evidence is None:
        if audit.get("human_resolution") is not None:
            raise AuditValidationError(f"{label} unexpectedly contains human approval evidence")
        return None
    resolution = _mapping(audit.get("human_resolution"), f"{label}.human_resolution")
    if set(resolution) != {"actor_id", "approved", "evidence", "resolved_at"}:
        raise AuditValidationError(f"{label} human approval has an incompatible shape")
    if (
        resolution.get("actor_id") != "operator"
        or resolution.get("approved") is not True
        or resolution.get("evidence") != dict(expected_evidence)
    ):
        raise AuditValidationError(f"{label} has invalid human approval evidence")
    resolved_at = _timestamp(resolution.get("resolved_at"), f"{label}.human_resolution.resolved_at")
    if not request_time <= resolved_at <= recorded_at:
        raise AuditValidationError(f"{label} human approval has an invalid temporal basis")
    return {
        "actor_id": "operator",
        "approved": True,
        "evidence": dict(expected_evidence),
        "kind": "human",
        "resolved_at": _string(resolution.get("resolved_at"), "resolution time"),
    }


def _effect_authorization(decision: Mapping[str, object]) -> dict[str, object]:
    raw_reads = _list(decision.get("reads"), "admission decision reads")
    return {
        "effect": decision.get("effect"),
        "evaluated_policies": decision.get("evaluated_policies"),
        "policy_id": decision.get("policy_id"),
        "policy_version": decision.get("policy_version"),
        "reads": [
            {
                name: value
                for name, value in _mapping(read, "admission decision read").items()
                if name != "latency_ms"
            }
            for read in raw_reads
        ],
        "reason": decision.get("reason"),
        "rule_id": decision.get("rule_id"),
    }


def validate_committed_spend_audit(
    record: object,
    label: str,
    *,
    expected: SpendAuditExpectation,
    spend_authorization: Mapping[str, object],
) -> ValidatedSpendAudit:
    """Validate a committed record from request through durable receipt."""

    audit = _mapping(record, label)
    if audit.get("status") != "committed":
        raise AuditValidationError(f"{label} is not a committed terminal record")
    operation_id, request, request_time, recorded_at = _validate_request(audit, label, expected)
    anchor = validate_spend_authorization_anchor(spend_authorization)
    admission, binding_policies = _validate_policy_and_reads(
        audit,
        label,
        anchor=anchor,
        expected=expected,
        request_time=request_time,
    )
    if audit.get("decision") != dict(expected.terminal_decision):
        raise AuditValidationError(f"{label} has the wrong committed terminal decision")
    resolution = _human_resolution(
        audit,
        label,
        expected=expected,
        request_time=request_time,
        recorded_at=recorded_at,
    )
    entitlement = _mapping(audit.get("entitlement"), f"{label}.entitlement")
    if set(entitlement) != {"authorization_digest", "entitlement_id"}:
        raise AuditValidationError(f"{label} entitlement evidence has an incompatible shape")
    entitlement_id = _string(entitlement.get("entitlement_id"), f"{label}.entitlement_id")
    authorization = _sha256_string(
        entitlement.get("authorization_digest"), f"{label}.authorization_digest"
    )
    effect = _mapping(audit.get("effect"), f"{label}.effect")
    if set(effect) != {"action", "args", "payload"}:
        raise AuditValidationError(f"{label} effect has an incompatible shape")
    payload = _mapping(effect.get("payload"), f"{label}.effect.payload")
    expected_payload_shape = {
        "amount_cents",
        "authorization",
        "authorization_digest",
        "budget_version",
        "entitlement_id",
        "entitlement_state",
        "handoff",
        "merchant_id",
        "protected_execution",
        "request_ref",
        "team_id",
    }
    if resolution is not None:
        expected_payload_shape.add("resolution")
    if set(payload) != expected_payload_shape:
        raise AuditValidationError(f"{label} effect payload has an incompatible shape")
    budget_version = _integer(payload.get("budget_version"), f"{label}.budget_version")
    if budget_version != expected.budget_version:
        raise AuditValidationError(f"{label} committed effect has the wrong budget version")
    configuration_digest = _string(
        anchor.get("configuration_digest"), "executed spend configuration digest"
    )
    if authorization != authorization_digest(
        request,
        admission,
        budget_version=budget_version,
        configuration_digest=configuration_digest,
        resolution=resolution,
    ):
        raise AuditValidationError(f"{label} authorization digest is not durable evidence")

    protected = _mapping(audit.get("protected_execution"), f"{label}.protected_execution")
    if not {
        "binding",
        "binding_canonical_json",
        "binding_digest",
        "dispatch_started",
        "entitlement_state",
        "execution_id",
        "external_operation_id",
        "last_fence_token",
        "lease",
        "receipt",
        "result",
        "status",
    } <= set(protected):
        raise AuditValidationError(f"{label} protected execution has an incompatible shape")
    binding = _mapping(protected.get("binding"), f"{label}.binding")
    if set(binding) != {
        "action",
        "arguments",
        "authorization_digest",
        "connector_id",
        "coordination_domain_id",
        "entitlement_id",
        "idempotency_key",
        "policies",
        "principal_id",
        "provider_identity",
        "scopes",
        "tool_call_id",
    }:
        raise AuditValidationError(f"{label} protected binding has an incompatible shape")
    provider = _mapping(binding.get("provider_identity"), f"{label}.provider_identity")
    if provider != {
        "configuration_version": configuration_digest,
        "implementation_version": _PROVIDER_IMPLEMENTATION,
        "provider_id": _PROVIDER_ID,
    }:
        raise AuditValidationError(f"{label} protected binding has the wrong provider identity")
    if (
        binding.get("action") != _ACTION
        or binding.get("arguments") != dict(expected.arguments)
        or binding.get("authorization_digest") != authorization
        or binding.get("connector_id") != _CONNECTOR_ID
        or binding.get("coordination_domain_id") != "masugate.spend.reference.domain.v1"
        or binding.get("entitlement_id") != entitlement_id
        or binding.get("idempotency_key") != expected.idempotency_key
        or binding.get("policies") != binding_policies
        or binding.get("principal_id") != expected.principal_id
        or binding.get("scopes") != [_SCOPE]
        or binding.get("tool_call_id") != expected.trace_id
    ):
        raise AuditValidationError(f"{label} protected binding is not bound to its authorization")
    canonical = _string(protected.get("binding_canonical_json"), f"{label}.binding_canonical_json")
    if canonical != _canonical_json(binding):
        raise AuditValidationError(f"{label} protected binding is not canonical")
    binding_digest = _sha256_string(protected.get("binding_digest"), f"{label}.binding_digest")
    if hashlib.sha256(canonical.encode()).hexdigest() != binding_digest:
        raise AuditValidationError(f"{label} protected binding digest is invalid")
    last_fence_token = _integer(
        protected.get("last_fence_token"), f"{label}.protected_execution.last_fence_token"
    )
    if last_fence_token < 1:
        raise AuditValidationError(f"{label} protected execution has an invalid fence token")
    if (
        protected.get("execution_id") != f"px:{binding_digest}"
        or protected.get("status") != "succeeded"
        or protected.get("entitlement_state") != "consumed"
        or protected.get("dispatch_started") is not True
        or protected.get("lease") is not None
    ):
        raise AuditValidationError(f"{label} protected execution is not terminally consumed")

    receipt = _mapping(protected.get("receipt"), f"{label}.receipt")
    if set(receipt) != {
        "connector_id",
        "evidence_id",
        "external_operation_id",
        "idempotency_key",
        "observed_at",
        "outcome",
        "payload",
    }:
        raise AuditValidationError(f"{label} connector receipt has an incompatible shape")
    external_operation_id = _string(
        receipt.get("external_operation_id"), f"{label}.receipt.external_operation_id"
    )
    observed_at = _timestamp(receipt.get("observed_at"), f"{label}.receipt.observed_at")
    if not request_time <= observed_at <= recorded_at:
        raise AuditValidationError(f"{label} connector receipt has an invalid observation time")
    if resolution is not None and observed_at < _timestamp(
        resolution.get("resolved_at"), f"{label}.human_resolution.resolved_at"
    ):
        raise AuditValidationError(f"{label} connector receipt predates human approval")
    receipt_payload = {
        "amount_cents": expected.arguments.get("amount_cents"),
        "merchant_id": expected.arguments.get("merchant_id"),
    }
    if (
        receipt.get("connector_id") != _CONNECTOR_ID
        or receipt.get("evidence_id") != f"purchase-evidence:{binding_digest[:32]}"
        or external_operation_id != f"purchase:{binding_digest[:32]}"
        or receipt.get("idempotency_key") != f"masugate:{binding_digest}"
        or receipt.get("outcome") != "succeeded"
        or receipt.get("payload") != receipt_payload
        or protected.get("external_operation_id") != external_operation_id
        or protected.get("result") != receipt_payload
    ):
        raise AuditValidationError(f"{label} connector receipt is not bound to the purchase")
    handoff = _mapping(payload.get("handoff"), f"{label}.effect.handoff")
    payload_protected = _mapping(
        payload.get("protected_execution"), f"{label}.effect.protected_execution"
    )
    expected_payload_protected = {
        "binding_digest": binding_digest,
        "dispatch_started": True,
        "entitlement_state": "consumed",
        "execution_id": f"px:{binding_digest}",
        "external_operation_id": external_operation_id,
        "fence_token": last_fence_token,
        "lease": protected.get("lease"),
        "receipt": receipt,
        "status": "succeeded",
    }
    if (
        effect.get("action") != _ACTION
        or effect.get("args") != dict(expected.arguments)
        or payload.get("amount_cents") != expected.arguments.get("amount_cents")
        or payload.get("authorization") != _effect_authorization(admission)
        or payload.get("authorization_digest") != authorization
        or payload.get("entitlement_state") != "consumed"
        or payload.get("entitlement_id") != entitlement_id
        or handoff != {"binding_digest": binding_digest, "state": "succeeded"}
        or payload.get("merchant_id") != expected.arguments.get("merchant_id")
        or payload_protected != expected_payload_protected
        or payload.get("request_ref") != expected.arguments.get("request_ref")
        or payload.get("team_id") != "research"
        or payload.get("resolution") != resolution
    ):
        raise AuditValidationError(f"{label} committed effect is not bound to the execution")
    terminal = _mapping(audit.get("terminal_serialization"), f"{label}.terminal_serialization")
    evaluations = cast(list[object], audit["authorization_evaluations"])
    evaluated_at = _mapping(evaluations[0], f"{label}.admission").get("evaluated_at")
    if terminal != {
        "authorization_basis": expected.authorization_basis,
        "evaluation_at": evaluated_at,
        "evaluation_phase": "admission",
        "kind": "effect-commit",
        "provider_atomic": False,
        "recorded_at": audit.get("recorded_at"),
    }:
        raise AuditValidationError(f"{label} has the wrong terminal serialization")
    return ValidatedSpendAudit(
        audit=audit,
        available_cents=expected.available_cents,
        budget_version=budget_version,
        operation_id=operation_id,
        read_version=expected.read_version,
    )


def validate_denied_spend_audit(
    record: object,
    label: str,
    *,
    expected: SpendAuditExpectation,
    spend_authorization: Mapping[str, object],
) -> ValidatedSpendAudit:
    """Validate a denied record and prove that it serialized no effect."""

    audit = _mapping(record, label)
    if audit.get("status") != "denied":
        raise AuditValidationError(f"{label} is not a denied terminal record")
    operation_id, request, request_time, recorded_at = _validate_request(audit, label, expected)
    anchor = validate_spend_authorization_anchor(spend_authorization)
    admission, _binding_policies = _validate_policy_and_reads(
        audit,
        label,
        anchor=anchor,
        expected=expected,
        request_time=request_time,
    )
    if audit.get("decision") != dict(expected.terminal_decision):
        raise AuditValidationError(f"{label} has the wrong denied terminal decision")
    _human_resolution(
        audit,
        label,
        expected=expected,
        request_time=request_time,
        recorded_at=recorded_at,
    )
    entitlement = _mapping(audit.get("entitlement"), f"{label}.entitlement")
    if set(entitlement) != {"authorization_digest", "entitlement_id"}:
        raise AuditValidationError(f"{label} entitlement evidence has an incompatible shape")
    _string(entitlement.get("entitlement_id"), f"{label}.entitlement_id")
    authorization = _sha256_string(
        entitlement.get("authorization_digest"), f"{label}.authorization_digest"
    )
    configuration_digest = _string(
        anchor.get("configuration_digest"), "executed spend configuration digest"
    )
    if authorization != authorization_digest(
        request,
        admission,
        budget_version=expected.budget_version,
        configuration_digest=configuration_digest,
        resolution=None,
    ):
        raise AuditValidationError(f"{label} authorization digest is not durable evidence")
    if audit.get("effect") is not None or audit.get("protected_execution") is not None:
        raise AuditValidationError(f"{label} denied record contains protected effect evidence")
    evaluations = cast(list[object], audit["authorization_evaluations"])
    evaluated_at = _mapping(evaluations[0], f"{label}.admission").get("evaluated_at")
    terminal = _mapping(audit.get("terminal_serialization"), f"{label}.terminal_serialization")
    if terminal != {
        "authorization_basis": expected.authorization_basis,
        "evaluation_at": evaluated_at,
        "evaluation_phase": "admission",
        "kind": "denial-record",
        "provider_atomic": False,
        "recorded_at": audit.get("recorded_at"),
    }:
        raise AuditValidationError(f"{label} has the wrong denial serialization")
    return ValidatedSpendAudit(
        audit=audit,
        available_cents=expected.available_cents,
        budget_version=expected.budget_version,
        operation_id=operation_id,
        read_version=expected.read_version,
    )
