"""Strict-enough wire parsing with forward-compatible handling of extra fields."""

from __future__ import annotations

import json
import math
import re
from datetime import datetime
from hashlib import sha256
from typing import Literal, cast
from uuid import UUID

from .errors import MasuGateProtocolError
from .models import (
    ActionResult,
    ActionStatus,
    AppliedEffect,
    AuditDecision,
    AuditEntitlement,
    AuditPrincipal,
    AuditRecord,
    AuditRequest,
    AuthorizationEvaluation,
    AutomaticExpiry,
    CertifiedInputEvidence,
    Decision,
    DecisionEffect,
    EvaluatedPolicy,
    HumanResolution,
    JsonValue,
    PendingEvent,
    PendingList,
    PendingLookup,
    PendingOperation,
    PendingResolutionPlan,
    PolicyCatalog,
    PolicyProvenance,
    PolicyReceipt,
    ProtectedArtifactMetadata,
    ProtectedConnectorEvidence,
    ProtectedConnectorOutcome,
    ProtectedEntitlementState,
    ProtectedExecutionAudit,
    ProtectedExecutionAuditEvent,
    ProtectedExecutionStatus,
    Scalar,
    StagedArtifact,
    TerminalSerialization,
    ViewRead,
)


def _fail(path: str, expected: str) -> MasuGateProtocolError:
    return MasuGateProtocolError(f"{path} must be {expected}")


def _object(value: object, path: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise _fail(path, "an object")
    if any(not isinstance(key, str) for key in value):
        raise _fail(path, "an object with string keys")
    return cast(dict[str, object], value)


def _array(value: object, path: str) -> list[object]:
    if not isinstance(value, list):
        raise _fail(path, "an array")
    return cast(list[object], value)


def _required(obj: dict[str, object], key: str, path: str) -> object:
    if key not in obj:
        raise MasuGateProtocolError(f"{path}.{key} is required")
    return obj[key]


def _string(
    value: object,
    path: str,
    *,
    nonempty: bool = True,
    maximum_length: int | None = None,
) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        qualifier = "a non-empty string" if nonempty else "a string"
        raise _fail(path, qualifier)
    if maximum_length is not None and len(value) > maximum_length:
        raise _fail(path, f"a string no longer than {maximum_length} characters")
    return value


def _optional_string(value: object, path: str) -> str | None:
    if value is None:
        return None
    return _string(value, path)


def _boolean(value: object, path: str) -> bool:
    if not isinstance(value, bool):
        raise _fail(path, "a boolean")
    return value


def _integer(value: object, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _fail(path, "an integer")
    return value


def _number(value: object, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _fail(path, "a number")
    number = float(value)
    if not math.isfinite(number):
        raise _fail(path, "a finite number")
    return number


def _json_value(value: object, path: str) -> JsonValue:
    if value is None or isinstance(value, bool | str):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _fail(path, "a finite JSON value")
        return value
    if isinstance(value, list):
        return [_json_value(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, dict):
        raw = _object(value, path)
        return {key: _json_value(item, f"{path}.{key}") for key, item in raw.items()}
    raise _fail(path, "a JSON value")


def json_object(value: object, path: str) -> dict[str, JsonValue]:
    raw = _object(value, path)
    return {key: _json_value(item, f"{path}.{key}") for key, item in raw.items()}


def _canonical_protected_binding_json(binding: dict[str, JsonValue]) -> str:
    """Return the exact serialization used by ``ProtectedExecutionBinding``."""

    return json.dumps(
        binding,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _scalar(value: object, path: str) -> Scalar:
    if isinstance(value, bool | str):
        return value
    if isinstance(value, int):
        return value
    raise _fail(path, "a string, integer, or boolean")


def _date_time(value: object, path: str) -> datetime:
    text = _string(value, path)
    try:
        normalized = text.removesuffix("Z") + ("+00:00" if text.endswith("Z") else "")
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise _fail(path, "an RFC 3339 date-time") from exc
    if parsed.utcoffset() is None:
        raise _fail(path, "an RFC 3339 date-time with a UTC offset")
    return parsed


def _uuid(value: object, path: str) -> str:
    text = _string(value, path)
    try:
        UUID(text)
    except ValueError as exc:
        raise _fail(path, "a UUID string") from exc
    return text


def _audit_ref(value: object, path: str) -> str:
    ref = _string(value, path)
    if not ref.startswith("/v1/audit/") or ref == "/v1/audit/" or "/" in ref[10:]:
        raise _fail(path, "a /v1/audit/{operation_id} path")
    return ref


def _effect(value: object, path: str) -> DecisionEffect:
    effect = _string(value, path)
    if effect not in {"allow", "deny", "escalate"}:
        raise _fail(path, "one of allow, deny, or escalate")
    return cast(DecisionEffect, effect)


def _status(value: object, path: str) -> ActionStatus:
    status = _string(value, path)
    if status not in {
        "committed",
        "denied",
        "pending",
        "in_progress",
        "outcome_unknown",
    }:
        raise _fail(
            path,
            "one of committed, denied, pending, in_progress, or outcome_unknown",
        )
    return cast(ActionStatus, status)


def _resolution_plan(value: object, path: str) -> PendingResolutionPlan:
    plan = _string(value, path)
    if plan not in {"revalidate", "scoped-hold", "reservation-proof"}:
        raise _fail(path, "one of revalidate, scoped-hold, or reservation-proof")
    return cast(PendingResolutionPlan, plan)


def _protected_status(value: object, path: str) -> ProtectedExecutionStatus:
    status = _string(value, path)
    if status not in {"intent", "executing", "succeeded", "failed", "outcome_unknown"}:
        raise _fail(path, "a protected-execution status")
    return cast(ProtectedExecutionStatus, status)


def _protected_entitlement(value: object, path: str) -> ProtectedEntitlementState:
    state = _string(value, path)
    if state not in {"held", "consumed", "released", "quarantined"}:
        raise _fail(path, "a protected entitlement state")
    return cast(ProtectedEntitlementState, state)


def _protected_outcome(value: object, path: str) -> ProtectedConnectorOutcome:
    outcome = _string(value, path)
    if outcome not in {"succeeded", "failed", "unknown"}:
        raise _fail(path, "a protected connector outcome")
    return cast(ProtectedConnectorOutcome, outcome)


def _resolution_metadata(
    raw: dict[str, object], path: str
) -> tuple[PendingResolutionPlan | None, str | None, str | None]:
    has_plan = "resolution_plan" in raw
    has_digest = "reservation_safety_certificate_digest" in raw
    has_entitlement = "reservation_entitlement_digest" in raw
    if not has_plan:
        if has_digest or has_entitlement:
            raise MasuGateProtocolError(
                f"{path} reservation proof digests require resolution_plan"
            )
        # Compatibility with servers predating explicit pending-resolution metadata.
        return None, None, None
    plan = _resolution_plan(raw["resolution_plan"], f"{path}.resolution_plan")
    digest = (
        _string(
            raw["reservation_safety_certificate_digest"],
            f"{path}.reservation_safety_certificate_digest",
        )
        if has_digest
        else None
    )
    if digest is not None and re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise _fail(
            f"{path}.reservation_safety_certificate_digest",
            "a 64-character lowercase hexadecimal digest",
        )
    entitlement_digest = (
        _string(
            raw["reservation_entitlement_digest"],
            f"{path}.reservation_entitlement_digest",
        )
        if has_entitlement
        else None
    )
    if entitlement_digest is not None and re.fullmatch(r"[0-9a-f]{64}", entitlement_digest) is None:
        raise _fail(
            f"{path}.reservation_entitlement_digest",
            "a 64-character lowercase hexadecimal digest",
        )
    if plan == "reservation-proof" and (digest is None or entitlement_digest is None):
        raise MasuGateProtocolError(
            f"{path} reservation proof requires both safety-certificate and entitlement digests"
        )
    if plan != "reservation-proof" and (digest is not None or entitlement_digest is not None):
        raise MasuGateProtocolError(f"{path} reservation proof digests are forbidden for {plan}")
    return plan, digest, entitlement_digest


def _evaluated_policies(value: object, path: str) -> tuple[EvaluatedPolicy, ...]:
    policies: list[EvaluatedPolicy] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(_array(value, path)):
        item_path = f"{path}[{index}]"
        raw = _object(item, item_path)
        policy = EvaluatedPolicy(
            policy_id=_string(_required(raw, "policy_id", item_path), f"{item_path}.policy_id"),
            policy_version=_string(
                _required(raw, "policy_version", item_path),
                f"{item_path}.policy_version",
                nonempty=False,
            ),
        )
        key = (policy.policy_id, policy.policy_version)
        if key in seen:
            raise MasuGateProtocolError(f"{path} contains a duplicate policy")
        seen.add(key)
        policies.append(policy)
    return tuple(policies)


def _policy_provenance(value: object, path: str) -> tuple[PolicyProvenance, ...]:
    provenance: list[PolicyProvenance] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(_array(value, path)):
        item_path = f"{path}[{index}]"
        raw = _object(item, item_path)
        layer = _string(_required(raw, "layer", item_path), f"{item_path}.layer")
        if layer not in {"platform-safety", "deployment-regulatory", "owner"}:
            raise _fail(f"{item_path}.layer", "a governance policy layer")
        mode = _string(_required(raw, "mode", item_path), f"{item_path}.mode")
        expected_mode = "configurable" if layer == "owner" else "mandatory"
        if mode != expected_mode:
            raise _fail(f"{item_path}.mode", expected_mode)

        policy_digest = _string(
            _required(raw, "policy_digest", item_path), f"{item_path}.policy_digest"
        )
        bundle_digest = _string(
            _required(raw, "bundle_digest", item_path), f"{item_path}.bundle_digest"
        )
        if re.fullmatch(r"[0-9a-f]{64}", policy_digest) is None:
            raise _fail(f"{item_path}.policy_digest", "a lowercase SHA-256 digest")
        if re.fullmatch(r"[0-9a-f]{64}", bundle_digest) is None:
            raise _fail(f"{item_path}.bundle_digest", "a lowercase SHA-256 digest")

        record = PolicyProvenance(
            policy_id=_string(_required(raw, "policy_id", item_path), f"{item_path}.policy_id"),
            policy_declared_version=_string(
                _required(raw, "policy_declared_version", item_path),
                f"{item_path}.policy_declared_version",
            ),
            policy_runtime_version=_string(
                _required(raw, "policy_runtime_version", item_path),
                f"{item_path}.policy_runtime_version",
            ),
            policy_digest=policy_digest,
            bundle_id=_string(_required(raw, "bundle_id", item_path), f"{item_path}.bundle_id"),
            bundle_version=_string(
                _required(raw, "bundle_version", item_path), f"{item_path}.bundle_version"
            ),
            bundle_digest=bundle_digest,
            layer=cast(Literal["platform-safety", "deployment-regulatory", "owner"], layer),
            mode=cast(Literal["mandatory", "configurable"], mode),
        )
        key = (record.bundle_id, record.policy_id)
        if key in seen:
            raise MasuGateProtocolError(f"{path} contains duplicate policy provenance")
        seen.add(key)
        provenance.append(record)
    return tuple(provenance)


def _decision(value: object, path: str) -> Decision:
    raw = _object(value, path)
    evaluated_raw = raw.get("evaluated_policies", [])
    return Decision(
        effect=_effect(_required(raw, "effect", path), f"{path}.effect"),
        policy_id=_string(_required(raw, "policy_id", path), f"{path}.policy_id"),
        policy_version=_string(
            _required(raw, "policy_version", path),
            f"{path}.policy_version",
            nonempty=False,
        ),
        rule_id=_string(_required(raw, "rule_id", path), f"{path}.rule_id"),
        reason=_string(_required(raw, "reason", path), f"{path}.reason", nonempty=False),
        evaluated_policies=_evaluated_policies(evaluated_raw, f"{path}.evaluated_policies"),
        policy_provenance=_policy_provenance(
            raw.get("policy_provenance", []),
            f"{path}.policy_provenance",
        ),
    )


def parse_action_result(value: object) -> ActionResult:
    path = "action response"
    raw = _object(value, path)
    status = _status(_required(raw, "status", path), f"{path}.status")
    raw_decision = _required(raw, "decision", path)
    expected_effect: dict[str, DecisionEffect] = {
        "committed": "allow",
        "denied": "deny",
        "pending": "escalate",
    }
    if status in {"in_progress", "outcome_unknown"}:
        if raw_decision is not None:
            raise MasuGateProtocolError(f"{path}.decision must be null for status {status!r}")
        decision = None
    else:
        decision = _decision(raw_decision, f"{path}.decision")
        if decision.effect != expected_effect[status]:
            raise MasuGateProtocolError(
                f"{path} couples status {status!r} with invalid effect {decision.effect!r}"
            )
    pending_id = (
        _uuid(_required(raw, "pending_id", path), f"{path}.pending_id")
        if status == "pending"
        else None
    )
    if status != "pending" and "pending_id" in raw:
        raise MasuGateProtocolError(f"{path}.pending_id is forbidden for non-pending results")
    if status == "pending":
        resolution_plan, certificate_digest, entitlement_digest = _resolution_metadata(raw, path)
    else:
        if (
            "resolution_plan" in raw
            or "reservation_safety_certificate_digest" in raw
            or "reservation_entitlement_digest" in raw
        ):
            raise MasuGateProtocolError(
                f"{path} pending-resolution metadata is forbidden for non-pending results"
            )
        resolution_plan, certificate_digest, entitlement_digest = None, None, None
    return ActionResult(
        operation_id=_uuid(_required(raw, "operation_id", path), f"{path}.operation_id"),
        status=status,
        decision=decision,
        payload=json_object(_required(raw, "payload", path), f"{path}.payload"),
        audit_ref=_audit_ref(_required(raw, "audit_ref", path), f"{path}.audit_ref"),
        replayed=_boolean(_required(raw, "replayed", path), f"{path}.replayed"),
        pending_id=pending_id,
        resolution_plan=resolution_plan,
        reservation_safety_certificate_digest=certificate_digest,
        reservation_entitlement_digest=entitlement_digest,
    )


def parse_staged_artifact(value: object) -> StagedArtifact:
    """Parse the closed connector worker artifact-staging receipt."""

    path = "artifact response"
    raw = _object(value, path)
    expected = {
        "reference",
        "content_digest",
        "content_bytes",
        "media_type",
        "classification",
        "expires_at",
    }
    if set(raw) != expected:
        raise MasuGateProtocolError(
            "artifact response must contain exactly the staging receipt fields"
        )
    reference = _string(_required(raw, "reference", path), f"{path}.reference")
    if not reference.startswith("art:"):
        raise _fail(f"{path}.reference", "an opaque art: reference")
    content_digest = _string(_required(raw, "content_digest", path), f"{path}.content_digest")
    if re.fullmatch(r"[0-9a-f]{64}", content_digest) is None:
        raise _fail(f"{path}.content_digest", "a 64-character lowercase hexadecimal digest")
    content_bytes = _integer(_required(raw, "content_bytes", path), f"{path}.content_bytes")
    if content_bytes < 0:
        raise _fail(f"{path}.content_bytes", "a non-negative integer")
    media_type = _string(_required(raw, "media_type", path), f"{path}.media_type")
    if "/" not in media_type or any(character.isspace() for character in media_type):
        raise _fail(f"{path}.media_type", "a normalized media type")
    return StagedArtifact(
        reference=reference,
        content_digest=content_digest,
        content_bytes=content_bytes,
        media_type=media_type,
        classification=_string(
            _required(raw, "classification", path),
            f"{path}.classification",
            maximum_length=255,
        ),
        expires_at=_date_time(_required(raw, "expires_at", path), f"{path}.expires_at"),
    )


def _pending_operation(value: object, path: str) -> PendingOperation:
    raw = _object(value, path)
    decision = _decision(_required(raw, "decision", path), f"{path}.decision")
    if decision.effect != "escalate":
        raise MasuGateProtocolError(f"{path}.decision.effect must be escalate")
    pending_id = _uuid(_required(raw, "pending_id", path), f"{path}.pending_id")
    operation_id = _uuid(_required(raw, "operation_id", path), f"{path}.operation_id")
    resolution_plan, certificate_digest, entitlement_digest = _resolution_metadata(raw, path)
    return PendingOperation(
        pending_id=pending_id,
        operation_id=operation_id,
        principal_id=_string(_required(raw, "principal_id", path), f"{path}.principal_id"),
        action=_string(_required(raw, "action", path), f"{path}.action"),
        args=json_object(_required(raw, "args", path), f"{path}.args"),
        created_at=_date_time(_required(raw, "created_at", path), f"{path}.created_at"),
        decision=decision,
        audit_ref=_audit_ref(_required(raw, "audit_ref", path), f"{path}.audit_ref"),
        resolution_plan=resolution_plan,
        reservation_safety_certificate_digest=certificate_digest,
        reservation_entitlement_digest=entitlement_digest,
    )


def parse_pending_event(value: object) -> PendingEvent:
    path = "pending event"
    raw = _object(value, path)
    event_type = _string(_required(raw, "event_type", path), f"{path}.event_type")
    if event_type != "pending.created":
        raise MasuGateProtocolError(f"{path}.event_type must be pending.created")
    event_id = _string(_required(raw, "event_id", path), f"{path}.event_id")
    pending = _pending_operation(_required(raw, "pending", path), f"{path}.pending")
    if event_id != pending.pending_id:
        raise MasuGateProtocolError(f"{path}.event_id must equal pending.pending_id")
    return PendingEvent(
        event_id=event_id,
        event_type=cast(Literal["pending.created"], event_type),
        occurred_at=_date_time(_required(raw, "occurred_at", path), f"{path}.occurred_at"),
        pending=pending,
    )


def parse_pending_list(value: object) -> PendingList:
    path = "pending list"
    raw = _object(value, path)
    items_raw = _array(_required(raw, "items", path), f"{path}.items")
    items = tuple(
        _pending_operation(item, f"{path}.items[{index}]") for index, item in enumerate(items_raw)
    )
    return PendingList(
        items=items,
        next_cursor=_string(_required(raw, "next_cursor", path), f"{path}.next_cursor"),
    )


def parse_pending_lookup(value: object) -> PendingLookup:
    """Parse the owner-scoped pending locator/replay read response."""

    path = "pending lookup response"
    raw = _object(value, path)
    kind = _string(_required(raw, "kind", path), f"{path}.kind")
    if kind == "pending":
        if "result" in raw or "pending" not in raw:
            raise MasuGateProtocolError(f"{path}.pending shape is invalid")
        return PendingLookup(
            kind="pending",
            pending=_pending_operation(raw["pending"], f"{path}.pending"),
        )
    if kind == "terminal":
        if "pending" in raw or "result" not in raw:
            raise MasuGateProtocolError(f"{path}.result shape is invalid")
        result = parse_action_result(raw["result"])
        if result.status == "pending":
            raise MasuGateProtocolError(f"{path}.terminal result must not be pending")
        return PendingLookup(kind="terminal", result=result)
    raise MasuGateProtocolError(f"{path}.kind must be pending or terminal")


def _audit_principal(value: object, path: str) -> AuditPrincipal:
    raw = _object(value, path)
    attrs_raw = _object(_required(raw, "attributes", path), f"{path}.attributes")
    return AuditPrincipal(
        id=_string(_required(raw, "id", path), f"{path}.id"),
        attributes={
            key: _scalar(item, f"{path}.attributes.{key}") for key, item in attrs_raw.items()
        },
    )


def _audit_request(value: object, path: str) -> AuditRequest:
    raw = _object(value, path)
    timestamp = _date_time(_required(raw, "timestamp", path), f"{path}.timestamp")
    return AuditRequest(
        idempotency_key=_string(_required(raw, "idempotency_key", path), f"{path}.idempotency_key"),
        principal=_audit_principal(_required(raw, "principal", path), f"{path}.principal"),
        action=_string(_required(raw, "action", path), f"{path}.action"),
        args=json_object(_required(raw, "args", path), f"{path}.args"),
        timestamp=timestamp,
        request_time=(
            _date_time(raw["request_time"], f"{path}.request_time")
            if "request_time" in raw
            else timestamp
        ),
        trace_id=_optional_string(raw.get("trace_id"), f"{path}.trace_id"),
        adapter_invocation_digest=(
            _hex_digest(raw["adapter_invocation_digest"], f"{path}.adapter_invocation_digest")
            if "adapter_invocation_digest" in raw
            else None
        ),
        protected_artifacts=_protected_artifacts(
            raw.get("protected_artifacts", {}), f"{path}.protected_artifacts"
        ),
    )


def _protected_artifacts(value: object, path: str) -> dict[str, ProtectedArtifactMetadata]:
    raw = _object(value, path)
    parsed: dict[str, ProtectedArtifactMetadata] = {}
    expected = {
        "reference",
        "content_digest",
        "content_bytes",
        "media_type",
        "classification",
        "expires_at",
        "inspector_version",
    }
    for field, metadata in raw.items():
        item_path = f"{path}.{field}"
        item = _object(metadata, item_path)
        if set(item) != expected:
            raise MasuGateProtocolError(
                f"{item_path} must contain exactly protected artifact metadata"
            )
        reference = _string(_required(item, "reference", item_path), f"{item_path}.reference")
        if not reference.startswith("art:"):
            raise _fail(f"{item_path}.reference", "an opaque art: reference")
        content_digest = _hex_digest(
            _required(item, "content_digest", item_path), f"{item_path}.content_digest"
        )
        content_bytes = _integer(
            _required(item, "content_bytes", item_path), f"{item_path}.content_bytes"
        )
        if content_bytes < 0:
            raise _fail(f"{item_path}.content_bytes", "a non-negative integer")
        parsed[field] = ProtectedArtifactMetadata(
            reference=reference,
            content_digest=content_digest,
            content_bytes=content_bytes,
            media_type=_string(_required(item, "media_type", item_path), f"{item_path}.media_type"),
            classification=_string(
                _required(item, "classification", item_path),
                f"{item_path}.classification",
                maximum_length=255,
            ),
            expires_at=_date_time(
                _required(item, "expires_at", item_path), f"{item_path}.expires_at"
            ),
            inspector_version=_string(
                _required(item, "inspector_version", item_path),
                f"{item_path}.inspector_version",
                maximum_length=255,
            ),
        )
    return parsed


def _policy_receipt(value: object, path: str) -> PolicyReceipt:
    raw = _object(value, path)
    return PolicyReceipt(
        policy_id=_string(_required(raw, "policy_id", path), f"{path}.policy_id"),
        policy_version=_string(
            _required(raw, "policy_version", path),
            f"{path}.policy_version",
            nonempty=False,
        ),
        evaluated_policies=_evaluated_policies(
            _required(raw, "evaluated_policies", path),
            f"{path}.evaluated_policies",
        ),
        evaluated_policy_provenance=_policy_provenance(
            _required(raw, "evaluated_policy_provenance", path),
            f"{path}.evaluated_policy_provenance",
        ),
        catalog=(_policy_catalog(raw["catalog"], f"{path}.catalog") if "catalog" in raw else None),
    )


def _hex_digest(value: object, path: str) -> str:
    digest = _string(value, path)
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise _fail(path, "a 64-character lowercase hexadecimal digest")
    return digest


def _policy_catalog(value: object, path: str) -> PolicyCatalog:
    raw = _object(value, path)
    return PolicyCatalog(
        policy_digest=_hex_digest(_required(raw, "policy_digest", path), f"{path}.policy_digest"),
        bundle_digest=_hex_digest(_required(raw, "bundle_digest", path), f"{path}.bundle_digest"),
    )


def _audit_entitlement(value: object, path: str) -> AuditEntitlement:
    raw = _object(value, path)
    unexpected = set(raw) - {"entitlement_id", "authorization_digest"}
    if unexpected:
        raise MasuGateProtocolError(f"{path} has unknown fields: {sorted(unexpected)!r}")
    return AuditEntitlement(
        entitlement_id=_string(_required(raw, "entitlement_id", path), f"{path}.entitlement_id"),
        authorization_digest=_hex_digest(
            _required(raw, "authorization_digest", path), f"{path}.authorization_digest"
        ),
    )


def _validate_audit_provenance(
    policy: PolicyReceipt,
    entitlement: AuditEntitlement | None,
    protected_execution: ProtectedExecutionAudit | None,
    path: str,
) -> None:
    """Verify duplicated catalog and entitlement evidence remains one binding."""

    if policy.catalog is not None and not any(
        provenance.policy_digest == policy.catalog.policy_digest
        and provenance.bundle_digest == policy.catalog.bundle_digest
        for provenance in policy.evaluated_policy_provenance
    ):
        raise MasuGateProtocolError(
            f"{path}.policy.catalog does not match evaluated policy provenance"
        )
    if entitlement is None or protected_execution is None:
        return
    binding = protected_execution.binding
    if binding.get("entitlement_id") != entitlement.entitlement_id:
        raise MasuGateProtocolError(
            f"{path}.entitlement_id does not match protected execution binding"
        )
    if binding.get("authorization_digest") != entitlement.authorization_digest:
        raise MasuGateProtocolError(
            f"{path}.entitlement.authorization_digest does not match protected execution binding"
        )


def _protected_binding_policy_rows(
    binding: dict[str, JsonValue], path: str
) -> tuple[tuple[str, str, str, str, str, str], ...]:
    """Return the immutable policy basis carried by a protected binding."""

    raw_policies = binding.get("policies")
    if not isinstance(raw_policies, list):
        raise MasuGateProtocolError(f"{path}.binding.policies must be an array")
    rows: list[tuple[str, str, str, str, str, str]] = []
    for index, item in enumerate(raw_policies):
        item_path = f"{path}.binding.policies[{index}]"
        raw = _object(item, item_path)
        rows.append(
            (
                _string(_required(raw, "policy_id", item_path), f"{item_path}.policy_id"),
                _string(
                    _required(raw, "policy_version", item_path),
                    f"{item_path}.policy_version",
                ),
                _hex_digest(
                    _required(raw, "policy_digest", item_path), f"{item_path}.policy_digest"
                ),
                _string(_required(raw, "bundle_id", item_path), f"{item_path}.bundle_id"),
                _string(_required(raw, "bundle_version", item_path), f"{item_path}.bundle_version"),
                _hex_digest(
                    _required(raw, "bundle_digest", item_path), f"{item_path}.bundle_digest"
                ),
            )
        )
    return tuple(sorted(rows))


def _validate_protected_execution_binding(
    request: AuditRequest,
    policy: PolicyReceipt,
    effect: AppliedEffect | None,
    protected_execution: ProtectedExecutionAudit | None,
    path: str,
) -> None:
    """Require the displayed request, policy, and effect to name one binding."""

    if protected_execution is None:
        return
    binding = protected_execution.binding
    if binding.get("principal_id") != request.principal.id:
        raise MasuGateProtocolError(
            f"{path}.request principal does not match protected execution binding"
        )
    if binding.get("action") != request.action:
        raise MasuGateProtocolError(
            f"{path}.request action does not match protected execution binding"
        )
    if binding.get("arguments") != request.args:
        raise MasuGateProtocolError(
            f"{path}.request args do not match protected execution binding"
        )
    if binding.get("idempotency_key") != request.idempotency_key:
        raise MasuGateProtocolError(
            f"{path}.request idempotency key does not match protected execution binding"
        )
    if effect is not None and (
        effect.action != binding.get("action") or effect.args != binding.get("arguments")
    ):
        raise MasuGateProtocolError(f"{path}.effect does not match protected execution binding")
    if policy.evaluated_policy_provenance:
        expected = tuple(
            sorted(
                (
                    item.policy_id,
                    item.policy_declared_version,
                    item.policy_digest,
                    item.bundle_id,
                    item.bundle_version,
                    item.bundle_digest,
                )
                for item in policy.evaluated_policy_provenance
            )
        )
        actual = _protected_binding_policy_rows(binding, path)
        if actual != expected:
            raise MasuGateProtocolError(
                f"{path}.policy provenance does not match protected execution binding"
            )


def _audit_decision(value: object, path: str) -> AuditDecision:
    raw = _object(value, path)
    return AuditDecision(
        effect=_effect(_required(raw, "effect", path), f"{path}.effect"),
        rule_id=_string(_required(raw, "rule_id", path), f"{path}.rule_id"),
        reason=_string(_required(raw, "reason", path), f"{path}.reason", nonempty=False),
    )


def _view_read(value: object, path: str) -> ViewRead:
    raw = _object(value, path)
    arguments = tuple(
        _json_value(item, f"{path}.arguments[{index}]")
        for index, item in enumerate(_array(_required(raw, "arguments", path), f"{path}.arguments"))
    )
    version = _integer(_required(raw, "version", path), f"{path}.version")
    latency_ms = _number(_required(raw, "latency_ms", path), f"{path}.latency_ms")
    if version < 0:
        raise MasuGateProtocolError(f"{path}.version must be non-negative")
    if latency_ms < 0:
        raise MasuGateProtocolError(f"{path}.latency_ms must be non-negative")
    return ViewRead(
        function=_string(_required(raw, "function", path), f"{path}.function"),
        arguments=arguments,
        value=_json_value(_required(raw, "value", path), f"{path}.value"),
        scope=_string(_required(raw, "scope", path), f"{path}.scope"),
        version=version,
        latency_ms=latency_ms,
    )


def _applied_effect(value: object, path: str) -> AppliedEffect:
    raw = _object(value, path)
    return AppliedEffect(
        action=_string(_required(raw, "action", path), f"{path}.action"),
        args=json_object(_required(raw, "args", path), f"{path}.args"),
        payload=json_object(_required(raw, "payload", path), f"{path}.payload"),
    )


def _certified_input(value: object, path: str) -> CertifiedInputEvidence:
    raw = _object(value, path)
    value_type = _string(_required(raw, "value_type", path), f"{path}.value_type")
    stability = _string(_required(raw, "stability", path), f"{path}.stability")
    phase = _string(_required(raw, "phase", path), f"{path}.phase")
    proof = _optional_string(raw.get("stability_proof"), f"{path}.stability_proof")
    if value_type not in {"Bool", "Int", "String", "Duration"}:
        raise MasuGateProtocolError(f"{path}.value_type is invalid")
    if stability not in {"admission-stable", "resolution-volatile"}:
        raise MasuGateProtocolError(f"{path}.stability is invalid")
    if phase not in {"admission", "resolution"}:
        raise MasuGateProtocolError(f"{path}.phase is invalid")
    if proof not in {None, "request-bound-immutable-v1"}:
        raise MasuGateProtocolError(f"{path}.stability_proof is invalid")
    if (stability == "admission-stable") != (proof == "request-bound-immutable-v1"):
        raise MasuGateProtocolError(
            f"{path}.stability_proof does not prove the declared stability"
        )
    ttl = _integer(
        _required(raw, "freshness_ttl_seconds", path),
        f"{path}.freshness_ttl_seconds",
    )
    if ttl <= 0:
        raise MasuGateProtocolError(f"{path}.freshness_ttl_seconds must be positive")
    return CertifiedInputEvidence(
        name=_string(_required(raw, "name", path), f"{path}.name"),
        value=_json_value(_required(raw, "value", path), f"{path}.value"),
        value_type=cast(Literal["Bool", "Int", "String", "Duration"], value_type),
        stability=cast(Literal["admission-stable", "resolution-volatile"], stability),
        stability_proof=cast(Literal["request-bound-immutable-v1"] | None, proof),
        source_id=_string(_required(raw, "source_id", path), f"{path}.source_id"),
        source_version=_string(_required(raw, "source_version", path), f"{path}.source_version"),
        contract_version=_string(
            _required(raw, "contract_version", path), f"{path}.contract_version"
        ),
        observed_at=_date_time(_required(raw, "observed_at", path), f"{path}.observed_at"),
        certified_at=_date_time(_required(raw, "certified_at", path), f"{path}.certified_at"),
        freshness_ttl_seconds=ttl,
        expires_at=_date_time(_required(raw, "expires_at", path), f"{path}.expires_at"),
        phase=cast(Literal["admission", "resolution"], phase),
    )


def _authorization_evaluation(value: object, path: str) -> AuthorizationEvaluation:
    raw = _object(value, path)
    phase = _string(_required(raw, "phase", path), f"{path}.phase")
    if phase not in {"admission", "resolution"}:
        raise MasuGateProtocolError(f"{path}.phase is invalid")
    inputs = _array(_required(raw, "certified_inputs", path), f"{path}.certified_inputs")
    return AuthorizationEvaluation(
        phase=cast(Literal["admission", "resolution"], phase),
        evaluated_at=_date_time(_required(raw, "evaluated_at", path), f"{path}.evaluated_at"),
        decision=_decision(_required(raw, "decision", path), f"{path}.decision"),
        certified_inputs=tuple(
            _certified_input(item, f"{path}.certified_inputs[{index}]")
            for index, item in enumerate(inputs)
        ),
    )


def _terminal_serialization(value: object, path: str) -> TerminalSerialization:
    raw = _object(value, path)
    kind = _string(_required(raw, "kind", path), f"{path}.kind")
    if kind not in {"effect-commit", "denial-record"}:
        raise MasuGateProtocolError(f"{path}.kind is invalid")
    raw_phase = raw.get("evaluation_phase")
    phase = None if raw_phase is None else _string(raw_phase, f"{path}.evaluation_phase")
    if phase not in {None, "admission", "resolution"}:
        raise MasuGateProtocolError(f"{path}.evaluation_phase is invalid")
    return TerminalSerialization(
        kind=cast(Literal["effect-commit", "denial-record"], kind),
        authorization_basis=_string(
            _required(raw, "authorization_basis", path),
            f"{path}.authorization_basis",
        ),
        provider_atomic=_boolean(
            _required(raw, "provider_atomic", path), f"{path}.provider_atomic"
        ),
        recorded_at=_date_time(_required(raw, "recorded_at", path), f"{path}.recorded_at"),
        evaluation_phase=cast(Literal["admission", "resolution"] | None, phase),
        evaluation_at=(
            _date_time(raw["evaluation_at"], f"{path}.evaluation_at")
            if "evaluation_at" in raw
            else None
        ),
    )


def _protected_connector_evidence(value: object, path: str) -> ProtectedConnectorEvidence:
    raw = _object(value, path)
    return ProtectedConnectorEvidence(
        connector_id=_string(_required(raw, "connector_id", path), f"{path}.connector_id"),
        evidence_id=_string(_required(raw, "evidence_id", path), f"{path}.evidence_id"),
        idempotency_key=_string(_required(raw, "idempotency_key", path), f"{path}.idempotency_key"),
        external_operation_id=_optional_string(
            _required(raw, "external_operation_id", path),
            f"{path}.external_operation_id",
        ),
        outcome=_protected_outcome(_required(raw, "outcome", path), f"{path}.outcome"),
        observed_at=_date_time(_required(raw, "observed_at", path), f"{path}.observed_at"),
        payload=json_object(_required(raw, "payload", path), f"{path}.payload"),
    )


def _protected_execution_event(value: object, path: str) -> ProtectedExecutionAuditEvent:
    raw = _object(value, path)
    raw_from = _required(raw, "from_status", path)
    raw_fence = _required(raw, "fence_token", path)
    fence = None if raw_fence is None else _integer(raw_fence, f"{path}.fence_token")
    if fence is not None and fence < 1:
        raise _fail(f"{path}.fence_token", "a positive integer or null")
    sequence = _integer(_required(raw, "sequence", path), f"{path}.sequence")
    if sequence < 1:
        raise _fail(f"{path}.sequence", "a positive integer")
    return ProtectedExecutionAuditEvent(
        sequence=sequence,
        event_type=_string(_required(raw, "event_type", path), f"{path}.event_type"),
        from_status=(
            None if raw_from is None else _protected_status(raw_from, f"{path}.from_status")
        ),
        to_status=_protected_status(_required(raw, "to_status", path), f"{path}.to_status"),
        worker_id=_optional_string(_required(raw, "worker_id", path), f"{path}.worker_id"),
        fence_token=fence,
        recorded_at=_date_time(_required(raw, "recorded_at", path), f"{path}.recorded_at"),
        evidence=json_object(_required(raw, "evidence", path), f"{path}.evidence"),
    )


def _protected_execution(value: object, path: str) -> ProtectedExecutionAudit:
    raw = _object(value, path)
    execution_id = _string(_required(raw, "execution_id", path), f"{path}.execution_id")
    digest = _string(_required(raw, "binding_digest", path), f"{path}.binding_digest")
    if not re.fullmatch(r"[0-9a-f]{64}", digest) or execution_id != f"px:{digest}":
        raise MasuGateProtocolError(f"{path} execution identity does not match binding digest")
    binding = json_object(_required(raw, "binding", path), f"{path}.binding")
    canonical_binding_json = _string(
        _required(raw, "binding_canonical_json", path),
        f"{path}.binding_canonical_json",
    )
    try:
        canonical_binding = json_object(
            json.loads(canonical_binding_json),
            f"{path}.binding_canonical_json",
        )
    except (TypeError, ValueError) as exc:
        raise MasuGateProtocolError(
            f"{path}.binding_canonical_json must encode a JSON object"
        ) from exc
    if (
        canonical_binding != binding
        or _canonical_protected_binding_json(binding) != canonical_binding_json
    ):
        raise MasuGateProtocolError(
            f"{path}.binding_canonical_json does not match binding payload"
        )
    if sha256(canonical_binding_json.encode("utf-8")).hexdigest() != digest:
        raise MasuGateProtocolError(f"{path}.binding digest does not match binding payload")
    status = _protected_status(_required(raw, "status", path), f"{path}.status")
    entitlement = _protected_entitlement(
        _required(raw, "entitlement_state", path), f"{path}.entitlement_state"
    )
    dispatch_started = _boolean(
        _required(raw, "dispatch_started", path), f"{path}.dispatch_started"
    )
    raw_lease = _required(raw, "lease", path)
    lease_owner: str | None = None
    lease_fence: int | None = None
    lease_expires: datetime | None = None
    if raw_lease is not None:
        lease = _object(raw_lease, f"{path}.lease")
        lease_owner = _string(_required(lease, "owner", f"{path}.lease"), f"{path}.lease.owner")
        lease_fence = _integer(
            _required(lease, "fence_token", f"{path}.lease"), f"{path}.lease.fence_token"
        )
        lease_expires = _date_time(
            _required(lease, "expires_at", f"{path}.lease"), f"{path}.lease.expires_at"
        )
        if lease_fence < 1:
            raise _fail(f"{path}.lease.fence_token", "a positive integer")
    last_fence = _integer(_required(raw, "last_fence_token", path), f"{path}.last_fence_token")
    if last_fence < 0:
        raise _fail(f"{path}.last_fence_token", "a non-negative integer")
    if lease_fence is not None and lease_fence != last_fence:
        raise MasuGateProtocolError(f"{path}.lease fence must equal the last fence")
    raw_receipt = _required(raw, "receipt", path)
    receipt = (
        None
        if raw_receipt is None
        else _protected_connector_evidence(raw_receipt, f"{path}.receipt")
    )
    external_operation_id = _optional_string(
        _required(raw, "external_operation_id", path),
        f"{path}.external_operation_id",
    )
    events_raw = _array(_required(raw, "events", path), f"{path}.events")
    events = tuple(
        _protected_execution_event(item, f"{path}.events[{index}]")
        for index, item in enumerate(events_raw)
    )
    if tuple(event.sequence for event in events) != tuple(range(1, len(events) + 1)):
        raise MasuGateProtocolError(f"{path}.events must be an ordered contiguous audit trail")
    if events and events[-1].to_status != status:
        raise MasuGateProtocolError(f"{path}.status must match the last audit event")
    expected_entitlement = {
        "intent": "held",
        "executing": "held",
        "succeeded": "consumed",
        "failed": "released",
        "outcome_unknown": "quarantined",
    }[status]
    if entitlement != expected_entitlement:
        raise MasuGateProtocolError(f"{path}.entitlement_state contradicts status")
    if not dispatch_started and (receipt is not None or external_operation_id is not None):
        raise MasuGateProtocolError(
            f"{path} undispatched execution cannot carry external-operation evidence"
        )
    if receipt is not None and receipt.external_operation_id != external_operation_id:
        raise MasuGateProtocolError(f"{path}.receipt changed the external-operation identity")
    if receipt is not None and receipt.idempotency_key != f"masugate:{digest}":
        raise MasuGateProtocolError(
            f"{path}.receipt idempotency key does not match binding digest"
        )
    binding_connector_id = _string(
        binding.get("connector_id"),
        f"{path}.binding.connector_id",
    )
    if receipt is not None and receipt.connector_id != binding_connector_id:
        raise MasuGateProtocolError(f"{path}.receipt connector does not match binding")
    if (
        receipt is not None
        and receipt.outcome != "unknown"
        and receipt.external_operation_id is None
    ):
        raise MasuGateProtocolError(
            f"{path}.receipt terminal outcome requires an external operation id"
        )
    if status == "outcome_unknown" and not dispatch_started:
        raise MasuGateProtocolError(f"{path}.outcome_unknown requires a dispatch marker")
    if status == "succeeded" and (receipt is None or receipt.outcome != "succeeded"):
        raise MasuGateProtocolError(f"{path}.succeeded requires success evidence")
    if status == "failed" and dispatch_started and (receipt is None or receipt.outcome != "failed"):
        raise MasuGateProtocolError(f"{path}.post-dispatch failure requires failure evidence")
    return ProtectedExecutionAudit(
        execution_id=execution_id,
        binding_digest=digest,
        binding=binding,
        binding_canonical_json=canonical_binding_json,
        status=status,
        entitlement_state=entitlement,
        dispatch_started=dispatch_started,
        cancel_requested=_boolean(
            _required(raw, "cancel_requested", path), f"{path}.cancel_requested"
        ),
        external_operation_id=external_operation_id,
        lease_owner=lease_owner,
        lease_fence_token=lease_fence,
        lease_expires_at=lease_expires,
        last_fence_token=last_fence,
        receipt=receipt,
        result=json_object(_required(raw, "result", path), f"{path}.result"),
        created_at=_date_time(_required(raw, "created_at", path), f"{path}.created_at"),
        updated_at=_date_time(_required(raw, "updated_at", path), f"{path}.updated_at"),
        events=events,
    )


def _human_resolution(value: object, path: str) -> HumanResolution:
    raw = _object(value, path)
    approved = _boolean(_required(raw, "approved", path), f"{path}.approved")
    evidence = json_object(_required(raw, "evidence", path), f"{path}.evidence")
    has_actor = "actor_id" in raw
    has_time = "resolved_at" in raw
    if has_actor != has_time:
        raise MasuGateProtocolError(f"{path}.actor_id and resolved_at must appear together")
    return HumanResolution(
        approved=approved,
        evidence=evidence,
        actor_id=(
            _string(_required(raw, "actor_id", path), f"{path}.actor_id") if has_actor else None
        ),
        resolved_at=(
            _date_time(_required(raw, "resolved_at", path), f"{path}.resolved_at")
            if has_time
            else None
        ),
    )


def _automatic_expiry(value: object, path: str) -> AutomaticExpiry:
    raw = _object(value, path)
    unexpected = set(raw) - {"expires_at", "reason"}
    if unexpected:
        raise MasuGateProtocolError(f"{path} has unknown fields: {sorted(unexpected)!r}")
    reason = _string(_required(raw, "reason", path), f"{path}.reason")
    if reason != "approval-window-expired":
        raise MasuGateProtocolError(f"{path}.reason must be approval-window-expired")
    return AutomaticExpiry(
        expires_at=_date_time(_required(raw, "expires_at", path), f"{path}.expires_at"),
        reason="approval-window-expired",
    )


def parse_audit_record(value: object) -> AuditRecord:
    path = "audit response"
    raw = _object(value, path)
    status = _status(_required(raw, "status", path), f"{path}.status")
    raw_decision = _required(raw, "decision", path)
    expected_effect: dict[str, DecisionEffect] = {
        "committed": "allow",
        "denied": "deny",
        "pending": "escalate",
    }
    if status in {"in_progress", "outcome_unknown"}:
        if raw_decision is not None:
            raise MasuGateProtocolError(f"{path}.decision must be null for status {status!r}")
        decision = None
    else:
        decision = _audit_decision(raw_decision, f"{path}.decision")
        if decision.effect != expected_effect[status]:
            raise MasuGateProtocolError(
                f"{path} couples status {status!r} with invalid effect {decision.effect!r}"
            )
    raw_effect = _required(raw, "effect", path)
    effect = None if raw_effect is None else _applied_effect(raw_effect, f"{path}.effect")
    if (status == "committed") != (effect is not None):
        raise MasuGateProtocolError(f"{path}.effect must be present only when status is committed")
    request = _audit_request(_required(raw, "request", path), f"{path}.request")
    protected_execution = (
        _protected_execution(raw["protected_execution"], f"{path}.protected_execution")
        if "protected_execution" in raw
        else None
    )
    policy = _policy_receipt(_required(raw, "policy", path), f"{path}.policy")
    entitlement = (
        _audit_entitlement(raw["entitlement"], f"{path}.entitlement")
        if "entitlement" in raw
        else None
    )
    _validate_audit_provenance(policy, entitlement, protected_execution, path)
    _validate_protected_execution_binding(request, policy, effect, protected_execution, path)
    if status == "pending" and protected_execution is not None:
        raise MasuGateProtocolError(f"{path}.protected_execution is forbidden for pending status")
    expected_protected_status: dict[ActionStatus, ProtectedExecutionStatus | None] = {
        "committed": "succeeded",
        "denied": "failed",
        "pending": None,
        "in_progress": None,
        "outcome_unknown": "outcome_unknown",
    }
    if protected_execution is not None:
        if status == "in_progress" and protected_execution.status not in {"intent", "executing"}:
            raise MasuGateProtocolError(
                f"{path}.in_progress requires intent or executing protected execution"
            )
        expected_protected = expected_protected_status[status]
        if expected_protected is not None and protected_execution.status != expected_protected:
            raise MasuGateProtocolError(
                f"{path}.status {status!r} requires protected execution status "
                f"{expected_protected!r}"
            )
    reads_raw = _array(_required(raw, "view_reads", path), f"{path}.view_reads")
    evaluations_raw = _array(
        _required(raw, "authorization_evaluations", path),
        f"{path}.authorization_evaluations",
    )
    raw_terminal = _required(raw, "terminal_serialization", path)
    terminal_serialization = (
        _terminal_serialization(raw_terminal, f"{path}.terminal_serialization")
        if raw_terminal is not None
        else None
    )
    if status == "committed" and (
        terminal_serialization is None or terminal_serialization.kind != "effect-commit"
    ):
        raise MasuGateProtocolError(
            f"{path}.committed requires effect-commit terminal serialization"
        )
    if status == "denied" and (
        terminal_serialization is None or terminal_serialization.kind != "denial-record"
    ):
        raise MasuGateProtocolError(f"{path}.denied requires denial-record terminal serialization")
    if status == "pending" and terminal_serialization is not None:
        raise MasuGateProtocolError(f"{path}.pending requires null terminal serialization")
    resolution_plan, certificate_digest, entitlement_digest = _resolution_metadata(raw, path)
    if status in {"in_progress", "outcome_unknown"}:
        if raw_terminal is not None:
            raise MasuGateProtocolError(
                f"{path}.terminal_serialization must be null for status {status!r}"
            )
        if any(
            key in raw
            for key in (
                "resolution_plan",
                "reservation_safety_certificate_digest",
                "reservation_entitlement_digest",
            )
        ):
            raise MasuGateProtocolError(
                f"{path} pending-resolution metadata is forbidden for status {status!r}"
            )
    automatic_expiry = (
        _automatic_expiry(raw["automatic_expiry"], f"{path}.automatic_expiry")
        if "automatic_expiry" in raw
        else None
    )
    if automatic_expiry is not None:
        if status != "denied" or decision is None or decision.rule_id != "approval.expired":
            raise MasuGateProtocolError(
                "automatic expiry requires a denied receipt with approval.expired"
            )
        if "human_resolution" in raw:
            raise MasuGateProtocolError("automatic expiry may not claim a human resolution")
    if decision is not None and decision.rule_id == "approval.expired" and automatic_expiry is None:
        raise MasuGateProtocolError("approval.expired requires automatic expiry evidence")
    return AuditRecord(
        operation_id=_uuid(_required(raw, "operation_id", path), f"{path}.operation_id"),
        status=status,
        request=request,
        policy=policy,
        decision=decision,
        view_reads=tuple(
            _view_read(item, f"{path}.view_reads[{index}]") for index, item in enumerate(reads_raw)
        ),
        authorization_evaluations=tuple(
            _authorization_evaluation(item, f"{path}.authorization_evaluations[{index}]")
            for index, item in enumerate(evaluations_raw)
        ),
        terminal_serialization=terminal_serialization,
        effect=effect,
        recorded_at=_date_time(_required(raw, "recorded_at", path), f"{path}.recorded_at"),
        resolution_plan=resolution_plan,
        reservation_safety_certificate_digest=certificate_digest,
        reservation_entitlement_digest=entitlement_digest,
        human_resolution=(
            _human_resolution(raw["human_resolution"], f"{path}.human_resolution")
            if "human_resolution" in raw
            else None
        ),
        automatic_expiry=automatic_expiry,
        protected_execution=protected_execution,
        entitlement=entitlement,
    )


def parse_error_envelope(
    value: object,
) -> tuple[str, str, dict[str, JsonValue] | None] | None:
    """Best-effort parser: malformed HTTP errors still become typed HTTP errors."""

    try:
        outer = _object(value, "error response")
        error = _object(_required(outer, "error", "error response"), "error response.error")
        code = _string(_required(error, "code", "error response.error"), "error.code")
        message = _string(_required(error, "message", "error response.error"), "error.message")
        details = json_object(error["details"], "error.details") if "details" in error else None
    except MasuGateProtocolError:
        return None
    return code, message, details
