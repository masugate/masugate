"""FastAPI implementation of the Governed Action Protocol (steps 1.2--1.5).

The HTTP boundary is deliberately narrow:

* authentication maps a bearer token to a principal id;
* request bodies cannot assert identity, attributes, operation ids, or time;
* every action calls ``AsyncGovernedCoordinator.execute`` and returns a
  terminal/pending result, never a detached authorization token;
* pending resolution always re-enters the coordinator;
* pending and audit reads come from the governed resource's durable store.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import re
from collections.abc import AsyncIterator, Collection, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Annotated, Any, cast
from uuid import uuid4

from fastapi import FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from masugate import __version__ as MASUGATE_PLATFORM_VERSION
from masugate.coordinator import AsyncGovernedCoordinator
from masugate.errors import ResourceError
from masugate.model import (
    ActionRequest,
    Duration,
    JsonValue,
    OperationResult,
    OperationStatus,
    PendingOperation,
    Principal,
    ProtectedArtifactMetadata,
    Scalar,
)
from masugate.operations import (
    DEFAULT_ARTIFACT_TTL,
    ArtifactBinding,
    ArtifactConflict,
    ArtifactError,
    ArtifactStore,
    ArtifactUnavailable,
    CompiledOperationRoutes,
)
from masugate.operations.schema import require_model_field
from masugate.provider_assembly import EffectExecutionPosition
from masugate.resources.base import GovernanceQueryResource


class ActionBody(BaseModel):
    """Caller-controlled fields for ``POST /v1/actions``.

    ``extra='forbid'`` is part of the trust boundary: a caller cannot smuggle
    principal attributes, an operation id, or a timestamp into admission.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    action: str = Field(min_length=1, max_length=255)
    args: dict[str, Scalar]
    idempotency_key: str = Field(min_length=1, max_length=255)
    trace_id: str | None = Field(default=None, min_length=1, max_length=255)
    adapter_invocation: str | None = Field(default=None, min_length=1, max_length=16_384)

    @field_validator("args")
    @classmethod
    def _require_javascript_safe_integers(cls, args: dict[str, Scalar]) -> dict[str, Scalar]:
        for name, value in args.items():
            if type(value) is int and not (
                -9_007_199_254_740_991 <= value <= 9_007_199_254_740_991
            ):
                raise ValueError(f"args.{name} must be a JavaScript-safe integer")
        return args


class ArtifactBody(BaseModel):
    """Authenticated one-field payload upload for a declared v2 operation route."""

    model_config = ConfigDict(extra="forbid", strict=True)

    action: str = Field(min_length=1, max_length=255)
    field: str = Field(min_length=1, max_length=256)
    idempotency_key: str = Field(min_length=1, max_length=255)
    media_type: str = Field(min_length=3, max_length=128)
    content_base64: str = Field(max_length=11_184_816)
    # Staging and the matching governed action must share one bound. The
    # assertion is an identity proof, never an alternate bulk-upload channel.
    adapter_invocation: str = Field(min_length=2, max_length=16_384)


_ADAPTER_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:/-]+$")
_ADAPTER_ARGUMENT_NAME = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
_ADAPTER_CAPABILITIES = frozenset({"cancellation", "locator", "pending-presentation", "receipt"})
_ADAPTER_RESERVED_ARGUMENT_NAMES = frozenset(
    {
        "adapter",
        "adaptercapabilities",
        "adapterid",
        "agentid",
        "auditref",
        "authorization",
        "connectorid",
        "contractversion",
        "credential",
        "decision",
        "effect",
        "executionposition",
        "idempotencykey",
        "invocationid",
        "locator",
        "operationid",
        "pendingid",
        "policyid",
        "policyversion",
        "principal",
        "principalid",
        "principalref",
        "providerid",
        "receipt",
        "receiptref",
        "replayed",
        "retry",
        "retryauthority",
        "ruleid",
        "runid",
        "sessionid",
        "sessionkey",
        "sourceid",
        "sourceinvocation",
        "sourcenamespace",
        "stableid",
        "token",
        "toolcallid",
        "traceid",
    }
)


def _adapter_identifier(value: object, field: str, *, max_length: int = 256) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > max_length
        or _ADAPTER_IDENTIFIER.fullmatch(value) is None
    ):
        raise ValueError(f"adapter_invocation {field} must be a canonical identifier")
    return value


def _adapter_argument_name(value: object) -> str:
    if (
        type(value) is not str
        or len(value) > 256
        or _ADAPTER_ARGUMENT_NAME.fullmatch(value) is None
    ):
        raise ValueError("adapter_invocation argument names must be canonical lower_snake_case")
    if value in {"__proto__", "prototype", "constructor"}:
        raise ValueError("adapter_invocation argument name uses a reserved unsafe object key")
    if value.replace("_", "") in _ADAPTER_RESERVED_ARGUMENT_NAMES:
        raise ValueError("adapter_invocation argument name uses a reserved trust-boundary name")
    return value


def _has_unpaired_surrogate(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _scalar_matches(left: object, right: Scalar) -> bool:
    return type(left) is type(right) and left == right


def _adapter_invocation_digest(
    canonical: str | None,
    *,
    principal_id: str,
    action: str,
    args: Mapping[str, Scalar],
) -> str | None:
    """Verify the adapter assertion matches the authenticated GAP request.

    The assertion is deliberately a canonical string rather than a second
    loosely-normalized object.  The public SDK produces it with the host
    contract's canonicalizer; persisting its digest makes replay binding cover
    adapter/source provenance without making framework objects part of the
    server API.
    """

    if canonical is None:
        return None
    try:
        invocation = json.loads(canonical)
    except (TypeError, ValueError) as exc:
        raise ValueError("adapter_invocation must be canonical JSON") from exc
    if not isinstance(invocation, dict) or set(invocation) != {
        "principal",
        "source",
        "adapter",
        "action",
    }:
        raise ValueError("adapter_invocation has an invalid envelope")
    principal = invocation["principal"]
    source = invocation["source"]
    adapter = invocation["adapter"]
    asserted_action = invocation["action"]
    if not isinstance(principal, dict) or set(principal) != {"id"}:
        raise ValueError("adapter_invocation principal is invalid")
    if _adapter_identifier(principal.get("id"), "principal.id") != principal_id:
        raise ValueError("adapter_invocation principal does not match authenticated principal")
    if not isinstance(source, dict) or set(source) != {"namespace", "id"}:
        raise ValueError("adapter_invocation source is invalid")
    _adapter_identifier(source.get("namespace"), "source.namespace")
    _adapter_identifier(source.get("id"), "source.id")
    if (
        not isinstance(adapter, dict)
        or set(adapter) != {"id", "contract_version", "capabilities"}
        or adapter.get("contract_version") != "masugate.host-adapter.v1"
        or not isinstance(adapter.get("capabilities"), list)
        or any(
            type(capability) is not str or capability not in _ADAPTER_CAPABILITIES
            for capability in adapter["capabilities"]
        )
        or len(set(adapter["capabilities"])) != len(adapter["capabilities"])
    ):
        raise ValueError("adapter_invocation adapter provenance is invalid")
    adapter_id = _adapter_identifier(adapter.get("id"), "adapter.id")
    capabilities = cast(list[str], adapter["capabilities"])
    if not isinstance(asserted_action, dict) or set(asserted_action) != {"name", "arguments"}:
        raise ValueError("adapter_invocation action is invalid")
    if _adapter_identifier(asserted_action.get("name"), "action.name", max_length=255) != action:
        raise ValueError("adapter_invocation action does not match action request")
    asserted_arguments = asserted_action.get("arguments")
    if not isinstance(asserted_arguments, dict):
        raise ValueError("adapter_invocation action arguments are invalid")
    normalized_arguments: dict[str, Scalar] = {}
    for name, value in asserted_arguments.items():
        canonical_name = _adapter_argument_name(name)
        if type(value) is str:
            if _has_unpaired_surrogate(value):
                raise ValueError("adapter_invocation strings must not contain unpaired surrogates")
        elif type(value) is int:
            if not -9_007_199_254_740_991 <= value <= 9_007_199_254_740_991:
                raise ValueError("adapter_invocation integers must be JavaScript-safe")
        elif type(value) is not bool:
            raise ValueError("adapter_invocation arguments must be scalar")
        normalized_arguments[canonical_name] = cast(Scalar, value)
    if set(normalized_arguments) != set(args) or any(
        not _scalar_matches(normalized_arguments[name], args[name]) for name in args
    ):
        raise ValueError("adapter_invocation action does not match action request")
    # Adapter-envelope keys and declared argument names are ASCII identifiers,
    # so sorted JSON keys have the same order as the contract's UTF-16 order.
    # Values are scalar and the SDK canonicalizer rejects surrogate code units.
    # Requiring this exact compact spelling prevents whitespace/key-order
    # variants from becoming distinct durable bindings for one assertion.
    normalized = json.dumps(
        {
            "principal": {"id": principal_id},
            "source": {"namespace": source["namespace"], "id": source["id"]},
            "adapter": {
                "id": adapter_id,
                "contract_version": "masugate.host-adapter.v1",
                "capabilities": sorted(capabilities),
            },
            "action": {"name": action, "arguments": normalized_arguments},
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    if canonical != normalized:
        raise ValueError("adapter_invocation is not canonical JSON")
    return sha256(canonical.encode("utf-8")).hexdigest()


def _artifact_invocation_digest(
    canonical: str,
    *,
    principal_id: str,
    action: str,
    field: str,
    content: bytes,
) -> str:
    """Bind a payload upload to one canonical trusted v2-capable invocation.

    The adapter integration assertion checker intentionally permits scalar arguments only.
    Payload routes are nested and content-bearing, so this companion checker
    verifies the same trusted principal/source/adapter envelope while leaving
    the exact bounded input schema to the compiled operation route.
    """

    try:
        invocation = json.loads(
            canonical,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"invalid JSON constant {value}")
            ),
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("artifact adapter_invocation must be canonical JSON") from exc
    if not isinstance(invocation, dict) or set(invocation) != {
        "principal",
        "source",
        "adapter",
        "action",
    }:
        raise ValueError("artifact adapter_invocation has an invalid envelope")
    principal = invocation["principal"]
    source = invocation["source"]
    adapter = invocation["adapter"]
    asserted_action = invocation["action"]
    if not isinstance(principal, dict) or set(principal) != {"id"}:
        raise ValueError("artifact adapter_invocation principal is invalid")
    if _adapter_identifier(principal.get("id"), "principal.id") != principal_id:
        raise ValueError(
            "artifact adapter_invocation principal does not match authenticated principal"
        )
    if not isinstance(source, dict) or set(source) != {"namespace", "id"}:
        raise ValueError("artifact adapter_invocation source is invalid")
    _adapter_identifier(source.get("namespace"), "source.namespace")
    _adapter_identifier(source.get("id"), "source.id")
    if (
        not isinstance(adapter, dict)
        or set(adapter) != {"id", "contract_version", "capabilities"}
        or adapter.get("contract_version") != "masugate.host-adapter.v1"
        or not isinstance(adapter.get("capabilities"), list)
    ):
        raise ValueError("artifact adapter_invocation adapter provenance is invalid")
    _adapter_identifier(adapter.get("id"), "adapter.id")
    capabilities = adapter["capabilities"]
    if (
        any(
            type(capability) is not str or capability not in _ADAPTER_CAPABILITIES
            for capability in capabilities
        )
        or len(set(capabilities)) != len(capabilities)
        or capabilities != sorted(capabilities)
    ):
        raise ValueError("artifact adapter_invocation adapter provenance is invalid")
    if (
        not isinstance(asserted_action, dict)
        or set(asserted_action) != {"name", "arguments"}
        or _adapter_identifier(asserted_action.get("name"), "action.name", max_length=255) != action
        or not isinstance(asserted_action.get("arguments"), dict)
    ):
        raise ValueError("artifact adapter_invocation action is invalid")
    asserted_fields = asserted_action["arguments"]
    for argument_name in asserted_fields:
        _adapter_argument_name(argument_name)
    if field not in asserted_fields:
        raise ValueError("artifact adapter_invocation does not declare the staged field")
    asserted_content = asserted_fields[field]
    if type(asserted_content) is not str:
        raise ValueError("artifact adapter_invocation staged field must be text")
    if asserted_content.encode("utf-8") != content:
        raise ValueError("artifact content does not match the canonical adapter invocation field")
    try:
        normalized = json.dumps(
            invocation,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("artifact adapter_invocation contains unsupported JSON") from exc
    if canonical != normalized:
        raise ValueError("artifact adapter_invocation is not canonical JSON")
    return sha256(canonical.encode("utf-8")).hexdigest()


class ResolveBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    approved: bool
    evidence: dict[str, JsonValue] = Field(default_factory=dict)


@dataclass(frozen=True)
class ActionOwnerBinding:
    """Server-certified provider and legal effect position for one action."""

    provider_id: str
    position: EffectExecutionPosition
    connector_id: str | None = None

    def __post_init__(self) -> None:
        if (
            not isinstance(self.provider_id, str)
            or not self.provider_id.strip()
            or self.provider_id != self.provider_id.strip()
        ):
            raise ValueError("action owner provider_id must be a non-empty trimmed string")
        if type(self.position) is not EffectExecutionPosition:
            raise ValueError("action owner position must be an EffectExecutionPosition")
        if self.position is EffectExecutionPosition.TRANSACTIONAL:
            if self.connector_id is not None:
                raise ValueError("transactional action owner cannot name a connector_id")
            return
        if (
            not isinstance(self.connector_id, str)
            or not self.connector_id.strip()
            or self.connector_id != self.connector_id.strip()
        ):
            raise ValueError(
                "protected-external action owner connector_id must be a non-empty trimmed string"
            )


def _error(code: str, message: str, *, details: JsonValue = None) -> dict[str, JsonValue]:
    error: dict[str, JsonValue] = {"code": code, "message": message}
    if details is not None:
        error["details"] = details
    return {"error": error}


def _decision_json(result: OperationResult) -> dict[str, JsonValue]:
    decision = result.decision
    return {
        "effect": str(decision.effect),
        "policy_id": decision.policy_id,
        "policy_version": decision.policy_version,
        "rule_id": decision.rule_id,
        "reason": decision.reason,
        "evaluated_policies": [
            {"policy_id": policy_id, "policy_version": version}
            for policy_id, version in decision.evaluated_policies
        ],
    }


def result_json(result: OperationResult) -> dict[str, JsonValue]:
    """Encode a coordinator result in the structurally-coupled wire shape."""

    if result.status is None:  # OperationResult normally derives it in __post_init__.
        raise ValueError("operation result has no lifecycle status")
    if result.status is OperationStatus.ABORTED:
        raise ResourceError("aborted operations are returned through the error envelope")
    payload: dict[str, JsonValue] = {
        "operation_id": result.operation_id,
        "status": str(result.status),
        "decision": _decision_json(result),
        "payload": result.payload,
        "audit_ref": f"/v1/audit/{result.operation_id}",
        "replayed": result.replayed,
    }
    if result.pending_id is not None:
        payload["pending_id"] = result.pending_id
    if result.status is OperationStatus.PENDING:
        payload["resolution_plan"] = str(result.resolution_plan)
        if result.reservation_safety_certificate_digest is not None:
            payload["reservation_safety_certificate_digest"] = (
                result.reservation_safety_certificate_digest
            )
        if result.reservation_entitlement_digest is not None:
            payload["reservation_entitlement_digest"] = result.reservation_entitlement_digest
    return payload


def _pending_json(pending: PendingOperation) -> dict[str, JsonValue]:
    payload: dict[str, JsonValue] = {
        "pending_id": pending.pending_id,
        "operation_id": pending.request.operation_id,
        "action": pending.request.action,
        "principal_id": pending.request.principal.id,
        "args": _jsonable(pending.request.arguments),
        "created_at": pending.request.timestamp.isoformat(),
        "resolution_plan": str(pending.resolution_plan),
        "decision": {
            "effect": str(pending.decision.effect),
            "policy_id": pending.decision.policy_id,
            "policy_version": pending.decision.policy_version,
            "rule_id": pending.decision.rule_id,
            "reason": pending.decision.reason,
        },
        "audit_ref": f"/v1/audit/{pending.request.operation_id}",
    }
    if pending.reservation_safety_certificate_digest is not None:
        payload["reservation_safety_certificate_digest"] = (
            pending.reservation_safety_certificate_digest
        )
    if pending.reservation_entitlement_digest is not None:
        payload["reservation_entitlement_digest"] = pending.reservation_entitlement_digest
    return payload


def _pending_event(pending: PendingOperation) -> dict[str, JsonValue]:
    return {
        "event_id": pending.pending_id,
        "event_type": "pending.created",
        "occurred_at": pending.request.timestamp.isoformat(),
        "pending": _pending_json(pending),
    }


@dataclass(frozen=True)
class _Subscriber:
    queue: asyncio.Queue[dict[str, JsonValue]]


class PendingEventBroker:
    """One-process SSE fan-out with durable catch-up supplied by the provider.

    ``masugated`` is explicitly a one-process skeleton in core runtime.  Live events use
    in-memory fan-out; a newly connected client first receives the resource's
    durable pending snapshot, so reconnecting cannot miss an outstanding item.
    """

    def __init__(self) -> None:
        self._subscribers: set[_Subscriber] = set()
        self._lock = asyncio.Lock()

    async def publish(self, event: dict[str, JsonValue]) -> None:
        async with self._lock:
            subscribers = tuple(self._subscribers)
        for subscriber in subscribers:
            subscriber.queue.put_nowait(event)

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue[dict[str, JsonValue]]]:
        subscriber = _Subscriber(asyncio.Queue())
        async with self._lock:
            self._subscribers.add(subscriber)
        try:
            yield subscriber.queue
        finally:
            async with self._lock:
                self._subscribers.discard(subscriber)


def _jsonable(value: object) -> JsonValue:
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, Exception):
        return str(value)
    if isinstance(value, Duration):
        return value.seconds
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_jsonable(item) for item in value]
    raise TypeError(f"value is not JSON serializable: {type(value).__name__}")


def _is_sha256_digest(value: JsonValue) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _audit_resolution_metadata(
    record: Mapping[str, JsonValue],
) -> tuple[str, str | None, str | None]:
    """Return one coherent public resolution-metadata shape.

    Provider records are durable input at this boundary.  Only a complete,
    well-formed reservation proof is projected as such.  Legacy, partial, or
    malformed proof metadata is explicitly downgraded to revalidation with no
    proof digests, so the receipt cannot imply a proof the stored record lacks.
    """

    raw_plan = record.get("resolution_plan")
    certificate = record.get("reservation_safety_certificate_digest")
    entitlement = record.get("reservation_entitlement_digest")
    if (
        raw_plan == "reservation-proof"
        and _is_sha256_digest(certificate)
        and _is_sha256_digest(entitlement)
    ):
        return cast(str, raw_plan), cast(str, certificate), cast(str, entitlement)
    if (
        isinstance(raw_plan, str)
        and raw_plan in {"revalidate", "scoped-hold"}
        and (certificate is None and entitlement is None)
    ):
        return raw_plan, None, None
    return "revalidate", None, None


def _audit_authorization_evaluations(
    record: Mapping[str, JsonValue],
) -> list[JsonValue]:
    """Project stored evaluation decisions into the public receipt shape."""

    evaluations: list[JsonValue] = []
    for item in cast(list[JsonValue], record.get("authorization_evaluations", [])):
        evaluation = cast(dict[str, JsonValue], item)
        decision = cast(dict[str, JsonValue], evaluation["decision"])
        evaluated_raw = cast(list[JsonValue], decision.get("evaluated_policies", []))
        public_decision = dict(decision)
        public_decision["evaluated_policies"] = [
            {"policy_id": pair[0], "policy_version": pair[1]}
            for pair in (cast(list[str], policy) for policy in evaluated_raw)
        ]
        public_evaluation = dict(evaluation)
        public_evaluation["decision"] = public_decision
        evaluations.append(public_evaluation)
    return evaluations


def _audit_json(record: dict[str, JsonValue]) -> dict[str, JsonValue]:
    """Project the durable provider record into the public receipt shape."""

    decision = cast(dict[str, JsonValue], record["decision"])
    reads = cast(list[JsonValue], decision.get("reads", []))
    committed = bool(record["committed"])
    evaluated_raw = cast(list[JsonValue], decision.get("evaluated_policies", []))
    evaluated: list[JsonValue] = [
        {"policy_id": pair[0], "policy_version": pair[1]}
        for pair in (cast(list[str], item) for item in evaluated_raw)
    ]
    provenance = cast(list[JsonValue], decision.get("policy_provenance", []))
    resolution_plan, certificate_digest, entitlement_digest = _audit_resolution_metadata(record)
    request_time = cast(str, record.get("request_time", record["timestamp"]))
    authorization_evaluations = _audit_authorization_evaluations(record)
    terminal_serialization = record.get("terminal_serialization")
    if "terminal_serialization" not in record:
        terminal_serialization = (
            None
            if record.get("status") == "pending"
            else {
                "kind": "effect-commit" if committed else "denial-record",
                "authorization_basis": "legacy-unspecified",
                "provider_atomic": False,
                "recorded_at": cast(str, record.get("recorded_at", record["timestamp"])),
            }
        )
    receipt: dict[str, JsonValue] = {
        "operation_id": cast(str, record["operation_id"]),
        "status": cast(str, record["status"]),
        "request": {
            "idempotency_key": cast(str, record["idempotency_key"]),
            "principal": {
                "id": cast(str, record["principal_id"]),
                "attributes": cast(dict[str, JsonValue], record["principal_attributes"]),
            },
            "action": cast(str, record["action"]),
            "args": cast(dict[str, JsonValue], record["arguments"]),
            "timestamp": cast(str, record["timestamp"]),
            "request_time": request_time,
            "trace_id": record.get("trace_id"),
        },
        "policy": {
            "policy_id": cast(str, decision["policy_id"]),
            "policy_version": cast(str, decision.get("policy_version", "")),
            "evaluated_policies": evaluated,
            "evaluated_policy_provenance": provenance,
        },
        "decision": {
            "effect": cast(str, decision["effect"]),
            "rule_id": cast(str, decision["rule_id"]),
            "reason": cast(str, decision["reason"]),
        },
        "view_reads": reads,
        "authorization_evaluations": authorization_evaluations,
        "terminal_serialization": terminal_serialization,
        "resolution_plan": resolution_plan,
        "effect": (
            {
                "action": cast(str, record["action"]),
                "args": cast(dict[str, JsonValue], record["arguments"]),
                "payload": cast(dict[str, JsonValue], record["payload"]),
            }
            if committed
            else None
        ),
        "recorded_at": cast(str, record.get("recorded_at", record["timestamp"])),
    }
    if isinstance(record.get("protected_artifacts"), dict):
        receipt_request = cast(dict[str, JsonValue], receipt["request"])
        receipt_request["protected_artifacts"] = cast(
            dict[str, JsonValue], record["protected_artifacts"]
        )
    if isinstance(record.get("resolution_evidence"), dict):
        receipt["human_resolution"] = cast(dict[str, JsonValue], record["resolution_evidence"])
    if certificate_digest is not None:
        receipt["reservation_safety_certificate_digest"] = certificate_digest
    if entitlement_digest is not None:
        receipt["reservation_entitlement_digest"] = entitlement_digest
    if isinstance(record.get("protected_execution"), dict):
        receipt["protected_execution"] = cast(dict[str, JsonValue], record["protected_execution"])
    return receipt


def create_app(
    coordinator: AsyncGovernedCoordinator,
    resource: GovernanceQueryResource,
    token_principals: Mapping[str, str],
    *,
    operator_principals: Collection[str] = (),
    broker: PendingEventBroker | None = None,
    lifespan_resource: Any | None = None,
    action_owners: Mapping[str, ActionOwnerBinding] | None = None,
    action_assertion_principals: Collection[str] = (),
    adapter_invocation_principals: Collection[str] = (),
    artifact_store: ArtifactStore | None = None,
    compiled_operation_routes: CompiledOperationRoutes | None = None,
    artifact_ttl: timedelta = DEFAULT_ARTIFACT_TTL,
) -> FastAPI:
    """Create one ``masugated`` process around a coordinator and shared resource.

    ``token_principals`` is the authenticated connection-to-principal mapping.
    ``operator_principals`` may resolve every principal's pending work and
    inspect all records; other principals can inspect only their own.  Principal
    attributes remain in the coordinator's server-side registry.
    ``action_assertion_principals`` retains the adapter integration public contract:
    listed principals must supply the expected bearer subject and assembly-backed
    owner assertion. ``adapter_invocation_principals`` is the separately named
    connector SDK strict set; those principals must also supply a canonical adapter
    invocation on every action. A strict principal cannot be in the header-only
    set.
    When ``lifespan_resource`` is supplied (the CLI passes its ledger), its
    ``open``/``close`` methods run once for the app process, preserving one pool.
    """

    events = broker or PendingEventBroker()
    tokens: dict[str, str] = {}
    for token, principal_id in token_principals.items():
        if (
            not isinstance(token, str)
            or not token
            or token.strip() != token
            or not isinstance(principal_id, str)
            or not principal_id.strip()
        ):
            raise ValueError("bearer tokens and principal ids must be non-empty strings")
        tokens[token] = principal_id
    operators = frozenset(operator_principals)
    if any(
        not isinstance(principal_id, str) or not principal_id.strip() for principal_id in operators
    ):
        raise ValueError("operator principal ids must be non-empty strings")
    header_assertion_principals = frozenset(action_assertion_principals)
    if any(
        not isinstance(principal_id, str) or not principal_id.strip()
        for principal_id in header_assertion_principals
    ):
        raise ValueError("action-assertion principal ids must be non-empty strings")
    adapter_assertion_principals = frozenset(adapter_invocation_principals)
    if any(
        not isinstance(principal_id, str) or not principal_id.strip()
        for principal_id in adapter_assertion_principals
    ):
        raise ValueError("adapter-invocation principal ids must be non-empty strings")
    if adapter_assertion_principals & header_assertion_principals:
        raise ValueError("adapter and header-only action-assertion principals must be disjoint")
    if (artifact_store is None) is not (compiled_operation_routes is None):
        raise ValueError(
            "artifact storage and compiled operation routes must be configured together"
        )
    if type(artifact_ttl) is not timedelta or artifact_ttl <= timedelta(0):
        raise ValueError("artifact ttl must be positive")
    artifact_fields_by_action: dict[str, frozenset[str]] = {}
    if compiled_operation_routes is not None:
        artifact_fields_by_action = {
            action.action: frozenset(action.artifact_fields)
            for action in compiled_operation_routes.operation_pack.actions
        }
    owners: dict[str, ActionOwnerBinding] = {}
    for action, owner in (action_owners or {}).items():
        if not isinstance(action, str) or not action.strip() or action != action.strip():
            raise ValueError("action owner keys must be non-empty trimmed strings")
        if not isinstance(owner, ActionOwnerBinding):
            raise ValueError("action owners must be ActionOwnerBinding values")
        owners[action] = owner

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        if lifespan_resource is not None:
            await lifespan_resource.open()
        if artifact_store is not None:
            await artifact_store.initialize()
        try:
            yield
        finally:
            if lifespan_resource is not None:
                await lifespan_resource.close()

    app = FastAPI(title="masugated", version=MASUGATE_PLATFORM_VERSION, lifespan=lifespan)
    app.state.pending_events = events

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request: Request, exc: RequestValidationError) -> JSONResponse:
        details: JsonValue = {"violations": _jsonable(exc.errors())}
        return JSONResponse(
            status_code=422,
            content=_error(
                "invalid_request",
                "request does not match the protocol",
                details=details,
            ),
        )

    @app.exception_handler(ResourceError)
    async def resource_error(_request: Request, exc: ResourceError) -> JSONResponse:
        status = 404 if str(exc).startswith("unknown pending operation") else 409
        code = "not_found" if status == 404 else "resource_conflict"
        return JSONResponse(status_code=status, content=_error(code, str(exc)))

    @app.exception_handler(ArtifactConflict)
    async def artifact_conflict(_request: Request, exc: ArtifactConflict) -> JSONResponse:
        return JSONResponse(status_code=409, content=_error("artifact_conflict", str(exc)))

    @app.exception_handler(ArtifactError)
    async def artifact_error(_request: Request, exc: ArtifactError) -> JSONResponse:
        return JSONResponse(status_code=400, content=_error("invalid_artifact", str(exc)))

    @app.exception_handler(ValueError)
    async def value_error(_request: Request, exc: ValueError) -> JSONResponse:
        return JSONResponse(status_code=400, content=_error("invalid_request", str(exc)))

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = "not_found" if exc.status_code == 404 else "http_error"
        return JSONResponse(
            status_code=exc.status_code,
            content=_error(code, str(exc.detail)),
        )

    @app.exception_handler(Exception)
    async def internal_error(_request: Request, _exc: Exception) -> JSONResponse:
        # Never leak stack traces or provider details through the wire contract.
        return JSONResponse(
            status_code=500,
            content=_error("internal_error", "unexpected server error"),
        )

    def authenticated_principal(authorization: str | None) -> str:
        if authorization is None or not authorization.startswith("Bearer "):
            raise _Unauthorized("missing bearer token")
        token = authorization.removeprefix("Bearer ")
        if not token:
            raise _Unauthorized("missing bearer token")
        try:
            return tokens[token]
        except KeyError as exc:
            raise _Unauthorized("invalid bearer token") from exc

    @app.exception_handler(_Unauthorized)
    async def unauthorized(_request: Request, exc: _Unauthorized) -> JSONResponse:
        return JSONResponse(status_code=401, content=_error("unauthorized", str(exc)))

    if artifact_store is not None:

        @app.post("/v1/artifacts")
        async def stage_artifact(
            body: ArtifactBody,
            authorization: Annotated[str | None, Header()] = None,
        ) -> dict[str, JsonValue]:
            """Stage one declared content field before its governed action.

            The returned reference is a server-owned opaque handle.  It is
            accepted only later through a matching committed provider handoff;
            action callers never submit a digest, classification, path, or
            retention choice.
            """

            principal_id = authenticated_principal(authorization)
            try:
                field = require_model_field(body.field, "artifact field")
                route_fields = artifact_fields_by_action[body.action]
            except KeyError as exc:
                raise ValueError(
                    "artifact action is not declared by the installed operation pack"
                ) from exc
            if field not in route_fields:
                raise ValueError("artifact field is not declared by the installed operation pack")
            try:
                content = base64.b64decode(body.content_base64.encode("ascii"), validate=True)
            except (UnicodeEncodeError, binascii.Error) as exc:
                raise ValueError("artifact content_base64 is invalid") from exc
            invocation_digest = _artifact_invocation_digest(
                body.adapter_invocation,
                principal_id=principal_id,
                action=body.action,
                field=field,
                content=content,
            )
            metadata = await artifact_store.stage(
                ArtifactBinding(
                    principal_id=principal_id,
                    action=body.action,
                    idempotency_key=body.idempotency_key,
                    adapter_invocation_digest=invocation_digest,
                    field=field,
                ),
                content,
                declared_media_type=body.media_type,
                now=datetime.now(UTC),
                ttl=artifact_ttl,
            )
            return cast(dict[str, JsonValue], metadata.payload())

    @app.post("/v1/actions")
    async def execute_action(
        body: ActionBody,
        authorization: Annotated[str | None, Header()] = None,
        masugate_expected_principal: Annotated[str | None, Header()] = None,
        masugate_expected_provider: Annotated[str | None, Header()] = None,
        masugate_expected_position: Annotated[str | None, Header()] = None,
        masugate_expected_connector: Annotated[str | None, Header()] = None,
    ) -> dict[str, JsonValue]:
        principal_id = authenticated_principal(authorization)
        header_assertions_required = principal_id in header_assertion_principals
        adapter_assertions_required = principal_id in adapter_assertion_principals
        if (
            header_assertions_required or adapter_assertions_required
        ) and masugate_expected_principal is None:
            raise _Unauthorized("missing required expected principal assertion")
        if (
            masugate_expected_principal is not None
            and masugate_expected_principal != principal_id
        ):
            raise _Unauthorized("bearer token principal does not match expected principal")
        if adapter_assertions_required and body.adapter_invocation is None:
            raise ValueError("missing required adapter invocation assertion")
        adapter_invocation_digest = _adapter_invocation_digest(
            body.adapter_invocation,
            principal_id=principal_id,
            action=body.action,
            args=body.args,
        )
        request_arguments = dict(body.args)
        protected_artifacts: dict[str, ProtectedArtifactMetadata] = {}
        expired_artifact = False
        if artifact_store is not None:
            declared_artifact_fields = artifact_fields_by_action.get(body.action, frozenset())
            if declared_artifact_fields:
                if body.adapter_invocation is None:
                    raise ValueError("artifact-bearing actions require an adapter invocation")
                for field in declared_artifact_fields:
                    value = body.args.get(field)
                    if type(value) is not str:
                        raise ValueError("artifact-bearing action fields must be staged text")
                    if value.startswith("art:"):
                        raise ValueError("model arguments must not provide artifact references")
                    artifact_binding = ArtifactBinding(
                        principal_id=principal_id,
                        action=body.action,
                        idempotency_key=body.idempotency_key,
                        adapter_invocation_digest=_artifact_invocation_digest(
                            body.adapter_invocation,
                            principal_id=principal_id,
                            action=body.action,
                            field=field,
                            content=value.encode("utf-8"),
                        ),
                        field=field,
                    )
                    try:
                        metadata = await artifact_store.lookup(
                            artifact_binding,
                            now=datetime.now(UTC),
                        )
                    except ArtifactUnavailable:
                        # Retained expiry metadata can prove only an exact
                        # durable action or pending replay.  It is never an
                        # authorization to restore bytes or dispatch a
                        # connector again.
                        metadata = await artifact_store.lookup(
                            artifact_binding,
                            now=datetime.now(UTC),
                            allow_expired=True,
                        )
                        expired_artifact = True
                    # Providers, audit records, and the protected binding get
                    # only a server-derived reference. Raw bytes remain in the
                    # sealed store for connector-only verified reads.
                    request_arguments[field] = metadata.artifact_id
                    protected_artifacts[field] = ProtectedArtifactMetadata(
                        reference=metadata.artifact_id,
                        content_digest=metadata.content_digest,
                        content_bytes=metadata.content_bytes,
                        media_type=metadata.media_type,
                        classification=metadata.classification,
                        expires_at=metadata.expires_at,
                        inspector_version=metadata.inspector_version,
                    )
        owner_asserted = any(
            value is not None
            for value in (
                masugate_expected_provider,
                masugate_expected_position,
                masugate_expected_connector,
            )
        )
        if header_assertions_required or adapter_assertions_required or owner_asserted:
            if masugate_expected_provider is None or masugate_expected_position is None:
                raise ResourceError("incomplete expected action owner binding")
            owner = owners.get(body.action)
            if owner is None:
                raise ResourceError(f"action has no certified execution owner: {body.action}")
            try:
                expected_position = EffectExecutionPosition(masugate_expected_position)
            except ValueError as exc:
                raise ResourceError("invalid expected action execution position") from exc
            expected_connector = masugate_expected_connector
            if (
                expected_position is EffectExecutionPosition.PROTECTED_EXTERNAL
                and expected_connector is None
            ):
                raise ResourceError("incomplete expected action owner binding")
            if (
                expected_position is EffectExecutionPosition.TRANSACTIONAL
                and expected_connector is not None
            ):
                raise ResourceError(f"action execution owner mismatch: {body.action}")
            if (
                owner.provider_id != masugate_expected_provider
                or owner.position is not expected_position
                or owner.connector_id != expected_connector
            ):
                raise ResourceError(f"action execution owner mismatch: {body.action}")
        request = ActionRequest(
            operation_id=str(uuid4()),
            principal=Principal(id=principal_id),
            action=body.action,
            arguments=request_arguments,
            idempotency_key=body.idempotency_key,
            # The coordinator replaces this after acquiring DB locks. Setting a
            # server value here means even non-DB test resources never see a
            # caller-controlled timestamp.
            timestamp=datetime.now(UTC),
            trace_id=body.trace_id,
            adapter_invocation_digest=adapter_invocation_digest,
            protected_artifacts=protected_artifacts,
        )
        if expired_artifact:
            result = await coordinator.replay(request)
            if result is None:
                raise ArtifactUnavailable("artifact has expired")
        else:
            result = await coordinator.execute(request)
        encoded = result_json(result)
        if result.status is OperationStatus.PENDING:
            assert result.pending_id is not None
            async with resource.open_session(write=False) as session:
                pending = await resource.load_pending_operation(session, result.pending_id)
            if pending is not None:
                await events.publish(_pending_event(pending))
        return encoded

    @app.post("/v1/pending/{pending_id}/resolve")
    async def resolve_pending(
        pending_id: str,
        body: ResolveBody,
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, JsonValue]:
        principal_id = authenticated_principal(authorization)
        if principal_id not in operators:
            # Resolution is a human/operator authority, never self-approval by
            # an ordinary action principal. Conceal whether the id exists.
            raise ResourceError(f"unknown pending operation: {pending_id}")
        async with resource.open_session(write=False) as session:
            owner = await resource.load_pending_owner(session, pending_id)
        if owner is None:
            # Conceal whether another principal owns this identifier.
            raise ResourceError(f"unknown pending operation: {pending_id}")
        result = await coordinator.resolve_pending(
            pending_id,
            approved=body.approved,
            evidence=body.evidence,
        )
        return result_json(result)

    @app.post("/v1/pending/{pending_id}/cancel")
    async def cancel_pending(
        pending_id: str,
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, JsonValue]:
        """Request the bounded cancellation of one durable pending locator.

        Cancellation is an operator authority, just like approval.  The wire
        response deliberately contains only an acknowledgement: callers must
        re-read the locator or receipt for its authoritative terminal state.
        If a concurrent resolver has already settled the work, the response
        instead exposes that existing terminal result and does not claim that
        this cancellation changed anything.
        """

        principal_id = authenticated_principal(authorization)
        if principal_id not in operators:
            raise ResourceError(f"unknown pending operation: {pending_id}")
        async with resource.open_session(write=False) as session:
            owner = await resource.load_pending_owner(session, pending_id)
            pending = await resource.load_pending_operation(session, pending_id)
            terminal = (
                None
                if pending is not None
                else await resource.load_resolved_pending_result(session, pending_id)
            )
        if owner is None or (pending is None and terminal is None):
            raise ResourceError(f"unknown pending operation: {pending_id}")
        if pending is None:
            assert terminal is not None
            return {
                "kind": "cancellation",
                "locator": {"operation_id": terminal.operation_id, "pending_id": pending_id},
                "accepted": False,
                "terminal_result": result_json(terminal),
            }

        result = await coordinator.resolve_pending(
            pending_id,
            approved=False,
            # This is an authenticated operator cancellation request, not
            # fabricated human-approval evidence. The resulting receipt makes
            # the negative resolution and its operator-only route visible.
            evidence={"cancellation": "operator-requested"},
        )
        locator: dict[str, JsonValue] = {
            "operation_id": pending.request.operation_id,
            "pending_id": pending_id,
        }
        # ``resolve_pending`` marks a durable replay, including a concurrent
        # denial, so this cancellation did not perform the transition. Do not
        # advertise it as accepted merely because the prior result is denied.
        if result.replayed:
            if result.status not in {OperationStatus.COMMITTED, OperationStatus.DENIED}:
                return {"kind": "cancellation", "locator": locator, "accepted": False}
            return {
                "kind": "cancellation",
                "locator": locator,
                "accepted": False,
                "terminal_result": result_json(result),
            }
        return {"kind": "cancellation", "locator": locator, "accepted": True}

    @app.get("/v1/pending")
    async def list_pending(
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, JsonValue]:
        principal_id = authenticated_principal(authorization)
        async with resource.open_session(write=False) as session:
            pending = await resource.list_pending_operations(
                session,
                principal_id=None if principal_id in operators else principal_id,
            )
        return {
            "items": [_pending_json(item) for item in pending],
            "next_cursor": pending[-1].pending_id if pending else "0",
        }

    @app.get("/v1/pending/stream")
    async def stream_pending(
        authorization: Annotated[str | None, Header()] = None,
        once: Annotated[bool, Query()] = False,
        last_event_id: Annotated[str | None, Header(alias="Last-Event-ID")] = None,
    ) -> StreamingResponse:
        principal_id = authenticated_principal(authorization)
        operator = principal_id in operators

        async def stream() -> AsyncIterator[str]:
            # Subscribe BEFORE the durable snapshot: an event created during
            # the read may be delivered twice, but can never fall through the
            # list-to-stream gap. SSE is intentionally at-least-once.
            async with events.subscribe() as queue:
                async with resource.open_session(write=False) as session:
                    snapshot = await resource.list_pending_operations(
                        session,
                        principal_id=None if operator else principal_id,
                    )
                if last_event_id is not None:
                    matching = next(
                        (
                            index
                            for index, item in enumerate(snapshot)
                            if item.pending_id == last_event_id
                        ),
                        None,
                    )
                    if matching is not None:
                        snapshot = snapshot[matching + 1 :]
                for pending in snapshot:
                    event = _pending_event(pending)
                    yield (
                        f"id: {pending.pending_id}\nevent: pending.created\n"
                        f"data: {json.dumps(event)}\n\n"
                    )
                if once:
                    return
                while True:
                    event = await queue.get()
                    if not operator:
                        pending_event = cast(dict[str, JsonValue], event["pending"])
                        if pending_event.get("principal_id") != principal_id:
                            continue
                    event_id = cast(str, event["event_id"])
                    yield (f"id: {event_id}\nevent: pending.created\ndata: {json.dumps(event)}\n\n")

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/v1/pending/{pending_id}", response_model=None)
    async def get_pending(
        pending_id: str,
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, JsonValue] | JSONResponse:
        """Return one caller-owned pending locator or its terminal replay.

        ``list_pending`` deliberately exposes only unresolved work.  A host
        restart can otherwise lose its process-local presentation binding after
        MasuGate has settled the locator, leaving no safe way to recover the exact
        audit record.  This narrow read remains owner-scoped (or operator
        scoped) and carries no resolution authority.
        """

        principal_id = authenticated_principal(authorization)
        async with resource.open_session(write=False) as session:
            owner = await resource.load_pending_owner(session, pending_id)
            if owner is None or (principal_id not in operators and owner != principal_id):
                return JSONResponse(
                    status_code=404,
                    content=_error("not_found", f"unknown pending operation: {pending_id}"),
                )
            pending = await resource.load_pending_operation(session, pending_id)
            if pending is not None:
                return {"kind": "pending", "pending": _pending_json(pending)}
            terminal = await resource.load_resolved_pending_result(session, pending_id)
        if terminal is None:
            return JSONResponse(
                status_code=404,
                content=_error("not_found", f"unknown pending operation: {pending_id}"),
            )
        return {"kind": "terminal", "result": result_json(terminal)}

    @app.get("/v1/audit/{operation_id}", response_model=None)
    async def get_audit(
        operation_id: str,
        authorization: Annotated[str | None, Header()] = None,
    ) -> dict[str, JsonValue] | JSONResponse:
        principal_id = authenticated_principal(authorization)
        async with resource.open_session(write=False) as session:
            record = await resource.load_governance_record(session, operation_id)
        if record is None or (
            principal_id not in operators and record.get("principal_id") != principal_id
        ):
            return JSONResponse(
                status_code=404,
                content=_error("not_found", f"unknown operation: {operation_id}"),
            )
        return _audit_json(record)

    return app


class _Unauthorized(Exception):
    """Internal authentication failure mapped to the protocol error shape."""
