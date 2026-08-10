"""Framework-neutral host-adapter contract validators.

The contract intentionally accepts and returns JSON-shaped dictionaries. Host
packages supply trusted context at their boundary; this module ensures that the
record which crosses into GAP cannot be weakened by a second, host-specific
shadow result type.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from typing import Literal, TypeAlias, cast

from .models import JsonValue

HOST_ADAPTER_CONTRACT_VERSION = "masugate.host-adapter.v1"
GOVERNED_ROUTE_MANIFEST_VERSION = "masugate.governed-route-manifest.v1"

AdapterCapability: TypeAlias = Literal["cancellation", "locator", "pending-presentation", "receipt"]
GovernedArgumentKind: TypeAlias = Literal["string", "integer", "boolean"]
AdapterInvocation: TypeAlias = dict[str, JsonValue]
AdapterLifecycleEnvelope: TypeAlias = dict[str, JsonValue]
AdapterCancellationEnvelope: TypeAlias = dict[str, JsonValue]
AdapterReceiptEnvelope: TypeAlias = dict[str, JsonValue]
OperationLocator: TypeAlias = dict[str, str]
GovernedRouteManifest: TypeAlias = dict[str, JsonValue]

_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:/-]+$")
_ARGUMENT_NAME = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")
_UUID = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_INTEGER_MIN = -9_007_199_254_740_991
_SAFE_INTEGER_MAX = 9_007_199_254_740_991
_CAPABILITIES = frozenset({"cancellation", "locator", "pending-presentation", "receipt"})
_STATUSES = frozenset({"committed", "denied", "pending", "in_progress", "outcome_unknown"})

RESERVED_ADAPTER_ARGUMENT_NAMES = (
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
)
_RESERVED_ARGUMENT_NAMES = frozenset(RESERVED_ADAPTER_ARGUMENT_NAMES)
_UNSAFE_OBJECT_KEYS = frozenset({"__proto__", "prototype", "constructor"})


def _record(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    if not all(isinstance(key, str) for key in value):
        raise ValueError(f"{field} must use string keys")
    return cast(Mapping[str, object], value)


def _exact_keys(value: Mapping[str, object], allowed: Sequence[str], field: str) -> None:
    for key in value:
        if key not in allowed:
            raise ValueError(f"{field}.{key} is not allowed")


def _string(value: object, field: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise ValueError(f"{field} must be {qualifier}")
    return value


def _identifier(value: object, field: str, *, max_length: int = 256) -> str:
    text = _string(value, field)
    if len(text) > max_length or _IDENTIFIER.fullmatch(text) is None:
        raise ValueError(f"{field} must be a non-empty canonical identifier")
    return text


def _uuid(value: object, field: str) -> str:
    text = _string(value, field)
    if _UUID.fullmatch(text) is None:
        raise ValueError(f"{field} must be a UUID")
    return text


def _audit_ref(value: object, field: str, operation_id: str) -> str:
    text = _string(value, field)
    if not text.startswith("/v1/audit/") or "/" in text.removeprefix("/v1/audit/"):
        raise ValueError(f"{field} must be a GAP audit reference")
    if text != f"/v1/audit/{operation_id}":
        raise ValueError(f"{field} must identify the same operation")
    return text


def _json_value(value: object, field: str) -> JsonValue:
    if value is None or isinstance(value, str | bool):
        return cast(JsonValue, value)
    if type(value) is int:
        if not _SAFE_INTEGER_MIN <= value <= _SAFE_INTEGER_MAX:
            raise ValueError(f"{field} integer must be JavaScript-safe")
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError(f"{field} must be a JSON value")
        if value.is_integer() and not _SAFE_INTEGER_MIN <= value <= _SAFE_INTEGER_MAX:
            raise ValueError(f"{field} integer must be JavaScript-safe")
        return value
    if isinstance(value, list | tuple):
        return [_json_value(item, f"{field}[{index}]") for index, item in enumerate(value)]
    mapping = _record(value, field)
    return {key: _json_value(item, f"{field}.{key}") for key, item in mapping.items()}


def _json_object(value: object, field: str) -> dict[str, JsonValue]:
    mapping = _record(value, field)
    return {key: _json_value(item, f"{field}.{key}") for key, item in mapping.items()}


def require_adapter_action_name(name: object) -> str:
    return _identifier(name, "action.name", max_length=255)


def require_adapter_argument_name(name: object) -> str:
    text = _string(name, "adapter argument name")
    if len(text) > 256 or _ARGUMENT_NAME.fullmatch(text) is None:
        raise ValueError("adapter argument name must already be canonical lower_snake_case")
    if text in _UNSAFE_OBJECT_KEYS:
        raise ValueError("adapter argument name uses a reserved unsafe object key")
    if text.replace("_", "") in _RESERVED_ARGUMENT_NAMES:
        raise ValueError("adapter argument name uses a reserved trust-boundary name")
    return text


def create_adapter_invocation(value: object) -> AdapterInvocation:
    root = _record(value, "adapter invocation")
    _exact_keys(root, ("principal", "source", "adapter", "action"), "adapter invocation")
    principal = _record(root.get("principal"), "principal")
    source = _record(root.get("source"), "source")
    adapter = _record(root.get("adapter"), "adapter")
    action = _record(root.get("action"), "action")
    _exact_keys(principal, ("id",), "principal")
    _exact_keys(source, ("namespace", "id"), "source")
    _exact_keys(adapter, ("id", "contract_version", "capabilities"), "adapter")
    _exact_keys(action, ("name", "arguments"), "action")

    principal_id = _identifier(principal.get("id"), "principal.id")
    source_namespace = _identifier(source.get("namespace"), "source.namespace")
    source_id = _identifier(source.get("id"), "source.id")
    adapter_id = _identifier(adapter.get("id"), "adapter.id")
    if adapter.get("contract_version") != HOST_ADAPTER_CONTRACT_VERSION:
        raise ValueError("adapter.contract_version is unsupported")
    raw_capabilities = adapter.get("capabilities")
    if not isinstance(raw_capabilities, list | tuple):
        raise ValueError("adapter.capabilities must be an array")
    capabilities: list[str] = []
    for capability in raw_capabilities:
        if not isinstance(capability, str) or capability not in _CAPABILITIES:
            raise ValueError("adapter.capabilities contains an unsupported capability")
        if capability in capabilities:
            raise ValueError("adapter.capabilities must not contain duplicates")
        capabilities.append(capability)
    action_name = require_adapter_action_name(action.get("name"))
    raw_arguments = _record(action.get("arguments"), "action.arguments")
    arguments: dict[str, JsonValue] = {}
    for name, argument in raw_arguments.items():
        canonical_name = require_adapter_argument_name(name)
        if not isinstance(argument, str | bool) and not (
            type(argument) is int and _SAFE_INTEGER_MIN <= argument <= _SAFE_INTEGER_MAX
        ):
            raise ValueError(
                f"action.arguments.{canonical_name} must be a string, integer, or boolean"
            )
        arguments[canonical_name] = cast(JsonValue, argument)
    return {
        "principal": {"id": principal_id},
        "source": {"namespace": source_namespace, "id": source_id},
        "adapter": {
            "id": adapter_id,
            "contract_version": HOST_ADAPTER_CONTRACT_VERSION,
            "capabilities": cast(JsonValue, sorted(capabilities)),
        },
        "action": {"name": action_name, "arguments": arguments},
    }


def validate_governed_route_manifest(value: object) -> GovernedRouteManifest:
    manifest = _record(value, "governed route manifest")
    _exact_keys(manifest, ("contract_version", "routes"), "governed route manifest")
    if manifest.get("contract_version") != GOVERNED_ROUTE_MANIFEST_VERSION:
        raise ValueError("governed route manifest.contract_version is unsupported")
    raw_routes = manifest.get("routes")
    if not isinstance(raw_routes, list | tuple) or not raw_routes:
        raise ValueError("governed route manifest.routes must be a non-empty array")
    names: set[str] = set()
    routes: list[dict[str, JsonValue]] = []
    for index, raw_route in enumerate(raw_routes):
        context = f"governed route manifest.routes[{index}]"
        route = _record(raw_route, context)
        _exact_keys(route, ("host_tool", "action", "arguments", "owner"), context)
        host_tool = _identifier(route.get("host_tool"), f"{context}.host_tool")
        if host_tool in names:
            raise ValueError("governed route manifest.routes must not repeat host_tool")
        names.add(host_tool)
        action = require_adapter_action_name(route.get("action"))
        raw_arguments = _record(route.get("arguments"), f"{context}.arguments")
        arguments: dict[str, JsonValue] = {}
        for name, kind in raw_arguments.items():
            canonical_name = require_adapter_argument_name(name)
            if kind not in ("string", "integer", "boolean"):
                raise ValueError(
                    f"{context}.arguments.{canonical_name} must be string, integer, or boolean"
                )
            arguments[canonical_name] = cast(JsonValue, kind)
        raw_owner = _record(route.get("owner"), f"{context}.owner")
        _exact_keys(raw_owner, ("provider_id", "position", "connector_id"), f"{context}.owner")
        provider_id = _identifier(raw_owner.get("provider_id"), f"{context}.owner.provider_id")
        position = raw_owner.get("position")
        if position == "transactional":
            if "connector_id" in raw_owner:
                raise ValueError(f"{context}.owner transactional position cannot name connector_id")
            owner: dict[str, JsonValue] = {
                "provider_id": provider_id,
                "position": "transactional",
            }
        elif position == "protected-external":
            owner = {
                "provider_id": provider_id,
                "position": "protected-external",
                "connector_id": _identifier(
                    raw_owner.get("connector_id"), f"{context}.owner.connector_id"
                ),
            }
        else:
            raise ValueError(f"{context}.owner.position is invalid")
        routes.append(
            {"host_tool": host_tool, "action": action, "arguments": arguments, "owner": owner}
        )
    routes.sort(key=lambda route: cast(str, route["host_tool"]))
    return {
        "contract_version": GOVERNED_ROUTE_MANIFEST_VERSION,
        "routes": cast(JsonValue, routes),
    }


def validate_operation_locator(value: object) -> OperationLocator:
    locator = _record(value, "adapter locator")
    _exact_keys(locator, ("operation_id", "pending_id"), "adapter locator")
    parsed = {"operation_id": _uuid(locator.get("operation_id"), "adapter locator.operation_id")}
    if "pending_id" in locator:
        parsed["pending_id"] = _uuid(locator["pending_id"], "adapter locator.pending_id")
    return parsed


def operation_locator(result: Mapping[str, object]) -> OperationLocator:
    operation_id = _uuid(result.get("operation_id"), "adapter lifecycle result.operation_id")
    if result.get("status") == "pending":
        return {
            "operation_id": operation_id,
            "pending_id": _uuid(result.get("pending_id"), "adapter lifecycle result.pending_id"),
        }
    return {"operation_id": operation_id}


def _decision(value: object, expected_effect: str) -> dict[str, JsonValue]:
    decision = _record(value, "adapter lifecycle result.decision")
    _exact_keys(
        decision,
        ("effect", "policy_id", "policy_version", "rule_id", "reason", "evaluated_policies"),
        "adapter lifecycle result.decision",
    )
    if decision.get("effect") != expected_effect:
        raise ValueError(f"adapter lifecycle decision effect must be {expected_effect}")
    parsed: dict[str, JsonValue] = {
        "effect": expected_effect,
        "policy_id": _string(decision.get("policy_id"), "adapter lifecycle decision.policy_id"),
        "policy_version": _string(
            decision.get("policy_version"),
            "adapter lifecycle decision.policy_version",
            allow_empty=True,
        ),
        "rule_id": _string(decision.get("rule_id"), "adapter lifecycle decision.rule_id"),
        "reason": _string(
            decision.get("reason"), "adapter lifecycle decision.reason", allow_empty=True
        ),
    }
    if "evaluated_policies" not in decision:
        return parsed
    raw_policies = decision["evaluated_policies"]
    if not isinstance(raw_policies, list | tuple):
        raise ValueError("adapter lifecycle decision.evaluated_policies must be an array")
    policies: list[dict[str, JsonValue]] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(raw_policies):
        policy = _record(item, f"adapter lifecycle decision.evaluated_policies[{index}]")
        _exact_keys(
            policy,
            ("policy_id", "policy_version"),
            f"adapter lifecycle decision.evaluated_policies[{index}]",
        )
        item_id = _string(
            policy.get("policy_id"),
            f"adapter lifecycle decision.evaluated_policies[{index}].policy_id",
        )
        item_version = _string(
            policy.get("policy_version"),
            f"adapter lifecycle decision.evaluated_policies[{index}].policy_version",
            allow_empty=True,
        )
        if (item_id, item_version) in seen:
            raise ValueError("adapter lifecycle decision.evaluated_policies must be unique")
        seen.add((item_id, item_version))
        policies.append({"policy_id": item_id, "policy_version": item_version})
    parsed["evaluated_policies"] = cast(JsonValue, policies)
    return parsed


def _lifecycle_result(value: object) -> dict[str, JsonValue]:
    result = _record(value, "adapter lifecycle result")
    _exact_keys(
        result,
        (
            "operation_id",
            "pending_id",
            "status",
            "decision",
            "payload",
            "resolution_plan",
            "reservation_safety_certificate_digest",
            "reservation_entitlement_digest",
            "audit_ref",
            "replayed",
        ),
        "adapter lifecycle result",
    )
    operation_id = _uuid(result.get("operation_id"), "adapter lifecycle result.operation_id")
    status = result.get("status")
    if not isinstance(status, str) or status not in _STATUSES:
        raise ValueError("adapter lifecycle result.status is invalid")
    payload = _json_object(result.get("payload"), "adapter lifecycle result.payload")
    audit_ref = _audit_ref(
        result.get("audit_ref"),
        "adapter lifecycle result.audit_ref",
        operation_id,
    )
    replayed = result.get("replayed")
    if type(replayed) is not bool:
        raise ValueError("adapter lifecycle result.replayed must be boolean")
    pending_fields = (
        "pending_id",
        "resolution_plan",
        "reservation_safety_certificate_digest",
        "reservation_entitlement_digest",
    )
    if status != "pending" and any(field in result for field in pending_fields):
        raise ValueError("non-pending adapter lifecycle result must not carry pending metadata")
    if status in ("in_progress", "outcome_unknown"):
        if result.get("decision") is not None:
            raise ValueError("operational adapter lifecycle result.decision must be null")
        return {
            "operation_id": operation_id,
            "status": status,
            "decision": None,
            "payload": payload,
            "audit_ref": audit_ref,
            "replayed": replayed,
        }
    expected_effect = {"committed": "allow", "denied": "deny", "pending": "escalate"}[status]
    parsed: dict[str, JsonValue] = {
        "operation_id": operation_id,
        "status": status,
        "decision": _decision(result.get("decision"), expected_effect),
        "payload": payload,
        "audit_ref": audit_ref,
        "replayed": replayed,
    }
    if status != "pending":
        return parsed
    pending_id = _uuid(result.get("pending_id"), "adapter lifecycle result.pending_id")
    plan = result.get("resolution_plan")
    safety = result.get("reservation_safety_certificate_digest")
    entitlement = result.get("reservation_entitlement_digest")
    parsed["pending_id"] = pending_id
    if plan is None:
        if safety is not None or entitlement is not None:
            raise ValueError("adapter lifecycle reservation digests require resolution_plan")
        return parsed
    if plan not in ("revalidate", "scoped-hold", "reservation-proof"):
        raise ValueError("adapter lifecycle result.resolution_plan is invalid")
    if plan == "reservation-proof":
        if (
            not isinstance(safety, str)
            or _SHA256.fullmatch(safety) is None
            or not isinstance(entitlement, str)
            or _SHA256.fullmatch(entitlement) is None
        ):
            raise ValueError("adapter lifecycle reservation-proof digests must be SHA-256 values")
        parsed["reservation_safety_certificate_digest"] = safety
        parsed["reservation_entitlement_digest"] = entitlement
    elif safety is not None or entitlement is not None:
        raise ValueError("non-proof adapter lifecycle result must not carry reservation digests")
    parsed["resolution_plan"] = cast(JsonValue, plan)
    return parsed


def validate_adapter_lifecycle_envelope(value: object) -> AdapterLifecycleEnvelope:
    envelope = _record(value, "adapter lifecycle")
    _exact_keys(envelope, ("kind", "invocation", "result", "locator"), "adapter lifecycle")
    if envelope.get("kind") != "lifecycle":
        raise ValueError("adapter lifecycle kind is invalid")
    invocation = create_adapter_invocation(envelope.get("invocation"))
    result = _lifecycle_result(envelope.get("result"))
    locator = validate_operation_locator(envelope.get("locator"))
    if result["operation_id"] != locator["operation_id"]:
        raise ValueError("adapter lifecycle result and locator operation_id must match")
    if result["status"] == "pending":
        if locator.get("pending_id") != result["pending_id"]:
            raise ValueError("adapter lifecycle result and locator pending_id must match")
    elif "pending_id" in locator:
        raise ValueError("non-pending adapter lifecycle must not carry a pending locator")
    return {
        "kind": "lifecycle",
        "invocation": cast(JsonValue, invocation),
        "result": cast(JsonValue, result),
        "locator": cast(JsonValue, locator),
    }


def create_adapter_lifecycle_envelope(
    invocation: object, result: Mapping[str, object]
) -> AdapterLifecycleEnvelope:
    return validate_adapter_lifecycle_envelope(
        {
            "kind": "lifecycle",
            "invocation": invocation,
            "result": result,
            "locator": cast(JsonValue, operation_locator(result)),
        }
    )


def validate_adapter_cancellation_envelope(value: object) -> AdapterCancellationEnvelope:
    envelope = _record(value, "adapter cancellation")
    _exact_keys(
        envelope,
        ("kind", "locator", "accepted", "terminal_result"),
        "adapter cancellation",
    )
    accepted = envelope.get("accepted")
    if envelope.get("kind") != "cancellation" or type(accepted) is not bool:
        raise ValueError("adapter cancellation is malformed")
    locator = validate_operation_locator(envelope.get("locator"))
    if "pending_id" not in locator:
        raise ValueError("adapter cancellation locator must include pending_id")
    if accepted and "terminal_result" in envelope:
        raise ValueError("accepted adapter cancellation must not carry a terminal result")
    if "terminal_result" not in envelope:
        return {
            "kind": "cancellation",
            "locator": cast(JsonValue, locator),
            "accepted": accepted,
        }
    terminal = _lifecycle_result(envelope["terminal_result"])
    if terminal["status"] not in ("committed", "denied"):
        raise ValueError("adapter cancellation terminal_result must be committed or denied")
    if terminal["operation_id"] != locator["operation_id"]:
        raise ValueError("adapter cancellation result and locator operation_id must match")
    return {
        "kind": "cancellation",
        "locator": cast(JsonValue, locator),
        "accepted": False,
        "terminal_result": cast(JsonValue, terminal),
    }


def validate_adapter_receipt_envelope(value: object) -> AdapterReceiptEnvelope:
    receipt = _record(value, "adapter receipt")
    _exact_keys(receipt, ("kind", "locator", "audit_ref", "status", "marker"), "adapter receipt")
    if receipt.get("kind") != "receipt":
        raise ValueError("adapter receipt kind is invalid")
    status = receipt.get("status")
    if not isinstance(status, str) or status not in _STATUSES:
        raise ValueError("adapter receipt.status is invalid")
    locator = validate_operation_locator(receipt.get("locator"))
    return {
        "kind": "receipt",
        "locator": cast(JsonValue, locator),
        "audit_ref": _audit_ref(
            receipt.get("audit_ref"),
            "adapter receipt.audit_ref",
            locator["operation_id"],
        ),
        "status": status,
        "marker": _string(receipt.get("marker"), "adapter receipt.marker"),
    }


def _canonical_string(value: str) -> str:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ValueError("canonical JSON strings must not contain unpaired surrogate code units")
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _ecmascript_number(value: float) -> str:
    """Render a finite IEEE-754 value with ECMAScript JSON number rules."""

    if not math.isfinite(value):
        raise ValueError("canonical JSON numbers must be finite")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    mantissa, _, exponent_text = repr(abs(value)).lower().partition("e")
    exponent = int(exponent_text) if exponent_text else 0
    whole, _dot, fraction = mantissa.partition(".")
    digits = whole + fraction
    leading_zeroes = len(digits) - len(digits.lstrip("0"))
    digits = digits.lstrip("0").rstrip("0")
    if not digits:  # pragma: no cover - zero returned above
        return "0"
    decimal_point = len(whole) + exponent - leading_zeroes
    scientific_exponent = decimal_point - 1
    if scientific_exponent >= 21 or scientific_exponent <= -7:
        coefficient = digits[0] if len(digits) == 1 else f"{digits[0]}.{digits[1:]}"
        return f"{sign}{coefficient}e{scientific_exponent:+d}"
    if decimal_point <= 0:
        return f"{sign}0.{('0' * -decimal_point)}{digits}"
    if decimal_point >= len(digits):
        return f"{sign}{digits}{('0' * (decimal_point - len(digits)))}"
    return f"{sign}{digits[:decimal_point]}.{digits[decimal_point:]}"


def _canonical_json(value: JsonValue) -> str:
    """Encode the shared UTF-16/ECMAScript host-adapter canonical JSON form."""

    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return str(value)
    if type(value) is float:
        return _ecmascript_number(value)
    if isinstance(value, str):
        return _canonical_string(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonical_json(item) for item in value) + "]"
    object_value = cast(dict[str, JsonValue], value)
    return (
        "{"
        + ",".join(
            f"{_canonical_string(key)}:{_canonical_json(object_value[key])}"
            for key in sorted(object_value, key=lambda item: item.encode("utf-16-be"))
        )
        + "}"
    )


def canonical_adapter_envelope(value: object) -> str:
    record = _record(value, "adapter envelope")
    kind = record.get("kind")
    if kind == "lifecycle":
        parsed: object = validate_adapter_lifecycle_envelope(record)
    elif kind == "cancellation":
        parsed = validate_adapter_cancellation_envelope(record)
    elif kind == "receipt":
        parsed = validate_adapter_receipt_envelope(record)
    else:
        parsed = create_adapter_invocation(record)
    return _canonical_json(cast(JsonValue, parsed))


def canonical_governed_route_manifest(value: object) -> str:
    return _canonical_json(validate_governed_route_manifest(value))
