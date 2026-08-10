"""Governed Action Protocol schema contract (build step 1.1).

The examples are executable protocol documentation. The deliberately invalid
detached-allow response is the teeth check: a decision cannot escape from the
terminal status/effect coupling encoded by the action-result schema.
"""

from __future__ import annotations

import importlib.util
import json
from copy import deepcopy
from importlib import import_module
from pathlib import Path
from typing import Any, cast

import pytest

from masugate.masugated.app import _audit_json

jsonschema: Any = import_module("jsonschema")

PROTOCOL_DIR = Path(__file__).parents[1] / "protocol"
SCHEMA_DIR = PROTOCOL_DIR / "schemas"
EXAMPLE_DIR = PROTOCOL_DIR / "examples"

EXPECTED_SCHEMAS = {
    "action-request.schema.json",
    "action-response.schema.json",
    "artifact-request.schema.json",
    "artifact-response.schema.json",
    "audit.schema.json",
    "connector-registry.schema.json",
    "connector-worker-containment.schema.json",
    "error.schema.json",
    "host-adapter-envelope.schema.json",
    "host-adapter-lifecycle.schema.json",
    "host-adapter-route-manifest.schema.json",
    "host-adapter-roster.schema.json",
    "governed-route-manifest-v2.schema.json",
    "operation-deployment-binding.schema.json",
    "operation-pack.schema.json",
    "pending-event.schema.json",
    "pending-list.schema.json",
    "resolve-request.schema.json",
}

EXPECTED_EXAMPLES = {
    "adapter-core-conformance.json",
    "action-request.json",
    "artifact-request.json",
    "artifact-response.json",
    "audit.json",
    "committed-response.json",
    "connector-registry-route-fixture.json",
    "connector-worker-containment.json",
    "denied-response.json",
    "error.json",
    "host-adapter-cancellation.json",
    "host-adapter-golden-vectors.json",
    "host-adapter-invocation.json",
    "host-adapter-lifecycle.json",
    "host-adapter-route-manifest.json",
    "host-adapter-roster.json",
    "governed-route-manifest-v2-route-fixture.json",
    "host-adapter-receipt.json",
    "invalid-detached-allow-response.json",
    "pending-event.json",
    "pending-list.json",
    "pending-response.json",
    "operation-deployment-binding-route-fixture.json",
    "operation-pack-route-fixture.json",
    "operation-pack-v2-field-vectors.json",
    "resolve-request.json",
}

VALID_EXAMPLES = {
    "action-request.schema.json": ("action-request.json",),
    "artifact-request.schema.json": ("artifact-request.json",),
    "artifact-response.schema.json": ("artifact-response.json",),
    "action-response.schema.json": (
        "committed-response.json",
        "denied-response.json",
        "pending-response.json",
    ),
    "audit.schema.json": ("audit.json",),
    "connector-registry.schema.json": ("connector-registry-route-fixture.json",),
    "connector-worker-containment.schema.json": ("connector-worker-containment.json",),
    "error.schema.json": ("error.json",),
    "host-adapter-envelope.schema.json": ("host-adapter-invocation.json",),
    "host-adapter-lifecycle.schema.json": (
        "host-adapter-lifecycle.json",
        "host-adapter-cancellation.json",
        "host-adapter-receipt.json",
    ),
    "host-adapter-route-manifest.schema.json": ("host-adapter-route-manifest.json",),
    "host-adapter-roster.schema.json": ("host-adapter-roster.json",),
    "governed-route-manifest-v2.schema.json": ("governed-route-manifest-v2-route-fixture.json",),
    "operation-deployment-binding.schema.json": (
        "operation-deployment-binding-route-fixture.json",
    ),
    "operation-pack.schema.json": ("operation-pack-route-fixture.json",),
    "pending-event.schema.json": ("pending-event.json",),
    "pending-list.schema.json": ("pending-list.json",),
    "resolve-request.schema.json": ("resolve-request.json",),
}


def _load(path: Path) -> dict[str, object]:
    raw: object = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(raw, dict), f"{path} must contain a JSON object"
    return cast(dict[str, object], raw)


def _package_checker_module() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "check-package-artifacts.py"
    spec = importlib.util.spec_from_file_location("package_artifacts", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _validator(schema_name: str) -> Any:
    schema = _load(SCHEMA_DIR / schema_name)
    return jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )


def test_protocol_asset_inventory_is_complete_and_every_json_file_loads() -> None:
    schema_files = {path.name for path in SCHEMA_DIR.glob("*.json")}
    example_files = {path.name for path in EXAMPLE_DIR.glob("*.json")}

    assert schema_files == EXPECTED_SCHEMAS
    assert example_files == EXPECTED_EXAMPLES
    assert set(VALID_EXAMPLES) == EXPECTED_SCHEMAS

    for path in sorted((*SCHEMA_DIR.glob("*.json"), *EXAMPLE_DIR.glob("*.json"))):
        _load(path)


def test_every_normative_host_adapter_example_is_in_the_package_inventory() -> None:
    expected = {
        f"masugate/protocol/examples/{name}"
        for name in EXPECTED_EXAMPLES
        if name.startswith("host-adapter-")
    }

    assert expected <= _package_checker_module().REQUIRED_PACKAGE_FILES


@pytest.mark.parametrize("schema_name", sorted(EXPECTED_SCHEMAS))
def test_every_schema_is_valid_draft_2020_12(schema_name: str) -> None:
    schema = _load(SCHEMA_DIR / schema_name)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    jsonschema.Draft202012Validator.check_schema(schema)


def test_host_adapter_schemas_share_the_exact_invocation_contract() -> None:
    invocation_schema = _load(SCHEMA_DIR / "host-adapter-envelope.schema.json")
    lifecycle_schema = _load(SCHEMA_DIR / "host-adapter-lifecycle.schema.json")
    invocation_defs = cast(dict[str, object], invocation_schema["$defs"])
    lifecycle_defs = cast(dict[str, object], lifecycle_schema["$defs"])

    assert lifecycle_defs["identifier"] == invocation_defs["identifier"]
    assert lifecycle_defs["action_identifier"] == invocation_defs["action_identifier"]
    assert lifecycle_defs["argument_name"] == invocation_defs["argument_name"]
    assert lifecycle_defs["invocation"] == invocation_defs["invocation"]


def test_governed_route_manifest_reuses_the_host_adapter_argument_name_boundary() -> None:
    invocation_schema = _load(SCHEMA_DIR / "host-adapter-envelope.schema.json")
    manifest_schema = _load(SCHEMA_DIR / "host-adapter-route-manifest.schema.json")
    invocation_defs = cast(dict[str, object], invocation_schema["$defs"])
    manifest_defs = cast(dict[str, object], manifest_schema["$defs"])

    manifest_argument_name = cast(dict[str, object], manifest_defs["argument_name"])
    invocation_argument_name = cast(dict[str, object], invocation_defs["argument_name"])
    assert manifest_argument_name["type"] == invocation_argument_name["type"] == "string"
    assert manifest_argument_name["maxLength"] == invocation_argument_name["maxLength"] == 256
    assert manifest_argument_name["pattern"] == invocation_argument_name["pattern"]


@pytest.mark.parametrize(
    ("schema_name", "example_name"),
    [
        ("host-adapter-envelope.schema.json", "host-adapter-invocation.json"),
        ("host-adapter-lifecycle.schema.json", "host-adapter-lifecycle.json"),
    ],
)
def test_host_adapter_schemas_reject_unsafe_integer_arguments(
    schema_name: str,
    example_name: str,
) -> None:
    envelope = deepcopy(_load(EXAMPLE_DIR / example_name))
    if schema_name == "host-adapter-envelope.schema.json":
        invocation = envelope
    else:
        invocation = cast(dict[str, object], envelope["invocation"])
    action = cast(dict[str, object], invocation["action"])
    arguments = cast(dict[str, object], action["arguments"])
    arguments["amount"] = 9_007_199_254_740_992

    with pytest.raises(jsonschema.ValidationError):
        _validator(schema_name).validate(envelope)


def test_governed_route_manifest_requires_a_complete_execution_owner() -> None:
    manifest = _load(EXAMPLE_DIR / "host-adapter-route-manifest.json")
    route = cast(dict[str, object], cast(list[object], manifest["routes"])[0])
    owner = cast(dict[str, object], route["owner"])
    del owner["connector_id"]

    with pytest.raises(jsonschema.ValidationError):
        _validator("host-adapter-route-manifest.schema.json").validate(manifest)


@pytest.mark.parametrize(
    ("schema_name", "example_name"),
    [
        (schema_name, example_name)
        for schema_name, example_names in VALID_EXAMPLES.items()
        for example_name in example_names
    ],
)
def test_handwritten_examples_validate(schema_name: str, example_name: str) -> None:
    _validator(schema_name).validate(_load(EXAMPLE_DIR / example_name))


@pytest.mark.parametrize(
    "field_name",
    [
        item["name"]
        for item in cast(
            list[dict[str, str]],
            _load(EXAMPLE_DIR / "operation-pack-v2-field-vectors.json")["invalid_model_fields"],
        )
    ],
)
def test_operation_schemas_reject_the_shared_trust_and_credential_field_vectors(
    field_name: str,
) -> None:
    pack = _load(EXAMPLE_DIR / "operation-pack-route-fixture.json")
    pack_action = cast(dict[str, object], cast(list[object], pack["actions"])[0])
    pack_input = cast(dict[str, object], pack_action["input_schema"])
    cast(dict[str, object], pack_input["properties"])[field_name] = {
        "type": "string",
        "maxLength": 16,
    }
    with pytest.raises(jsonschema.ValidationError):
        _validator("operation-pack.schema.json").validate(pack)

    manifest = _load(EXAMPLE_DIR / "governed-route-manifest-v2-route-fixture.json")
    route = cast(dict[str, object], cast(list[object], manifest["routes"])[0])
    route_input = cast(dict[str, object], route["input_schema"])
    cast(dict[str, object], route_input["properties"])[field_name] = {
        "type": "string",
        "maxLength": 16,
    }
    with pytest.raises(jsonschema.ValidationError):
        _validator("governed-route-manifest-v2.schema.json").validate(manifest)


def test_operation_pack_schema_requires_an_object_input_schema() -> None:
    pack = _load(EXAMPLE_DIR / "operation-pack-route-fixture.json")
    action = cast(dict[str, object], cast(list[object], pack["actions"])[0])
    action["input_schema"] = {
        "type": "array",
        "items": {"type": "string", "maxLength": 16},
        "maxItems": 1,
    }

    with pytest.raises(jsonschema.ValidationError):
        _validator("operation-pack.schema.json").validate(pack)


def test_operation_schemas_bound_action_route_and_capability_breadth() -> None:
    pack = _load(EXAMPLE_DIR / "operation-pack-route-fixture.json")
    action = cast(dict[str, object], cast(list[object], pack["actions"])[0])
    pack["actions"] = [
        {**deepcopy(action), "action": f"reference.notify_{index}"} for index in range(65)
    ]
    with pytest.raises(jsonschema.ValidationError):
        _validator("operation-pack.schema.json").validate(pack)

    pack = _load(EXAMPLE_DIR / "operation-pack-route-fixture.json")
    action = cast(dict[str, object], cast(list[object], pack["actions"])[0])
    action["required_connector_capabilities"] = [f"capability_{index}" for index in range(65)]
    with pytest.raises(jsonschema.ValidationError):
        _validator("operation-pack.schema.json").validate(pack)

    manifest = _load(EXAMPLE_DIR / "governed-route-manifest-v2-route-fixture.json")
    route = cast(dict[str, object], cast(list[object], manifest["routes"])[0])
    manifest["routes"] = [
        {
            **deepcopy(route),
            "host_tool": f"reference_notify_{index}",
            "action": f"reference.notify_{index}",
        }
        for index in range(65)
    ]
    with pytest.raises(jsonschema.ValidationError):
        _validator("governed-route-manifest-v2.schema.json").validate(manifest)

    manifest = _load(EXAMPLE_DIR / "governed-route-manifest-v2-route-fixture.json")
    route = cast(dict[str, object], cast(list[object], manifest["routes"])[0])
    route["required_connector_capabilities"] = [f"capability_{index}" for index in range(65)]
    with pytest.raises(jsonschema.ValidationError):
        _validator("governed-route-manifest-v2.schema.json").validate(manifest)


@pytest.mark.parametrize(
    ("schema_name", "example_name", "collection_name"),
    [
        ("operation-pack.schema.json", "operation-pack-route-fixture.json", "actions"),
        (
            "governed-route-manifest-v2.schema.json",
            "governed-route-manifest-v2-route-fixture.json",
            "routes",
        ),
        (
            "operation-deployment-binding.schema.json",
            "operation-deployment-binding-route-fixture.json",
            "routes",
        ),
    ],
)
def test_operation_schemas_enforce_the_255_character_action_limit(
    schema_name: str,
    example_name: str,
    collection_name: str,
) -> None:
    document = _load(EXAMPLE_DIR / example_name)
    item = cast(dict[str, object], cast(list[object], document[collection_name])[0])
    item["action"] = "a" * 255
    _validator(schema_name).validate(document)

    item["action"] = "a" * 256

    with pytest.raises(jsonschema.ValidationError):
        _validator(schema_name).validate(document)


def test_operation_schemas_require_production_profiles_to_be_protected_external() -> None:
    pack = _load(EXAMPLE_DIR / "operation-pack-route-fixture.json")
    action = cast(dict[str, object], cast(list[object], pack["actions"])[0])
    action["owner_position"] = "transactional"
    action["required_connector_capabilities"] = []
    action["maturity"] = "production-profile"
    with pytest.raises(jsonschema.ValidationError):
        _validator("operation-pack.schema.json").validate(pack)

    manifest = _load(EXAMPLE_DIR / "governed-route-manifest-v2-route-fixture.json")
    route = cast(dict[str, object], cast(list[object], manifest["routes"])[0])
    route["owner"] = {"provider_id": "route-fixture-provider-v1", "position": "transactional"}
    route["required_connector_capabilities"] = []
    route["maturity"] = "production-profile"
    with pytest.raises(jsonschema.ValidationError):
        _validator("governed-route-manifest-v2.schema.json").validate(manifest)

    pack = _load(EXAMPLE_DIR / "operation-pack-route-fixture.json")
    action = cast(dict[str, object], cast(list[object], pack["actions"])[0])
    action["owner_position"] = "transactional"
    action["maturity"] = "reference-effect"
    with pytest.raises(jsonschema.ValidationError):
        _validator("operation-pack.schema.json").validate(pack)

    manifest = _load(EXAMPLE_DIR / "governed-route-manifest-v2-route-fixture.json")
    route = cast(dict[str, object], cast(list[object], manifest["routes"])[0])
    route["owner"] = {"provider_id": "route-fixture-provider-v1", "position": "transactional"}
    route["maturity"] = "reference-effect"
    with pytest.raises(jsonschema.ValidationError):
        _validator("governed-route-manifest-v2.schema.json").validate(manifest)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("entitlement_state", "released"),
        ("dispatch_started", False),
        ("receipt", None),
    ],
)
def test_protected_execution_audit_rejects_false_success_accounting(
    field: str,
    invalid_value: object,
) -> None:
    audit = _load(EXAMPLE_DIR / "audit.json")
    protected = cast(dict[str, object], audit["protected_execution"])
    protected[field] = invalid_value

    with pytest.raises(jsonschema.ValidationError):
        _validator("audit.schema.json").validate(audit)


@pytest.mark.parametrize("evidence_field", ["receipt", "external_operation_id"])
def test_protected_execution_audit_rejects_evidence_without_dispatch(
    evidence_field: str,
) -> None:
    audit = _load(EXAMPLE_DIR / "audit.json")
    protected = cast(dict[str, object], audit["protected_execution"])
    protected["status"] = "executing"
    protected["entitlement_state"] = "held"
    protected["dispatch_started"] = False
    if evidence_field == "receipt":
        protected["external_operation_id"] = None
    else:
        protected["receipt"] = None

    with pytest.raises(jsonschema.ValidationError):
        _validator("audit.schema.json").validate(audit)


def test_audit_schema_rejects_removed_legacy_authorization_evidence() -> None:
    audit = _load(EXAMPLE_DIR / "audit.json")
    entitlement = cast(dict[str, object], audit["entitlement"])
    entitlement["authorization_request_digest"] = "e" * 64

    with pytest.raises(jsonschema.ValidationError):
        _validator("audit.schema.json").validate(audit)


@pytest.mark.parametrize(
    "status",
    ["committed", "denied", "pending", "in_progress", "outcome_unknown"],
)
def test_audit_schema_rejects_contradictory_protected_execution_status(status: str) -> None:
    audit = _load(EXAMPLE_DIR / "audit.json")
    protected = cast(dict[str, object], audit["protected_execution"])
    decision = cast(dict[str, object], audit["decision"])
    if status == "committed":
        protected["status"] = "failed"
        protected["entitlement_state"] = "released"
        receipt = cast(dict[str, object], protected["receipt"])
        receipt["outcome"] = "failed"
        events = cast(list[dict[str, object]], protected["events"])
        events[-1]["to_status"] = "failed"
    elif status == "denied":
        audit["status"] = status
        decision["effect"] = "deny"
        audit["effect"] = None
    elif status == "pending":
        audit["status"] = status
        decision["effect"] = "escalate"
        audit["effect"] = None
    else:
        audit["status"] = status
        audit["decision"] = None
        audit["effect"] = None

    with pytest.raises(jsonschema.ValidationError):
        _validator("audit.schema.json").validate(audit)


@pytest.mark.parametrize(
    "path",
    [
        "authorization_evaluations",
        "terminal_serialization",
        "policy.evaluated_policy_provenance",
    ],
)
def test_audit_schema_requires_normative_receipt_evidence(path: str) -> None:
    audit = _load(EXAMPLE_DIR / "audit.json")
    target = audit
    *parents, leaf = path.split(".")
    for parent in parents:
        target = cast(dict[str, object], target[parent])
    del target[leaf]

    with pytest.raises(jsonschema.ValidationError):
        _validator("audit.schema.json").validate(audit)


@pytest.mark.parametrize(
    ("status", "terminal_kind"),
    [
        ("committed", "denial-record"),
        ("denied", "effect-commit"),
        ("pending", "effect-commit"),
    ],
)
def test_audit_schema_couples_terminal_serialization_to_status(
    status: str, terminal_kind: str
) -> None:
    audit = _load(EXAMPLE_DIR / "audit.json")
    decision = cast(dict[str, object], audit["decision"])
    if status == "denied":
        audit["status"] = status
        decision["effect"] = "deny"
        audit["effect"] = None
        protected = cast(dict[str, object], audit["protected_execution"])
        protected["status"] = "failed"
        protected["entitlement_state"] = "released"
        receipt = cast(dict[str, object], protected["receipt"])
        receipt["outcome"] = "failed"
        events = cast(list[dict[str, object]], protected["events"])
        events[-1]["to_status"] = "failed"
    elif status == "pending":
        audit["status"] = status
        decision["effect"] = "escalate"
        audit["effect"] = None
        del audit["protected_execution"]
    terminal = cast(dict[str, object], audit["terminal_serialization"])
    terminal["kind"] = terminal_kind

    with pytest.raises(jsonschema.ValidationError):
        _validator("audit.schema.json").validate(audit)


def test_detached_allow_anti_example_is_structurally_rejected() -> None:
    detached_allow = _load(EXAMPLE_DIR / "invalid-detached-allow-response.json")

    with pytest.raises(jsonschema.ValidationError):
        _validator("action-response.schema.json").validate(detached_allow)


@pytest.mark.parametrize(
    "server_owned_field",
    ["operation_id", "principal_ref", "principal", "attributes", "timestamp"],
)
def test_action_request_rejects_server_owned_fields(server_owned_field: str) -> None:
    request = _load(EXAMPLE_DIR / "action-request.json")
    request[server_owned_field] = "caller-controlled"

    with pytest.raises(jsonschema.ValidationError):
        _validator("action-request.schema.json").validate(request)


def test_action_request_rejects_unsafe_integer_arguments() -> None:
    request = _load(EXAMPLE_DIR / "action-request.json")
    arguments = cast(dict[str, object], request["args"])
    arguments["amount_cents"] = 9_007_199_254_740_992

    with pytest.raises(jsonschema.ValidationError):
        _validator("action-request.schema.json").validate(request)


@pytest.mark.parametrize(
    ("example_name", "wrong_effect"),
    [
        ("committed-response.json", "deny"),
        ("denied-response.json", "allow"),
        ("pending-response.json", "allow"),
    ],
)
def test_each_status_rejects_a_mismatched_decision_effect(
    example_name: str, wrong_effect: str
) -> None:
    response = deepcopy(_load(EXAMPLE_DIR / example_name))
    decision = cast(dict[str, object], response["decision"])
    decision["effect"] = wrong_effect

    with pytest.raises(jsonschema.ValidationError):
        _validator("action-response.schema.json").validate(response)


def test_pending_response_requires_pending_id() -> None:
    response = _load(EXAMPLE_DIR / "pending-response.json")
    del response["pending_id"]

    with pytest.raises(jsonschema.ValidationError):
        _validator("action-response.schema.json").validate(response)


def test_host_adapter_lifecycle_rejects_incomplete_invocation() -> None:
    lifecycle = _load(EXAMPLE_DIR / "host-adapter-lifecycle.json")
    invocation = cast(dict[str, object], lifecycle["invocation"])
    del invocation["principal"]

    with pytest.raises(jsonschema.ValidationError):
        _validator("host-adapter-lifecycle.schema.json").validate(lifecycle)


@pytest.mark.parametrize(
    "argument_name",
    [
        "adapter_id",
        "adapter_capabilities",
        "contract_version",
        "invocation_id",
        "p_r_i_n_c_i_p_a_l",
        "retry_authority",
        "receipt_ref",
        "source_id",
        "source_namespace",
        "Tool-Call-ID",
    ],
)
@pytest.mark.parametrize(
    ("schema_name", "example_name", "invocation_location"),
    [
        ("host-adapter-envelope.schema.json", "host-adapter-invocation.json", "root"),
        ("host-adapter-lifecycle.schema.json", "host-adapter-lifecycle.json", "nested"),
    ],
)
def test_host_adapter_schemas_reject_reserved_authority_argument_names(
    argument_name: str,
    schema_name: str,
    example_name: str,
    invocation_location: str,
) -> None:
    document = _load(EXAMPLE_DIR / example_name)
    invocation = (
        document
        if invocation_location == "root"
        else cast(dict[str, object], document["invocation"])
    )
    action = cast(dict[str, object], invocation["action"])
    arguments = cast(dict[str, object], action["arguments"])
    arguments[argument_name] = "spoofed"

    with pytest.raises(jsonschema.ValidationError):
        _validator(schema_name).validate(document)


def test_host_adapter_lifecycle_couples_pending_status_and_decision() -> None:
    lifecycle = _load(EXAMPLE_DIR / "host-adapter-lifecycle.json")
    result = cast(dict[str, object], lifecycle["result"])
    decision = cast(dict[str, object], result["decision"])
    decision["effect"] = "allow"

    with pytest.raises(jsonschema.ValidationError):
        _validator("host-adapter-lifecycle.schema.json").validate(lifecycle)


def test_host_adapter_pending_lifecycle_requires_pending_locator() -> None:
    lifecycle = _load(EXAMPLE_DIR / "host-adapter-lifecycle.json")
    locator = cast(dict[str, object], lifecycle["locator"])
    del locator["pending_id"]

    with pytest.raises(jsonschema.ValidationError):
        _validator("host-adapter-lifecycle.schema.json").validate(lifecycle)


def test_host_adapter_cancellation_rejects_pending_as_terminal() -> None:
    cancellation = _load(EXAMPLE_DIR / "host-adapter-cancellation.json")
    cancellation["accepted"] = False
    lifecycle = _load(EXAMPLE_DIR / "host-adapter-lifecycle.json")
    cancellation["terminal_result"] = lifecycle["result"]

    with pytest.raises(jsonschema.ValidationError):
        _validator("host-adapter-lifecycle.schema.json").validate(cancellation)


def test_host_adapter_cancellation_requires_the_requested_pending_locator() -> None:
    cancellation = _load(EXAMPLE_DIR / "host-adapter-cancellation.json")
    locator = cast(dict[str, object], cancellation["locator"])
    del locator["pending_id"]

    with pytest.raises(jsonschema.ValidationError):
        _validator("host-adapter-lifecycle.schema.json").validate(cancellation)


@pytest.mark.parametrize("status", ["in_progress", "outcome_unknown"])
def test_host_adapter_operational_status_is_nonterminal(status: str) -> None:
    lifecycle = _load(EXAMPLE_DIR / "host-adapter-lifecycle.json")
    result = cast(dict[str, object], lifecycle["result"])
    result["status"] = status
    result["decision"] = None
    del result["pending_id"]
    result.pop("resolution_plan", None)
    locator = cast(dict[str, object], lifecycle["locator"])
    locator.pop("pending_id")
    _validator("host-adapter-lifecycle.schema.json").validate(lifecycle)

    cancellation = _load(EXAMPLE_DIR / "host-adapter-cancellation.json")
    cancellation["accepted"] = False
    cancellation["terminal_result"] = result
    with pytest.raises(jsonschema.ValidationError):
        _validator("host-adapter-lifecycle.schema.json").validate(cancellation)


@pytest.mark.parametrize(
    ("schema_name", "example_name", "location"),
    [
        ("action-response.schema.json", "pending-response.json", "root"),
        ("audit.schema.json", "audit.json", "root"),
        ("pending-list.schema.json", "pending-list.json", "list-item"),
        ("pending-event.schema.json", "pending-event.json", "event-pending"),
    ],
)
def test_resolution_metadata_accepts_only_complete_current_or_empty_legacy_shape(
    schema_name: str,
    example_name: str,
    location: str,
) -> None:
    def metadata(value: dict[str, object]) -> dict[str, object]:
        if location == "root":
            return value
        if location == "list-item":
            return cast(dict[str, object], cast(list[object], value["items"])[0])
        return cast(dict[str, object], value["pending"])

    validator = _validator(schema_name)

    missing_plan = _load(EXAMPLE_DIR / example_name)
    del metadata(missing_plan)["resolution_plan"]
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(missing_plan)

    planless_certificate = _load(EXAMPLE_DIR / example_name)
    planless_metadata = metadata(planless_certificate)
    del planless_metadata["resolution_plan"]
    del planless_metadata["reservation_entitlement_digest"]
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(planless_certificate)

    planless_entitlement = _load(EXAMPLE_DIR / example_name)
    planless_metadata = metadata(planless_entitlement)
    del planless_metadata["resolution_plan"]
    del planless_metadata["reservation_safety_certificate_digest"]
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(planless_entitlement)

    missing_certificate = _load(EXAMPLE_DIR / example_name)
    del metadata(missing_certificate)["reservation_safety_certificate_digest"]
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(missing_certificate)

    missing_entitlement = _load(EXAMPLE_DIR / example_name)
    del metadata(missing_entitlement)["reservation_entitlement_digest"]
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(missing_entitlement)

    revalidation_with_certificate = _load(EXAMPLE_DIR / example_name)
    revalidation_metadata = metadata(revalidation_with_certificate)
    revalidation_metadata["resolution_plan"] = "revalidate"
    del revalidation_metadata["reservation_entitlement_digest"]
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(revalidation_with_certificate)

    revalidation_with_entitlement = _load(EXAMPLE_DIR / example_name)
    revalidation_metadata = metadata(revalidation_with_entitlement)
    revalidation_metadata["resolution_plan"] = "revalidate"
    del revalidation_metadata["reservation_safety_certificate_digest"]
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(revalidation_with_entitlement)

    # A safely downgraded invalid proof carries an explicit revalidation plan and
    # no proof identity. This is a current, schema-valid representation.
    revalidation = _load(EXAMPLE_DIR / example_name)
    revalidation_metadata = metadata(revalidation)
    revalidation_metadata["resolution_plan"] = "revalidate"
    del revalidation_metadata["reservation_safety_certificate_digest"]
    del revalidation_metadata["reservation_entitlement_digest"]
    validator.validate(revalidation)

    # Compatibility is limited to the pre-metadata shape: all three fields absent.
    legacy = _load(EXAMPLE_DIR / example_name)
    legacy_metadata = metadata(legacy)
    del legacy_metadata["resolution_plan"]
    del legacy_metadata["reservation_safety_certificate_digest"]
    del legacy_metadata["reservation_entitlement_digest"]
    validator.validate(legacy)


def test_invalid_reservation_proof_denial_audit_is_schema_valid() -> None:
    audit = _load(EXAMPLE_DIR / "audit.json")
    audit["status"] = "denied"
    decision = cast(dict[str, object], audit["decision"])
    decision["effect"] = "deny"
    decision["rule_id"] = "reservation-proof-invalid"
    decision["reason"] = "reservation proof identity is invalid"
    audit["effect"] = None
    terminal = cast(dict[str, object], audit["terminal_serialization"])
    terminal["kind"] = "denial-record"
    terminal["authorization_basis"] = "mechanism-denial"
    audit["resolution_plan"] = "revalidate"
    del audit["reservation_safety_certificate_digest"]
    del audit["reservation_entitlement_digest"]
    del audit["protected_execution"]

    _validator("audit.schema.json").validate(audit)


def _provider_audit_record() -> dict[str, object]:
    return {
        "operation_id": "11111111-1111-4111-8111-111111111111",
        "status": "pending",
        "committed": False,
        "idempotency_key": "audit-projection",
        "principal_id": "alice",
        "principal_attributes": {"team": "research"},
        "action": "transfer",
        "arguments": {"receiver_id": "bob", "amount_cents": 5_000},
        "timestamp": "2026-07-13T12:00:00+00:00",
        "recorded_at": "2026-07-13T12:01:00+00:00",
        "trace_id": None,
        "decision": {
            "effect": "escalate",
            "policy_id": "approval",
            "policy_version": "v1",
            "rule_id": "review",
            "reason": "review required",
            "evaluated_policies": [["approval", "v1"]],
            "reads": [],
        },
        "payload": {},
    }


@pytest.mark.parametrize(
    "metadata",
    [
        {},
        {"resolution_plan": "reservation-proof"},
        {
            "resolution_plan": "reservation-proof",
            "reservation_safety_certificate_digest": "ab" * 32,
        },
        {
            "resolution_plan": "reservation-proof",
            "reservation_entitlement_digest": "cd" * 32,
        },
        {
            "resolution_plan": "reservation-proof",
            "reservation_safety_certificate_digest": "not-a-digest",
            "reservation_entitlement_digest": "cd" * 32,
        },
        {
            "resolution_plan": "unknown-plan",
            "reservation_safety_certificate_digest": "ab" * 32,
            "reservation_entitlement_digest": "cd" * 32,
        },
        {"resolution_plan": ["reservation-proof"]},
        {
            "resolution_plan": "revalidate",
            "reservation_safety_certificate_digest": "ab" * 32,
            "reservation_entitlement_digest": "cd" * 32,
        },
        {
            "resolution_plan": "scoped-hold",
            "reservation_safety_certificate_digest": "ab" * 32,
        },
    ],
)
def test_audit_projection_downgrades_incoherent_proof_metadata(
    metadata: dict[str, object],
) -> None:
    record = _provider_audit_record()
    record.update(metadata)

    receipt = _audit_json(cast(dict[str, Any], record))

    assert receipt["resolution_plan"] == "revalidate"
    assert "reservation_safety_certificate_digest" not in receipt
    assert "reservation_entitlement_digest" not in receipt
    assert receipt["recorded_at"] == record["recorded_at"]
    _validator("audit.schema.json").validate(receipt)


def test_audit_projection_preserves_only_complete_reservation_proof() -> None:
    record = _provider_audit_record()
    record.update(
        {
            "resolution_plan": "reservation-proof",
            "reservation_safety_certificate_digest": "ab" * 32,
            "reservation_entitlement_digest": "cd" * 32,
        }
    )

    receipt = _audit_json(cast(dict[str, Any], record))

    assert receipt["resolution_plan"] == "reservation-proof"
    assert receipt["reservation_safety_certificate_digest"] == "ab" * 32
    assert receipt["reservation_entitlement_digest"] == "cd" * 32
    assert receipt["recorded_at"] == record["recorded_at"]
    _validator("audit.schema.json").validate(receipt)


def test_audit_projection_falls_back_to_certified_timestamp_for_legacy_record() -> None:
    record = _provider_audit_record()
    del record["recorded_at"]

    receipt = _audit_json(cast(dict[str, Any], record))

    assert receipt["recorded_at"] == record["timestamp"]


@pytest.mark.parametrize("example_name", ["committed-response.json", "denied-response.json"])
def test_terminal_response_forbids_pending_id(example_name: str) -> None:
    response = _load(EXAMPLE_DIR / example_name)
    response["pending_id"] = "44444444-4444-4444-8444-444444444444"

    with pytest.raises(jsonschema.ValidationError):
        _validator("action-response.schema.json").validate(response)


@pytest.mark.parametrize("example_name", ["committed-response.json", "denied-response.json"])
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("resolution_plan", "revalidate"),
        ("reservation_safety_certificate_digest", "01" * 32),
        ("reservation_entitlement_digest", "ef" * 32),
    ],
)
def test_terminal_response_forbids_pending_resolution_metadata(
    example_name: str, field: str, value: str
) -> None:
    response = _load(EXAMPLE_DIR / example_name)
    response[field] = value

    with pytest.raises(jsonschema.ValidationError):
        _validator("action-response.schema.json").validate(response)
