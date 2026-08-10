"""Cross-language golden vectors for the public host-adapter contract."""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from copy import deepcopy
from pathlib import Path
from typing import cast

import pytest

from masugate_client import (
    canonical_adapter_envelope,
    canonical_governed_route_manifest,
    canonical_governed_route_manifest_v2,
    create_adapter_invocation,
    validate_adapter_lifecycle_envelope,
    validate_governed_route_manifest,
    validate_governed_route_manifest_v2,
)

_VECTOR_PATH = (
    Path(__file__).parents[3] / "protocol" / "examples" / "host-adapter-golden-vectors.json"
)
_VECTORS = json.loads(_VECTOR_PATH.read_text(encoding="utf-8"))
_V2_MANIFEST = json.loads(
    (
        Path(__file__).parents[3]
        / "protocol"
        / "examples"
        / "governed-route-manifest-v2-route-fixture.json"
    ).read_text(encoding="utf-8")
)
_V2_FIELD_VECTORS = cast(
    list[dict[str, str]],
    json.loads(
        (
            Path(__file__).parents[3]
            / "protocol"
            / "examples"
            / "operation-pack-v2-field-vectors.json"
        ).read_text(encoding="utf-8")
    )["invalid_model_fields"],
)


class _CountingMapping(Mapping[str, object]):
    def __init__(self, values: dict[str, object], counter: list[int]) -> None:
        self._values = values
        self._counter = counter

    def __getitem__(self, key: str) -> object:
        self._counter[0] += 1
        return self._values[key]

    def __iter__(self) -> Iterator[str]:
        self._counter[0] += 1
        return iter(self._values)

    def __len__(self) -> int:
        self._counter[0] += 1
        return len(self._values)


def _counted_schema_bomb(depth: int, counter: list[int]) -> Mapping[str, object]:
    if depth == 0:
        return _CountingMapping({"type": "string", "maxLength": 1}, counter)
    properties = {f"field_{index}": _counted_schema_bomb(depth - 1, counter) for index in range(8)}
    return _CountingMapping(
        {
            "type": "object",
            "properties": _CountingMapping(properties, counter),
            "required": list(properties),
            "additionalProperties": False,
        },
        counter,
    )


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _invocation() -> dict[str, object]:
    return deepcopy(cast(dict[str, object], _VECTORS["invocation"]))


def _lifecycle(name: str) -> dict[str, object]:
    for item in cast(list[dict[str, object]], _VECTORS["lifecycle"]):
        if item["name"] == name:
            return {
                "kind": "lifecycle",
                "invocation": _invocation(),
                "result": deepcopy(cast(dict[str, object], item["result"])),
                "locator": deepcopy(cast(dict[str, object], item["locator"])),
            }
    raise AssertionError(f"missing lifecycle vector: {name}")


def test_golden_vectors_canonicalize_invocation_manifest_and_every_lifecycle_state() -> None:
    invocation = create_adapter_invocation(_invocation())
    assert invocation["adapter"] == {
        "id": "masugate.canary",
        "contract_version": "masugate.host-adapter.v1",
        "capabilities": ["cancellation", "locator", "receipt"],
    }
    assert canonical_adapter_envelope(_invocation()) == _canonical(invocation)

    manifest = validate_governed_route_manifest(_VECTORS["manifest"])
    assert canonical_governed_route_manifest(_VECTORS["manifest"]) == _canonical(manifest)

    for status in ("committed", "denied", "pending", "in_progress", "outcome_unknown"):
        envelope = _lifecycle(status)
        parsed = validate_adapter_lifecycle_envelope(envelope)
        assert parsed["result"]["status"] == status
        assert canonical_adapter_envelope(envelope) == _canonical(parsed)

    cancellation = deepcopy(cast(dict[str, object], _VECTORS["cancellation"]))
    receipt = deepcopy(cast(dict[str, object], _VECTORS["receipt"]))
    assert canonical_adapter_envelope(cancellation) == _canonical(cancellation)
    assert canonical_adapter_envelope(receipt) == _canonical(receipt)

    canonicalization = cast(dict[str, object], _VECTORS["canonicalization"])
    numeric_unicode = _lifecycle("committed")
    result = cast(dict[str, object], numeric_unicode["result"])
    result["payload"] = deepcopy(canonicalization["payload"])
    expected_payload = cast(str, canonicalization["expected_payload_json"])
    assert f'"payload":{expected_payload}' in canonical_adapter_envelope(numeric_unicode)


def test_v2_route_manifest_canonicalization_is_stable_and_private_binding_free() -> None:
    manifest = validate_governed_route_manifest_v2(_V2_MANIFEST)
    canonical = canonical_governed_route_manifest_v2(_V2_MANIFEST)

    assert canonical == _canonical(manifest)
    assert "credential_refs" not in canonical
    assert "allowed_destinations" not in canonical


def test_v1_argument_names_remain_compatible_with_generated_host_prefixes() -> None:
    invocation = _invocation()
    action = cast(dict[str, object], invocation["action"])
    action["arguments"] = {"model_id": "model-1"}
    parsed_invocation = create_adapter_invocation(invocation)
    assert parsed_invocation["action"]["arguments"] == {"model_id": "model-1"}

    manifest = deepcopy(cast(dict[str, object], _VECTORS["manifest"]))
    route = cast(dict[str, object], cast(list[object], manifest["routes"])[0])
    arguments = cast(dict[str, object], route["arguments"])
    arguments["model_id"] = "string"
    parsed_manifest = validate_governed_route_manifest(manifest)
    assert parsed_manifest["routes"][0]["arguments"]["model_id"] == "string"


def test_v2_route_manifest_rejects_transactional_capabilities_and_production_profiles() -> None:
    manifest = deepcopy(cast(dict[str, object], _V2_MANIFEST))
    route = cast(dict[str, object], cast(list[object], manifest["routes"])[0])
    route["owner"] = {"provider_id": "route-fixture-provider-v1", "position": "transactional"}

    with pytest.raises(
        ValueError, match="transactional route cannot require connector capabilities"
    ):
        validate_governed_route_manifest_v2(manifest)

    route["required_connector_capabilities"] = []
    route["maturity"] = "production-profile"

    with pytest.raises(ValueError, match="production-profile requires protected-external"):
        validate_governed_route_manifest_v2(manifest)


def test_v2_route_manifest_rejects_artifact_shapes_the_shared_bridge_cannot_stage() -> None:
    manifest = deepcopy(cast(dict[str, object], _V2_MANIFEST))
    route = cast(dict[str, object], cast(list[object], manifest["routes"])[0])
    schema = cast(dict[str, object], route["input_schema"])
    properties = cast(dict[str, object], schema["properties"])
    properties["content"] = {"type": "string", "maxLength": 16}
    cast(list[str], schema["required"]).append("content")
    route["artifact_fields"] = ["content"]

    route["owner"] = {"provider_id": "route-fixture-provider-v1", "position": "transactional"}
    route["required_connector_capabilities"] = []
    with pytest.raises(ValueError, match="artifact_fields require protected-external position"):
        validate_governed_route_manifest_v2(manifest)

    route["owner"] = {
        "provider_id": "route-fixture-provider-v1",
        "position": "protected-external",
        "connector_id": "reference-route-fixture-v1",
    }
    cast(list[str], schema["required"]).remove("content")
    with pytest.raises(ValueError, match="required bounded string properties"):
        validate_governed_route_manifest_v2(manifest)


def test_v2_route_manifest_rejects_duplicate_actions_under_distinct_host_tools() -> None:
    manifest = deepcopy(cast(dict[str, object], _V2_MANIFEST))
    routes = cast(list[dict[str, object]], manifest["routes"])
    alias = deepcopy(routes[0])
    alias["host_tool"] = "reference_notify_alias"
    alias_schema = cast(dict[str, object], alias["input_schema"])
    alias_properties = cast(dict[str, object], alias_schema["properties"])
    cast(dict[str, object], alias_properties["recipient"])["maxLength"] = 319
    routes.append(alias)

    with pytest.raises(ValueError, match="must not repeat action"):
        validate_governed_route_manifest_v2(manifest)


def test_v2_route_manifest_bounds_route_capability_and_canonical_breadth() -> None:
    manifest = deepcopy(cast(dict[str, object], _V2_MANIFEST))
    route = cast(dict[str, object], cast(list[object], manifest["routes"])[0])
    manifest["routes"] = [
        {
            **deepcopy(route),
            "host_tool": f"reference_notify_{index}",
            "action": f"reference.notify_{index}",
        }
        for index in range(65)
    ]
    with pytest.raises(ValueError, match="routes must contain at most 64 entries"):
        validate_governed_route_manifest_v2(manifest)

    manifest = deepcopy(cast(dict[str, object], _V2_MANIFEST))
    route = cast(dict[str, object], cast(list[object], manifest["routes"])[0])
    route["required_connector_capabilities"] = [f"capability_{index}" for index in range(65)]
    with pytest.raises(ValueError, match="required_connector_capabilities must contain at most 64"):
        validate_governed_route_manifest_v2(manifest)

    with pytest.raises(ValueError, match="canonical form exceeds configured limit"):
        validate_governed_route_manifest_v2(_V2_MANIFEST, max_manifest_canonical_bytes=1)


def test_v2_schema_budget_stops_before_expanding_a_schema_bomb() -> None:
    reads = [0]
    manifest = deepcopy(cast(dict[str, object], _V2_MANIFEST))
    route = cast(dict[str, object], cast(list[object], manifest["routes"])[0])
    route["input_schema"] = _counted_schema_bomb(5, reads)

    with pytest.raises(ValueError, match="canonical form exceeds configured limit"):
        validate_governed_route_manifest_v2(manifest, max_schema_canonical_bytes=1)
    assert reads[0] < 100


@pytest.mark.parametrize(
    ("field_name", "message"),
    [(vector["name"], vector["message"]) for vector in _V2_FIELD_VECTORS],
)
def test_v2_route_manifest_rejects_trust_and_compound_credential_fields(
    field_name: str, message: str
) -> None:
    manifest = deepcopy(cast(dict[str, object], _V2_MANIFEST))
    route = cast(dict[str, object], cast(list[object], manifest["routes"])[0])
    schema = cast(dict[str, object], route["input_schema"])
    properties = cast(dict[str, object], schema["properties"])
    properties[field_name] = {"type": "string", "maxLength": 16}

    with pytest.raises(ValueError, match=message):
        validate_governed_route_manifest_v2(manifest)


@pytest.mark.parametrize("unsafe_integer", [9_007_199_254_740_992.0, 1e20])
def test_lifecycle_rejects_unsafe_integral_float_payloads(unsafe_integer: float) -> None:
    envelope = _lifecycle("committed")
    result = cast(dict[str, object], envelope["result"])
    result["payload"] = {"amount": unsafe_integer}

    with pytest.raises(ValueError, match="JavaScript-safe"):
        validate_adapter_lifecycle_envelope(envelope)


def test_canonicalization_rejects_unpaired_surrogate_strings() -> None:
    envelope = _lifecycle("committed")
    result = cast(dict[str, object], envelope["result"])
    result["payload"] = {"invalid": "\ud800"}

    with pytest.raises(ValueError, match="unpaired surrogate"):
        canonical_adapter_envelope(envelope)


@pytest.mark.parametrize(
    "vector",
    cast(list[dict[str, object]], _VECTORS["invalid"]),
    ids=lambda item: str(item["name"]),
)
def test_golden_vectors_reject_trust_boundary_and_identifier_drift(
    vector: dict[str, object],
) -> None:
    kind = vector["kind"]
    input_ = cast(dict[str, object], vector["input"])
    with pytest.raises(ValueError):
        if kind == "invocation":
            invocation = _invocation()
            action = cast(dict[str, object], invocation["action"])
            action["arguments"] = input_["arguments"]
            create_adapter_invocation(invocation)
        elif kind == "lifecycle":
            envelope = _lifecycle(cast(str, input_["result"]))
            envelope["locator"] = input_["locator"]
            validate_adapter_lifecycle_envelope(envelope)
        elif kind == "manifest":
            validate_governed_route_manifest(input_)
        else:  # pragma: no cover - fixture integrity guard
            raise AssertionError(f"unknown vector kind: {kind!r}")
