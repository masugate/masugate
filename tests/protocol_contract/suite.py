"""Implementation-independent Governed Action Protocol contract checks.

Any HTTP implementation can run this suite by supplying a transport and two
environment-specific action cases: one that commits and one that policy-denies.
No server internals are imported.  MCP is a distinct wire surface and therefore
uses the gateway's MCP-level contract tests.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, Protocol, cast

from masugate.model import JsonValue

SCHEMA_DIR = Path(__file__).parents[2] / "protocol" / "schemas"
jsonschema: Any = import_module("jsonschema")


class ContractResponse(Protocol):
    status_code: int

    def json(self) -> Any: ...


class ContractTransport(Protocol):
    async def request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, JsonValue] | None = None,
        headers: dict[str, str] | None = None,
    ) -> ContractResponse: ...


@dataclass(frozen=True)
class ContractCases:
    bearer_token: str
    committed_action: dict[str, JsonValue]
    denied_action: dict[str, JsonValue]


def _validator(name: str) -> Any:
    schema = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
    return jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )


def _body(response: ContractResponse) -> dict[str, JsonValue]:
    value = response.json()
    if not isinstance(value, dict):
        raise AssertionError(f"protocol response is not an object: {value!r}")
    return cast(dict[str, JsonValue], value)


async def run_contract_suite(
    transport: ContractTransport,
    cases: ContractCases,
) -> dict[str, dict[str, JsonValue]]:
    """Run schema, retry, no-detached-token, audit, and error contracts."""

    auth = {"Authorization": f"Bearer {cases.bearer_token}"}
    action_schema = _validator("action-response.schema.json")
    audit_schema = _validator("audit.schema.json")
    pending_schema = _validator("pending-list.schema.json")
    error_schema = _validator("error.schema.json")

    committed_response = await transport.request(
        "POST", "/v1/actions", json=cases.committed_action, headers=auth
    )
    assert committed_response.status_code == 200
    committed = _body(committed_response)
    action_schema.validate(committed)
    assert committed["status"] == "committed"

    retry_response = await transport.request(
        "POST", "/v1/actions", json=cases.committed_action, headers=auth
    )
    assert retry_response.status_code == 200
    retry = _body(retry_response)
    action_schema.validate(retry)
    assert retry["operation_id"] == committed["operation_id"]
    assert retry["replayed"] is True

    denied_response = await transport.request(
        "POST", "/v1/actions", json=cases.denied_action, headers=auth
    )
    assert denied_response.status_code == 200
    denied = _body(denied_response)
    action_schema.validate(denied)
    assert denied["status"] == "denied"

    # No detached authorization token: this semantic assertion complements
    # the action schema's structural status/effect oneOf.
    for result in (committed, retry, denied):
        decision = cast(dict[str, JsonValue], result["decision"])
        if decision["effect"] == "allow":
            assert result["status"] == "committed"

    for result in (committed, denied):
        audit_ref = cast(str, result["audit_ref"])
        audit_response = await transport.request("GET", audit_ref, headers=auth)
        assert audit_response.status_code == 200
        audit_schema.validate(_body(audit_response))

    pending_response = await transport.request("GET", "/v1/pending", headers=auth)
    assert pending_response.status_code == 200
    pending_schema.validate(_body(pending_response))

    forged = dict(cases.committed_action)
    forged["timestamp"] = "2000-01-01T00:00:00Z"
    invalid_response = await transport.request("POST", "/v1/actions", json=forged, headers=auth)
    assert invalid_response.status_code == 422
    invalid = _body(invalid_response)
    error_schema.validate(invalid)
    assert cast(dict[str, JsonValue], invalid["error"])["code"] == "invalid_request"

    unauthenticated_response = await transport.request(
        "POST", "/v1/actions", json=cases.committed_action
    )
    assert unauthenticated_response.status_code == 401
    unauthenticated = _body(unauthenticated_response)
    error_schema.validate(unauthenticated)
    assert cast(dict[str, JsonValue], unauthenticated["error"])["code"] == "unauthorized"

    return {
        "committed": committed,
        "retry": retry,
        "denied": denied,
        "invalid": invalid,
        "unauthenticated": unauthenticated,
    }
