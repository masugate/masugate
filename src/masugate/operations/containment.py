"""Closed containment profile validation for the connector-only worker."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from masugate.errors import ContractError
from masugate.model import JsonValue

CONTAINMENT_CONTRACT_VERSION = "masugate.connector-worker-containment.v1"
_BLOCKED_SURFACES = frozenset(
    {
        "blocked.agent-network",
        "blocked.database-administration-credential",
        "blocked.docker-socket",
        "blocked.gateway-network",
        "blocked.host-root",
        "blocked.http-proxy",
        "blocked.https-proxy",
        "blocked.no-proxy",
    }
)


class ConnectorContainmentError(ContractError):
    """The deployment attempted to weaken the connector-worker boundary."""


def _record(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise ConnectorContainmentError(f"{field} must be an object with string keys")
    return cast(Mapping[str, object], value)


def _exact(record: Mapping[str, object], keys: frozenset[str], field: str) -> None:
    if set(record) != keys:
        raise ConnectorContainmentError(f"{field} has an invalid closed shape")


def validate_connector_worker_containment(value: object) -> dict[str, JsonValue]:
    """Validate the immutable minimum worker isolation policy.

    Per-connector destination ids may be added to the profile, but every other
    property is fixed. This validator mirrors the normative JSON Schema for
    startup and mutation tests without requiring a schema engine in the worker
    image.
    """

    root = _record(value, "connector worker containment")
    _exact(
        root,
        frozenset({"contract_version", "connector_worker"}),
        "connector worker containment",
    )
    if root["contract_version"] != CONTAINMENT_CONTRACT_VERSION:
        raise ConnectorContainmentError("connector worker containment version is unsupported")
    worker = _record(root["connector_worker"], "connector worker containment.worker")
    _exact(
        worker,
        frozenset(
            {
                "run_as_non_root",
                "read_only_root_filesystem",
                "drop_all_capabilities",
                "no_new_privileges",
                "network",
                "secret_mount",
                "environment_allowlist",
                "blocked_surfaces",
                "database_administration_credentials",
            }
        ),
        "connector worker containment.worker",
    )
    for key in (
        "run_as_non_root",
        "read_only_root_filesystem",
        "drop_all_capabilities",
        "no_new_privileges",
    ):
        if worker[key] is not True:
            raise ConnectorContainmentError(f"connector worker containment {key} must be true")
    if worker["database_administration_credentials"] is not False:
        raise ConnectorContainmentError(
            "connector worker containment forbids database administration credentials"
        )
    network = _record(worker["network"], "connector worker containment network")
    _exact(
        network,
        frozenset({"name", "agent_gateway_reachable", "allowed_destinations"}),
        "connector worker containment network",
    )
    destinations = network["allowed_destinations"]
    if (
        network["name"] != "connector-only"
        or network["agent_gateway_reachable"] is not False
        or not isinstance(destinations, list)
        or any(type(item) is not str or not item for item in destinations)
        or len(set(cast(list[str], destinations))) != len(destinations)
    ):
        raise ConnectorContainmentError("connector worker containment network is invalid")
    mount = _record(worker["secret_mount"], "connector worker containment secret mount")
    _exact(
        mount,
        frozenset({"target", "read_only", "allowlisted_files_only"}),
        "connector worker containment secret mount",
    )
    if (
        mount["target"] != "/run/masugate-secrets"
        or mount["read_only"] is not True
        or mount["allowlisted_files_only"] is not True
    ):
        raise ConnectorContainmentError("connector worker containment secret mount is invalid")
    if worker["environment_allowlist"] != ["LANG", "TZ"]:
        raise ConnectorContainmentError("connector worker containment environment is invalid")
    blocked = worker["blocked_surfaces"]
    if (
        not isinstance(blocked, list)
        or any(type(item) is not str for item in blocked)
        or len(set(cast(list[str], blocked))) != len(blocked)
        or not set(cast(list[str], blocked)) >= _BLOCKED_SURFACES
    ):
        raise ConnectorContainmentError(
            "connector worker containment blocked surfaces are incomplete"
        )
    return cast(
        dict[str, JsonValue],
        {"contract_version": root["contract_version"], "connector_worker": dict(worker)},
    )


__all__ = [
    "CONTAINMENT_CONTRACT_VERSION",
    "ConnectorContainmentError",
    "validate_connector_worker_containment",
]
