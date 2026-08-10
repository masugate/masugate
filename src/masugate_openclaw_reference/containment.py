"""Deployment-owned reference containment containment profile and executable checks.

This module intentionally contains OpenClaw and reference-deployment names. It
is not imported by ``masugate`` or the reusable ``@masugate/openclaw`` adapter.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar, Literal, cast

ContainmentDisposition = Literal[
    "governed", "safely_available", "intentionally_blocked", "unsupported_unclaimed"
]
_VALID_DISPOSITIONS: dict[str, ContainmentDisposition] = {
    "governed": "governed",
    "safely_available": "safely_available",
    "intentionally_blocked": "intentionally_blocked",
    "unsupported_unclaimed": "unsupported_unclaimed",
}

_SCHEMA_VERSION = "masugate.openclaw-reference.containment/v1"
_PROFILE_VERSION = "masugate.openclaw-reference.profile/v1"
_REQUIRED_SURFACES = frozenset(
    {
        "governed.spend.purchase",
        "safe.read",
        "safe.search",
        "safe.browse",
        "safe.draft",
        "safe.local-compute",
        "safe.network",
        "blocked.native-consequential-tools",
        "blocked.shell",
        "blocked.child-process",
        "blocked.browser-direct",
        "blocked.purchase-api-direct",
        "blocked.masugated-api-direct",
        "blocked.provider-credentials",
        "blocked.governance-database",
        "blocked.protected-mounts",
        "blocked.agent-mcp-extension",
        "blocked.admin-configuration",
        "unsupported.arbitrary-host-tools",
    }
)
_SAFE_CAPABILITIES = frozenset({"read", "search", "browse", "draft", "local-compute", "network"})
_PROTECTED_ENVIRONMENT = frozenset(
    {
        "MASUGATE_BUYER_ALPHA_TOKEN",
        "MASUGATE_POSTGRES_DSN",
        "REFERENCE_PURCHASE_SERVICE_TOKEN",
    }
)
_AGENT_ENVIRONMENT = frozenset({"LANG", "TZ"})
_GATEWAY_CONTROL_ENVIRONMENT = frozenset({"OPENCLAW_GATEWAY_TOKEN"})
_GATEWAY_ACTION_CREDENTIALS = frozenset({"MASUGATE_BUYER_ALPHA_TOKEN"})
_AGENT_NETWORK = "masugate-openclaw-reference-agent"
_SAFE_CONTENT_NETWORK = "masugate-openclaw-reference-safe-content"
_GOVERNANCE_NETWORK = "masugate-openclaw-reference-governance"
_PROVIDER_NETWORK = "masugate-openclaw-reference-provider"
_SAFE_CONTENT_TOOL = "masugate_reference_content"
_OPENCLAW_ALLOWED_TOOLS = frozenset({"read", "masugate_governed_action", _SAFE_CONTENT_TOOL})
_EXPECTED_MASUGATE_PLUGIN_CONFIG: dict[str, object] = {
    "masugatedBaseUrl": "http://masugated:8000",
    "agents": {"buyer-alpha": "MASUGATE_BUYER_ALPHA_TOKEN"},
    "routes": {
        "purchase": {
            "action": "spend.purchase",
            "arguments": {
                "amount_cents": "integer",
                "merchant_id": "string",
                "request_ref": "string",
            },
            "owner": {
                "providerId": "masugate.spend.reference",
                "position": "protected-external",
                "connectorId": "reference-purchase-v1",
            },
        }
    },
}
_EXPECTED_REFERENCE_CONTENT_CONFIG: dict[str, object] = {
    "safeContentBaseUrl": "http://safe-content:8080",
    "documents": {
        "procurement": "/reference/procurement",
        "travel": "/reference/travel",
    },
}
_EXPECTED_LOOPBACK_MODEL_CONFIG: dict[str, object] = {
    "mode": "merge",
    "providers": {
        "reference_containment-full": {
            "baseUrl": "http://127.0.0.1:18790/v1",
            "apiKey": "reference-containment-loopback-model",
            "api": "openai-completions",
            "models": [
                {
                    "id": "reference_containment-full",
                    "name": "reference containment deterministic containment fixture",
                    "reasoning": False,
                    "input": ["text"],
                    "cost": {
                        "input": 0,
                        "output": 0,
                        "cacheRead": 0,
                        "cacheWrite": 0,
                    },
                    "contextWindow": 131072,
                    "maxTokens": 4096,
                    "compat": {"requiresStringContent": True},
                }
            ],
        },
        "reference_containment-narrow": {
            "baseUrl": "http://127.0.0.1:18791/v1",
            "apiKey": "reference-containment-loopback-model",
            "api": "openai-completions",
            "models": [
                {
                    "id": "reference_containment-narrow",
                    "name": "reference containment narrow containment fixture",
                    "reasoning": False,
                    "input": ["text"],
                    "cost": {
                        "input": 0,
                        "output": 0,
                        "cacheRead": 0,
                        "cacheWrite": 0,
                    },
                    "contextWindow": 131072,
                    "maxTokens": 4096,
                    "compat": {"requiresStringContent": True},
                }
            ],
        },
    },
}
_EXPECTED_NARROW_AGENT_CONFIG: dict[str, object] = {
    "id": "buyer-narrow",
    "model": {"primary": "reference_containment-narrow/reference_containment-narrow"},
    "tools": {"sandbox": {"tools": {"allow": ["read"], "deny": ["image"]}}},
}
_COMPOSE_GATEWAY_ENVIRONMENT = {
    "OPENCLAW_GATEWAY_TOKEN": "reference-containment-local-gateway-token",
    "MASUGATE_AGENT_SANDBOX_IMAGE": (
        "masugate-openclaw-reference-agent-sandbox:reference_containment"
    ),
    "MASUGATE_BUYER_ALPHA_TOKEN": "reference-containment-reference-token",
    "MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT": (
        "${MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT:?set by the live containment oracle}"
    ),
}
_COMPOSE_CONNECTOR_ENVIRONMENT = {
    "REFERENCE_PURCHASE_SERVICE_TOKEN": "reference-containment-connector-token"
}
_COMPOSE_FORBIDDEN_MOUNT_SECTIONS = frozenset(
    {"configs", "env_file", "secrets", "tmpfs", "volumes_from"}
)


class ContainmentProfileError(ValueError):
    """The deployed profile does not support its declared mediation claim."""


@dataclass(frozen=True, slots=True)
class SurfaceDisposition:
    """One agent-reachable (or explicitly unreachable) reference surface."""

    surface_id: str
    resource: str
    disposition: ContainmentDisposition
    detail: dict[str, object]


@dataclass(frozen=True, slots=True)
class ReferenceContainment:
    """Validated manifest/profile pair for the pinned reference deployment."""

    manifest_version: str
    profile_version: str
    surfaces: tuple[SurfaceDisposition, ...]
    agent_environment: frozenset[str]
    agent_destinations: frozenset[str]
    gateway_environment: frozenset[str]
    gateway_destinations: frozenset[str]

    def surface(self, surface_id: str) -> SurfaceDisposition:
        for surface in self.surfaces:
            if surface.surface_id == surface_id:
                return surface
        raise ContainmentProfileError(f"unknown containment surface: {surface_id}")

    def require_safe(self, capability: str) -> SurfaceDisposition:
        surface = self.surface(f"safe.{capability}")
        if surface.disposition != "safely_available":
            raise ContainmentProfileError(f"safe capability {capability} is not available")
        return surface

    def require_blocked(self, surface_id: str) -> None:
        surface = self.surface(surface_id)
        if surface.disposition != "intentionally_blocked":
            raise ContainmentProfileError(f"{surface_id} is not intentionally blocked")


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def containment_directory() -> Path:
    """Return the deployment-owned profile directory in this source tree."""

    return _root() / "integrations" / "openclaw-reference" / "containment"


def _load_json(path: Path) -> dict[str, object]:
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContainmentProfileError(f"cannot load containment artifact {path}") from exc
    if not isinstance(loaded, dict):
        raise ContainmentProfileError(f"containment artifact {path} must be a JSON object")
    return cast(dict[str, object], loaded)


def _object(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ContainmentProfileError(f"{context} must be an object")
    return cast(dict[str, object], value)


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContainmentProfileError(f"{context} must be a non-empty string")
    return value


def _strings(value: object, context: str) -> frozenset[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ContainmentProfileError(f"{context} must be an array of non-empty strings")
    values = frozenset(cast(list[str], value))
    if len(values) != len(value):
        raise ContainmentProfileError(f"{context} must not contain duplicates")
    return values


def _exact_keys(value: dict[str, object], expected: frozenset[str], context: str) -> None:
    actual = frozenset(value)
    if actual != expected:
        raise ContainmentProfileError(
            f"{context} keys must be {sorted(expected)}, got {sorted(actual)}"
        )


def _parse_surface(value: object, index: int) -> SurfaceDisposition:
    context = f"manifest.surfaces[{index}]"
    raw = _object(value, context)
    _exact_keys(raw, frozenset({"id", "resource", "disposition", "detail"}), context)
    surface_id = _string(raw["id"], f"{context}.id")
    resource = _string(raw["resource"], f"{context}.resource")
    raw_disposition = _string(raw["disposition"], f"{context}.disposition")
    typed_disposition = _VALID_DISPOSITIONS.get(raw_disposition)
    if typed_disposition is None:
        raise ContainmentProfileError(f"{context}.disposition is invalid")
    detail = _object(raw["detail"], f"{context}.detail")
    if typed_disposition == "governed":
        _exact_keys(detail, frozenset({"tool", "route", "action"}), f"{context}.detail")
        if (
            _string(detail["tool"], f"{context}.detail.tool") != "masugate_governed_action"
            or _string(detail["route"], f"{context}.detail.route") != "purchase"
            or _string(detail["action"], f"{context}.detail.action") != "spend.purchase"
        ):
            raise ContainmentProfileError(
                f"{context} does not name the one declared MasuGate path"
            )
    elif typed_disposition == "safely_available":
        _exact_keys(detail, frozenset({"capability", "target"}), f"{context}.detail")
        capability = _string(detail["capability"], f"{context}.detail.capability")
        if capability not in _SAFE_CAPABILITIES:
            raise ContainmentProfileError(f"{context} names an undeclared safe capability")
        _string(detail["target"], f"{context}.detail.target")
    else:
        _exact_keys(detail, frozenset({"reason", "alternative"}), f"{context}.detail")
        _string(detail["reason"], f"{context}.detail.reason")
        _string(detail["alternative"], f"{context}.detail.alternative")
    return SurfaceDisposition(surface_id, resource, typed_disposition, detail)


def _parse_manifest(path: Path) -> tuple[str, tuple[SurfaceDisposition, ...]]:
    raw = _load_json(path)
    _exact_keys(
        raw,
        frozenset(
            {"schema_version", "profile_id", "pinned_openclaw", "protected_resources", "surfaces"}
        ),
        "manifest",
    )
    if _string(raw["schema_version"], "manifest.schema_version") != _SCHEMA_VERSION:
        raise ContainmentProfileError("manifest has an unsupported schema version")
    _string(raw["profile_id"], "manifest.profile_id")
    pinned = _object(raw["pinned_openclaw"], "manifest.pinned_openclaw")
    _exact_keys(pinned, frozenset({"version", "node_runtime"}), "manifest.pinned_openclaw")
    if _string(pinned["version"], "manifest.pinned_openclaw.version") != "2026.7.1":
        raise ContainmentProfileError("manifest must name the pinned OpenClaw version")
    if _string(pinned["node_runtime"], "manifest.pinned_openclaw.node_runtime") != "24.16.0":
        raise ContainmentProfileError("manifest must name the pinned Node runtime")
    protected = _strings(raw["protected_resources"], "manifest.protected_resources")
    if protected != {
        "reference-purchase-api",
        "reference-purchase-credential",
        "masugate-action-api",
        "masugate-governance-postgres",
    }:
        raise ContainmentProfileError("manifest protected-resource inventory is incomplete")
    raw_surfaces = raw["surfaces"]
    if not isinstance(raw_surfaces, list):
        raise ContainmentProfileError("manifest.surfaces must be an array")
    surfaces = tuple(_parse_surface(item, index) for index, item in enumerate(raw_surfaces))
    ids = frozenset(surface.surface_id for surface in surfaces)
    if len(ids) != len(surfaces):
        raise ContainmentProfileError("manifest surfaces must have unique ids")
    if ids != _REQUIRED_SURFACES:
        raise ContainmentProfileError(
            "manifest does not classify the complete pinned-profile universe"
        )
    return _SCHEMA_VERSION, surfaces


def _parse_profile(
    path: Path,
) -> tuple[str, frozenset[str], frozenset[str], frozenset[str], frozenset[str]]:
    raw = _load_json(path)
    _exact_keys(
        raw, frozenset({"schema_version", "agent_sandbox", "gateway", "connector"}), "profile"
    )
    if _string(raw["schema_version"], "profile.schema_version") != _PROFILE_VERSION:
        raise ContainmentProfileError("profile has an unsupported schema version")
    sandbox = _object(raw["agent_sandbox"], "profile.agent_sandbox")
    _exact_keys(
        sandbox,
        frozenset(
            {
                "enabled",
                "read_only_root",
                "cap_drop",
                "no_new_privileges",
                "network",
                "mounts",
                "environment_allowlist",
                "tool_allowlist",
                "blocked_surfaces",
            }
        ),
        "profile.agent_sandbox",
    )
    if sandbox["enabled"] is not True or sandbox["read_only_root"] is not True:
        raise ContainmentProfileError("agent sandbox must be enabled with a read-only root")
    if sandbox["no_new_privileges"] is not True or _strings(
        sandbox["cap_drop"], "profile.agent_sandbox.cap_drop"
    ) != {"ALL"}:
        raise ContainmentProfileError(
            "agent sandbox must drop every capability and forbid privilege escalation"
        )
    network = _object(sandbox["network"], "profile.agent_sandbox.network")
    _exact_keys(
        network, frozenset({"default", "allowed_destinations"}), "profile.agent_sandbox.network"
    )
    if network["default"] != "deny":
        raise ContainmentProfileError("agent network must deny by default")
    destinations = _strings(
        network["allowed_destinations"], "profile.agent_sandbox.network.allowed_destinations"
    )
    if destinations:
        raise ContainmentProfileError("agent sandbox must have no direct network destination")
    mounts = sandbox["mounts"]
    if mounts != [
        {
            "source": "openclaw-managed-session-copy",
            "target": "/workspace",
            "read_only": True,
        }
    ]:
        raise ContainmentProfileError(
            "agent sandbox may expose only the read-only OpenClaw-managed session copy"
        )
    agent_environment = _strings(
        sandbox["environment_allowlist"], "profile.agent_sandbox.environment_allowlist"
    )
    if agent_environment != _AGENT_ENVIRONMENT:
        raise ContainmentProfileError(
            "agent sandbox environment is not the declared safe allowlist"
        )
    if _PROTECTED_ENVIRONMENT & agent_environment:  # Defensive guard for future allowlist edits.
        raise ContainmentProfileError(
            "agent sandbox exposes a protected credential or database setting"
        )
    if (
        _strings(sandbox["tool_allowlist"], "profile.agent_sandbox.tool_allowlist")
        != _OPENCLAW_ALLOWED_TOOLS
    ):
        raise ContainmentProfileError(
            "agent sandbox tool allowlist is not the bounded reference set"
        )
    blocked = _strings(sandbox["blocked_surfaces"], "profile.agent_sandbox.blocked_surfaces")
    expected_blocked = frozenset(
        surface for surface in _REQUIRED_SURFACES if surface.startswith("blocked.")
    )
    if blocked != expected_blocked:
        raise ContainmentProfileError("agent sandbox blocklist does not match the manifest")

    gateway = _object(raw["gateway"], "profile.gateway")
    _exact_keys(
        gateway,
        frozenset({"tool_allowlist", "environment", "host_control_mounts", "allowed_destinations"}),
        "profile.gateway",
    )
    if _strings(gateway["tool_allowlist"], "profile.gateway.tool_allowlist") != {
        "masugate_governed_action",
        "masugate_reference_content",
    }:
        raise ContainmentProfileError("gateway tool allowlist is not the bounded reference set")
    gateway_environment = _strings(gateway["environment"], "profile.gateway.environment")
    if gateway_environment != _GATEWAY_CONTROL_ENVIRONMENT | _GATEWAY_ACTION_CREDENTIALS:
        raise ContainmentProfileError(
            "gateway must hold only the control-plane authentication token and per-agent "
            "MasuGate action credential"
        )
    if _strings(gateway["host_control_mounts"], "profile.gateway.host_control_mounts") != {
        "docker-daemon-socket"
    }:
        raise ContainmentProfileError(
            "gateway must declare its sole trusted sandbox-orchestration mount"
        )
    gateway_destinations = _strings(
        gateway["allowed_destinations"], "profile.gateway.allowed_destinations"
    )
    if gateway_destinations != {"masugated:8000", "safe-content:8080"}:
        raise ContainmentProfileError(
            "gateway may reach only the MasuGate action API and the bounded safe-content service"
        )

    connector = _object(raw["connector"], "profile.connector")
    _exact_keys(connector, frozenset({"environment", "allowed_destinations"}), "profile.connector")
    if _strings(connector["environment"], "profile.connector.environment") != {
        "REFERENCE_PURCHASE_SERVICE_TOKEN"
    }:
        raise ContainmentProfileError("connector must hold only its server-to-server credential")
    if _strings(connector["allowed_destinations"], "profile.connector.allowed_destinations") != {
        "reference-purchase:8081"
    }:
        raise ContainmentProfileError("connector must reach only the reference purchase service")
    return (
        _PROFILE_VERSION,
        agent_environment,
        destinations,
        gateway_environment,
        gateway_destinations,
    )


def _verify_plugin_binding(containment: ReferenceContainment, plugin_config_path: Path) -> None:
    plugin = _load_json(plugin_config_path)
    _exact_keys(
        plugin,
        frozenset({"masugatedBaseUrl", "agents", "routes"}),
        "reference MasuGate plugin config",
    )
    if plugin != _EXPECTED_MASUGATE_PLUGIN_CONFIG:
        raise ContainmentProfileError(
            "reference MasuGate plugin config must exactly bind the one agent, endpoint, and "
            "purchase route"
        )
    agents = _object(plugin["agents"], "plugin config.agents")
    if frozenset(agents.values()) != (
        containment.gateway_environment - _GATEWAY_CONTROL_ENVIRONMENT
    ):
        raise ContainmentProfileError(
            "gateway credential inventory does not match plugin agent bindings"
        )


def _verify_reference_content_binding(value: object) -> None:
    content_config = _object(value, "OpenClaw reference-content plugin config")
    _exact_keys(
        content_config,
        frozenset({"safeContentBaseUrl", "documents"}),
        "OpenClaw reference-content plugin config",
    )
    if content_config != _EXPECTED_REFERENCE_CONTENT_CONFIG:
        raise ContainmentProfileError(
            "reference-content plugin must exactly bind its bounded service and documents"
        )


def _verify_openclaw_sandbox(
    containment: ReferenceContainment,
    openclaw_config_path: Path,
    plugin_config_path: Path,
) -> None:
    """Verify the actual pinned-host configuration fragment, not only prose."""

    config = _load_json(openclaw_config_path)
    _exact_keys(
        config,
        frozenset({"agents", "gateway", "models", "plugins", "tools"}),
        "OpenClaw sandbox config",
    )
    agents = _object(config["agents"], "OpenClaw sandbox config.agents")
    _exact_keys(agents, frozenset({"defaults", "list"}), "OpenClaw sandbox config.agents")
    defaults = _object(agents["defaults"], "OpenClaw sandbox config.agents.defaults")
    _exact_keys(
        defaults,
        frozenset({"model", "sandbox"}),
        "OpenClaw sandbox config.agents.defaults",
    )
    if defaults["model"] != {"primary": "reference_containment-full/reference_containment-full"}:
        raise ContainmentProfileError("OpenClaw reference agent must use its loopback test model")
    if agents["list"] != [
        {"id": "buyer-alpha", "default": True},
        _EXPECTED_NARROW_AGENT_CONFIG,
    ]:
        raise ContainmentProfileError(
            "OpenClaw reference agents must retain the narrow-policy regression"
        )
    if config["gateway"] != {"http": {"endpoints": {"chatCompletions": {"enabled": True}}}}:
        raise ContainmentProfileError("OpenClaw Gateway session endpoint is not enabled")
    if config["models"] != _EXPECTED_LOOPBACK_MODEL_CONFIG:
        raise ContainmentProfileError("OpenClaw Gateway model fixture is not loopback-bound")
    sandbox = _object(defaults["sandbox"], "OpenClaw sandbox config.agents.defaults.sandbox")
    _exact_keys(
        sandbox,
        frozenset({"mode", "scope", "backend", "workspaceAccess", "docker"}),
        "OpenClaw sandbox config.agents.defaults.sandbox",
    )
    if (
        sandbox["mode"] != "all"
        or sandbox["scope"] != "session"
        or sandbox["backend"] != "docker"
        or sandbox["workspaceAccess"] != "none"
    ):
        raise ContainmentProfileError("OpenClaw sandbox must confine every session")
    docker = _object(sandbox["docker"], "OpenClaw sandbox config.agents.defaults.sandbox.docker")
    _exact_keys(
        docker,
        frozenset(
            {"image", "containerPrefix", "network", "readOnlyRoot", "capDrop", "tmpfs", "env"}
        ),
        "OpenClaw sandbox config.agents.defaults.sandbox.docker",
    )
    if (
        docker["image"] != "masugate-openclaw-reference-agent-sandbox:reference_containment"
        or docker["containerPrefix"] != "masugate-openclaw-reference-agent-"
        or docker["network"] != _AGENT_NETWORK
        or docker["readOnlyRoot"] is not True
        or _strings(docker["capDrop"], "OpenClaw sandbox config.docker.capDrop") != {"ALL"}
        or _strings(docker["tmpfs"], "OpenClaw sandbox config.docker.tmpfs") != {"/tmp"}
    ):
        raise ContainmentProfileError("OpenClaw Docker sandbox is not fail-closed")
    docker_environment = _object(docker["env"], "OpenClaw sandbox config.docker.env")
    if frozenset(docker_environment) != _AGENT_ENVIRONMENT or any(
        not isinstance(value, str) or not value for value in docker_environment.values()
    ):
        raise ContainmentProfileError("OpenClaw Docker sandbox exposes an undeclared environment")

    plugins = _object(config["plugins"], "OpenClaw sandbox config.plugins")
    _exact_keys(plugins, frozenset({"allow", "entries"}), "OpenClaw sandbox config.plugins")
    if _strings(plugins["allow"], "OpenClaw sandbox config.plugins.allow") != {
        "masugate",
        "masugate-reference-content",
    }:
        raise ContainmentProfileError(
            "OpenClaw profile must allow only the MasuGate and bounded safe-content plugins"
        )
    entries = _object(plugins["entries"], "OpenClaw sandbox config.plugins.entries")
    _exact_keys(
        entries,
        frozenset({"masugate", "masugate-reference-content"}),
        "OpenClaw sandbox config.plugins.entries",
    )
    masugate_plugin = _object(entries["masugate"], "OpenClaw sandbox config.plugins.entries.pvl")
    _exact_keys(
        masugate_plugin,
        frozenset({"enabled", "config"}),
        "OpenClaw sandbox config.plugins.entries.pvl",
    )
    if masugate_plugin["enabled"] is not True:
        raise ContainmentProfileError("OpenClaw MasuGate plugin must be enabled")
    if masugate_plugin["config"] != _load_json(plugin_config_path):
        raise ContainmentProfileError(
            "OpenClaw sandbox plugin binding drifts from reference config"
        )
    if masugate_plugin["config"] != _EXPECTED_MASUGATE_PLUGIN_CONFIG:
        raise ContainmentProfileError(
            "OpenClaw MasuGate plugin binding is not the exact reference route"
        )
    content_plugin = _object(
        entries["masugate-reference-content"],
        "OpenClaw sandbox config.plugins.entries.masugate-reference-content",
    )
    _exact_keys(
        content_plugin,
        frozenset({"enabled", "config"}),
        "OpenClaw sandbox config.plugins.entries.masugate-reference-content",
    )
    if content_plugin["enabled"] is not True:
        raise ContainmentProfileError("OpenClaw bounded safe-content plugin must be enabled")
    _verify_reference_content_binding(content_plugin["config"])

    tools = _object(config["tools"], "OpenClaw sandbox config.tools")
    _exact_keys(
        tools,
        frozenset({"allow", "elevated", "sandbox"}),
        "OpenClaw sandbox config.tools",
    )
    if _strings(tools["allow"], "OpenClaw sandbox config.tools.allow") != _OPENCLAW_ALLOWED_TOOLS:
        raise ContainmentProfileError("OpenClaw profile exposes an undeclared native tool")
    elevated = _object(tools["elevated"], "OpenClaw sandbox config.tools.elevated")
    if elevated != {"enabled": False}:
        raise ContainmentProfileError("OpenClaw profile must disable elevated execution")
    sandbox_tools = _object(tools["sandbox"], "OpenClaw sandbox config.tools.sandbox")
    _exact_keys(sandbox_tools, frozenset({"tools"}), "OpenClaw sandbox config.tools.sandbox")
    sandbox_policy = _object(sandbox_tools["tools"], "OpenClaw sandbox config.tools.sandbox.tools")
    _exact_keys(
        sandbox_policy,
        frozenset({"allow", "deny"}),
        "OpenClaw sandbox config.tools.sandbox.tools",
    )
    if (
        _strings(sandbox_policy["allow"], "OpenClaw sandbox config.tools.sandbox.tools.allow")
        != _OPENCLAW_ALLOWED_TOOLS
    ):
        raise ContainmentProfileError("OpenClaw sandbox tool policy is not fail-closed")
    if _strings(sandbox_policy["deny"], "OpenClaw sandbox config.tools.sandbox.tools.deny") != {
        "image"
    }:
        raise ContainmentProfileError("OpenClaw sandbox must deny the built-in image tool")
    if containment.agent_destinations:
        raise ContainmentProfileError("containment model and OpenClaw network policy disagree")


def _verify_network_topology(containment: ReferenceContainment, path: Path) -> None:
    """Ensure the agent network contains no protected deployment service."""

    topology = _load_json(path)
    _exact_keys(
        topology,
        frozenset({"schema_version", "agent_network", "networks"}),
        "network topology",
    )
    if topology["schema_version"] != "masugate.openclaw-reference.network-topology/v1":
        raise ContainmentProfileError("network topology has an unsupported schema version")
    if topology["agent_network"] != _AGENT_NETWORK:
        raise ContainmentProfileError("network topology assigns the agent to the wrong network")
    networks = _object(topology["networks"], "network topology.networks")
    _exact_keys(
        networks,
        frozenset({_AGENT_NETWORK, _SAFE_CONTENT_NETWORK, _GOVERNANCE_NETWORK, _PROVIDER_NETWORK}),
        "network topology.networks",
    )
    agent_network = _object(
        networks[_AGENT_NETWORK],
        f"network topology.networks.{_AGENT_NETWORK}",
    )
    safe_network = _object(
        networks[_SAFE_CONTENT_NETWORK],
        f"network topology.networks.{_SAFE_CONTENT_NETWORK}",
    )
    governance_network = _object(
        networks[_GOVERNANCE_NETWORK],
        "network topology.networks.masugate-openclaw-reference-governance",
    )
    provider_network = _object(
        networks[_PROVIDER_NETWORK],
        "network topology.networks.masugate-openclaw-reference-provider",
    )
    _exact_keys(
        agent_network,
        frozenset({"internal", "members"}),
        "network topology agent network",
    )
    _exact_keys(
        safe_network,
        frozenset({"internal", "members"}),
        "network topology safe network",
    )
    _exact_keys(
        governance_network,
        frozenset({"internal", "members"}),
        "network topology governance network",
    )
    _exact_keys(
        provider_network,
        frozenset({"internal", "members"}),
        "network topology provider network",
    )
    if agent_network["internal"] is not True or _strings(
        agent_network["members"], "network topology agent network members"
    ) != {"openclaw-session-sandbox"}:
        raise ContainmentProfileError("agent network exposes a service or an egress path")
    if safe_network["internal"] is not True or _strings(
        safe_network["members"], "network topology safe network members"
    ) != {"openclaw-gateway", "safe-content"}:
        raise ContainmentProfileError("safe network exposes a non-safe service")
    if governance_network["internal"] is not True or _strings(
        governance_network["members"], "network topology governance network members"
    ) != {
        "openclaw-gateway",
        "masugate-governance-postgres",
        "masugated",
    }:
        raise ContainmentProfileError("governance network inventory is incomplete")
    if provider_network["internal"] is not True or _strings(
        provider_network["members"], "network topology provider network members"
    ) != {"reference-purchase", "reference-purchase-connector"}:
        raise ContainmentProfileError(
            "provider network must contain only connector and purchase service"
        )
    if containment.agent_destinations:
        raise ContainmentProfileError("network topology and containment profile disagree")


def _compose_service_block(compose: str, service: str) -> str:
    """Extract one service from the intentionally small, checked-in Compose form.

    This is deliberately a strict parser for this profile's subset rather than
    a permissive YAML parser: a different indentation/form requires updating
    the deployment verifier alongside the Compose topology.
    """

    services_match = re.search(r"^services:\n(?P<body>.*?)(?=^networks:\n)", compose, re.M | re.S)
    if services_match is None:
        raise ContainmentProfileError("compose must contain a services mapping")
    services = services_match.group("body")
    match = re.search(
        rf"^  {re.escape(service)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        services,
        re.M | re.S,
    )
    if match is None:
        raise ContainmentProfileError(f"compose is missing service {service}")
    return match.group("body")


def _reject_noncanonical_compose_syntax(compose: str) -> None:
    """Admit only the checked-in, non-indirect YAML subset for this profile.

    This verifier deliberately does *not* implement a permissive YAML loader.
    A permissive loader would have to resolve anchors, aliases, tags, and
    explicit mapping keys before the exact service checks below could reason
    about the resulting Compose model.  The reference topology needs none of
    those forms, so its security boundary is closed by rejecting every such
    alternate representation before the small parser examines service blocks.

    In particular, this catches the legal forms ``? <<`` / ``: *anchor`` and
    ``!!merge <<: *anchor`` as well as quoted and whitespace-separated keys.
    The latter two matter because they can spell a forbidden property such as
    ``env_file`` or ``tmpfs`` while bypassing a raw ``name:`` regular expression.
    """

    for line_number, raw_line in enumerate(compose.splitlines(), start=1):
        line = raw_line.lstrip(" \t")
        if not line or line.startswith("#"):
            continue
        if line.startswith(("?", ":", "---", "...", "%")):
            raise ContainmentProfileError(
                "compose YAML alternate mapping syntax is forbidden " f"(line {line_number})"
            )
        if re.match(r"(?:['\"][^'\"]+['\"]|[A-Za-z0-9_-]+[ \t]+):", line):
            raise ContainmentProfileError(
                "compose YAML noncanonical keys are forbidden " f"(line {line_number})"
            )

        # Anchors, aliases, tags, and merge keys can materialize properties
        # which do not appear in the direct service text.  The checked-in
        # profile has none of these token forms.  Match tokens, rather than
        # incidental punctuation in command strings or ``${VAR:?message}``.
        if (
            "<<" in line
            or re.search(r"(?<![A-Za-z0-9_.-])[&*][A-Za-z_][A-Za-z0-9_-]*", line)
            or re.search(r"(?<![A-Za-z0-9_.-])!!?[A-Za-z_][A-Za-z0-9_.-]*", line)
        ):
            raise ContainmentProfileError(
                "compose YAML indirections and merge keys are forbidden " f"(line {line_number})"
            )


def _compose_mapping(block: str, section: str, context: str) -> dict[str, str]:
    match = re.search(
        rf"^    {re.escape(section)}:\n(?P<body>(?:^      .*\n?)*)",
        block,
        re.M,
    )
    if match is None:
        raise ContainmentProfileError(f"{context} is missing {section}")
    result: dict[str, str] = {}
    for line in match.group("body").splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        item = re.fullmatch(r"      ([A-Za-z0-9_]+): (.+)", line)
        if item is None or item.group(1) in result:
            raise ContainmentProfileError(f"{context}.{section} has an unsupported Compose shape")
        result[item.group(1)] = item.group(2)
    return result


def _compose_list(block: str, section: str, context: str) -> list[str]:
    match = re.search(
        rf"^    {re.escape(section)}:\n(?P<body>(?:^      .*\n?)*)",
        block,
        re.M,
    )
    if match is None:
        return []
    result: list[str] = []
    for line in match.group("body").splitlines():
        item = re.fullmatch(r"      - (.+)", line)
        if item is None:
            raise ContainmentProfileError(f"{context}.{section} has an unsupported Compose shape")
        result.append(item.group(1))
    return result


def _reject_compose_mount_indirections(block: str, context: str) -> None:
    """Reject service forms that can add mounts or inject credentials indirectly.

    The reference deployment deliberately has only the two explicit Gateway
    binds and no connector mounts.  Compose ``secrets``, ``configs``,
    ``volumes_from`` and related forms are not semantically equivalent to the
    simple list grammar checked below, so accepting them would make the
    claimed exact boundary depend on an incomplete parser.
    """

    match = re.search(
        r"^    (?P<section>configs|env_file|secrets|tmpfs|volumes_from):",
        block,
        re.M,
    )
    if match is not None:
        section = match.group("section")
        if section in _COMPOSE_FORBIDDEN_MOUNT_SECTIONS:
            raise ContainmentProfileError(
                f"compose {context} forbids indirect mount or credential section {section}"
            )


def _compose_direct_sections(
    block: str,
    context: str,
    allowed: frozenset[str],
) -> None:
    """Reject undeclared direct service properties in the closed Compose form."""

    for line in block.splitlines():
        if not line.startswith("    ") or line.startswith("     "):
            continue
        item = re.fullmatch(r"    ([A-Za-z0-9_-]+):(?: .*)?", line)
        if item is None or item.group(1) not in allowed:
            raise ContainmentProfileError(
                f"compose {context} has an undeclared or noncanonical service property"
            )


def _compose_networks(compose: str) -> dict[str, dict[str, str]]:
    match = re.search(r"^networks:\n(?P<body>.*)\Z", compose, re.M | re.S)
    if match is None:
        raise ContainmentProfileError("compose is missing its network declarations")
    networks = match.group("body")
    result: dict[str, dict[str, str]] = {}
    for entry in re.finditer(
        r"^  (?P<name>[A-Za-z0-9_-]+):\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
        networks,
        re.M | re.S,
    ):
        name = entry.group("name")
        properties: dict[str, str] = {}
        for line in entry.group("body").splitlines():
            item = re.fullmatch(r"    ([A-Za-z0-9_-]+): (.+)", line)
            if item is None or item.group(1) in properties:
                raise ContainmentProfileError("compose network has an unsupported shape")
            properties[item.group(1)] = item.group(2)
        result[name] = properties
    return result


def _verify_compose(containment: ReferenceContainment, path: Path) -> None:
    """Bind the profile's credential and routing claim to executable Compose."""

    try:
        compose = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ContainmentProfileError(f"cannot load containment compose file {path}") from exc
    _reject_noncanonical_compose_syntax(compose)
    gateway = _compose_service_block(compose, "openclaw-gateway")
    connector = _compose_service_block(compose, "reference-purchase-connector")
    purchase = _compose_service_block(compose, "reference-purchase")
    _reject_compose_mount_indirections(gateway, "gateway")
    _reject_compose_mount_indirections(connector, "connector")
    _reject_compose_mount_indirections(purchase, "reference purchase")
    _compose_direct_sections(
        gateway,
        "gateway",
        frozenset({"build", "depends_on", "environment", "healthcheck", "networks", "volumes"}),
    )
    _compose_direct_sections(
        connector,
        "connector",
        frozenset({"command", "environment", "image", "networks"}),
    )
    _compose_direct_sections(
        purchase,
        "reference purchase",
        frozenset({"build", "healthcheck", "networks"}),
    )
    if _compose_mapping(gateway, "environment", "gateway") != _COMPOSE_GATEWAY_ENVIRONMENT:
        raise ContainmentProfileError(
            "compose gateway environment does not match credential profile"
        )
    if _compose_mapping(connector, "environment", "connector") != _COMPOSE_CONNECTOR_ENVIRONMENT:
        raise ContainmentProfileError(
            "compose connector environment does not match credential profile"
        )
    if _compose_list(gateway, "networks", "gateway") != [
        _SAFE_CONTENT_NETWORK,
        _GOVERNANCE_NETWORK,
    ]:
        raise ContainmentProfileError("compose gateway networks do not match bounded destinations")
    if _compose_list(connector, "networks", "connector") != [_PROVIDER_NETWORK]:
        raise ContainmentProfileError("compose connector has an external or undeclared network")
    if _compose_list(purchase, "networks", "reference purchase") != [_PROVIDER_NETWORK]:
        raise ContainmentProfileError(
            "compose purchase service is not confined to connector network"
        )
    if _compose_list(connector, "volumes", "connector"):
        raise ContainmentProfileError("compose connector must not receive a host bind")
    if _compose_list(gateway, "volumes", "gateway") != [
        "/var/run/docker.sock:/var/run/docker.sock",
        "${MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT:?set by the live containment oracle}:"
        "${MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT:?set by the live containment oracle}",
    ]:
        raise ContainmentProfileError("compose gateway host binds do not match containment profile")
    networks = _compose_networks(compose)
    expected_networks = {
        _AGENT_NETWORK,
        _SAFE_CONTENT_NETWORK,
        _GOVERNANCE_NETWORK,
        _PROVIDER_NETWORK,
    }
    if set(networks) != expected_networks or any(
        properties != {"name": name, "internal": "true"} for name, properties in networks.items()
    ):
        raise ContainmentProfileError("compose must declare only internal reference networks")
    if containment.gateway_environment != (
        _GATEWAY_CONTROL_ENVIRONMENT | _GATEWAY_ACTION_CREDENTIALS
    ):
        raise ContainmentProfileError("profile gateway credentials do not match compose boundary")
    if containment.gateway_destinations != {"masugated:8000", "safe-content:8080"}:
        raise ContainmentProfileError("profile gateway destinations do not match plugin boundary")


def load_reference_containment(
    *,
    manifest_path: Path | None = None,
    profile_path: Path | None = None,
    plugin_config_path: Path | None = None,
    openclaw_config_path: Path | None = None,
    network_topology_path: Path | None = None,
    compose_path: Path | None = None,
) -> ReferenceContainment:
    """Load and cross-check the versioned deployment containment artifacts."""

    directory = containment_directory()
    manifest_version, surfaces = _parse_manifest(
        manifest_path if manifest_path is not None else directory / "manifest.json"
    )
    (
        profile_version,
        agent_environment,
        agent_destinations,
        gateway_environment,
        gateway_destinations,
    ) = _parse_profile(profile_path if profile_path is not None else directory / "profile.json")
    containment = ReferenceContainment(
        manifest_version=manifest_version,
        profile_version=profile_version,
        surfaces=surfaces,
        agent_environment=agent_environment,
        agent_destinations=agent_destinations,
        gateway_environment=gateway_environment,
        gateway_destinations=gateway_destinations,
    )
    selected_plugin_config = (
        plugin_config_path
        if plugin_config_path is not None
        else directory.parent / "plugin-config.example.json"
    )
    _verify_plugin_binding(containment, selected_plugin_config)
    _verify_openclaw_sandbox(
        containment,
        openclaw_config_path
        if openclaw_config_path is not None
        else directory / "openclaw-sandbox.json",
        selected_plugin_config,
    )
    _verify_network_topology(
        containment,
        network_topology_path
        if network_topology_path is not None
        else directory / "network-topology.json",
    )
    _verify_compose(
        containment,
        compose_path if compose_path is not None else directory / "compose.yaml",
    )
    return containment


class ReferenceSafeCapabilitySmoke:
    """Declarative benign-work fixture tied to the containment profile.

    The live containment test independently invokes the pinned host's bounded
    content tool. This fixture validates the profile inventory only; it never
    claims to exercise a Docker or OpenClaw enforcement boundary.
    """

    _DOCUMENTS: ClassVar[dict[str, str]] = {
        "procurement": "Office supplies require a purchase request.",
        "travel": "Use the approved travel handbook for itinerary drafts.",
    }

    def __init__(self, containment: ReferenceContainment) -> None:
        self._containment = containment

    def run(self) -> dict[str, str]:
        self._containment.require_safe("read")
        read = self._DOCUMENTS["procurement"]
        self._containment.require_safe("search")
        search = "procurement" if "purchase" in read else ""
        self._containment.require_safe("browse")
        browse = self._DOCUMENTS["travel"]
        self._containment.require_safe("draft")
        draft = f"Draft: {browse}"
        self._containment.require_safe("local-compute")
        compute = str(2 + 3)
        self._containment.require_safe("network")
        network = "masugate_reference_content:travel"
        if self._containment.agent_destinations:
            raise ContainmentProfileError("agent must not have direct network access")
        return {
            "read": read,
            "search": search,
            "browse": browse,
            "draft": draft,
            "compute": compute,
            "network": network,
        }


def declared_bypass_matrix(containment: ReferenceContainment) -> dict[str, str]:
    """Return the declared bypass inventory, not live enforcement evidence.

    ``run-reference-containment-live.py`` makes the corresponding Docker and
    pinned-OpenClaw attempts. Keeping the declaration separate prevents static
    artifact checks from being mistaken for complete-mediation proof.
    """

    vectors = {
        "curl": "blocked.purchase-api-direct",
        "python-sdk": "blocked.masugated-api-direct",
        "node-sdk": "blocked.masugated-api-direct",
        "browser-fetch": "blocked.browser-direct",
        "shell": "blocked.shell",
        "child-process": "blocked.child-process",
        "native-tool": "blocked.native-consequential-tools",
        "agent-mcp": "blocked.agent-mcp-extension",
        "provider-credential-read": "blocked.provider-credentials",
        "governance-database-read": "blocked.governance-database",
        "protected-mount-read": "blocked.protected-mounts",
        "admin-config": "blocked.admin-configuration",
    }
    results: dict[str, str] = {}
    for vector, surface_id in vectors.items():
        containment.require_blocked(surface_id)
        results[vector] = "blocked"
    return results
