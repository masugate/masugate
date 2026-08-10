#!/usr/bin/env python3
"""Run the reference containment Docker/OpenClaw containment acceptance oracle.

This is deliberately a deployment test, not a reusable MasuGate runtime feature.
It starts the checked-in reference topology, invokes the bounded content tool
through the pinned OpenClaw resolver on the trusted Gateway, then makes direct
curl/Python/Node attempts from the agent sandbox. The agent must have no DNS
or network route to safe-content or any governance service.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_CONTEXT_ENV = "MASUGATE_CONTAINMENT_CONTEXT"
_context = os.environ.get(_CONTEXT_ENV)
ROOT = Path(_context).resolve() if _context else Path(__file__).resolve().parents[1]
if _context and (not ROOT.is_dir() or ROOT.name != "context"):
    raise RuntimeError(f"{_CONTEXT_ENV} must name a staged containment context")
COMPOSE_FILE = ROOT / "integrations" / "openclaw-reference" / "containment" / "compose.yaml"
PROJECT = "masugate-reference_containment-containment"
_DOCKER = os.environ.get("MASUGATE_DOCKER_BIN", "docker")
_AGENT_NETWORK = "masugate-openclaw-reference-agent"
_AGENT_CONTAINER_PREFIX = "masugate-openclaw-reference-agent-"
_SAFE_CONTENT_NETWORK = "masugate-openclaw-reference-safe-content"
_GOVERNANCE_NETWORK = "masugate-openclaw-reference-governance"
_PROVIDER_NETWORK = "masugate-openclaw-reference-provider"
_STATE_ROOT: Path | None = None
_GATEWAY_HEALTH_PROBE = (
    "fetch('http://127.0.0.1:18789/healthz')"
    ".then((response) => process.exit(response.ok ? 0 : 1))"
    ".catch(() => process.exit(1))"
)
_MASUGATED_CONTROL_PROBE = (
    "fetch('http://masugated:8000/')"
    ".then((response) => process.exit(response.ok ? 0 : 1))"
    ".catch(() => process.exit(1))"
)
_GATEWAY_IMAGE_ENVIRONMENT = {
    "NODE_VERSION": "24.16.0",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "YARN_VERSION": "1.22.22",
}
_CONNECTOR_IMAGE_ENVIRONMENT = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
}
_CONTAINMENT_DIRECTORY = ROOT / "integrations" / "openclaw-reference" / "containment"
_PROFILE_PATH = _CONTAINMENT_DIRECTORY / "profile.json"
_OPENCLAW_CONFIG_PATH = _CONTAINMENT_DIRECTORY / "openclaw-sandbox.json"
_MASUGATE_PLUGIN_CONFIG_PATH = (
    ROOT / "integrations" / "openclaw-reference" / "plugin-config.example.json"
)
_SENTINEL_LISTENS = {
    "safe-content": (_CONTAINMENT_DIRECTORY / "safe-content.conf", 8080),
    "masugated": (_CONTAINMENT_DIRECTORY / "masugated-sentinel.conf", 8000),
    "reference-purchase": (_CONTAINMENT_DIRECTORY / "purchase-sentinel.conf", 8081),
}
_REFERENCE_TARGETS = (
    ("safe-content", _SAFE_CONTENT_NETWORK, "http://safe-content:8080/reference/travel", 200),
    ("masugated", _GOVERNANCE_NETWORK, "http://masugated:8000/", 200),
    ("reference-purchase", _PROVIDER_NETWORK, "http://reference-purchase:8081/", 401),
)
_COMPOSE_SERVICE_IMAGES = frozenset(
    {
        "masugate-openclaw-reference-agent-sandbox:reference_containment",
        f"{PROJECT}-openclaw-gateway:latest",
        f"{PROJECT}-masugated:latest",
        f"{PROJECT}-reference-purchase:latest",
        f"{PROJECT}-safe-content:latest",
    }
)


class LiveContainmentError(RuntimeError):
    """The running reference topology violates its reference containment profile."""


def _run(*args: str, capture: bool = False, environment: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        args,
        check=False,
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=capture,
    )
    if completed.returncode != 0:
        raise LiveContainmentError(
            f"command failed ({' '.join(args)}):\n{completed.stdout}\n{completed.stderr}"
        )
    return completed.stdout


def _compose(*args: str, capture: bool = False) -> str:
    if _STATE_ROOT is None:
        raise LiveContainmentError("live containment state root was not initialized")
    environment_file = _STATE_ROOT / "compose.env"
    environment_file.write_text(
        f"MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT={_STATE_ROOT}\n", encoding="utf-8"
    )
    environment = dict(os.environ)
    environment["MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT"] = str(_STATE_ROOT)
    return _run(
        _DOCKER,
        "compose",
        "--env-file",
        str(environment_file),
        "-p",
        PROJECT,
        "-f",
        str(COMPOSE_FILE),
        *args,
        capture=capture,
        environment=environment,
    )


def _remove_compose_service_images() -> None:
    """Remove only service images produced by this fixed disposable oracle."""

    rendered = _run(_DOCKER, "image", "ls", "--format", "{{.Repository}}:{{.Tag}}", capture=True)
    # Docker can render the same repository/tag more than once while a local
    # image is being retagged by Compose.  Removal is an exact cleanup action,
    # so de-duplicate the rendered names before issuing a destructive command.
    images = tuple(
        sorted(
            {
                image
                for image in rendered.splitlines()
                if image.startswith(f"{PROJECT}-")
                or image == "masugate-openclaw-reference-agent-sandbox:reference_containment"
            }
        )
    )
    unexpected = tuple(image for image in images if image not in _COMPOSE_SERVICE_IMAGES)
    if unexpected:
        raise LiveContainmentError(
            "refusing to remove an unexpected containment Compose image: " + ", ".join(unexpected)
        )
    for image in images:
        _run(_DOCKER, "image", "rm", image)
    remaining = tuple(
        image
        for image in _run(
            _DOCKER, "image", "ls", "--format", "{{.Repository}}:{{.Tag}}", capture=True
        ).splitlines()
        if image.startswith(f"{PROJECT}-")
        or image == "masugate-openclaw-reference-agent-sandbox:reference_containment"
    )
    if remaining:
        raise LiveContainmentError(
            "containment Compose service-image cleanup left images behind: " + ", ".join(remaining)
        )


def _cleanup_compose_project(*, remove_dynamic_agents: bool = False) -> None:
    """Attempt every fixed-project cleanup stage independently and retain failures."""

    failures: list[Exception] = []
    try:
        _compose("down", "--volumes", "--remove-orphans")
    except Exception as exc:
        failures.append(exc)
    if remove_dynamic_agents:
        try:
            _remove_dynamic_agent_resources()
        except Exception as exc:
            failures.append(exc)
    try:
        _remove_compose_service_images()
    except Exception as exc:
        failures.append(exc)
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise ExceptionGroup("containment Compose teardown and image cleanup failed", failures)


def _service_id(service: str) -> str:
    return _compose("ps", "-q", service, capture=True).strip()


def _inspect_container(container: str) -> dict[str, Any]:
    raw = _run(_DOCKER, "inspect", container, capture=True)
    parsed = json.loads(raw)
    if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(parsed[0], dict):
        raise LiveContainmentError(f"cannot inspect container {container}")
    return parsed[0]


def _network_members(network: str) -> set[str]:
    raw = _run(_DOCKER, "network", "inspect", network, capture=True)
    parsed = json.loads(raw)
    if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(parsed[0], dict):
        raise LiveContainmentError(f"cannot inspect network {network}")
    containers = parsed[0].get("Containers")
    if not isinstance(containers, dict):
        raise LiveContainmentError(f"network {network} has no container inventory")
    return set(containers)


def _agent_sandbox_ids() -> list[str]:
    """Return only dynamic sandboxes owned by this disposable profile."""

    raw = _run(
        _DOCKER,
        "ps",
        "--all",
        "--quiet",
        "--filter",
        f"name={_AGENT_CONTAINER_PREFIX}",
        capture=True,
    )
    return [container_id for container_id in raw.splitlines() if container_id]


def _agent_network_exists() -> bool:
    """Check without treating an already-clean Docker host as an error."""

    completed = subprocess.run(
        (_DOCKER, "network", "inspect", _AGENT_NETWORK),
        check=False,
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return completed.returncode == 0


def _remove_dynamic_agent_resources() -> None:
    """Remove only sandboxes and network created by this fixed profile."""

    sandbox_ids = _agent_sandbox_ids()
    for sandbox_id in sandbox_ids:
        # Docker can begin removing a just-stopped sandbox before this oracle
        # reaches its explicit cleanup.  An absent container is the required
        # end state; retain a bounded retry for any other daemon response.
        deadline = time.monotonic() + 20
        while True:
            completed = subprocess.run(
                (_DOCKER, "rm", "--force", sandbox_id),
                check=False,
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if completed.returncode == 0:
                break
            inspected = subprocess.run(
                (_DOCKER, "inspect", sandbox_id),
                check=False,
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if inspected.returncode != 0:
                break
            if time.monotonic() >= deadline:
                raise LiveContainmentError(
                    f"OpenClaw agent sandbox {sandbox_id} did not stop for cleanup"
                )
            time.sleep(0.2)
    if _agent_network_exists():
        _run(_DOCKER, "network", "rm", _AGENT_NETWORK)


def _clear_state_root_from_container() -> None:
    """Remove root-owned OpenClaw session files before Python removes the root.

    The pinned Docker backend writes session copies as root.  On a native Linux
    worktree, ``TemporaryDirectory`` cannot unlink those files even when every
    Compose service has stopped.  A short-lived container removes only the
    generated state-root contents, preserving normal non-root cleanup.
    """

    if _STATE_ROOT is None:
        raise LiveContainmentError("live containment state root was not initialized")
    if _STATE_ROOT.parent != ROOT or not _STATE_ROOT.name.startswith(
        ".masugate-reference_containment-containment-"
    ):
        raise LiveContainmentError("refusing to clear a state root outside this live oracle")
    _run(
        _DOCKER,
        "run",
        "--rm",
        "--volume",
        f"{_STATE_ROOT}:/state:rw",
        "alpine:3.21",
        "sh",
        "-ec",
        "rm -rf /state/* /state/.[!.]* /state/..?*",
    )
    if any(_STATE_ROOT.iterdir()):
        raise LiveContainmentError("container-side cleanup left files in the live state root")


def _prepare_dynamic_agent_network() -> None:
    """OpenClaw joins its dynamic sandbox to this empty internal network."""

    _remove_dynamic_agent_resources()
    _run(_DOCKER, "network", "create", "--internal", _AGENT_NETWORK)


def _require_equal(actual: object, expected: object, context: str) -> None:
    if actual != expected:
        raise LiveContainmentError(f"{context}: expected {expected!r}, got {actual!r}")


def _json_object(path: Path, context: str) -> dict[str, object]:
    try:
        value: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LiveContainmentError(f"cannot load {context}") from exc
    if not isinstance(value, dict):
        raise LiveContainmentError(f"{context} must be a JSON object")
    return value


def _object(value: object, context: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise LiveContainmentError(f"{context} must be an object")
    return value


def _target_destination(url: str, context: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or not parsed.hostname or parsed.port is None:
        raise LiveContainmentError(f"{context} must be an absolute HTTP URL with a port")
    return f"{parsed.hostname}:{parsed.port}"


def _compose_service_networks(compose: str, service: str) -> set[str]:
    match = re.search(
        rf"^  {re.escape(service)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:\n|^networks:\n)",
        compose,
        re.M | re.S,
    )
    if match is None:
        raise LiveContainmentError(f"compose is missing target service {service}")
    networks = re.search(
        r"^    networks:\n(?P<body>(?:^      - .+\n?)*)", match.group("body"), re.M
    )
    if networks is None:
        raise LiveContainmentError(f"compose target service {service} has no networks")
    return {
        item.group(1)
        for line in networks.group("body").splitlines()
        if (item := re.fullmatch(r"      - ([A-Za-z0-9_-]+)", line)) is not None
    }


def _assert_reference_targets_are_normative() -> None:
    """Bind every live destination to the published profile and sentinels."""

    targets = {name: (network, url, status) for name, network, url, status in _REFERENCE_TARGETS}
    if len(targets) != len(_REFERENCE_TARGETS):
        raise LiveContainmentError("reference target inventory contains duplicate names")
    _require_equal(
        set(targets),
        {"safe-content", "masugated", "reference-purchase"},
        "reference target names",
    )
    safe_network, safe_url, safe_status = targets["safe-content"]
    masugated_network, masugated_url, masugated_status = targets["masugated"]
    purchase_network, purchase_url, purchase_status = targets["reference-purchase"]
    _require_equal(
        (safe_network, masugated_network, purchase_network),
        (_SAFE_CONTENT_NETWORK, _GOVERNANCE_NETWORK, _PROVIDER_NETWORK),
        "reference target networks",
    )
    _require_equal(
        (safe_status, masugated_status, purchase_status), (200, 200, 401), "target statuses"
    )
    safe_destination = _target_destination(safe_url, "safe target")
    masugated_destination = _target_destination(masugated_url, "MasuGateD target")
    purchase_destination = _target_destination(purchase_url, "purchase target")
    profile = _json_object(_PROFILE_PATH, "containment profile")
    gateway_profile = _object(profile.get("gateway"), "profile.gateway")
    profile_destinations = gateway_profile.get("allowed_destinations")
    if (
        not isinstance(profile_destinations, list)
        or any(not isinstance(destination, str) for destination in profile_destinations)
        or len(set(profile_destinations)) != len(profile_destinations)
    ):
        raise LiveContainmentError("profile Gateway destinations must be a string list")
    _require_equal(
        frozenset(profile_destinations),
        frozenset({safe_destination, masugated_destination}),
        "profile Gateway destinations",
    )
    connector = _object(profile.get("connector"), "profile.connector")
    _require_equal(
        connector.get("allowed_destinations"),
        [purchase_destination],
        "profile connector destination",
    )
    openclaw = _json_object(_OPENCLAW_CONFIG_PATH, "OpenClaw containment config")
    entries = _object(_object(openclaw.get("plugins"), "plugins").get("entries"), "plugin entries")
    masugate_config = _object(
        _object(entries.get("masugate"), "MasuGate plugin").get("config"), "MasuGate config"
    )
    content_config = _object(
        _object(entries.get("masugate-reference-content"), "safe-content plugin").get("config"),
        "safe-content config",
    )
    standalone_masugate_config = _json_object(
        _MASUGATE_PLUGIN_CONFIG_PATH, "MasuGate plugin config"
    )
    _require_equal(
        masugate_config, standalone_masugate_config, "published MasuGate plugin binding"
    )
    _require_equal(
        masugate_config.get("masugatedBaseUrl"),
        f"http://{masugated_destination}",
        "MasuGate target",
    )
    _require_equal(
        content_config.get("safeContentBaseUrl"),
        f"http://{safe_destination}",
        "safe-content target",
    )
    compose = COMPOSE_FILE.read_text(encoding="utf-8")
    for name, expected_network in (
        ("safe-content", safe_network),
        ("masugated", masugated_network),
        ("reference-purchase", purchase_network),
    ):
        _require_equal(
            _compose_service_networks(compose, name), {expected_network}, f"{name} network"
        )
    for name, (sentinel, port) in _SENTINEL_LISTENS.items():
        if not re.search(rf"^\s*listen\s+{port};", sentinel.read_text(encoding="utf-8"), re.M):
            raise LiveContainmentError(f"{name} sentinel does not bind its target port")
    purchase_sentinel = _SENTINEL_LISTENS["reference-purchase"][0].read_text(encoding="utf-8")
    if "return 401;" not in purchase_sentinel:
        raise LiveContainmentError(
            "purchase sentinel does not expose the expected unauthenticated status"
        )


def _wait_for_gateway() -> None:
    deadline = time.monotonic() + 90
    last_logs = ""
    while time.monotonic() < deadline:
        last_logs = _compose("logs", "--no-color", "openclaw-gateway", capture=True)
        try:
            _compose(
                "exec",
                "-T",
                "openclaw-gateway",
                "node",
                "-e",
                _GATEWAY_HEALTH_PROBE,
            )
        except LiveContainmentError:
            time.sleep(1)
            continue
        return
    raise LiveContainmentError(f"pinned OpenClaw Gateway did not become healthy:\n{last_logs}")


def _create_pinned_openclaw_session() -> list[str]:
    """Drive both profiles through the running Gateway's agent-session API."""

    try:
        output = _compose(
            "exec",
            "-T",
            "openclaw-gateway",
            "node",
            "gateway-live-session.mjs",
            capture=True,
        )
    except LiveContainmentError as exc:
        logs = _compose("logs", "--no-color", "openclaw-gateway", capture=True)
        raise LiveContainmentError(
            f"Gateway session request failed; Gateway logs follow:\n{logs}\n{exc}"
        ) from exc
    if "REFERENCE_CONTAINMENT_GATEWAY_SESSION_OK" not in output:
        raise LiveContainmentError(
            f"pinned OpenClaw Gateway session invocation did not succeed:\n{output}"
        )
    if "REFERENCE_CONTAINMENT_GATEWAY_NARROW_POLICY_OK" not in output:
        raise LiveContainmentError(
            f"pinned OpenClaw Gateway did not apply the narrow session policy:\n{output}"
        )
    sandboxes = _agent_sandbox_ids()
    if len(sandboxes) != 2:
        raise LiveContainmentError(
            "pinned OpenClaw Gateway did not create the full and narrowed session sandboxes: "
            f"got {sandboxes!r}"
        )
    return sandboxes


def _assert_gateway_session_evidence() -> str:
    """Verify the loopback model saw the real Gateway's session tool loop."""

    if _STATE_ROOT is None:
        raise LiveContainmentError("live containment state root was not initialized")
    try:
        value: object = json.loads(
            (_STATE_ROOT / "gateway-session-evidence.json").read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise LiveContainmentError(
            "pinned OpenClaw Gateway session did not emit model-loop evidence"
        ) from exc
    if (
        not isinstance(value, list)
        or len(value) != 5
        or any(not isinstance(item, dict) for item in value)
    ):
        raise LiveContainmentError("Gateway model-loop evidence has an unexpected shape")
    full = value[:4]
    narrow = value[4]
    if any(
        item.get("session") != "buyer-alpha"
        or item.get("tools")
        != sorted(["read", "masugate_governed_action", "masugate_reference_content"])
        for item in full
    ):
        raise LiveContainmentError("Gateway did not supply the full session tool policy")
    if [len(item.get("results", [])) for item in full] != [0, 1, 2, 3]:
        raise LiveContainmentError("Gateway did not complete the expected session tool sequence")
    sandbox = full[0].get("sandbox")
    if not isinstance(sandbox, dict) or set(sandbox) != {
        "sessionKey",
        "containerName",
        "workspaceAccess",
        "containerWorkdir",
    }:
        raise LiveContainmentError("Gateway session evidence omitted its resolved sandbox context")
    if (
        sandbox.get("sessionKey") != "agent:buyer-alpha:reference-containment-live-session"
        or not isinstance(sandbox.get("containerName"), str)
        or not sandbox["containerName"]
        or sandbox.get("workspaceAccess") != "none"
        or sandbox.get("containerWorkdir") != "/workspace"
    ):
        raise LiveContainmentError(
            "Gateway session sandbox evidence does not match the pinned profile"
        )
    if any("sandbox" in item for item in full[1:]):
        raise LiveContainmentError(
            "Gateway session fixture resolved the sandbox outside session setup"
        )
    if narrow != {"session": "narrow", "tools": ["read"], "results": []}:
        raise LiveContainmentError("Gateway did not apply the narrowed sandbox tool policy")
    encoded = json.dumps(full[-1], sort_keys=True)
    for expected in (
        "Use the approved travel handbook for itinerary drafts.",
        "reference-containment-governed-plugin",
        "reference-containment sandbox-bound read proof",
    ):
        if expected not in encoded:
            raise LiveContainmentError(
                f"Gateway session evidence is missing the expected tool result: {expected!r}"
            )
    return sandbox["containerName"]


def _container_environment(container: dict[str, Any], context: str) -> dict[str, str]:
    """Return the exact declared Docker environment inventory.

    Docker's ``Config.Env`` records image and Compose declarations; process
    shell variables such as ``PWD`` are not added there.  Deliberately keep
    every listed name so an explicitly configured ``HOSTNAME``, ``PWD`` or
    ``SHLVL`` fails the closed profile comparison.
    """

    environment = container.get("Config", {}).get("Env")
    if not isinstance(environment, list):
        raise LiveContainmentError(f"{context} does not expose its environment inventory")
    result: dict[str, str] = {}
    for item in environment:
        if not isinstance(item, str) or "=" not in item:
            raise LiveContainmentError(f"{context} has a malformed environment entry")
        key, value = item.split("=", 1)
        if not key or key in result:
            raise LiveContainmentError(f"{context} has a malformed environment inventory")
        result[key] = value
    return result


def _assert_exact_environment(
    container: dict[str, Any],
    image_environment: dict[str, str],
    profile_environment: dict[str, str],
    context: str,
) -> None:
    _require_equal(
        _container_environment(container, context),
        image_environment | profile_environment,
        context,
    )


def _assert_exact_mounts(
    container: dict[str, Any],
    expected: list[tuple[str, str, str, bool]],
    context: str,
) -> None:
    """Compare Docker's effective mount inventory, not just Compose bind text.

    ``HostConfig.Binds`` omits Compose secrets, configs, and ``volumes_from``
    materialized by Docker.  The effective ``Mounts`` inventory makes those
    alternate forms visible and rejects every additional Gateway or connector
    mount, including a mounted provider credential.
    """

    mounts = container.get("Mounts")
    if not isinstance(mounts, list):
        raise LiveContainmentError(f"{context} does not expose Docker mount inventory")
    actual: list[tuple[str, str, str, bool]] = []
    for mount in mounts:
        if not isinstance(mount, dict):
            raise LiveContainmentError(f"{context} contains a malformed Docker mount")
        mount_type = mount.get("Type")
        source = mount.get("Source")
        destination = mount.get("Destination")
        read_write = mount.get("RW")
        if (
            not isinstance(mount_type, str)
            or not isinstance(source, str)
            or not isinstance(destination, str)
            or not isinstance(read_write, bool)
        ):
            raise LiveContainmentError(f"{context} contains an incomplete Docker mount")
        actual.append((mount_type, source, destination, read_write))
    _require_equal(sorted(actual), sorted(expected), context)


def _assert_live_topology(agent_containers: list[str], gateway_session_sandbox: str) -> None:
    if len(agent_containers) != 2:
        raise LiveContainmentError("expected the full and narrowed OpenClaw session sandboxes")
    agents = [_inspect_container(container) for container in agent_containers]
    if gateway_session_sandbox not in {
        str(agent.get("Name", "")).removeprefix("/") for agent in agents
    }:
        raise LiveContainmentError(
            "Gateway session evidence did not identify one of the live session sandboxes"
        )
    gateway = _inspect_container(_service_id("openclaw-gateway"))
    gateway_networks = gateway["NetworkSettings"]["Networks"]
    _require_equal(
        set(gateway_networks),
        {_SAFE_CONTENT_NETWORK, _GOVERNANCE_NETWORK},
        "gateway network membership",
    )
    _require_equal(
        _network_members("masugate-openclaw-reference-agent"),
        {agent["Id"] for agent in agents},
        "agent network container membership",
    )
    _require_equal(
        _network_members(_SAFE_CONTENT_NETWORK),
        {_service_id("openclaw-gateway"), _service_id("safe-content")},
        "safe-content network container membership",
    )
    _require_equal(
        _network_members(_GOVERNANCE_NETWORK),
        {
            _service_id("openclaw-gateway"),
            _service_id("masugated"),
            _service_id("masugate-governance-postgres"),
        },
        "governance network container membership",
    )
    _require_equal(
        _network_members(_PROVIDER_NETWORK),
        {_service_id("reference-purchase"), _service_id("reference-purchase-connector")},
        "provider network container membership",
    )
    connector = _inspect_container(_service_id("reference-purchase-connector"))
    _require_equal(
        set(connector["NetworkSettings"]["Networks"]),
        {_PROVIDER_NETWORK},
        "connector network membership",
    )
    _assert_exact_environment(
        gateway,
        _GATEWAY_IMAGE_ENVIRONMENT,
        {
            "OPENCLAW_GATEWAY_TOKEN": "reference-containment-local-gateway-token",
            "MASUGATE_AGENT_SANDBOX_IMAGE": (
                "masugate-openclaw-reference-agent-sandbox:reference_containment"
            ),
            "MASUGATE_BUYER_ALPHA_TOKEN": "reference-containment-reference-token",
            "MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT": str(_STATE_ROOT),
        },
        "Gateway credential and state-root inventory",
    )
    _assert_exact_environment(
        connector,
        _CONNECTOR_IMAGE_ENVIRONMENT,
        {"REFERENCE_PURCHASE_SERVICE_TOKEN": "reference-containment-connector-token"},
        "connector credential inventory",
    )
    _require_equal(connector["HostConfig"].get("Binds") or [], [], "connector host binds")
    _assert_exact_mounts(connector, [], "connector effective mounts")
    connector_host_config = connector["HostConfig"]
    if connector_host_config.get("VolumesFrom"):
        raise LiveContainmentError("connector receives inherited volumes")
    if connector_host_config.get("Tmpfs"):
        raise LiveContainmentError("connector receives an unreviewed tmpfs mount")

    for agent in agents:
        agent_networks = agent["NetworkSettings"]["Networks"]
        _require_equal(
            set(agent_networks),
            {_AGENT_NETWORK},
            "agent network membership",
        )
        host_config = agent["HostConfig"]
        _require_equal(host_config["ReadonlyRootfs"], True, "agent root filesystem")
        _require_equal(set(host_config.get("CapDrop") or []), {"ALL"}, "agent dropped capabilities")
        # The pinned OpenClaw Docker backend passes the exact Docker CLI flag
        # ``--security-opt no-new-privileges``. Docker inspect preserves that
        # spelling (rather than rewriting it to ``:true``).
        if "no-new-privileges" not in (host_config.get("SecurityOpt") or []):
            raise LiveContainmentError("agent container permits privilege escalation")
        binds = host_config.get("Binds") or []
        if len(binds) != 1 or not isinstance(binds[0], str):
            raise LiveContainmentError(
                "agent container must have exactly one OpenClaw-managed workspace bind: "
                f"got {binds!r}"
            )
        if _STATE_ROOT is None or not binds[0].startswith(f"{_STATE_ROOT}/sandbox-workspaces/"):
            raise LiveContainmentError(
                "agent container exposes a non-session workspace host bind: "
                f"expected {_STATE_ROOT}/sandbox-workspaces, got {binds[0]!r}"
            )
        if not binds[0].endswith(":/workspace:ro,z"):
            raise LiveContainmentError(
                "agent workspace bind is not the required read-only OpenClaw copy"
            )
        workspace_source = binds[0].removesuffix(":/workspace:ro,z")
        _assert_exact_mounts(
            agent,
            [("bind", workspace_source, "/workspace", False)],
            "agent effective mounts",
        )
        if any("docker.sock" in bind for bind in binds):
            raise LiveContainmentError("agent container receives the trusted Gateway Docker socket")
        if host_config.get("VolumesFrom"):
            raise LiveContainmentError("agent container receives inherited volumes")
        if set(host_config.get("Tmpfs") or {}) != {"/tmp"}:
            raise LiveContainmentError("agent container tmpfs profile drifted")

    if _STATE_ROOT is None:
        raise LiveContainmentError("live containment state root was not initialized")
    _assert_exact_mounts(
        gateway,
        [
            ("bind", "/var/run/docker.sock", "/var/run/docker.sock", True),
            ("bind", str(_STATE_ROOT), str(_STATE_ROOT), True),
        ],
        "Gateway effective mounts",
    )
    gateway_host_config = gateway["HostConfig"]
    if gateway_host_config.get("VolumesFrom"):
        raise LiveContainmentError("trusted Gateway receives inherited volumes")
    if gateway_host_config.get("Tmpfs"):
        raise LiveContainmentError("trusted Gateway receives an unreviewed tmpfs mount")


def _assert_target_positive_controls_succeed() -> None:
    """Prove every blocked target/port is live before testing sandbox isolation.

    HTTP 401 still proves a transport route.  Each control therefore checks the
    exact status from curl, Python, and Node rather than treating authorization
    failure as if the destination were unreachable.
    """

    for _name, network, url, expected_status in _REFERENCE_TARGETS:
        probe = f"""
set -eu
URL={shlex.quote(url)}
EXPECTED_STATUS={expected_status}
curl_status="$(curl --silent --show-error --connect-timeout 2 --max-time 2 \\
  --output /dev/null --write-out '%{{http_code}}' "$URL")"
test "$curl_status" = "$EXPECTED_STATUS"
python3 -c '
import sys
import urllib.error as error
import urllib.request as request
url, expected = sys.argv[1], int(sys.argv[2])
try:
    response = request.urlopen(url, timeout=2)
    status = response.status
except error.HTTPError as http_error:
    status = http_error.code
if status != expected:
    raise SystemExit(f"expected HTTP {{expected}}, got {{status}}")
' "$URL" "$EXPECTED_STATUS"
node -e '
const [url, expected] = process.argv.slice(1);
fetch(url, {{ signal: AbortSignal.timeout(2e3) }})
  .then((response) => process.exit(response.status === Number(expected) ? 0 : 1))
  .catch(() => process.exit(1));
' "$URL" "$EXPECTED_STATUS"
""".strip()
        _run(
            _DOCKER,
            "run",
            "--rm",
            "--network",
            network,
            "masugate-openclaw-reference-agent-sandbox:reference_containment",
            "sh",
            "-ec",
            probe,
        )


def _assert_direct_agent_bypasses_fail() -> None:
    base_probe = """
set -eu
test -z "${MASUGATE_BUYER_ALPHA_TOKEN+x}"
test -z "${REFERENCE_PURCHASE_SERVICE_TOKEN+x}"
test -z "${MASUGATE_POSTGRES_DSN+x}"
test ! -e /protected
test ! -e /run/secrets/MASUGATE_BUYER_ALPHA_TOKEN
! mount | grep -q '/protected'
""".strip()
    sandboxes = _network_members(_AGENT_NETWORK)
    if len(sandboxes) != 2:
        raise LiveContainmentError("cannot identify the two live OpenClaw session sandboxes")
    for sandbox in sandboxes:
        _run(_DOCKER, "exec", sandbox, "sh", "-ec", base_probe)
        for name, _network, url, _expected_status in _REFERENCE_TARGETS:
            probe = f"""
set -eu
URL={shlex.quote(url)}
if curl --silent --show-error --connect-timeout 2 --max-time 2 --output /dev/null "$URL"; then
  echo "curl reached blocked target {name}" >&2
  exit 1
fi
python3 -c '
import sys
import urllib.error as error
import urllib.request as request
try:
    request.urlopen(sys.argv[1], timeout=2)
except error.HTTPError:
    raise SystemExit(1)
except error.URLError:
    raise SystemExit(0)
raise SystemExit(1)
' "$URL"
node -e '
fetch(process.argv[1], {{ signal: AbortSignal.timeout(2e3) }})
  .then(() => process.exit(1))
  .catch(() => process.exit(0));
' "$URL"
""".strip()
            _run(_DOCKER, "exec", sandbox, "sh", "-ec", probe)


def _assert_authorized_controls_succeed() -> None:
    _compose(
        "exec",
        "-T",
        "openclaw-gateway",
        "node",
        "-e",
        _MASUGATED_CONTROL_PROBE,
    )
    _compose(
        "exec",
        "-T",
        "reference-purchase-connector",
        "sh",
        "-ec",
        """
set -eu
! wget -q -O /dev/null http://reference-purchase:8081/
wget --header="X-Reference-Purchase-Token: ${REFERENCE_PURCHASE_SERVICE_TOKEN:?}" \\
  -q -O /dev/null http://reference-purchase:8081/
""".strip(),
    )


def main() -> None:
    global _STATE_ROOT
    _run(_DOCKER, "info", capture=True)
    _assert_reference_targets_are_normative()
    with tempfile.TemporaryDirectory(
        prefix=".masugate-reference_containment-containment-",
        dir=ROOT,
    ) as state_root:
        _STATE_ROOT = Path(state_root)
        try:
            # The oracle has a fixed Compose project/network identity so it can
            # assert exact topology membership.  A killed local/CI run can
            # leave containers whose transient state-root bind no longer
            # exists; remove that previous disposable topology before build
            # and force every service to use this run's state root.
            _cleanup_compose_project(remove_dynamic_agents=True)
            _prepare_dynamic_agent_network()
            _compose("build", "openclaw-agent-sandbox-image")
            _compose(
                "up",
                "--pull",
                "never",
                "--build",
                "--detach",
                "--wait",
                "--wait-timeout",
                "120",
                "--force-recreate",
            )
            _wait_for_gateway()
            agent_containers = _create_pinned_openclaw_session()
            gateway_session_sandbox = _assert_gateway_session_evidence()
            _assert_live_topology(agent_containers, gateway_session_sandbox)
            _assert_authorized_controls_succeed()
            _assert_target_positive_controls_succeed()
            _assert_direct_agent_bypasses_fail()
        finally:
            try:
                _cleanup_compose_project(remove_dynamic_agents=True)
            finally:
                try:
                    _clear_state_root_from_container()
                finally:
                    _STATE_ROOT = None
    print("reference-containment live containment acceptance passed")


if __name__ == "__main__":
    try:
        main()
    except LiveContainmentError as exc:
        print(f"reference-containment live containment acceptance failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
