#!/usr/bin/env python3
"""Run the pinned-Gateway gateway recovery native-approval crash matrix.

This oracle is intentionally a deployment test.  It drives the published
OpenClaw HTTP session API, waits for the native ``plugin.approval`` record,
resolves it through the pinned Gateway RPC, and kills the actual containers at
the durable native-approval/handoff boundaries.  It does not import a plugin
factory or manufacture a SandboxContext in the test process.
"""

from __future__ import annotations

import json
import os
import re
import select
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTAINMENT = ROOT / "integrations" / "openclaw-reference" / "containment"
COMPOSE = CONTAINMENT / "compose.yaml"
GATEWAY_RECOVERY_COMPOSE = CONTAINMENT / "compose.gateway_recovery.yaml"
PROJECT = "masugate-gateway_recovery-native-approval"
DOCKER = os.environ.get("MASUGATE_DOCKER_BIN", "docker")
STATE_ROOT: Path | None = None
_AGENT_NETWORK = "masugate-openclaw-reference-agent"
_AGENT_CONTAINER_PREFIX = "masugate-openclaw-reference-agent-"

_CASES: tuple[tuple[str, str | None], ...] = (
    ("gateway-plugin-restart", None),
    ("masugated-pending-restart", None),
    ("before-handoff", "before-handoff"),
    ("after-handoff", "after-handoff"),
    ("after-provider", "after-provider"),
)
_GATEWAY_HEALTH_PROBE = (
    "node -e \"fetch('http://127.0.0.1:18789/healthz')"
    '.then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"'
)
_MASUGATED_HEALTH_PROBE = (
    'python -c "import urllib.request; request=urllib.request.Request('
    "'http://127.0.0.1:8000/v1/health', headers={'Authorization':"
    "'Bearer reference-containment-reference-token'}); urllib.request.urlopen(request, timeout=2)\""
)
_EFFECT_COUNT_PROGRAM = (
    "import sqlite3; "
    "print(sqlite3.connect('/reference-purchase-state/reference-purchases.sqlite')"
    ".execute('SELECT count(*) FROM reference_purchases').fetchone()[0])"
)
_PURCHASE_MANIFEST_ENV = "MASUGATE_REFERENCE_CREDENTIAL_MANIFEST_JSON"
_PURCHASE_STATE_ROOT = "/reference-purchase-state"
_PURCHASE_EXPECTED_ENVIRONMENT = {
    "REFERENCE_PURCHASE_SERVICE_TOKEN": "reference-containment-connector-token",
    "MASUGATE_GATEWAY_RECOVERY_PURCHASE_STATE_ROOT": _PURCHASE_STATE_ROOT,
}
_GOVERNANCE_CREDENTIAL_ENVIRONMENT = frozenset(
    {
        "OPENCLAW_GATEWAY_TOKEN",
        "MASUGATE_BUYER_ALPHA_TOKEN",
        "MASUGATE_RESOLVER_TOKEN",
        "MASUGATE_POSTGRES_DSN",
        "MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT",
        "MASUGATE_GATEWAY_RECOVERY_STATE_ROOT",
    }
)
_AGENT_IMAGE_ENVIRONMENT = {
    "NODE_VERSION": "24.16.0",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "YARN_VERSION": "1.22.22",
}
_AGENT_PROFILE_ENVIRONMENT = {"LANG": "C.UTF-8", "TZ": "UTC"}
# OpenClaw injects this fixed runtime marker when it creates the sandbox.  It
# is distinct from profile configuration, but is still part of the reviewed
# effective environment; no other runtime environment entry is permitted.
_AGENT_RUNTIME_ENVIRONMENT = {"OPENCLAW_CLI": "1"}
_AUDIT_PROGRAM = """
const [id, pendingId, sessionKey, sessionId, caseId] = process.argv.slice(1);
const assertThat = (condition, mesmasugate) => {
  if (!condition) throw new Error(mesmasugate);
};
fetch(`http://masugated:8000/v1/audit/${id}`, {
  headers: { Authorization: "Bearer reference-containment-reference-token" },
})
  .then(async (response) => {
    const body = await response.json();
    const human = body?.human_resolution;
    const evidence = human?.evidence;
    const protectedState = body?.protected_execution;
    const binding = protectedState?.binding;
    const events = protectedState?.events;
    const entitlement = body?.entitlement;
    assertThat(response.ok, "audit endpoint failed");
    assertThat(body?.operation_id === id, "operation mismatch");
    assertThat(body?.status === "committed", "terminal status mismatch");
    assertThat(
      human?.approved === true && human?.actor_id === "operator",
      "human resolution missing",
    );
    assertThat(
      evidence?.agent_id === "buyer-alpha" && evidence?.pending_id === pendingId,
      "pending provenance mismatch",
    );
    assertThat(
      evidence?.decision === "allow-once" && evidence?.session_key === sessionKey,
      "native decision/session key mismatch",
    );
    assertThat(
      evidence?.session_id === sessionId && evidence?.source === "openclaw-native-approval",
      "native session epoch mismatch",
    );
    assertThat(
      typeof entitlement?.entitlement_id === "string" &&
        /^[0-9a-f]{64}$/.test(entitlement?.authorization_digest ?? ""),
      "durable entitlement missing",
    );
    assertThat(
      protectedState?.status === "succeeded" &&
        protectedState?.entitlement_state === "consumed",
      "protected terminal state mismatch",
    );
    assertThat(
      protectedState?.dispatch_started === true && protectedState?.lease === null,
      "protected dispatch/lease mismatch",
    );
    assertThat(protectedState?.receipt?.outcome === "succeeded", "protected receipt mismatch");
    assertThat(
      protectedState?.execution_id === `px:${protectedState?.binding_digest}`,
      "execution identity mismatch",
    );
    assertThat(
      binding?.principal_id === "openclaw:buyer-alpha" && binding?.action === "spend.purchase",
      "binding principal/action mismatch",
    );
    assertThat(
      binding?.arguments?.request_ref === `gateway_recovery-${caseId}`,
      "binding request mismatch",
    );
    assertThat(
      binding?.entitlement_id === entitlement?.entitlement_id &&
        binding?.authorization_digest === entitlement?.authorization_digest,
      "binding entitlement mismatch",
    );
    assertThat(Array.isArray(events) && events.length >= 2, "protected event chain missing");
    assertThat(
      events.filter((event) => event?.to_status === "intent").length === 1,
      "durable intent count mismatch",
    );
    assertThat(
      events[0]?.from_status === null && events[0]?.to_status === "intent",
      "intent event mismatch",
    );
    assertThat(events.at(-1)?.to_status === "succeeded", "terminal event mismatch");
    assertThat(
      body?.effect?.action === "spend.purchase" &&
        body?.effect?.args?.request_ref === `gateway_recovery-${caseId}`,
      "effect binding mismatch",
    );
    console.log(JSON.stringify(body));
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
"""
_NATIVE_HANDOFF_PROGRAM = """
const [operationId, pendingId, sessionKey, sessionId] = process.argv.slice(1);
fetch(`http://masugated:8000/v1/audit/${operationId}`, {
  headers: { Authorization: "Bearer reference-containment-reference-token" },
})
  .then(async (response) => {
    if (!response.ok) process.exit(1);
    const body = await response.json();
    const evidence = body?.human_resolution?.evidence;
    if (
      body?.human_resolution?.approved === true &&
      evidence?.agent_id === "buyer-alpha" &&
      evidence?.decision === "allow-once" &&
      evidence?.pending_id === pendingId &&
      evidence?.session_key === sessionKey &&
      evidence?.session_id === sessionId &&
      evidence?.source === "openclaw-native-approval"
    ) {
      console.log("ready");
      return;
    }
    process.exit(1);
  })
  .catch(() => process.exit(1));
"""
_TERMINAL_RECOVERY_PROGRAM = """
const [operationId] = process.argv.slice(1);
fetch(`http://masugated:8000/v1/audit/${operationId}`, {
  headers: { Authorization: "Bearer reference-containment-reference-token" },
})
  .then(async (response) => {
    if (!response.ok) process.exit(1);
    const body = await response.json();
    if (body?.operation_id === operationId && body?.status === "committed") {
      console.log("committed");
      return;
    }
    process.exit(1);
  })
  .catch(() => process.exit(1));
"""


class MatrixError(RuntimeError):
    """The live native-approval matrix has not established its invariant."""


def _agent_sandbox_ids() -> tuple[str, ...]:
    """Return only dynamic sandbox containers owned by this reference profile."""

    output = run(
        DOCKER,
        "ps",
        "--all",
        "--quiet",
        "--filter",
        f"name={_AGENT_CONTAINER_PREFIX}",
        capture=True,
    )
    return tuple(sorted(container_id for container_id in output.splitlines() if container_id))


def _agent_network_exists() -> bool:
    """Avoid treating a clean disposable Docker host as a cleanup error."""

    completed = subprocess.run(
        (DOCKER, "network", "inspect", _AGENT_NETWORK),
        check=False,
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return completed.returncode == 0


def _container_inspect(container_id: str, context: str) -> dict[str, object]:
    """Return one running container's Docker inspect record."""

    raw = run(DOCKER, "inspect", container_id, capture=True)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MatrixError(f"Docker inspect for {context} was not JSON") from exc
    if not isinstance(parsed, list) or len(parsed) != 1 or not isinstance(parsed[0], dict):
        raise MatrixError(f"Docker inspect for {context} has an unexpected shape")
    return parsed[0]


def _service_inspect(service: str) -> dict[str, object]:
    """Return one running Compose service's Docker inspect record."""

    container_id = compose("ps", "--quiet", service, capture=True).strip()
    if not container_id:
        raise MatrixError(f"Compose service {service} has no running container")
    return _container_inspect(container_id, service)


def _environment(inspect: dict[str, object], service: str) -> dict[str, str]:
    config = inspect.get("Config")
    raw = config.get("Env") if isinstance(config, dict) else None
    if not isinstance(raw, list) or any(
        not isinstance(item, str) or "=" not in item for item in raw
    ):
        raise MatrixError(f"Docker inspect for {service} has no valid environment")
    result: dict[str, str] = {}
    for item in raw:
        assert isinstance(item, str)
        name, value = item.split("=", 1)
        if not name or name in result:
            raise MatrixError(f"Docker inspect for {service} has an ambiguous environment")
        result[name] = value
    return result


def _assert_reference_provider_boundary(sandbox_ids: tuple[str, ...]) -> None:
    """Prove the real provider process has no governance authority or state.

    gateway recovery keeps ``masugated`` on the provider transport network so it can call
    the authenticated purchase API.  The provider is therefore deliberately
    checked for *both* absence of governance credentials/state and a reachable
    unauthenticated governance request that returns 401 rather than authority.
    """

    purchase = _service_inspect("reference-purchase")
    environment = _environment(purchase, "reference-purchase")
    protected_names = {
        name
        for name in environment
        if name.startswith("MASUGATE_") or name.startswith("REFERENCE_PURCHASE_")
    }
    expected_names = set(_PURCHASE_EXPECTED_ENVIRONMENT) | {_PURCHASE_MANIFEST_ENV}
    if protected_names != expected_names:
        raise MatrixError(
            "reference-purchase environment is not the exact connector-only inventory: "
            f"{sorted(protected_names)}"
        )
    for name, expected in _PURCHASE_EXPECTED_ENVIRONMENT.items():
        if environment.get(name) != expected:
            raise MatrixError(f"reference-purchase environment {name} is not the reviewed value")
    manifest = environment.get(_PURCHASE_MANIFEST_ENV)
    if manifest is None:
        raise MatrixError("reference-purchase lacks its non-secret credential manifest")
    try:
        manifest_value = json.loads(manifest)
    except json.JSONDecodeError as exc:
        raise MatrixError("reference-purchase credential manifest is not JSON") from exc
    if not isinstance(manifest_value, dict) or set(manifest_value) != {
        "connector_credential_fingerprint",
        "masugate_bearer_credential_fingerprints",
    }:
        raise MatrixError("reference-purchase credential manifest has an invalid shape")
    if _GOVERNANCE_CREDENTIAL_ENVIRONMENT & set(environment):
        raise MatrixError(
            "reference-purchase received a governance credential or Gateway state root"
        )

    mounts = purchase.get("Mounts")
    if not isinstance(mounts, list) or len(mounts) != 1 or not isinstance(mounts[0], dict):
        raise MatrixError("reference-purchase must have exactly one dedicated state mount")
    mount = mounts[0]
    if (
        mount.get("Type") != "volume"
        or mount.get("Destination") != _PURCHASE_STATE_ROOT
        or mount.get("RW") is not True
        or not isinstance(mount.get("Name"), str)
        or not mount["Name"].endswith("masugate-gateway_recovery-purchase-state")
    ):
        raise MatrixError("reference-purchase mount is not its dedicated writable provider state")
    if STATE_ROOT is not None and str(STATE_ROOT) == mount.get("Source"):
        raise MatrixError("reference-purchase reuses the Gateway/session state root")
    networks = purchase.get("NetworkSettings")
    attached = networks.get("Networks") if isinstance(networks, dict) else None
    if (
        not isinstance(attached, dict)
        or len(attached) != 1
        or not next(iter(attached)).endswith("masugate-openclaw-reference-provider")
    ):
        raise MatrixError("reference-purchase must join only the internal provider network")

    # This must be a genuine reachable-but-unauthorized control: connection
    # failure is not proof of credential separation, and any 2xx/other result
    # means the provider acquired unintended governance authority.
    provider_probe = (
        "import urllib.error, urllib.request; "
        "request=urllib.request.Request('http://masugated:8000/v1/pending'); "
        "\ntry:\n urllib.request.urlopen(request, timeout=2)\n"
        "except urllib.error.HTTPError as error:\n"
        " assert error.code == 401, error.code\n"
        "else:\n raise SystemExit('unauthenticated provider reached governance endpoint')\n"
    )
    compose("exec", "-T", "reference-purchase", "python", "-c", provider_probe)
    for sandbox_id in sandbox_ids:
        sandbox = _container_inspect(sandbox_id, "OpenClaw agent sandbox")
        sandbox_environment = _environment(sandbox, "OpenClaw agent sandbox")
        expected_sandbox_environment = (
            _AGENT_IMAGE_ENVIRONMENT | _AGENT_PROFILE_ENVIRONMENT | _AGENT_RUNTIME_ENVIRONMENT
        )
        if sandbox_environment != expected_sandbox_environment:
            missing = sorted(set(expected_sandbox_environment) - set(sandbox_environment))
            unexpected = sorted(set(sandbox_environment) - set(expected_sandbox_environment))
            wrong = sorted(
                name
                for name, value in expected_sandbox_environment.items()
                if sandbox_environment.get(name) not in (None, value)
            )
            raise MatrixError(
                "agent sandbox environment is not the exact reviewed profile "
                f"(missing={missing}, unexpected={unexpected}, wrong={wrong})"
            )
        if _GOVERNANCE_CREDENTIAL_ENVIRONMENT & set(sandbox_environment) or any(
            name.startswith("REFERENCE_PURCHASE_") for name in sandbox_environment
        ):
            raise MatrixError("agent sandbox received a governance or provider credential")
        sandbox_networks = sandbox.get("NetworkSettings")
        attached_sandbox_networks = (
            sandbox_networks.get("Networks") if isinstance(sandbox_networks, dict) else None
        )
        if not isinstance(attached_sandbox_networks, dict) or set(attached_sandbox_networks) != {
            _AGENT_NETWORK
        }:
            raise MatrixError("agent sandbox network membership is not isolated")
        sandbox_host_config = sandbox.get("HostConfig")
        if not isinstance(sandbox_host_config, dict):
            raise MatrixError("agent sandbox has no Docker host configuration")
        if sandbox_host_config.get("ReadonlyRootfs") is not True:
            raise MatrixError("agent sandbox root filesystem is writable")
        if set(sandbox_host_config.get("CapDrop") or []) != {"ALL"}:
            raise MatrixError("agent sandbox does not drop every capability")
        if "no-new-privileges" not in (sandbox_host_config.get("SecurityOpt") or []):
            raise MatrixError("agent sandbox permits privilege escalation")
        if set(sandbox_host_config.get("Tmpfs") or {}) != {"/tmp"}:
            raise MatrixError("agent sandbox tmpfs profile drifted")
        sandbox_mounts = sandbox.get("Mounts")
        if (
            not isinstance(sandbox_mounts, list)
            or len(sandbox_mounts) != 1
            or not isinstance(sandbox_mounts[0], dict)
            or sandbox_mounts[0].get("Type") != "bind"
            or sandbox_mounts[0].get("Destination") != "/workspace"
            or sandbox_mounts[0].get("RW") is not False
            or not isinstance(sandbox_mounts[0].get("Source"), str)
            or STATE_ROOT is None
            or not sandbox_mounts[0]["Source"].startswith(f"{STATE_ROOT}/sandbox-workspaces/")
        ):
            raise MatrixError("agent sandbox mounts are not the exact read-only session workspace")
        run(
            DOCKER,
            "exec",
            sandbox_id,
            "node",
            "-e",
            "fetch('http://masugated:8000/v1/pending', {signal: AbortSignal.timeout(2000)})"
            ".then(() => process.exit(1)).catch(() => process.exit(0))",
        )


def _remove_dynamic_agent_resources() -> None:
    """Remove dynamic sandboxes and their manually owned internal network."""

    sandbox_ids = _agent_sandbox_ids()
    for sandbox_id in sandbox_ids:
        # ``docker rm --force`` is asynchronous for a sandbox whose parent
        # Gateway has just restarted.  A concurrent daemon-side removal is a
        # successful cleanup state, not a live-gate failure.  Wait only for
        # that bounded transition and otherwise preserve a hard failure.
        deadline = time.monotonic() + 20
        while True:
            completed = subprocess.run(
                (DOCKER, "rm", "--force", sandbox_id),
                check=False,
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if completed.returncode == 0:
                break
            inspected = subprocess.run(
                (DOCKER, "inspect", sandbox_id),
                check=False,
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if inspected.returncode != 0:
                break
            if time.monotonic() >= deadline:
                raise MatrixError(
                    f"OpenClaw agent sandbox {sandbox_id} did not stop for live-gate cleanup"
                )
            time.sleep(0.2)
    if _agent_network_exists():
        deadline = time.monotonic() + 20
        while True:
            completed = subprocess.run(
                (DOCKER, "network", "rm", _AGENT_NETWORK),
                check=False,
                cwd=ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if completed.returncode == 0 or not _agent_network_exists():
                break
            if time.monotonic() >= deadline:
                raise MatrixError("OpenClaw agent network did not stop for live-gate cleanup")
            time.sleep(0.2)


def _prepare_dynamic_agent_network() -> None:
    """Give the pinned Gateway a fresh internal network for its session sandbox."""

    _remove_dynamic_agent_resources()
    run(DOCKER, "network", "create", "--internal", _AGENT_NETWORK)


def _clear_state_root_from_container() -> None:
    """Remove root-owned Gateway session files before TemporaryDirectory cleanup."""

    if STATE_ROOT is None:
        raise MatrixError("gateway recovery live state root is not initialized")
    if STATE_ROOT.parent != ROOT or not STATE_ROOT.name.startswith(
        ".masugate-gateway_recovery-gateway-"
    ):
        raise MatrixError("refusing to clear a state root outside the gateway recovery live oracle")
    run(
        DOCKER,
        "run",
        "--rm",
        "--volume",
        f"{STATE_ROOT}:/state:rw",
        "alpine:3.21",
        "sh",
        "-ec",
        "rm -rf /state/* /state/.[!.]* /state/..?*",
    )
    if any(STATE_ROOT.iterdir()):
        raise MatrixError("container-side cleanup left gateway recovery state behind")


def run(*args: str, capture: bool = False, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        args,
        cwd=ROOT,
        check=False,
        capture_output=capture,
        text=True,
        env=env,
    )
    if completed.returncode != 0:
        raise MatrixError(
            f"command failed ({' '.join(args)}):\n{completed.stdout}\n{completed.stderr}"
        )
    return completed.stdout


def compose(*args: str, capture: bool = False, hazard: str | None = None) -> str:
    if STATE_ROOT is None:
        raise MatrixError("gateway recovery live state root is not initialized")
    environment = dict(os.environ)
    environment["MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT"] = str(STATE_ROOT)
    environment["MASUGATE_GATEWAY_RECOVERY_HAZARD"] = hazard or ""
    return run(
        DOCKER,
        "compose",
        "-p",
        PROJECT,
        "-f",
        str(COMPOSE),
        "-f",
        str(GATEWAY_RECOVERY_COMPOSE),
        *args,
        capture=capture,
        env=environment,
    )


def wait_for(service: str, probe: str) -> None:
    deadline = time.monotonic() + 120
    logs = ""
    while time.monotonic() < deadline:
        try:
            compose("exec", "-T", service, "sh", "-ec", probe)
            return
        except MatrixError:
            logs = compose("logs", "--no-color", service, capture=True)
            time.sleep(1)
    raise MatrixError(f"{service} did not become ready:\n{logs}")


def gateway_session(
    command: str, case_id: str, *, background: bool = False
) -> subprocess.Popen[str] | str:
    if background:
        if STATE_ROOT is None:
            raise MatrixError("gateway recovery live state root is not initialized")
        environment = dict(os.environ)
        environment["MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT"] = str(STATE_ROOT)
        environment["MASUGATE_GATEWAY_RECOVERY_HAZARD"] = os.environ.get(
            "MASUGATE_GATEWAY_RECOVERY_HAZARD", ""
        )
        return subprocess.Popen(
            (
                DOCKER,
                "compose",
                "-p",
                PROJECT,
                "-f",
                str(COMPOSE),
                "-f",
                str(GATEWAY_RECOVERY_COMPOSE),
                "exec",
                "-T",
                "openclaw-gateway",
                "node",
                "gateway-gateway_recovery-session.mjs",
                command,
                case_id,
            ),
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    return compose(
        "exec",
        "-T",
        "openclaw-gateway",
        "node",
        "gateway-gateway_recovery-session.mjs",
        command,
        case_id,
        capture=True,
    )


def _gateway_call(method: str, params: dict[str, object]) -> object:
    output = compose(*_gateway_call_args(method, params), capture=True)
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise MatrixError(f"Gateway RPC {method} did not emit JSON: {output}") from exc


def _gateway_call_args(method: str, params: dict[str, object]) -> tuple[str, ...]:
    return (
        "exec",
        "-T",
        "openclaw-gateway",
        "node",
        "node_modules/openclaw/openclaw.mjs",
        "gateway",
        "call",
        method,
        "--json",
        "--params",
        json.dumps(params, separators=(",", ":")),
    )


def _gateway_call_background(method: str, params: dict[str, object]) -> subprocess.Popen[str]:
    if STATE_ROOT is None:
        raise MatrixError("gateway recovery live state root is not initialized")
    environment = dict(os.environ)
    environment["MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT"] = str(STATE_ROOT)
    return subprocess.Popen(
        (
            DOCKER,
            "compose",
            "-p",
            PROJECT,
            "-f",
            str(COMPOSE),
            "-f",
            str(GATEWAY_RECOVERY_COMPOSE),
            *_gateway_call_args(method, params),
        ),
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def _approval_runtime_call(command: str, case_id: str, approval_id: str | None = None) -> object:
    """Use the pinned Gateway's local approval-runtime reviewer path."""

    args = (
        "exec",
        "-T",
        "openclaw-gateway",
        "node",
        "gateway-gateway_recovery-approval.mjs",
        command,
        case_id,
    ) + ((approval_id,) if approval_id is not None else ())
    output = compose(*args, capture=True)
    try:
        return json.loads(output)
    except json.JSONDecodeError as exc:
        raise MatrixError(f"Gateway approval runtime did not emit JSON: {output}") from exc


def _approval_runtime_call_background(
    command: str, case_id: str, approval_id: str | None = None
) -> subprocess.Popen[str]:
    """Start the same authorized reviewer without delaying an injected crash."""

    if STATE_ROOT is None:
        raise MatrixError("gateway recovery live state root is not initialized")
    environment = dict(os.environ)
    environment["MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT"] = str(STATE_ROOT)
    environment["MASUGATE_GATEWAY_RECOVERY_HAZARD"] = os.environ.get(
        "MASUGATE_GATEWAY_RECOVERY_HAZARD", ""
    )
    return subprocess.Popen(
        (
            DOCKER,
            "compose",
            "-p",
            PROJECT,
            "-f",
            str(COMPOSE),
            "-f",
            str(GATEWAY_RECOVERY_COMPOSE),
            "exec",
            "-T",
            "openclaw-gateway",
            "node",
            "gateway-gateway_recovery-approval.mjs",
            command,
            case_id,
            *((approval_id,) if approval_id is not None else ()),
        ),
        cwd=ROOT,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )


def _reviewer_event(
    process: subprocess.Popen[str], case_id: str, *, timeout: float
) -> dict[str, object]:
    """Read one bounded JSON event from a live native-approval reviewer."""

    if process.stdout is None:
        raise MatrixError("Gateway native approval reviewer has no stdout pipe")
    readable, _, _ = select.select([process.stdout], [], [], timeout)
    if not readable:
        raise MatrixError(f"Gateway native approval reviewer did not respond for {case_id}")
    line = process.stdout.readline()
    if not line:
        _, stderr = process.communicate()
        raise MatrixError(
            f"Gateway native approval reviewer exited before reporting {case_id}: {stderr}"
        )
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as exc:
        raise MatrixError(f"Gateway native approval reviewer emitted invalid JSON: {line}") from exc
    if not isinstance(payload, dict):
        raise MatrixError("Gateway native approval reviewer event was not an object")
    return payload


def start_native_reviewer(case_id: str) -> subprocess.Popen[str]:
    """Connect an actual Gateway approval client *before* the host tool call.

    OpenClaw expires a plugin approval if no eligible native reviewer exists
    when the request reaches the Gateway.  This watcher establishes that real
    host-side delivery route first; it never manufactures or resolves a
    request itself.
    """

    reviewer = _approval_runtime_call_background("WATCH", case_id)
    ready = _reviewer_event(reviewer, case_id, timeout=15)
    if ready != {"status": "ready"}:
        reviewer.kill()
        _, stderr = reviewer.communicate()
        raise MatrixError(
            f"Gateway native approval reviewer was not ready for {case_id}: {ready}\n{stderr}"
        )
    return reviewer


def wait_for_native_approval(reviewer: subprocess.Popen[str], case_id: str) -> str:
    """Return the one native record observed by the pre-connected reviewer."""

    event = _reviewer_event(reviewer, case_id, timeout=45)
    approval_id = event.get("id")
    if event.get("status") != "record" or not isinstance(approval_id, str):
        raise MatrixError(f"Gateway did not create a native approval for {case_id}: {event}")
    if not re.fullmatch(r"plugin:[0-9a-f-]{36}", approval_id):
        raise MatrixError(f"Gateway native approval id was not canonical: {approval_id!r}")
    try:
        _, stderr = reviewer.communicate(timeout=15)
    except subprocess.TimeoutExpired as exc:
        reviewer.kill()
        _, stderr = reviewer.communicate()
        raise MatrixError(
            f"Gateway native approval reviewer did not finish after observing {case_id}: {stderr}"
        ) from exc
    if reviewer.returncode != 0:
        raise MatrixError(f"Gateway native approval reviewer failed for {case_id}: {stderr}")
    return approval_id


def stop_native_reviewer(reviewer: subprocess.Popen[str] | None) -> None:
    """Avoid leaking the long-lived delivery-route client on a failing case."""

    if reviewer is None or reviewer.poll() is not None:
        return
    reviewer.terminate()
    try:
        reviewer.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        reviewer.kill()
        reviewer.communicate()


def resolve_native_approval(
    case_id: str, reviewer: subprocess.Popen[str], *, background: bool = False
) -> subprocess.Popen[str] | None:
    approval_id = wait_for_native_approval(reviewer, case_id)
    if background:
        return _approval_runtime_call_background("RESOLVE", case_id, approval_id)
    resolved = _approval_runtime_call("RESOLVE", case_id, approval_id)
    if not isinstance(resolved, dict) or resolved.get("id") != approval_id:
        raise MatrixError(f"Gateway did not resolve native approval {approval_id}")
    return None


def assert_no_second_native_approval(reviewer: subprocess.Popen[str], case_id: str) -> None:
    """Prove a same-session recovery retry reuses, rather than re-prompts, consent.

    The first real Gateway callback records allow-once in the bridge.  When a
    killed MasuGate process later yields an in-progress/recovery retry, the plugin
    must re-submit that already selected decision to MasuGate.  A new
    ``plugin.approval`` record would both contradict the supported adapter
    contract and let the matrix accidentally mask a double-prompt regression.
    """

    if reviewer.poll() is not None:
        _, stderr = reviewer.communicate()
        raise MatrixError(
            f"Gateway native approval reviewer ended before recovery retry for {case_id}: {stderr}"
        )
    if reviewer.stdout is None:
        raise MatrixError("Gateway native approval reviewer has no stdout pipe")
    readable, _, _ = select.select([reviewer.stdout], [], [], 8)
    if readable:
        event = _reviewer_event(reviewer, case_id, timeout=0)
        raise MatrixError(
            f"Gateway created a second native approval during recovery for {case_id}: {event}"
        )
    if reviewer.poll() is not None:
        _, stderr = reviewer.communicate()
        raise MatrixError(
            f"Gateway native approval reviewer ended during recovery retry for {case_id}: {stderr}"
        )


def _pending_id_from_created_session(case_id: str, output: str) -> str:
    match = re.search(
        rf"GATEWAY_RECOVERY_PENDING_READY:{re.escape(case_id)}:"
        r"([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})",
        output,
    )
    if match is None:
        raise MatrixError(f"Gateway session {case_id} did not return a canonical pending locator")
    return match.group(1)


def _operation_id_from_created_session(case_id: str, output: str) -> str:
    match = re.search(
        rf"GATEWAY_RECOVERY_PENDING_READY:{re.escape(case_id)}:"
        r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:"
        r"([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})",
        output,
    )
    if match is None:
        raise MatrixError(
            f"Gateway session {case_id} did not return a canonical operation identity"
        )
    return match.group(1)


def wait_for_native_handoff(
    operation_id: str, pending_id: str, session_key: str, session_id: str
) -> None:
    """Wait for the host's fire-and-forget callback to reach durable MasuGate state."""

    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            output = compose(
                "exec",
                "-T",
                "openclaw-gateway",
                "node",
                "-e",
                _NATIVE_HANDOFF_PROGRAM,
                operation_id,
                pending_id,
                session_key,
                session_id,
                capture=True,
            )
            if output.strip() == "ready":
                return
        except MatrixError:
            pass
        time.sleep(0.25)
    raise MatrixError("native approval callback did not record its MasuGate handoff")


def wait_for_terminal_recovery(operation_id: str) -> None:
    """Wait for the deployment worker to settle a crashed handoff.

    A real recovery worker must observe the durable record without a model
    repeatedly invoking ``masugate_resume_pending`` while the old dispatch lease
    is still live.  This read-only audit wait does not create a handoff or
    execute an effect; the following real Gateway session remains the oracle
    that carries the terminal result through the host tool pipeline.
    """

    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            output = compose(
                "exec",
                "-T",
                "openclaw-gateway",
                "node",
                "-e",
                _TERMINAL_RECOVERY_PROGRAM,
                operation_id,
                capture=True,
            )
            if output.strip() == "committed":
                return
        except MatrixError:
            pass
        time.sleep(0.5)
    raise MatrixError("crashed native approval handoff did not recover to a terminal result")


def _gateway_session_id(case_id: str) -> str:
    """Resolve the actual pinned-Gateway session generation for a session key."""

    expected_key = f"agent:buyer-alpha:gateway_recovery-{case_id}"
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        raw = _gateway_call("sessions.list", {"agentId": "buyer-alpha"})
        if isinstance(raw, dict) and isinstance(raw.get("sessions"), list):
            for entry in raw["sessions"]:
                if not isinstance(entry, dict) or entry.get("key") != expected_key:
                    continue
                session_id = entry.get("sessionId")
                if isinstance(session_id, str) and session_id:
                    return session_id
        time.sleep(0.25)
    raise MatrixError(f"Gateway did not expose a trusted session generation for {expected_key}")


def reap_resolution(process: subprocess.Popen[str], case_id: str) -> None:
    """Do not leave an RPC helper behind after the injected process death.

    A real Gateway may acknowledge the decision before its plugin callback
    finishes, or it may propagate the killed MasuGate request as an RPC error.
    Either is valid here: the retry below, its committed Gateway result, and
    the exact-one-effect/audit assertions are the recovery oracle.
    """

    try:
        process.communicate(timeout=60)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        stdout, stderr = process.communicate()
        raise MatrixError(
            f"Gateway approval RPC for {case_id} did not finish after injected crash:\n"
            f"{stdout}\n{stderr}"
        ) from exc


def wait_for_marker(hazard: str) -> None:
    if STATE_ROOT is None:
        raise MatrixError("gateway recovery live state root is not initialized")
    marker = STATE_ROOT / f"gateway_recovery-{hazard}.ready"
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        value = marker.read_text(encoding="utf-8") if marker.exists() else ""
        if value == "ready\n":
            return
        time.sleep(0.05)
    raise MatrixError(f"MasuGate deployment did not reach crash marker {hazard}")


def wait_for_session(process: subprocess.Popen[str], case_id: str, *, expected: str) -> str:
    stdout, stderr = process.communicate(timeout=150)
    if process.returncode != 0:
        raise MatrixError(
            f"Gateway session {case_id} failed:\n{stdout}\n{stderr}\n"
            f"fixture evidence:\n{_fixture_evidence_for_failure()}"
        )
    if f"GATEWAY_RECOVERY_{expected}:{case_id}:" not in stdout:
        raise MatrixError(
            f"Gateway session {case_id} did not return the expected {expected} boundary:\n{stdout}"
        )
    return stdout


def _fixture_evidence_for_failure() -> str:
    """Retain model-facing gateway evidence when a child session fails closed."""

    if STATE_ROOT is None:
        return "<gateway_recovery state root unavailable>"
    try:
        raw = json.loads(
            (STATE_ROOT / "gateway_recovery-gateway-session-evidence.json").read_text(
                encoding="utf-8"
            )
        )
        if not isinstance(raw, list) or not raw:
            return json.dumps(raw, sort_keys=True)
        latest = raw[-1]
        if isinstance(latest, dict) and isinstance(latest.get("results"), list):
            latest = {
                **latest,
                "results": latest["results"][-8:],
                "result_count": len(latest["results"]),
            }
        return json.dumps(latest, indent=2, sort_keys=True)
    except (OSError, json.JSONDecodeError):
        return "<no gateway_recovery Gateway fixture evidence>"


def _assert_one_effect(case_id: str, operation_id: str, pending_id: str, session_id: str) -> None:
    count = compose(
        "exec",
        "-T",
        "reference-purchase",
        "python",
        "-c",
        _EFFECT_COUNT_PROGRAM,
        capture=True,
    ).strip()
    if count != "1":
        raise MatrixError(f"{case_id} produced {count!r} external purchase effects, expected one")
    if STATE_ROOT is None:
        raise MatrixError("gateway recovery live state root is not initialized")
    try:
        evidence = json.loads(
            (STATE_ROOT / "gateway_recovery-gateway-session-evidence.json").read_text()
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise MatrixError(
            "Gateway fixture did not persist gateway recovery session evidence"
        ) from exc
    if not isinstance(evidence, list):
        raise MatrixError("Gateway fixture evidence is not a session-event list")
    terminal_round_trip = any(
        isinstance(entry, dict)
        and entry.get("case") == case_id
        and entry.get("command") == "CONTINUE"
        and operation_id in entry.get("operation_ids", [])
        and "committed" in entry.get("result_statuses", [])
        for entry in evidence
    )
    if not terminal_round_trip:
        raise MatrixError(
            "Gateway evidence omitted the exact committed terminal operation from its session path"
        )
    audit = compose(
        "exec",
        "-T",
        "openclaw-gateway",
        "node",
        "-e",
        _AUDIT_PROGRAM,
        operation_id,
        pending_id,
        f"agent:buyer-alpha:gateway_recovery-{case_id}",
        session_id,
        case_id,
        capture=True,
    )
    if '"status":"committed"' not in audit.replace(" ", ""):
        raise MatrixError("terminal audit does not preserve committed native-approval evidence")


def _restart_gateway() -> None:
    compose("restart", "openclaw-gateway")
    wait_for("openclaw-gateway", _GATEWAY_HEALTH_PROBE)


def _restart_masugated() -> None:
    compose("restart", "masugated")
    wait_for(
        "masugated",
        _MASUGATED_HEALTH_PROBE,
    )


def _assert_real_session_sandbox(
    expected: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    sandboxes = _agent_sandbox_ids()
    if len(sandboxes) != 1:
        raise MatrixError("pinned Gateway session did not create an OpenClaw sandbox container")
    if expected is not None and sandboxes != expected:
        raise MatrixError("Gateway session changed or leaked its owned sandbox container")
    return sandboxes


def run_case(case_id: str, hazard: str | None) -> None:
    global STATE_ROOT
    with tempfile.TemporaryDirectory(
        prefix=".masugate-gateway_recovery-gateway-", dir=ROOT
    ) as raw_root:
        STATE_ROOT = Path(raw_root)
        reviewer: subprocess.Popen[str] | None = None
        recovery_reviewer: subprocess.Popen[str] | None = None
        try:
            compose("down", "--volumes", "--remove-orphans")
            _prepare_dynamic_agent_network()
            compose("--profile", "sandbox-image", "build", "openclaw-agent-sandbox-image")
            compose(
                "up",
                "--build",
                "--detach",
                "--wait",
                "--wait-timeout",
                "180",
                "--force-recreate",
                hazard=hazard,
            )
            wait_for("openclaw-gateway", _GATEWAY_HEALTH_PROBE)
            created = gateway_session("CREATE", case_id)
            if (
                not isinstance(created, str)
                or f"GATEWAY_RECOVERY_PENDING_READY:{case_id}:" not in created
            ):
                raise MatrixError(
                    f"Gateway did not create a durable pending operation for {case_id}"
                )
            pending_id = _pending_id_from_created_session(case_id, created)
            operation_id = _operation_id_from_created_session(case_id, created)
            session_id = _gateway_session_id(case_id)
            sandboxes = _assert_real_session_sandbox()
            _assert_reference_provider_boundary(sandboxes)
            if case_id == "gateway-plugin-restart":
                _restart_gateway()
            elif case_id == "masugated-pending-restart":
                _restart_masugated()
            reviewer = start_native_reviewer(case_id)
            process = gateway_session("PRESENT", case_id, background=True)
            if not isinstance(process, subprocess.Popen):
                raise MatrixError("failed to start a pinned Gateway native-resume session")
            if _gateway_session_id(case_id) != session_id:
                raise MatrixError(
                    "Gateway changed the trusted session generation between "
                    "the governed action and native approval"
                )
            resolution = resolve_native_approval(case_id, reviewer, background=hazard is not None)
            reviewer = None
            # The pinned host deliberately does not await async onResolution.
            # The first turn must therefore prove native presentation only;
            # the next real Gateway turn re-enters MasuGate and receives terminal
            # authority after the callback's durable handoff/recovery.
            wait_for_session(process, case_id, expected="APPROVAL_PRESENTED")
            if hazard is not None:
                if not isinstance(resolution, subprocess.Popen):
                    raise MatrixError(
                        "crash hazard did not start an asynchronous Gateway resolution"
                    )
                wait_for_marker(hazard)
                compose("kill", "masugated")
                reap_resolution(resolution, case_id)
                _restart_masugated()
                wait_for_terminal_recovery(operation_id)
                # Keep a real eligible native reviewer connected while the
                # retry runs.  If the plugin double-prompts, the Gateway must
                # deliver a new plugin.approval.requested event and the oracle
                # fails rather than merely observing an expired request.
                recovery_reviewer = start_native_reviewer(case_id)
                process = gateway_session("CONTINUE", case_id, background=True)
                if not isinstance(process, subprocess.Popen):
                    raise MatrixError("failed to retry a pinned Gateway native-resume session")
                if _gateway_session_id(case_id) != session_id:
                    raise MatrixError("Gateway changed session generation during crash recovery")
                assert_no_second_native_approval(recovery_reviewer, case_id)
                stop_native_reviewer(recovery_reviewer)
                recovery_reviewer = None
            else:
                wait_for_native_handoff(
                    operation_id,
                    pending_id,
                    f"agent:buyer-alpha:gateway_recovery-{case_id}",
                    session_id,
                )
                recovery_reviewer = start_native_reviewer(case_id)
                process = gateway_session("CONTINUE", case_id, background=True)
                if not isinstance(process, subprocess.Popen):
                    raise MatrixError("failed to continue the pinned Gateway native-resume session")
                if _gateway_session_id(case_id) != session_id:
                    raise MatrixError(
                        "Gateway changed session generation before terminal native resume"
                    )
                assert_no_second_native_approval(recovery_reviewer, case_id)
                stop_native_reviewer(recovery_reviewer)
                recovery_reviewer = None
            wait_for_session(process, case_id, expected="COMMITTED")
            _assert_real_session_sandbox(sandboxes)
            _assert_one_effect(case_id, operation_id, pending_id, session_id)
        except Exception:
            try:
                print(
                    compose("logs", "--no-color", "--tail", "200", capture=True, hazard=hazard),
                    file=sys.stderr,
                )
            except MatrixError as log_error:
                print(
                    f"unable to collect gateway recovery failure logs: {log_error}", file=sys.stderr
                )
            raise
        finally:
            try:
                stop_native_reviewer(reviewer)
            finally:
                try:
                    try:
                        stop_native_reviewer(recovery_reviewer)
                    finally:
                        compose("down", "--volumes", "--remove-orphans", hazard=hazard)
                finally:
                    try:
                        _remove_dynamic_agent_resources()
                    finally:
                        try:
                            _clear_state_root_from_container()
                        finally:
                            STATE_ROOT = None


def main() -> None:
    run(DOCKER, "info", capture=True)
    for case_id, hazard in _CASES:
        run_case(case_id, hazard)
    print("gateway-recovery pinned Gateway native-approval crash matrix passed")


if __name__ == "__main__":
    try:
        main()
    except (MatrixError, subprocess.TimeoutExpired) as exc:
        print(f"gateway-recovery pinned Gateway crash matrix failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
