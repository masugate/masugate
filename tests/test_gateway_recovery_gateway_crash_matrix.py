"""Static and live acceptance coverage for the gateway recovery Gateway crash matrix."""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from contextlib import suppress
from pathlib import Path

import pytest

from masugate_openclaw_reference import gateway_recovery_live

ROOT = Path(__file__).parents[1]
CONTAINMENT = ROOT / "integrations" / "openclaw-reference" / "containment"
LIVE_ORACLE = ROOT / "scripts" / "run-gateway_recovery-gateway-crash-matrix.py"
DOCKER = os.environ.get("MASUGATE_DOCKER_BIN", "docker")


def _docker_available() -> bool:
    if shutil.which(DOCKER) is None and not Path(DOCKER).is_file():
        return False
    try:
        return (
            subprocess.run(
                [DOCKER, "info"],
                check=False,
                capture_output=True,
            ).returncode
            == 0
        )
    except OSError:
        # A local Docker Desktop/WSL bridge can be installed but temporarily
        # unavailable.  Local acceptance runs report that as unavailable;
        # the CI branch below still fails closed in that situation.
        return False


def test_gateway_recovery_topology_uses_real_processes() -> None:
    override = (CONTAINMENT / "compose.gateway_recovery.yaml").read_text(encoding="utf-8")
    dockerfile = (CONTAINMENT / "Dockerfile.gateway_recovery-reference").read_text(encoding="utf-8")
    gateway_dockerfile = (CONTAINMENT / "Dockerfile.gateway").read_text(encoding="utf-8")
    entrypoint = (
        ROOT / "src" / "masugate_openclaw_reference" / "gateway_recovery_live.py"
    ).read_text(encoding="utf-8")
    assert "Dockerfile.gateway_recovery-reference" in override
    assert "masugate_openclaw_reference.gateway_recovery_live" in override
    assert "masugate-governance-postgres" in override
    assert "reference-purchase" in override
    assert "MASUGATE_RESOLVER_TOKEN" in override
    purchase = override.split("  reference-purchase:\n", 1)[1]
    assert "MASUGATE_BUYER_ALPHA_TOKEN" not in purchase
    assert "MASUGATE_RESOLVER_TOKEN" not in purchase
    assert "MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT" not in purchase
    assert "MASUGATE_GATEWAY_RECOVERY_STATE_ROOT" not in purchase
    assert "MASUGATE_REFERENCE_CREDENTIAL_MANIFEST_JSON" in purchase
    assert "masugate-gateway_recovery-purchase-state:/reference-purchase-state" in purchase
    assert "COPY connectors/sdk/src ./connectors/sdk/src" in dockerfile
    assert "pip install --no-cache-dir ./connectors/sdk . ./clients/python" in dockerfile
    assert "COPY clients/python/src ./clients/python/src" in dockerfile
    assert "./clients/python" in dockerfile
    assert "COPY integrations/openclaw/dist" not in gateway_dockerfile
    assert "COPY integrations/openclaw/src ./masugate-plugin/src" in gateway_dockerfile
    assert "tsc -p ./masugate-plugin/tsconfig.json" in gateway_dockerfile
    assert "./node_modules/@masugate/client" in gateway_dockerfile
    assert "build_postgres_reference_spend_resource" in entrypoint
    assert "HttpReferencePurchaseApi" in entrypoint
    assert "create_reference_purchase_api_app" in entrypoint


def test_gateway_recovery_purchase_process_uses_connector_and_precomputed_manifest_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("REFERENCE_PURCHASE_SERVICE_TOKEN", "reference-containment-connector-token")
    monkeypatch.setenv(
        "MASUGATE_REFERENCE_CREDENTIAL_MANIFEST_JSON",
        '{"connector_credential_fingerprint":"ca22ffe6801be8e3ac5ae59e5dc702d87888d6797f92ccc5e309d463a9602358",'
        '"masugate_bearer_credential_fingerprints":["3ca698f5cd94edc0f19843cf662e4acbfa2a3e8d0b6c2a45a7fcbf970139c869",'
        '"ef0b2a7e6f68563271cbb3ec57246b0f30d8c0491875896c4d6bdc6227f13ce6"]}',
    )
    monkeypatch.delenv("MASUGATE_BUYER_ALPHA_TOKEN", raising=False)
    monkeypatch.delenv("MASUGATE_RESOLVER_TOKEN", raising=False)

    connector, manifest = gateway_recovery_live._purchase_credentials()

    assert connector == "reference-containment-connector-token"
    assert manifest.validates_connector_credential(connector)
    assert len(manifest.masugate_bearer_credential_fingerprints) == 2


def test_gateway_recovery_oracle_drives_gateway_session_and_native_approval_rpc() -> None:
    source = LIVE_ORACLE.read_text(encoding="utf-8")
    fixture = (CONTAINMENT / "gateway-model-fixture.mjs").read_text(encoding="utf-8")
    entrypoint = (CONTAINMENT / "gateway-entrypoint.mjs").read_text(encoding="utf-8")
    session = (CONTAINMENT / "gateway-gateway_recovery-session.mjs").read_text(encoding="utf-8")
    approval = (CONTAINMENT / "gateway-gateway_recovery-approval.mjs").read_text(encoding="utf-8")
    assert 'client.request("chat.send"' in session
    assert 'event?.event !== "chat"' in session
    assert "GatewayClient" in session
    assert "plugin.approval.resolve; waiting for" in session
    assert "acknowledged run id plus the reviewer event" in session
    assert "/v1/chat/completions" not in session
    assert '"plugin.approval.resolve"' in approval
    assert '"plugin.approval.requested"' in approval
    assert 'request?.toolName === "masugate_resume_pending"' in approval
    assert "config.plugins.entries.masugate.config.nativeApproval" in entrypoint
    assert "config.plugins.entries.masugate.config.agents" in entrypoint
    assert "config.plugins.entries.pvl" not in entrypoint
    assert 'command === "WATCH"' in approval
    assert 'console.log(JSON.stringify({ status: "ready" }))' in approval
    assert "start_native_reviewer(case_id)" in source
    assert "wait_for_native_approval(reviewer, case_id)" in source
    assert "OpenClaw expires a plugin approval if no eligible native reviewer exists" in source
    assert "gateway-gateway_recovery-approval.mjs" in source
    assert '"allow-once"' in source
    assert '"gateway-plugin-restart"' in source
    assert '"masugated-pending-restart"' in source
    assert '"before-handoff"' in source
    assert '"after-handoff"' in source
    assert '"after-provider"' in source
    assert '"masugate_resume_pending"' in fixture
    assert "function textLeaves(value)" in fixture
    assert "const latestUser" in fixture
    assert "textLeaves(latestUser?.content)" in fixture
    assert "(?:^|\\s)GATEWAY_RECOVERY_(CREATE|PRESENT|CONTINUE)" in fixture
    assert ".filter(Boolean)\n    .at(-1)" in fixture
    assert "function toolPayloads(messages)" in fixture
    assert "function operationId(messages)" in fixture
    assert "payload.status === status" in fixture
    assert "function hasResumeResult(messages)" in fixture
    assert 'message.tool_call_id.includes("gateway_recoveryresume")' in fixture
    assert "GATEWAY_RECOVERY_APPROVAL_PRESENTED" in fixture
    assert "createOpenClawCodingTools" not in fixture
    assert "background=hazard is not None" in source
    assert "reap_resolution(resolution, case_id)" in source
    assert "assert_no_second_native_approval(recovery_reviewer, case_id)" in source
    assert "Gateway created a second native approval during recovery" in source
    assert 'gateway_session("CONTINUE", case_id, background=True)' in source
    assert "Gateway changed the trusted session generation" in source
    assert "Gateway changed session generation during crash recovery" in source
    assert 'expected="APPROVAL_PRESENTED"' in source
    assert 'expected="COMMITTED"' in source
    assert "wait_for_native_handoff(" in source
    assert "native approval callback did not record its MasuGate handoff" in source
    assert "wait_for_terminal_recovery(operation_id)" in source
    assert "crashed native approval handoff did not recover to a terminal result" in source
    assert "the following real Gateway session remains the oracle" in source
    assert '"sandbox-image", "build", "openclaw-agent-sandbox-image"' in source
    assert "_prepare_dynamic_agent_network()" in source
    assert "_remove_dynamic_agent_resources()" in source
    assert "_clear_state_root_from_container()" in source
    assert '"sessions.list"' in source
    assert "pending provenance mismatch" in source
    assert "durable intent count mismatch" in source
    assert "_assert_reference_provider_boundary(sandboxes)" in source
    assert "unauthenticated provider reached governance endpoint" in source
    assert "reference-purchase environment is not the exact connector-only inventory" in source
    assert "agent sandbox environment is not the exact reviewed profile" in source
    assert "agent sandbox mounts are not the exact read-only session workspace" in source


def test_gateway_recovery_crash_hooks_pause_only_at_named_durable_boundaries() -> None:
    source = (ROOT / "src" / "masugate_openclaw_reference" / "gateway_recovery_live.py").read_text(
        encoding="utf-8"
    )
    hazards = '_HAZARDS = frozenset({"before-handoff", "after-handoff", "after-provider"})'
    assert hazards in source
    assert 'await _pause_at("before-handoff")' in source
    assert 'await _pause_at("after-handoff")' in source
    assert 'await _pause_at("after-provider")' in source
    assert "while not release.exists()" in source
    assert "_claim_one_shot_hazard" in source


def test_gateway_recovery_crash_hazard_is_durably_one_shot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("MASUGATE_GATEWAY_RECOVERY_STATE_ROOT", str(tmp_path))

    async def exercise() -> None:
        paused = asyncio.create_task(gateway_recovery_live._pause_at("before-handoff"))
        marker = tmp_path / "gateway_recovery-before-handoff.ready"
        for _ in range(20):
            if marker.exists():
                break
            await asyncio.sleep(0.01)
        assert marker.read_text(encoding="utf-8") == "ready\n"
        paused.cancel()
        with suppress(asyncio.CancelledError):
            await paused
        await asyncio.wait_for(gateway_recovery_live._pause_at("before-handoff"), timeout=0.1)

    asyncio.run(exercise())
    assert (tmp_path / "gateway_recovery-before-handoff.claimed").read_text(
        encoding="utf-8"
    ) == "claimed\n"
    assert gateway_recovery_live._claim_one_shot_hazard("after-handoff")


@pytest.mark.gateway_recovery_crash_live
def test_pinned_gateway_native_approval_crash_matrix() -> None:
    if not _docker_available():
        if os.environ.get("CI"):
            pytest.fail(
                "gateway recovery pinned Gateway crash matrix requires a reachable Docker daemon"
            )
        pytest.skip(
            "gateway recovery pinned Gateway crash matrix requires a reachable Docker daemon"
        )
    existing_state_roots = set(ROOT.glob(".masugate-gateway_recovery-gateway-*"))
    completed = subprocess.run(
        [sys.executable, str(LIVE_ORACLE)],
        check=False,
        cwd=ROOT,
        text=True,
        capture_output=True,
        env=dict(os.environ),
        timeout=1_800,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "gateway-recovery pinned Gateway native-approval crash matrix passed" in completed.stdout
    new_state_roots = set(ROOT.glob(".masugate-gateway_recovery-gateway-*")) - existing_state_roots
    assert not new_state_roots, "gateway recovery crash matrix left generated state behind"
