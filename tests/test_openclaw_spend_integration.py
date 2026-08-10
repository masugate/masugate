"""Real pinned OpenClaw host round trip for the bounded reference spend spend route."""

from __future__ import annotations

import asyncio
import json
import shutil
import socket
from pathlib import Path
from typing import Any

import httpx
import pytest
import uvicorn

from masugate.providers import SpendPolicy, SqliteReferencePurchaseApi
from masugate_openclaw_reference import (
    build_postgres_reference_spend_resource as build_postgres_openclaw_resource,
)
from masugate_openclaw_reference import (
    create_spend_reference_app,
)

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "integrations" / "openclaw-reference" / "test" / "masugated-roundtrip.mjs"
PLUGIN_DIST = ROOT / "integrations" / "openclaw" / "dist" / "src" / "plugin.js"
RESULT_PREFIX = "MASUGATE_RESULT:"


def _free_loopback_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


async def _wait_until_started(server: uvicorn.Server, task: asyncio.Task[None]) -> None:
    for _ in range(200):
        if server.started:
            return
        if task.done():
            task.result()
            raise AssertionError("reference spend server exited before accepting host requests")
        await asyncio.sleep(0.01)
    raise AssertionError("reference spend server did not start within two seconds")


def _roundtrip_result(stdout: bytes) -> dict[str, Any]:
    """Extract the fixture's one machine result amid pinned-host diagnostics."""

    output = stdout.decode("utf-8", errors="replace")
    payloads = [
        line.removeprefix(RESULT_PREFIX)
        for line in output.splitlines()
        if line.startswith(RESULT_PREFIX)
    ]
    assert len(payloads) == 1, f"expected one OpenClaw result line, got:\n{output}"
    result = json.loads(payloads[0])
    assert isinstance(result, dict), "OpenClaw result payload must be an object"
    return result


def test_openclaw_spend_roundtrip_parser_ignores_host_diagnostics() -> None:
    result = _roundtrip_result(
        b"[agents/tool-policy] tool policy removed 25 tool(s)\n"
        b'MASUGATE_RESULT:{"first":{"status":"committed"}}\n'
    )
    assert result["first"] == {"status": "committed"}


def test_openclaw_spend_roundtrip_parser_rejects_missing_or_duplicate_results() -> None:
    with pytest.raises(AssertionError, match="expected one OpenClaw result line"):
        _roundtrip_result(b"host diagnostic only\n")
    with pytest.raises(AssertionError, match="expected one OpenClaw result line"):
        _roundtrip_result(b"MASUGATE_RESULT:{}\nMASUGATE_RESULT:{}\n")


@pytest.mark.asyncio
@pytest.mark.postgres
async def test_real_openclaw_tool_commits_and_replays_one_reference_purchase(
    reference_postgres_dsn: str,
    tmp_path: Path,
) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable; the CI Node gate runs this test")
    assert PLUGIN_DIST.is_file(), "build @masugate/openclaw before running the integration suite"

    policy = SpendPolicy(budget_limit_cents=1_000, approval_threshold_cents=500)
    api = SqliteReferencePurchaseApi(tmp_path / "reference-purchase-api.sqlite")
    resource = build_postgres_openclaw_resource(
        dsn=reference_postgres_dsn,
        purchase_api=api,
        policy=policy,
        worker_id="openclaw-reference-worker",
        principals={
            "openclaw:buyer-alpha": {
                "team": "research",
                "masugate_require_adapter_invocation": True,
            },
            "openclaw:buyer-beta": {
                "team": "research",
                "masugate_require_adapter_invocation": True,
            },
            "operator": {"team": "operations", "masugate_operator": True},
        },
        token_principals={
            "buyer-token": "openclaw:buyer-alpha",
            "beta-token": "openclaw:buyer-beta",
            "operator-token": "operator",
        },
        fleet_roster={
            "agents": {
                "buyer-alpha": "MASUGATE_BUYER_ALPHA_TOKEN",
                "buyer-beta": "MASUGATE_BUYER_BETA_TOKEN",
            }
        },
        plugin_config={
            "agents": {
                "buyer-alpha": "MASUGATE_BUYER_ALPHA_TOKEN",
                "buyer-beta": "MASUGATE_BUYER_BETA_TOKEN",
            }
        },
        environment={
            "MASUGATE_BUYER_ALPHA_TOKEN": "buyer-token",
            "MASUGATE_BUYER_BETA_TOKEN": "beta-token",
        },
        operator_principals={"operator"},
    )
    app = create_spend_reference_app(resource)
    port = _free_loopback_port()
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="on")
    )
    server_task = asyncio.create_task(server.serve())
    await _wait_until_started(server, server_task)
    try:
        process = await asyncio.create_subprocess_exec(
            node,
            str(SCRIPT),
            f"http://127.0.0.1:{port}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=20)
        assert process.returncode == 0, stderr.decode("utf-8", errors="replace")
        result = _roundtrip_result(stdout)
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}") as client:
            audit_response = await client.get(
                result["first"]["audit_ref"],
                headers={"Authorization": "Bearer buyer-token"},
            )
        assert audit_response.status_code == 200, audit_response.text
        receipt = audit_response.json()
    finally:
        server.should_exit = True
        await asyncio.wait_for(server_task, timeout=5)

    first = result["first"]
    replay = result["replay"]
    assert first["status"] == "committed"
    assert first["replayed"] is False
    assert first["decision"]["policy_id"] == "spend_budget_guard"
    assert replay["status"] == "committed"
    assert replay["replayed"] is True
    assert replay["operation_id"] == first["operation_id"]
    assert replay["audit_ref"] == first["audit_ref"]
    pending = result["pending"]
    assert pending["status"] == "pending"
    assert pending["decision"]["effect"] == "escalate"
    race = result["race"]
    assert {operation["status"] for operation in race} == {"committed", "denied"}
    assert receipt["protected_execution"]["receipt"]["outcome"] == "succeeded"
    assert await api.effect_count() == 2
