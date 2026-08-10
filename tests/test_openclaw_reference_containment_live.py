"""Live Docker acceptance gate for the bounded reference containment reference profile."""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
LIVE_ORACLE = ROOT / "scripts" / "run-reference-containment-live.py"
DOCKER = os.environ.get("MASUGATE_DOCKER_BIN", "docker")


def _docker_available() -> bool:
    return (shutil.which(DOCKER) is not None or Path(DOCKER).is_file()) and subprocess.run(
        [DOCKER, "info"],
        check=False,
        capture_output=True,
    ).returncode == 0


def _oracle() -> Any:
    spec = importlib.util.spec_from_file_location("containment_live", LIVE_ORACLE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_containment_oracle_removes_only_its_compose_service_images(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oracle = _oracle()
    owned = tuple(sorted(oracle._COMPOSE_SERVICE_IMAGES))
    calls: list[tuple[str, ...]] = []
    listings = iter(("\n".join((*owned, owned[0], "unrelated:latest")) + "\n", ""))

    def run(*arguments: str, capture: bool = False, **_kwargs: object) -> str:
        calls.append(arguments)
        if arguments[1:3] == ("image", "ls"):
            assert capture is True
            return next(listings)
        return ""

    monkeypatch.setattr(oracle, "_run", run)
    oracle._remove_compose_service_images()
    assert "masugate-openclaw-reference-agent-sandbox:reference_containment" in owned
    assert [call for call in calls if call[1:3] == ("image", "rm")] == [
        (oracle._DOCKER, "image", "rm", image) for image in owned
    ]


def test_containment_oracle_attempts_image_cleanup_when_teardown_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oracle = _oracle()
    calls: list[str] = []

    def compose(*_arguments: str, **_kwargs: object) -> str:
        calls.append("down")
        raise oracle.LiveContainmentError("simulated Compose teardown failure")

    def remove_images() -> None:
        calls.append("images")
        raise oracle.LiveContainmentError("simulated image cleanup failure")

    monkeypatch.setattr(oracle, "_compose", compose)
    monkeypatch.setattr(oracle, "_remove_compose_service_images", remove_images)

    with pytest.raises(ExceptionGroup) as raised:
        oracle._cleanup_compose_project()

    assert calls == ["down", "images"]
    assert {str(error) for error in raised.value.exceptions} == {
        "simulated Compose teardown failure",
        "simulated image cleanup failure",
    }


def test_containment_oracle_removes_dynamic_sandbox_before_its_service_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oracle = _oracle()
    calls: list[str] = []

    monkeypatch.setattr(oracle, "_compose", lambda *_args, **_kwargs: calls.append("down"))
    monkeypatch.setattr(
        oracle,
        "_remove_dynamic_agent_resources",
        lambda: calls.append("dynamic-agents"),
    )
    monkeypatch.setattr(
        oracle,
        "_remove_compose_service_images",
        lambda: calls.append("images"),
    )

    oracle._cleanup_compose_project(remove_dynamic_agents=True)

    assert calls == ["down", "dynamic-agents", "images"]


def test_containment_oracle_accepts_a_sandbox_already_being_removed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oracle = _oracle()
    calls: list[tuple[str, ...]] = []

    monkeypatch.setattr(oracle, "_agent_sandbox_ids", lambda: ["sandbox-id"])
    monkeypatch.setattr(oracle, "_agent_network_exists", lambda: False)

    def run(arguments: tuple[str, ...], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 1)

    monkeypatch.setattr(oracle.subprocess, "run", run)
    oracle._remove_dynamic_agent_resources()

    assert calls == [
        (oracle._DOCKER, "rm", "--force", "sandbox-id"),
        (oracle._DOCKER, "inspect", "sandbox-id"),
    ]


@pytest.mark.containment_live
def test_live_profile_blocks_direct_agent_bypasses_and_keeps_safe_content_available() -> None:
    if not _docker_available():
        if os.environ.get("CI"):
            pytest.fail(
                "reference containment live containment acceptance requires a "
                "reachable Docker daemon"
            )
        pytest.skip(
            "reference containment live containment acceptance requires a reachable Docker daemon"
        )
    completed = subprocess.run(
        [sys.executable, str(LIVE_ORACLE)],
        check=False,
        cwd=ROOT,
        text=True,
        capture_output=True,
        env=dict(os.environ),
        timeout=300,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "reference-containment live containment acceptance passed" in completed.stdout
    assert not list(
        ROOT.glob(".masugate-reference_containment-containment-*")
    ), "live containment left a generated state root behind"
