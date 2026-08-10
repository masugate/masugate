"""Regression checks for the clean TypeScript release packaging order."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]


def _release_builder() -> Any:
    path = ROOT / "scripts" / "build-reference-release.py"
    spec = importlib.util.spec_from_file_location("reference_release_builder", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_npm_release_builds_the_workspace_before_packing_without_lifecycle_hooks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    builder = _release_builder()
    commands: list[list[str]] = []

    def capture(command: list[str], **_kwargs: object) -> None:
        commands.append(command)

    monkeypatch.setattr(
        builder.shutil,
        "which",
        lambda name: "/locked/npm" if name == "npm" else None,
    )
    monkeypatch.setattr(builder, "_run", capture)
    builder._build_npm(tmp_path, {"PATH": "/locked"})

    builds = commands[:4]
    assert builds == [
        ["/locked/npm", "run", "build", "--workspace", "@masugate/client"],
        ["/locked/npm", "run", "build", "--workspace", "@masugate/adapter-core"],
        ["/locked/npm", "run", "build", "--workspace", "@masugate/mcp-gateway"],
        ["/locked/npm", "run", "build", "--workspace", "@masugate/openclaw"],
    ]
    packs = commands[4:]
    assert len(packs) == 4
    assert all("--ignore-scripts=true" in command for command in packs)
    assert all("--ignore-scripts=false" not in command for command in packs)
