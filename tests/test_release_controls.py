"""Release-control contract coverage."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]


def _controls() -> Any:
    path = ROOT / "scripts" / "verify-release-controls.py"
    spec = importlib.util.spec_from_file_location("release_controls", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _documentation() -> Any:
    path = ROOT / "scripts" / "verify-documentation.py"
    spec = importlib.util.spec_from_file_location("documentation", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_public_source_release_controls_are_immutable_and_bounded() -> None:
    _controls().verify()


def test_documentation_links_and_declared_public_surfaces_are_coherent() -> None:
    _documentation().verify()


def test_documentation_verifier_rejects_an_unledgered_docs_page(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    documentation = _documentation()
    (tmp_path / "README.md").write_text("# Candidate\n", encoding="utf-8")
    (tmp_path / "docs" / "claims").mkdir(parents=True)
    ledger = tmp_path / "docs" / "claims" / "reference-release-claims.json"
    ledger.write_text(
        '{"public_surfaces": [{"path": "README.md", "category": "project"}]}\n',
        encoding="utf-8",
    )
    (tmp_path / "docs" / "unledgered.md").write_text("# Unledgered\n", encoding="utf-8")
    monkeypatch.setattr(documentation, "ROOT", tmp_path)
    monkeypatch.setattr(documentation, "LEDGER", ledger)

    with pytest.raises(
        documentation.DocumentationError,
        match="documentation page is absent from the public-surface ledger: docs/unledgered.md",
    ):
        documentation.verify()


@pytest.mark.parametrize(
    ("original", "replacement", "message"),
    (
        (
            "@11bd71901bbe5b1630ceea73d27597364c9af683",
            "@v4",
            "mutable or malformed action reference",
        ),
        ("push:\n", "workflow_dispatch:\n", "ci workflow must run"),
        (
            "python scripts/build-reference-release.py --verify-only",
            "# descriptor verification removed",
            "ci workflow is missing python scripts/build-reference-release.py --verify-only",
        ),
        (
            "python scripts/verify-documentation.py",
            "python scripts/verify-documentation.py\n          npm publish",
            "secret or publication command",
        ),
    ),
)
def test_release_control_verifier_rejects_unsafe_workflow_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, original: str, replacement: str, message: str
) -> None:
    controls = _controls()
    candidate = tmp_path / "ci.yml"
    source = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    candidate.write_text(source.replace(original, replacement, 1), encoding="utf-8")
    monkeypatch.setitem(controls.WORKFLOWS, "ci.yml", candidate)

    with pytest.raises(controls.ReleaseControlError, match=message):
        controls.verify()


def test_release_control_verifier_rejects_misnested_project_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controls = _controls()
    candidate = tmp_path / "pyproject.toml"
    candidate.write_text(
        "[project]\n"
        "name = \"candidate\"\n"
        "version = \"0.1.0\"\n\n"
        "[project.urls]\n"
        "Homepage = \"https://github.com/masugate/masugate\"\n"
        "Source = \"https://github.com/masugate/masugate\"\n"
        "Issues = \"https://github.com/masugate/masugate/issues\"\n"
        "dependencies = []\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(controls, "ROOT", tmp_path)

    with pytest.raises(controls.ReleaseControlError, match="Python package dependencies are invalid"):
        controls._validate_project_python_metadata()


def test_release_control_verifier_rejects_a_scheduled_disabled_workflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    controls = _controls()
    candidate = tmp_path / "nightly.yml"
    source = (ROOT / ".github" / "workflows" / "nightly.yml").read_text(encoding="utf-8")
    candidate.write_text(
        source.replace(
            "  workflow_dispatch:\n",
            "  schedule:\n    - cron: \"17 3 * * *\"\n  workflow_dispatch:\n",
            1,
        ),
        encoding="utf-8",
    )
    monkeypatch.setitem(controls.WORKFLOWS, "nightly.yml", candidate)

    with pytest.raises(controls.ReleaseControlError, match="must not schedule a disabled job"):
        controls.verify()
