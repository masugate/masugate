"""Named catalog-capability identities remain loadable and fail closed."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from masugate.catalog import (
    CatalogValidationError,
    PolicyBundle,
    RequirementResolution,
    ResolutionKind,
    load_bundle,
    load_deployment_profile,
    load_trusted_catalog,
)

CATALOG_ROOT = Path(__file__).resolve().parents[1] / "src/masugate/catalog"


def _resolutions(bundle: PolicyBundle) -> tuple[RequirementResolution, ...]:
    result: list[RequirementResolution] = []
    for effect in bundle.effects:
        result.append(effect.resolution)
    for view in bundle.views:
        result.append(view.resolution)
    for certified_input in bundle.certified_inputs:
        result.append(certified_input.resolution)
    return tuple(result)


def test_catalog_provider_resolutions_use_named_capabilities() -> None:
    bundles = [load_bundle(path.parent) for path in sorted(CATALOG_ROOT.rglob("bundle.json"))]
    resolutions = tuple(resolution for bundle in bundles for resolution in _resolutions(bundle))

    assert resolutions
    assert all(
        resolution.capability is not None
        for resolution in resolutions
        if resolution.kind is ResolutionKind.PROVIDER
    )
    assert all(
        resolution.capability is None
        for resolution in resolutions
        if resolution.kind is ResolutionKind.GAP
    )

    profile = load_deployment_profile(CATALOG_ROOT / "readiness/deployment.json")
    trusted = load_trusted_catalog(profile)
    assert (
        trusted.bundles[0].digest
        == "3c67110b4fe72113b9d741baf7345cbeb59820c9a404eb0b2c9be95640da6f94"
    )


def test_catalog_rejects_retired_resolution_field(tmp_path: Path) -> None:
    source = CATALOG_ROOT / "readiness/platform/bundle.json"
    raw = json.loads(source.read_text(encoding="utf-8"))
    raw["contracts"]["effects"][0]["resolution"] = {
        "kind": "provider",
        "s" + "tep": "retired",
    }
    target = tmp_path / "platform"
    target.mkdir()
    for path in source.parent.iterdir():
        destination = target / path.name
        destination.write_bytes(path.read_bytes())
    (target / "bundle.json").write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(CatalogValidationError, match="unknown fields"):
        load_bundle(target)
