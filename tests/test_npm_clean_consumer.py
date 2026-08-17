"""Unit coverage for the offline npm clean-consumer verifier."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]


def _consumer() -> Any:
    path = ROOT / "scripts" / "verify-npm-clean-consumer.py"
    spec = importlib.util.spec_from_file_location("npm_clean_consumer", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_exact_overrides_exclude_ambiguous_host_and_own_packages() -> None:
    consumer = _consumer()
    overrides = consumer._exact_overrides(
        {
            "alpha": frozenset({"1.0.0"}),
            "ambiguous": frozenset({"1.0.0", "2.0.0"}),
            "openclaw": frozenset({"2026.7.1"}),
            "@masugate/client": frozenset({"0.1.1"}),
        }
    )
    assert overrides == {"alpha": "1.0.0"}


def test_consumer_lock_rejects_unapproved_external_version(tmp_path: Path) -> None:
    consumer = _consumer()
    release = tmp_path / "release"
    npm = release / "npm"
    npm.mkdir(parents=True)
    for filename in consumer.OWN_PACKAGES.values():
        (npm / filename).write_bytes(b"tarball")
    direct = {
        package: f"file:{(npm / filename).resolve()}"
        for package, filename in consumer.OWN_PACKAGES.items()
    }
    lock = {
        "packages": {
            "": {
                "name": "@masugate/clean-consumer",
                "dependencies": {**direct, "openclaw": "2026.7.1"},
            },
            "node_modules/example": {"version": "9.9.9"},
        }
    }
    with pytest.raises(consumer.CleanConsumerError, match="unapproved package version"):
        consumer._validate_consumer_lock(lock, {"example": frozenset({"1.0.0"})}, release)


def test_consumer_lock_rejects_stale_relative_own_package_resolution(tmp_path: Path) -> None:
    consumer = _consumer()
    release = tmp_path / "release"
    npm = release / "npm"
    npm.mkdir(parents=True)
    for filename in consumer.OWN_PACKAGES.values():
        (npm / filename).write_bytes(b"tarball")
    direct = {
        package: f"file:{(npm / filename).resolve()}"
        for package, filename in consumer.OWN_PACKAGES.items()
    }
    packages = {
        "": {
            "name": "@masugate/clean-consumer",
            "dependencies": {**direct, "openclaw": "2026.7.1"},
        }
    }
    for package, filename in consumer.OWN_PACKAGES.items():
        resolved = f"file:{(npm / filename).resolve()}"
        packages[f"node_modules/{package}"] = {
            "version": "0.1.1",
            "resolved": resolved,
        }
    packages["node_modules/@masugate/client"]["resolved"] = (
        "file:../old-build/masugate-client-0.1.1.tgz"
    )
    lock = {"packages": packages}
    with pytest.raises(consumer.CleanConsumerError, match="does not resolve the built tarball"):
        consumer._validate_consumer_lock(lock, {"openclaw": frozenset({"2026.7.1"})}, release)


def test_consumer_lock_allows_bundled_own_dependency_without_tarball_resolution(
    tmp_path: Path,
) -> None:
    consumer = _consumer()
    release = tmp_path / "release"
    npm = release / "npm"
    npm.mkdir(parents=True)
    for filename in consumer.OWN_PACKAGES.values():
        (npm / filename).write_bytes(b"tarball")
    direct = {
        package: f"file:{(npm / filename).resolve()}"
        for package, filename in consumer.OWN_PACKAGES.items()
    }
    packages: dict[str, dict[str, object]] = {
        "": {
            "name": "@masugate/clean-consumer",
            "dependencies": {**direct, "openclaw": "2026.7.1"},
        },
    }
    for package, filename in consumer.OWN_PACKAGES.items():
        packages[f"node_modules/{package}"] = {
            "version": "0.1.1",
            "resolved": f"file:{(npm / filename).resolve()}",
        }
    packages["node_modules/@masugate/openclaw/node_modules/@masugate/adapter-core"] = {
        "version": "0.1.1",
        "inBundle": True,
    }
    consumer._validate_consumer_lock(
        lock={"packages": packages},
        expected_versions={"openclaw": frozenset({"2026.7.1"})},
        release_dir=release,
    )
