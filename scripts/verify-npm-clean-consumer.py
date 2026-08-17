#!/usr/bin/env python3
"""Verify a release's npm tarballs in an offline, lock-derived clean consumer."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OWN_PACKAGES = {
    "@masugate/client": "masugate-client-0.1.1.tgz",
    "@masugate/adapter-core": "masugate-adapter-core-0.1.1.tgz",
    "@masugate/mcp-gateway": "masugate-mcp-gateway-0.1.1.tgz",
    "@masugate/openclaw": "masugate-openclaw-0.1.1.tgz",
}
IMPORT_SMOKE = """
import { MasuGateClient } from '@masugate/client';
import { GovernedToolRuntime } from '@masugate/adapter-core';
import { createGatewayServer } from '@masugate/mcp-gateway';
import { createMasuGateOpenClawPlugin } from '@masugate/openclaw';
const actual = {
  client: typeof MasuGateClient,
  adapter: typeof GovernedToolRuntime,
  gateway: typeof createGatewayServer,
  openclaw: typeof createMasuGateOpenClawPlugin,
};
if (Object.values(actual).some((value) => value !== 'function')) {
  throw new Error(`unexpected clean-consumer exports: ${JSON.stringify(actual)}`);
}
console.log(JSON.stringify(actual));
"""


class CleanConsumerError(RuntimeError):
    """The release tarballs or the derived consumer closure are invalid."""


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CleanConsumerError(f"cannot read JSON file: {path}") from exc
    if not isinstance(value, dict):
        raise CleanConsumerError(f"expected an object in {path}")
    return value


def _versions_by_name(lock: dict[str, Any]) -> dict[str, frozenset[str]]:
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise CleanConsumerError("source npm lock lacks a packages object")
    versions: dict[str, set[str]] = {}
    for location, record in packages.items():
        if (
            not isinstance(location, str)
            or "node_modules/" not in location
            or not isinstance(record, dict)
        ):
            continue
        version = record.get("version")
        if not isinstance(version, str):
            continue
        name = location.rsplit("node_modules/", 1)[-1]
        versions.setdefault(name, set()).add(version)
    return {name: frozenset(values) for name, values in versions.items()}


def _exact_overrides(versions: dict[str, frozenset[str]]) -> dict[str, str]:
    """Use only unambiguous source-lock versions and never override own tarballs."""

    excluded = {"openclaw", *OWN_PACKAGES}
    return {
        name: next(iter(values))
        for name, values in sorted(versions.items())
        if name not in excluded and len(values) == 1
    }


def _run(command: list[str], *, cwd: Path, env: dict[str, str]) -> None:
    try:
        subprocess.run(command, cwd=cwd, env=env, check=True)
    except FileNotFoundError as exc:
        raise CleanConsumerError(f"required executable is unavailable: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        raise CleanConsumerError(f"clean-consumer command failed: {' '.join(command)}") from exc


def _portable_lock(release_dir: Path) -> dict[str, Any]:
    marker = "file:__MASUGATE_RELEASE_NPM__"
    source = release_dir / "deployment" / "npm-clean-consumer-lock.json"
    try:
        text = source.read_text(encoding="utf-8")
    except OSError as exc:
        raise CleanConsumerError(f"cannot read clean-consumer lock template: {source}") from exc
    if marker not in text:
        raise CleanConsumerError("clean-consumer lock template has no release-path marker")
    try:
        value = json.loads(text.replace(marker, f"file:{(release_dir / 'npm').resolve()}"))
    except json.JSONDecodeError as exc:
        raise CleanConsumerError("clean-consumer lock template is invalid JSON") from exc
    if not isinstance(value, dict):
        raise CleanConsumerError("clean-consumer lock template must contain an object")
    return value


def _manifest_from_lock(lock: dict[str, Any]) -> dict[str, Any]:
    packages = lock.get("packages")
    root = packages.get("") if isinstance(packages, dict) else None
    if not isinstance(root, dict):
        raise CleanConsumerError("clean-consumer lock template lacks root metadata")
    dependencies = root.get("dependencies")
    if not isinstance(dependencies, dict):
        raise CleanConsumerError("clean-consumer lock template lacks dependencies")
    return {
        "name": root.get("name"),
        "version": root.get("version"),
        "private": True,
        "type": "module",
        "dependencies": dependencies,
    }


def _validate_consumer_lock(
    lock: dict[str, Any], expected_versions: dict[str, frozenset[str]], release_dir: Path
) -> None:
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise CleanConsumerError("consumer lock lacks a packages object")
    root = packages.get("")
    if not isinstance(root, dict) or root.get("name") != "@masugate/clean-consumer":
        raise CleanConsumerError("consumer lock does not describe the reviewed clean consumer")
    required_direct = set(OWN_PACKAGES) | {"openclaw"}
    dependencies = root.get("dependencies")
    if not isinstance(dependencies, dict) or required_direct - set(dependencies):
        raise CleanConsumerError("consumer lock omits a required direct dependency")
    for location, record in packages.items():
        if not isinstance(location, str) or not location or not isinstance(record, dict):
            continue
        version = record.get("version")
        if not isinstance(version, str):
            continue
        name = location.rsplit("node_modules/", 1)[-1]
        if name in OWN_PACKAGES:
            if location != f"node_modules/{name}":
                if record.get("inBundle") is True:
                    continue
                raise CleanConsumerError(
                    f"consumer has an unexpected nested own package: {location}"
                )
            if version != "0.1.1":
                raise CleanConsumerError(f"own package version drifted: {name}@{version}")
            expected = f"file:{((release_dir / 'npm') / OWN_PACKAGES[name]).resolve()}"
            if record.get("resolved") != expected:
                raise CleanConsumerError(f"consumer does not resolve the built tarball for {name}")
            continue
        allowed = expected_versions.get(name)
        if allowed is None or version not in allowed:
            raise CleanConsumerError(
                f"consumer selected an unapproved package version: {name}@{version}"
            )
    npm_dir = release_dir / "npm"
    for package, filename in OWN_PACKAGES.items():
        expected = f"file:{(npm_dir / filename).resolve()}"
        if dependencies.get(package) != expected:
            raise CleanConsumerError(f"consumer does not install the built tarball for {package}")


def verify(
    *,
    release_dir: Path,
    consumer_dir: Path,
    npm_cache: Path,
    npm: str = "npm",
    node: str = "node",
    source_lock: Path = ROOT / "package-lock.json",
) -> None:
    release_dir = release_dir.resolve()
    consumer_dir = consumer_dir.resolve()
    npm_cache = npm_cache.resolve()
    if not release_dir.is_dir() or not npm_cache.is_dir():
        raise CleanConsumerError("release directory and npm cache must exist")
    if consumer_dir.exists():
        if any(consumer_dir.iterdir()):
            raise CleanConsumerError("consumer directory must be new or empty")
    else:
        consumer_dir.mkdir(parents=True)
    matrix = _load_json(release_dir / "deployment" / "compatibility-matrix.json")
    host = matrix.get("pinned_host")
    if not isinstance(host, dict) or not isinstance(host.get("openclaw"), str):
        raise CleanConsumerError("compatibility matrix lacks the exact OpenClaw host")
    expected_versions = _versions_by_name(_load_json(source_lock))
    consumer_lock = _portable_lock(release_dir)
    _validate_consumer_lock(consumer_lock, expected_versions, release_dir)
    manifest = _manifest_from_lock(consumer_lock)
    if manifest["dependencies"].get("openclaw") != host["openclaw"]:
        raise CleanConsumerError(
            "clean-consumer lock OpenClaw host drifts from the compatibility matrix"
        )
    (consumer_dir / "package.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (consumer_dir / "package-lock.json").write_text(
        json.dumps(consumer_lock, indent=2) + "\n", encoding="utf-8"
    )
    environment = {**os.environ, "npm_config_cache": str(npm_cache)}
    tool_dirs = [str(tool.parent) for command in (npm, node) if (tool := Path(command)).is_file()]
    if tool_dirs:
        environment["PATH"] = os.pathsep.join([*tool_dirs, environment.get("PATH", "")])
    common = [
        "--offline",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--userconfig",
        "/dev/null",
    ]
    _run([npm, "ci", *common], cwd=consumer_dir, env=environment)
    _run([node, "--input-type=module", "--eval", IMPORT_SMOKE], cwd=consumer_dir, env=environment)
    print(
        "offline clean npm consumer installed exact source-lock versions and "
        "imported all release packages"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("release_dir", type=Path)
    parser.add_argument("consumer_dir", type=Path)
    parser.add_argument("npm_cache", type=Path)
    parser.add_argument("--npm", default="npm")
    parser.add_argument("--node", default="node")
    parser.add_argument("--source-lock", type=Path, default=ROOT / "package-lock.json")
    args = parser.parse_args()
    try:
        verify(
            release_dir=args.release_dir,
            consumer_dir=args.consumer_dir,
            npm_cache=args.npm_cache,
            npm=args.npm,
            node=args.node,
            source_lock=args.source_lock,
        )
    except CleanConsumerError as exc:
        raise SystemExit(f"clean npm consumer verification failed: {exc}") from exc


if __name__ == "__main__":
    main()
