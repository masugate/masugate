#!/usr/bin/env python3
"""Prepare every local input required by the credential-free reference demo."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
SOURCE_REVISION = "1373f5507c1680c60a7700d8a6c26a8b4d3fb025"
SOURCE_DATE_EPOCH = 1785365155
NODE_VERSION = "v24.16.0"
NPM_VERSION = "11.13.0"
UV_VERSION = "0.11.26"
LOCK = Path("release/requirements/reference-demo-build.requirements.lock")
CONTRACT = Path("integrations/openclaw-contract")
DEMO_IMAGE_KEYS = (
    "node_24_16_0_alpine",
    "docker_27_5_1_cli_alpine_3_21",
    "python_3_12_11_slim_bookworm",
    "nginx_1_27_5_alpine",
    "postgres_17_5_alpine",
    "alpine_3_21",
)
SECRET_ENV = re.compile(r"(?:TOKEN|PASSWORD|PASSWD|SECRET|CREDENTIAL|API_KEY|AUTH)$", re.IGNORECASE)
_CALLER_ENV_ALLOWLIST = ("PATH", "LANG", "LC_ALL", "TZ")
_NPM_CACHE_KEY_PREFIX = "make-fetch-happen:request-cache:"


class SetupError(RuntimeError):
    """Raised when a reviewer input cannot be prepared exactly."""


def _run(
    args: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args,
            cwd=cwd,
            env=env,
            check=True,
            text=True,
            capture_output=capture,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SetupError(f"setup command failed: {shlex.join(args)}") from exc


def _output(args: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    return _run(args, cwd=cwd, env=env, capture=True).stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_bytes(root: Path) -> int:
    return sum(path.stat().st_size for path in root.rglob("*") if path.is_file())


def _tool(path: str) -> str:
    resolved = shutil.which(path)
    if resolved is None:
        raise SetupError(f"required tool is not on PATH: {path}")
    return resolved


def _base_environment(outdir: Path) -> dict[str, str]:
    # Retrieval subprocesses receive only locale/tool-location context from the
    # caller. In particular, do not inherit proxies, alternate indexes,
    # registry overrides, netrc/home configuration, or authentication helpers.
    for name in ("empty-home", "empty-xdg-config", "empty-xdg-cache", "empty-docker-config"):
        (outdir / name).mkdir(exist_ok=True)
    environment = {key: os.environ[key] for key in _CALLER_ENV_ALLOWLIST if key in os.environ}
    environment.update(
        {
            "HOME": str(outdir / "empty-home"),
            "XDG_CONFIG_HOME": str(outdir / "empty-xdg-config"),
            "XDG_CACHE_HOME": str(outdir / "empty-xdg-cache"),
            "DOCKER_CONFIG": str(outdir / "empty-docker-config"),
            "TMPDIR": "/tmp",
            "NO_PROXY": "*",
            "no_proxy": "*",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "PIP_CONFIG_FILE": "/dev/null",
            "UV_NO_CONFIG": "1",
            "UV_NO_PROGRESS": "1",
            "UV_PYTHON_DOWNLOADS": "never",
            "UV_CACHE_DIR": str(outdir / "uv-cache"),
            "UV_DEFAULT_INDEX": "https://pypi.org/simple",
            "NPM_CONFIG_AUDIT": "false",
            "NPM_CONFIG_FUND": "false",
            "NPM_CONFIG_IGNORE_SCRIPTS": "true",
            "NPM_CONFIG_REGISTRY": "https://registry.npmjs.org/",
            "NPM_CONFIG_UPDATE_NOTIFIER": "false",
            "NPM_CONFIG_USERCONFIG": str(outdir / "empty-npm-userconfig"),
            "NPM_CONFIG_GLOBALCONFIG": str(outdir / "empty-npm-globalconfig"),
            "NODE_DISABLE_COMPILE_CACHE": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "/bin/false",
        }
    )
    if any(SECRET_ENV.search(key) for key in environment):
        raise SetupError("credential-shaped variable entered the setup environment")
    return environment


def _versions(environment: dict[str, str]) -> dict[str, str]:
    if sys.version_info[:2] != (3, 12):
        raise SetupError("the reviewer setup requires CPython 3.12")
    if sys.platform != "linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
        raise SetupError("the reviewer setup requires Linux/amd64")
    git = _tool("git")
    node = _tool("node")
    npm = _tool("npm")
    uv = _tool("uv")
    docker = os.environ.get("MASUGATE_DOCKER_BIN", "docker")
    if shutil.which(docker) is None and not Path(docker).is_file():
        raise SetupError(f"required Docker CLI is not available: {docker}")
    versions = {
        "python": platform.python_version(),
        "git": _output([git, "--version"], env=environment),
        "node": _output([node, "--version"], env=environment),
        "npm": _output([npm, "--version"], env=environment),
        "uv": _output([uv, "--version"], env=environment),
        "docker_client_server": _output(
            [docker, "version", "--format", "{{.Client.Version}} {{.Server.Version}}"],
            env=environment,
        ),
        "docker_compose": _output([docker, "compose", "version", "--short"], env=environment),
        "docker_target": _output(
            [docker, "info", "--format", "{{.OSType}}/{{.Architecture}}"], env=environment
        ),
    }
    if versions["node"] != NODE_VERSION:
        raise SetupError(f"Node must be {NODE_VERSION}; found {versions['node']}")
    if versions["npm"] != NPM_VERSION:
        raise SetupError(f"npm must be {NPM_VERSION}; found {versions['npm']}")
    if not versions["uv"].startswith(f"uv {UV_VERSION} "):
        raise SetupError(f"uv must be {UV_VERSION}; found {versions['uv']}")
    if versions["docker_target"] != "linux/x86_64":
        raise SetupError(f"Docker must target linux/x86_64; found {versions['docker_target']}")
    versions["git_path"] = git
    versions["node_path"] = node
    versions["npm_path"] = npm
    versions["uv_path"] = uv
    versions["docker_path"] = docker
    return versions


def _clean_clone(outdir: Path, git: str, environment: dict[str, str]) -> tuple[Path, str]:
    if _output([git, "status", "--porcelain"], cwd=ROOT, env=environment):
        raise SetupError("reviewer setup must start from a clean Git candidate")
    revision = _output([git, "rev-parse", "HEAD"], cwd=ROOT, env=environment)
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise SetupError("candidate Git revision is not a full SHA-1 identity")
    candidate = outdir / "candidate"
    _run(
        [git, "clone", "--quiet", "--no-hardlinks", "--", str(ROOT), str(candidate)],
        env=environment,
    )
    _run([git, "remote", "remove", "origin"], cwd=candidate, env=environment)
    if _output([git, "rev-parse", "HEAD"], cwd=candidate, env=environment) != revision:
        raise SetupError("clean candidate clone changed the staging realization revision")
    return candidate, revision


def _prepare_python(
    outdir: Path, candidate: Path, versions: dict[str, str], environment: dict[str, str]
) -> Path:
    venv = outdir / "venv"
    _run(
        [versions["uv_path"], "--no-config", "venv", "--python", sys.executable, str(venv)],
        env=environment,
    )
    python = venv / "bin" / "python"
    _run(
        [
            versions["uv_path"],
            "--no-config",
            "pip",
            "install",
            "--python",
            str(python),
            "--default-index",
            "https://pypi.org/simple",
            "--require-hashes",
            "--requirements",
            str(candidate / LOCK),
        ],
        env=environment,
    )
    return python


def _npm_ci(
    npm: str, cwd: Path, cache: Path, environment: dict[str, str], *, offline: bool = False
) -> None:
    arguments = [npm, "ci"]
    if offline:
        arguments.append("--offline")
    arguments.extend(["--ignore-scripts", "--no-audit", "--no-fund", "--cache", str(cache)])
    _run(arguments, cwd=cwd, env=environment)


def _matches_npm_platform(raw: object, current: str) -> bool:
    if raw is None:
        return True
    if not isinstance(raw, list) or not all(isinstance(value, str) for value in raw):
        raise SetupError("OpenClaw contract package lock has invalid platform metadata")
    values = set(raw)
    if f"!{current}" in values:
        return False
    allowed = {value for value in values if not value.startswith("!")}
    return not allowed or current in allowed


def _cache_content_path(cache: Path, integrity: str) -> Path:
    digest = base64.b64decode(integrity.removeprefix("sha512-"), validate=True).hex()
    return cache / "content-v2" / "sha512" / digest[:2] / digest[2:4] / digest[4:]


def _cache_index_path(cache: Path, url: str) -> Path:
    digest = hashlib.sha256((_NPM_CACHE_KEY_PREFIX + url).encode("utf-8")).hexdigest()
    return cache / "index-v5" / digest[:2] / digest[2:4] / digest[4:]


def _contract_npm_cache_paths(contract: Path, cache: Path) -> set[Path]:
    try:
        lock = json.loads((contract / "package-lock.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SetupError("cannot read the OpenClaw contract package lock") from exc
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise SetupError("OpenClaw contract package lock has no packages object")
    expected: set[Path] = set()
    for label, package in packages.items():
        if not isinstance(label, str) or not isinstance(package, dict):
            raise SetupError("OpenClaw contract package lock contains an invalid package")
        if not (
            _matches_npm_platform(package.get("os"), "linux")
            and _matches_npm_platform(package.get("cpu"), "x64")
        ):
            continue
        url = package.get("resolved")
        integrity = package.get("integrity")
        if url is None and integrity is None:
            continue
        if not isinstance(url, str) or not isinstance(integrity, str):
            raise SetupError(f"OpenClaw contract package is not fully bound: {label}")
        parsed = urlparse(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "registry.npmjs.org"
            or parsed.port is not None
            or parsed.query
            or parsed.fragment
            or not integrity.startswith("sha512-")
        ):
            raise SetupError(f"OpenClaw contract package escaped the reviewed registry: {label}")
        try:
            digest = base64.b64decode(integrity.removeprefix("sha512-"), validate=True)
        except ValueError as exc:
            raise SetupError(f"OpenClaw contract package has invalid integrity: {label}") from exc
        if len(digest) != 64:
            raise SetupError(f"OpenClaw contract package has invalid integrity length: {label}")
        expected.add(_cache_content_path(cache, integrity))
        expected.add(_cache_index_path(cache, url))
    if not expected:
        raise SetupError("OpenClaw contract package lock has no Linux/x64 tarballs")
    return expected


def _prune_demo_npm_cache(cache: Path, contract: Path) -> None:
    """Remove only optional non-Linux/x64 cache entries excluded by the lock."""

    raw_cache = cache / "_cacache"
    if not raw_cache.is_dir() or raw_cache.is_symlink():
        raise SetupError("prepared demo npm cache has no regular _cacache directory")
    expected = _contract_npm_cache_paths(contract, raw_cache)
    actual: set[Path] = set()
    for path in sorted(raw_cache.rglob("*")):
        if path.is_symlink():
            raise SetupError(f"prepared demo npm cache contains a symbolic link: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise SetupError(f"prepared demo npm cache contains a non-regular entry: {path}")
        relative = path.relative_to(raw_cache).as_posix()
        if not (relative.startswith("content-v2/") or relative.startswith("index-v5/")):
            raise SetupError(f"prepared demo npm cache has an unexpected path: {relative}")
        actual.add(path)
    for path in sorted(actual - expected):
        path.unlink()
    for path in sorted(raw_cache.rglob("*"), reverse=True):
        if path.is_dir() and path != raw_cache and not any(path.iterdir()):
            path.rmdir()
    remaining = {path for path in raw_cache.rglob("*") if path.is_file()}
    if remaining != expected:
        raise SetupError("prepared demo npm cache does not match the reviewed Linux/x64 closure")


def _prepare_npm(
    outdir: Path, candidate: Path, npm: str, environment: dict[str, str]
) -> tuple[Path, Path]:
    build_cache = outdir / "build-npm-cache"
    demo_cache = outdir / "demo-npm-cache"
    _npm_ci(npm, candidate, build_cache, environment)
    contract = candidate / CONTRACT
    _npm_ci(npm, contract, demo_cache, environment)
    _npm_ci(npm, contract, demo_cache, environment, offline=True)
    for wrapper in (demo_cache / "_logs", demo_cache / "_update-notifier-last-checked"):
        if wrapper.is_dir() and not wrapper.is_symlink():
            shutil.rmtree(wrapper)
        elif wrapper.is_file() and not wrapper.is_symlink():
            wrapper.unlink()
    _prune_demo_npm_cache(demo_cache, contract)
    if {path.name for path in demo_cache.iterdir()} != {"_cacache"}:
        raise SetupError("prepared demo npm cache has an unexpected wrapper entry")
    return build_cache, demo_cache


def _build_release(
    outdir: Path,
    candidate: Path,
    python: Path,
    versions: dict[str, str],
    environment: dict[str, str],
) -> Path:
    release = outdir / "release"
    build_environment = dict(environment)
    build_environment["PATH"] = (
        f"{python.parent}:{Path(versions['node_path']).parent}:" + build_environment.get("PATH", "")
    )
    build_environment["PYTHONPATH"] = ":".join(
        str(candidate / relative)
        for relative in (
            "src",
            "clients/python/src",
            "connectors/sdk/src",
            "integrations/openclaw-reference/src",
            ".",
        )
    )
    _run(
        [
            str(python),
            "scripts/build-reference-release.py",
            "--outdir",
            str(release),
            "--source-revision",
            SOURCE_REVISION,
            "--source-date-epoch",
            str(SOURCE_DATE_EPOCH),
        ],
        cwd=candidate,
        env=build_environment,
    )
    return release


def _pull_images(
    outdir: Path, candidate: Path, docker: str, environment: dict[str, str]
) -> list[dict[str, str]]:
    descriptor = json.loads((candidate / "release/reference-release.json").read_text())
    images = descriptor.get("container_images")
    if not isinstance(images, dict):
        raise SetupError("reference descriptor has no container_images object")
    docker_config = outdir / "empty-docker-config"
    docker_config.mkdir(exist_ok=True)
    records: list[dict[str, str]] = []
    for key in DEMO_IMAGE_KEYS:
        reference = images.get(key)
        if not isinstance(reference, str) or "@sha256:" not in reference:
            raise SetupError(f"reference descriptor has no exact demo image: {key}")
        _run([docker, "--config", str(docker_config), "image", "pull", reference], env=environment)
        image_id = _output(
            [
                docker,
                "--config",
                str(docker_config),
                "image",
                "inspect",
                "--format",
                "{{.Id}}",
                reference,
            ],
            env=environment,
        )
        expected_id = "sha256:" + reference.rsplit("@sha256:", 1)[1]
        if image_id != expected_id:
            raise SetupError(f"pulled image identity differs: {reference}")
        records.append({"key": key, "reference": reference, "local_id": image_id})
    return records


def _remove_build_only_inputs(outdir: Path, candidate: Path) -> None:
    for path in (
        outdir / "build-npm-cache",
        outdir / "uv-cache",
        outdir / "empty-xdg-cache",
        candidate / "node_modules",
        candidate / CONTRACT / "node_modules",
        candidate / "clients/typescript/dist",
        candidate / "adapters/typescript/dist",
        candidate / "gateway/dist",
        candidate / "integrations/openclaw/dist",
    ):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)


def _write_environment(
    outdir: Path,
    candidate: Path,
    release: Path,
    demo_cache: Path,
    python: Path,
    docker: str,
) -> Path:
    pythonpath = ":".join(
        str(candidate / relative)
        for relative in (
            "src",
            "clients/python/src",
            "connectors/sdk/src",
            "integrations/openclaw-reference/src",
            ".",
        )
    )
    values = {
        "MASUGATE_REVIEWER_SETUP_DIR": str(outdir),
        "MASUGATE_CANDIDATE_DIR": str(candidate),
        "MASUGATE_REVIEWER_PYTHON": str(python),
        "MASUGATE_RELEASE_VERIFICATION_RELEASE_DIR": str(release),
        "MASUGATE_OFFLINE_NPM_CACHE": str(demo_cache),
        "MASUGATE_SOURCE_REVISION": SOURCE_REVISION,
        "MASUGATE_SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH),
        "MASUGATE_DOCKER_BIN": docker,
        "PYTHONPATH": pythonpath,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "NPM_CONFIG_OFFLINE": "true",
        "NPM_CONFIG_AUDIT": "false",
        "NPM_CONFIG_FUND": "false",
        "NPM_CONFIG_IGNORE_SCRIPTS": "true",
        "NPM_CONFIG_UPDATE_NOTIFIER": "false",
        "NODE_DISABLE_COMPILE_CACHE": "1",
    }
    path = outdir / "reviewer.env"
    path.write_text(
        "".join(f"export {key}={shlex.quote(value)}\n" for key, value in values.items()),
        encoding="utf-8",
    )
    return path


def prepare(outdir: Path) -> dict[str, Any]:
    started = time.monotonic()
    if outdir.exists() or outdir.is_symlink():
        raise SetupError(f"refusing to overwrite reviewer setup directory: {outdir}")
    outdir.mkdir(parents=True)
    for name in ("empty-npm-userconfig", "empty-npm-globalconfig"):
        (outdir / name).write_text("", encoding="utf-8")
    environment = _base_environment(outdir)
    versions = _versions(environment)
    candidate, candidate_revision = _clean_clone(outdir, versions["git_path"], environment)
    python = _prepare_python(outdir, candidate, versions, environment)
    _build_cache, demo_cache = _prepare_npm(outdir, candidate, versions["npm_path"], environment)
    release = _build_release(outdir, candidate, python, versions, environment)
    images = _pull_images(outdir, candidate, versions["docker_path"], environment)
    _remove_build_only_inputs(outdir, candidate)
    environment_path = _write_environment(
        outdir, candidate, release, demo_cache, python, versions["docker_path"]
    )
    record: dict[str, Any] = {
        "schema_version": "masugate.reviewer-setup/v1",
        "created_at": datetime.now(UTC).isoformat(),
        "candidate_revision": candidate_revision,
        "source_revision": SOURCE_REVISION,
        "source_date_epoch": SOURCE_DATE_EPOCH,
        "network_during_setup": True,
        "credentials": False,
        "caller_environment_allowlist": list(_CALLER_ENV_ALLOWLIST),
        "tools": {key: value for key, value in versions.items() if not key.endswith("_path")},
        "inputs": {
            str(LOCK): _sha256(candidate / LOCK),
            "package-lock.json": _sha256(candidate / "package-lock.json"),
            str(CONTRACT / "package-lock.json"): _sha256(
                candidate / CONTRACT / "package-lock.json"
            ),
        },
        "images": images,
        "paths": {
            "candidate": str(candidate),
            "python": str(python),
            "release": str(release),
            "offline_npm_cache": str(demo_cache),
            "environment": str(environment_path),
        },
        "setup_seconds": time.monotonic() - started,
    }
    record["retained_bytes_before_manifest"] = _tree_bytes(outdir)
    (outdir / "setup-manifest.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"MasuGate reviewer inputs: {environment_path}")
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--outdir",
        type=Path,
        default=Path("/tmp/masugate-reviewer-setup"),
        help="new disposable setup directory (default: /tmp/masugate-reviewer-setup)",
    )
    args = parser.parse_args()
    prepare(args.outdir.resolve())


if __name__ == "__main__":
    try:
        main()
    except SetupError as exc:
        print(f"reviewer setup failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
