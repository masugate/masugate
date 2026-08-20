#!/usr/bin/env python3
"""Build clean release artifacts, start the reference demonstration stack, and save evidence.

The six scenarios are intentionally small, disposable deployments.  They
use first-party wheels and the packed OpenClaw adapter from one verified
``build-reference-release.py`` output, not files copied from the checkout.
The checked-in Compose profile still supplies the fixed external image digests
and the locked OpenClaw host contract.  Every invocation writes machine-
readable evidence and tears the project down unless ``--keep-stack`` is set.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Literal, cast
from urllib.parse import urlparse
from uuid import UUID

from masugate.pss import History, Operation, ScopeAccess, TransitionKind, check_pss
from masugate.pss.model import ScopeValue
from masugate_openclaw_reference.audit_validation import (
    AuditValidationError,
    SpendAuditExpectation,
    validate_committed_spend_audit,
    validate_denied_spend_audit,
)
from masugate_openclaw_reference.audit_validation import (
    authorization_digest as _shared_authorization_digest,
)
from masugate_openclaw_reference.audit_validation import (
    validate_spend_authorization_anchor as _shared_spend_authorization_anchor,
)
from masugate_openclaw_reference.procurement_workload import REFERENCE_SPEND_DECISION_VALIDATOR

ROOT = Path(__file__).resolve().parents[1]
RELEASE_BUILDER = ROOT / "scripts" / "build-reference-release.py"
RELEASE_MANIFEST = ROOT / "release" / "reference-release.json"
DOCKER = os.environ.get("MASUGATE_DOCKER_BIN", "docker")

_OFFLINE_NPM_LOCK = ROOT / "integrations" / "openclaw-contract" / "package-lock.json"
_NPM_CACHE_KEY_PREFIX = "make-fetch-happen:request-cache:"


def _matches_npm_platform(raw: object, current: str) -> bool:
    if raw is None:
        return True
    if not isinstance(raw, list) or not all(isinstance(value, str) for value in raw):
        raise DemoRunnerError("OpenClaw contract package lock has invalid platform metadata")
    values = set(raw)
    if f"!{current}" in values:
        return False
    allowed = {value for value in values if not value.startswith("!")}
    return not allowed or current in allowed


def _locked_npm_tarballs() -> dict[str, str]:
    lock = json.loads(_OFFLINE_NPM_LOCK.read_text(encoding="utf-8"))
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        raise DemoRunnerError("OpenClaw contract package lock has no packages object")
    expected: dict[str, str] = {}
    for label, raw_package in packages.items():
        if not isinstance(label, str) or not isinstance(raw_package, dict):
            raise DemoRunnerError("OpenClaw contract package lock contains an invalid package")
        if not (
            _matches_npm_platform(raw_package.get("os"), "linux")
            and _matches_npm_platform(raw_package.get("cpu"), "x64")
        ):
            continue
        resolved = raw_package.get("resolved")
        integrity = raw_package.get("integrity")
        if resolved is None and integrity is None:
            continue
        if not isinstance(resolved, str) or not isinstance(integrity, str):
            raise DemoRunnerError(f"locked npm package is not fully bound: {label}")
        parsed = urlparse(resolved)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "registry.npmjs.org"
            or parsed.port is not None
            or parsed.query
            or parsed.fragment
            or not integrity.startswith("sha512-")
        ):
            raise DemoRunnerError(
                f"locked npm package escaped the exact registry/SHA-512 boundary: {label}"
            )
        try:
            digest = base64.b64decode(integrity.removeprefix("sha512-"), validate=True)
        except ValueError as exc:
            raise DemoRunnerError(
                f"locked npm package has invalid SHA-512 integrity: {label}"
            ) from exc
        if len(digest) != 64:
            raise DemoRunnerError(f"locked npm package has invalid SHA-512 length: {label}")
        prior = expected.setdefault(resolved, integrity)
        if prior != integrity:
            raise DemoRunnerError(f"one locked npm URL has conflicting integrity: {resolved}")
    if not expected:
        raise DemoRunnerError("OpenClaw contract package lock contains no resolved tarballs")
    return expected


def _cache_content_path(raw_cache: Path, integrity: str) -> Path:
    digest = base64.b64decode(integrity.removeprefix("sha512-"), validate=True).hex()
    return raw_cache / "content-v2" / "sha512" / digest[:2] / digest[2:4] / digest[4:]


def _cache_index_path(raw_cache: Path, key: str) -> Path:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return raw_cache / "index-v5" / digest[:2] / digest[2:4] / digest[4:]


def _validate_offline_npm_cache(cache: Path) -> str:
    if not cache.is_dir():
        raise DemoRunnerError(f"offline npm cache is not a directory: {cache}")
    entries = tuple(sorted(cache.iterdir()))
    if (
        len(entries) != 1
        or entries[0].name != "_cacache"
        or entries[0].is_symlink()
        or not entries[0].is_dir()
    ):
        raise DemoRunnerError(
            "offline npm cache root must contain exactly one non-symlink _cacache directory"
        )
    raw_cache = entries[0]
    expected = _locked_npm_tarballs()
    expected_content = {
        _cache_content_path(raw_cache, integrity) for integrity in expected.values()
    }
    expected_indexes = {
        _cache_index_path(raw_cache, _NPM_CACHE_KEY_PREFIX + url) for url in expected
    }
    actual_content: set[Path] = set()
    actual_indexes: set[Path] = set()
    for path in sorted(raw_cache.rglob("*")):
        if path.is_symlink():
            raise DemoRunnerError(f"offline npm cache contains a symbolic link: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise DemoRunnerError(f"offline npm cache contains a non-regular entry: {path}")
        relative = path.relative_to(raw_cache).as_posix()
        if not (relative.startswith("content-v2/") or relative.startswith("index-v5/")):
            raise DemoRunnerError(f"offline npm cache contains an unexpected path: {relative}")
        if relative.startswith("content-v2/"):
            actual_content.add(path)
        else:
            actual_indexes.add(path)
    if actual_content != expected_content or actual_indexes != expected_indexes:
        raise DemoRunnerError(
            "offline npm cache paths do not exactly match the checked-in OpenClaw contract lock"
        )
    for url, integrity in expected.items():
        content = _cache_content_path(raw_cache, integrity)
        raw = content.read_bytes()
        actual_integrity = "sha512-" + base64.b64encode(hashlib.sha512(raw).digest()).decode(
            "ascii"
        )
        if actual_integrity != integrity:
            raise DemoRunnerError(
                f"offline npm cache payload differs from package-lock integrity: {url}"
            )
    seen: set[str] = set()
    for path in sorted(actual_indexes):
        records = 0
        for line in path.read_bytes().splitlines():
            if not line:
                continue
            checksum, separator, encoded = line.partition(bytes((9,)))
            if (
                separator != bytes((9,))
                or hashlib.sha1(encoded).hexdigest().encode("ascii") != checksum
            ):
                raise DemoRunnerError(f"offline npm cache index checksum is invalid: {path}")
            try:
                record = json.loads(encoded)
            except json.JSONDecodeError as exc:
                raise DemoRunnerError(f"offline npm cache index is not JSON: {path}") from exc
            if not isinstance(record, dict):
                raise DemoRunnerError(f"offline npm cache index record is not an object: {path}")
            key = record.get("key")
            integrity = record.get("integrity")
            size = record.get("size")
            metadata = record.get("metadata")
            if not isinstance(key, str) or not key.startswith(_NPM_CACHE_KEY_PREFIX):
                raise DemoRunnerError(f"offline npm cache index has an invalid key: {path}")
            url = key.removeprefix(_NPM_CACHE_KEY_PREFIX)
            if expected.get(url) != integrity or _cache_index_path(raw_cache, key) != path:
                raise DemoRunnerError(f"offline npm cache index escaped the package lock: {url}")
            content = _cache_content_path(raw_cache, cast(str, integrity))
            if type(size) is not int or size != content.stat().st_size:
                raise DemoRunnerError(f"offline npm cache index has an invalid payload size: {url}")
            if not isinstance(metadata, dict) or metadata.get("url") != url:
                raise DemoRunnerError(f"offline npm cache index has an invalid source URL: {url}")
            seen.add(url)
            records += 1
        if records == 0:
            raise DemoRunnerError(f"offline npm cache index has no records: {path}")
    if seen != set(expected):
        raise DemoRunnerError("offline npm cache does not cover every package-lock tarball")
    rows = "".join(f"{url}\0{expected[url]}\n" for url in sorted(expected)).encode("utf-8")
    return hashlib.sha256(rows).hexdigest()


def _copy_offline_npm_cache(cache: Path, artifacts: Path) -> None:
    source = cache.resolve()
    source_digest = _validate_offline_npm_cache(source)
    destination = artifacts / "offline" / "npm" / "cache"
    shutil.copytree(source, destination)
    if _validate_offline_npm_cache(destination) != source_digest:
        raise DemoRunnerError("copied offline npm cache does not bind the checked-in package lock")


_STATE_CLEANUP_IMAGE = (
    "alpine:3.21@sha256:48b0309ca019d89d40f670aa1bc06e426dc0931948452e8491e3d65087abc07d"
)
_EVIDENCE_SCHEMA = "masugate.reference_demo-demo-evidence/v3"
_RELEASE_DESCRIPTOR_SCHEMA = "masugate.reference_demo-release-descriptor/v1"
_RUNTIME_TARGET = {
    "os": "linux",
    "architecture": "amd64",
    "python_abi": "cp312",
}
_PROVIDER_ID = "masugate.spend.reference"
_PROVIDER_IMPLEMENTATION = "masugate.spend.reference-v1"
_CONNECTOR_ID = "reference-purchase-v1"
_ACTION = "spend.purchase"
_SCENARIOS = ("race", "stale-approval", "blast-radius", "receipt", "recovery", "procurement")
_FIVE_DEMOS = _SCENARIOS[:5]

_EXPECTED_REQUESTS: dict[str, tuple[str, dict[str, object], str]] = {
    "reference_demo-e2-alpha": (
        "openclaw:buyer-alpha",
        {
            "amount_cents": 6_000,
            "merchant_id": "reference-demo-procurement",
            "request_ref": "reference_demo-e2-alpha",
        },
        "preserved-admission-evaluation",
    ),
    "reference_demo-e2-beta": (
        "openclaw:buyer-beta",
        {
            "amount_cents": 6_000,
            "merchant_id": "reference-demo-procurement",
            "request_ref": "reference_demo-e2-beta",
        },
        "preserved-admission-evaluation",
    ),
    "reference_demo-revalidation": (
        "openclaw:buyer-alpha",
        {
            "amount_cents": 6_000,
            "merchant_id": "reference-demo-procurement",
            "request_ref": "reference_demo-revalidation",
        },
        "preserved-admission-evaluation",
    ),
    "reference_demo-blast-beta": (
        "openclaw:buyer-beta",
        {
            "amount_cents": 400,
            "merchant_id": "reference-demo-procurement",
            "request_ref": "reference_demo-blast-beta",
        },
        "admission-evaluation",
    ),
    "reference_demo-receipt": (
        "openclaw:buyer-alpha",
        {
            "amount_cents": 400,
            "merchant_id": "reference-demo-procurement",
            "request_ref": "reference_demo-receipt",
        },
        "admission-evaluation",
    ),
    "reference_demo-recovery": (
        "openclaw:buyer-alpha",
        {
            "amount_cents": 400,
            "merchant_id": "reference-demo-procurement",
            "request_ref": "reference_demo-recovery",
        },
        "admission-evaluation",
    ),
}
_SCENARIO_REQUEST_KEYS = {
    "race": frozenset({"reference_demo-e2-alpha", "reference_demo-e2-beta"}),
    "procurement": frozenset({"reference_demo-e2-alpha", "reference_demo-e2-beta"}),
    "stale-approval": frozenset({"reference_demo-revalidation"}),
    "blast-radius": frozenset({"reference_demo-blast-beta"}),
    "receipt": frozenset({"reference_demo-receipt"}),
    "recovery": frozenset({"reference_demo-recovery"}),
}
_EXPECTED_PRINCIPAL_ATTRIBUTES: dict[str, dict[str, object]] = {
    "openclaw:buyer-alpha": {
        "masugate_require_adapter_invocation": True,
        "team": "research",
    },
    "openclaw:buyer-beta": {
        "masugate_require_adapter_invocation": True,
        "team": "research",
    },
}
_HUMAN_RESOLUTION_SCENARIOS = {
    "race": "e2-procurement-race",
    "procurement": "e2-procurement-race",
    "stale-approval": "approval-replay",
}


class DemoRunnerError(RuntimeError):
    """The reproducible demo runner failed before producing valid evidence."""


def _run(
    arguments: Sequence[str],
    *,
    environment: dict[str, str],
    capture: bool = True,
    timeout: float | None = None,
) -> str:
    completed = subprocess.run(
        arguments,
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=capture,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise DemoRunnerError(
            f"command failed ({' '.join(arguments)}):\n{completed.stdout}\n{completed.stderr}"
        )
    return completed.stdout


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_digest(value: object) -> str:
    rendered = json.dumps(value, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def _sha256_string(value: object, label: str) -> str:
    rendered = _string(value, label)
    if len(rendered) != 64:
        raise DemoRunnerError(f"{label} must be a SHA-256 digest")
    try:
        int(rendered, 16)
    except ValueError as exc:
        raise DemoRunnerError(f"{label} must be a hexadecimal SHA-256 digest") from exc
    return rendered


def _json_file(path: Path, label: str) -> dict[str, object]:
    try:
        raw: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DemoRunnerError(f"{label} is not valid JSON: {path}") from exc
    if not isinstance(raw, dict):
        raise DemoRunnerError(f"{label} must be a JSON object: {path}")
    return cast(dict[str, object], raw)


def _safe_release_path(relative: object, label: str) -> PurePosixPath:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise DemoRunnerError(f"{label} contains an invalid artifact path")
    path = PurePosixPath(relative)
    if (
        path.is_absolute()
        or path.as_posix() != relative
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise DemoRunnerError(f"{label} contains an unsafe artifact path: {relative!r}")
    return path


def _artifact_inventory(release: Path) -> dict[str, str]:
    metadata = {"checksums.sha256", "provenance.json", "sbom.cdx.json"}
    inventory: dict[str, str] = {}
    for path in sorted(release.rglob("*")):
        if path.is_symlink():
            raise DemoRunnerError(f"release output contains a symbolic link: {path}")
        if not path.is_file():
            continue
        relative = path.relative_to(release).as_posix()
        if relative in metadata:
            continue
        inventory[relative] = _sha256(path)
    if not inventory:
        raise DemoRunnerError("release output contains no artifacts")
    return inventory


def _checksum_inventory(checksums: Path) -> dict[str, str]:
    inventory: dict[str, str] = {}
    for line in checksums.read_text(encoding="utf-8").splitlines():
        digest, separator, raw_relative = line.partition("  ")
        relative = _safe_release_path(raw_relative, "release checksums").as_posix()
        if not separator or len(digest) != 64:
            raise DemoRunnerError("release checksum file has an invalid line")
        try:
            int(digest, 16)
        except ValueError as exc:
            raise DemoRunnerError("release checksum contains a non-hexadecimal digest") from exc
        if relative in inventory:
            raise DemoRunnerError(f"release checksum path is duplicated: {relative}")
        inventory[relative] = digest
    return inventory


def _provenance_inventory(provenance: dict[str, object]) -> dict[str, str]:
    raw_artifacts = provenance.get("artifacts")
    if not isinstance(raw_artifacts, list):
        raise DemoRunnerError("release provenance artifacts must be a list")
    inventory: dict[str, str] = {}
    for raw in raw_artifacts:
        artifact = _mapping(raw, "release provenance artifact")
        relative = _safe_release_path(artifact.get("path"), "release provenance").as_posix()
        digest = artifact.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64:
            raise DemoRunnerError("release provenance contains an invalid digest")
        try:
            int(digest, 16)
        except ValueError as exc:
            raise DemoRunnerError("release provenance contains a non-hexadecimal digest") from exc
        if relative in inventory:
            raise DemoRunnerError(f"release provenance path is duplicated: {relative}")
        inventory[relative] = digest
    return inventory


def _current_source_revision() -> str:
    return _run(
        ("git", "rev-parse", "HEAD"),
        environment=dict(os.environ),
    ).strip()


def _validate_spend_authorization_anchor(value: object) -> dict[str, object]:
    try:
        return _shared_spend_authorization_anchor(value)
    except AuditValidationError as exc:
        raise DemoRunnerError(f"reference artifact {exc}") from exc


def _spend_authorization_anchor_from_manifest(
    manifest: Mapping[str, object],
) -> dict[str, object]:
    declared = _mapping(
        manifest.get("reference_demo_spend_authorization"),
        "release reference artifact spend authorization",
    )
    if set(declared) != {"configuration", "configuration_digest", "policy"}:
        raise DemoRunnerError("release reference artifact spend authorization has the wrong shape")
    configuration = _mapping(
        declared.get("configuration"), "release reference artifact spend configuration"
    )
    if configuration != {
        "approval_threshold_cents": 500,
        "approval_timeout_seconds": 600,
        "budget_limit_cents": 10_000,
        "scope_derivation": "masugate.spend.reference.scopes.v1",
    }:
        raise DemoRunnerError("release reference artifact spend configuration is incompatible")
    policy = _mapping(declared.get("policy"), "release reference artifact spend policy")
    expected_configuration_digest = _canonical_digest(
        {
            "approval_threshold_cents": configuration["approval_threshold_cents"],
            "approval_timeout_seconds": configuration["approval_timeout_seconds"],
            "bundle_id": policy.get("bundle_id"),
            "bundle_version": policy.get("bundle_version"),
            "budget_limit_cents": configuration["budget_limit_cents"],
            "policy_id": policy.get("policy_id"),
            "policy_version": policy.get("policy_declared_version"),
            "scope_derivation": configuration["scope_derivation"],
        }
    )
    if declared.get("configuration_digest") != expected_configuration_digest:
        raise DemoRunnerError(
            "release reference artifact spend configuration digest is inconsistent"
        )
    return _validate_spend_authorization_anchor(
        {
            "configuration_digest": expected_configuration_digest,
            "policy": policy,
        }
    )


def _verify_release_output(
    release: Path,
    *,
    expected_source_revision: str,
    expected_staging_realization_revision: str,
) -> dict[str, object]:
    """Verify the generated release manifest before any container build sees it."""

    checksums = release / "checksums.sha256"
    sbom = release / "sbom.cdx.json"
    provenance = release / "provenance.json"
    if not checksums.is_file() or not sbom.is_file() or not provenance.is_file():
        raise DemoRunnerError("release output is missing checksums, SBOM, or provenance")
    actual = _artifact_inventory(release)
    declared_checksums = _checksum_inventory(checksums)
    provenance_document = _json_file(provenance, "release provenance")
    declared_provenance = _provenance_inventory(provenance_document)
    if actual != declared_checksums or actual != declared_provenance:
        raise DemoRunnerError(
            "release artifact set, checksums, and provenance do not match exactly"
        )
    packaged_manifest_path = release / "deployment" / "reference-release.json"
    if not packaged_manifest_path.is_file():
        raise DemoRunnerError("release output is missing its packaged release manifest")
    packaged_manifest = _json_file(packaged_manifest_path, "packaged release manifest")
    current_manifest = _json_file(RELEASE_MANIFEST, "reference release manifest")
    if provenance_document.get("schema_version") != "masugate.reference-release.provenance/v1":
        raise DemoRunnerError("release provenance schema identity is incompatible")
    if provenance_document.get("release_id") != packaged_manifest.get("release_id"):
        raise DemoRunnerError("release provenance has the wrong release identity")
    if provenance_document.get("source_revision") != expected_source_revision:
        raise DemoRunnerError("release provenance was not built from the requested source revision")
    if (
        provenance_document.get("staging_realization_revision")
        != expected_staging_realization_revision
    ):
        raise DemoRunnerError(
            "release provenance was not built from the requested staging realization"
        )
    manifest_digest = provenance_document.get("release_manifest_sha256")
    if manifest_digest != _sha256(packaged_manifest_path):
        raise DemoRunnerError("release provenance has the wrong manifest digest")
    if manifest_digest != _sha256(RELEASE_MANIFEST) or packaged_manifest != current_manifest:
        raise DemoRunnerError("release manifest does not match the current source revision")
    if packaged_manifest.get("runtime_target") != _RUNTIME_TARGET:
        raise DemoRunnerError(
            "release manifest has an incompatible reference artifact runtime target"
        )
    source_epoch = provenance_document.get("source_date_epoch")
    if type(source_epoch) is not int or source_epoch <= 0:
        raise DemoRunnerError("release provenance has an invalid source date epoch")
    staging_epoch = provenance_document.get("staging_realization_date_epoch")
    if type(staging_epoch) is not int or staging_epoch <= 0:
        raise DemoRunnerError("release provenance has an invalid staging realization date epoch")
    environment = dict(os.environ)
    _run(
        (sys.executable, str(RELEASE_BUILDER), "--validate-sbom", str(sbom)),
        environment=environment,
    )
    release_id = _string(packaged_manifest.get("release_id"), "release ID")
    spend_authorization = _spend_authorization_anchor_from_manifest(packaged_manifest)
    return {
        "schema_version": _RELEASE_DESCRIPTOR_SCHEMA,
        "release_id": release_id,
        "source_revision": expected_source_revision,
        "staging_realization_revision": expected_staging_realization_revision,
        "release_manifest_sha256": _sha256(packaged_manifest_path),
        "provenance_sha256": _sha256(provenance),
        "checksums_sha256": _sha256(checksums),
        "sbom_sha256": _sha256(sbom),
        "artifact_inventory_sha256": _canonical_digest(actual),
        "runtime_target": dict(_RUNTIME_TARGET),
        "spend_authorization": spend_authorization,
    }


def _single(paths: Iterable[Path], label: str) -> Path:
    values = tuple(sorted(paths))
    if len(values) != 1:
        raise DemoRunnerError(f"release must contain exactly one {label}, found {values!r}")
    return values[0]


def _stage_artifact_context(release: Path, staging_root: Path, *, offline_npm_cache: Path) -> Path:
    """Create the only Docker build context permitted for reference demonstration images."""

    context = staging_root / "context"
    artifacts = context / "artifacts"
    shutil.copytree(release / "python", artifacts / "python")
    shutil.copytree(release / "npm", artifacts / "npm")
    _copy_offline_npm_cache(offline_npm_cache, artifacts)
    wheel = _single((artifacts / "python" / "reference").glob("*.whl"), "reference wheel")
    extracted = staging_root / "reference-wheel"
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.infolist():
            relative = member.filename.rstrip("/")
            _safe_release_path(relative, "reference wheel")
            if stat.S_ISLNK(member.external_attr >> 16):
                raise DemoRunnerError("reference wheel contains a symbolic link")
        archive.extractall(extracted)
    package_root = extracted / "masugate_openclaw_reference"
    if not package_root.is_dir():
        raise DemoRunnerError("reference wheel does not contain the deployment package")
    shutil.copytree(package_root / "containment", context / "containment")
    configuration = context / "reference-config"
    configuration.mkdir()
    for name in (
        "fleet-roster.example.json",
        "plugin-config.example.json",
        "plugin-config.native-approval.example.json",
    ):
        source = package_root / name
        if not source.is_file():
            raise DemoRunnerError(f"reference wheel is missing deployment configuration: {name}")
        shutil.copy2(source, configuration / name)
    shutil.copytree(
        package_root / "safe-content-plugin",
        context / "containment" / "safe-content-plugin",
    )
    contract = context / "containment" / "openclaw-contract"
    contract.mkdir()
    for name in ("package.json", "package-lock.json"):
        shutil.copy2(release / "deployment" / "openclaw-contract" / name, contract / name)
    required = (
        context / "containment" / "Dockerfile.reference_demo-reference",
        context / "containment" / "Dockerfile.reference_demo-gateway",
        context / "containment" / "Dockerfile.reference_demo-safe-content",
        context / "containment" / "Dockerfile.reference_demo-agent-probe",
        context / "containment" / "compose.yaml",
        context / "containment" / "compose.reference_demo.yaml",
        context / "containment" / "gateway-entrypoint.mjs",
        context / "containment" / "openclaw-contract" / "package-lock.json",
        context / "reference-config" / "fleet-roster.example.json",
        context / "reference-config" / "plugin-config.example.json",
        context / "reference-config" / "plugin-config.native-approval.example.json",
        context / "artifacts" / "python" / "masugate",
        context / "artifacts" / "python" / "masugate-connector-sdk",
        context / "artifacts" / "python" / "masugate-client",
        context / "artifacts" / "python" / "runtime" / "requirements.txt",
        context / "artifacts" / "python" / "runtime" / "wheelhouse",
        context / "artifacts" / "npm",
        context / "artifacts" / "offline" / "npm" / "cache",
    )
    if any(not path.exists() for path in required):
        raise DemoRunnerError("staged clean artifact context is incomplete")
    return context


def _bind_staged_compose_identity(
    release_descriptor: Mapping[str, object],
    artifact_context: Path,
) -> dict[str, object]:
    deployment_files = {
        relative: _sha256(artifact_context / relative)
        for relative in (
            "containment/compose.yaml",
            "containment/compose.reference_demo.yaml",
            "containment/gateway-entrypoint.mjs",
        )
    }
    return {
        **release_descriptor,
        "staged_compose": {
            "files": deployment_files,
            "bundle_sha256": _canonical_digest(deployment_files),
        },
    }


def _compose_arguments(
    project: str,
    environment: Mapping[str, str],
    *arguments: str,
) -> tuple[str, ...]:
    compose_root = Path(
        _string(environment.get("MASUGATE_REFERENCE_DEMO_COMPOSE_ROOT"), "Compose root")
    )
    env_file = Path(
        _string(environment.get("MASUGATE_REFERENCE_DEMO_ENV_FILE"), "Compose environment file")
    )
    compose = compose_root / "compose.yaml"
    reference_demo_compose = compose_root / "compose.reference_demo.yaml"
    if not compose.is_file() or not reference_demo_compose.is_file() or not env_file.is_file():
        raise DemoRunnerError("staged release context is missing the Compose profiles")
    return (
        DOCKER,
        "compose",
        "--env-file",
        str(env_file),
        "--project-name",
        project,
        "--file",
        str(compose),
        "--file",
        str(reference_demo_compose),
        *arguments,
    )


def _write_compose_environment(environment: Mapping[str, str]) -> None:
    path = Path(
        _string(environment.get("MASUGATE_REFERENCE_DEMO_ENV_FILE"), "Compose environment file")
    )
    names = (
        "MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT",
        "MASUGATE_REFERENCE_DEMO_ARTIFACT_CONTEXT",
        "MASUGATE_REFERENCE_DEMO_NETWORK_PREFIX",
        "MASUGATE_AGENT_SANDBOX_IMAGE",
        "MASUGATE_GATEWAY_RECOVERY_HAZARD",
    )
    lines: list[str] = []
    for name in names:
        raw_value = environment.get(name)
        if not isinstance(raw_value, str) or (
            not raw_value and name != "MASUGATE_GATEWAY_RECOVERY_HAZARD"
        ):
            raise DemoRunnerError(f"Compose environment {name} must be a string")
        value = raw_value
        if "\n" in value or "\r" in value:
            raise DemoRunnerError(f"Compose environment {name} contains a newline")
        if DOCKER.lower().endswith(".exe") and name in {
            "MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT",
            "MASUGATE_REFERENCE_DEMO_ARTIFACT_CONTEXT",
        }:
            converted = subprocess.run(
                ["wslpath", "-w", value],
                check=False,
                text=True,
                capture_output=True,
            )
            if converted.returncode != 0 or not converted.stdout.strip():
                raise DemoRunnerError(f"cannot convert Compose environment {name} for WSL")
            value = converted.stdout.strip()
        lines.append(f"{name}={value}\n")
    path.write_text("".join(lines), encoding="utf-8")


def _compose(project: str, environment: dict[str, str], *arguments: str) -> str:
    _write_compose_environment(environment)
    return _run(_compose_arguments(project, environment, *arguments), environment=environment)


def _verify_docker_runtime() -> None:
    architecture = _run(
        (DOCKER, "info", "--format", "{{.Architecture}}"),
        environment=dict(os.environ),
    ).strip()
    if architecture not in {"amd64", "x86_64"}:
        raise DemoRunnerError(
            "reference demonstration requires a linux/amd64 Docker runtime for "
            "its CPython 3.12 wheelhouse"
        )


def _clear_state_root_from_container(state_root: Path) -> None:
    """Remove generated state after every Compose service has stopped.

    The Gateway can start an agent sandbox through Docker's socket. That
    sandbox is outside the Compose project and can leave an unprivileged,
    non-removable nested directory after the Gateway itself stops. Mount only
    the runner-created state root into the pinned Alpine image already used by
    the profile, then remove its contents before Python cleans the directory.
    """

    if not state_root.is_dir() or not state_root.name.startswith("masugate-reference_demo-state-"):
        raise DemoRunnerError(
            "refusing to clear a state root outside the reference demonstration runner"
        )
    _run(
        (
            DOCKER,
            "run",
            "--rm",
            "--network",
            "none",
            "--volume",
            f"{state_root}:/state:rw",
            _STATE_CLEANUP_IMAGE,
            "sh",
            "-ec",
            "rm -rf /state/* /state/.[!.]* /state/..?*",
        ),
        environment=dict(os.environ),
    )
    if any(state_root.iterdir()):
        raise DemoRunnerError("container-side cleanup left reference demonstration state behind")


def _remove_sandbox_image(image: str) -> None:
    if not image.startswith("masugate-openclaw-reference-agent-sandbox:reference_demo-"):
        raise DemoRunnerError(
            "refusing to remove an image outside the reference demonstration namespace"
        )
    # Compose cleanup can already have removed the image. Treat that desired
    # end state as success while retaining the namespace check above.
    present = subprocess.run(
        (DOCKER, "image", "inspect", image),
        check=False,
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if present.returncode != 0:
        return
    # Sandboxes are created by the Gateway through Docker's socket, outside
    # the Compose project.  Remove only containers descended from this
    # runner's uniquely tagged image before removing that image, so a partial
    # Gateway failure cannot leave an orphan that masks the original error.
    container_ids = tuple(
        container_id
        for container_id in _run(
            (DOCKER, "ps", "--all", "--quiet", "--filter", f"ancestor={image}"),
            environment=dict(os.environ),
        ).splitlines()
        if container_id
    )
    if container_ids:
        _run(
            (DOCKER, "rm", "--force", *container_ids),
            environment=dict(os.environ),
        )
    _run(
        (DOCKER, "image", "rm", image),
        environment=dict(os.environ),
    )


_COMPOSE_SERVICE_IMAGE_SUFFIXES = frozenset(
    {
        "openclaw-gateway:latest",
        "masugated:latest",
        "reference-purchase:latest",
        "safe-content:latest",
    }
)


def _owned_compose_service_images(project: str, environment: Mapping[str, str]) -> tuple[str, ...]:
    """List only images tagged by one unique disposable Compose project."""

    if not re.fullmatch(r"masugate-(?:reference-demo|release-verification)-[a-z0-9-]+", project):
        raise DemoRunnerError(
            "refusing to inspect images outside the reference demonstration namespace"
        )
    prefix = f"{project}-"
    images: list[str] = []
    for image in _run(
        (DOCKER, "image", "ls", "--format", "{{.Repository}}:{{.Tag}}"),
        environment=dict(environment),
    ).splitlines():
        if not image.startswith(prefix):
            continue
        if image.removeprefix(prefix) not in _COMPOSE_SERVICE_IMAGE_SUFFIXES:
            raise DemoRunnerError(f"refusing to remove an unexpected Compose image: {image}")
        images.append(image)
    return tuple(images)


def _remove_compose_service_images(project: str, environment: Mapping[str, str]) -> None:
    """Remove every service image built by one disposable Compose project."""

    for image in _owned_compose_service_images(project, environment):
        _run((DOCKER, "image", "rm", image), environment=dict(environment))
    remaining = _owned_compose_service_images(project, environment)
    if remaining:
        raise DemoRunnerError(
            "Compose service-image cleanup left runner-owned images behind: " + ", ".join(remaining)
        )


def _cleanup_compose_project(
    project: str,
    environment: Mapping[str, str],
    *,
    remove_local_images: bool,
) -> None:
    """Attempt Compose teardown and exact service-image removal independently."""

    failures: list[Exception] = []
    down_arguments = ["down", "--volumes", "--remove-orphans"]
    if remove_local_images:
        down_arguments.extend(("--rmi", "local"))
    try:
        _compose(project, environment, *down_arguments)
    except Exception as exc:
        failures.append(exc)
    try:
        _remove_compose_service_images(project, environment)
    except Exception as exc:
        failures.append(exc)
    if len(failures) == 1:
        raise failures[0]
    if failures:
        raise ExceptionGroup(
            f"Compose teardown and service-image cleanup failed for {project}", failures
        )


def _dynamic_agent_network(project: str) -> str:
    """Return the empty internal network owned by one disposable run."""

    if not re.fullmatch(r"masugate-(?:reference-demo|release-verification)-[a-z0-9-]+", project):
        raise DemoRunnerError(
            "refusing to create a dynamic network outside the reference demonstration namespace"
        )
    network = f"{project}-agent"
    if len(network) > 63:
        raise DemoRunnerError("reference demonstration dynamic network name exceeds Docker's limit")
    return network


def _create_dynamic_agent_network(project: str) -> str:
    """Create the sandbox-only network that Compose cannot create itself."""

    network = _dynamic_agent_network(project)
    _run(
        (DOCKER, "network", "create", "--internal", network),
        environment=dict(os.environ),
    )
    return network


def _remove_dynamic_agent_network(network: str) -> None:
    """Remove a runner-created sandbox network if it remains after teardown."""

    if not re.fullmatch(
        r"masugate-(?:reference-demo|release-verification)-[a-z0-9-]+-agent", network
    ):
        raise DemoRunnerError(
            "refusing to remove a network outside the reference demonstration namespace"
        )
    completed = subprocess.run(
        (DOCKER, "network", "inspect", network),
        check=False,
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if completed.returncode == 0:
        _run(
            (DOCKER, "network", "rm", network),
            environment=dict(os.environ),
        )


def _json_output(output: str, label: str) -> dict[str, object]:
    try:
        raw: object = json.loads(output)
    except json.JSONDecodeError as exc:
        raise DemoRunnerError(f"{label} did not emit JSON: {output}") from exc
    if not isinstance(raw, dict):
        raise DemoRunnerError(f"{label} did not emit an object")
    return cast(dict[str, object], raw)


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise DemoRunnerError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise DemoRunnerError(f"{label} must be a list")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DemoRunnerError(f"{label} must be a non-empty string")
    return value


def _integer(value: object, label: str) -> int:
    if type(value) is not int:
        raise DemoRunnerError(f"{label} must be an integer")
    return value


def _timestamp(value: object, label: str) -> datetime:
    rendered = _string(value, label)
    try:
        parsed = datetime.fromisoformat(rendered)
    except ValueError as exc:
        raise DemoRunnerError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.isoformat() != rendered:
        raise DemoRunnerError(f"{label} must be a canonical timezone-aware timestamp")
    return parsed


def _validate_release_descriptor(
    value: object,
    *,
    expected: Mapping[str, object] | None = None,
) -> dict[str, object]:
    descriptor = _mapping(value, "release descriptor")
    if descriptor.get("schema_version") != _RELEASE_DESCRIPTOR_SCHEMA:
        raise DemoRunnerError("release descriptor has an incompatible schema version")
    _string(descriptor.get("release_id"), "release descriptor release_id")
    revision = _string(descriptor.get("source_revision"), "release descriptor source_revision")
    if len(revision) != 40:
        raise DemoRunnerError("release descriptor source_revision must be a full Git revision")
    try:
        int(revision, 16)
    except ValueError as exc:
        raise DemoRunnerError("release descriptor source_revision is not hexadecimal") from exc
    staging_revision = _string(
        descriptor.get("staging_realization_revision"),
        "release descriptor staging_realization_revision",
    )
    if len(staging_revision) != 40:
        raise DemoRunnerError(
            "release descriptor staging_realization_revision must be a full Git revision"
        )
    try:
        int(staging_revision, 16)
    except ValueError as exc:
        raise DemoRunnerError(
            "release descriptor staging_realization_revision is not hexadecimal"
        ) from exc
    for field in (
        "release_manifest_sha256",
        "provenance_sha256",
        "checksums_sha256",
        "sbom_sha256",
        "artifact_inventory_sha256",
    ):
        _sha256_string(descriptor.get(field), f"release descriptor {field}")
    if descriptor.get("runtime_target") != _RUNTIME_TARGET:
        raise DemoRunnerError("release descriptor has the wrong runtime target")
    _validate_spend_authorization_anchor(descriptor.get("spend_authorization"))
    staged = _mapping(descriptor.get("staged_compose"), "release descriptor staged_compose")
    files = _mapping(staged.get("files"), "release descriptor staged_compose.files")
    expected_paths = {
        "containment/compose.yaml",
        "containment/compose.reference_demo.yaml",
        "containment/gateway-entrypoint.mjs",
    }
    if set(files) != expected_paths:
        raise DemoRunnerError("release descriptor has the wrong staged Compose file set")
    for path, digest in files.items():
        _sha256_string(digest, f"release descriptor staged Compose file {path}")
    bundle_digest = _sha256_string(
        staged.get("bundle_sha256"), "release descriptor staged Compose bundle"
    )
    if bundle_digest != _canonical_digest(files):
        raise DemoRunnerError("release descriptor staged Compose bundle digest is invalid")
    if expected is not None and descriptor != dict(expected):
        raise DemoRunnerError("evidence release descriptor does not match the executed release")
    return descriptor


def _envelope(
    scenario: str,
    evidence: dict[str, object],
    *,
    started_ns: int,
    finished_ns: int,
    release_descriptor: Mapping[str, object],
) -> dict[str, object]:
    if started_ns <= 0 or finished_ns < started_ns:
        raise DemoRunnerError(f"{scenario} emitted invalid event timestamps")
    return {
        "schema_version": _EVIDENCE_SCHEMA,
        "scenario_id": scenario,
        "started_ns": started_ns,
        "finished_ns": finished_ns,
        "release": dict(release_descriptor),
        "evidence": evidence,
    }


def _scope_value(value: object, label: str) -> ScopeValue:
    if value is None or isinstance(value, (str, int, float, bool)):
        if type(value) is float and not math.isfinite(value):
            raise DemoRunnerError(f"{label} must be finite")
        return value
    raise DemoRunnerError(f"{label} must be a JSON scalar")


def _optional_string(value: object, label: str) -> str | None:
    return None if value is None else _string(value, label)


def _scope_accesses(value: object, label: str) -> tuple[ScopeAccess, ...]:
    accesses: list[ScopeAccess] = []
    for index, raw in enumerate(_list(value, label)):
        access = _mapping(raw, f"{label}[{index}]")
        scope = _string(access.get("scope"), f"{label}[{index}].scope")
        version = _integer(access.get("version"), f"{label}[{index}].version")
        if version < 0:
            raise DemoRunnerError(f"{label}[{index}] has a negative version")
        accesses.append(
            ScopeAccess(
                scope=scope,
                version=version,
                value=_scope_value(access.get("value"), f"{label}[{index}].value"),
            )
        )
    return tuple(accesses)


def _validate_history(
    history: object,
    label: str,
    *,
    kind: str,
    initial_policy_state: object,
) -> History:
    raw_operations = _list(history, label)
    expected_length = 3 if kind == "governed" else 2
    if len(raw_operations) != expected_length:
        raise DemoRunnerError(
            f"{label} must contain exactly {expected_length} captured state transitions"
        )
    operations: list[Operation] = []
    event_kinds: list[str] = []
    operation_ids: set[str] = set()
    for index, raw in enumerate(raw_operations):
        operation = _mapping(raw, f"{label}[{index}]")
        event_kind = _string(operation.get("event_kind"), f"{label}[{index}].event_kind")
        causal_operation_id = _string(
            operation.get("causal_operation_id"),
            f"{label}[{index}].causal_operation_id",
        )
        begin_ns = _integer(operation.get("begin_ns"), f"{label}[{index}].begin_ns")
        terminal_ns = _integer(operation.get("terminal_ns"), f"{label}[{index}].terminal_ns")
        if begin_ns <= 0 or terminal_ns < begin_ns:
            raise DemoRunnerError(f"{label}[{index}] has invalid event timestamps")
        committed = operation.get("committed")
        if type(committed) is not bool:
            raise DemoRunnerError(f"{label}[{index}].committed must be boolean")
        decision = _optional_string(operation.get("decision"), f"{label}[{index}].decision")
        if decision not in {None, "allow", "deny"}:
            raise DemoRunnerError(f"{label}[{index}].decision must be allow or deny")
        policy_reads = _scope_accesses(
            operation.get("policy_reads"), f"{label}[{index}].policy_reads"
        )
        effect_reads = _scope_accesses(
            operation.get("effect_reads"), f"{label}[{index}].effect_reads"
        )
        effect_writes = _scope_accesses(
            operation.get("effect_writes"), f"{label}[{index}].effect_writes"
        )
        if committed and not effect_writes:
            raise DemoRunnerError(f"{label}[{index}] committed without an effect write")
        if not committed and effect_writes:
            raise DemoRunnerError(f"{label}[{index}] denied but contains an effect write")
        operation_id = _string(operation.get("operation_id"), f"{label}[{index}].operation_id")
        if operation_id in operation_ids:
            raise DemoRunnerError(f"{label} contains a duplicate transition identity")
        operation_ids.add(operation_id)
        if event_kind == "coordination-reservation":
            if not committed or not policy_reads or effect_reads or len(effect_writes) != 1:
                raise DemoRunnerError(f"{label}[{index}] has an invalid reservation transition")
            if causal_operation_id == operation_id:
                raise DemoRunnerError(f"{label}[{index}] reservation lacks its causal operation")
        elif event_kind == "terminal-settlement":
            if not committed or policy_reads or len(effect_reads) != 1 or len(effect_writes) != 1:
                raise DemoRunnerError(f"{label}[{index}] has an invalid settlement transition")
            if causal_operation_id == operation_id:
                raise DemoRunnerError(f"{label}[{index}] settlement lacks its causal operation")
        elif event_kind == "terminal-denial":
            if committed or not policy_reads or effect_reads or effect_writes:
                raise DemoRunnerError(f"{label}[{index}] has an invalid denial transition")
            if causal_operation_id != operation_id:
                raise DemoRunnerError(f"{label}[{index}] denial has the wrong causal operation")
        elif event_kind == "terminal-effect":
            if not committed or not policy_reads or effect_reads or len(effect_writes) != 1:
                raise DemoRunnerError(f"{label}[{index}] has an invalid terminal effect")
            if causal_operation_id != operation_id:
                raise DemoRunnerError(f"{label}[{index}] effect has the wrong causal operation")
        else:
            raise DemoRunnerError(f"{label}[{index}] has an unknown event kind")
        event_kinds.append(event_kind)
        operations.append(
            Operation(
                op_id=operation_id,
                begin_ns=begin_ns,
                commit_ns=terminal_ns,
                committed=committed,
                policy_reads=policy_reads,
                effect_reads=effect_reads,
                effect_writes=effect_writes,
                decision=cast(Literal["allow", "deny"] | None, decision),
                policy_id=_optional_string(
                    operation.get("policy_id"), f"{label}[{index}].policy_id"
                ),
                policy_version=_optional_string(
                    operation.get("policy_version"), f"{label}[{index}].policy_version"
                ),
                evaluation_time=_optional_string(
                    operation.get("evaluation_time"), f"{label}[{index}].evaluation_time"
                ),
                evaluation_input_digest=_optional_string(
                    operation.get("evaluation_input_digest"),
                    f"{label}[{index}].evaluation_input_digest",
                ),
                causal_operation_id=causal_operation_id,
                transition_kind=cast(TransitionKind, event_kind),
            )
        )
    expected_kinds = (
        ["coordination-reservation", "terminal-denial", "terminal-settlement"]
        if kind == "governed"
        else ["terminal-effect", "terminal-effect"]
    )
    if event_kinds != expected_kinds:
        raise DemoRunnerError(f"{label} has an invalid transition sequence")
    first, second = operations[:2]
    if max(first.begin_ns, second.begin_ns) > min(first.commit_ns, second.commit_ns):
        raise DemoRunnerError(f"{label} does not retain overlapping race windows")
    if kind == "governed":
        settlement = operations[2]
        if settlement.begin_ns < max(first.commit_ns, second.commit_ns):
            raise DemoRunnerError(
                f"{label} settlement begins before both governed admissions finish"
            )
    initial_versions = _scope_accesses(initial_policy_state, f"{label}.initial_policy_state")
    if not initial_versions:
        raise DemoRunnerError(f"{label} must retain an initial policy-state baseline")
    return History(tuple(operations), initial_versions=initial_versions)


def _validate_scenario_request(
    audit: Mapping[str, object],
    label: str,
    *,
    scenario: str,
) -> tuple[str, str, dict[str, object], str, dict[str, object], datetime]:
    operation_id = _string(audit.get("operation_id"), f"{label}.operation_id")
    request = _mapping(audit.get("request"), f"{label}.request")
    idempotency_key = _string(request.get("idempotency_key"), f"{label}.request.idempotency_key")
    if idempotency_key not in _SCENARIO_REQUEST_KEYS.get(scenario, frozenset()):
        raise DemoRunnerError(f"{label} has the wrong scenario request identity")
    expected_principal, expected_arguments, authorization_basis = _EXPECTED_REQUESTS[
        idempotency_key
    ]
    principal = _mapping(request.get("principal"), f"{label}.request.principal")
    if principal != {
        "attributes": _EXPECTED_PRINCIPAL_ATTRIBUTES[expected_principal],
        "id": expected_principal,
    }:
        raise DemoRunnerError(f"{label} has the wrong request principal")
    if request.get("action") != _ACTION or request.get("args") != expected_arguments:
        raise DemoRunnerError(f"{label} has the wrong request action or arguments")
    if request.get("trace_id") != f"reference_demo:{idempotency_key}":
        raise DemoRunnerError(f"{label} has the wrong request trace identity")
    request_time = _timestamp(request.get("request_time"), f"{label}.request.request_time")
    if request.get("timestamp") != request.get("request_time"):
        raise DemoRunnerError(f"{label} request timestamp does not match request_time")
    return (
        operation_id,
        idempotency_key,
        expected_arguments,
        authorization_basis,
        request,
        request_time,
    )


def _read_without_latency(read: Mapping[str, object]) -> dict[str, object]:
    return {name: value for name, value in read.items() if name != "latency_ms"}


def _validate_policy_and_reads(
    audit: Mapping[str, object],
    label: str,
    *,
    spend_authorization: Mapping[str, object],
    request_time: datetime,
    expected_effect: str,
    expected_rule_id: str,
    expected_reason: str,
    expected_available_cents: int,
    expected_version: int,
) -> tuple[list[object], dict[str, object], list[dict[str, object]]]:
    reads = _list(audit.get("view_reads"), f"{label}.view_reads")
    if len(reads) != 1:
        raise DemoRunnerError(f"{label} must contain exactly one spend policy-state read")
    read = _mapping(reads[0], f"{label}.view_reads[0]")
    latency = read.get("latency_ms")
    if (
        type(latency) not in {int, float}
        or not math.isfinite(cast(float, latency))
        or cast(float, latency) < 0
    ):
        raise DemoRunnerError(f"{label} has an invalid policy-state read latency")
    if _read_without_latency(read) != {
        "arguments": ["research"],
        "function": "spend.available_cents",
        "scope": "spend:team:research",
        "value": expected_available_cents,
        "version": expected_version,
    }:
        raise DemoRunnerError(f"{label} has fabricated policy-state read evidence")

    evaluations = _list(
        audit.get("authorization_evaluations"), f"{label}.authorization_evaluations"
    )
    if len(evaluations) != 1:
        raise DemoRunnerError(f"{label} must contain exactly one admission evaluation")
    admission = _mapping(evaluations[0], f"{label}.authorization_evaluations[0]")
    if admission.get("phase") != "admission" or admission.get("certified_inputs") != []:
        raise DemoRunnerError(f"{label} has the wrong authorization evaluation phase")
    evaluated_at = _timestamp(
        admission.get("evaluated_at"), f"{label}.authorization_evaluations[0].evaluated_at"
    )
    if evaluated_at != request_time:
        raise DemoRunnerError(f"{label} admission evaluation is not bound to request time")
    decision = _mapping(admission.get("decision"), f"{label}.admission decision")
    if decision.get("reads") != reads:
        raise DemoRunnerError(f"{label} view reads do not match its admission decision")
    if (
        decision.get("effect") != expected_effect
        or decision.get("rule_id") != expected_rule_id
        or decision.get("reason") != expected_reason
        or decision.get("policy_id") != "spend_budget_guard"
    ):
        raise DemoRunnerError(f"{label} has the wrong admission policy decision")

    provenance = _list(decision.get("policy_provenance"), f"{label}.admission policy_provenance")
    if len(provenance) != 1:
        raise DemoRunnerError(f"{label} must name exactly one evaluated policy artifact")
    artifact = _mapping(provenance[0], f"{label}.admission policy_provenance[0]")
    anchor = _validate_spend_authorization_anchor(spend_authorization)
    expected_artifact = _mapping(anchor.get("policy"), "executed spend policy anchor")
    if artifact != expected_artifact:
        raise DemoRunnerError(f"{label} does not match the executed policy provenance")
    policy_digest = _string(expected_artifact.get("policy_digest"), "executed policy digest")
    bundle_digest = _string(expected_artifact.get("bundle_digest"), "executed bundle digest")
    runtime_version = _string(
        expected_artifact.get("policy_runtime_version"), "executed policy runtime version"
    )
    evaluated = [{"policy_id": "spend_budget_guard", "policy_version": runtime_version}]
    if (
        decision.get("evaluated_policies") != evaluated
        or decision.get("policy_version") != runtime_version
    ):
        raise DemoRunnerError(f"{label} has fabricated evaluated-policy identity")

    policy = _mapping(audit.get("policy"), f"{label}.policy")
    if policy != {
        "catalog": {
            "bundle_digest": bundle_digest,
            "policy_digest": policy_digest,
        },
        "evaluated_policies": evaluated,
        "evaluated_policy_provenance": provenance,
        "policy_id": "spend_budget_guard",
        "policy_version": runtime_version,
    }:
        raise DemoRunnerError(f"{label} outer policy evidence does not match admission")
    binding_policies: list[dict[str, object]] = [
        {
            "bundle_digest": bundle_digest,
            "bundle_id": "masugate.spend.reference",
            "bundle_version": "1.0.0",
            "policy_digest": policy_digest,
            "policy_id": "spend_budget_guard",
            "policy_version": "1.0.0",
        }
    ]
    return reads, decision, binding_policies


def _effect_authorization(decision: Mapping[str, object]) -> dict[str, object]:
    raw_reads = _list(decision.get("reads"), "admission decision reads")
    return {
        "effect": decision.get("effect"),
        "evaluated_policies": decision.get("evaluated_policies"),
        "policy_id": decision.get("policy_id"),
        "policy_version": decision.get("policy_version"),
        "reads": [
            _read_without_latency(_mapping(read, "admission decision read")) for read in raw_reads
        ],
        "reason": decision.get("reason"),
        "rule_id": decision.get("rule_id"),
    }


def _human_resolution_payload(
    audit: Mapping[str, object],
    label: str,
    *,
    scenario: str,
    request_time: datetime,
    recorded_at: datetime,
    escalated: bool,
) -> dict[str, object] | None:
    if not escalated:
        if audit.get("human_resolution") is not None:
            raise DemoRunnerError(f"{label} unexpectedly contains human approval evidence")
        return None
    resolution = _mapping(audit.get("human_resolution"), f"{label}.human_resolution")
    expected_evidence = {
        "decision": "allow-once",
        "scenario": _HUMAN_RESOLUTION_SCENARIOS[scenario],
        "source": "reference-demo-demo",
    }
    if (
        resolution.get("actor_id") != "operator"
        or resolution.get("approved") is not True
        or resolution.get("evidence") != expected_evidence
    ):
        raise DemoRunnerError(f"{label} has invalid human approval evidence")
    resolved_at = _timestamp(resolution.get("resolved_at"), f"{label}.human_resolution.resolved_at")
    if not request_time <= resolved_at <= recorded_at:
        raise DemoRunnerError(f"{label} human approval has an invalid temporal basis")
    if set(resolution) != {"actor_id", "approved", "evidence", "resolved_at"}:
        raise DemoRunnerError(f"{label} human approval has an incompatible shape")
    return {
        "actor_id": "operator",
        "approved": True,
        "evidence": expected_evidence,
        "kind": "human",
        "resolved_at": _string(resolution.get("resolved_at"), "resolution time"),
    }


def _authorization_digest(
    request: Mapping[str, object],
    decision: Mapping[str, object],
    *,
    budget_version: int,
    configuration_digest: str,
    resolution: Mapping[str, object] | None,
) -> str:
    """Recompute the spend provider's durable authorization binding."""
    return _shared_authorization_digest(
        request,
        decision,
        budget_version=budget_version,
        configuration_digest=configuration_digest,
        resolution=resolution,
    )


def _validate_committed_record_legacy(
    record: object,
    label: str,
    *,
    scenario: str,
    spend_authorization: Mapping[str, object],
    expected_operation_id: str | None = None,
) -> dict[str, object]:
    audit = _mapping(record, label)
    if audit.get("status") != "committed":
        raise DemoRunnerError(f"{label} is not a committed terminal record")
    (
        operation_id,
        idempotency_key,
        expected_arguments,
        authorization_basis,
        request,
        request_time,
    ) = _validate_scenario_request(audit, label, scenario=scenario)
    if expected_operation_id is not None and operation_id != expected_operation_id:
        raise DemoRunnerError(f"{label} has the wrong operation identity")
    expected_principal = _EXPECTED_REQUESTS[idempotency_key][0]
    trace_id = cast(str, request["trace_id"])
    escalated = authorization_basis == "preserved-admission-evaluation"
    anchor = _validate_spend_authorization_anchor(spend_authorization)
    recorded_at = _timestamp(audit.get("recorded_at"), f"{label}.recorded_at")
    if recorded_at < request_time:
        raise DemoRunnerError(f"{label} was recorded before its trusted request")
    _reads, admission_decision, binding_policies = _validate_policy_and_reads(
        audit,
        label,
        spend_authorization=anchor,
        request_time=request_time,
        expected_effect="escalate" if escalated else "allow",
        expected_rule_id="ask_first" if escalated else "otherwise",
        expected_reason=("rule ask_first evaluated to true" if escalated else "default rule"),
        expected_available_cents=10_000,
        expected_version=0,
    )
    outer_decision = _mapping(audit.get("decision"), f"{label}.decision")
    if outer_decision != {
        "effect": "allow",
        "reason": "reference purchase committed with connector receipt",
        "rule_id": "approval.approved" if escalated else "otherwise",
    }:
        raise DemoRunnerError(f"{label} has the wrong committed terminal decision")
    resolution = _human_resolution_payload(
        audit,
        label,
        scenario=scenario,
        request_time=request_time,
        recorded_at=recorded_at,
        escalated=escalated,
    )
    protected = _mapping(audit.get("protected_execution"), f"{label}.protected_execution")
    binding = _mapping(protected.get("binding"), f"{label}.protected_execution.binding")
    entitlement = _mapping(audit.get("entitlement"), f"{label}.entitlement")
    if set(entitlement) != {"authorization_digest", "entitlement_id"}:
        raise DemoRunnerError(f"{label} entitlement evidence has an incompatible shape")
    entitlement_id = _string(
        entitlement.get("entitlement_id"), f"{label}.entitlement.entitlement_id"
    )
    authorization_digest = _sha256_string(
        entitlement.get("authorization_digest"),
        f"{label}.entitlement.authorization_digest",
    )
    effect = _mapping(audit.get("effect"), f"{label}.effect")
    effect_payload = _mapping(effect.get("payload"), f"{label}.effect.payload")
    budget_version = _integer(
        effect_payload.get("budget_version"), f"{label}.effect.payload.budget_version"
    )
    if budget_version != 1:
        raise DemoRunnerError(f"{label} committed effect has the wrong budget version")
    configuration_digest = _string(
        anchor.get("configuration_digest"), "executed spend configuration digest"
    )
    expected_authorization_digest = _authorization_digest(
        request,
        admission_decision,
        budget_version=budget_version,
        configuration_digest=configuration_digest,
        resolution=resolution,
    )
    if authorization_digest != expected_authorization_digest:
        raise DemoRunnerError(f"{label} authorization digest is not durable evidence")
    if binding.get("principal_id") != expected_principal:
        raise DemoRunnerError(f"{label} protected binding has the wrong principal")
    if (
        binding.get("action") != _ACTION
        or binding.get("arguments") != expected_arguments
        or binding.get("idempotency_key") != idempotency_key
        or binding.get("tool_call_id") != trace_id
    ):
        raise DemoRunnerError(f"{label} protected binding does not match the outer request")
    if (
        binding.get("connector_id") != _CONNECTOR_ID
        or binding.get("coordination_domain_id") != "masugate.spend.reference.domain.v1"
        or binding.get("entitlement_id") != entitlement_id
        or binding.get("authorization_digest") != authorization_digest
    ):
        raise DemoRunnerError(f"{label} protected binding does not match its entitlement")
    provider = _mapping(binding.get("provider_identity"), f"{label}.binding.provider_identity")
    if (
        provider.get("provider_id") != _PROVIDER_ID
        or provider.get("implementation_version") != _PROVIDER_IMPLEMENTATION
    ):
        raise DemoRunnerError(f"{label} protected binding has the wrong provider identity")
    if provider.get("configuration_version") != configuration_digest:
        raise DemoRunnerError(f"{label} protected binding has the wrong provider configuration")
    scopes = _list(binding.get("scopes"), f"{label}.binding.scopes")
    if scopes != ["spend:team:research"]:
        raise DemoRunnerError(f"{label} protected binding has the wrong policy-state scope")
    if binding.get("policies") != binding_policies:
        raise DemoRunnerError(f"{label} protected binding has the wrong policy provenance")
    canonical = _string(protected.get("binding_canonical_json"), f"{label}.binding_canonical_json")
    try:
        canonical_binding: object = json.loads(canonical)
    except json.JSONDecodeError as exc:
        raise DemoRunnerError(f"{label} canonical protected binding is invalid JSON") from exc
    if _mapping(canonical_binding, f"{label}.binding_canonical_json") != binding:
        raise DemoRunnerError(f"{label} canonical protected binding does not match its object")
    binding_digest = _string(protected.get("binding_digest"), f"{label}.binding_digest")
    if hashlib.sha256(canonical.encode()).hexdigest() != binding_digest:
        raise DemoRunnerError(f"{label} protected binding digest is invalid")
    if protected.get("execution_id") != f"px:{binding_digest}":
        raise DemoRunnerError(f"{label} protected execution has the wrong identity")
    if (
        protected.get("status") != "succeeded"
        or protected.get("entitlement_state") != "consumed"
        or protected.get("dispatch_started") is not True
    ):
        raise DemoRunnerError(f"{label} protected execution is not terminally consumed")
    receipt = _mapping(protected.get("receipt"), f"{label}.protected_execution.receipt")
    if set(receipt) != {
        "connector_id",
        "evidence_id",
        "external_operation_id",
        "idempotency_key",
        "observed_at",
        "outcome",
        "payload",
    }:
        raise DemoRunnerError(f"{label} connector receipt has an incompatible shape")
    external_operation_id = _string(
        receipt.get("external_operation_id"), f"{label}.receipt.external_operation_id"
    )
    observed_at = _timestamp(receipt.get("observed_at"), f"{label}.receipt.observed_at")
    if not request_time <= observed_at <= recorded_at:
        raise DemoRunnerError(f"{label} connector receipt has an invalid observation time")
    if resolution is not None and observed_at < _timestamp(
        resolution.get("resolved_at"), f"{label}.human_resolution.resolved_at"
    ):
        raise DemoRunnerError(f"{label} connector receipt predates human approval")
    expected_receipt_payload = {
        "amount_cents": expected_arguments["amount_cents"],
        "merchant_id": expected_arguments["merchant_id"],
    }
    if (
        receipt.get("outcome") != "succeeded"
        or receipt.get("connector_id") != _CONNECTOR_ID
        or receipt.get("idempotency_key") != f"masugate:{binding_digest}"
        or protected.get("external_operation_id") != external_operation_id
        or external_operation_id != f"purchase:{binding_digest[:32]}"
        or receipt.get("evidence_id") != f"purchase-evidence:{binding_digest[:32]}"
        or receipt.get("payload") != expected_receipt_payload
        or protected.get("result") != expected_receipt_payload
    ):
        raise DemoRunnerError(f"{label} connector receipt is not bound to the executed purchase")
    handoff = _mapping(effect_payload.get("handoff"), f"{label}.effect.payload.handoff")
    if (
        effect.get("action") != _ACTION
        or effect.get("args") != expected_arguments
        or effect_payload.get("entitlement_id") != entitlement_id
        or effect_payload.get("authorization_digest") != authorization_digest
        or handoff.get("binding_digest") != binding_digest
        or effect_payload.get("authorization") != _effect_authorization(admission_decision)
    ):
        raise DemoRunnerError(f"{label} committed effect is not bound to the protected execution")
    terminal = _mapping(audit.get("terminal_serialization"), f"{label}.terminal_serialization")
    if (
        terminal.get("kind") != "effect-commit"
        or terminal.get("authorization_basis") != authorization_basis
        or terminal.get("provider_atomic") is not False
        or terminal.get("recorded_at") != audit.get("recorded_at")
        or terminal.get("evaluation_phase") != "admission"
    ):
        raise DemoRunnerError(f"{label} has the wrong terminal serialization")
    evaluations = cast(list[object], audit["authorization_evaluations"])
    latest = _mapping(evaluations[0], f"{label}.authorization_evaluations[0]")
    if latest.get("phase") != "admission" or terminal.get("evaluation_at") != latest.get(
        "evaluated_at"
    ):
        raise DemoRunnerError(f"{label} terminal serialization has the wrong evaluation basis")
    return audit


def _validate_denied_record_legacy(
    record: object,
    label: str,
    *,
    scenario: str,
    spend_authorization: Mapping[str, object],
    expected_operation_id: str | None = None,
) -> dict[str, object]:
    audit = _mapping(record, label)
    if audit.get("status") != "denied":
        raise DemoRunnerError(f"{label} is not a denied terminal record")
    operation_id, _key, _arguments, _basis, request, request_time = _validate_scenario_request(
        audit, label, scenario=scenario
    )
    if expected_operation_id is not None and operation_id != expected_operation_id:
        raise DemoRunnerError(f"{label} has the wrong operation identity")
    anchor = _validate_spend_authorization_anchor(spend_authorization)
    recorded_at = _timestamp(audit.get("recorded_at"), f"{label}.recorded_at")
    if recorded_at < request_time:
        raise DemoRunnerError(f"{label} was recorded before its trusted request")
    _validate_policy_and_reads(
        audit,
        label,
        spend_authorization=anchor,
        request_time=request_time,
        expected_effect="deny",
        expected_rule_id="budget_cap",
        expected_reason="rule budget_cap evaluated to true",
        expected_available_cents=4_000,
        expected_version=1,
    )
    if audit.get("decision") != {
        "effect": "deny",
        "reason": "rule budget_cap evaluated to true",
        "rule_id": "budget_cap",
    }:
        raise DemoRunnerError(f"{label} has the wrong denied terminal decision")
    _human_resolution_payload(
        audit,
        label,
        scenario=scenario,
        request_time=request_time,
        recorded_at=recorded_at,
        escalated=False,
    )
    entitlement = _mapping(audit.get("entitlement"), f"{label}.entitlement")
    if set(entitlement) != {"authorization_digest", "entitlement_id"}:
        raise DemoRunnerError(f"{label} entitlement evidence has an incompatible shape")
    _string(entitlement.get("entitlement_id"), f"{label}.entitlement.entitlement_id")
    authorization_digest = _sha256_string(
        entitlement.get("authorization_digest"),
        f"{label}.entitlement.authorization_digest",
    )
    budget_version = 1
    configuration_digest = _string(
        anchor.get("configuration_digest"), "executed spend configuration digest"
    )
    evaluations = cast(list[object], audit["authorization_evaluations"])
    admission = _mapping(evaluations[0], f"{label}.authorization_evaluations[0]")
    decision = _mapping(admission.get("decision"), f"{label}.admission decision")
    if authorization_digest != _authorization_digest(
        request,
        decision,
        budget_version=budget_version,
        configuration_digest=configuration_digest,
        resolution=None,
    ):
        raise DemoRunnerError(f"{label} authorization digest is not durable evidence")
    if audit.get("effect") is not None or audit.get("protected_execution") is not None:
        raise DemoRunnerError(f"{label} denied record contains protected effect evidence")
    terminal = _mapping(audit.get("terminal_serialization"), f"{label}.terminal_serialization")
    if terminal != {
        "authorization_basis": "admission-evaluation",
        "evaluation_at": admission.get("evaluated_at"),
        "evaluation_phase": "admission",
        "kind": "denial-record",
        "provider_atomic": False,
        "recorded_at": audit.get("recorded_at"),
    }:
        raise DemoRunnerError(f"{label} has the wrong denial serialization")
    return audit


def _spend_audit_expectation(
    record: object,
    label: str,
    *,
    scenario: str,
    committed: bool,
    expected_operation_id: str | None,
) -> SpendAuditExpectation:
    audit = _mapping(record, label)
    request = _mapping(audit.get("request"), f"{label}.request")
    idempotency_key = _string(request.get("idempotency_key"), f"{label}.request.idempotency_key")
    if idempotency_key not in _SCENARIO_REQUEST_KEYS.get(scenario, frozenset()):
        raise DemoRunnerError(f"{label} has the wrong scenario request identity")
    principal_id, arguments, authorization_basis = _EXPECTED_REQUESTS[idempotency_key]
    escalated = authorization_basis == "preserved-admission-evaluation"
    human_evidence = (
        {
            "decision": "allow-once",
            "scenario": _HUMAN_RESOLUTION_SCENARIOS[scenario],
            "source": "reference-demo-demo",
        }
        if committed and escalated
        else None
    )
    return SpendAuditExpectation(
        operation_id=expected_operation_id,
        idempotency_key=idempotency_key,
        principal_id=principal_id,
        principal_attributes=_EXPECTED_PRINCIPAL_ATTRIBUTES[principal_id],
        arguments=arguments,
        trace_id=f"reference_demo:{idempotency_key}",
        admission_effect=("escalate" if escalated else "allow") if committed else "deny",
        admission_rule_id=(
            ("ask_first" if escalated else "otherwise") if committed else "budget_cap"
        ),
        admission_reason=(
            ("rule ask_first evaluated to true" if escalated else "default rule")
            if committed
            else "rule budget_cap evaluated to true"
        ),
        available_cents=10_000 if committed else 4_000,
        read_version=0 if committed else 1,
        budget_version=1,
        terminal_decision=(
            {
                "effect": "allow",
                "reason": "reference purchase committed with connector receipt",
                "rule_id": "approval.approved" if escalated else "otherwise",
            }
            if committed
            else {
                "effect": "deny",
                "reason": "rule budget_cap evaluated to true",
                "rule_id": "budget_cap",
            }
        ),
        authorization_basis=authorization_basis if committed else "admission-evaluation",
        human_resolution_evidence=human_evidence,
    )


def _validate_committed_record(
    record: object,
    label: str,
    *,
    scenario: str,
    spend_authorization: Mapping[str, object],
    expected_operation_id: str | None = None,
) -> dict[str, object]:
    expected = _spend_audit_expectation(
        record,
        label,
        scenario=scenario,
        committed=True,
        expected_operation_id=expected_operation_id,
    )
    try:
        return validate_committed_spend_audit(
            record,
            label,
            expected=expected,
            spend_authorization=spend_authorization,
        ).audit
    except AuditValidationError as exc:
        raise DemoRunnerError(str(exc)) from exc


def _validate_denied_record(
    record: object,
    label: str,
    *,
    scenario: str,
    spend_authorization: Mapping[str, object],
    expected_operation_id: str | None = None,
) -> dict[str, object]:
    expected = _spend_audit_expectation(
        record,
        label,
        scenario=scenario,
        committed=False,
        expected_operation_id=expected_operation_id,
    )
    try:
        return validate_denied_spend_audit(
            record,
            label,
            expected=expected,
            spend_authorization=spend_authorization,
        ).audit
    except AuditValidationError as exc:
        raise DemoRunnerError(str(exc)) from exc


def _validate_demo_evidence(
    envelope: dict[str, object],
    *,
    expected_release_descriptor: Mapping[str, object],
) -> None:
    """Fail closed on the versioned, scenario-specific evidence contract."""

    if envelope.get("schema_version") != _EVIDENCE_SCHEMA:
        raise DemoRunnerError("demo evidence has an incompatible schema version")
    scenario = _string(envelope.get("scenario_id"), "evidence scenario_id")
    started_ns = _integer(envelope.get("started_ns"), "evidence started_ns")
    finished_ns = _integer(envelope.get("finished_ns"), "evidence finished_ns")
    if started_ns <= 0 or finished_ns < started_ns:
        raise DemoRunnerError("demo evidence has invalid event timestamps")
    release_descriptor = _validate_release_descriptor(
        envelope.get("release"), expected=expected_release_descriptor
    )
    spend_authorization = _mapping(
        release_descriptor.get("spend_authorization"), "executed spend authorization anchor"
    )
    evidence = _mapping(envelope.get("evidence"), f"{scenario} evidence")
    expected_labels = {
        "race": "Race",
        "stale-approval": "Approval Replay",
        "blast-radius": "Blast Radius",
        "receipt": "Receipt",
        "recovery": "Recovery",
        "procurement": "E2 procurement workload",
    }
    if evidence.get("scenario") != expected_labels.get(scenario):
        raise DemoRunnerError(f"{scenario} evidence has the wrong scenario identity")

    if scenario in {"race", "procurement"}:
        governed = _mapping(evidence.get("governed"), f"{scenario}.governed")
        if governed.get("kind") != "governed-product-coordination" or governed.get(
            "assumptions"
        ) != {
            "budget_cents": 10_000,
            "agents": 2,
            "amount_cents_each": 6_000,
            "coordination": ("PostgreSQL spend entitlement/reservation plus protected runner"),
            "artifact_boundary": (
                "calls the running reference demonstration clean-artifact compose service"
            ),
        }:
            raise DemoRunnerError(f"{scenario} governed assumptions are incompatible")
        if governed.get("committed_cents") != 6_000:
            raise DemoRunnerError(f"{scenario} governed committed total is invalid")
        if governed.get("budget_valid") is not True:
            raise DemoRunnerError(f"{scenario} governed budget evidence is invalid")
        pss = _mapping(governed.get("pss"), f"{scenario}.governed.pss")
        if (
            pss.get("valid") is not True
            or pss.get("decision_validator_supplied") is not True
            or pss.get("decision_semantics_checked") is not True
            or pss.get("inconclusive") is not False
        ):
            raise DemoRunnerError(f"{scenario} governed PSS evidence is invalid")
        statuses = [
            _string(status, "terminal status")
            for status in _list(governed.get("terminal_statuses"), "terminal statuses")
        ]
        if sorted(statuses) != [
            "committed",
            "denied",
        ]:
            raise DemoRunnerError(f"{scenario} has unexpected terminal statuses")
        raw_history = _list(governed.get("history"), f"{scenario}.governed.history")
        history = _validate_history(
            raw_history,
            f"{scenario}.governed.history",
            kind="governed",
            initial_policy_state=governed.get("initial_policy_state"),
        )
        governed_verdict = check_pss(
            history,
            decision_validator=REFERENCE_SPEND_DECISION_VALIDATOR,
        )
        if not governed_verdict.pss:
            raise DemoRunnerError(f"{scenario} governed history does not replay as PSS")
        if pss != {
            "valid": governed_verdict.pss,
            "reason": governed_verdict.reason,
            "decision_validator_supplied": governed_verdict.decision_validator_supplied,
            "decision_semantics_checked": governed_verdict.decision_semantics_checked,
            "inconclusive": governed_verdict.inconclusive,
        }:
            raise DemoRunnerError(f"{scenario} governed PSS report does not match its history")
        reservation = _mapping(raw_history[0], f"{scenario}.governed.reservation")
        denial = _mapping(raw_history[1], f"{scenario}.governed.denial")
        settlement = _mapping(raw_history[2], f"{scenario}.governed.settlement")
        reservation_read = _scope_accesses(
            reservation.get("policy_reads"), "governed reservation reads"
        )[0]
        reservation_write = _scope_accesses(
            reservation.get("effect_writes"), "governed reservation writes"
        )[0]
        denial_read = _scope_accesses(denial.get("policy_reads"), "governed denial reads")[0]
        settlement_read = _scope_accesses(
            settlement.get("effect_reads"), "governed settlement reads"
        )[0]
        settlement_write = _scope_accesses(
            settlement.get("effect_writes"), "governed settlement writes"
        )[0]
        if not (
            reservation_read.scope
            == reservation_write.scope
            == denial_read.scope
            == settlement_read.scope
            == settlement_write.scope
            and denial_read.version == settlement_read.version == reservation_write.version
            and reservation_write.version == reservation_read.version + 1
            and settlement_write.version == reservation_write.version + 1
        ):
            raise DemoRunnerError(f"{scenario} governed transitions do not form one state chain")
        final_state = _mapping(
            governed.get("final_policy_state"), f"{scenario}.governed.final_policy_state"
        )
        if final_state != {
            "scope": settlement_write.scope,
            "version": settlement_write.version,
            "limit_cents": 10_000,
            "spent_cents": 6_000,
            "held_cents": 0,
            "available_cents": 4_000,
        }:
            raise DemoRunnerError(f"{scenario} governed final policy state is invalid")
        records = _list(governed.get("governance_records"), "governance records")
        if len(records) != 2:
            raise DemoRunnerError(f"{scenario} must contain two terminal governance records")
        committed = [
            record for record in records if _mapping(record, "record").get("status") == "committed"
        ]
        denied_records = [
            record for record in records if _mapping(record, "record").get("status") == "denied"
        ]
        if len(committed) != 1 or len(denied_records) != 1:
            raise DemoRunnerError(
                f"{scenario} must contain one committed and one denied governance record"
            )
        committed_audit = _validate_committed_record(
            committed[0],
            f"{scenario}.governance_record",
            scenario=scenario,
            spend_authorization=spend_authorization,
        )
        committed_operation_id = _string(
            committed_audit.get("operation_id"), f"{scenario}.committed operation_id"
        )
        if (
            reservation.get("causal_operation_id") != committed_operation_id
            or settlement.get("causal_operation_id") != committed_operation_id
        ):
            raise DemoRunnerError(
                f"{scenario} reservation and settlement do not name the committed operation"
            )
        denied_operation_id = _string(denial.get("operation_id"), f"{scenario}.denial operation_id")
        denied_audit = _validate_denied_record(
            denied_records[0],
            f"{scenario}.denied governance_record",
            scenario=scenario,
            spend_authorization=spend_authorization,
            expected_operation_id=denied_operation_id,
        )
        if denial.get("causal_operation_id") != denied_operation_id:
            raise DemoRunnerError(f"{scenario} denial transition has the wrong causal identity")
        committed_reads = _scope_accesses(
            committed_audit.get("view_reads"), f"{scenario}.committed audit reads"
        )
        denied_reads = _scope_accesses(
            denied_audit.get("view_reads"), f"{scenario}.denied audit reads"
        )
        if committed_reads != (reservation_read,) or denied_reads != (denial_read,):
            raise DemoRunnerError(
                f"{scenario} serialized history does not match both terminal audit reads"
            )
        committed_effect = _mapping(
            committed_audit.get("effect"), f"{scenario}.committed audit effect"
        )
        committed_payload = _mapping(
            committed_effect.get("payload"), f"{scenario}.committed audit effect payload"
        )
        if committed_payload.get("budget_version") != reservation_write.version:
            raise DemoRunnerError(
                f"{scenario} reservation write does not match the committed audit"
            )
        committed_request = _mapping(
            committed_audit.get("request"), f"{scenario}.committed audit request"
        )
        denied_request = _mapping(denied_audit.get("request"), f"{scenario}.denied audit request")
        if {
            committed_request.get("idempotency_key"),
            denied_request.get("idempotency_key"),
        } != set(_SCENARIO_REQUEST_KEYS[scenario]):
            raise DemoRunnerError(
                f"{scenario} terminal audits do not cover both procurement requests"
            )
    if scenario == "procurement":
        weak = _mapping(evidence.get("weak_baseline"), "procurement.weak_baseline")
        if weak.get("kind") != "deliberately-weak-request-time-baseline" or weak.get(
            "assumptions"
        ) != {
            "budget_cents": 10_000,
            "agents": 2,
            "amount_cents_each": 6_000,
            "interleaving": ("both requests read remaining budget version 0 before either effect"),
            "coordination": "none after the request-time read",
        }:
            raise DemoRunnerError("weak executable baseline assumptions are incompatible")
        if (
            weak.get("committed_cents") != 12_000
            or weak.get("overshoot_cents") != 2_000
            or weak.get("stale_authorization") is not True
        ):
            raise DemoRunnerError("weak executable baseline totals are invalid")
        weak_pss = _mapping(weak.get("pss"), "procurement.weak_baseline.pss")
        if (
            weak_pss.get("valid") is not False
            or weak_pss.get("decision_validator_supplied") is not True
            or weak_pss.get("decision_semantics_checked") is not False
            or weak_pss.get("inconclusive") is not False
        ):
            raise DemoRunnerError("weak baseline unexpectedly passed PSS")
        weak_history = _validate_history(
            weak.get("history"),
            "procurement.weak_baseline.history",
            kind="weak",
            initial_policy_state=weak.get("initial_policy_state"),
        )
        weak_verdict = check_pss(
            weak_history,
            decision_validator=REFERENCE_SPEND_DECISION_VALIDATOR,
        )
        if weak_verdict.pss:
            raise DemoRunnerError("weak baseline history replays as PSS")
        if weak_pss != {
            "valid": weak_verdict.pss,
            "reason": weak_verdict.reason,
            "decision_validator_supplied": weak_verdict.decision_validator_supplied,
            "decision_semantics_checked": weak_verdict.decision_semantics_checked,
            "inconclusive": weak_verdict.inconclusive,
        }:
            raise DemoRunnerError("weak baseline PSS report does not match its history")
        ledger_rows = _list(weak.get("effect_ledger"), "weak effect ledger")
        if len(ledger_rows) != 2:
            raise DemoRunnerError("weak executable baseline must retain two effects")
        ledger: dict[str, dict[str, object]] = {}
        for index, raw_row in enumerate(ledger_rows):
            row = _mapping(raw_row, f"weak effect ledger[{index}]")
            if set(row) != {"amount_cents", "budget_version", "operation_id"}:
                raise DemoRunnerError("weak effect ledger has an incompatible row")
            operation_id = _string(row.get("operation_id"), "weak effect operation_id")
            if operation_id in ledger:
                raise DemoRunnerError("weak effect ledger repeats an operation")
            _integer(row.get("amount_cents"), "weak effect amount")
            _integer(row.get("budget_version"), "weak effect budget version")
            ledger[operation_id] = row
        if (
            set(ledger) != {"weak-alpha", "weak-beta"}
            or {row.get("budget_version") for row in ledger.values()} != {1, 2}
            or any(row.get("amount_cents") != 6_000 for row in ledger.values())
        ):
            raise DemoRunnerError("weak effect ledger does not establish the overshoot")
        for operation in weak_history.operations:
            if (
                len(operation.policy_reads) != 1
                or operation.policy_reads[0]
                != ScopeAccess(scope="spend:team:research", version=0, value=10_000)
                or len(operation.effect_writes) != 1
                or operation.effect_writes[0]
                != ScopeAccess(
                    scope="spend:team:research",
                    version=cast(int, ledger[operation.op_id]["budget_version"]),
                    value=(
                        10_000
                        - 6_000 * cast(int, ledger[operation.op_id]["budget_version"])
                    ),
                )
            ):
                raise DemoRunnerError("weak effect ledger does not match its captured history")
        if evidence.get("measured_asymmetry") != {
            "weak_committed_cents": weak["committed_cents"],
            "governed_committed_cents": governed["committed_cents"],
            "weak_overshoot_cents": weak["overshoot_cents"],
            "governed_pss_valid": governed["pss"],
        }:
            raise DemoRunnerError("procurement measured asymmetry is not derived from evidence")
    elif scenario in {"receipt", "stale-approval", "blast-radius"}:
        if scenario == "blast-radius" and evidence.get("blocked_impersonation_status") != 401:
            raise DemoRunnerError("blast-radius impersonation was not rejected")
        expected_operation_id = _string(evidence.get("operation_id"), f"{scenario}.operation_id")
        if scenario == "stale-approval":
            attempts = _list(evidence.get("resolution_attempts"), "approval resolution attempts")
            if len(attempts) != 2:
                raise DemoRunnerError("approval replay must retain two resolution attempts")
            windows: list[tuple[int, int]] = []
            for index, raw_attempt in enumerate(attempts):
                attempt = _mapping(raw_attempt, f"approval resolution attempt {index}")
                if set(attempt) != {"begin_ns", "operation_id", "status", "terminal_ns"}:
                    raise DemoRunnerError("approval replay has an incompatible resolution attempt")
                begin_ns = _integer(attempt.get("begin_ns"), "approval resolution begin")
                terminal_ns = _integer(attempt.get("terminal_ns"), "approval resolution terminal")
                if (
                    begin_ns <= 0
                    or terminal_ns < begin_ns
                    or attempt.get("operation_id") != expected_operation_id
                    or attempt.get("status") not in {"committed", "in_progress"}
                ):
                    raise DemoRunnerError("approval replay resolution attempt is invalid")
                windows.append((begin_ns, terminal_ns))
            if max(begin for begin, _terminal in windows) > min(
                terminal for _begin, terminal in windows
            ):
                raise DemoRunnerError("approval replay resolution attempts did not overlap")
        _validate_committed_record(
            evidence.get("governance_record"),
            f"{scenario}.record",
            scenario=scenario,
            spend_authorization=spend_authorization,
            expected_operation_id=expected_operation_id,
        )
    elif scenario == "recovery":
        if evidence.get("external_effect_count") != 1:
            raise DemoRunnerError("recovery did not retain exactly one external effect")
        accounting = _mapping(evidence.get("accounting"), "recovery.accounting")
        if accounting != {"spent_cents": 400, "held_cents": 0}:
            raise DemoRunnerError("recovery accounting is not settled")
        expected_operation_id = _string(evidence.get("operation_id"), "recovery.operation_id")
        _validate_committed_record(
            evidence.get("governance_record"),
            "recovery.record",
            scenario=scenario,
            spend_authorization=spend_authorization,
            expected_operation_id=expected_operation_id,
        )


def _service_demo(
    project: str,
    environment: dict[str, str],
    scenario: str,
    release_descriptor: Mapping[str, object],
) -> dict[str, object]:
    output = _compose(
        project,
        environment,
        "exec",
        "--no-TTY",
        "masugated",
        "python",
        "-m",
        "masugate_openclaw_reference.procurement_workload",
        scenario,
    )
    child = _json_output(output, scenario)
    evidence = _mapping(child.get("evidence"), f"{scenario} child evidence")
    return _envelope(
        scenario,
        evidence,
        started_ns=_integer(child.get("started_ns"), f"{scenario} started_ns"),
        finished_ns=_integer(child.get("finished_ns"), f"{scenario} finished_ns"),
        release_descriptor=release_descriptor,
    )


def _wait_for_marker(path: Path) -> None:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        if path.is_file():
            return
        time.sleep(0.2)
    raise DemoRunnerError(f"recovery crash marker was not created: {path}")


def _recovery_operation_id(project: str, environment: dict[str, str]) -> str:
    query = (
        "SELECT operation_id FROM spend_entitlements "
        "WHERE idempotency_key = 'reference_demo-recovery' "
        "AND principal_id = 'openclaw:buyer-alpha'"
    )
    operation_id = _compose(
        project,
        environment,
        "exec",
        "--no-TTY",
        "masugate-governance-postgres",
        "psql",
        "--tuples-only",
        "--no-align",
        "--quiet",
        "--username",
        "masugate",
        "--dbname",
        "masugate",
        "--command",
        query,
    ).strip()
    try:
        return str(UUID(operation_id))
    except ValueError as exc:
        raise DemoRunnerError("recovery scenario has no durable operation id") from exc


def _recovery_audit(
    project: str,
    environment: dict[str, str],
    operation_id: str,
) -> dict[str, object]:
    program = (
        "import json, urllib.request; "
        f"request=urllib.request.Request('http://127.0.0.1:8000/v1/audit/{operation_id}', "
        "headers={'Authorization':'Bearer gateway-recovery-resolver-token'}); "
        "print(json.dumps(json.load(urllib.request.urlopen(request, timeout=20)), sort_keys=True))"
    )
    return _json_output(
        _compose(
            project,
            environment,
            "exec",
            "--no-TTY",
            "masugated",
            "python",
            "-c",
            program,
        ),
        "recovery audit",
    )


def _recovery_demo(
    project: str,
    environment: dict[str, str],
    state_root: Path,
) -> dict[str, object]:
    """Kill ``masugated`` only after its real connector has returned success."""

    hazard_environment = {**environment, "MASUGATE_GATEWAY_RECOVERY_HAZARD": "after-provider"}
    _compose(
        project,
        hazard_environment,
        "up",
        "--pull",
        "never",
        "--detach",
        "--wait",
        "--wait-timeout",
        "90",
        "--force-recreate",
        "--no-deps",
        "masugated",
    )
    request = subprocess.Popen(
        _compose_arguments(
            project,
            hazard_environment,
            "exec",
            "--no-TTY",
            "masugated",
            "python",
            "-m",
            "masugate_openclaw_reference.procurement_workload",
            "recovery-request",
        ),
        cwd=ROOT,
        env=hazard_environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    _wait_for_marker(state_root / "gateway_recovery-after-provider.ready")
    operation_id = _recovery_operation_id(project, hazard_environment)
    _compose(project, hazard_environment, "kill", "masugated")
    stdout, stderr = request.communicate(timeout=30)
    if request.returncode == 0:
        raise DemoRunnerError(
            "recovery request unexpectedly completed after the external-success crash boundary: "
            f"{stdout}\n{stderr}"
        )
    _compose(
        project,
        hazard_environment,
        "up",
        "--pull",
        "never",
        "--detach",
        "--wait",
        "--wait-timeout",
        "90",
        "--force-recreate",
        "--no-deps",
        "masugated",
    )
    deadline = time.monotonic() + 90
    audit: dict[str, object] | None = None
    while time.monotonic() < deadline:
        try:
            audit = _recovery_audit(project, hazard_environment, operation_id)
        except DemoRunnerError:
            time.sleep(0.5)
            continue
        if audit.get("status") == "committed":
            break
        time.sleep(0.5)
    if audit is None or audit.get("status") != "committed":
        raise DemoRunnerError("recovery did not settle the durable operation to committed")
    effect_count_program = (
        "import sqlite3; "
        "connection=sqlite3.connect('/reference-purchase-state/reference-purchases.sqlite'); "
        "print(connection.execute('SELECT count(*) FROM reference_purchases').fetchone()[0])"
    )
    effects = _compose(
        project,
        hazard_environment,
        "exec",
        "--no-TTY",
        "reference-purchase",
        "python",
        "-c",
        effect_count_program,
    ).strip()
    accounting = _compose(
        project,
        hazard_environment,
        "exec",
        "--no-TTY",
        "masugate-governance-postgres",
        "psql",
        "--tuples-only",
        "--no-align",
        "--quiet",
        "--username",
        "masugate",
        "--dbname",
        "masugate",
        "--command",
        "SELECT spent_cents || ':' || held_cents FROM spend_budgets WHERE team_id = 'research'",
    ).strip()
    if effects != "1" or accounting != "400:0":
        raise DemoRunnerError(
            "recovery did not preserve one external effect and settled accounting: "
            f"effects={effects!r}, accounting={accounting!r}"
        )
    return {
        "scenario": "Recovery",
        "guarantee": (
            "after provider success, restart reconciles exactly one purchase and settled budget"
        ),
        "operation_id": operation_id,
        "external_effect_count": 1,
        "accounting": {"spent_cents": 400, "held_cents": 0},
        "governance_record": audit,
    }


def _run_one(
    scenario: str,
    *,
    artifact_context: Path,
    release_descriptor: Mapping[str, object],
    state_root: Path,
    keep_stack: bool,
) -> dict[str, object]:
    revision = _string(
        release_descriptor.get("source_revision"), "release descriptor source revision"
    )
    run_identity = hashlib.sha256(
        f"{os.getpid()}:{scenario}:{time.time_ns()}".encode()
    ).hexdigest()[:12]
    project = f"masugate-reference_demo-{scenario}-{run_identity}".replace("_", "-")
    sandbox_image = (
        f"masugate-openclaw-reference-agent-sandbox:"
        f"reference_demo-{revision[:12]}-{run_identity}"
    )
    environment = {
        **os.environ,
        "MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT": str(state_root),
        "MASUGATE_REFERENCE_DEMO_ENV_FILE": str(
            artifact_context.parent / ".masugate-compose.env"
        ),
        "MASUGATE_REFERENCE_DEMO_ARTIFACT_CONTEXT": str(artifact_context),
        "MASUGATE_REFERENCE_DEMO_COMPOSE_ROOT": str(artifact_context / "containment"),
        # reference containment deliberately gives its networks fixed names for the
        # acceptance matrix.  reference demonstration must not share their Docker DNS
        # namespace: a host lookup between two PostgreSQL transactions could
        # otherwise reach different disposable database containers.
        "MASUGATE_REFERENCE_DEMO_NETWORK_PREFIX": project,
        "MASUGATE_AGENT_SANDBOX_IMAGE": sandbox_image,
        "MASUGATE_GATEWAY_RECOVERY_HAZARD": "",
    }
    state_may_have_been_written = False
    image_was_built = False
    agent_network: str | None = None
    try:
        _cleanup_compose_project(project, environment, remove_local_images=False)
        state_may_have_been_written = True
        agent_network = _create_dynamic_agent_network(project)
        _compose(
            project,
            environment,
            "--profile",
            "sandbox-image",
            "build",
            "openclaw-agent-sandbox-image",
        )
        image_was_built = True
        _compose(
            project,
            environment,
            "up",
            "--pull",
            "never",
            "--build",
            "--detach",
            "--wait",
            "--wait-timeout",
            "180",
            "--force-recreate",
        )
        if scenario == "recovery":
            started_ns = time.time_ns()
            result = _envelope(
                scenario,
                _recovery_demo(project, environment, state_root),
                started_ns=started_ns,
                finished_ns=time.time_ns(),
                release_descriptor=release_descriptor,
            )
        else:
            result = _service_demo(project, environment, scenario, release_descriptor)
        _validate_demo_evidence(
            result,
            expected_release_descriptor=release_descriptor,
        )
        return result
    except Exception:
        try:
            print(
                _compose(project, environment, "logs", "--no-color", "--tail", "200"),
                file=sys.stderr,
            )
        except DemoRunnerError as log_error:
            print(
                f"unable to collect reference artifact failure logs: {log_error}", file=sys.stderr
            )
        try:
            print(
                "reference artifact gateway failure log:\n"
                + _compose(
                    project,
                    environment,
                    "logs",
                    "--no-color",
                    "--tail",
                    "200",
                    "openclaw-gateway",
                ),
                file=sys.stderr,
            )
        except DemoRunnerError as log_error:
            print(
                f"unable to collect reference artifact gateway failure log: {log_error}",
                file=sys.stderr,
            )
        raise
    finally:
        if not keep_stack:
            try:
                _cleanup_compose_project(project, environment, remove_local_images=True)
            finally:
                try:
                    if state_may_have_been_written:
                        _clear_state_root_from_container(state_root)
                finally:
                    try:
                        if image_was_built:
                            _remove_sandbox_image(sandbox_image)
                    finally:
                        if agent_network is not None:
                            _remove_dynamic_agent_network(agent_network)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenarios", nargs="*", choices=(*_SCENARIOS, "all"), default=["all"])
    parser.add_argument(
        "--outdir",
        type=Path,
        default=Path(tempfile.gettempdir()) / "masugate-reference_demo-demo-evidence",
        help=(
            "directory for built artifacts and JSON evidence "
            "(default: /tmp/masugate-reference_demo-demo-evidence)"
        ),
    )
    parser.add_argument(
        "--release-dir",
        type=Path,
        help="use an existing verified build-reference-release.py output instead of building one",
    )
    parser.add_argument(
        "--offline-npm-cache",
        type=Path,
        required=True,
        help=(
            "path to the package-lock-bound native npm cache required for the "
            "offline reference build context"
        ),
    )
    parser.add_argument(
        "--source-revision",
        help="immutable source revision for a reviewed staging realization",
    )
    parser.add_argument(
        "--source-date-epoch",
        type=int,
        help="Unix timestamp of --source-revision",
    )
    parser.add_argument(
        "--keep-stack",
        action="store_true",
        help="leave the final disposable stack running",
    )
    return parser.parse_args(argv)


def _run_requested_scenarios(
    requested: Sequence[str],
    *,
    release: Path,
    release_descriptor: Mapping[str, object],
    evidence_dir: Path,
    staging_root: Path,
    state_root: Path,
    keep_stack: bool,
    offline_npm_cache: Path,
) -> None:
    artifact_context = _stage_artifact_context(
        release, staging_root, offline_npm_cache=offline_npm_cache
    )
    bound_release_descriptor = _bind_staged_compose_identity(release_descriptor, artifact_context)
    _validate_release_descriptor(bound_release_descriptor)
    descriptor_path = evidence_dir / "release-descriptor.json"
    descriptor_path.write_text(
        json.dumps(bound_release_descriptor, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    for scenario in requested:
        evidence = _run_one(
            scenario,
            artifact_context=artifact_context,
            release_descriptor=bound_release_descriptor,
            state_root=state_root,
            keep_stack=keep_stack,
        )
        path = evidence_dir / f"{scenario}.json"
        path.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"MasuGate {scenario} evidence: {path}")


def _write_run_metadata(
    evidence_dir: Path,
    *,
    scenarios: Sequence[str],
    started_ns: int,
    finished_ns: int,
    elapsed_ns: int,
) -> Path:
    """Retain the command-level timing required by the flagship demonstration."""

    if started_ns <= 0 or finished_ns < started_ns or elapsed_ns < 0:
        raise DemoRunnerError("reference demonstration run timing is invalid")
    path = evidence_dir / "run-metadata.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "masugate.reference-demo-run-metadata/v1",
                "requested_scenarios": list(scenarios),
                "started_ns": started_ns,
                "finished_ns": finished_ns,
                "elapsed_ns": elapsed_ns,
                "network_access": False,
                "credentials_used": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def main(argv: Sequence[str] | None = None) -> None:
    args = _parse_args(argv)
    command_started_ns = time.time_ns()
    command_started_monotonic_ns = time.perf_counter_ns()
    requested = (*_FIVE_DEMOS, "procurement") if "all" in args.scenarios else tuple(args.scenarios)
    if len(set(requested)) != len(requested):
        raise SystemExit("each reference demonstration scenario may be requested only once")
    if args.keep_stack and len(requested) != 1:
        raise SystemExit("--keep-stack requires exactly one reference demonstration scenario")
    output = args.outdir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    release = args.release_dir.resolve() if args.release_dir is not None else output / "release"
    staging_realization_revision = _current_source_revision()
    if (args.source_revision is None) != (args.source_date_epoch is None):
        raise SystemExit("--source-revision and --source-date-epoch must be supplied together")
    source_revision = args.source_revision or staging_realization_revision
    if args.release_dir is None:
        if release.exists() and any(release.iterdir()):
            # Release outputs are immutable enough to reuse for a repeated
            # demonstration. A new output directory requests a new clean-tree
            # build, preserving the source-identity guarantee of 2.8a.
            _verify_release_output(
                release,
                expected_source_revision=source_revision,
                expected_staging_realization_revision=staging_realization_revision,
            )
        else:
            builder_args = [sys.executable, str(RELEASE_BUILDER), "--outdir", str(release)]
            if args.source_revision is not None:
                builder_args.extend(
                    [
                        "--source-revision",
                        args.source_revision,
                        "--source-date-epoch",
                        str(args.source_date_epoch),
                    ]
                )
            _run(
                tuple(builder_args),
                environment=dict(os.environ),
            )
    release_descriptor = _verify_release_output(
        release,
        expected_source_revision=source_revision,
        expected_staging_realization_revision=staging_realization_revision,
    )
    _verify_docker_runtime()
    evidence_dir = output / "evidence"
    evidence_dir.mkdir(exist_ok=True)
    if args.keep_stack:
        staging_root = output / "kept-artifacts"
        state_root = output / "kept-state"
        for path in (staging_root, state_root):
            if path.exists() and any(path.iterdir()):
                raise DemoRunnerError(f"kept-stack directory must be empty: {path}")
            path.mkdir(exist_ok=True)
        _run_requested_scenarios(
            requested,
            release=release,
            release_descriptor=release_descriptor,
            evidence_dir=evidence_dir,
            staging_root=staging_root,
            state_root=state_root,
            keep_stack=True,
            offline_npm_cache=args.offline_npm_cache,
        )
        metadata = _write_run_metadata(
            evidence_dir,
            scenarios=requested,
            started_ns=command_started_ns,
            finished_ns=time.time_ns(),
            elapsed_ns=time.perf_counter_ns() - command_started_monotonic_ns,
        )
        print(f"MasuGate run metadata: {metadata}")
        return
    with (
        tempfile.TemporaryDirectory(
            prefix="masugate-reference_demo-artifacts-", dir=output
        ) as staging,
        tempfile.TemporaryDirectory(prefix="masugate-reference_demo-state-", dir=output) as state,
    ):
        _run_requested_scenarios(
            requested,
            release=release,
            release_descriptor=release_descriptor,
            evidence_dir=evidence_dir,
            staging_root=Path(staging),
            state_root=Path(state),
            keep_stack=False,
            offline_npm_cache=args.offline_npm_cache,
        )
    metadata = _write_run_metadata(
        evidence_dir,
        scenarios=requested,
        started_ns=command_started_ns,
        finished_ns=time.time_ns(),
        elapsed_ns=time.perf_counter_ns() - command_started_monotonic_ns,
    )
    print(f"MasuGate run metadata: {metadata}")


if __name__ == "__main__":
    try:
        main()
    except (DemoRunnerError, subprocess.TimeoutExpired) as exc:
        print(f"reference demonstration demo failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
