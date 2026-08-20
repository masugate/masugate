#!/usr/bin/env python3
"""Build and attest the bounded reference release reference-release artifacts.

The script intentionally produces files only below an explicitly supplied
output directory. It never publishes an artifact. Publishing remains an
operator action after the resulting checksums, SBOM, provenance, and CI gates
have been reviewed.
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from datetime import UTC, datetime
from email.parser import Parser
from pathlib import Path
from typing import cast
from urllib.parse import quote, urlparse
from urllib.request import urlopen
from uuid import RFC_4122, UUID

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "release" / "reference-release.json"
MANIFEST_SCHEMA_PATH = ROOT / "release" / "reference-release.schema.json"
COMPATIBILITY_MATRIX_PATH = ROOT / "release" / "compatibility-matrix.json"
NPM_CLEAN_CONSUMER_LOCK_PATH = ROOT / "release" / "npm-clean-consumer-lock.json"
_NPM_CLEAN_CONSUMER_TARBALLS = {
    "@masugate/client": "masugate-client-0.1.1.tgz",
    "@masugate/adapter-core": "masugate-adapter-core-0.1.1.tgz",
    "@masugate/mcp-gateway": "masugate-mcp-gateway-0.1.1.tgz",
    "@masugate/openclaw": "masugate-openclaw-0.1.1.tgz",
}
CANONICAL_REFERENCE_SOURCE = ROOT / "src" / "masugate_openclaw_reference"
PACKAGED_REFERENCE_SOURCE = (
    ROOT / "integrations" / "openclaw-reference" / "src" / "masugate_openclaw_reference"
)
CYCLONEDX_SCHEMA_PATH = ROOT / "release" / "schemas" / "cyclonedx" / "bom-1.5.schema.json"
CYCLONEDX_SCHEMA_SHA256 = "067f7824b08653839ea050ae9e09ca48375eadc2652b0e2a299476e7db90335b"
_FIRST_PARTY_RUNTIME_PROJECTS = {
    "masugate-connector-sdk": ROOT / "connectors" / "sdk" / "pyproject.toml",
}
_PYTHON_RELEASE_PROJECTS: tuple[tuple[str, Path, str], ...] = (
    ("platform", ROOT, "masugate"),
    ("connector_sdk", ROOT / "connectors" / "sdk", "masugate-connector-sdk"),
    ("python_client", ROOT / "clients" / "python", "masugate-client"),
    ("adapter_core", ROOT / "adapters" / "python", "masugate-adapter-core"),
    ("langchain_adapter", ROOT / "adapters" / "langchain", "masugate-langchain"),
    ("agent_framework_adapter", ROOT / "adapters" / "agent-framework", "masugate-agent-framework"),
    ("crewai_adapter", ROOT / "adapters" / "crewai", "masugate-crewai"),
    (
        "google_calendar_connector",
        ROOT / "connectors" / "google-calendar",
        "masugate-connector-google-calendar",
    ),
    (
        "stripe_payment_intent_connector",
        ROOT / "connectors" / "stripe-payment-intent",
        "masugate-connector-stripe-payment-intent",
    ),
    ("filesystem_connector", ROOT / "connectors" / "filesystem", "masugate-connector-filesystem"),
    ("calendar_operation", ROOT / "operations" / "calendar", "masugate-operation-calendar"),
    ("spend_operation", ROOT / "operations" / "spend", "masugate-operation-spend"),
    ("filesystem_operation", ROOT / "operations" / "filesystem", "masugate-operation-filesystem"),
    ("reference_deployment", ROOT / "integrations" / "openclaw-reference", "reference"),
)


class ReleaseBuildError(RuntimeError):
    """Raised when declared and buildable reference-release identities diverge."""


def _json(path: Path) -> dict[str, object]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ReleaseBuildError(f"{path} must contain a JSON object")
    return cast(dict[str, object], raw)


def _require_mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ReleaseBuildError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReleaseBuildError(f"{label} must be a non-empty string")
    return value


def _toml_version(path: Path) -> str:
    project = _toml_project(path)
    return _require_string(project.get("version"), f"{path} project.version")


def _toml_project(path: Path) -> dict[str, object]:
    import tomllib

    raw = tomllib.loads(path.read_text(encoding="utf-8"))
    return _require_mapping(raw.get("project"), f"{path} project")


def _package_version(path: Path) -> str:
    raw = _json(path)
    return _require_string(raw.get("version"), f"{path} version")


def _typescript_contract_version() -> str:
    path = ROOT / "clients" / "typescript" / "src" / "adapter-contract.ts"
    match = re.search(
        r'^export const HOST_ADAPTER_CONTRACT_VERSION = "([^"]+)";$',
        path.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    if match is None:
        raise ReleaseBuildError(f"cannot resolve host-adapter contract identity from {path}")
    return match.group(1)


def _validate_artifact_identities(artifacts: dict[str, object]) -> None:
    for name, project, _output in _PYTHON_RELEASE_PROJECTS:
        source = _toml_project(project / "pyproject.toml")
        declared = _require_mapping(artifacts.get(name), f"artifacts.{name}")
        if declared.get("distribution") != source.get("name"):
            raise ReleaseBuildError(
                f"artifacts.{name}.distribution does not match {project / 'pyproject.toml'}"
            )
    platform_path = ROOT / "pyproject.toml"
    platform_source = _toml_project(platform_path)
    platform = _require_mapping(artifacts.get("platform"), "artifacts.platform")
    if platform.get("distribution") != platform_source.get("name"):
        raise ReleaseBuildError("platform distribution does not match pyproject project.name")
    scripts = _require_mapping(platform_source.get("scripts"), "platform project.scripts")
    entry_point = _require_string(platform.get("entry_point"), "platform entry_point")
    if scripts.get(entry_point) != "masugate.masugated.cli:main":
        raise ReleaseBuildError("platform entry point does not resolve to masugated's source CLI")
    protocol_contract = _require_string(
        platform.get("protocol_contract"), "platform protocol_contract"
    )
    if protocol_contract != _typescript_contract_version():
        raise ReleaseBuildError("platform protocol contract does not match the client source")

    connector_sdk_source = _toml_project(ROOT / "connectors" / "sdk" / "pyproject.toml")
    connector_sdk = _require_mapping(artifacts.get("connector_sdk"), "artifacts.connector_sdk")
    if connector_sdk.get("distribution") != connector_sdk_source.get("name"):
        raise ReleaseBuildError("connector SDK distribution does not match project.name")

    python_client_source = _toml_project(ROOT / "clients" / "python" / "pyproject.toml")
    python_client = _require_mapping(artifacts.get("python_client"), "artifacts.python_client")
    if python_client.get("distribution") != python_client_source.get("name"):
        raise ReleaseBuildError("Python client distribution does not match project.name")

    typescript_source = _json(ROOT / "clients" / "typescript" / "package.json")
    typescript_client = _require_mapping(
        artifacts.get("typescript_client"), "artifacts.typescript_client"
    )
    if typescript_client.get("package") != typescript_source.get("name"):
        raise ReleaseBuildError("TypeScript client package does not match package.json")

    adapter_core_source = _json(ROOT / "adapters" / "typescript" / "package.json")
    adapter_core = _require_mapping(
        artifacts.get("typescript_adapter_core"), "artifacts.typescript_adapter_core"
    )
    if adapter_core.get("package") != adapter_core_source.get("name"):
        raise ReleaseBuildError("TypeScript adapter-core package does not match package.json")
    adapter_core_dependencies = _require_mapping(
        adapter_core_source.get("dependencies"), "TypeScript adapter-core dependencies"
    )
    if adapter_core.get("client_dependency") != adapter_core_dependencies.get("@masugate/client"):
        raise ReleaseBuildError(
            "TypeScript adapter-core client dependency does not match package.json"
        )

    gateway_source = _json(ROOT / "gateway" / "package.json")
    gateway = _require_mapping(artifacts.get("mcp_gateway"), "artifacts.mcp_gateway")
    if gateway.get("package") != gateway_source.get("name"):
        raise ReleaseBuildError("MCP gateway package does not match package.json")
    gateway_dependencies = _require_mapping(
        gateway_source.get("dependencies"), "MCP gateway dependencies"
    )
    if gateway.get("client_dependency") != gateway_dependencies.get("@masugate/client"):
        raise ReleaseBuildError("MCP gateway client dependency does not match package.json")

    adapter_source = _json(ROOT / "integrations" / "openclaw" / "package.json")
    adapter = _require_mapping(artifacts.get("openclaw_adapter"), "artifacts.openclaw_adapter")
    if adapter.get("package") != adapter_source.get("name"):
        raise ReleaseBuildError("OpenClaw adapter package does not match package.json")
    adapter_dependencies = _require_mapping(
        adapter_source.get("dependencies"), "OpenClaw adapter dependencies"
    )
    adapter_client = _require_string(
        adapter_dependencies.get("@masugate/client"), "OpenClaw adapter client"
    )
    adapter_core_dependency = _require_string(
        adapter_dependencies.get("@masugate/adapter-core"), "OpenClaw adapter-core dependency"
    )
    bundled_dependencies = adapter_source.get("bundledDependencies")
    if (
        not isinstance(bundled_dependencies, list)
        or any(type(value) is not str for value in bundled_dependencies)
        or set(bundled_dependencies) != set(adapter_dependencies)
        or adapter.get("bundled_dependencies") != bundled_dependencies
    ):
        raise ReleaseBuildError(
            "OpenClaw adapter must bundle its complete runtime dependency closure"
        )
    build_command = _require_string(
        _require_mapping(adapter_source.get("scripts"), "OpenClaw adapter scripts").get("build"),
        "OpenClaw adapter build command",
    )
    if (
        "--external:@masugate/client" in build_command
        or "--external:@masugate/adapter-core" in build_command
        or adapter.get("client_dependency") != adapter_client
        or adapter.get("adapter_core_dependency") != adapter_core_dependency
    ):
        raise ReleaseBuildError("OpenClaw adapter runtime dependencies do not match source")

    reference_source = _toml_project(
        ROOT / "integrations" / "openclaw-reference" / "pyproject.toml"
    )
    reference = _require_mapping(
        artifacts.get("reference_deployment"), "artifacts.reference_deployment"
    )
    if reference.get("distribution") != reference_source.get("name"):
        raise ReleaseBuildError("reference distribution does not match project.name")
    platform_version = _require_string(platform.get("version"), "platform version")
    expected_platform_dependency = f"masugate=={platform_version}"
    connector_sdk_version = _require_string(connector_sdk.get("version"), "connector SDK version")
    expected_connector_sdk_dependency = f"masugate-connector-sdk=={connector_sdk_version}"
    platform_dependencies = platform_source.get("dependencies")
    if (
        not isinstance(platform_dependencies, list)
        or expected_connector_sdk_dependency not in platform_dependencies
        or platform.get("connector_sdk_dependency") != expected_connector_sdk_dependency
    ):
        raise ReleaseBuildError("platform connector SDK dependency is not exact")
    python_client_version = _require_string(python_client.get("version"), "Python client version")
    expected_python_client_dependency = f"masugate-client=={python_client_version}"
    dependencies = reference_source.get("dependencies")
    if (
        dependencies != [expected_platform_dependency, expected_python_client_dependency]
        or reference.get("platform_dependency") != expected_platform_dependency
        or reference.get("python_client_dependency") != expected_python_client_dependency
    ):
        raise ReleaseBuildError(
            "reference deployment platform dependency or Python client dependency is not exact"
        )


def _catalog_identities() -> tuple[str, ...]:
    identities: list[str] = []
    for path in sorted((ROOT / "src" / "masugate" / "catalog").glob("reference_*/bundle.json")):
        bundle = _require_mapping(_json(path).get("bundle"), f"{path} bundle")
        identity = (
            _require_string(bundle.get("id"), f"{path} bundle.id")
            + "@"
            + _require_string(bundle.get("version"), f"{path} bundle.version")
        )
        identities.append(identity)
    if not identities:
        raise ReleaseBuildError("no reference catalog bundles were found")
    if len(identities) != len(set(identities)):
        raise ReleaseBuildError("reference catalog bundle identities must be unique")
    return tuple(sorted(identities))


def _validate_reference_demo_spend_authorization(manifest: dict[str, object]) -> None:
    """Bind the reference artifact evidence anchor to the shipped spend artifacts."""

    from masugate.catalog.loader import load_bundle
    from masugate.providers import SpendPolicy

    declared = _require_mapping(
        manifest.get("reference_demo_spend_authorization"), "reference_demo_spend_authorization"
    )
    configuration = _require_mapping(
        declared.get("configuration"), "reference_demo spend configuration"
    )
    if set(configuration) != {
        "approval_threshold_cents",
        "approval_timeout_seconds",
        "budget_limit_cents",
        "scope_derivation",
    }:
        raise ReleaseBuildError("reference_demo spend configuration has an incompatible shape")
    for field in (
        "approval_threshold_cents",
        "approval_timeout_seconds",
        "budget_limit_cents",
    ):
        if type(configuration.get(field)) is not int:
            raise ReleaseBuildError(
                f"reference_demo spend configuration {field} must be an integer"
            )
    if configuration.get("scope_derivation") != "masugate.spend.reference.scopes.v1":
        raise ReleaseBuildError("reference_demo spend configuration has the wrong scope derivation")
    policy = _require_mapping(declared.get("policy"), "reference_demo spend policy")
    if set(policy) != {
        "bundle_digest",
        "bundle_id",
        "bundle_version",
        "layer",
        "mode",
        "policy_declared_version",
        "policy_digest",
        "policy_id",
        "policy_runtime_version",
    }:
        raise ReleaseBuildError("reference_demo spend policy anchor has an incompatible shape")
    bundle = load_bundle(ROOT / "src" / "masugate" / "catalog" / "reference_spend")
    if len(bundle.policies) != 1:
        raise ReleaseBuildError("reference spend catalog must contain exactly one policy")
    loaded = bundle.policies[0]
    expected_policy = {
        "bundle_digest": bundle.digest,
        "bundle_id": bundle.bundle_id,
        "bundle_version": bundle.version,
        "layer": bundle.layer.value,
        "mode": bundle.mode.value,
        "policy_declared_version": loaded.version,
        "policy_digest": loaded.semantic_sha256,
        "policy_id": loaded.policy_id,
        "policy_runtime_version": loaded.semantic_sha256[:16],
    }
    if policy != expected_policy:
        raise ReleaseBuildError(
            "reference_demo spend policy anchor does not match the source catalog"
        )
    configured = SpendPolicy(
        budget_limit_cents=cast(int, configuration["budget_limit_cents"]),
        approval_threshold_cents=cast(int, configuration["approval_threshold_cents"]),
        approval_timeout_seconds=cast(int, configuration["approval_timeout_seconds"]),
        policy_id=loaded.policy_id,
        policy_version=loaded.version,
        bundle_id=bundle.bundle_id,
        bundle_version=bundle.version,
    )
    if declared.get("configuration_digest") != configured.configuration_digest:
        raise ReleaseBuildError(
            "reference_demo spend configuration anchor does not match the provider configuration"
        )


def _provider_identities() -> tuple[tuple[str, str], ...]:
    identities: list[tuple[str, str]] = []
    providers = ROOT / "src" / "masugate" / "providers"
    for path in sorted(providers.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        constants = {
            target.id: node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign | ast.AnnAssign)
            for target in (node.targets if isinstance(node, ast.Assign) else (node.target,))
            if isinstance(target, ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        }
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            if not isinstance(call.func, ast.Name) or call.func.id != "ProviderIdentity":
                continue
            keywords = {keyword.arg: keyword.value for keyword in call.keywords if keyword.arg}
            provider = keywords.get("provider_id")
            implementation = keywords.get("implementation_version")
            # Deserialization reconstructs a ProviderIdentity dynamically and is
            # not a declaration of a shipped provider implementation.
            if not isinstance(provider, ast.Constant) or not isinstance(provider.value, str):
                continue
            implementation_version: str | None
            if isinstance(implementation, ast.Constant) and isinstance(implementation.value, str):
                implementation_version = implementation.value
            elif isinstance(implementation, ast.Name):
                implementation_version = constants.get(implementation.id)
            else:
                implementation_version = None
            if implementation_version is None:
                raise ReleaseBuildError(f"cannot resolve ProviderIdentity implementation in {path}")
            identities.append((provider.value, implementation_version))
    if not identities:
        raise ReleaseBuildError("no source ProviderIdentity declarations were found")
    if len(identities) != len(set(identities)):
        raise ReleaseBuildError("source ProviderIdentity declarations must be unique")
    return tuple(sorted(identities))


def _declared_provider_identities(manifest: dict[str, object]) -> tuple[tuple[str, str], ...]:
    modules = manifest.get("provider_modules")
    if not isinstance(modules, list) or not modules:
        raise ReleaseBuildError(
            "provider_modules must declare the released provider implementations"
        )
    identities = tuple(
        (
            _require_string(
                _require_mapping(module, "provider module").get("id"), "provider module id"
            ),
            _require_string(
                _require_mapping(module, "provider module").get("implementation_version"),
                "provider implementation version",
            ),
        )
        for module in modules
    )
    if len(identities) != len(set(identities)):
        raise ReleaseBuildError("provider_modules identities must be unique")
    return tuple(sorted(identities))


def _validate_openclaw_identity(artifacts: dict[str, object]) -> str:
    adapter_manifest = _json(ROOT / "integrations" / "openclaw" / "package.json")
    contracts = tuple(
        sorted((ROOT / "integrations" / "openclaw-contract" / "contract").glob("openclaw-v*.json"))
    )
    if len(contracts) != 1:
        raise ReleaseBuildError("exactly one accepted OpenClaw host contract is required")
    host_contract = _json(contracts[0])
    contract_release = _require_mapping(host_contract.get("release"), "host contract release")
    contract_node = _require_mapping(host_contract.get("node"), "host contract node")
    contract_npm = _require_mapping(host_contract.get("npm"), "host contract npm")
    contract_container = _require_mapping(host_contract.get("container"), "host contract container")
    adapter = _require_mapping(artifacts.get("openclaw_adapter"), "OpenClaw adapter")
    peer = _require_string(adapter.get("openclaw_peer"), "OpenClaw adapter peer")
    peer_dependencies = _require_mapping(
        adapter_manifest.get("peerDependencies"), "OpenClaw peerDependencies"
    )
    workspace_manifest = _json(ROOT / "package.json")
    development_dependencies = _require_mapping(
        workspace_manifest.get("devDependencies"), "workspace devDependencies"
    )
    openclaw = _require_mapping(adapter_manifest.get("openclaw"), "OpenClaw metadata")
    compatibility = _require_mapping(openclaw.get("compat"), "OpenClaw compatibility")
    engines = _require_mapping(adapter_manifest.get("engines"), "OpenClaw engines")
    containment = _json(
        ROOT / "integrations" / "openclaw-reference" / "containment" / "manifest.json"
    )
    pinned = _require_mapping(containment.get("pinned_openclaw"), "pinned OpenClaw")
    release_tag = _require_string(contract_release.get("tag"), "host contract release.tag")
    if not release_tag.startswith("v"):
        raise ReleaseBuildError("OpenClaw host contract release tag must start with 'v'")
    node_version = _require_string(contract_node.get("version"), "host contract node.version")
    peer_sources = {
        "release manifest": peer,
        "adapter peer dependency": _require_string(
            peer_dependencies.get("openclaw"), "OpenClaw peer dependency"
        ),
        "workspace development dependency": _require_string(
            development_dependencies.get("openclaw"), "workspace OpenClaw development dependency"
        ),
        "adapter plugin API": _require_string(
            compatibility.get("pluginApi"), "OpenClaw plugin API"
        ),
        "adapter minimum gateway": _require_string(
            compatibility.get("minGatewayVersion"), "OpenClaw minimum gateway"
        ),
        "host contract release": release_tag[1:],
        "host contract npm": _require_string(
            contract_npm.get("version"), "host contract npm.version"
        ),
        "containment profile": _require_string(pinned.get("version"), "pinned OpenClaw version"),
    }
    if set(peer_sources.values()) != {peer}:
        raise ReleaseBuildError(f"OpenClaw release identities diverge: {peer_sources!r}")
    node_sources = {
        "adapter engine": _require_string(engines.get("node"), "OpenClaw adapter Node engine"),
        "host contract": node_version,
        "host container": _require_string(
            contract_container.get("nodeVersion"), "host container Node version"
        ),
        "containment profile": _require_string(
            pinned.get("node_runtime"), "pinned OpenClaw Node runtime"
        ),
    }
    if set(node_sources.values()) != {node_version}:
        raise ReleaseBuildError(f"OpenClaw Node identities diverge: {node_sources!r}")
    return _require_string(contract_container.get("image"), "host contract container.image")


def _containment_images() -> tuple[str, ...]:
    containment = ROOT / "integrations" / "openclaw-reference" / "containment"
    images: list[str] = []
    for path in sorted(containment.glob("Dockerfile*")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.startswith("FROM "):
                continue
            image = line.split()[1]
            if "@sha256:" not in image:
                raise ReleaseBuildError(
                    f"container base image is not digest-pinned: {path}: {image}"
                )
            images.append(image)
    compose = containment / "compose.yaml"
    for match in re.finditer(
        r"^\s*image:\s*([^\s#]+)", compose.read_text(encoding="utf-8"), re.MULTILINE
    ):
        image = match.group(1).strip("'\"")
        if "@sha256:" in image:
            images.append(image)
        elif not image.startswith("masugate-openclaw-reference-"):
            raise ReleaseBuildError(f"external Compose image is not digest-pinned: {image}")
    if not images:
        raise ReleaseBuildError("containment sources declare no digest-pinned images")
    return tuple(sorted(set(images)))


def _validate_sandbox_profile(manifest: dict[str, object]) -> None:
    expected = {
        "containment_manifest": "integrations/openclaw-reference/containment/manifest.json",
        "profile": "integrations/openclaw-reference/containment/profile.json",
    }
    profile = _require_mapping(manifest.get("sandbox_profile"), "sandbox_profile")
    if profile != expected:
        raise ReleaseBuildError("sandbox profile paths do not identify the release profile")
    containment = _json(ROOT / expected["containment_manifest"])
    if containment.get("schema_version") != "masugate.openclaw-reference.containment/v1":
        raise ReleaseBuildError("containment manifest schema identity is incompatible")
    if containment.get("profile_id") != "masugate-openclaw-reference/v1":
        raise ReleaseBuildError("containment manifest profile identity is incompatible")
    sandbox = _json(ROOT / expected["profile"])
    if sandbox.get("schema_version") != "masugate.openclaw-reference.profile/v1":
        raise ReleaseBuildError("sandbox profile schema identity is incompatible")


def _compare_locked_package(
    source_path: Path,
    locked: dict[str, object],
    *,
    label: str,
) -> None:
    source = _json(source_path)
    for field in (
        "name",
        "version",
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "peerDependenciesMeta",
        "engines",
    ):
        if source.get(field) != locked.get(field):
            raise ReleaseBuildError(f"{label} lock field {field!r} does not match {source_path}")
    if source.get("bundledDependencies") != locked.get("bundleDependencies"):
        raise ReleaseBuildError(
            f"{label} lock bundled runtime dependencies do not match {source_path}"
        )


def _validate_npm_locks(manifest: dict[str, object]) -> None:
    expected = {
        "python": "release/requirements/pylock.masugate-platform.toml",
        "npm": "package-lock.json",
        "gateway_shrinkwrap": "gateway/npm-shrinkwrap.json",
        "openclaw_contract": "integrations/openclaw-contract/package-lock.json",
        "npm_clean_consumer": "release/npm-clean-consumer-lock.json",
    }
    locks = _require_mapping(manifest.get("locks"), "locks")
    if locks != expected:
        raise ReleaseBuildError("release lock paths do not identify the supported lock set")
    for label, relative in expected.items():
        path = ROOT / relative
        if not path.is_file():
            raise ReleaseBuildError(f"declared release lock is missing: {label}: {path}")

    workspace_source = _json(ROOT / "package.json")
    workspace_lock = _json(ROOT / expected["npm"])
    packages = _require_mapping(workspace_lock.get("packages"), "npm lock packages")
    root_lock = _require_mapping(packages.get(""), "npm lock workspace root")
    for field in ("name", "workspaces"):
        if workspace_source.get(field) != root_lock.get(field):
            raise ReleaseBuildError(f"npm workspace lock field {field!r} is stale")
    for location in (
        "clients/typescript",
        "adapters/typescript",
        "gateway",
        "integrations/openclaw",
    ):
        _compare_locked_package(
            ROOT / location / "package.json",
            _require_mapping(packages.get(location), f"npm lock {location}"),
            label=location,
        )

    contract_path = ROOT / "integrations" / "openclaw-contract"
    contract_lock = _json(ROOT / expected["openclaw_contract"])
    contract_packages = _require_mapping(
        contract_lock.get("packages"), "OpenClaw contract lock packages"
    )
    _compare_locked_package(
        contract_path / "package.json",
        _require_mapping(contract_packages.get(""), "OpenClaw contract lock root"),
        label="OpenClaw contract",
    )
    locked_openclaw = _require_mapping(
        contract_packages.get("node_modules/openclaw"), "locked OpenClaw package"
    )
    contracts = tuple(sorted((contract_path / "contract").glob("openclaw-v*.json")))
    if len(contracts) != 1:
        raise ReleaseBuildError("exactly one OpenClaw contract is required for lock validation")
    host_npm = _require_mapping(_json(contracts[0]).get("npm"), "host contract npm")
    for field in ("version", "integrity"):
        if locked_openclaw.get(field) != host_npm.get(field):
            raise ReleaseBuildError(f"locked OpenClaw {field} does not match the host contract")
    marker = "file:__MASUGATE_RELEASE_NPM__"
    consumer_lock = _json(NPM_CLEAN_CONSUMER_LOCK_PATH)
    consumer_packages = _require_mapping(consumer_lock.get("packages"), "clean consumer packages")
    consumer_root = _require_mapping(consumer_packages.get(""), "clean consumer root")
    if consumer_root.get("name") != "@masugate/clean-consumer":
        raise ReleaseBuildError("npm clean-consumer lock has an unexpected root identity")
    consumer_dependencies = _require_mapping(
        consumer_root.get("dependencies"), "clean consumer dependencies"
    )
    if consumer_dependencies.get("openclaw") != host_npm.get("version"):
        raise ReleaseBuildError("npm clean-consumer OpenClaw version does not match host contract")
    for package, filename in {
        "@masugate/client": "masugate-client-0.1.1.tgz",
        "@masugate/adapter-core": "masugate-adapter-core-0.1.1.tgz",
        "@masugate/mcp-gateway": "masugate-mcp-gateway-0.1.1.tgz",
        "@masugate/openclaw": "masugate-openclaw-0.1.1.tgz",
    }.items():
        if consumer_dependencies.get(package) != marker + "/" + filename:
            raise ReleaseBuildError(f"npm clean-consumer does not select {package}'s built tarball")
        record = _require_mapping(
            consumer_packages.get(f"node_modules/{package}"),
            f"clean consumer record for {package}",
        )
        if record.get("resolved") != marker + "/" + filename:
            raise ReleaseBuildError(
                f"npm clean-consumer does not resolve {package} from its portable tarball marker"
            )
    for location, record in consumer_packages.items():
        if not isinstance(location, str) or not isinstance(record, dict):
            continue
        resolved = record.get("resolved")
        if isinstance(resolved, str) and resolved.startswith("file:"):
            package = location.rsplit("node_modules/", 1)[-1]
            if package not in {
                "@masugate/client",
                "@masugate/adapter-core",
                "@masugate/mcp-gateway",
                "@masugate/openclaw",
            }:
                raise ReleaseBuildError(
                    f"npm clean-consumer has an unexpected local dependency at {location}"
                )

    gateway_shrinkwrap = _json(ROOT / expected["gateway_shrinkwrap"])
    shrinkwrap_packages = _require_mapping(
        gateway_shrinkwrap.get("packages"), "gateway npm shrinkwrap packages"
    )
    _compare_locked_package(
        ROOT / "gateway" / "package.json",
        _require_mapping(shrinkwrap_packages.get(""), "gateway shrinkwrap root"),
        label="gateway shrinkwrap",
    )
    client_version = _package_version(ROOT / "clients" / "typescript" / "package.json")
    for location, raw_entry in shrinkwrap_packages.items():
        if not location:
            continue
        entry = _require_mapping(raw_entry, f"gateway shrinkwrap {location}")
        if location == "node_modules/@masugate/client":
            if entry.get("version") != client_version:
                raise ReleaseBuildError("gateway shrinkwrap client identity does not match source")
            continue
        workspace_entry = _require_mapping(
            packages.get("gateway/" + location), "workspace npm lock gateway/" + location
        )
        for field in (
            "version",
            "integrity",
            "resolved",
            "dependencies",
            "optionalDependencies",
            "peerDependencies",
            "peerDependenciesMeta",
        ):
            if entry.get(field) != workspace_entry.get(field):
                raise ReleaseBuildError(
                    f"gateway shrinkwrap {field} does not match the workspace lock: {location}"
                )


def load_and_validate_manifest() -> dict[str, object]:
    """Validate static release identity without requiring build tooling."""

    manifest = _json(MANIFEST_PATH)
    schema = _json(MANIFEST_SCHEMA_PATH)
    try:
        jsonschema = importlib.import_module("jsonschema")
    except ModuleNotFoundError as exc:  # pragma: no cover - CI/test dependency
        raise ReleaseBuildError("jsonschema is required to validate the release manifest") from exc
    jsonschema.Draft202012Validator.check_schema(schema)
    try:
        jsonschema.Draft202012Validator(schema).validate(manifest)
    except jsonschema.ValidationError as exc:
        raise ReleaseBuildError(f"release manifest is invalid: {exc.message}") from exc

    artifacts = _require_mapping(manifest["artifacts"], "artifacts")
    checks = (
        ("platform", ROOT / "pyproject.toml", _toml_version),
        ("connector_sdk", ROOT / "connectors" / "sdk" / "pyproject.toml", _toml_version),
        ("python_client", ROOT / "clients" / "python" / "pyproject.toml", _toml_version),
        ("adapter_core", ROOT / "adapters" / "python" / "pyproject.toml", _toml_version),
        ("langchain_adapter", ROOT / "adapters" / "langchain" / "pyproject.toml", _toml_version),
        (
            "agent_framework_adapter",
            ROOT / "adapters" / "agent-framework" / "pyproject.toml",
            _toml_version,
        ),
        ("crewai_adapter", ROOT / "adapters" / "crewai" / "pyproject.toml", _toml_version),
        (
            "google_calendar_connector",
            ROOT / "connectors" / "google-calendar" / "pyproject.toml",
            _toml_version,
        ),
        (
            "stripe_payment_intent_connector",
            ROOT / "connectors" / "stripe-payment-intent" / "pyproject.toml",
            _toml_version,
        ),
        (
            "filesystem_connector",
            ROOT / "connectors" / "filesystem" / "pyproject.toml",
            _toml_version,
        ),
        ("calendar_operation", ROOT / "operations" / "calendar" / "pyproject.toml", _toml_version),
        ("spend_operation", ROOT / "operations" / "spend" / "pyproject.toml", _toml_version),
        (
            "filesystem_operation",
            ROOT / "operations" / "filesystem" / "pyproject.toml",
            _toml_version,
        ),
        ("typescript_client", ROOT / "clients" / "typescript" / "package.json", _package_version),
        (
            "typescript_adapter_core",
            ROOT / "adapters" / "typescript" / "package.json",
            _package_version,
        ),
        ("mcp_gateway", ROOT / "gateway" / "package.json", _package_version),
        ("openclaw_adapter", ROOT / "integrations" / "openclaw" / "package.json", _package_version),
        (
            "reference_deployment",
            ROOT / "integrations" / "openclaw-reference" / "pyproject.toml",
            _toml_version,
        ),
    )
    for name, path, version_loader in checks:
        declared = _require_mapping(artifacts.get(name), f"artifacts.{name}")
        declared_version = _require_string(declared.get("version"), f"artifacts.{name}.version")
        actual_version = version_loader(path)
        if declared_version != actual_version:
            raise ReleaseBuildError(
                f"artifacts.{name}.version={declared_version!r} does not match {path}: "
                f"{actual_version!r}"
            )
    _validate_artifact_identities(artifacts)
    _validate_reference_source_copy()

    release_id = _require_string(manifest.get("release_id"), "release_id")
    reference = _require_mapping(artifacts.get("reference_deployment"), "reference deployment")
    if release_id != "masugate-openclaw-reference/" + _require_string(
        reference.get("version"), "reference deployment version"
    ):
        raise ReleaseBuildError("release_id must name the exact reference deployment version")
    if manifest.get("runtime_target") != {
        "os": "linux",
        "architecture": "amd64",
        "python_abi": "cp312",
    }:
        raise ReleaseBuildError(
            "runtime_target must name the linux/amd64 CPython 3.12 artifact premise"
        )
    schema_identity = _require_mapping(reference.get("schema"), "reference schema")
    if schema_identity != {
        "id": "masugate-openclaw-reference",
        "version": 1,
        "boundary": "clean-install-only",
        "metadata_table": "masugate_release_metadata",
    }:
        raise ReleaseBuildError(
            "reference schema manifest does not match the clean-install boundary"
        )

    catalogs = manifest.get("catalogs")
    if not isinstance(catalogs, list) or not all(isinstance(item, str) for item in catalogs):
        raise ReleaseBuildError("catalogs must be a list of bundle identities")
    declared_catalogs = tuple(sorted(cast(list[str], catalogs)))
    source_catalogs = _catalog_identities()
    if declared_catalogs != source_catalogs:
        raise ReleaseBuildError(
            f"declared catalogs do not match source bundles: "
            f"declared={declared_catalogs!r}, source={source_catalogs!r}"
        )
    declared_providers = _declared_provider_identities(manifest)
    source_providers = _provider_identities()
    if declared_providers != source_providers:
        raise ReleaseBuildError(
            f"declared provider modules do not match source identities: "
            f"declared={declared_providers!r}, source={source_providers!r}"
        )
    _validate_reference_demo_spend_authorization(manifest)
    openclaw_image = _validate_openclaw_identity(artifacts)
    _validate_sandbox_profile(manifest)

    images = _require_mapping(manifest["container_images"], "container_images")
    declared_images: list[str] = []
    for image_name, image in images.items():
        rendered = _require_string(image, f"container_images.{image_name}")
        if "@sha256:" not in rendered:
            raise ReleaseBuildError(f"container_images.{image_name} is not digest-pinned")
        declared_images.append(rendered)
    if len(declared_images) != len(set(declared_images)):
        raise ReleaseBuildError("container image declarations must be unique")
    source_images = tuple(sorted({openclaw_image, *_containment_images()}))
    if tuple(sorted(declared_images)) != source_images:
        raise ReleaseBuildError(
            f"declared container images do not match deployment sources: "
            f"declared={tuple(sorted(declared_images))!r}, source={source_images!r}"
        )
    _validate_container_artifact_declaration(manifest)
    _validate_npm_locks(manifest)
    _validate_python_lock(manifest)
    _validate_compatibility_matrix(manifest)
    _validate_package_catalog(manifest)
    provenance = _require_mapping(manifest.get("provenance"), "provenance")
    if provenance != {
        "generator": "scripts/build-reference-release.py",
        "source_revision": "recorded-at-build-or-supplied-origin",
        "staging_realization_revision": "recorded-at-build",
        "checksums": "SHA-256",
        "sbom": "CycloneDX 1.5 JSON",
        "sbom_schema": "release/schemas/cyclonedx/bom-1.5.schema.json",
        "sbom_schema_sha256": CYCLONEDX_SCHEMA_SHA256,
    }:
        raise ReleaseBuildError("release provenance declarations are incompatible")
    if (
        not CYCLONEDX_SCHEMA_PATH.is_file()
        or _sha256(CYCLONEDX_SCHEMA_PATH) != CYCLONEDX_SCHEMA_SHA256
    ):
        raise ReleaseBuildError("release CycloneDX schema is missing or has drifted")
    return manifest


def _validate_python_lock(manifest: dict[str, object]) -> None:
    """Require the platform's direct pins to be resolved in the checked-in lock."""

    import tomllib

    locks = _require_mapping(manifest["locks"], "locks")
    lock_path = ROOT / _require_string(locks["python"], "locks.python")
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ReleaseBuildError(f"{lock_path} must contain resolved packages")
    resolved = {
        _require_string(
            _require_mapping(package, "locked package").get("name"), "locked name"
        ): _require_string(
            _require_mapping(package, "locked package").get("version"), "locked version"
        )
        for package in packages
    }
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    direct = _require_mapping(project.get("project"), "pyproject project").get("dependencies")
    if not isinstance(direct, list):
        raise ReleaseBuildError("pyproject project.dependencies must be a list")
    for requirement in direct:
        rendered = _require_string(requirement, "direct dependency")
        if "==" not in rendered:
            raise ReleaseBuildError(f"direct dependency is not exactly pinned: {rendered}")
        name, version = rendered.split("==", 1)
        normalized = name.split("[", 1)[0]
        first_party = _FIRST_PARTY_RUNTIME_PROJECTS.get(normalized)
        if first_party is not None:
            if _toml_version(first_party) != version:
                raise ReleaseBuildError(
                    f"first-party runtime dependency {normalized} does not match {first_party}"
                )
            continue
        if resolved.get(normalized) != version:
            raise ReleaseBuildError(
                f"Python lock does not resolve {normalized}=={version}; "
                f"found {resolved.get(normalized)!r}"
            )


def _validate_reference_source_copy() -> None:
    """Reject a release package payload that drifts from the canonical source."""

    def inventory(root: Path) -> dict[str, str]:
        if not root.is_dir():
            raise ReleaseBuildError(f"reference source directory is missing: {root}")
        files = [
            path
            for path in sorted(root.rglob("*"))
            if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
        ]
        if not files:
            raise ReleaseBuildError(f"reference source directory is empty: {root}")
        return {path.relative_to(root).as_posix(): _sha256(path) for path in files}

    if inventory(PACKAGED_REFERENCE_SOURCE) != inventory(CANONICAL_REFERENCE_SOURCE):
        raise ReleaseBuildError(
            "reference package src payload drifts from canonical reference source"
        )


def _validate_container_artifact_declaration(manifest: dict[str, object]) -> None:
    """Keep the private first-party container set explicit and closed."""

    declared = _require_mapping(manifest.get("container_artifact"), "container artifact")
    expected = {
        "archive": "masugate-reference-images.tar",
        "images": [
            {
                "role": "agent-sandbox",
                "dockerfile": "Dockerfile.reference_demo-agent-probe",
                "compose_services": ["openclaw-agent-sandbox-image"],
            },
            {
                "role": "gateway",
                "dockerfile": "Dockerfile.reference_demo-gateway",
                "compose_services": ["openclaw-gateway"],
            },
            {
                "role": "safe-content",
                "dockerfile": "Dockerfile.reference_demo-safe-content",
                "compose_services": ["safe-content"],
            },
            {
                "role": "reference",
                "dockerfile": "Dockerfile.reference_demo-reference",
                "compose_services": ["masugated", "reference-purchase"],
            },
        ],
    }
    if declared != expected:
        raise ReleaseBuildError(
            "private first-party container artifact declaration is incompatible"
        )


def _validate_compatibility_matrix(manifest: dict[str, object]) -> None:
    """Require the checked-in matrix to describe this exact release boundary."""

    matrix = _json(COMPATIBILITY_MATRIX_PATH)
    if matrix.get("schema_version") != "masugate.reference-release.compatibility/v1":
        raise ReleaseBuildError("compatibility matrix has an incompatible schema")
    if matrix.get("release_id") != manifest.get("release_id"):
        raise ReleaseBuildError("compatibility matrix release identity drifts from the manifest")
    if matrix.get("runtime_target") != manifest.get("runtime_target"):
        raise ReleaseBuildError("compatibility matrix runtime target drifts from the manifest")
    raw_artifacts = matrix.get("artifacts")
    if not isinstance(raw_artifacts, list):
        raise ReleaseBuildError("compatibility matrix artifacts must be a list")
    expected: list[dict[str, object]] = []
    for component in _expected_first_party_components(manifest):
        purl = component["purl"]
        if purl.startswith("pkg:pypi/"):
            formats = ["wheel", "sdist"]
        elif purl.startswith("pkg:npm/"):
            formats = ["npm-tarball"]
        else:  # pragma: no cover - closed helper contract
            raise ReleaseBuildError(f"unexpected first-party package URL: {purl}")
        expected.append({"purl": purl, "formats": formats})
    actual = sorted(
        (_require_mapping(item, "compatibility matrix artifact") for item in raw_artifacts),
        key=lambda item: _require_string(item.get("purl"), "compatibility matrix purl"),
    )
    if actual != expected:
        raise ReleaseBuildError("compatibility matrix artifacts drift from the manifest")
    host = _require_mapping(matrix.get("pinned_host"), "compatibility matrix pinned_host")
    adapter = _require_mapping(
        _require_mapping(manifest.get("artifacts"), "artifacts").get("openclaw_adapter"),
        "openclaw adapter",
    )
    if host != {
        "agent-framework-core": "1.12.0",
        "crewai": "1.15.6",
        "langchain": "1.3.14",
        "langgraph": "1.2.9",
        "node": "24.16.0",
        "openclaw": adapter.get("openclaw_peer"),
    }:
        raise ReleaseBuildError("compatibility matrix pinned host drifts from the release contract")


def _expected_release_formats(manifest: dict[str, object]) -> list[dict[str, object]]:
    expected: list[dict[str, object]] = []
    for component in _expected_first_party_components(manifest):
        purl = component["purl"]
        if purl.startswith("pkg:pypi/"):
            formats = ["wheel", "sdist"]
        elif purl.startswith("pkg:npm/"):
            formats = ["npm-tarball"]
        else:  # pragma: no cover - closed helper contract
            raise ReleaseBuildError(f"unexpected first-party package URL: {purl}")
        expected.append({"purl": purl, "formats": formats})
    return sorted(expected, key=lambda item: cast(str, item["purl"]))


def _validate_package_catalog(manifest: dict[str, object]) -> None:
    catalog_path = ROOT / _require_string(manifest.get("package_catalog"), "package_catalog")
    catalog = _json(catalog_path)
    if catalog.get("schema_version") != "masugate.release-package-catalog/v1":
        raise ReleaseBuildError("package catalog has an incompatible schema")
    if catalog.get("release_id") != manifest.get("release_id"):
        raise ReleaseBuildError("package catalog release identity drifts from the manifest")
    packages = catalog.get("packages")
    if not isinstance(packages, list):
        raise ReleaseBuildError("package catalog packages must be a list")
    actual = sorted(
        (_require_mapping(item, "package catalog package") for item in packages),
        key=lambda item: _require_string(item.get("purl"), "package catalog purl"),
    )
    if actual != _expected_release_formats(manifest):
        raise ReleaseBuildError("package catalog does not match the declared release set")


def _run(args: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    try:
        subprocess.run(args, cwd=cwd, env=env, check=True)
    except subprocess.CalledProcessError as exc:
        raise ReleaseBuildError(f"release command failed: {' '.join(args)}") from exc


def _git_output(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, check=True, text=True, capture_output=True)
    return result.stdout.strip()


def _source_environment() -> tuple[dict[str, str], str, int]:
    if _git_output("status", "--porcelain"):
        raise ReleaseBuildError("release artifacts require a clean source tree")
    revision = _git_output("rev-parse", "HEAD")
    epoch = int(_git_output("show", "-s", "--format=%ct", "HEAD"))
    env = dict(os.environ)
    env["SOURCE_DATE_EPOCH"] = str(epoch)
    return env, revision, epoch


def _provenance_source(
    staging_revision: str,
    staging_epoch: int,
    *,
    source_revision: str | None,
    source_date_epoch: int | None,
) -> tuple[str, int]:
    """Resolve the immutable origin recorded in an attestation.

    A normal build records its checked-out Git revision as both the source and
    the staging realization.  A reviewed staging realization can instead pass
    an explicit immutable origin, but it must also provide that origin's
    timestamp so reproducible archive metadata does not silently derive from a
    different temporary commit.
    """

    if (source_revision is None) != (source_date_epoch is None):
        raise ReleaseBuildError(
            "--source-revision and --source-date-epoch must be supplied together"
        )
    if source_revision is None:
        return staging_revision, staging_epoch
    if not re.fullmatch(r"[0-9a-f]{40}", source_revision):
        raise ReleaseBuildError("--source-revision must be a full lowercase Git revision")
    if source_date_epoch is None or source_date_epoch <= 0:
        raise ReleaseBuildError("--source-date-epoch must be a positive Unix epoch")
    return source_revision, source_date_epoch


def _build_python(project: Path, output: Path, env: dict[str, str]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    # Use an output-directory cwd so the repository's ``build/`` worktree
    # directory cannot shadow the third-party ``build`` module.
    _run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--sdist",
            "--wheel",
            "--outdir",
            str(output),
            str(project),
        ],
        cwd=output.parent,
        env=env,
    )


def _build_npm(output: Path, env: dict[str, str]) -> None:
    npm = shutil.which("npm")
    if npm is None:
        raise ReleaseBuildError("npm is required to build the TypeScript release artifacts")
    output.mkdir(parents=True, exist_ok=True)
    # Build the closed workspace in dependency order before packing it.
    # Invoking each workspace's prepack hook independently can remove the
    # workspace links needed by a later package, while a broad workspace run
    # permits the client and its consumers to overlap. Packing after this pass
    # deliberately suppresses lifecycle hooks: every included dist/ file was
    # produced above from the same locked workspace.
    workspaces = (
        "@masugate/client",
        "@masugate/adapter-core",
        "@masugate/mcp-gateway",
        "@masugate/openclaw",
    )
    for workspace in workspaces:
        _run([npm, "run", "build", "--workspace", workspace], cwd=ROOT, env=env)
    for workspace in workspaces:
        _run(
            [
                npm,
                "pack",
                "--ignore-scripts=true",
                "--workspace",
                workspace,
                "--pack-destination",
                str(output),
            ],
            cwd=ROOT,
            env=env,
        )


def _npm_integrity(path: Path) -> str:
    """Return npm's SRI form for an exact locally built tarball."""

    digest = hashlib.sha512()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha512-" + base64.b64encode(digest.digest()).decode("ascii")


def _stage_npm_clean_consumer_lock(output: Path, destination: Path) -> None:
    """Bind the portable clean-consumer lock to this build's tarball bytes.

    ``npm pack`` includes archive metadata, so a source lock cannot safely
    retain a previous build's SRI values.  The paths and package identities are
    reviewed in the source template; only the integrity values are derived
    from the exact tarballs that this attested output contains.
    """

    lock = _json(NPM_CLEAN_CONSUMER_LOCK_PATH)
    packages = _require_mapping(lock.get("packages"), "clean-consumer lock packages")
    marker = "file:__MASUGATE_RELEASE_NPM__"
    for package, filename in _NPM_CLEAN_CONSUMER_TARBALLS.items():
        record = _require_mapping(
            packages.get(f"node_modules/{package}"),
            f"clean-consumer lock record for {package}",
        )
        if record.get("resolved") != f"{marker}/{filename}":
            raise ReleaseBuildError(
                f"clean-consumer lock has an unexpected tarball path for {package}"
            )
        tarball = output / "npm" / filename
        if not tarball.is_file() or tarball.is_symlink():
            raise ReleaseBuildError(f"built npm tarball is unavailable: {filename}")
        record["integrity"] = _npm_integrity(tarball)
    destination.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _stage_locked_python_runtime(
    output: Path,
    manifest: dict[str, object],
    *,
    offline_wheelhouse: Path | None = None,
) -> None:
    """Materialize the exact locked runtime wheels for offline image builds."""

    import tomllib

    locks = _require_mapping(manifest["locks"], "locks")
    lock_path = ROOT / _require_string(locks["python"], "locks.python")
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock.get("packages")
    if not isinstance(packages, list) or not packages:
        raise ReleaseBuildError("Python runtime lock contains no packages")
    runtime = output / "python" / "runtime"
    wheelhouse = runtime / "wheelhouse"
    wheelhouse.mkdir(parents=True)
    shutil.copy2(lock_path, runtime / lock_path.name)
    requirements: list[str] = []
    seen_filenames: set[str] = set()
    for raw_package in packages:
        package = _require_mapping(raw_package, "locked Python package")
        name = _require_string(package.get("name"), "locked Python package name")
        version = _require_string(package.get("version"), "locked Python package version")
        raw_wheels = package.get("wheels")
        if not isinstance(raw_wheels, list) or not raw_wheels:
            raise ReleaseBuildError(f"locked Python package has no wheels: {name}")
        hashes: list[str] = []
        for raw_wheel in raw_wheels:
            wheel = _require_mapping(raw_wheel, f"locked wheel for {name}")
            filename = _require_string(wheel.get("name"), f"locked wheel name for {name}")
            url = _require_string(wheel.get("url"), f"locked wheel URL for {name}")
            parsed = urlparse(url)
            if parsed.scheme != "https" or parsed.hostname != "files.pythonhosted.org":
                raise ReleaseBuildError(
                    f"locked wheel URL is outside files.pythonhosted.org: {url}"
                )
            declared_hashes = _require_mapping(
                wheel.get("hashes"), f"locked wheel hashes for {name}"
            )
            digest = _require_string(
                declared_hashes.get("sha256"), f"locked wheel SHA-256 for {name}"
            )
            if len(digest) != 64 or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ReleaseBuildError(f"locked wheel SHA-256 is invalid for {name}")
            if filename in seen_filenames:
                raise ReleaseBuildError(f"locked wheel filename is duplicated: {filename}")
            seen_filenames.add(filename)
            target = wheelhouse / filename
            if offline_wheelhouse is None:
                try:
                    with urlopen(url, timeout=120) as source, target.open("wb") as destination:
                        shutil.copyfileobj(source, destination)
                except OSError as exc:
                    raise ReleaseBuildError(f"failed to download locked wheel: {url}") from exc
            else:
                source = offline_wheelhouse / filename
                if not source.is_file() or source.is_symlink():
                    raise ReleaseBuildError(f"offline wheelhouse lacks locked wheel: {filename}")
                shutil.copy2(source, target)
            if _sha256(target) != digest:
                raise ReleaseBuildError(f"downloaded wheel does not match lock digest: {filename}")
            hashes.append(f"--hash=sha256:{digest}")
        requirements.append(f"{name}=={version} {' '.join(sorted(hashes))}")
    (runtime / "requirements.txt").write_text("\n".join(requirements) + "\n", encoding="utf-8")


def _stage_deployment_inputs(
    output: Path,
    manifest: dict[str, object],
    *,
    offline_wheelhouse: Path | None = None,
) -> None:
    """Put every non-package reference demonstration build input inside the attested output."""

    deployment = output / "deployment"
    contract = deployment / "openclaw-contract"
    contract.mkdir(parents=True)
    for name in ("package.json", "package-lock.json"):
        shutil.copy2(ROOT / "integrations" / "openclaw-contract" / name, contract / name)
    shutil.copy2(MANIFEST_PATH, deployment / "reference-release.json")
    shutil.copy2(COMPATIBILITY_MATRIX_PATH, deployment / "compatibility-matrix.json")
    shutil.copy2(
        ROOT / _require_string(manifest.get("package_catalog"), "package_catalog"),
        deployment / "package-catalog.json",
    )
    _stage_locked_python_runtime(output, manifest, offline_wheelhouse=offline_wheelhouse)
    _stage_npm_clean_consumer_lock(output, deployment / "npm-clean-consumer-lock.json")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_paths(output: Path) -> tuple[Path, ...]:
    paths = tuple(
        path
        for path in sorted(output.rglob("*"))
        if path.is_file()
        and path.name not in {"checksums.sha256", "provenance.json", "sbom.cdx.json"}
    )
    if not paths:
        raise ReleaseBuildError("release build produced no artifacts")
    return paths


def _npm_purl(name: str, version: str) -> str:
    if name.startswith("@"):
        scope, separator, package = name.partition("/")
        if not separator or not package:
            raise ReleaseBuildError(f"invalid scoped npm package name: {name!r}")
        encoded_name = f"{quote(scope, safe='')}/{quote(package, safe='')}"
    else:
        encoded_name = quote(name, safe="")
    return f"pkg:npm/{encoded_name}@{quote(version, safe='')}"


def _pypi_purl(name: str, version: str) -> str:
    normalized_name = re.sub(r"[-_.]+", "-", name).lower()
    return f"pkg:pypi/{quote(normalized_name, safe='')}@{quote(version, safe='')}"


def _package_component(ecosystem: str, name: str, version: str) -> dict[str, str]:
    if ecosystem == "npm":
        purl = _npm_purl(name, version)
    elif ecosystem == "pypi":
        purl = _pypi_purl(name, version)
    else:  # pragma: no cover - internal contract
        raise ReleaseBuildError(f"unsupported package ecosystem: {ecosystem}")
    return {
        "type": "library",
        "name": name,
        "version": version,
        "purl": purl,
        "bom-ref": purl,
    }


def _expected_first_party_components(manifest: dict[str, object]) -> list[dict[str, str]]:
    artifacts = _require_mapping(manifest.get("artifacts"), "artifacts")
    declarations = (
        ("pypi", "platform", "distribution"),
        ("pypi", "connector_sdk", "distribution"),
        ("pypi", "python_client", "distribution"),
        ("pypi", "adapter_core", "distribution"),
        ("pypi", "langchain_adapter", "distribution"),
        ("pypi", "agent_framework_adapter", "distribution"),
        ("pypi", "crewai_adapter", "distribution"),
        ("pypi", "google_calendar_connector", "distribution"),
        ("pypi", "stripe_payment_intent_connector", "distribution"),
        ("pypi", "filesystem_connector", "distribution"),
        ("pypi", "calendar_operation", "distribution"),
        ("pypi", "spend_operation", "distribution"),
        ("pypi", "filesystem_operation", "distribution"),
        ("pypi", "reference_deployment", "distribution"),
        ("npm", "typescript_client", "package"),
        ("npm", "typescript_adapter_core", "package"),
        ("npm", "mcp_gateway", "package"),
        ("npm", "openclaw_adapter", "package"),
    )
    components = [
        _package_component(
            ecosystem,
            _require_string(
                _require_mapping(artifacts.get(key), f"artifacts.{key}").get(name_field),
                f"artifacts.{key}.{name_field}",
            ),
            _require_string(
                _require_mapping(artifacts.get(key), f"artifacts.{key}").get("version"),
                f"artifacts.{key}.version",
            ),
        )
        for ecosystem, key, name_field in declarations
    ]
    if len({component["purl"] for component in components}) != len(declarations):
        raise ReleaseBuildError("first-party release component identities must be unique")
    return sorted(components, key=lambda component: component["purl"])


def _npm_components() -> list[dict[str, str]]:
    lock = _json(ROOT / "package-lock.json")
    packages = _require_mapping(lock.get("packages"), "package-lock packages")
    components: list[dict[str, str]] = []
    for location, value in sorted(packages.items()):
        if not location or not isinstance(value, dict):
            continue
        version = value.get("version")
        if isinstance(version, str):
            declared_name = value.get("name")
            if isinstance(declared_name, str) and declared_name:
                name = declared_name
            elif "node_modules/" in location:
                name = location.rsplit("node_modules/", 1)[-1]
            else:
                raise ReleaseBuildError(f"versioned npm lock entry has no package name: {location}")
            components.append(_package_component("npm", name, version))
    return components


def _python_components() -> list[dict[str, str]]:
    import tomllib

    manifest = _json(MANIFEST_PATH)
    locks = _require_mapping(manifest["locks"], "locks")
    lock_path = ROOT / _require_string(locks["python"], "locks.python")
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = lock.get("packages")
    if not isinstance(packages, list):
        raise ReleaseBuildError(f"{lock_path} must contain packages")
    components: list[dict[str, str]] = []
    for package in packages:
        locked = _require_mapping(package, "locked package")
        name = _require_string(locked.get("name"), "locked name")
        version = _require_string(locked.get("version"), "locked version")
        components.append(_package_component("pypi", name, version))
    return components


def _canonical_uuid(value: str) -> str:
    digest = hashlib.sha256(value.encode()).digest()
    return str(UUID(bytes=digest[:16], version=5))


def _unique_components(components: list[dict[str, str]]) -> list[dict[str, str]]:
    unique: dict[str, dict[str, str]] = {}
    for component in components:
        identity = component.get("purl") or ":".join(
            (
                component["type"],
                component["name"],
                component.get("version", ""),
            )
        )
        previous = unique.get(identity)
        if previous is not None and previous != component:
            raise ReleaseBuildError(f"conflicting SBOM component identity: {identity}")
        unique.setdefault(identity, component)
    return [unique[identity] for identity in sorted(unique)]


def _core_metadata_identity(contents: str, label: str) -> tuple[str, str]:
    metadata = Parser().parsestr(contents)
    return (
        _require_string(metadata.get("Name"), f"{label} Name"),
        _require_string(metadata.get("Version"), f"{label} Version"),
    )


def _wheel_identity(path: Path) -> tuple[str, str]:
    with zipfile.ZipFile(path) as wheel:
        metadata_paths = [
            member for member in wheel.namelist() if member.endswith(".dist-info/METADATA")
        ]
        if len(metadata_paths) != 1:
            raise ReleaseBuildError(f"wheel must contain exactly one METADATA file: {path}")
        contents = wheel.read(metadata_paths[0]).decode("utf-8")
    return _core_metadata_identity(contents, str(path))


def _sdist_identity(path: Path) -> tuple[str, str]:
    with tarfile.open(path, "r:gz") as archive:
        metadata_members = [
            member
            for member in archive.getmembers()
            if member.isfile() and member.name.endswith("/PKG-INFO")
        ]
        if len(metadata_members) != 1:
            raise ReleaseBuildError(f"sdist must contain exactly one PKG-INFO file: {path}")
        handle = archive.extractfile(metadata_members[0])
        if handle is None:  # pragma: no cover - guarded by member.isreg()
            raise ReleaseBuildError(f"cannot read sdist PKG-INFO: {path}")
        contents = handle.read().decode("utf-8")
    return _core_metadata_identity(contents, str(path))


def _npm_archive_identity(path: Path) -> tuple[str, str]:
    with tarfile.open(path, "r:gz") as archive:
        try:
            member = archive.getmember("package/package.json")
        except KeyError as exc:
            raise ReleaseBuildError(f"npm archive is missing package/package.json: {path}") from exc
        handle = archive.extractfile(member)
        if handle is None:
            raise ReleaseBuildError(f"cannot read npm package metadata: {path}")
        raw = json.loads(handle.read().decode("utf-8"))
    package = _require_mapping(raw, f"{path} package.json")
    return (
        _require_string(package.get("name"), f"{path} package name"),
        _require_string(package.get("version"), f"{path} package version"),
    )


def _built_first_party_components(
    output: Path,
    manifest: dict[str, object],
) -> list[dict[str, str]]:
    expected = {
        component["purl"]: component for component in _expected_first_party_components(manifest)
    }
    actual: dict[str, dict[str, str]] = {}
    python_formats: dict[str, set[str]] = {}

    python_root = output / "python"
    python_files = tuple(
        path
        for component_root in sorted(python_root.iterdir())
        if component_root.name != "runtime"
        for path in sorted(component_root.rglob("*"))
        if path.is_file()
    )
    for path in python_files:
        if path.suffix == ".whl":
            name, version = _wheel_identity(path)
            package_format = "wheel"
        elif path.name.endswith(".tar.gz"):
            name, version = _sdist_identity(path)
            package_format = "sdist"
        else:
            raise ReleaseBuildError(f"unexpected Python release artifact: {path}")
        component = _package_component("pypi", name, version)
        purl = component["purl"]
        if package_format in python_formats.setdefault(purl, set()):
            raise ReleaseBuildError(
                f"duplicate {package_format} for built Python component: {purl}"
            )
        python_formats[purl].add(package_format)
        previous = actual.setdefault(purl, component)
        if previous != component:
            raise ReleaseBuildError(f"conflicting built Python component identity: {purl}")

    npm_root = output / "npm"
    npm_files = tuple(path for path in sorted(npm_root.rglob("*")) if path.is_file())
    npm_purls: set[str] = set()
    for path in npm_files:
        if not path.name.endswith(".tgz"):
            raise ReleaseBuildError(f"unexpected npm release artifact: {path}")
        name, version = _npm_archive_identity(path)
        component = _package_component("npm", name, version)
        purl = component["purl"]
        if purl in npm_purls:
            raise ReleaseBuildError(f"duplicate built npm component identity: {purl}")
        npm_purls.add(purl)
        actual.setdefault(purl, component)

    expected_python = {purl for purl in expected if purl.startswith("pkg:pypi/")}
    expected_npm = {purl for purl in expected if purl.startswith("pkg:npm/")}
    if set(python_formats) != expected_python or any(
        formats != {"wheel", "sdist"} for formats in python_formats.values()
    ):
        actual_python = sorted((purl, sorted(formats)) for purl, formats in python_formats.items())
        raise ReleaseBuildError(
            "built Python artifacts do not match the release manifest: "
            f"expected={sorted(expected_python)!r}, "
            f"actual={actual_python!r}"
        )
    if npm_purls != expected_npm:
        raise ReleaseBuildError(
            "built npm artifacts do not match the release manifest: "
            f"expected={sorted(expected_npm)!r}, actual={sorted(npm_purls)!r}"
        )
    if actual != expected:
        raise ReleaseBuildError("built package metadata does not match release declarations")
    return [actual[purl] for purl in sorted(actual)]


def _primary_release_component(manifest: dict[str, object]) -> dict[str, str]:
    artifacts = _require_mapping(manifest.get("artifacts"), "artifacts")
    reference = _require_mapping(
        artifacts.get("reference_deployment"), "artifacts.reference_deployment"
    )
    name = _require_string(
        reference.get("distribution"), "artifacts.reference_deployment.distribution"
    )
    version = _require_string(reference.get("version"), "artifacts.reference_deployment.version")
    purl = f"pkg:generic/{quote(name, safe='')}@{quote(version, safe='')}"
    return {
        "type": "application",
        "name": name,
        "version": version,
        "purl": purl,
        "bom-ref": purl,
    }


def _validate_sbom(sbom: dict[str, object], manifest: dict[str, object]) -> None:
    try:
        jsonschema = importlib.import_module("jsonschema")
    except ModuleNotFoundError as exc:  # pragma: no cover - CI/test dependency
        raise ReleaseBuildError("jsonschema is required to validate the CycloneDX SBOM") from exc
    if not CYCLONEDX_SCHEMA_PATH.is_file():
        raise ReleaseBuildError(f"CycloneDX schema is missing: {CYCLONEDX_SCHEMA_PATH}")
    if _sha256(CYCLONEDX_SCHEMA_PATH) != CYCLONEDX_SCHEMA_SHA256:
        raise ReleaseBuildError("vendored CycloneDX 1.5 schema does not match its pinned digest")
    schema = _json(CYCLONEDX_SCHEMA_PATH)
    validator = jsonschema.Draft7Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    errors = sorted(
        validator.iter_errors(sbom),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "<root>"
        raise ReleaseBuildError(f"CycloneDX 1.5 SBOM is invalid at {location}: {first.message}")

    serial = _require_string(sbom.get("serialNumber"), "SBOM serialNumber")
    try:
        identifier = UUID(serial.removeprefix("urn:uuid:"))
    except ValueError as exc:
        raise ReleaseBuildError("SBOM serialNumber is not a UUID URN") from exc
    if not serial.startswith("urn:uuid:") or identifier.version != 5:
        raise ReleaseBuildError("SBOM serialNumber must be a deterministic UUIDv5 URN")
    if identifier.variant != RFC_4122:
        raise ReleaseBuildError("SBOM serialNumber does not use the RFC 4122 variant")

    metadata = _require_mapping(sbom.get("metadata"), "SBOM metadata")
    all_components = [_require_mapping(metadata.get("component"), "SBOM metadata.component")]
    components = sbom.get("components")
    if not isinstance(components, list):
        raise ReleaseBuildError("SBOM components must be a list")
    all_components.extend(_require_mapping(component, "SBOM component") for component in components)
    for component in all_components:
        purl = component.get("purl")
        if isinstance(purl, str) and purl.startswith("pkg:npm/@"):
            raise ReleaseBuildError(f"scoped npm package URL is not percent-encoded: {purl}")

    expected_components = {
        component["purl"]: component for component in _expected_first_party_components(manifest)
    }
    components_by_purl: dict[str, list[dict[str, object]]] = {}
    for component in (
        _require_mapping(raw_component, "SBOM component") for raw_component in components
    ):
        purl = component.get("purl")
        if isinstance(purl, str):
            components_by_purl.setdefault(purl, []).append(component)
    for purl, expected in expected_components.items():
        matches = components_by_purl.get(purl, [])
        if len(matches) != 1:
            raise ReleaseBuildError(f"SBOM must contain first-party component exactly once: {purl}")
        actual = matches[0]
        for field, expected_value in expected.items():
            if actual.get(field) != expected_value:
                raise ReleaseBuildError(
                    f"SBOM first-party component {purl} has invalid {field}: {actual.get(field)!r}"
                )

    expected_names = {component["name"] for component in expected_components.values()}
    expected_by_name = {component["name"]: component for component in expected_components.values()}
    legacy_workspace_purls = {
        _npm_purl(workspace, expected_by_name[package]["version"])
        for workspace, package in (
            ("clients/typescript", "@masugate/client"),
            ("adapters/typescript", "@masugate/adapter-core"),
            ("gateway", "@masugate/mcp-gateway"),
            ("integrations/openclaw", "@masugate/openclaw"),
        )
    }
    for component in (
        _require_mapping(raw_component, "SBOM component") for raw_component in components
    ):
        name = component.get("name")
        purl = component.get("purl")
        if purl in legacy_workspace_purls:
            raise ReleaseBuildError(f"SBOM contains a path-derived workspace identity: {name}")
        is_masugate_npm = isinstance(purl, str) and purl.startswith("pkg:npm/%40masugate/")
        is_masugate_python = isinstance(name, str) and name.startswith("masugate")
        if (is_masugate_npm or is_masugate_python) and name not in expected_names:
            raise ReleaseBuildError(f"SBOM contains an undeclared first-party component: {name}")

    primary_component = _primary_release_component(manifest)
    metadata_component = _require_mapping(metadata.get("component"), "SBOM metadata.component")
    if metadata_component != primary_component:
        raise ReleaseBuildError("SBOM metadata component does not identify the release bundle")
    dependencies = sbom.get("dependencies")
    if not isinstance(dependencies, list):
        raise ReleaseBuildError("SBOM dependencies must identify the released artifacts")
    root_dependencies = [
        _require_mapping(dependency, "SBOM dependency")
        for dependency in dependencies
        if _require_mapping(dependency, "SBOM dependency").get("ref")
        == primary_component["bom-ref"]
    ]
    if len(root_dependencies) != 1:
        raise ReleaseBuildError("SBOM must contain exactly one release-bundle dependency entry")
    depends_on = root_dependencies[0].get("dependsOn")
    expected_refs = sorted(expected_components)
    if not isinstance(depends_on, list) or sorted(depends_on) != expected_refs:
        raise ReleaseBuildError(
            "SBOM release bundle must depend on exactly the declared first-party artifacts"
        )


def _assert_reference_package_boundary(output: Path) -> None:
    wheels = tuple((output / "python" / "reference").glob("masugate_openclaw_reference-*.whl"))
    if len(wheels) != 1:
        raise ReleaseBuildError("reference build must produce exactly one wheel")
    with zipfile.ZipFile(wheels[0]) as wheel:
        contents = set(wheel.namelist())
    if "masugate_openclaw_reference/release.py" not in contents:
        raise ReleaseBuildError("reference wheel is missing its release identity module")
    if any(path.startswith("masugate/") for path in contents):
        raise ReleaseBuildError("reference wheel must not bundle the reusable masugate platform")


def _write_attestations(
    output: Path,
    manifest: dict[str, object],
    source_revision: str,
    source_epoch: int,
    staging_realization_revision: str | None = None,
    staging_realization_epoch: int | None = None,
) -> None:
    if staging_realization_revision is None:
        staging_realization_revision = source_revision
    if staging_realization_epoch is None:
        staging_realization_epoch = source_epoch
    artifacts = _artifact_paths(output)
    first_party_components = _built_first_party_components(output, manifest)
    checksum_lines = [
        f"{_sha256(path)}  {path.relative_to(output).as_posix()}" for path in artifacts
    ]
    (output / "checksums.sha256").write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")
    primary_component = _primary_release_component(manifest)
    components = _unique_components(
        [
            *first_party_components,
            *_python_components(),
            *_npm_components(),
            *(
                {
                    "type": "container",
                    "name": str(name),
                    "version": str(image).split("@", 1)[1],
                }
                for name, image in _require_mapping(
                    manifest["container_images"], "container_images"
                ).items()
            ),
        ]
    )
    sbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + _canonical_uuid(source_revision + str(source_epoch)),
        "version": 1,
        "metadata": {
            "timestamp": (
                datetime.fromtimestamp(source_epoch, UTC).isoformat().replace("+00:00", "Z")
            ),
            "component": primary_component,
        },
        "components": components,
        "dependencies": [
            {
                "ref": primary_component["bom-ref"],
                "dependsOn": [component["bom-ref"] for component in first_party_components],
            }
        ],
    }
    _validate_sbom(sbom, manifest)
    (output / "sbom.cdx.json").write_text(
        json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    provenance = {
        "schema_version": "masugate.reference-release.provenance/v1",
        "release_id": manifest["release_id"],
        "source_revision": source_revision,
        "source_date_epoch": source_epoch,
        "staging_realization_revision": staging_realization_revision,
        "staging_realization_date_epoch": staging_realization_epoch,
        "release_manifest_sha256": _sha256(MANIFEST_PATH),
        "artifacts": [
            {"path": path.relative_to(output).as_posix(), "sha256": _sha256(path)}
            for path in artifacts
        ],
    }
    (output / "provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def build(
    output: Path,
    *,
    source_revision: str | None = None,
    source_date_epoch: int | None = None,
    offline_wheelhouse: Path | None = None,
) -> None:
    manifest = load_and_validate_manifest()
    if output.exists() and any(output.iterdir()):
        raise ReleaseBuildError(f"release output directory must be empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    env, staging_revision, staging_epoch = _source_environment()
    provenance_source_revision, provenance_source_epoch = _provenance_source(
        staging_revision,
        staging_epoch,
        source_revision=source_revision,
        source_date_epoch=source_date_epoch,
    )
    env["SOURCE_DATE_EPOCH"] = str(provenance_source_epoch)
    for _name, project, output_name in _PYTHON_RELEASE_PROJECTS:
        _build_python(project, output / "python" / output_name, env)
    _assert_reference_package_boundary(output)
    _build_npm(output / "npm", env)
    _stage_deployment_inputs(output, manifest, offline_wheelhouse=offline_wheelhouse)
    _write_attestations(
        output,
        manifest,
        provenance_source_revision,
        provenance_source_epoch,
        staging_revision,
        staging_epoch,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--outdir", type=Path)
    mode.add_argument("--verify-only", action="store_true")
    mode.add_argument("--validate-sbom", type=Path)
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
        "--offline-wheelhouse",
        type=Path,
        help="copy only hash-verified locked Python wheels from this local directory",
    )
    args = parser.parse_args()
    if args.verify_only:
        load_and_validate_manifest()
        print("reference release manifest is coherent")
        return
    if args.validate_sbom is not None:
        manifest = load_and_validate_manifest()
        _validate_sbom(_json(args.validate_sbom.resolve()), manifest)
        print(f"CycloneDX 1.5 SBOM is valid: {args.validate_sbom}")
        return
    if args.outdir is None:
        parser.error("one of --outdir, --verify-only, or --validate-sbom is required")
    build(
        args.outdir.resolve(),
        source_revision=args.source_revision,
        source_date_epoch=args.source_date_epoch,
        offline_wheelhouse=(
            None if args.offline_wheelhouse is None else args.offline_wheelhouse.resolve()
        ),
    )
    print(f"reference release artifacts verified at {args.outdir}")


if __name__ == "__main__":
    main()
