#!/usr/bin/env python3
"""Fail closed on release-control drift without external side effects."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "release" / "ci-action-lock.json"
POLICY = ROOT / "release" / "release-control-policy.json"
MATRIX = ROOT / "release" / "compatibility-matrix.json"
DESCRIPTOR = ROOT / "release" / "reference-release.json"
WORKFLOWS = {
    "ci.yml": ROOT / ".github" / "workflows" / "ci.yml",
    "nightly.yml": ROOT / ".github" / "workflows" / "nightly.yml",
    "release.yml": ROOT / ".github" / "workflows" / "release.yml",
}
USE = re.compile(r"^\s*-\s*uses:\s+([^@\s]+)@([0-9a-f]{40})\s+#\s+(v[^\s]+)\s*$", re.MULTILINE)
SHA = re.compile(r"[0-9a-f]{40}\Z")
PROJECT_URLS = {
    "Homepage": "https://github.com/masugate/masugate",
    "Source": "https://github.com/masugate/masugate",
    "Issues": "https://github.com/masugate/masugate/issues",
}


class ReleaseControlError(RuntimeError):
    """A release control is incomplete, mutable, or publishable."""


def _load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReleaseControlError(f"cannot read {path}") from exc
    if not isinstance(value, dict):
        raise ReleaseControlError(f"{path} must contain a JSON object")
    return value


def _expected_matrix(descriptor: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts = descriptor.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ReleaseControlError("descriptor artifacts are invalid")
    fields = (
        ("platform", "distribution", "pkg:pypi/", ["wheel", "sdist"]),
        ("connector_sdk", "distribution", "pkg:pypi/", ["wheel", "sdist"]),
        ("python_client", "distribution", "pkg:pypi/", ["wheel", "sdist"]),
        ("adapter_core", "distribution", "pkg:pypi/", ["wheel", "sdist"]),
        ("langchain_adapter", "distribution", "pkg:pypi/", ["wheel", "sdist"]),
        ("agent_framework_adapter", "distribution", "pkg:pypi/", ["wheel", "sdist"]),
        ("crewai_adapter", "distribution", "pkg:pypi/", ["wheel", "sdist"]),
        ("google_calendar_connector", "distribution", "pkg:pypi/", ["wheel", "sdist"]),
        ("stripe_payment_intent_connector", "distribution", "pkg:pypi/", ["wheel", "sdist"]),
        ("filesystem_connector", "distribution", "pkg:pypi/", ["wheel", "sdist"]),
        ("calendar_operation", "distribution", "pkg:pypi/", ["wheel", "sdist"]),
        ("spend_operation", "distribution", "pkg:pypi/", ["wheel", "sdist"]),
        ("filesystem_operation", "distribution", "pkg:pypi/", ["wheel", "sdist"]),
        ("reference_deployment", "distribution", "pkg:pypi/", ["wheel", "sdist"]),
        ("typescript_client", "package", "pkg:npm/", ["npm-tarball"]),
        ("typescript_adapter_core", "package", "pkg:npm/", ["npm-tarball"]),
        ("mcp_gateway", "package", "pkg:npm/", ["npm-tarball"]),
        ("openclaw_adapter", "package", "pkg:npm/", ["npm-tarball"]),
    )
    expected: list[dict[str, Any]] = []
    for key, name_key, prefix, formats in fields:
        item = artifacts.get(key)
        if (
            not isinstance(item, dict)
            or not isinstance(item.get(name_key), str)
            or not isinstance(item.get("version"), str)
        ):
            raise ReleaseControlError(f"descriptor artifact {key} is invalid")
        name = item[name_key].replace("@", "%40", 1) if prefix == "pkg:npm/" else item[name_key]
        expected.append({"purl": f"{prefix}{name}@{item['version']}", "formats": formats})
    return sorted(expected, key=lambda item: item["purl"])


def _validate_project_python_metadata() -> None:
    for path in sorted(ROOT.rglob("pyproject.toml")):
        try:
            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ReleaseControlError(f"cannot read Python package metadata: {path}") from exc
        project = raw.get("project")
        if not isinstance(project, dict):
            raise ReleaseControlError(f"Python package metadata lacks [project]: {path}")
        dependencies = project.get("dependencies")
        if not isinstance(dependencies, list) or any(
            not isinstance(dependency, str) for dependency in dependencies
        ):
            raise ReleaseControlError(f"Python package dependencies are invalid: {path}")
        if project.get("urls") != PROJECT_URLS:
            raise ReleaseControlError(f"Python package project URLs are invalid: {path}")


def verify() -> None:
    lock = _load(LOCK)
    policy = _load(POLICY)
    matrix = _load(MATRIX)
    descriptor = _load(DESCRIPTOR)
    _validate_project_python_metadata()
    if (
        lock.get("schema_version") != "masugate.ci-action-lock/v1"
        or lock.get("status") != "source-release-staged"
    ):
        raise ReleaseControlError("action lock is not a staged source-release control")
    records = lock.get("actions")
    if not isinstance(records, list) or len(records) != 4:
        raise ReleaseControlError("action lock must contain exactly four reviewed actions")
    actions: dict[str, tuple[str, str]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise ReleaseControlError("action lock record is invalid")
        repository, tag, commit = (
            record.get("repository"),
            record.get("resolved_tag"),
            record.get("commit"),
        )
        if (
            not isinstance(repository, str)
            or not isinstance(tag, str)
            or not isinstance(commit, str)
            or SHA.fullmatch(commit) is None
            or repository in actions
        ):
            raise ReleaseControlError("action lock contains a mutable or duplicate action")
        actions[repository] = (tag, commit)
    if (
        policy.get("schema_version") != "masugate.release-control-policy/v1"
        or policy.get("status") != "source-release-staged"
    ):
        raise ReleaseControlError("release policy is not a staged source-release policy")
    if (
        policy.get("release_environment") != "not-configured"
        or policy.get("activation", {}).get("source_repository") != "private"
        or policy.get("activation", {}).get("source_ci") != "enabled"
    ):
        raise ReleaseControlError("release policy has an invalid source-release staging boundary")
    if policy.get("publication", {}).get("long_lived_publication_secrets") != "prohibited":
        raise ReleaseControlError("release policy does not prohibit long-lived publication secrets")
    if policy.get("publication", {}).get("package_and_container_artifacts") != "not-published":
        raise ReleaseControlError("release policy does not retain the package-publication boundary")
    if policy.get("two_person_control", {}).get("minimum_distinct_approvers") != 2:
        raise ReleaseControlError("release policy does not require two distinct approvers")
    if (
        matrix.get("schema_version") != "masugate.reference-release.compatibility/v1"
        or matrix.get("release_id") != descriptor.get("release_id")
        or matrix.get("runtime_target") != descriptor.get("runtime_target")
    ):
        raise ReleaseControlError("compatibility matrix identity drifts from the descriptor")
    actual = matrix.get("artifacts")
    if not isinstance(actual, list) or sorted(
        actual, key=lambda item: item.get("purl", "") if isinstance(item, dict) else ""
    ) != _expected_matrix(descriptor):
        raise ReleaseControlError(
            "compatibility matrix artifacts drift from the declared release set"
        )
    host = matrix.get("pinned_host")
    adapter = (
        descriptor.get("artifacts", {}).get("openclaw_adapter")
        if isinstance(descriptor.get("artifacts"), dict)
        else None
    )
    if (
        not isinstance(host, dict)
        or not isinstance(adapter, dict)
        or host
        != {
            "agent-framework-core": "1.12.0",
            "crewai": "1.15.6",
            "langchain": "1.3.14",
            "langgraph": "1.2.9",
            "node": "24.16.0",
            "openclaw": adapter.get("openclaw_peer"),
        }
    ):
        raise ReleaseControlError("compatibility matrix host identity drifts from the descriptor")
    for name, path in WORKFLOWS.items():
        text = path.read_text(encoding="utf-8")
        if name == "ci.yml":
            if "push:\n" not in text or "pull_request:" not in text:
                raise ReleaseControlError("ci workflow must run for main pushes and pull requests")
            if "if: $" + "{{ false }}" in text:
                raise ReleaseControlError("ci workflow must not be disabled")
            for command in (
                "python -m pip install --require-hashes -r release/requirements/reference-demo-build.requirements.lock",
                "python -m pip install --no-build-isolation --no-deps ./connectors/sdk",
                "python scripts/verify-release-controls.py",
                "python scripts/verify-documentation.py",
                "python scripts/build-reference-release.py --verify-only",
            ):
                if command not in text:
                    raise ReleaseControlError(f"ci workflow is missing {command}")
        else:
            if "if: $" + "{{ false }}" not in text:
                raise ReleaseControlError(f"{name} is not explicitly disabled")
            if name == "nightly.yml" and "schedule:" in text:
                raise ReleaseControlError("nightly workflow must not schedule a disabled job")
        raw_uses = re.findall(r"^\s*-\s*uses:\s+(\S+)", text, re.MULTILINE)
        pinned = USE.findall(text)
        if not raw_uses or len(raw_uses) != len(pinned):
            raise ReleaseControlError(f"{name} has a mutable or malformed action reference")
        for repository, commit, tag in pinned:
            if actions.get(repository) != (tag, commit):
                raise ReleaseControlError(
                    f"{name} action is absent from the reviewed immutable lock"
                )
        if "secrets." in text or any(
            command in text.lower()
            for command in ("twine upload", "npm publish", "docker push", "gh release create")
        ):
            raise ReleaseControlError(f"{name} contains a secret or publication command")
    release = WORKFLOWS["release.yml"].read_text(encoding="utf-8")
    for required in (
        "id-token: write",
        "environment: masugate-release",
        "pypi-trusted-publishing:",
        "npm-trusted-publishing:",
        "container-attestation:",
    ):
        if required not in release:
            raise ReleaseControlError(f"release workflow is missing {required}")


def main() -> None:
    try:
        verify()
    except ReleaseControlError as exc:
        raise SystemExit(f"release-control verification failed: {exc}") from exc
    print("source-release controls are staged, bounded, and internally coherent")


if __name__ == "__main__":
    main()
