#!/usr/bin/env python3
"""Fail unless MasuGate wheel and sdist contain governance and protocol artifacts."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

REQUIRED_PACKAGE_FILES = frozenset(
    {
        "masugate/catalog/schema/bundle.schema.json",
        "masugate/catalog/reference/bundle.json",
        "masugate/catalog/reference/reference_guard.pvl",
        "masugate/catalog/reference_spend/bundle.json",
        "masugate/catalog/reference_spend/spend_budget_guard.pvl",
        "masugate/catalog/reference_operational_limits/bundle.json",
        "masugate/catalog/reference_operational_limits/api_spend_reference.pvl",
        "masugate/catalog/reference_operational_limits/http_post_reference.pvl",
        "masugate/catalog/readiness/deployment.json",
        "masugate/catalog/readiness/platform/bundle.json",
        "masugate/catalog/readiness/platform/capacity_guard.pvl",
        "masugate/catalog/readiness/platform/review_guard.pvl",
        "masugate/catalog/readiness/platform/hold_guard.pvl",
        "masugate/catalog/readiness/owner/bundle.json",
        "masugate/catalog/readiness/owner/owner_limit.pvl",
        "masugate/protected_execution/audit.py",
        "masugate/protected_execution/postgres.py",
        "masugate/protected_execution/recovery.py",
        "masugate/protected_execution/runner.py",
        "masugate/protected_execution/store.py",
        "masugate/providers/spend.py",
        "masugate/providers/operational_limits.py",
        "masugate/protocol/Host-Adapter-Contract.md",
        "masugate/protocol/Operation-Pack-Contract.md",
        "masugate/protocol/Operation-Payload-Contract.md",
        "masugate/protocol/examples/host-adapter-cancellation.json",
        "masugate/protocol/examples/artifact-request.json",
        "masugate/protocol/examples/artifact-response.json",
        "masugate/protocol/examples/connector-registry-route-fixture.json",
        "masugate/protocol/examples/connector-worker-containment.json",
        "masugate/protocol/examples/host-adapter-golden-vectors.json",
        "masugate/protocol/examples/host-adapter-invocation.json",
        "masugate/protocol/examples/host-adapter-lifecycle.json",
        "masugate/protocol/examples/host-adapter-route-manifest.json",
        "masugate/protocol/examples/host-adapter-receipt.json",
        "masugate/protocol/examples/host-adapter-roster.json",
        "masugate/protocol/examples/governed-route-manifest-v2-route-fixture.json",
        "masugate/protocol/examples/operation-deployment-binding-route-fixture.json",
        "masugate/protocol/examples/operation-pack-route-fixture.json",
        "masugate/protocol/examples/operation-pack-v2-field-vectors.json",
        "masugate/protocol/schemas/host-adapter-envelope.schema.json",
        "masugate/protocol/schemas/artifact-request.schema.json",
        "masugate/protocol/schemas/artifact-response.schema.json",
        "masugate/protocol/schemas/connector-registry.schema.json",
        "masugate/protocol/schemas/connector-worker-containment.schema.json",
        "masugate/protocol/schemas/host-adapter-lifecycle.schema.json",
        "masugate/protocol/schemas/host-adapter-route-manifest.schema.json",
        "masugate/protocol/schemas/host-adapter-roster.schema.json",
        "masugate/protocol/schemas/governed-route-manifest-v2.schema.json",
        "masugate/protocol/schemas/operation-deployment-binding.schema.json",
        "masugate/protocol/schemas/operation-pack.schema.json",
        "masugate/operations/compiler.py",
        "masugate/operations/artifacts.py",
        "masugate/operations/loader.py",
        "masugate/operations/secrets.py",
        "masugate/operations/worker.py",
        "masugate/testing/protected_execution.py",
    }
)


def _normalized_sdist_members(path: Path) -> frozenset[str]:
    with tarfile.open(path, "r:gz") as archive:
        members = tuple(member.name for member in archive.getmembers() if member.isfile())
    normalized: set[str] = set()
    for member in members:
        source_marker = "/src/"
        protocol_marker = "/protocol/"
        if source_marker in member:
            normalized.add(member.split(source_marker, 1)[1])
        elif protocol_marker in member:
            normalized.add("masugate/protocol/" + member.split(protocol_marker, 1)[1])
    return frozenset(normalized)


def _wheel_members(path: Path) -> frozenset[str]:
    with zipfile.ZipFile(path) as archive:
        return frozenset(name for name in archive.namelist() if not name.endswith("/"))


def _check(path: Path) -> None:
    if path.name.endswith(".whl"):
        members = _wheel_members(path)
    elif path.name.endswith(".tar.gz"):
        members = _normalized_sdist_members(path)
    else:
        raise SystemExit(f"unsupported package artifact: {path}")
    missing = REQUIRED_PACKAGE_FILES - members
    if missing:
        rendered = "\n  ".join(sorted(missing))
        raise SystemExit(f"{path} is missing required package files:\n  {rendered}")
    print(f"package artifact contains required governance and protocol artifacts: {path}")


def _run_integrated_readiness(target: Path) -> None:
    """Run package-readiness and protected-execution recovery joins with wheel-pinned imports."""

    tests = Path(__file__).resolve().parents[1] / "tests"
    readiness_tests = (
        tests / "test_platform_readiness.py",
        tests / "test_protected_package_readiness.py",
    )
    missing = tuple(path for path in readiness_tests if not path.is_file())
    if missing:
        raise SystemExit(f"integrated readiness tests are missing: {missing}")
    isolated_config = target / "pytest.ini"
    isolated_config.write_text("[pytest]\nasyncio_mode = auto\n", encoding="utf-8")
    pytest_args = [
        *(str(path) for path in readiness_tests),
        "-q",
        "--no-header",
        "--import-mode=importlib",
        "-p",
        "no:cacheprovider",
        "--rootdir",
        str(target),
        "-c",
        str(isolated_config),
    ]
    runner = "\n".join(
        (
            "from pathlib import Path",
            "import sys",
            f"artifact_root = Path({str(target)!r}).resolve()",
            "sys.path.insert(0, str(artifact_root))",
            "import masugate",
            "package_path = Path(masugate.__file__).resolve()",
            "if not package_path.is_relative_to(artifact_root):",
            "    raise SystemExit(f'MasuGate imported outside wheel: {package_path}')",
            "contract_root = package_path.parent / 'protocol'",
            "required_contract = (",
            "    contract_root / 'Host-Adapter-Contract.md',",
            "    contract_root / 'Operation-Pack-Contract.md',",
            "    contract_root / 'examples' / 'host-adapter-cancellation.json',",
            "    contract_root / 'examples' / 'artifact-request.json',",
            "    contract_root / 'examples' / 'artifact-response.json',",
            "    contract_root / 'examples' / 'connector-registry-route-fixture.json',",
            "    contract_root / 'examples' / 'connector-worker-containment.json',",
            "    contract_root / 'examples' / 'host-adapter-golden-vectors.json',",
            "    contract_root / 'examples' / 'host-adapter-invocation.json',",
            "    contract_root / 'examples' / 'host-adapter-lifecycle.json',",
            "    contract_root / 'examples' / 'host-adapter-route-manifest.json',",
            "    contract_root / 'examples' / 'host-adapter-receipt.json',",
            "    contract_root / 'examples' / 'host-adapter-roster.json',",
            "    contract_root / 'examples' / 'governed-route-manifest-v2-route-fixture.json',",
            "    contract_root / 'examples' / 'operation-deployment-binding-route-fixture.json',",
            "    contract_root / 'examples' / 'operation-pack-route-fixture.json',",
            "    contract_root / 'examples' / 'operation-pack-v2-field-vectors.json',",
            "    contract_root / 'schemas' / 'host-adapter-envelope.schema.json',",
            "    contract_root / 'schemas' / 'artifact-request.schema.json',",
            "    contract_root / 'schemas' / 'artifact-response.schema.json',",
            "    contract_root / 'schemas' / 'connector-registry.schema.json',",
            "    contract_root / 'schemas' / 'connector-worker-containment.schema.json',",
            "    contract_root / 'schemas' / 'host-adapter-lifecycle.schema.json',",
            "    contract_root / 'schemas' / 'host-adapter-route-manifest.schema.json',",
            "    contract_root / 'schemas' / 'host-adapter-roster.schema.json',",
            "    contract_root / 'schemas' / 'governed-route-manifest-v2.schema.json',",
            "    contract_root / 'schemas' / 'operation-deployment-binding.schema.json',",
            "    contract_root / 'schemas' / 'operation-pack.schema.json',",
            ")",
            "missing_contract = [path for path in required_contract if not path.is_file()]",
            "if missing_contract:",
            "    raise SystemExit("
            "f'MasuGate wheel lacks host-adapter contract: {missing_contract}'"
            ")",
            "import pytest",
            f"raise SystemExit(pytest.main({pytest_args!r}))",
        )
    )
    try:
        subprocess.run(
            [sys.executable, "-I", "-c", runner],
            cwd=target,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise SystemExit("extracted-wheel integrated readiness failed") from exc


def _check_connector_sdk(path: Path) -> None:
    if path.suffix != ".whl":
        raise SystemExit(f"connector SDK must be a wheel: {path}")
    members = _wheel_members(path)
    required = {
        "masugate_connector_sdk/__init__.py",
        "masugate_connector_sdk/conformance.py",
    }
    missing = required - members
    if missing:
        rendered = "\n  ".join(sorted(missing))
        raise SystemExit(f"{path} is missing required connector SDK files:\n  {rendered}")
    if not any(name.endswith(".dist-info/METADATA") for name in members):
        raise SystemExit(f"{path} is missing connector SDK distribution metadata")
    print(f"connector SDK artifact contains required public files: {path}")


def _check_core_sdk_separation(core_wheel: Path, connector_sdk: Path) -> None:
    """Reject the uninstall-order collision caused by bundling the SDK twice."""

    core_members = _wheel_members(core_wheel)
    sdk_members = _wheel_members(connector_sdk)
    overlapping_sdk = {
        member
        for member in core_members & sdk_members
        if member.startswith("masugate_connector_sdk/")
    }
    if overlapping_sdk or any(
        member.startswith("masugate_connector_sdk/") for member in core_members
    ):
        raise SystemExit("MasuGate core wheel must not claim masugate_connector_sdk files")
    with zipfile.ZipFile(core_wheel) as archive:
        metadata_names = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        if len(metadata_names) != 1:
            raise SystemExit("MasuGate core wheel has invalid distribution metadata")
        metadata = archive.read(metadata_names[0]).decode("utf-8")
    normalized_metadata = metadata.replace(" ", "")
    if "Requires-Dist:masugate-connector-sdk==0.1.1" not in normalized_metadata:
        raise SystemExit("MasuGate core wheel must require the exact standalone connector SDK")
    print("core and connector SDK wheels have disjoint ownership and an exact dependency")


def _smoke_wheel(path: Path, connector_sdk: Path) -> None:
    """Execute platform joins from the core wheel plus its public SDK wheel."""

    with tempfile.TemporaryDirectory(prefix="masugate-wheel-smoke-") as directory:
        target = Path(directory)
        with zipfile.ZipFile(connector_sdk) as archive:
            archive.extractall(target)
        with zipfile.ZipFile(path) as archive:
            archive.extractall(target)
        _run_integrated_readiness(target)
    print(f"package artifact integrated readiness passed: {path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact_directory", type=Path)
    parser.add_argument("connector_sdk_wheel", type=Path)
    args = parser.parse_args()
    root: Path = args.artifact_directory
    wheels = tuple(sorted(root.glob("*.whl")))
    sdists = tuple(sorted(root.glob("*.tar.gz")))
    if len(wheels) != 1 or len(sdists) != 1:
        raise SystemExit(
            f"expected exactly one wheel and one sdist in {root}; "
            f"found wheels={len(wheels)} sdists={len(sdists)}"
        )
    for artifact in (*wheels, *sdists):
        _check(artifact)
    _check_connector_sdk(args.connector_sdk_wheel)
    _check_core_sdk_separation(wheels[0], args.connector_sdk_wheel)
    _smoke_wheel(wheels[0], args.connector_sdk_wheel)


if __name__ == "__main__":
    main()
