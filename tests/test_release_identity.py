"""reference release release identity and preview schema-boundary tests."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import io
import json
import sqlite3
import tarfile
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from typing import Any, cast
from uuid import RFC_4122, UUID

import pytest

from masugate import __version__ as masugate_version
from masugate_openclaw_reference import ReferenceSpendResource
from masugate_openclaw_reference import __version__ as reference_version
from masugate_openclaw_reference.release import (
    REFERENCE_RELEASE_ID,
    REFERENCE_SCHEMA_ID,
    REFERENCE_SCHEMA_VERSION,
    ReferenceSchemaBoundaryError,
    ensure_postgres_reference_schema,
    ensure_sqlite_reference_schema,
)


def _release_builder() -> Any:
    path = Path(__file__).parents[1] / "scripts" / "build-reference-release.py"
    spec = importlib.util.spec_from_file_location("reference_release", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_test_release_archives(
    output: Path,
    builder: Any,
    manifest: dict[str, object],
    *,
    npm_name_override: tuple[str, str] | None = None,
) -> None:
    for component in builder._expected_first_party_components(manifest):
        name = cast(str, component["name"])
        version = cast(str, component["version"])
        purl = cast(str, component["purl"])
        if purl.startswith("pkg:pypi/"):
            normalized = name.replace("-", "_")
            metadata = (f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n\n").encode()
            python_output = output / "python" / normalized
            python_output.mkdir(parents=True, exist_ok=True)
            wheel = python_output / f"{normalized}-{version}-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr(f"{normalized}-{version}.dist-info/METADATA", metadata)
            sdist = python_output / f"{normalized}-{version}.tar.gz"
            with tarfile.open(sdist, "w:gz") as archive:
                member = tarfile.TarInfo(f"{normalized}-{version}/PKG-INFO")
                member.size = len(metadata)
                archive.addfile(member, io.BytesIO(metadata))
        else:
            archive_name = name
            if npm_name_override is not None and name == npm_name_override[0]:
                archive_name = npm_name_override[1]
            package_json = json.dumps({"name": archive_name, "version": version}).encode()
            npm_output = output / "npm"
            npm_output.mkdir(parents=True, exist_ok=True)
            tarball_name = name.removeprefix("@").replace("/", "-")
            with tarfile.open(npm_output / f"{tarball_name}-{version}.tgz", "w:gz") as archive:
                member = tarfile.TarInfo("package/package.json")
                member.size = len(package_json)
                archive.addfile(member, io.BytesIO(package_json))


def test_release_npm_builds_workspaces_before_packing_without_lifecycle_hooks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = _release_builder()
    calls: list[tuple[list[str], Path, dict[str, str]]] = []
    monkeypatch.setattr(
        builder.shutil, "which", lambda name: "/local/npm" if name == "npm" else None
    )
    monkeypatch.setattr(
        builder,
        "_run",
        lambda argv, *, cwd, env: calls.append((argv, cwd, env)),
    )
    environment = {"NPM_CONFIG_IGNORE_SCRIPTS": "true", "NPM_CONFIG_OFFLINE": "true"}

    builder._build_npm(tmp_path / "npm", environment)

    assert len(calls) == 8
    assert [argv[1:4] for argv, _cwd, _env in calls[:4]] == [
        ["run", "build", "--workspace"],
        ["run", "build", "--workspace"],
        ["run", "build", "--workspace"],
        ["run", "build", "--workspace"],
    ]
    assert all("--ignore-scripts=true" in argv for argv, _cwd, _env in calls[4:])
    assert all("--ignore-scripts=false" not in argv for argv, _cwd, _env in calls[4:])
    assert all(cwd == builder.ROOT for _argv, cwd, _env in calls)
    assert all(env is environment for _argv, _cwd, env in calls)


def test_reference_release_manifest_matches_all_shipped_package_versions() -> None:
    manifest = _release_builder().load_and_validate_manifest()

    assert manifest["release_id"] == f"masugate-openclaw-reference/{reference_version}"
    assert manifest["runtime_target"] == {
        "os": "linux",
        "architecture": "amd64",
        "python_abi": "cp312",
    }
    artifacts = manifest["artifacts"]
    assert isinstance(artifacts, dict)
    assert artifacts["platform"]["version"] == masugate_version
    assert artifacts["connector_sdk"]["version"] == masugate_version
    assert artifacts["platform"]["connector_sdk_dependency"] == (
        f"masugate-connector-sdk=={masugate_version}"
    )
    assert artifacts["reference_deployment"]["schema"]["boundary"] == "clean-install-only"
    modules = cast(list[dict[str, object]], manifest["provider_modules"])
    assert {str(module["id"]) for module in modules} >= {
        "masugate.spend.reference",
        "masugate.operational-limits",
    }


def test_compatibility_matrix_pins_each_supported_framework_host() -> None:
    builder = _release_builder()
    manifest = builder.load_and_validate_manifest()
    builder._validate_compatibility_matrix(manifest)

    matrix = json.loads(builder.COMPATIBILITY_MATRIX_PATH.read_text(encoding="utf-8"))
    assert matrix["pinned_host"] == {
        "agent-framework-core": "1.12.0",
        "crewai": "1.15.6",
        "langchain": "1.3.14",
        "langgraph": "1.2.9",
        "node": "24.16.0",
        "openclaw": "2026.7.1",
    }


def test_compatibility_matrix_rejects_missing_framework_host(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = _release_builder()
    manifest = builder.load_and_validate_manifest()
    matrix = json.loads(builder.COMPATIBILITY_MATRIX_PATH.read_text(encoding="utf-8"))
    matrix["pinned_host"].pop("crewai")
    matrix_path = tmp_path / "compatibility-matrix.json"
    matrix_path.write_text(json.dumps(matrix), encoding="utf-8")
    monkeypatch.setattr(builder, "COMPATIBILITY_MATRIX_PATH", matrix_path)

    with pytest.raises(builder.ReleaseBuildError, match="pinned host"):
        builder._validate_compatibility_matrix(manifest)


def test_reference_release_manifest_pins_all_declared_images_by_digest() -> None:
    manifest = _release_builder().load_and_validate_manifest()
    images = manifest["container_images"]
    assert isinstance(images, dict)
    assert images
    assert all("@sha256:" in image for image in images.values())


def test_reference_release_manifest_declares_closed_first_party_container_set() -> None:
    manifest = _release_builder().load_and_validate_manifest()
    declaration = manifest["container_artifact"]
    assert declaration == {
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


def test_reference_release_manifest_refuses_declared_identity_drift(tmp_path: Path) -> None:
    builder = _release_builder()
    source = json.loads(builder.MANIFEST_PATH.read_text(encoding="utf-8"))
    variants: dict[str, dict[str, object]] = {}

    catalog = json.loads(json.dumps(source))
    catalog["catalogs"][0] = "masugate.adversarial.reference@9.9.9"
    variants["catalog"] = catalog

    provider = json.loads(json.dumps(source))
    provider["provider_modules"][0]["implementation_version"] = "masugate.spend.reference-v999"
    variants["provider"] = provider

    openclaw = json.loads(json.dumps(source))
    openclaw["artifacts"]["openclaw_adapter"]["openclaw_peer"] = "2026.7.2"
    variants["openclaw"] = openclaw

    image = json.loads(json.dumps(source))
    image["container_images"]["openclaw"] = "ghcr.io/openclaw/openclaw@sha256:" + "0" * 64
    variants["image"] = image

    distribution = json.loads(json.dumps(source))
    distribution["artifacts"]["platform"]["distribution"] = "not-masugate"
    variants["distribution"] = distribution

    protocol = json.loads(json.dumps(source))
    protocol["artifacts"]["platform"]["protocol_contract"] = "invented.contract"
    variants["protocol"] = protocol

    dependency = json.loads(json.dumps(source))
    dependency["artifacts"]["mcp_gateway"]["client_dependency"] = "9.9.9"
    variants["dependency"] = dependency

    platform_dependency = json.loads(json.dumps(source))
    platform_dependency["artifacts"]["reference_deployment"]["platform_dependency"] = (
        "masugate==9.9.9"
    )
    variants["platform-dependency"] = platform_dependency

    connector_sdk_dependency = json.loads(json.dumps(source))
    connector_sdk_dependency["artifacts"]["platform"]["connector_sdk_dependency"] = (
        "masugate-connector-sdk==9.9.9"
    )
    variants["connector-sdk-dependency"] = connector_sdk_dependency

    locks = json.loads(json.dumps(source))
    locks["locks"]["npm"] = "README.md"
    locks["locks"]["openclaw_contract"] = "README.md"
    variants["locks"] = locks

    profile = json.loads(json.dumps(source))
    profile["sandbox_profile"]["profile"] = "README.md"
    variants["profile"] = profile

    for name, variant in variants.items():
        path = tmp_path / f"{name}.json"
        path.write_text(json.dumps(variant), encoding="utf-8")
        builder.MANIFEST_PATH = path
        with pytest.raises(builder.ReleaseBuildError):
            builder.load_and_validate_manifest()


def test_reference_release_manifest_refuses_source_lock_and_profile_drift() -> None:
    builder = _release_builder()
    original_json = builder._json

    def stale_lock(path: Path) -> dict[str, object]:
        raw = original_json(path)
        if path == builder.ROOT / "package-lock.json":
            raw = json.loads(json.dumps(raw))
            raw["packages"]["gateway"]["dependencies"]["@masugate/client"] = "9.9.9"
        return cast(dict[str, object], raw)

    builder._json = stale_lock
    with pytest.raises(builder.ReleaseBuildError, match="lock"):
        builder.load_and_validate_manifest()

    def stale_profile(path: Path) -> dict[str, object]:
        raw = original_json(path)
        if path == (
            builder.ROOT / "integrations" / "openclaw-reference" / "containment" / "profile.json"
        ):
            raw = json.loads(json.dumps(raw))
            raw["schema_version"] = "invented.profile/v9"
        return cast(dict[str, object], raw)

    builder._json = stale_profile
    with pytest.raises(builder.ReleaseBuildError, match="profile schema identity"):
        builder.load_and_validate_manifest()


def test_reference_release_manifest_refuses_adapter_runtime_dependency_drift() -> None:
    builder = _release_builder()
    original_json = builder._json

    def stale_adapter_core(path: Path) -> dict[str, object]:
        raw = original_json(path)
        if path == builder.ROOT / "adapters" / "typescript" / "package.json":
            raw = json.loads(json.dumps(raw))
            raw["dependencies"]["@masugate/client"] = "^9.9.9"
        return cast(dict[str, object], raw)

    builder._json = stale_adapter_core
    with pytest.raises(builder.ReleaseBuildError, match="adapter-core client dependency"):
        builder.load_and_validate_manifest()

    def stale_openclaw(path: Path) -> dict[str, object]:
        raw = original_json(path)
        if path == builder.ROOT / "integrations" / "openclaw" / "package.json":
            raw = json.loads(json.dumps(raw))
            raw["dependencies"]["@masugate/adapter-core"] = "9.9.9"
        return cast(dict[str, object], raw)

    builder._json = stale_openclaw
    with pytest.raises(builder.ReleaseBuildError, match="runtime dependencies"):
        builder.load_and_validate_manifest()

    def incomplete_openclaw_bundle(path: Path) -> dict[str, object]:
        raw = original_json(path)
        if path == builder.ROOT / "integrations" / "openclaw" / "package.json":
            raw = json.loads(json.dumps(raw))
            raw["bundledDependencies"].remove("typebox")
        return cast(dict[str, object], raw)

    builder._json = incomplete_openclaw_bundle
    with pytest.raises(builder.ReleaseBuildError, match="complete runtime dependency closure"):
        builder.load_and_validate_manifest()

    def stale_openclaw_bundle_lock(path: Path) -> dict[str, object]:
        raw = original_json(path)
        if path == builder.ROOT / "package-lock.json":
            raw = json.loads(json.dumps(raw))
            raw["packages"]["integrations/openclaw"]["bundleDependencies"].remove("typebox")
        return cast(dict[str, object], raw)

    builder._json = stale_openclaw_bundle_lock
    with pytest.raises(builder.ReleaseBuildError, match="bundled runtime dependencies"):
        builder.load_and_validate_manifest()


def test_reference_release_manifest_refuses_reference_dependency_source_drift() -> None:
    builder = _release_builder()
    original_project = builder._toml_project

    def stale_project(path: Path) -> dict[str, object]:
        project = original_project(path)
        if path == (builder.ROOT / "integrations" / "openclaw-reference" / "pyproject.toml"):
            project = dict(project)
            project["dependencies"] = ["masugate>=0.1.1", "masugate-client==0.1.1"]
        return cast(dict[str, object], project)

    builder._toml_project = stale_project
    with pytest.raises(builder.ReleaseBuildError, match="platform dependency"):
        builder.load_and_validate_manifest()


def test_reference_release_sbom_conforms_to_official_cyclonedx_1_5_schema(
    tmp_path: Path,
) -> None:
    builder = _release_builder()
    manifest = builder.load_and_validate_manifest()
    _write_test_release_archives(tmp_path, builder, manifest)

    builder._write_attestations(tmp_path, manifest, "a" * 40, 1_700_000_000)

    sbom = json.loads((tmp_path / "sbom.cdx.json").read_text(encoding="utf-8"))
    builder._validate_sbom(sbom, manifest)
    components = cast(list[dict[str, str]], sbom["components"])
    assert len(components) == len(
        {json.dumps(component, sort_keys=True) for component in components}
    )
    expected_first_party = {
        component["purl"]: component
        for component in builder._expected_first_party_components(manifest)
    }
    actual_first_party = {
        component["purl"]: component
        for component in components
        if component.get("purl") in expected_first_party
    }
    assert actual_first_party == expected_first_party
    assert set(expected_first_party) == {
        "pkg:npm/%40masugate/client@0.1.1",
        "pkg:npm/%40masugate/adapter-core@0.1.1",
        "pkg:npm/%40masugate/mcp-gateway@0.1.1",
        "pkg:npm/%40masugate/openclaw@0.1.1",
        "pkg:pypi/masugate-adapter-core@0.1.1",
        "pkg:pypi/masugate-agent-framework@0.1.1",
        "pkg:pypi/masugate-client@0.1.1",
        "pkg:pypi/masugate-connector-filesystem@0.1.1",
        "pkg:pypi/masugate-connector-google-calendar@0.1.1",
        "pkg:pypi/masugate-connector-sdk@0.1.1",
        "pkg:pypi/masugate-connector-stripe-payment-intent@0.1.1",
        "pkg:pypi/masugate-crewai@0.1.1",
        "pkg:pypi/masugate-langchain@0.1.1",
        "pkg:pypi/masugate-openclaw-reference@0.1.1",
        "pkg:pypi/masugate-operation-calendar@0.1.1",
        "pkg:pypi/masugate-operation-filesystem@0.1.1",
        "pkg:pypi/masugate-operation-spend@0.1.1",
        "pkg:pypi/masugate@0.1.1",
    }
    assert not {
        "clients/typescript",
        "adapters/typescript",
        "gateway",
        "integrations/openclaw",
    } & {component["name"] for component in components}
    primary = cast(dict[str, str], sbom["metadata"]["component"])
    dependencies = cast(list[dict[str, object]], sbom["dependencies"])
    assert dependencies == [
        {
            "ref": primary["bom-ref"],
            "dependsOn": sorted(expected_first_party),
        }
    ]
    raw_component_count = (
        len(builder._expected_first_party_components(manifest))
        + len(builder._python_components())
        + len(builder._npm_components())
        + len(cast(dict[str, str], manifest["container_images"]))
    )
    assert len(components) < raw_component_count
    assert any(
        component.get("purl") == "pkg:npm/%40hono/node-server@1.19.14" for component in components
    )
    serial = cast(str, sbom["serialNumber"])
    identifier = UUID(serial.removeprefix("urn:uuid:"))
    assert identifier.version == 5
    assert identifier.variant == RFC_4122


def test_reference_release_attestation_keeps_origin_and_staging_realization_distinct(
    tmp_path: Path,
) -> None:
    builder = _release_builder()
    manifest = builder.load_and_validate_manifest()
    _write_test_release_archives(tmp_path, builder, manifest)

    builder._write_attestations(
        tmp_path,
        manifest,
        "a" * 40,
        1_700_000_000,
        "b" * 40,
        1_700_000_001,
    )

    provenance = json.loads((tmp_path / "provenance.json").read_text(encoding="utf-8"))
    assert provenance["source_revision"] == "a" * 40
    assert provenance["source_date_epoch"] == 1_700_000_000
    assert provenance["staging_realization_revision"] == "b" * 40
    assert provenance["staging_realization_date_epoch"] == 1_700_000_001


def test_reference_release_requires_complete_explicit_origin_provenance() -> None:
    builder = _release_builder()

    assert builder._provenance_source(
        "a" * 40, 10, source_revision="b" * 40, source_date_epoch=11
    ) == (
        "b" * 40,
        11,
    )
    with pytest.raises(builder.ReleaseBuildError, match="supplied together"):
        builder._provenance_source("a" * 40, 10, source_revision="b" * 40, source_date_epoch=None)
    with pytest.raises(builder.ReleaseBuildError, match="full lowercase Git revision"):
        builder._provenance_source(
            "a" * 40, 10, source_revision="not-a-revision", source_date_epoch=11
        )


def test_reference_release_sbom_validator_rejects_invalid_supply_chain_fields(
    tmp_path: Path,
) -> None:
    builder = _release_builder()
    manifest = builder.load_and_validate_manifest()
    _write_test_release_archives(tmp_path, builder, manifest)
    builder._write_attestations(tmp_path, manifest, "b" * 40, 1_700_000_000)
    source = json.loads((tmp_path / "sbom.cdx.json").read_text(encoding="utf-8"))

    duplicate = json.loads(json.dumps(source))
    duplicate["components"].append(duplicate["components"][0])
    with pytest.raises(builder.ReleaseBuildError, match=r"CycloneDX 1\.5 SBOM is invalid"):
        builder._validate_sbom(duplicate, manifest)

    serial = json.loads(json.dumps(source))
    serial["serialNumber"] = "urn:uuid:00000000-0000-0000-0000-000000000000"
    with pytest.raises(builder.ReleaseBuildError, match="UUIDv5"):
        builder._validate_sbom(serial, manifest)

    purl = json.loads(json.dumps(source))
    scoped = next(
        component
        for component in purl["components"]
        if component.get("purl", "").startswith("pkg:npm/%40")
    )
    scoped["purl"] = scoped["purl"].replace("pkg:npm/%40", "pkg:npm/@", 1)
    with pytest.raises(builder.ReleaseBuildError, match="not percent-encoded"):
        builder._validate_sbom(purl, manifest)

    missing = json.loads(json.dumps(source))
    missing["components"] = [
        component
        for component in missing["components"]
        if component.get("purl") != "pkg:pypi/masugate@0.1.1"
    ]
    with pytest.raises(builder.ReleaseBuildError, match="first-party component exactly once"):
        builder._validate_sbom(missing, manifest)

    workspace_path = json.loads(json.dumps(source))
    workspace_path["components"].append(
        {
            "type": "library",
            "name": "clients/typescript",
            "version": "0.1.1",
            "purl": "pkg:npm/clients%2Ftypescript@0.1.1",
            "bom-ref": "pkg:npm/clients%2Ftypescript@0.1.1",
        }
    )
    with pytest.raises(builder.ReleaseBuildError, match="path-derived workspace identity"):
        builder._validate_sbom(workspace_path, manifest)

    adapter_workspace_path = json.loads(json.dumps(source))
    adapter_workspace_path["components"].append(
        {
            "type": "library",
            "name": "adapters/typescript",
            "version": "0.1.1",
            "purl": "pkg:npm/adapters%2Ftypescript@0.1.1",
            "bom-ref": "pkg:npm/adapters%2Ftypescript@0.1.1",
        }
    )
    with pytest.raises(builder.ReleaseBuildError, match="path-derived workspace identity"):
        builder._validate_sbom(adapter_workspace_path, manifest)

    incomplete_root = json.loads(json.dumps(source))
    incomplete_root["dependencies"][0]["dependsOn"].pop()
    with pytest.raises(builder.ReleaseBuildError, match="exactly the declared"):
        builder._validate_sbom(incomplete_root, manifest)


def test_reference_release_sbom_refuses_built_package_identity_drift(tmp_path: Path) -> None:
    builder = _release_builder()
    manifest = builder.load_and_validate_manifest()
    _write_test_release_archives(
        tmp_path,
        builder,
        manifest,
        npm_name_override=("@masugate/client", "@masugate/not-client"),
    )

    with pytest.raises(builder.ReleaseBuildError, match="built npm artifacts"):
        builder._write_attestations(tmp_path, manifest, "c" * 40, 1_700_000_000)


def test_clean_consumer_lock_binds_sri_to_the_exact_built_tarballs(tmp_path: Path) -> None:
    builder = _release_builder()
    npm = tmp_path / "npm"
    npm.mkdir()
    contents: dict[str, bytes] = {}
    for position, filename in enumerate(builder._NPM_CLEAN_CONSUMER_TARBALLS.values(), start=1):
        value = f"tarball-{position}".encode("ascii")
        contents[filename] = value
        (npm / filename).write_bytes(value)

    destination = tmp_path / "deployment" / "npm-clean-consumer-lock.json"
    destination.parent.mkdir()
    builder._stage_npm_clean_consumer_lock(tmp_path, destination)

    packages = json.loads(destination.read_text(encoding="utf-8"))["packages"]
    for package, filename in builder._NPM_CLEAN_CONSUMER_TARBALLS.items():
        expected = "sha512-" + base64.b64encode(hashlib.sha512(contents[filename]).digest()).decode(
            "ascii"
        )
        assert packages[f"node_modules/{package}"]["integrity"] == expected


def test_reference_release_materializes_hashed_offline_runtime_wheelhouse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _release_builder()
    wheel = b"locked wheel fixture"
    digest = hashlib.sha256(wheel).hexdigest()
    lock = tmp_path / "pylock.toml"
    lock.write_text(
        "\n".join(
            (
                'lock-version = "1.0"',
                "[[packages]]",
                'name = "fixture"',
                'version = "1.2.3"',
                "[[packages.wheels]]",
                'name = "fixture-1.2.3-py3-none-any.whl"',
                'url = "https://files.pythonhosted.org/packages/fixture.whl"',
                "[packages.wheels.hashes]",
                f'sha256 = "{digest}"',
            )
        )
        + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(builder, "urlopen", lambda *_args, **_kwargs: io.BytesIO(wheel))

    builder._stage_locked_python_runtime(
        tmp_path / "release",
        {"locks": {"python": str(lock)}},
    )

    runtime = tmp_path / "release" / "python" / "runtime"
    assert (runtime / "wheelhouse" / "fixture-1.2.3-py3-none-any.whl").read_bytes() == wheel
    assert (runtime / "requirements.txt").read_text(encoding="utf-8") == (
        f"fixture==1.2.3 --hash=sha256:{digest}\n"
    )
    assert (runtime / "pylock.toml").read_text(encoding="utf-8") == lock.read_text(encoding="utf-8")


def test_reference_release_copies_an_exact_offline_wheelhouse_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    builder = _release_builder()
    wheel = b"offline locked wheel fixture"
    digest = hashlib.sha256(wheel).hexdigest()
    lock = tmp_path / "pylock.toml"
    filename = "fixture-1.2.3-py3-none-any.whl"
    lock.write_text(
        "\n".join(
            (
                'lock-version = "1.0"',
                "[[packages]]",
                'name = "fixture"',
                'version = "1.2.3"',
                "[[packages.wheels]]",
                f'name = "{filename}"',
                'url = "https://files.pythonhosted.org/packages/fixture.whl"',
                "[packages.wheels.hashes]",
                f'sha256 = "{digest}"',
            )
        )
        + "\n",
        encoding="utf-8",
    )
    wheelhouse = tmp_path / "wheelhouse"
    wheelhouse.mkdir()
    (wheelhouse / filename).write_bytes(wheel)
    monkeypatch.setattr(builder, "urlopen", lambda *_args, **_kwargs: pytest.fail("network used"))

    builder._stage_locked_python_runtime(
        tmp_path / "release",
        {"locks": {"python": str(lock)}},
        offline_wheelhouse=wheelhouse,
    )

    assert (tmp_path / "release/python/runtime/wheelhouse" / filename).read_bytes() == wheel


def test_clean_sqlite_reference_database_records_one_schema_marker(tmp_path: Path) -> None:
    database = tmp_path / "reference.sqlite3"

    ensure_sqlite_reference_schema(database)
    ensure_sqlite_reference_schema(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT schema_id, schema_version, release_id FROM masugate_release_metadata"
        ).fetchone() == (REFERENCE_SCHEMA_ID, REFERENCE_SCHEMA_VERSION, REFERENCE_RELEASE_ID)


def test_unmarked_existing_sqlite_state_is_refused_without_mutation(tmp_path: Path) -> None:
    database = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE legacy_state (id INTEGER PRIMARY KEY)")

    with pytest.raises(ReferenceSchemaBoundaryError, match="clean installation only"):
        ensure_sqlite_reference_schema(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ).fetchall() == [("legacy_state",)]


def test_unmarked_sqlite_view_is_refused_without_mutation(tmp_path: Path) -> None:
    database = tmp_path / "legacy-view.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE VIEW legacy_view AS SELECT 1 AS value")

    with pytest.raises(ReferenceSchemaBoundaryError, match="clean installation only"):
        ensure_sqlite_reference_schema(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
        ).fetchall() == [("view", "legacy_view")]


@pytest.mark.parametrize(
    ("pragma", "value"),
    (("application_id", 1234), ("user_version", 37)),
)
def test_sqlite_persistent_identity_is_refused_without_mutation(
    tmp_path: Path,
    pragma: str,
    value: int,
) -> None:
    database = tmp_path / f"configured-{pragma}.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(f"PRAGMA {pragma} = {value}")

    with pytest.raises(ReferenceSchemaBoundaryError, match="clean installation only"):
        ensure_sqlite_reference_schema(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute(f"PRAGMA {pragma}").fetchone() == (value,)
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name = 'masugate_release_metadata'"
            ).fetchone()
            is None
        )


def test_object_free_sqlite_database_with_schema_history_is_refused(tmp_path: Path) -> None:
    database = tmp_path / "configured-schema.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE prior_state (value INTEGER)")
        connection.execute("DROP TABLE prior_state")
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
            == []
        )
        schema_version = cast(int, connection.execute("PRAGMA schema_version").fetchone()[0])
        assert schema_version > 0

    with pytest.raises(ReferenceSchemaBoundaryError, match="clean installation only"):
        ensure_sqlite_reference_schema(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute("PRAGMA schema_version").fetchone() == (schema_version,)
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name = 'masugate_release_metadata'"
            ).fetchone()
            is None
        )


async def test_marked_sqlite_schema_missing_provenance_is_refused_before_provider_initialization(
    tmp_path: Path,
) -> None:
    database = tmp_path / "missing-provenance.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE masugate_release_metadata "
            "(schema_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL, "
            "release_id TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO masugate_release_metadata VALUES (?, ?, ?)",
            (REFERENCE_SCHEMA_ID, REFERENCE_SCHEMA_VERSION, REFERENCE_RELEASE_ID),
        )
        connection.execute(
            "CREATE TABLE spend_entitlements "
            "(entitlement_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL)"
        )

    class PreviousStore:
        path = database

    class UninitializedService:
        store = PreviousStore()
        initialized = False

        async def initialize(self) -> None:
            self.initialized = True

    service = UninitializedService()
    resource = object.__new__(ReferenceSpendResource)
    resource.service = service  # type: ignore[assignment]

    with pytest.raises(
        ReferenceSchemaBoundaryError,
        match=r"missing required columns .*adapter_invocation_digest",
    ):
        await resource.initialize()

    assert not service.initialized
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT schema_id, schema_version, release_id FROM masugate_release_metadata"
        ).fetchone() == (REFERENCE_SCHEMA_ID, REFERENCE_SCHEMA_VERSION, REFERENCE_RELEASE_ID)
        assert connection.execute("PRAGMA table_info(spend_entitlements)").fetchall() == [
            (0, "entitlement_id", "TEXT", 0, None, 1),
            (1, "request_digest", "TEXT", 1, None, 0),
        ]


def test_wrong_marked_sqlite_release_is_refused_without_mutation(tmp_path: Path) -> None:
    database = tmp_path / "wrong-release.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE masugate_release_metadata "
            "(schema_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL, "
            "release_id TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO masugate_release_metadata VALUES (?, ?, ?)",
            (REFERENCE_SCHEMA_ID, REFERENCE_SCHEMA_VERSION, "masugate-openclaw-reference/9.9.9"),
        )

    with pytest.raises(ReferenceSchemaBoundaryError, match="clean installation only"):
        ensure_sqlite_reference_schema(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT schema_id, schema_version, release_id FROM masugate_release_metadata"
        ).fetchone() == (
            REFERENCE_SCHEMA_ID,
            REFERENCE_SCHEMA_VERSION,
            "masugate-openclaw-reference/9.9.9",
        )


async def test_reference_resource_refuses_legacy_store_before_provider_initialization(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy-resource.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE legacy_state (id INTEGER PRIMARY KEY)")

    class LegacyStore:
        path = database

    class UninitializedService:
        store = LegacyStore()
        initialized = False

        async def initialize(self) -> None:
            self.initialized = True

    service = UninitializedService()
    resource = object.__new__(ReferenceSpendResource)
    resource.service = service  # type: ignore[assignment]

    with pytest.raises(ReferenceSchemaBoundaryError, match="clean installation only"):
        await resource.initialize()

    assert not service.initialized
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
        ).fetchall() == [("legacy_state",)]


@pytest.mark.postgres
def test_clean_postgres_reference_schema_records_one_idempotent_marker(
    reference_postgres_dsn: str,
) -> None:
    import psycopg

    ensure_postgres_reference_schema(reference_postgres_dsn)
    ensure_postgres_reference_schema(reference_postgres_dsn)

    with psycopg.connect(reference_postgres_dsn) as connection:
        assert connection.execute(
            "SELECT schema_id, schema_version, release_id FROM masugate_release_metadata"
        ).fetchone() == (
            REFERENCE_SCHEMA_ID,
            REFERENCE_SCHEMA_VERSION,
            REFERENCE_RELEASE_ID,
        )


@pytest.mark.postgres
async def test_marked_postgres_schema_missing_provenance_is_refused_before_provider_initialization(
    reference_postgres_dsn: str,
) -> None:
    import psycopg

    with psycopg.connect(reference_postgres_dsn) as connection:
        connection.execute(
            "CREATE TABLE masugate_release_metadata ("
            "schema_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL, "
            "release_id TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO masugate_release_metadata VALUES (%s, %s, %s)",
            (REFERENCE_SCHEMA_ID, REFERENCE_SCHEMA_VERSION, REFERENCE_RELEASE_ID),
        )
        connection.execute(
            "CREATE TABLE spend_entitlements "
            "(entitlement_id TEXT PRIMARY KEY, request_digest TEXT NOT NULL)"
        )

    class MarkedStore:
        dsn = reference_postgres_dsn

    class UninitializedService:
        store = MarkedStore()
        initialized = False

        async def initialize(self) -> None:
            self.initialized = True

    service = UninitializedService()
    resource = object.__new__(ReferenceSpendResource)
    resource.service = service  # type: ignore[assignment]

    with pytest.raises(
        ReferenceSchemaBoundaryError,
        match=r"missing required columns .*adapter_invocation_digest",
    ):
        await resource.initialize()

    assert not service.initialized
    with psycopg.connect(reference_postgres_dsn) as connection:
        assert connection.execute(
            "SELECT schema_id, schema_version, release_id FROM masugate_release_metadata"
        ).fetchone() == (REFERENCE_SCHEMA_ID, REFERENCE_SCHEMA_VERSION, REFERENCE_RELEASE_ID)
        assert connection.execute(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = current_schema() AND table_name = 'spend_entitlements'
            ORDER BY ordinal_position
            """
        ).fetchall() == [("entitlement_id",), ("request_digest",)]


@pytest.mark.postgres
def test_wrong_postgres_release_is_refused_without_mutation(
    reference_postgres_dsn: str,
) -> None:
    import psycopg

    wrong_release = "masugate-openclaw-reference/9.9.9"
    with psycopg.connect(reference_postgres_dsn) as connection:
        connection.execute(
            "CREATE TABLE masugate_release_metadata ("
            "schema_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL, "
            "release_id TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO masugate_release_metadata VALUES (%s, %s, %s)",
            (REFERENCE_SCHEMA_ID, REFERENCE_SCHEMA_VERSION, wrong_release),
        )

    with pytest.raises(ReferenceSchemaBoundaryError, match="clean installation only"):
        ensure_postgres_reference_schema(reference_postgres_dsn)

    with psycopg.connect(reference_postgres_dsn) as connection:
        assert connection.execute(
            "SELECT schema_id, schema_version, release_id FROM masugate_release_metadata"
        ).fetchone() == (REFERENCE_SCHEMA_ID, REFERENCE_SCHEMA_VERSION, wrong_release)


@pytest.mark.postgres
def test_unmarked_postgres_view_is_refused_without_mutation(
    reference_postgres_dsn: str,
) -> None:
    import psycopg

    with psycopg.connect(reference_postgres_dsn) as connection:
        connection.execute("CREATE VIEW legacy_view AS SELECT 1 AS value")

    with pytest.raises(ReferenceSchemaBoundaryError, match="clean installation only"):
        ensure_postgres_reference_schema(reference_postgres_dsn)

    with psycopg.connect(reference_postgres_dsn) as connection:
        assert connection.execute("SELECT value FROM legacy_view").fetchone() == (1,)
        assert connection.execute(
            "SELECT to_regclass(current_schema() || '.masugate_release_metadata')"
        ).fetchone() == (None,)


@pytest.mark.postgres
def test_postgres_foreign_schema_create_acl_is_refused_without_mutation(
    reference_postgres_dsn: str,
) -> None:
    import psycopg
    from psycopg import sql

    with psycopg.connect(reference_postgres_dsn) as connection:
        schema_row = connection.execute("SELECT current_schema()").fetchone()
        assert schema_row is not None
        schema = cast(str, schema_row[0])
        connection.execute(
            sql.SQL("GRANT CREATE ON SCHEMA {} TO PUBLIC").format(sql.Identifier(schema))
        )

    with pytest.raises(ReferenceSchemaBoundaryError, match="clean installation only"):
        ensure_postgres_reference_schema(reference_postgres_dsn)

    with psycopg.connect(reference_postgres_dsn) as connection:
        assert connection.execute(
            "SELECT to_regclass(current_schema() || '.masugate_release_metadata')"
        ).fetchone() == (None,)
        assert connection.execute(
            """
            SELECT bool_or(
                acl_entry.grantee = 0 AND acl_entry.privilege_type = 'CREATE'
            )
            FROM pg_catalog.pg_namespace AS namespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) AS acl_entry
            WHERE namespace.nspname = current_schema()
            """
        ).fetchone() == (True,)


@pytest.mark.postgres
def test_postgres_default_table_privileges_are_refused_without_mutation(
    reference_postgres_dsn: str,
) -> None:
    import psycopg
    from psycopg import sql

    with psycopg.connect(reference_postgres_dsn) as connection:
        schema_row = connection.execute("SELECT current_schema()").fetchone()
        assert schema_row is not None
        schema = cast(str, schema_row[0])
        connection.execute(
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA {} GRANT SELECT ON TABLES TO PUBLIC"
            ).format(sql.Identifier(schema))
        )

    with pytest.raises(ReferenceSchemaBoundaryError, match="clean installation only"):
        ensure_postgres_reference_schema(reference_postgres_dsn)

    with psycopg.connect(reference_postgres_dsn) as connection:
        assert connection.execute(
            "SELECT to_regclass(current_schema() || '.masugate_release_metadata')"
        ).fetchone() == (None,)
        assert connection.execute(
            """
            SELECT count(*)
            FROM pg_catalog.pg_default_acl AS default_acl
            JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = default_acl.defaclnamespace
            WHERE namespace.nspname = current_schema()
            """
        ).fetchone() == (1,)


@pytest.mark.postgres
def test_concurrent_postgres_startup_serializes_marker_creation(
    reference_postgres_dsn: str,
) -> None:
    import psycopg

    barrier = Barrier(2)

    def initialize() -> None:
        barrier.wait(timeout=10)
        ensure_postgres_reference_schema(reference_postgres_dsn)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(initialize) for _ in range(2)]
        for future in futures:
            future.result(timeout=30)

    with psycopg.connect(reference_postgres_dsn) as connection:
        assert connection.execute("SELECT count(*) FROM masugate_release_metadata").fetchone() == (
            1,
        )


@pytest.mark.postgres
async def test_reference_resource_refuses_unmarked_postgres_before_initialization(
    reference_postgres_dsn: str,
) -> None:
    import psycopg

    with psycopg.connect(reference_postgres_dsn) as connection:
        connection.execute("CREATE VIEW legacy_view AS SELECT 1 AS value")

    class LegacyStore:
        dsn = reference_postgres_dsn

    class UninitializedService:
        store = LegacyStore()
        initialized = False

        async def initialize(self) -> None:
            self.initialized = True

    service = UninitializedService()
    resource = object.__new__(ReferenceSpendResource)
    resource.service = service  # type: ignore[assignment]

    with pytest.raises(ReferenceSchemaBoundaryError, match="clean installation only"):
        await resource.initialize()

    assert not service.initialized
    with psycopg.connect(reference_postgres_dsn) as connection:
        assert connection.execute("SELECT value FROM legacy_view").fetchone() == (1,)
        assert connection.execute(
            "SELECT to_regclass(current_schema() || '.masugate_release_metadata')"
        ).fetchone() == (None,)
