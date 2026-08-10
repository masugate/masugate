#!/usr/bin/env python3
"""Build and verify the local, clean-artifact connector-worker image.

This helper is deliberately a local evidence mechanism.  It never pulls,
pushes, or tags an external registry image.  Its Docker build context is made
only from a verified release's locked wheels plus the reviewed worker controls
in this tree.  Verification reloads the saved archive into an empty Docker
configuration and runs a one-pass closed bootstrap as the non-root worker.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
_SCHEMA = "masugate.connector-worker-artifact/v1"
_BASE_IMAGE = (
    "python:3.12.11-slim-bookworm@sha256:"
    "519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7"
)
_CONTROL_FILES = (
    "connectors/worker/Dockerfile.release",
    "connectors/worker/bootstrap.example.json",
    "connectors/worker/compose.fragment.yaml",
    "connectors/worker/containment-profile.json",
    "connectors/worker/entrypoint.sh",
)


class ConnectorWorkerArtifactError(RuntimeError):
    """Raised when the local worker artifact is incomplete or untrustworthy."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _json(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConnectorWorkerArtifactError(f"cannot read {label}: {path}") from exc
    if not isinstance(value, dict):
        raise ConnectorWorkerArtifactError(f"{label} must contain a JSON object")
    return value


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ConnectorWorkerArtifactError(f"{label} must be an object")
    return value


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConnectorWorkerArtifactError(f"{label} must be a nonempty string")
    return value


def _run(
    command: Sequence[str], *, capture: bool = False, environment: Mapping[str, str] | None = None
) -> str:
    try:
        result = subprocess.run(
            list(command),
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            env=None if environment is None else dict(environment),
        )
    except FileNotFoundError as exc:
        raise ConnectorWorkerArtifactError(
            f"required executable is unavailable: {command[0]}"
        ) from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        suffix = f": {detail}" if detail else ""
        raise ConnectorWorkerArtifactError(
            f"container command failed: {' '.join(command)}{suffix}"
        ) from exc
    return result.stdout.strip() if capture and result.stdout else ""


def _docker_environment(config_dir: Path) -> dict[str, str]:
    path = os.environ.get("PATH")
    if not path:
        raise ConnectorWorkerArtifactError("PATH is required for the local Docker executable")
    config_dir.mkdir()
    return {
        "DOCKER_BUILDKIT": "1",
        "DOCKER_CONFIG": str(config_dir),
        "DOCKER_CONTEXT": "default",
        "NO_PROXY": "*",
        "PATH": path,
        "no_proxy": "*",
    }


def _temporary_directory(prefix: str) -> tempfile.TemporaryDirectory[str]:
    raw_root = os.environ.get("MASUGATE_CONTAINER_ARTIFACT_TMPDIR")
    if not raw_root:
        raise ConnectorWorkerArtifactError(
            "MASUGATE_CONTAINER_ARTIFACT_TMPDIR must name an existing temporary directory"
        )
    root = Path(raw_root).resolve()
    if not root.is_dir() or not os.access(root, os.W_OK | os.X_OK):
        raise ConnectorWorkerArtifactError(
            "MASUGATE_CONTAINER_ARTIFACT_TMPDIR must name an existing writable temporary directory"
        )
    return tempfile.TemporaryDirectory(prefix=prefix, dir=root)


def _load_demo_runner() -> Any:
    path = ROOT / "scripts" / "run_reference_demos.py"
    spec = importlib.util.spec_from_file_location("masugate_reference_demos", path)
    if spec is None or spec.loader is None:
        raise ConnectorWorkerArtifactError("cannot load the reference demonstration runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _verified_release(
    release_dir: Path, *, expected_source_revision: str, expected_staging_realization_revision: str
) -> dict[str, object]:
    runner = _load_demo_runner()
    try:
        descriptor = runner._verify_release_output(
            release_dir.resolve(),
            expected_source_revision=expected_source_revision,
            expected_staging_realization_revision=expected_staging_realization_revision,
        )
    except Exception as exc:
        raise ConnectorWorkerArtifactError(
            f"release output is not eligible for worker assembly: {exc}"
        ) from exc
    if not isinstance(descriptor, dict):
        raise ConnectorWorkerArtifactError("release verification returned an invalid descriptor")
    return descriptor


def _single_wheel(directory: Path, label: str) -> Path:
    values = tuple(sorted(directory.glob("*.whl")))
    if len(values) != 1:
        raise ConnectorWorkerArtifactError(
            f"release must contain exactly one {label} wheel, found {values!r}"
        )
    return values[0]


def _stage_context(release_dir: Path, staging_root: Path) -> Path:
    context = staging_root / "context"
    artifacts = context / "artifacts" / "python"
    for name in (
        "masugate",
        "masugate-connector-sdk",
        "masugate-connector-filesystem",
        "runtime",
    ):
        source = release_dir / "python" / name
        if not source.is_dir():
            raise ConnectorWorkerArtifactError(
                f"verified release lacks Python artifact directory: {name}"
            )
        shutil.copytree(source, artifacts / name)
    _single_wheel(artifacts / "masugate", "masugate")
    _single_wheel(artifacts / "masugate-connector-sdk", "masugate-connector-sdk")
    if (
        not (artifacts / "runtime" / "requirements.txt").is_file()
        or not (artifacts / "runtime" / "wheelhouse").is_dir()
    ):
        raise ConnectorWorkerArtifactError("verified release lacks the locked runtime wheelhouse")
    shutil.copy2(
        ROOT / "connectors" / "worker" / "Dockerfile.release", context / "Dockerfile.release"
    )
    shutil.copy2(ROOT / "connectors" / "worker" / "entrypoint.sh", context / "worker-entrypoint.sh")
    shutil.copy2(
        ROOT / "connectors" / "worker" / "bootstrap.example.json",
        context / "bootstrap.example.json",
    )
    return context


def _installed_connector_probe(
    docker: str, tag: str, environment: Mapping[str, str]
) -> dict[str, str]:
    """Load the shipped filesystem connector through its installed entry point.

    The filesystem connector intentionally refuses to execute on an arbitrary
    Docker bind mount: its runtime verifier requires a deployment-provisioned
    ext4 mount rooted at ``/``. This artifact check therefore proves the
    package/distribution/entry-point closure without claiming a filesystem
    effect from an unsuitable containment mount.
    """

    probe = """
import json
from importlib import metadata

matches = tuple(
    entry
    for entry in metadata.entry_points(group="masugate.connector", name="filesystem")
    if entry.dist is not None
    and entry.dist.metadata.get("Name") == "masugate-connector-filesystem"
    and entry.dist.version == "0.1.0"
)
if len(matches) != 1:
    raise SystemExit("expected one filesystem connector entry point")
connector = matches[0].load()
if connector.connector_id != "filesystem-v1":
    raise SystemExit("filesystem connector identity drifted")
print(json.dumps({
    "connector_id": connector.connector_id,
    "entry_point": matches[0].name,
    "package_id": matches[0].dist.metadata["Name"],
    "package_version": matches[0].dist.version,
}, sort_keys=True))
"""
    output = _run(
        (
            docker,
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--user=10001:10001",
            "--env",
            "PYTHONDONTWRITEBYTECODE=1",
            "--entrypoint",
            "/usr/local/bin/python",
            tag,
            "-c",
            probe,
        ),
        capture=True,
        environment=environment,
    )
    try:
        result = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ConnectorWorkerArtifactError("installed connector probe output is not JSON") from exc
    expected = {
        "connector_id": "filesystem-v1",
        "entry_point": "filesystem",
        "package_id": "masugate-connector-filesystem",
        "package_version": "0.1.0",
    }
    if result != expected:
        raise ConnectorWorkerArtifactError("installed connector probe has an unexpected result")
    return expected


def _inventory(root: Path) -> dict[str, str]:
    files = [path for path in sorted(root.rglob("*")) if path.is_file()]
    if not files:
        raise ConnectorWorkerArtifactError("worker image build context is empty")
    return {path.relative_to(root).as_posix(): _sha256(path) for path in files}


def _controls() -> dict[str, str]:
    result: dict[str, str] = {}
    for relative in _CONTROL_FILES:
        path = ROOT / relative
        if not path.is_file():
            raise ConnectorWorkerArtifactError(f"reviewed worker control is missing: {relative}")
        result[relative] = _sha256(path)
    return result


def _tag(release_descriptor: Mapping[str, object]) -> str:
    manifest_sha256 = _string(release_descriptor.get("release_manifest_sha256"), "manifest SHA-256")
    if len(manifest_sha256) != 64 or any(
        char not in "0123456789abcdef" for char in manifest_sha256
    ):
        raise ConnectorWorkerArtifactError("release manifest SHA-256 is malformed")
    return f"masugate-connector-worker:0.1.0-{manifest_sha256[:16]}"


def _image_id(docker: str, tag: str, environment: Mapping[str, str]) -> str:
    image_id = _run(
        (docker, "image", "inspect", "--format", "{{.Id}}", tag),
        capture=True,
        environment=environment,
    )
    if not image_id.startswith("sha256:") or len(image_id) != 71:
        raise ConnectorWorkerArtifactError(f"container image {tag} has an invalid image ID")
    if any(char not in "0123456789abcdef" for char in image_id.removeprefix("sha256:")):
        raise ConnectorWorkerArtifactError(f"container image {tag} has a non-hex image ID")
    return image_id


def _require_absent_tag(docker: str, tag: str, environment: Mapping[str, str]) -> None:
    result = subprocess.run(
        [docker, "image", "inspect", tag],
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=dict(environment),
        check=False,
    )
    if result.returncode == 0:
        raise ConnectorWorkerArtifactError(f"worker artifact tag is already in use: {tag}")
    if result.returncode != 1:
        raise ConnectorWorkerArtifactError(
            f"cannot determine whether worker artifact tag is absent: {tag}"
        )


def _archive_image_id(archive: Path, tag: str) -> str:
    try:
        with tarfile.open(archive, "r") as bundle:
            members = {member.name: member for member in bundle.getmembers() if member.isfile()}
            manifest_member = members.get("manifest.json")
            if manifest_member is None:
                raise ConnectorWorkerArtifactError("worker image archive lacks manifest.json")
            handle = bundle.extractfile(manifest_member)
            if handle is None:
                raise ConnectorWorkerArtifactError("worker image archive manifest is unreadable")
            records = json.loads(handle.read().decode("utf-8"))
            if (
                not isinstance(records, list)
                or len(records) != 1
                or not isinstance(records[0], dict)
            ):
                raise ConnectorWorkerArtifactError(
                    "worker image archive must contain exactly one image"
                )
            record = records[0]
            if record.get("RepoTags") != [tag]:
                raise ConnectorWorkerArtifactError("worker image archive tag is inconsistent")
            config = _string(record.get("Config"), "worker image archive config")
            config_member = members.get(config)
            if config_member is None:
                raise ConnectorWorkerArtifactError("worker image archive config is missing")
            config_handle = bundle.extractfile(config_member)
            if config_handle is None:
                raise ConnectorWorkerArtifactError("worker image archive config is unreadable")
            return "sha256:" + hashlib.sha256(config_handle.read()).hexdigest()
    except (OSError, tarfile.TarError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectorWorkerArtifactError(
            f"cannot inspect worker image archive: {archive}"
        ) from exc


def _run_lifecycle(
    docker: str, tag: str, environment: Mapping[str, str], temporary_root: Path
) -> dict[str, object]:
    temporary_root.mkdir(mode=0o755)
    bootstrap = temporary_root / "bootstrap"
    secrets = temporary_root / "secrets"
    bootstrap.mkdir(mode=0o755)
    secrets.mkdir(mode=0o755)
    shutil.copy2(
        ROOT / "connectors" / "worker" / "bootstrap.example.json", bootstrap / "bootstrap.json"
    )
    os.chmod(bootstrap / "bootstrap.json", 0o644)
    output = _run(
        (
            docker,
            "run",
            "--rm",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--user=10001:10001",
            "--mount",
            f"type=bind,source={bootstrap},destination=/run/masugate-worker,readonly",
            "--mount",
            f"type=bind,source={secrets},destination=/run/masugate-secrets,readonly",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=16m",
            "--tmpfs",
            "/var/lib/masugate-connector-worker:rw,noexec,nosuid,nodev,size=16m",
            tag,
            "--serve-committed-handoffs",
            "--bootstrap",
            "/run/masugate-worker/bootstrap.json",
            "--once",
        ),
        capture=True,
        environment=environment,
    )
    try:
        report = json.loads(output)
    except json.JSONDecodeError as exc:
        raise ConnectorWorkerArtifactError("worker one-pass lifecycle output is not JSON") from exc
    if report != {"recovered": 0, "scanned": 0}:
        raise ConnectorWorkerArtifactError("worker one-pass lifecycle has an unexpected result")
    compose = _run(
        (
            docker,
            "compose",
            "--project-name",
            "masugate-worker-artifact-check",
            "--file",
            str(ROOT / "connectors" / "worker" / "compose.fragment.yaml"),
            "config",
        ),
        capture=True,
        environment={**environment, "MASUGATE_CONNECTOR_WORKER_IMAGE": tag},
    )
    for required in (tag, "read_only: true", "no-new-privileges:true", "internal: true"):
        if required not in compose:
            raise ConnectorWorkerArtifactError(
                f"worker Compose rendering omits required containment fact: {required}"
            )
    return {
        "one_pass": report,
        "compose_config_sha256": hashlib.sha256(compose.encode()).hexdigest(),
    }


def _cleanup_image(docker: str, tag: str, environment: Mapping[str, str]) -> None:
    _run((docker, "image", "rm", tag), environment=environment)


def _build(
    *,
    release_dir: Path,
    outdir: Path,
    expected_source_revision: str,
    expected_staging_realization_revision: str,
    docker: str,
) -> Path:
    outdir = outdir.resolve()
    if outdir.exists() and any(outdir.iterdir()):
        raise ConnectorWorkerArtifactError("worker artifact output directory must be new or empty")
    outdir.mkdir(parents=True, exist_ok=True)
    release_descriptor = _verified_release(
        release_dir,
        expected_source_revision=expected_source_revision,
        expected_staging_realization_revision=expected_staging_realization_revision,
    )
    tag = _tag(release_descriptor)
    with _temporary_directory("masugate-worker-artifact-") as temporary:
        temporary_root = Path(temporary)
        context = _stage_context(release_dir.resolve(), temporary_root)
        context_files = _inventory(context)
        environment = _docker_environment(temporary_root / "docker-config")
        if (
            _run(
                (docker, "info", "--format", "{{.OSType}}/{{.Architecture}}"),
                capture=True,
                environment=environment,
            )
            != "linux/x86_64"
        ):
            raise ConnectorWorkerArtifactError(
                "worker artifact build requires a local linux/x86_64 daemon"
            )
        _run((docker, "image", "inspect", _BASE_IMAGE), environment=environment)
        _require_absent_tag(docker, tag, environment)
        built = False
        try:
            _run(
                (
                    docker,
                    "build",
                    "--pull=false",
                    "--network=none",
                    "--platform=linux/amd64",
                    "--no-cache",
                    "--quiet",
                    "--file",
                    str(context / "Dockerfile.release"),
                    "--tag",
                    tag,
                    str(context),
                ),
                environment=environment,
            )
            built = True
            build_manifest_id = _image_id(docker, tag, environment)
            installed_connector = _installed_connector_probe(docker, tag, environment)
            archive = outdir / "masugate-connector-worker-image.tar"
            _run((docker, "save", "--output", str(archive), tag), environment=environment)
            archive_image_id = _archive_image_id(archive, tag)
            lifecycle = _run_lifecycle(docker, tag, environment, temporary_root / "lifecycle")
            document = {
                "schema_version": _SCHEMA,
                "release_descriptor": release_descriptor,
                "worker_artifact": {
                    "archive": {
                        "bytes": archive.stat().st_size,
                        "filename": archive.name,
                        "sha256": _sha256(archive),
                    },
                    "base_image": _BASE_IMAGE,
                    "build_contract": {
                        "network": "none",
                        "no_cache": True,
                        "platform": "linux/amd64",
                        "pull": False,
                    },
                    "context_files": context_files,
                    "context_sha256": _canonical_digest(context_files),
                    "controls": _controls(),
                    "archive_image_id": archive_image_id,
                    "build_manifest_id": build_manifest_id,
                    "installed_connector": installed_connector,
                    "lifecycle": lifecycle,
                    "tag": tag,
                },
            }
            manifest = outdir / "connector-worker-artifact.json"
            _write_json(manifest, document)
            return manifest
        finally:
            if built:
                _cleanup_image(docker, tag, environment)


def _verify(
    *,
    release_dir: Path,
    artifact_dir: Path,
    expected_source_revision: str,
    expected_staging_realization_revision: str,
    docker: str,
) -> None:
    document = _json(artifact_dir / "connector-worker-artifact.json", "worker artifact manifest")
    if document.get("schema_version") != _SCHEMA:
        raise ConnectorWorkerArtifactError("worker artifact has an incompatible schema identity")
    expected_release = _verified_release(
        release_dir,
        expected_source_revision=expected_source_revision,
        expected_staging_realization_revision=expected_staging_realization_revision,
    )
    if document.get("release_descriptor") != expected_release:
        raise ConnectorWorkerArtifactError(
            "worker artifact is not bound to the verified release output"
        )
    artifact = _mapping(document.get("worker_artifact"), "worker artifact")
    if artifact.get("controls") != _controls():
        raise ConnectorWorkerArtifactError("worker artifact controls drift from this reviewed tree")
    if artifact.get("build_contract") != {
        "network": "none",
        "no_cache": True,
        "platform": "linux/amd64",
        "pull": False,
    }:
        raise ConnectorWorkerArtifactError("worker artifact build contract is incompatible")
    if artifact.get("context_sha256") != _canonical_digest(artifact.get("context_files")):
        raise ConnectorWorkerArtifactError(
            "worker artifact context inventory digest is inconsistent"
        )
    if artifact.get("base_image") != _BASE_IMAGE:
        raise ConnectorWorkerArtifactError("worker artifact base image is inconsistent")
    expected_connector = {
        "connector_id": "filesystem-v1",
        "entry_point": "filesystem",
        "package_id": "masugate-connector-filesystem",
        "package_version": "0.1.0",
    }
    if artifact.get("installed_connector") != expected_connector:
        raise ConnectorWorkerArtifactError(
            "worker artifact installed connector identity is inconsistent"
        )
    archive = _mapping(artifact.get("archive"), "worker artifact archive")
    filename = _string(archive.get("filename"), "worker archive filename")
    archive_path = artifact_dir / filename
    if filename != "masugate-connector-worker-image.tar" or not archive_path.is_file():
        raise ConnectorWorkerArtifactError("worker artifact archive is missing")
    if _sha256(archive_path) != archive.get("sha256") or archive_path.stat().st_size != archive.get(
        "bytes"
    ):
        raise ConnectorWorkerArtifactError("worker artifact archive digest or size is inconsistent")
    tag = _string(artifact.get("tag"), "worker artifact tag")
    archive_image_id = _string(artifact.get("archive_image_id"), "worker archive image ID")
    build_manifest_id = _string(artifact.get("build_manifest_id"), "worker build manifest ID")
    if _archive_image_id(archive_path, tag) != archive_image_id:
        raise ConnectorWorkerArtifactError("worker archive identity differs from its manifest")
    with _temporary_directory("masugate-worker-artifact-verify-") as temporary:
        temporary_root = Path(temporary)
        environment = _docker_environment(temporary_root / "docker-config")
        _require_absent_tag(docker, tag, environment)
        loaded = False
        try:
            _run((docker, "load", "--input", str(archive_path)), environment=environment)
            loaded = True
            if _image_id(docker, tag, environment) != build_manifest_id:
                raise ConnectorWorkerArtifactError(
                    "loaded worker image identity differs from the archive"
                )
            if _installed_connector_probe(docker, tag, environment) != expected_connector:
                raise ConnectorWorkerArtifactError(
                    "reloaded worker installed connector differs from the artifact"
                )
            lifecycle = _run_lifecycle(docker, tag, environment, temporary_root / "lifecycle")
            if lifecycle != artifact.get("lifecycle"):
                raise ConnectorWorkerArtifactError(
                    "reloaded worker lifecycle evidence differs from the artifact"
                )
        finally:
            if loaded:
                _cleanup_image(docker, tag, environment)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("--expected-source-revision", required=True)
    parser.add_argument("--expected-staging-realization-revision", required=True)
    parser.add_argument("--outdir", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--docker", default="docker")
    args = parser.parse_args(argv)
    if args.verify:
        if args.artifact_dir is None or args.outdir is not None:
            parser.error("--verify requires --artifact-dir and forbids --outdir")
    elif args.outdir is None or args.artifact_dir is not None:
        parser.error("building requires --outdir and forbids --artifact-dir")
    return args


def main(argv: Sequence[str] | None = None) -> None:
    args = _parse_args(argv)
    try:
        if args.verify:
            _verify(
                release_dir=args.release_dir,
                artifact_dir=args.artifact_dir,
                expected_source_revision=args.expected_source_revision,
                expected_staging_realization_revision=args.expected_staging_realization_revision,
                docker=args.docker,
            )
            print("connector-worker artifact verified")
        else:
            manifest = _build(
                release_dir=args.release_dir,
                outdir=args.outdir,
                expected_source_revision=args.expected_source_revision,
                expected_staging_realization_revision=args.expected_staging_realization_revision,
                docker=args.docker,
            )
            print(f"connector-worker artifact written: {manifest}")
    except ConnectorWorkerArtifactError as exc:
        raise SystemExit(f"connector-worker artifact error: {exc}") from exc


if __name__ == "__main__":
    main()
