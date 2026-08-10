#!/usr/bin/env python3
"""Build or verify the first-party reference-container archive offline.

This helper consumes an already-verified reference release.  It is deliberately
separate from package assembly: its output is a retained verification
artifact, not a registry image and not a publication mechanism.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
_SCHEMA = "masugate.reference-container-artifact/v1"


class ContainerArtifactError(RuntimeError):
    """Raised when reference-container evidence is incomplete or inconsistent."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha256_bytes(encoded)


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _json(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContainerArtifactError(f"cannot read {label}: {path}") from exc
    if not isinstance(value, dict):
        raise ContainerArtifactError(f"{label} must contain a JSON object")
    return value


def _require_mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ContainerArtifactError(f"{label} must be an object")
    return value


def _require_string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ContainerArtifactError(f"{label} must be a nonempty string")
    return value


def _load_demo_runner() -> Any:
    path = ROOT / "scripts" / "run_reference_demos.py"
    spec = importlib.util.spec_from_file_location("masugate_reference_demos", path)
    if spec is None or spec.loader is None:
        raise ContainerArtifactError("cannot load the reference demonstration runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _declared_images(release_dir: Path) -> list[dict[str, object]]:
    manifest = _json(release_dir / "deployment" / "reference-release.json", "release manifest")
    declaration = _require_mapping(manifest.get("container_artifact"), "container artifact")
    archive = _require_string(declaration.get("archive"), "container artifact archive")
    if archive != "masugate-reference-images.tar":
        raise ContainerArtifactError("container artifact archive identity is incompatible")
    entries = declaration.get("images")
    if not isinstance(entries, list) or len(entries) != 4:
        raise ContainerArtifactError(
            "container artifact must declare exactly four first-party images"
        )
    result: list[dict[str, object]] = []
    for entry in entries:
        value = dict(_require_mapping(entry, "container image declaration"))
        role = _require_string(value.get("role"), "container image role")
        _require_string(value.get("dockerfile"), "container image Dockerfile")
        services = value.get("compose_services")
        if (
            not isinstance(services, list)
            or not services
            or not all(isinstance(service, str) and service for service in services)
        ):
            raise ContainerArtifactError(f"container image {role} has invalid compose services")
        if set(value) != {"role", "dockerfile", "compose_services"}:
            raise ContainerArtifactError(
                f"container image {role} has an unexpected declaration field"
            )
        result.append(value)
    if len({entry["role"] for entry in result}) != len(result):
        raise ContainerArtifactError("container artifact roles must be unique")
    return result


def _inventory(root: Path) -> dict[str, str]:
    if not root.is_dir():
        raise ContainerArtifactError(f"container build context is missing: {root}")
    files = [path for path in sorted(root.rglob("*")) if path.is_file()]
    if not files:
        raise ContainerArtifactError("container build context is empty")
    return {path.relative_to(root).as_posix(): _sha256(path) for path in files}


def _run(
    command: Sequence[str], *, capture: bool = False, environment: Mapping[str, str] | None = None
) -> str:
    try:
        completed = subprocess.run(
            list(command),
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            env=None if environment is None else dict(environment),
        )
    except FileNotFoundError as exc:
        raise ContainerArtifactError(f"required executable is unavailable: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        suffix = f": {detail}" if detail else ""
        raise ContainerArtifactError(
            f"container command failed: {' '.join(command)}{suffix}"
        ) from exc
    return completed.stdout.strip() if capture and completed.stdout else ""


def _docker_environment(config_dir: Path) -> dict[str, str]:
    """Use an empty Docker configuration and the default local context only."""

    config_dir.mkdir()
    path = os.environ.get("PATH")
    if not path:
        raise ContainerArtifactError("PATH is required for the local Docker executable")
    return {
        "PATH": path,
        "DOCKER_CONFIG": str(config_dir),
        "DOCKER_CONTEXT": "default",
        "DOCKER_BUILDKIT": "1",
        "NO_PROXY": "*",
        "no_proxy": "*",
    }


def _container_artifact_temporary_directory(prefix: str) -> tempfile.TemporaryDirectory[str]:
    """Create transient container state only in an explicitly selected root."""

    raw_root = os.environ.get("MASUGATE_CONTAINER_ARTIFACT_TMPDIR")
    if not raw_root:
        raise ContainerArtifactError(
            "MASUGATE_CONTAINER_ARTIFACT_TMPDIR must name an existing temporary directory"
        )
    root = Path(raw_root).resolve()
    if not root.is_dir() or not os.access(root, os.W_OK | os.X_OK):
        raise ContainerArtifactError(
            "MASUGATE_CONTAINER_ARTIFACT_TMPDIR must name an existing writable temporary directory"
        )
    return tempfile.TemporaryDirectory(prefix=prefix, dir=root)


def _tag(role: str, manifest_sha256: str) -> str:
    return f"masugate-reference-artifact/{role}:0.1.0-{manifest_sha256[:16]}"


def _image_id(docker: str, tag: str, environment: Mapping[str, str]) -> str:
    image_id = _run(
        (docker, "image", "inspect", "--format", "{{.Id}}", tag),
        capture=True,
        environment=environment,
    )
    if not image_id.startswith("sha256:") or len(image_id) != 71:
        raise ContainerArtifactError(f"container image {tag} has an invalid image ID")
    if any(character not in "0123456789abcdef" for character in image_id.removeprefix("sha256:")):
        raise ContainerArtifactError(f"container image {tag} has a non-hex image ID")
    return image_id


def _require_absent_tags(docker: str, tags: Sequence[str], environment: Mapping[str, str]) -> None:
    """Refuse to overwrite or later remove an image this invocation does not own."""

    for tag in tags:
        completed = subprocess.run(
            [docker, "image", "inspect", tag],
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=dict(environment),
            check=False,
        )
        if completed.returncode == 0:
            raise ContainerArtifactError(f"container artifact tag is already in use: {tag}")
        if completed.returncode != 1:
            raise ContainerArtifactError(
                f"cannot determine whether container artifact tag is absent: {tag}"
            )


def _saved_archive_config_ids(archive: Path) -> dict[str, str]:
    if not archive.is_file():
        raise ContainerArtifactError(f"container archive is missing: {archive}")
    try:
        with tarfile.open(archive, "r") as bundle:
            members = {member.name: member for member in bundle.getmembers() if member.isfile()}
            manifest_member = members.get("manifest.json")
            if manifest_member is None:
                raise ContainerArtifactError("container archive lacks manifest.json")
            handle = bundle.extractfile(manifest_member)
            if handle is None:
                raise ContainerArtifactError("cannot read container archive manifest")
            records = json.loads(handle.read().decode("utf-8"))
            if not isinstance(records, list) or not records:
                raise ContainerArtifactError("container archive has no images")
            by_tag: dict[str, str] = {}
            for record in records:
                mapping = _require_mapping(record, "container archive manifest record")
                tags = mapping.get("RepoTags")
                config = _require_string(mapping.get("Config"), "container archive config")
                if not isinstance(tags, list) or len(tags) != 1 or not isinstance(tags[0], str):
                    raise ContainerArtifactError(
                        "container archive record must have exactly one tag"
                    )
                if tags[0] in by_tag or config not in members:
                    raise ContainerArtifactError(
                        "container archive has duplicate tags or a missing config"
                    )
                config_handle = bundle.extractfile(members[config])
                if config_handle is None:
                    raise ContainerArtifactError("cannot read container archive config")
                config_bytes = config_handle.read()
                by_tag[tags[0]] = "sha256:" + _sha256_bytes(config_bytes)
                try:
                    config_document = json.loads(config_bytes.decode("utf-8"))
                    diff_ids = _require_mapping(config_document, "container archive config").get(
                        "rootfs"
                    )
                    diff_ids = _require_mapping(diff_ids, "container archive rootfs").get(
                        "diff_ids"
                    )
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ContainerArtifactError(
                        "container archive config is invalid JSON"
                    ) from exc
                layers = mapping.get("Layers")
                if (
                    not isinstance(layers, list)
                    or not layers
                    or not all(isinstance(layer, str) for layer in layers)
                    or not isinstance(diff_ids, list)
                    or len(diff_ids) != len(layers)
                ):
                    raise ContainerArtifactError("container archive record has invalid layers")
                for index, layer in enumerate(layers):
                    if layer not in members:
                        raise ContainerArtifactError(
                            "container archive is missing a referenced layer"
                        )
                    if layer.startswith("blobs/sha256/"):
                        expected_digest = Path(layer).name
                    elif layer.endswith("/layer.tar"):
                        declared = diff_ids[index]
                        if not isinstance(declared, str) or not declared.startswith("sha256:"):
                            raise ContainerArtifactError(
                                "container archive layer has an invalid diff ID"
                            )
                        expected_digest = declared.removeprefix("sha256:")
                    else:
                        raise ContainerArtifactError(
                            "container archive has an unrecognized layer layout"
                        )
                    if len(expected_digest) != 64 or any(
                        character not in "0123456789abcdef" for character in expected_digest
                    ):
                        raise ContainerArtifactError(
                            "container archive layer has an invalid digest path"
                        )
                    layer_handle = bundle.extractfile(members[layer])
                    if (
                        layer_handle is None
                        or _sha256_bytes(layer_handle.read()) != expected_digest
                    ):
                        raise ContainerArtifactError(
                            "container archive layer digest is inconsistent"
                        )
    except (OSError, tarfile.TarError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ContainerArtifactError(f"cannot validate container archive: {archive}") from exc
    return by_tag


def _validate_saved_archive(archive: Path, images: Mapping[str, Mapping[str, object]]) -> None:
    by_tag = _saved_archive_config_ids(archive)
    if set(by_tag) != set(images):
        raise ContainerArtifactError("container archive tags do not match the declared image set")
    for tag, actual_id in by_tag.items():
        expected = _require_string(images[tag].get("image_id"), "image ID")
        if actual_id != expected:
            raise ContainerArtifactError(
                f"container archive config does not match image ID for {tag}"
            )


def _raise_cleanup_failure(label: str, failures: Sequence[str]) -> None:
    if not failures:
        return
    cleanup_error = ContainerArtifactError(label + ": " + "; ".join(failures))
    active_error = sys.exc_info()[1]
    if active_error is not None:
        raise ExceptionGroup(
            "container operation and cleanup both failed", [active_error, cleanup_error]
        )
    raise cleanup_error


def _build(
    *,
    release_dir: Path,
    offline_npm_cache: Path,
    outdir: Path,
    expected_source_revision: str,
    expected_staging_realization_revision: str,
    docker: str,
) -> Path:
    release_dir = release_dir.resolve()
    offline_npm_cache = offline_npm_cache.resolve()
    outdir = outdir.resolve()
    if outdir.exists() and any(outdir.iterdir()):
        raise ContainerArtifactError("container artifact output directory must be new or empty")
    if not offline_npm_cache.is_dir():
        raise ContainerArtifactError("offline npm cache is missing")
    outdir.mkdir(parents=True, exist_ok=True)
    runner = _load_demo_runner()
    try:
        release_descriptor = runner._verify_release_output(
            release_dir,
            expected_source_revision=expected_source_revision,
            expected_staging_realization_revision=expected_staging_realization_revision,
        )
    except Exception as exc:
        raise ContainerArtifactError(
            f"release output is not eligible for container assembly: {exc}"
        ) from exc
    declaration = _declared_images(release_dir)
    manifest_sha256 = _require_string(
        release_descriptor.get("release_manifest_sha256"), "manifest SHA-256"
    )
    images: dict[str, dict[str, object]] = {}
    with _container_artifact_temporary_directory(
        prefix="masugate-container-artifact-context-"
    ) as temporary:
        staging_root = Path(temporary)
        try:
            context = runner._stage_artifact_context(
                release_dir, staging_root, offline_npm_cache=offline_npm_cache
            )
        except Exception as exc:
            raise ContainerArtifactError(f"cannot stage clean container context: {exc}") from exc
        context_files = _inventory(context)
        tags: list[str] = []
        docker_environment = _docker_environment(staging_root / "docker-config")
        info = _run(
            (docker, "info", "--format", "{{.OSType}}/{{.Architecture}}"),
            capture=True,
            environment=docker_environment,
        )
        if info != "linux/x86_64":
            raise ContainerArtifactError(
                "container artifact build requires the local linux/x86_64 daemon"
            )
        expected_tags = tuple(
            _tag(_require_string(declared.get("role"), "container role"), manifest_sha256)
            for declared in declaration
        )
        _require_absent_tags(docker, expected_tags, docker_environment)
        try:
            for declared in declaration:
                role = _require_string(declared.get("role"), "container role")
                dockerfile = _require_string(declared.get("dockerfile"), "container Dockerfile")
                dockerfile_path = context / "containment" / dockerfile
                if not dockerfile_path.is_file():
                    raise ContainerArtifactError(f"declared Dockerfile is missing: {dockerfile}")
                tag = _tag(role, manifest_sha256)
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
                        str(dockerfile_path),
                        "--tag",
                        tag,
                        str(context),
                    ),
                    environment=docker_environment,
                )
                tags.append(tag)
                image = {
                    **declared,
                    "tag": tag,
                    "build_manifest_id": _image_id(docker, tag, docker_environment),
                }
                images[tag] = image
            archive_name = "masugate-reference-images.tar"
            archive = outdir / archive_name
            _run((docker, "save", "--output", str(archive), *tags), environment=docker_environment)
            archive_ids = _saved_archive_config_ids(archive)
            if set(archive_ids) != set(images):
                raise ContainerArtifactError(
                    "container archive tags do not match the built image set"
                )
            for tag, image in images.items():
                image["image_id"] = archive_ids[tag]
            _validate_saved_archive(archive, images)
            _run((docker, "load", "--input", str(archive)), environment=docker_environment)
            document = {
                "schema_version": _SCHEMA,
                "release_descriptor": release_descriptor,
                "container_artifact": {
                    "archive": {
                        "filename": archive_name,
                        "sha256": _sha256(archive),
                        "bytes": archive.stat().st_size,
                    },
                    "images": [images[tag] for tag in tags],
                    "context_files": context_files,
                    "context_sha256": _canonical_digest(context_files),
                    "build_contract": {
                        "network": "none",
                        "pull": False,
                        "platform": "linux/amd64",
                        "no_cache": True,
                    },
                },
            }
            manifest = outdir / "container-artifact.json"
            _write_json(manifest, document)
            return manifest
        finally:
            cleanup_failures: list[str] = []
            for tag in reversed(tags):
                try:
                    _run((docker, "image", "rm", tag), environment=docker_environment)
                except ContainerArtifactError as exc:
                    cleanup_failures.append(f"{tag}: {exc}")
            _raise_cleanup_failure("container artifact image cleanup failed", cleanup_failures)


def _verify(
    *,
    release_dir: Path,
    artifact_dir: Path,
    expected_source_revision: str,
    expected_staging_realization_revision: str,
    docker: str,
) -> None:
    artifact_dir = artifact_dir.resolve()
    document = _json(artifact_dir / "container-artifact.json", "container artifact manifest")
    if document.get("schema_version") != _SCHEMA:
        raise ContainerArtifactError("container artifact has an incompatible schema identity")
    runner = _load_demo_runner()
    try:
        expected_release = runner._verify_release_output(
            release_dir.resolve(),
            expected_source_revision=expected_source_revision,
            expected_staging_realization_revision=expected_staging_realization_revision,
        )
    except Exception as exc:
        raise ContainerArtifactError(
            f"release output is not eligible for container verification: {exc}"
        ) from exc
    if document.get("release_descriptor") != expected_release:
        raise ContainerArtifactError(
            "container artifact is not bound to the verified release output"
        )
    artifact = _require_mapping(document.get("container_artifact"), "container artifact")
    archive = _require_mapping(artifact.get("archive"), "container archive")
    filename = _require_string(archive.get("filename"), "container archive filename")
    archive_path = artifact_dir / filename
    if filename != "masugate-reference-images.tar" or _sha256(archive_path) != archive.get(
        "sha256"
    ):
        raise ContainerArtifactError("container archive digest is inconsistent")
    if archive_path.stat().st_size != archive.get("bytes"):
        raise ContainerArtifactError("container archive size is inconsistent")
    images_raw = artifact.get("images")
    if not isinstance(images_raw, list):
        raise ContainerArtifactError("container artifact image records are invalid")
    images: dict[str, Mapping[str, object]] = {}
    for item in images_raw:
        image = _require_mapping(item, "container artifact image")
        tag = _require_string(image.get("tag"), "container artifact tag")
        if tag in images:
            raise ContainerArtifactError("container artifact has duplicate image tags")
        images[tag] = image
    declaration = _declared_images(release_dir.resolve())
    manifest_sha256 = _require_string(
        expected_release.get("release_manifest_sha256"), "manifest SHA-256"
    )
    expected_images = {
        _tag(_require_string(entry.get("role"), "container role"), manifest_sha256): entry
        for entry in declaration
    }
    if set(images) != set(expected_images):
        raise ContainerArtifactError("container artifact tags drift from the release declaration")
    for tag, declared in expected_images.items():
        actual = images[tag]
        if {
            field: actual.get(field) for field in ("role", "dockerfile", "compose_services")
        } != declared:
            raise ContainerArtifactError(
                "container artifact image declaration drifted from the release"
            )
    if artifact.get("context_sha256") != _canonical_digest(artifact.get("context_files")):
        raise ContainerArtifactError("container artifact context inventory digest is inconsistent")
    if artifact.get("build_contract") != {
        "network": "none",
        "pull": False,
        "platform": "linux/amd64",
        "no_cache": True,
    }:
        raise ContainerArtifactError("container artifact build contract is incompatible")
    _validate_saved_archive(archive_path, images)
    with _container_artifact_temporary_directory(
        prefix="masugate-container-artifact-verify-"
    ) as temporary:
        docker_environment = _docker_environment(Path(temporary) / "docker-config")
        _require_absent_tags(docker, tuple(images), docker_environment)
        cleanup_failures: list[str] = []
        try:
            _run((docker, "load", "--input", str(archive_path)), environment=docker_environment)
            for tag, image in images.items():
                if _image_id(docker, tag, docker_environment) != image.get("build_manifest_id"):
                    raise ContainerArtifactError(
                        "loaded image identity differs from the retained archive"
                    )
        finally:
            for tag in reversed(tuple(images)):
                try:
                    _run((docker, "image", "rm", tag), environment=docker_environment)
                except ContainerArtifactError as exc:
                    cleanup_failures.append(f"{tag}: {exc}")
            _raise_cleanup_failure(
                "container artifact loaded-image cleanup failed", cleanup_failures
            )


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-dir", required=True, type=Path)
    parser.add_argument("--expected-source-revision", required=True)
    parser.add_argument("--expected-staging-realization-revision", required=True)
    parser.add_argument("--offline-npm-cache", type=Path)
    parser.add_argument("--outdir", type=Path)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--docker", default="docker")
    args = parser.parse_args(argv)
    if args.verify:
        if (
            args.artifact_dir is None
            or args.outdir is not None
            or args.offline_npm_cache is not None
        ):
            parser.error(
                "--verify requires --artifact-dir and forbids --outdir and --offline-npm-cache"
            )
    elif args.outdir is None or args.offline_npm_cache is None or args.artifact_dir is not None:
        parser.error(
            "building requires --outdir and --offline-npm-cache and forbids --artifact-dir"
        )
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
            print("reference container artifact verified")
        else:
            manifest = _build(
                release_dir=args.release_dir,
                offline_npm_cache=args.offline_npm_cache,
                outdir=args.outdir,
                expected_source_revision=args.expected_source_revision,
                expected_staging_realization_revision=args.expected_staging_realization_revision,
                docker=args.docker,
            )
            print(f"reference container artifact written: {manifest}")
    except ContainerArtifactError as exc:
        raise SystemExit(f"container artifact error: {exc}") from exc


if __name__ == "__main__":
    main()
