"""Regression coverage for reference-container archive validation."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import tarfile
import types
from pathlib import Path
from typing import Any, cast

import pytest

ROOT = Path(__file__).parents[1]


def _container_builder() -> Any:
    path = ROOT / "scripts" / "build-reference-container-artifact.py"
    spec = importlib.util.spec_from_file_location("reference_container_artifact", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _add_bytes(bundle: tarfile.TarFile, name: str, value: bytes) -> None:
    entry = tarfile.TarInfo(name)
    entry.size = len(value)
    bundle.addfile(entry, io.BytesIO(value))


def test_saved_archive_rejects_missing_referenced_layer(tmp_path: Path) -> None:
    builder = _container_builder()
    config = json.dumps({"rootfs": {"diff_ids": ["sha256:" + "0" * 64]}}).encode("utf-8")
    archive = tmp_path / "images.tar"
    tag = "masugate-reference-artifact/reference:0.1.1-ffffffffffffffff"
    missing_layer = "blobs/sha256/" + "0" * 64
    manifest = [{"Config": "blobs/sha256/config", "RepoTags": [tag], "Layers": [missing_layer]}]
    with tarfile.open(archive, "w") as bundle:
        _add_bytes(bundle, "manifest.json", json.dumps(manifest).encode("utf-8"))
        _add_bytes(bundle, "blobs/sha256/config", config)
    images = {tag: {"image_id": "sha256:" + hashlib.sha256(config).hexdigest()}}
    with pytest.raises(builder.ContainerArtifactError, match="missing a referenced layer"):
        builder._validate_saved_archive(archive, images)


def test_saved_archive_accepts_legacy_layer_tar_layout(tmp_path: Path) -> None:
    builder = _container_builder()
    layer = b"legacy-layer"
    digest = hashlib.sha256(layer).hexdigest()
    config = json.dumps({"rootfs": {"diff_ids": ["sha256:" + digest]}}).encode("utf-8")
    archive = tmp_path / "images.tar"
    tag = "masugate-reference-artifact/reference:0.1.1-test"
    manifest = [{"Config": "config.json", "RepoTags": [tag], "Layers": ["legacy/layer.tar"]}]
    with tarfile.open(archive, "w") as bundle:
        _add_bytes(bundle, "manifest.json", json.dumps(manifest).encode("utf-8"))
        _add_bytes(bundle, "config.json", config)
        _add_bytes(bundle, "legacy/layer.tar", layer)
    images = {tag: {"image_id": "sha256:" + hashlib.sha256(config).hexdigest()}}
    builder._validate_saved_archive(archive, images)


def test_docker_environment_discards_redirect_and_credential_variables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = _container_builder()
    monkeypatch.setenv("DOCKER_HOST", "tcp://untrusted.example:2376")
    monkeypatch.setenv("DOCKER_CONTEXT", "untrusted")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example")
    environment = builder._docker_environment(tmp_path / "docker-config")
    assert environment["DOCKER_CONTEXT"] == "default"
    assert environment["DOCKER_CONFIG"] == str(tmp_path / "docker-config")
    assert "DOCKER_HOST" not in environment
    assert "HTTPS_PROXY" not in environment


def test_container_artifact_temporary_directory_requires_explicit_existing_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = _container_builder()
    monkeypatch.delenv("MASUGATE_CONTAINER_ARTIFACT_TMPDIR", raising=False)
    with pytest.raises(builder.ContainerArtifactError, match="must name an existing temporary"):
        builder._container_artifact_temporary_directory("container-artifact-")
    monkeypatch.setenv("MASUGATE_CONTAINER_ARTIFACT_TMPDIR", str(tmp_path / "missing"))
    with pytest.raises(builder.ContainerArtifactError, match="must name an existing writable"):
        builder._container_artifact_temporary_directory("container-artifact-")
    monkeypatch.setenv("MASUGATE_CONTAINER_ARTIFACT_TMPDIR", str(tmp_path))
    with builder._container_artifact_temporary_directory("container-artifact-") as temporary:
        assert Path(temporary).parent == tmp_path


def test_cleanup_failure_is_preserved_with_primary_failure() -> None:
    builder = _container_builder()
    with pytest.raises(ExceptionGroup) as captured:
        try:
            raise ValueError("primary failure")
        except ValueError:
            builder._raise_cleanup_failure("cleanup failed", ["tag: removal failed"])
    assert {type(error) for error in captured.value.exceptions} == {
        ValueError,
        builder.ContainerArtifactError,
    }


def test_require_absent_tags_rejects_collision(monkeypatch: pytest.MonkeyPatch) -> None:
    builder = _container_builder()
    monkeypatch.setattr(
        builder.subprocess, "run", lambda *_args, **_kwargs: types.SimpleNamespace(returncode=0)
    )
    with pytest.raises(builder.ContainerArtifactError, match="already in use"):
        builder._require_absent_tags(
            "docker", ("masugate-reference-artifact/reference:test",), {"PATH": "/bin"}
        )


def test_build_cleans_tag_when_inspection_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = _container_builder()
    monkeypatch.setenv("MASUGATE_CONTAINER_ARTIFACT_TMPDIR", str(tmp_path))
    release = tmp_path / "release"
    cache = tmp_path / "cache"
    context = tmp_path / "context"
    cache.mkdir()
    (context / "containment").mkdir(parents=True)
    (context / "containment" / "Dockerfile.reference_demo-reference").write_text(
        "FROM scratch\n", encoding="utf-8"
    )
    declaration = [
        {
            "role": "reference",
            "dockerfile": "Dockerfile.reference_demo-reference",
            "compose_services": ["masugated"],
        }
    ]
    runner = types.SimpleNamespace(
        _verify_release_output=lambda *_args, **_kwargs: {"release_manifest_sha256": "f" * 64},
        _stage_artifact_context=lambda *_args, **_kwargs: context,
    )
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(builder, "_load_demo_runner", lambda: runner)
    monkeypatch.setattr(builder, "_declared_images", lambda _release: declaration)
    monkeypatch.setattr(builder, "_inventory", lambda _context: {})
    monkeypatch.setattr(builder, "_docker_environment", lambda _path: {"PATH": "/bin"})
    monkeypatch.setattr(builder, "_require_absent_tags", lambda *_args: None)
    monkeypatch.setattr(
        builder,
        "_image_id",
        lambda *_args: (_ for _ in ()).throw(builder.ContainerArtifactError("inspect failed")),
    )

    def fake_run(command: tuple[str, ...], **_kwargs: object) -> str:
        calls.append(command)
        return "linux/x86_64" if command[1] == "info" else ""

    monkeypatch.setattr(builder, "_run", fake_run)
    with pytest.raises(builder.ContainerArtifactError, match="inspect failed"):
        builder._build(
            release_dir=release,
            offline_npm_cache=cache,
            outdir=tmp_path / "out",
            expected_source_revision="source",
            expected_staging_realization_revision="stage",
            docker="docker",
        )
    tag = builder._tag("reference", "f" * 64)
    assert ("docker", "image", "rm", tag) in calls


def test_verify_loads_archive_checks_identity_and_cleans_tags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = _container_builder()
    monkeypatch.setenv("MASUGATE_CONTAINER_ARTIFACT_TMPDIR", str(tmp_path))
    tag = "masugate-reference-artifact/reference:0.1.1-ffffffffffffffff"
    layer = b"layer"
    digest = hashlib.sha256(layer).hexdigest()
    config = json.dumps({"rootfs": {"diff_ids": ["sha256:" + digest]}}).encode("utf-8")
    archive = tmp_path / "masugate-reference-images.tar"
    manifest = [{"Config": "config.json", "RepoTags": [tag], "Layers": ["legacy/layer.tar"]}]
    with tarfile.open(archive, "w") as bundle:
        _add_bytes(bundle, "manifest.json", json.dumps(manifest).encode("utf-8"))
        _add_bytes(bundle, "config.json", config)
        _add_bytes(bundle, "legacy/layer.tar", layer)
    release = tmp_path / "release"
    (release / "deployment").mkdir(parents=True)
    declaration = {
        "container_artifact": {
            "archive": archive.name,
            "images": [
                {
                    "role": "reference",
                    "dockerfile": "Dockerfile.reference_demo-reference",
                    "compose_services": ["masugated"],
                }
            ],
        }
    }
    (release / "deployment" / "reference-release.json").write_text(
        json.dumps(declaration), encoding="utf-8"
    )
    expected_release = {"release_manifest_sha256": "f" * 64}
    image = {
        "tag": tag,
        "role": "reference",
        "dockerfile": "Dockerfile.reference_demo-reference",
        "compose_services": ["masugated"],
        "image_id": "sha256:" + hashlib.sha256(config).hexdigest(),
        "build_manifest_id": "sha256:" + "1" * 64,
    }
    document = {
        "schema_version": builder._SCHEMA,
        "release_descriptor": expected_release,
        "container_artifact": {
            "archive": {
                "filename": archive.name,
                "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "bytes": archive.stat().st_size,
            },
            "images": [image],
            "context_files": {},
            "context_sha256": hashlib.sha256(b"{}").hexdigest(),
            "build_contract": {
                "network": "none",
                "pull": False,
                "platform": "linux/amd64",
                "no_cache": True,
            },
        },
    }
    (tmp_path / "container-artifact.json").write_text(json.dumps(document), encoding="utf-8")
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        builder,
        "_load_demo_runner",
        lambda: types.SimpleNamespace(
            _verify_release_output=lambda *_args, **_kwargs: expected_release
        ),
    )
    monkeypatch.setattr(
        builder, "_declared_images", lambda _release: declaration["container_artifact"]["images"]
    )
    monkeypatch.setattr(builder, "_docker_environment", lambda _path: {"PATH": "/bin"})
    monkeypatch.setattr(builder, "_require_absent_tags", lambda *_args: None)

    def fake_run(command: tuple[str, ...], **_kwargs: object) -> str:
        calls.append(command)
        return cast(str, image["build_manifest_id"]) if command[1:3] == ("image", "inspect") else ""

    monkeypatch.setattr(builder, "_run", fake_run)
    builder._verify(
        release_dir=release,
        artifact_dir=tmp_path,
        expected_source_revision="source",
        expected_staging_realization_revision="stage",
        docker="docker",
    )
    assert ("docker", "load", "--input", str(archive)) in calls
    assert ("docker", "image", "rm", tag) in calls
    altered = json.loads(json.dumps(document))
    altered["container_artifact"]["images"][0]["tag"] = tag + "-altered"
    (tmp_path / "container-artifact.json").write_text(json.dumps(altered), encoding="utf-8")
    with pytest.raises(builder.ContainerArtifactError, match="tags drift"):
        builder._verify(
            release_dir=release,
            artifact_dir=tmp_path,
            expected_source_revision="source",
            expected_staging_realization_revision="stage",
            docker="docker",
        )
    altered = json.loads(json.dumps(document))
    altered["container_artifact"]["images"][0]["dockerfile"] = "Dockerfile.unreviewed"
    (tmp_path / "container-artifact.json").write_text(json.dumps(altered), encoding="utf-8")
    with pytest.raises(builder.ContainerArtifactError, match="image declaration drifted"):
        builder._verify(
            release_dir=release,
            artifact_dir=tmp_path,
            expected_source_revision="source",
            expected_staging_realization_revision="stage",
            docker="docker",
        )
    (tmp_path / "container-artifact.json").write_text(json.dumps(document), encoding="utf-8")
    calls.clear()
    monkeypatch.setattr(
        builder,
        "_require_absent_tags",
        lambda *_args: (_ for _ in ()).throw(builder.ContainerArtifactError("tag collision")),
    )
    with pytest.raises(builder.ContainerArtifactError, match="tag collision"):
        builder._verify(
            release_dir=release,
            artifact_dir=tmp_path,
            expected_source_revision="source",
            expected_staging_realization_revision="stage",
            docker="docker",
        )
    assert not any(command[1:3] == ("image", "rm") for command in calls)
    calls.clear()
    monkeypatch.setattr(builder, "_require_absent_tags", lambda *_args: None)

    def mismatched_image_id(command: tuple[str, ...], **_kwargs: object) -> str:
        if command[1:3] == ("image", "inspect"):
            return "sha256:" + "2" * 64
        calls.append(command)
        return ""

    monkeypatch.setattr(builder, "_run", mismatched_image_id)
    with pytest.raises(builder.ContainerArtifactError, match="loaded image identity differs"):
        builder._verify(
            release_dir=release,
            artifact_dir=tmp_path,
            expected_source_revision="source",
            expected_staging_realization_revision="stage",
            docker="docker",
        )
    assert ("docker", "image", "rm", tag) in calls
    calls.clear()

    def failing_load(command: tuple[str, ...], **_kwargs: object) -> str:
        if command[1] == "load":
            raise builder.ContainerArtifactError("partial load failed")
        calls.append(command)
        return ""

    monkeypatch.setattr(builder, "_run", failing_load)
    with pytest.raises(builder.ContainerArtifactError, match="partial load failed"):
        builder._verify(
            release_dir=release,
            artifact_dir=tmp_path,
            expected_source_revision="source",
            expected_staging_realization_revision="stage",
            docker="docker",
        )
    assert ("docker", "image", "rm", tag) in calls
