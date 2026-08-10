#!/usr/bin/env python3
"""Run the clean-artifact release verification governed-reference release gate.

The gate deliberately composes earlier release gates instead of reimplementing
their trusted deployment machinery.  It verifies the standalone containment
oracle, builds one attested reference release, starts a disposable reference demonstration
stack from that release, then records E4/E6, T4, T6, and the explicit T7
deferral in one validated evidence document.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
_SOURCE_ROOTS = (
    ROOT / "src",
    ROOT / "clients" / "python" / "src",
    ROOT / "connectors" / "sdk" / "src",
)
for source_root in reversed(_SOURCE_ROOTS):
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))
CONTAINMENT_ORACLE = ROOT / "scripts" / "run-reference-containment-live.py"
RELEASE_BUILDER = ROOT / "scripts" / "build-reference-release.py"
REFERENCE_DEMO_RUNNER = ROOT / "scripts" / "run_reference_demos.py"
DOCKER = os.environ.get("MASUGATE_DOCKER_BIN", "docker")
_DOCKER_TEMP_ROOT = Path("/tmp")
_SCHEMA = "masugate.release_verification-reference-release-evidence/v1"
_REFERENCE_CONFIGURATION_FILES = (
    "fleet-roster.example.json",
    "plugin-config.example.json",
    "plugin-config.native-approval.example.json",
)
_CONTAINMENT_CONFIGURATION_FILES = (
    "profile.json",
    "openclaw-sandbox.json",
    "compose.yaml",
    "compose.reference_demo.yaml",
)
_ALPINE_CLOSURE_FILE_SHA256 = "a4a6db52498e118a65b2742dee970a46ea890ea6f7e09cd16e43b1b4828cabc8"
_ALPINE_CLOSURE_CONTENT_SHA256 = "0541ed40a13407b5f104825a6c46aaf63fa9cdd1d23f63c3a92afd2b94fbb9e6"
_ALPINE_PYTHON_PYC_NAME = "python3-pycache-pyc0-3.12.13-r0.apk"
_ALPINE_PYTHON_PYC_SHA256 = "c8a27535906740a9b21b844b86c958c4c0e38eee6eaa93a8091ed1ec0b66955c"


class ReleaseGateError(RuntimeError):
    """The bounded release verification release gate has not established its evidence."""


def _reference_demo() -> Any:
    spec = importlib.util.spec_from_file_location(
        "reference_demo_release_runner", REFERENCE_DEMO_RUNNER
    )
    if spec is None or spec.loader is None:
        raise ReleaseGateError("cannot load the reference demonstration release runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _release_verification() -> Any:
    from masugate_openclaw_reference import release_verification_release

    return release_verification_release


def _json_output(raw: str, label: str) -> dict[str, object]:
    try:
        value: object = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ReleaseGateError(f"{label} did not emit JSON: {raw}") from exc
    if not isinstance(value, dict):
        raise ReleaseGateError(f"{label} did not emit a JSON object")
    return cast(dict[str, object], value)


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ReleaseGateError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReleaseGateError(f"{label} must be a non-empty string")
    return value


def _source_text_lines(text: str, suffix: str) -> int:
    """Count visible non-blank, non-comment lines with a reproducible rule."""

    comment = "//" if suffix.lower() in {".ts", ".mjs", ".js"} else "#"
    return sum(
        1 for line in text.splitlines() if line.strip() and not line.lstrip().startswith(comment)
    )


def _source_lines(path: Path) -> int:
    if not path.is_file():
        raise ReleaseGateError(f"integration-footprint input is missing: {path}")
    return _source_text_lines(path.read_text(encoding="utf-8"), path.suffix)


def _archive_member_text(archive: tarfile.TarFile, name: str) -> str:
    member = archive.getmember(name)
    if not member.isfile():
        raise ReleaseGateError(f"adapter artifact member is not a regular file: {name}")
    handle = archive.extractfile(member)
    if handle is None:
        raise ReleaseGateError(f"adapter artifact member cannot be read: {name}")
    return handle.read().decode("utf-8")


def _adapter_artifact(artifact_context: Path) -> tuple[dict[str, object], list[tuple[str, str]]]:
    tarballs = tuple(
        sorted((artifact_context / "artifacts" / "npm").glob("masugate-openclaw-*.tgz"))
    )
    if len(tarballs) != 1:
        raise ReleaseGateError(
            "clean artifact context must contain exactly one packed OpenClaw adapter"
        )
    tarball = tarballs[0]
    with tarfile.open(tarball, "r:gz") as archive:
        members = tuple(archive.getmembers())
        if any(member.issym() or member.islnk() for member in members):
            raise ReleaseGateError("packed OpenClaw adapter must not contain links")
        names = {member.name for member in members}
        if "package/package.json" not in names:
            raise ReleaseGateError("packed OpenClaw adapter has no package manifest")
        for name in names:
            parts = name.rstrip("/").split("/")
            if any(
                parts[index : index + 2] == ["node_modules", "openclaw"]
                for index in range(len(parts) - 1)
            ) or parts[:2] == ["package", "openclaw"]:
                raise ReleaseGateError("packed OpenClaw adapter contains a copied OpenClaw runtime")
        source_names = tuple(
            sorted(
                name
                for name in names
                if name.startswith("package/dist/src/") and name.endswith(".js")
            )
        )
        if not source_names:
            raise ReleaseGateError("packed OpenClaw adapter has no executable integration files")
        package = _json_output(
            _archive_member_text(archive, "package/package.json"), "adapter package"
        )
        files = [
            (f"artifacts/npm/{tarball.name}!{name}", _archive_member_text(archive, name))
            for name in source_names
        ]
    return package, files


def _integration_footprint(artifact_context: Path) -> dict[str, object]:
    """Measure the shipped adapter/configuration footprint and pin consistency."""

    adapter_package, source_files = _adapter_artifact(artifact_context)
    contract_package = _json_output(
        (artifact_context / "containment" / "openclaw-contract" / "package.json").read_text(
            encoding="utf-8"
        ),
        "OpenClaw contract package manifest",
    )
    for package, label in ((adapter_package, "adapter"), (contract_package, "contract")):
        peers = package.get("peerDependencies")
        development = package.get("devDependencies")
        if not isinstance(peers, dict) or not isinstance(development, dict):
            raise ReleaseGateError(f"{label} package has incomplete OpenClaw pins")
    adapter_openclaw = _mapping(adapter_package.get("openclaw"), "adapter OpenClaw metadata")
    adapter_compat = _mapping(adapter_openclaw.get("compat"), "adapter compatibility metadata")
    contract_openclaw = _mapping(contract_package.get("openclaw"), "contract OpenClaw metadata")
    contract_compat = _mapping(contract_openclaw.get("compat"), "contract compatibility metadata")
    pins = (
        _string(
            _mapping(adapter_package.get("peerDependencies"), "adapter peers").get("openclaw"),
            "adapter peer pin",
        ),
        _string(
            _mapping(adapter_package.get("devDependencies"), "adapter development").get("openclaw"),
            "adapter development pin",
        ),
        _string(adapter_compat.get("pluginApi"), "adapter plugin API pin"),
        _string(adapter_compat.get("minGatewayVersion"), "adapter minimum Gateway pin"),
        _string(
            _mapping(contract_package.get("peerDependencies"), "contract peers").get("openclaw"),
            "contract peer pin",
        ),
        _string(
            _mapping(contract_package.get("devDependencies"), "contract development").get(
                "openclaw"
            ),
            "contract development pin",
        ),
        _string(contract_compat.get("pluginApi"), "contract plugin API pin"),
        _string(contract_compat.get("minGatewayVersion"), "contract minimum Gateway pin"),
    )
    if len(set(pins)) != 1:
        raise ReleaseGateError(
            "packed adapter and contract diverge on the OpenClaw compatibility pin"
        )
    pin = pins[0]
    configuration_files = [
        *(artifact_context / "reference-config" / name for name in _REFERENCE_CONFIGURATION_FILES),
        *(artifact_context / "containment" / name for name in _CONTAINMENT_CONFIGURATION_FILES),
    ]
    return {
        "artifact_context": "clean release artifact context",
        "compatibility_pin": pin,
        "configuration_files": [
            path.relative_to(artifact_context).as_posix() for path in configuration_files
        ],
        "configuration_loc": sum(_source_lines(path) for path in configuration_files),
        "integration_files": [name for name, _ in source_files],
        "integration_loc": sum(_source_text_lines(text, ".js") for _, text in source_files),
        "no_fork": True,
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _copy_alpine_closure(closure: Path, destination: Path) -> None:
    """Materialize the preapproved signed Alpine closure into one test context."""

    root = closure.resolve()
    manifest_path = root / "MANIFEST.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ReleaseGateError("offline Alpine closure is missing a regular manifest")
    if _sha256(manifest_path) != _ALPINE_CLOSURE_FILE_SHA256:
        raise ReleaseGateError("offline Alpine manifest file does not match the approved input")
    manifest = _json_output(manifest_path.read_text(encoding="utf-8"), "offline Alpine manifest")
    if manifest.get("closure_manifest_sha256") != _ALPINE_CLOSURE_CONTENT_SHA256:
        raise ReleaseGateError("offline Alpine closure identity does not match the approved input")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != 35:
        raise ReleaseGateError("offline Alpine closure has the wrong artifact inventory")
    seen: set[str] = set()
    for index, raw_artifact in enumerate(artifacts):
        artifact = _mapping(raw_artifact, f"offline Alpine artifact {index}")
        kind = _string(artifact.get("kind"), f"offline Alpine artifact {index}.kind")
        raw_path = _string(artifact.get("path"), f"offline Alpine artifact {index}.path")
        digest = _string(artifact.get("sha256"), f"offline Alpine artifact {index}.sha256")
        relative = raw_path.replace("\\", "/")
        parts = tuple(part for part in relative.split("/") if part)
        if not parts or any(part in {".", ".."} for part in parts):
            raise ReleaseGateError("offline Alpine closure contains an unsafe artifact path")
        source = root.joinpath(*parts)
        if not source.is_file() or source.is_symlink() or _sha256(source) != digest:
            raise ReleaseGateError(
                "offline Alpine closure artifact hash does not match its manifest"
            )
        if kind == "public_key" and len(parts) == 2 and parts[0] == "trust":
            target = destination / "keys" / parts[-1]
        elif kind == "signed_index" and len(parts) == 3 and parts[0] == "indexes":
            repository = _string(artifact.get("repository"), "offline Alpine index repository")
            if repository != parts[1] or parts[-1] != "APKINDEX.tar.gz":
                raise ReleaseGateError("offline Alpine index escaped its declared repository")
            target = destination / "repositories" / repository / "x86_64" / "APKINDEX.tar.gz"
        elif kind == "apk" and len(parts) == 5 and parts[:2] == ("apk", "v3.21"):
            target = destination / "repositories" / parts[2] / "x86_64" / parts[-1]
        else:
            raise ReleaseGateError("offline Alpine closure has an unsupported artifact layout")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        target_label = target.relative_to(destination).as_posix()
        if target_label in seen:
            raise ReleaseGateError("offline Alpine closure maps multiple inputs to one output")
        seen.add(target_label)
    required = {
        "keys/alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub",
        "repositories/main/x86_64/APKINDEX.tar.gz",
        "repositories/community/x86_64/APKINDEX.tar.gz",
    }
    if not required <= seen:
        raise ReleaseGateError("offline Alpine closure omitted a required signed repository input")


def _copy_alpine_python_pyc_overlay(artifact: Path, destination: Path) -> None:
    if (
        artifact.name != _ALPINE_PYTHON_PYC_NAME
        or not artifact.is_file()
        or artifact.is_symlink()
        or _sha256(artifact) != _ALPINE_PYTHON_PYC_SHA256
    ):
        raise ReleaseGateError("offline Alpine pycache overlay does not match the signed input")
    target = destination / "repositories" / "main" / "x86_64" / artifact.name
    if target.exists():
        raise ReleaseGateError("offline Alpine pycache overlay would replace a closure artifact")
    shutil.copy2(artifact, target)


def _stage_containment_context(
    root: Path,
    *,
    offline_npm_cache: Path,
    offline_alpine_closure: Path,
    offline_alpine_python_pyc: Path,
) -> Path:
    context = root / "context"
    shutil.copytree(
        ROOT,
        context,
        ignore=shutil.ignore_patterns(".git", "node_modules", "__pycache__", "*.pyc"),
    )
    cache = offline_npm_cache.resolve()
    raw_cache = cache / "_cacache"
    if not raw_cache.is_dir() or raw_cache.is_symlink():
        raise ReleaseGateError("offline npm cache is missing its regular _cacache directory")
    shutil.copytree(raw_cache, context / "artifacts" / "offline" / "npm" / "cache" / "_cacache")
    alpine_destination = context / "artifacts" / "offline" / "alpine"
    _copy_alpine_closure(offline_alpine_closure, alpine_destination)
    _copy_alpine_python_pyc_overlay(offline_alpine_python_pyc, alpine_destination)
    return context


def _run_containment_oracle(
    *,
    offline_npm_cache: Path,
    offline_alpine_closure: Path,
    offline_alpine_python_pyc: Path,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(
        prefix="masugate-release_verification-containment-", dir=_DOCKER_TEMP_ROOT
    ) as staging:
        context = _stage_containment_context(
            Path(staging),
            offline_npm_cache=offline_npm_cache,
            offline_alpine_closure=offline_alpine_closure,
            offline_alpine_python_pyc=offline_alpine_python_pyc,
        )
        environment = {
            **os.environ,
            "MASUGATE_CONTAINMENT_CONTEXT": str(context),
        }
        completed = subprocess.run(
            (sys.executable, str(CONTAINMENT_ORACLE)),
            cwd=context,
            env=environment,
            check=False,
            text=True,
            capture_output=True,
            timeout=300,
        )
    if completed.returncode != 0:
        raise ReleaseGateError(
            "reference containment direct-access oracle failed:\n"
            f"{completed.stdout}\n{completed.stderr}"
        )
    marker = "reference-containment live containment acceptance passed"
    if marker not in completed.stdout:
        raise ReleaseGateError(
            "reference containment direct-access oracle emitted no success marker"
        )
    return {
        "status": "blocked",
        "oracle": "scripts/run-reference-containment-live.py",
        "output_sha256": hashlib.sha256(completed.stdout.encode("utf-8")).hexdigest(),
    }


def _gateway_probe(
    runner: Any,
    project: str,
    environment: dict[str, str],
    mode: str,
    case_id: str,
) -> dict[str, object]:
    prompt_arguments: tuple[str, ...] = ()
    if mode == "attack":
        prompt = _release_verification().gateway_jailbreak_prompt(case_id)
        prompt_arguments = (
            "--attack-prompt-base64",
            base64.b64encode(prompt.encode("utf-8")).decode("ascii"),
        )
    try:
        output = runner._compose(
            project,
            environment,
            "exec",
            "--no-TTY",
            "openclaw-gateway",
            "node",
            "gateway-release_verification-session.mjs",
            mode,
            case_id,
            *prompt_arguments,
        )
    except runner.DemoRunnerError as exc:
        try:
            logs = runner._compose(
                project,
                environment,
                "logs",
                "--tail",
                "200",
                "openclaw-gateway",
                "masugated",
            )
        except runner.DemoRunnerError as log_exc:
            logs = f"<unable to collect Gateway diagnostics: {log_exc}>"
        raise ReleaseGateError(
            f"release verification Gateway {mode} probe failed; "
            f"retained service diagnostics:\n{logs}"
        ) from exc
    result = _json_output(output, f"release verification Gateway {mode} probe")
    if result.get("mode") != mode or result.get("case_id") != case_id:
        raise ReleaseGateError(f"Gateway {mode} probe reported the wrong identity")
    expected = {
        "attack": "denied",
        "governed": "committed",
        "safe": "available",
        "down": "blocked",
    }
    if mode not in expected:
        raise ReleaseGateError(f"Gateway probe mode is unsupported: {mode}")
    if result.get("status") != expected[mode]:
        raise ReleaseGateError(f"Gateway {mode} probe did not report {expected[mode]!r}")
    if mode == "attack":
        expected_prompt = _release_verification().gateway_jailbreak_prompt_sha256(case_id)
        if result.get("prompt_sha256") != expected_prompt:
            raise ReleaseGateError(
                "Gateway attack probe did not preserve the selected jailbreak fixture"
            )
    elapsed = result.get("elapsed_ms")
    if not isinstance(elapsed, int | float) or isinstance(elapsed, bool) or elapsed < 0:
        raise ReleaseGateError(f"Gateway {mode} probe emitted an invalid latency")
    return result


def _service_probe(
    runner: Any,
    project: str,
    environment: dict[str, str],
    mode: str,
    *,
    samples: int,
) -> dict[str, object]:
    if mode == "concurrency":
        output = runner._compose(
            project,
            environment,
            "exec",
            "--no-TTY",
            "masugated",
            "python",
            "-m",
            "masugate_openclaw_reference.release_verification_release",
            mode,
        )
        return _json_output(output, "release verification concurrent evidence")
    arguments = [
        "exec",
        "--no-TTY",
        "masugated",
        "python",
        "-m",
        "masugate_openclaw_reference.release_verification_release",
        mode,
    ]
    if mode == "performance":
        arguments.extend(("--samples", str(samples)))
    return _json_output(
        runner._compose(project, environment, *arguments), f"release verification {mode} evidence"
    )


def _stack_resources(
    runner: Any,
    project: str,
    environment: dict[str, str],
) -> dict[str, object]:
    """Capture Docker's one-shot view of all running release containers."""

    identifiers = tuple(
        line.strip()
        for line in runner._compose(project, environment, "ps", "--quiet").splitlines()
        if line.strip()
    )
    if not identifiers:
        raise ReleaseGateError("release verification stack has no containers to measure")
    output = runner._run(
        (DOCKER, "stats", "--no-stream", "--format", "{{json .}}", *identifiers),
        environment=environment,
    )
    containers: list[dict[str, object]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        row = _json_output(line, "Docker stats")
        name = row.get("Name", row.get("Container"))
        cpu = row.get("CPUPerc")
        memory = row.get("MemUsage")
        network = row.get("NetIO")
        block = row.get("BlockIO")
        if not all(
            isinstance(value, str) and value for value in (name, cpu, memory, network, block)
        ):
            raise ReleaseGateError("Docker stats emitted an incomplete container measurement")
        containers.append(
            {
                "block_io": block,
                "container": name,
                "cpu_percent": cpu,
                "memory_usage": memory,
                "network_io": network,
            }
        )
    if not containers:
        raise ReleaseGateError("Docker stats emitted no resource measurements")
    return {"containers": containers, "source": "docker stats --no-stream"}


def _release_descriptor(value: Mapping[str, object]) -> dict[str, object]:
    required = {
        "artifact_inventory_sha256",
        "checksums_sha256",
        "provenance_sha256",
        "release_id",
        "release_manifest_sha256",
        "runtime_target",
        "sbom_sha256",
        "schema_version",
        "source_revision",
        "staging_realization_revision",
        "spend_authorization",
    }
    fields = set(value)
    if fields != required and fields != required | {"staged_compose"}:
        raise ReleaseGateError(
            "reference artifact release descriptor is incomplete for release verification"
        )
    return {key: value[key] for key in sorted(required)}


def _build_or_verify_release(
    runner: Any,
    output: Path,
    release_dir: Path | None,
) -> tuple[Path, dict[str, object]]:
    release = release_dir.resolve() if release_dir is not None else output / "release"
    if release_dir is not None:
        provenance_path = release / "provenance.json"
        if not provenance_path.is_file() or provenance_path.is_symlink():
            raise ReleaseGateError("retained release is missing a regular provenance.json")
        try:
            provenance_value: object = json.loads(provenance_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ReleaseGateError("retained release provenance.json is invalid JSON") from exc
        provenance = _mapping(provenance_value, "retained release provenance")
        source_revision = _string(
            provenance.get("source_revision"), "retained release source revision"
        )
        staging_realization_revision = _string(
            provenance.get("staging_realization_revision"),
            "retained release staging realization revision",
        )
    else:
        source_revision = runner._current_source_revision()
        staging_realization_revision = source_revision
    if release_dir is None:
        if release.exists() and any(release.iterdir()):
            descriptor = runner._verify_release_output(
                release,
                expected_source_revision=source_revision,
                expected_staging_realization_revision=staging_realization_revision,
            )
            return release, descriptor
        runner._run(
            (sys.executable, str(RELEASE_BUILDER), "--outdir", str(release)),
            environment=dict(os.environ),
        )
    descriptor = runner._verify_release_output(
        release,
        expected_source_revision=source_revision,
        expected_staging_realization_revision=staging_realization_revision,
    )
    return release, descriptor


def _validate_existing(path: Path, release_dir: Path | None, *, offline_npm_cache: Path) -> None:
    """Verify evidence structure and bind it to the retained release artifacts."""

    if not path.is_file():
        raise ReleaseGateError(f"evidence file does not exist: {path}")
    try:
        value: object = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ReleaseGateError(f"evidence file is not JSON: {path}") from exc
    evidence = _release_verification().validate_release_evidence(value)
    release = release_dir.resolve() if release_dir is not None else path.parent / "release"
    if not release.is_dir():
        raise ReleaseGateError(
            "offline evidence verification requires its sibling retained release directory; "
            "supply --release-dir when it is stored elsewhere"
        )
    expected = _mapping(evidence.get("release"), "evidence release descriptor")
    runner = _reference_demo()
    descriptor = runner._verify_release_output(
        release,
        expected_source_revision=_string(
            expected.get("source_revision"), "release source revision"
        ),
        expected_staging_realization_revision=_string(
            expected.get("staging_realization_revision"),
            "release staging realization revision",
        ),
    )
    if _release_descriptor(descriptor) != _release_descriptor(expected):
        raise ReleaseGateError("evidence release descriptor does not match the retained release")
    with tempfile.TemporaryDirectory(
        prefix="masugate-release_verification-verify-artifacts-", dir=_DOCKER_TEMP_ROOT
    ) as staging:
        artifact_context = runner._stage_artifact_context(
            release, Path(staging), offline_npm_cache=offline_npm_cache
        )
        derived_integration = _integration_footprint(artifact_context)
    retained_integration = _mapping(evidence.get("integration"), "retained integration evidence")
    retained_footprint = {field: retained_integration.get(field) for field in derived_integration}
    if retained_footprint != derived_integration:
        raise ReleaseGateError(
            "retained integration footprint does not match the verified release artifacts"
        )


def _run_live_gate(
    output: Path,
    release_dir: Path | None,
    samples: int,
    *,
    offline_npm_cache: Path,
    offline_alpine_closure: Path,
    offline_alpine_python_pyc: Path,
) -> Path:
    runner = _reference_demo()
    runner._verify_docker_runtime()
    direct_access = _run_containment_oracle(
        offline_npm_cache=offline_npm_cache,
        offline_alpine_closure=offline_alpine_closure,
        offline_alpine_python_pyc=offline_alpine_python_pyc,
    )
    release, descriptor = _build_or_verify_release(runner, output, release_dir)
    revision = runner._string(descriptor.get("source_revision"), "release source revision")
    run_identity = hashlib.sha256(f"{os.getpid()}:{time.time_ns()}".encode()).hexdigest()[:12]
    # This value becomes the Gateway sandbox-network prefix.  Docker permits
    # underscores in project names, but the Gateway deliberately accepts only
    # portable lowercase DNS-label characters for that prefix.
    project = f"masugate-release-verification-{run_identity}"
    sandbox_image = (
        f"masugate-openclaw-reference-agent-sandbox:reference_demo-{revision[:12]}-{run_identity}"
    )
    state_written = False
    image_built = False
    agent_network: str | None = None
    if not _DOCKER_TEMP_ROOT.is_dir():
        raise ReleaseGateError(
            "release verification requires POSIX /tmp for Docker-bound artifact staging and state"
        )
    with (
        tempfile.TemporaryDirectory(
            prefix="masugate-release_verification-artifacts-", dir=_DOCKER_TEMP_ROOT
        ) as staging,
        tempfile.TemporaryDirectory(
            prefix="masugate-reference_demo-state-", dir=_DOCKER_TEMP_ROOT
        ) as state,
    ):
        state_root = Path(state)
        artifact_context = runner._stage_artifact_context(
            release, Path(staging), offline_npm_cache=offline_npm_cache
        )
        bound_descriptor = runner._bind_staged_compose_identity(descriptor, artifact_context)
        runner._validate_release_descriptor(bound_descriptor)
        environment = {
            **os.environ,
            "MASUGATE_REFERENCE_CONTAINMENT_STATE_ROOT": str(state_root),
            "MASUGATE_REFERENCE_DEMO_ENV_FILE": str(
                artifact_context.parent / ".masugate-compose.env"
            ),
            "MASUGATE_REFERENCE_DEMO_ARTIFACT_CONTEXT": str(artifact_context),
            "MASUGATE_REFERENCE_DEMO_COMPOSE_ROOT": str(artifact_context / "containment"),
            "MASUGATE_REFERENCE_DEMO_NETWORK_PREFIX": project,
            "MASUGATE_AGENT_SANDBOX_IMAGE": sandbox_image,
            "MASUGATE_GATEWAY_RECOVERY_HAZARD": "",
        }
        try:
            runner._cleanup_compose_project(project, environment, remove_local_images=False)
            state_written = True
            agent_network = runner._create_dynamic_agent_network(project)
            runner._compose(
                project,
                environment,
                "--profile",
                "sandbox-image",
                "build",
                "openclaw-agent-sandbox-image",
            )
            image_built = True
            time_to_governed_started = time.perf_counter_ns()
            runner._compose(
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
            concurrent_addon = _service_probe(
                runner, project, environment, "concurrency", samples=samples
            )
            _gateway_probe(runner, project, environment, "governed", "drop-in")
            time_to_governed_ms = (time.perf_counter_ns() - time_to_governed_started) / 1_000_000
            adversarial = _service_probe(
                runner, project, environment, "adversarial", samples=samples
            )
            adversarial["concurrent_addon"] = concurrent_addon
            adversarial["gateway_jailbreak"] = _gateway_probe(
                runner, project, environment, "attack", "agentdojo-over-budget"
            )
            adversarial["direct_access"] = direct_access
            performance = _service_probe(
                runner, project, environment, "performance", samples=samples
            )
            resource_use = performance.get("resource_use")
            if not isinstance(resource_use, dict):
                raise ReleaseGateError(
                    "release verification performance evidence lacks resource use"
                )
            resource_use["stack"] = _stack_resources(runner, project, environment)
            negative = _service_probe(runner, project, environment, "negative", samples=samples)
            integration = _integration_footprint(artifact_context)
            integration["time_to_governed_definition"] = (
                "compose up start through first committed Gateway MasuGate-owned action"
            )
            integration["time_to_governed_ms"] = round(time_to_governed_ms, 6)
            runner._compose(project, environment, "stop", "masugated")
            availability = {
                "benign_action": _gateway_probe(
                    runner, project, environment, "safe", "coordinator-down"
                ),
                "consequential_action": _gateway_probe(
                    runner, project, environment, "down", "coordinator-down"
                ),
            }
            evidence: dict[str, object] = {
                "schema_version": _SCHEMA,
                "release": _release_descriptor(bound_descriptor),
                "adversarial": adversarial,
                "negative_boundaries": negative,
                "performance": performance,
                "availability": availability,
                "integration": integration,
                "external_validity": {
                    "claim": False,
                    "reason": (
                        "T7 is not run on a named realistic workload in this bounded reference "
                        "release; external validity remains deferred."
                    ),
                    "status": "deferred",
                },
            }
            _release_verification().validate_release_evidence(evidence)
            path = output / "reference-release-evidence.json"
            path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            return path
        finally:
            try:
                runner._cleanup_compose_project(project, environment, remove_local_images=False)
            finally:
                try:
                    if state_written:
                        runner._clear_state_root_from_container(state_root)
                finally:
                    try:
                        if image_built:
                            runner._remove_sandbox_image(sandbox_image)
                    finally:
                        if agent_network is not None:
                            runner._remove_dynamic_agent_network(agent_network)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--outdir",
        type=Path,
        default=Path(tempfile.gettempdir()) / "masugate-release_verification-reference-release",
        help="empty directory for the clean release and generated evidence",
    )
    parser.add_argument(
        "--release-dir",
        type=Path,
        help="reuse a release output, or bind --verify-evidence to a retained release elsewhere",
    )
    parser.add_argument(
        "--offline-npm-cache",
        type=Path,
        required=True,
        help=(
            "path to the hash-locked native npm cache required for the offline "
            "reference demonstration context"
        ),
    )
    parser.add_argument(
        "--offline-alpine-closure",
        type=Path,
        help=(
            "path to the approved signed Alpine closure used only by the private "
            "direct-access containment oracle"
        ),
    )
    parser.add_argument(
        "--offline-alpine-python-pyc",
        type=Path,
        help="hash-bound pycache package missing from the predecessor Alpine closure",
    )
    parser.add_argument("--samples", type=int, default=8)
    parser.add_argument(
        "--verify-evidence",
        type=Path,
        help="validate existing evidence against its retained release without Docker",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    arguments = _parse_args(argv)
    if arguments.verify_evidence is not None:
        _validate_existing(
            arguments.verify_evidence.resolve(),
            arguments.release_dir,
            offline_npm_cache=arguments.offline_npm_cache,
        )
        print(
            f"release verification reference-release evidence verified: {arguments.verify_evidence}"
        )
        return
    if arguments.samples < 6:
        raise SystemExit("--samples must be at least 6")
    if arguments.offline_alpine_closure is None:
        raise SystemExit("--offline-alpine-closure is required for the live release gate")
    if arguments.offline_alpine_python_pyc is None:
        raise SystemExit("--offline-alpine-python-pyc is required for the live release gate")
    output = arguments.outdir.resolve()
    if output.exists() and any(output.iterdir()):
        raise SystemExit(f"release verification output directory must be empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    path = _run_live_gate(
        output,
        arguments.release_dir,
        arguments.samples,
        offline_npm_cache=arguments.offline_npm_cache,
        offline_alpine_closure=arguments.offline_alpine_closure,
        offline_alpine_python_pyc=arguments.offline_alpine_python_pyc,
    )
    print(f"release verification reference-release gate passed: {path}")


if __name__ == "__main__":
    try:
        main()
    except (
        ReleaseGateError,
        OSError,
        subprocess.TimeoutExpired,
        _release_verification().ReleaseVerificationReleaseError,
    ) as exc:
        raise SystemExit(f"release verification reference-release gate failed: {exc}") from exc
