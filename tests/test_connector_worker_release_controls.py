"""Regression checks for the clean-artifact connector-worker controls."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from pathlib import Path

from masugate.operations.worker import _bootstrap_worker

ROOT = Path(__file__).parents[1]
WORKER = ROOT / "connectors" / "worker"


def test_worker_bootstrap_example_starts_a_closed_empty_recovery_pass(tmp_path: Path) -> None:
    document = json.loads((WORKER / "bootstrap.example.json").read_text(encoding="utf-8"))
    state = tmp_path / "state"
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    document["execution_store_path"] = str(state / "executions.sqlite")
    document["handoff_store_path"] = str(state / "handoffs.sqlite")
    document["artifact_store_path"] = str(state / "artifacts.sqlite")
    document["secret_mount"]["root"] = str(secrets)
    bootstrap = tmp_path / "bootstrap.json"
    bootstrap.write_text(json.dumps(document), encoding="utf-8")
    worker = _bootstrap_worker(bootstrap)
    asyncio.run(worker.initialize())
    report = asyncio.run(worker.recover())
    assert report.scanned == 0
    assert report.recovered == ()
    assert report.errors == ()


def test_worker_image_recipe_uses_only_verified_artifacts_and_closed_entrypoint() -> None:
    recipe = (WORKER / "Dockerfile.release").read_text(encoding="utf-8")
    assert "COPY artifacts/python/masugate/*.whl /artifacts/" in recipe
    assert "COPY artifacts/python/masugate-connector-sdk/*.whl /artifacts/" in recipe
    assert "COPY artifacts/python/masugate-connector-filesystem/*.whl /artifacts/" in recipe
    assert "COPY src/" not in recipe
    assert "--network=none" not in recipe
    assert 'ENTRYPOINT ["/usr/local/bin/masugate-connector-worker-entrypoint"]' in recipe
    assert "USER 10001:10001" in recipe


def test_worker_bootstrap_example_names_a_shipped_connector_entry_point() -> None:
    document = json.loads((WORKER / "bootstrap.example.json").read_text(encoding="utf-8"))
    registration = document["connector_registry"]["connectors"][0]
    deployment = document["deployment"]
    assert registration["package_id"] == "masugate-connector-filesystem"
    assert registration["entry_point"] == "filesystem"
    assert registration["id"] == "filesystem-v1"
    assert deployment["connector_package_id"] == registration["package_id"]
    assert deployment["connector_entry_point"] == registration["entry_point"]


def test_worker_compose_requires_a_reviewed_local_artifact_and_hardens_execution() -> None:
    compose = (WORKER / "compose.fragment.yaml").read_text(encoding="utf-8")
    assert "MASUGATE_CONNECTOR_WORKER_IMAGE" in compose
    assert "REPLACE_WITH_REVIEWED_DIGEST" not in compose
    assert '"--serve-committed-handoffs"' in compose
    assert '"masugate-connector-worker",' not in compose
    for required in ("read_only: true", 'cap_drop: ["ALL"]', "no-new-privileges:true"):
        assert required in compose


def test_worker_artifact_helper_exposes_build_and_archive_verification() -> None:
    path = ROOT / "scripts" / "build-connector-worker-artifact.py"
    spec = importlib.util.spec_from_file_location("connector_worker_artifact", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    assert module._SCHEMA == "masugate.connector-worker-artifact/v1"
    assert module._BASE_IMAGE.endswith(
        "519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7"
    )
    assert "shipped filesystem connector" in module._installed_connector_probe.__doc__
