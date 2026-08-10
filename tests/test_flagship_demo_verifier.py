"""The documented flagship command must retain all four required observations."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "verify-flagship-demo.py"


def _verifier() -> Any:
    spec = importlib.util.spec_from_file_location("flagship_demo_verifier", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_evidence(root: Path, *, elapsed_ns: int = 1_000_000_000) -> None:
    evidence = root / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "run-metadata.json").write_text(
        json.dumps(
            {
                "schema_version": "masugate.reference-demo-run-metadata/v1",
                "requested_scenarios": ["procurement"],
                "started_ns": 1,
                "finished_ns": 2,
                "elapsed_ns": elapsed_ns,
                "network_access": False,
                "credentials_used": False,
            }
        ),
        encoding="utf-8",
    )
    (evidence / "procurement.json").write_text(
        json.dumps(
            {
                "scenario_id": "procurement",
                "evidence": {
                    "weak_baseline": {
                        "stale_authorization": True,
                        "pss": {"valid": False},
                    },
                    "governed": {
                        "budget_valid": True,
                        "pss": {"valid": True},
                        "governance_records": [
                            {
                                "status": "committed",
                                "protected_execution": {"receipt": {"outcome": "succeeded"}},
                            },
                            {"status": "denied"},
                        ],
                    },
                },
            }
        ),
        encoding="utf-8",
    )


def test_flagship_verifier_accepts_the_documented_procurement_observations(
    tmp_path: Path,
) -> None:
    verifier = _verifier()
    _write_evidence(tmp_path)

    result = verifier.verify(tmp_path)

    assert result["result"] == "PASS"
    assert result["scenario"] == "procurement"


@pytest.mark.parametrize(
    ("path", "mutator", "message"),
    [
        (
            "evidence/run-metadata.json",
            lambda value: value.update({"elapsed_ns": 300 * 1_000_000_000}),
            "less than five minutes",
        ),
        (
            "evidence/procurement.json",
            lambda value: value["evidence"]["weak_baseline"].update({"stale_authorization": False}),
            "unsafe stale execution",
        ),
        (
            "evidence/procurement.json",
            lambda value: value["evidence"]["governed"]["pss"].update({"valid": False}),
            "governed PSS execution",
        ),
        (
            "evidence/procurement.json",
            lambda value: value["evidence"]["governed"]["governance_records"][0][
                "protected_execution"
            ]["receipt"].update({"outcome": "failed"}),
            "successful governed effect",
        ),
    ],
)
def test_flagship_verifier_rejects_missing_required_observations(
    tmp_path: Path, path: str, mutator: Any, message: str
) -> None:
    verifier = _verifier()
    _write_evidence(tmp_path)
    target = tmp_path / path
    value = json.loads(target.read_text(encoding="utf-8"))
    mutator(value)
    target.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(verifier.FlagshipDemoError, match=message):
        verifier.verify(tmp_path)
