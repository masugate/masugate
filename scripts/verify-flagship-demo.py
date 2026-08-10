#!/usr/bin/env python3
"""Verify the exact credential-free five-minute procurement demonstration."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import cast

_MAX_ELAPSED_NS = 300 * 1_000_000_000
_METADATA_SCHEMA = "masugate.reference-demo-run-metadata/v1"


class FlagshipDemoError(RuntimeError):
    """The documented flagship command did not retain all required observations."""


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise FlagshipDemoError(f"{label} must be an object")
    return cast(dict[str, object], value)


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise FlagshipDemoError(f"{label} must be a list")
    return value


def _read_json(path: Path, label: str) -> dict[str, object]:
    try:
        return _mapping(json.loads(path.read_text(encoding="utf-8")), label)
    except (OSError, json.JSONDecodeError) as exc:
        raise FlagshipDemoError(f"cannot read {label}: {path}") from exc


def verify(outdir: Path) -> dict[str, object]:
    """Check the literal README command's timing and four required observations."""

    evidence_dir = outdir.resolve() / "evidence"
    metadata = _read_json(evidence_dir / "run-metadata.json", "flagship run metadata")
    if metadata.get("schema_version") != _METADATA_SCHEMA:
        raise FlagshipDemoError("flagship run metadata has an incompatible schema")
    if metadata.get("requested_scenarios") != ["procurement"]:
        raise FlagshipDemoError("flagship run did not execute only the procurement scenario")
    elapsed_ns = metadata.get("elapsed_ns")
    if type(elapsed_ns) is not int or not 0 <= elapsed_ns < _MAX_ELAPSED_NS:
        raise FlagshipDemoError("flagship run did not finish in less than five minutes")
    if metadata.get("network_access") is not False or metadata.get("credentials_used") is not False:
        raise FlagshipDemoError("flagship run used network access or credentials")

    envelope = _read_json(evidence_dir / "procurement.json", "procurement evidence")
    if envelope.get("scenario_id") != "procurement":
        raise FlagshipDemoError("flagship evidence has the wrong scenario")
    evidence = _mapping(envelope.get("evidence"), "procurement evidence body")
    weak = _mapping(evidence.get("weak_baseline"), "unsafe baseline")
    weak_pss = _mapping(weak.get("pss"), "unsafe baseline PSS")
    if weak.get("stale_authorization") is not True or weak_pss.get("valid") is not False:
        raise FlagshipDemoError("flagship evidence does not retain the unsafe stale execution")

    governed = _mapping(evidence.get("governed"), "governed execution")
    governed_pss = _mapping(governed.get("pss"), "governed PSS")
    if governed.get("budget_valid") is not True or governed_pss.get("valid") is not True:
        raise FlagshipDemoError("flagship evidence does not retain a governed PSS execution")
    records = _list(governed.get("governance_records"), "governance records")
    committed = [
        _mapping(record, "governance record")
        for record in records
        if _mapping(record, "governance record").get("status") == "committed"
    ]
    if len(committed) != 1:
        raise FlagshipDemoError("flagship evidence must retain one committed governed receipt")
    protected = _mapping(committed[0].get("protected_execution"), "protected execution")
    receipt = _mapping(protected.get("receipt"), "governed receipt")
    if receipt.get("outcome") != "succeeded":
        raise FlagshipDemoError("flagship receipt is not a successful governed effect")
    return {
        "result": "PASS",
        "scenario": "procurement",
        "elapsed_ns": elapsed_ns,
        "unsafe_execution": "stale authorization is not PSS",
        "governed_execution": "PSS-valid bounded execution",
        "receipt": "successful governed receipt",
        "pss": "unsafe false; governed true",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outdir", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.outdir), sort_keys=True))
    except FlagshipDemoError as exc:
        raise SystemExit(f"flagship demonstration verification failed: {exc}") from exc


if __name__ == "__main__":
    main()
