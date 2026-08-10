"""Independently versioned protected filesystem operation-pack artifact."""

from __future__ import annotations

import json
from importlib.resources import files

from masugate.operations import OperationPack, load_operation_pack


def operation_pack() -> OperationPack:
    """Load and validate the packaged closed operation-pack document."""

    payload = json.loads(files(__package__).joinpath("operation-pack.json").read_text("utf-8"))
    return load_operation_pack(payload)


__all__ = ["operation_pack"]
