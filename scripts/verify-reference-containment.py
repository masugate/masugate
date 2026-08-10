#!/usr/bin/env python3
"""Verify the bounded reference containment OpenClaw reference-containment profile."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from masugate_openclaw_reference.containment import (  # noqa: E402
    ReferenceSafeCapabilitySmoke,
    declared_bypass_matrix,
    load_reference_containment,
)


def main() -> None:
    containment = load_reference_containment()
    report = {
        "manifest_version": containment.manifest_version,
        "profile_version": containment.profile_version,
        "governed_surfaces": [
            surface.surface_id
            for surface in containment.surfaces
            if surface.disposition == "governed"
        ],
        "safe_smoke": ReferenceSafeCapabilitySmoke(containment).run(),
        "declared_bypass_matrix": declared_bypass_matrix(containment),
    }
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
