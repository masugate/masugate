"""Regression checks for the exact Linux/x64 reviewer npm cache closure."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]


def _setup_module() -> Any:
    path = ROOT / "scripts" / "prepare-reference-demo.py"
    spec = importlib.util.spec_from_file_location("prepare_reference_demo", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_demo_cache_prunes_only_platform_excluded_package_entries(tmp_path: Path) -> None:
    setup = _setup_module()
    contract = tmp_path / "contract"
    contract.mkdir()
    required = b"linux-x64"
    excluded = b"darwin-arm64"
    required_integrity = "sha512-" + base64.b64encode(hashlib.sha512(required).digest()).decode()
    excluded_integrity = "sha512-" + base64.b64encode(hashlib.sha512(excluded).digest()).decode()
    required_url = "https://registry.npmjs.org/example-linux/-/example-linux-1.0.0.tgz"
    excluded_url = "https://registry.npmjs.org/example-darwin/-/example-darwin-1.0.0.tgz"
    (contract / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {},
                    "node_modules/example-linux": {
                        "resolved": required_url,
                        "integrity": required_integrity,
                        "os": ["linux"],
                        "cpu": ["x64"],
                    },
                    "node_modules/example-darwin": {
                        "resolved": excluded_url,
                        "integrity": excluded_integrity,
                        "os": ["darwin"],
                        "cpu": ["arm64"],
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    raw_cache = tmp_path / "cache" / "_cacache"
    for integrity, url, payload in (
        (required_integrity, required_url, required),
        (excluded_integrity, excluded_url, excluded),
    ):
        content = setup._cache_content_path(raw_cache, integrity)
        index = setup._cache_index_path(raw_cache, url)
        content.parent.mkdir(parents=True, exist_ok=True)
        index.parent.mkdir(parents=True, exist_ok=True)
        content.write_bytes(payload)
        index.write_bytes(b"")

    setup._prune_demo_npm_cache(raw_cache.parent, contract)

    assert setup._cache_content_path(raw_cache, required_integrity).is_file()
    assert setup._cache_index_path(raw_cache, required_url).is_file()
    assert not setup._cache_content_path(raw_cache, excluded_integrity).exists()
    assert not setup._cache_index_path(raw_cache, excluded_url).exists()
