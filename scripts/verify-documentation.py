#!/usr/bin/env python3
"""Validate checked-in reader links and declared public-surface paths locally."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LEDGER = ROOT / "docs/claims/reference-release-claims.json"
_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
_BLOCKED_PUBLIC_PREFIXES = ("internal/", "evidence/private/", "work/")


class DocumentationError(RuntimeError):
    """A reader-visible path or local Markdown link is absent or unsafe."""


def _local_target(raw: str, source: Path) -> Path | None:
    target = raw.strip().strip("<>")
    if not target or target.startswith(("#", "http://", "https://", "mailto:")):
        return None
    target = target.split("#", 1)[0]
    if not target:
        return None
    resolved = (source.parent / target).resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError as exc:
        raise DocumentationError(
            f"link escapes repository: {source.relative_to(ROOT)} -> {raw}"
        ) from exc
    return resolved


def verify() -> None:
    ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
    surfaces = ledger.get("public_surfaces")
    if not isinstance(surfaces, list):
        raise DocumentationError("claim ledger public_surfaces must be a list")
    paths: set[str] = set()
    for surface in surfaces:
        if not isinstance(surface, dict) or not isinstance(surface.get("path"), str):
            raise DocumentationError("claim ledger public surface is malformed")
        path = surface["path"]
        if path in paths or path.startswith(_BLOCKED_PUBLIC_PREFIXES):
            raise DocumentationError(f"claim ledger public surface is unsafe or duplicated: {path}")
        paths.add(path)
        candidate = ROOT / path
        if not candidate.is_file() or candidate.is_symlink():
            raise DocumentationError(f"claim ledger public surface is absent: {path}")
    documented_pages = {
        page.relative_to(ROOT).as_posix()
        for page in (ROOT / "docs").rglob("*.md")
        if page.is_file() and not page.is_symlink()
    }
    undeclared_pages = sorted(documented_pages - paths)
    if undeclared_pages:
        raise DocumentationError(
            "documentation page is absent from the public-surface ledger: "
            + ", ".join(undeclared_pages)
        )
    for source in sorted(ROOT.rglob("*.md")):
        if any(part in {".git", "node_modules"} for part in source.parts):
            continue
        text = source.read_text(encoding="utf-8")
        for raw in _LINK.findall(text):
            target = _local_target(raw, source)
            if target is not None and (not target.exists() or target.is_symlink()):
                raise DocumentationError(
                    f"Markdown link is absent: {source.relative_to(ROOT)} -> {raw}"
                )


def main() -> None:
    try:
        verify()
    except (DocumentationError, OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"documentation verification failed: {exc}") from exc
    print("documentation links and declared public surfaces are coherent")


if __name__ == "__main__":
    main()
