"""Durable monotonic versions for logical policy-state scopes.

Governance views return versions for the complete logical scope named by their
contract, not versions of whichever storage row supplied one field. Providers
sharing a coordination resource use this table so every view of one scope
observes the same version and every successful scope transition advances it
exactly once.
"""

from __future__ import annotations

from typing import Any, cast

from masugate.errors import ContractError


class ScopeVersionError(ContractError):
    """A durable logical-scope version is missing or malformed."""


SCOPE_VERSIONS_SCHEMA = """
CREATE TABLE IF NOT EXISTS policy_scope_versions (
    scope TEXT PRIMARY KEY,
    version BIGINT NOT NULL,
    CHECK(version >= 0)
);
"""


def scope_version(connection: Any, scope: str) -> int:
    """Read a scope's current version; an untouched scope starts at zero."""

    row = connection.execute(
        "SELECT version FROM policy_scope_versions WHERE scope = ?",
        (scope,),
    ).fetchone()
    if row is None:
        return 0
    version = int(cast(int, row["version"]))
    if version < 0:
        raise ScopeVersionError(f"policy scope {scope!r} has a negative version")
    return version


def advance_scope_version(connection: Any, scope: str) -> int:
    """Advance one locked scope exactly once and return its new version."""

    connection.execute(
        "INSERT INTO policy_scope_versions(scope, version) VALUES (?, 1) "
        "ON CONFLICT(scope) DO UPDATE SET "
        "version = policy_scope_versions.version + 1",
        (scope,),
    )
    version = scope_version(connection, scope)
    if version <= 0:
        raise ScopeVersionError(f"policy scope {scope!r} did not advance")
    return version
