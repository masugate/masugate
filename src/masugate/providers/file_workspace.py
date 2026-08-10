"""Framework-neutral canonical file/workspace claims.

This module governs a *logical* POSIX workspace namespace.  It never opens a
host path, follows a symlink, or imports an agent host.  A deployment supplies
the authoritative workspace roots and any known alias prefixes at composition
time; path spellings outside that canonical logical namespace fail closed.

Claim state is durable policy state.  The actual ``fs.write`` and
``fs.delete`` effects are deliberately declared ``protected-external``: a
filesystem implementation which cannot commit with that state must execute
through a protected runner rather than borrowing this transaction as proof of
an atomic host effect.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
from collections.abc import Callable, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Protocol, cast
from uuid import UUID, uuid5

from masugate.contracts import (
    EffectContract,
    GovernanceViewContract,
    ProviderIdentity,
    ReservationViewKind,
    ResourceSession,
)
from masugate.errors import ContractError
from masugate.model import (
    ActionRequest,
    ConsistencyGuarantee,
    Duration,
    JsonValue,
    ResourceFootprint,
    Scalar,
    TypeName,
)
from masugate.protected_execution import ProtectedExecutionRunner
from masugate.provider_assembly import (
    CoordinationDomain,
    EffectBinding,
    EffectExecutionPosition,
    ProtectedExecutionRegistration,
    ProtectedExternalExecutor,
    ProviderModule,
)

_MODULE_ID = "file-workspace"
_WRITE_ACTION = "fs.write"
_DELETE_ACTION = "fs.delete"
_CONNECTOR_ID = "filesystem-v1"
_IMPLEMENTATION_VERSION = "masugate.file-workspace-claims-v5"
_OPERATION_NAMESPACE = UUID("b79527bc-13d0-4928-aa67-c33b059fd237")


class FileWorkspaceClaimError(ContractError):
    """A logical workspace path or claim transition is unsafe."""


class FileWorkspaceClaimConflict(FileWorkspaceClaimError):
    """A canonical workspace prefix is already held by another operation."""


class _SessionResource(Protocol):
    def open_session(self, *, write: bool) -> AbstractAsyncContextManager[ResourceSession]: ...


def _canonical_identity(value: object, field_name: str) -> str:
    if not (
        type(value) is str
        and 0 < len(value) <= 255
        and value.strip() == value
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise ValueError(f"{field_name} must be a canonical identity")
    return value


def _expected_digest(value: object, field_name: str, *, allow_absent: bool = False) -> str:
    """Validate a caller-supplied compare precondition, never content facts.

    The certified write content digest and byte count come only from the sealed
    artifact handoff.  These values are merely optimistic-concurrency
    preconditions checked again by the connector against its protected root.
    """

    if allow_absent and value == "":
        return ""
    digest = _canonical_identity(value, field_name)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise FileWorkspaceClaimError(f"{field_name} must be a lowercase SHA-256 digest")
    return digest


def _canonical_json(value: JsonValue) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _digest(value: JsonValue) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("workspace claim time must be timezone-aware")
    return value.isoformat()


def _canonical_path(value: object, field_name: str) -> str:
    """Require one absolute, lexical POSIX path spelling.

    The policy namespace is intentionally not an OS-path normalizer.  Accepting
    ``..``, duplicate separators, backslashes, or a trailing slash would let
    two spellings claim different scopes for the same logical path.  A host
    runner still has to apply no-follow semantics before executing an external
    filesystem effect; this provider never resolves a host symlink itself.
    """

    if type(value) is not str or not value or len(value) > 1024:
        raise FileWorkspaceClaimError(f"{field_name} must be a canonical absolute POSIX path")
    if not value.startswith("/") or value.startswith("//") or "\\" in value or "\x00" in value:
        raise FileWorkspaceClaimError(f"{field_name} must be a canonical absolute POSIX path")
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
        raise FileWorkspaceClaimError(f"{field_name} must be a printable ASCII path")
    normalized = posixpath.normpath(value)
    if normalized != value or (value != "/" and value.endswith("/")):
        raise FileWorkspaceClaimError(f"{field_name} is not canonically normalized")
    return value


def _is_within(path: str, prefix: str) -> bool:
    return prefix == "/" or path == prefix or path.startswith(prefix + "/")


def _paths_overlap(left: str, right: str) -> bool:
    return _is_within(left, right) or _is_within(right, left)


def _path_prefixes(path: str) -> tuple[str, ...]:
    """Return the canonical path and each of its lexical ancestors."""

    parts = path.removeprefix("/").split("/") if path != "/" else []
    prefixes = ["/"]
    current = ""
    for part in parts:
        current += "/" + part
        prefixes.append(current)
    return tuple(prefixes)


def _path_scope(workspace_id: str, path: str) -> str:
    return f"workspace:{workspace_id}:path:{path}"


def _path_scopes(workspace_id: str, path: str) -> frozenset[str]:
    """Return every scope an external filesystem effect can mutate.

    An operation on a directory can remove or replace descendants. Its
    footprint must therefore include the target and every ancestor so a parent
    effect and a child effect are never declared independent.
    """

    return frozenset(_path_scope(workspace_id, prefix) for prefix in _path_prefixes(path))


def _path_lock_scopes(workspace_id: str, path: str) -> tuple[frozenset[str], str]:
    """Return shared ancestors and the exclusive target lock for ``path``.

    A parent claim takes its target lock exclusively. A descendant takes that
    same parent lock shared before it takes its own target lock exclusively,
    so parent/child operations serialize. Siblings only share common
    ancestors and can proceed concurrently.
    """

    prefixes = _path_prefixes(path)
    return (
        frozenset(_path_scope(workspace_id, prefix) for prefix in prefixes[:-1]),
        _path_scope(workspace_id, prefixes[-1]),
    )


def _connection(session: ResourceSession) -> Any:
    connection = getattr(session, "connection", None)
    if connection is None or not callable(getattr(connection, "execute", None)):
        raise FileWorkspaceClaimError(
            "file workspace claims require a resource-owned durable SQL session"
        )
    return connection


def _advisory_key(scope: str) -> int:
    """Match the coordination resource advisory-key derivation exactly."""

    digest = hashlib.blake2b(scope.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, byteorder="big", signed=True)


@dataclass(frozen=True)
class FileWorkspacePolicy:
    """Immutable trusted configuration for one logical workspace namespace."""

    workspace_id: str
    allowed_prefixes: tuple[str, ...]
    protected_prefixes: tuple[str, ...] = ()
    rejected_alias_prefixes: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        workspace_id = _canonical_identity(self.workspace_id, "workspace_id")
        allowed = tuple(_canonical_path(value, "allowed_prefix") for value in self.allowed_prefixes)
        protected = tuple(
            _canonical_path(value, "protected_prefix") for value in self.protected_prefixes
        )
        if not allowed:
            raise ValueError("file workspace policy needs at least one allowed prefix")
        if allowed != tuple(sorted(set(allowed))):
            raise ValueError("file workspace allowed prefixes must be sorted and unique")
        if protected != tuple(sorted(set(protected))):
            raise ValueError("file workspace protected prefixes must be sorted and unique")
        if any(
            not any(_is_within(prefix, allowed_prefix) for allowed_prefix in allowed)
            for prefix in protected
        ):
            raise ValueError("file workspace protected prefix is outside every allowed prefix")

        aliases: dict[str, str] = {}
        for raw_alias, raw_target in self.rejected_alias_prefixes.items():
            alias = _canonical_path(raw_alias, "rejected_alias_prefix")
            target = _canonical_path(raw_target, "rejected_alias_target")
            if alias == target:
                raise ValueError("file workspace alias prefix cannot equal its target")
            if not any(_is_within(alias, allowed_prefix) for allowed_prefix in allowed):
                raise ValueError("file workspace alias prefix is outside every allowed prefix")
            if not any(_is_within(target, allowed_prefix) for allowed_prefix in allowed):
                raise ValueError("file workspace alias target is outside every allowed prefix")
            aliases[alias] = target
        if tuple(sorted(aliases)) != tuple(aliases):
            raise ValueError("file workspace alias prefixes must be supplied in sorted order")

        object.__setattr__(self, "workspace_id", workspace_id)
        object.__setattr__(self, "allowed_prefixes", allowed)
        object.__setattr__(self, "protected_prefixes", protected)
        object.__setattr__(self, "rejected_alias_prefixes", MappingProxyType(aliases))

    @property
    def configuration_payload(self) -> dict[str, JsonValue]:
        return {
            "allowed_prefixes": list(self.allowed_prefixes),
            "protected_prefixes": list(self.protected_prefixes),
            "rejected_alias_prefixes": dict(self.rejected_alias_prefixes),
            "scope_scheme": "masugate.file-workspace.path-scopes.v4",
            "workspace_id": self.workspace_id,
        }

    @property
    def configuration_digest(self) -> str:
        return _digest(self.configuration_payload)

    @property
    def provider_identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="masugate.file-workspace",
            implementation_version=_IMPLEMENTATION_VERSION,
            configuration_version=self.configuration_digest,
        )

    def canonical_path(self, value: object, field_name: str = "path") -> str:
        path = _canonical_path(value, field_name)
        if not any(_is_within(path, prefix) for prefix in self.allowed_prefixes):
            raise FileWorkspaceClaimError(f"{field_name} is outside the configured workspace")
        if any(_is_within(path, prefix) for prefix in self.protected_prefixes):
            raise FileWorkspaceClaimError(f"{field_name} names a protected workspace path")
        if any(_is_within(path, alias) for alias in self.rejected_alias_prefixes):
            raise FileWorkspaceClaimError(
                f"{field_name} names a rejected alias/symlink workspace prefix"
            )
        return path

    def scopes(self, path: object) -> frozenset[str]:
        return _path_scopes(self.workspace_id, self.canonical_path(path))

    def claim_view_scope(self, path: object) -> str:
        """Return the lock scope covering every claim row a view may observe.

        workspace.claimed can read an exact claim or any ancestor claim.
        Its public dependency scope must therefore be the outermost configured
        workspace prefix containing the requested path, not the requested
        child path. Claim transitions take that prefix shared or exclusively,
        so an independently assembled action cannot observe a claim while its
        transition interleaves.
        """

        canonical_path = self.canonical_path(path)
        root = min(
            (prefix for prefix in self.allowed_prefixes if _is_within(canonical_path, prefix)),
            key=len,
        )
        return _path_scope(self.workspace_id, root)


@dataclass(frozen=True)
class FileWorkspaceClaim:
    """Durable ownership of one canonical logical workspace path."""

    claim_id: str
    workspace_id: str
    canonical_path: str
    principal_id: str
    operation_id: str
    active: bool
    version: int
    created_at: datetime
    released_at: datetime | None

    def __post_init__(self) -> None:
        _canonical_identity(self.claim_id, "claim_id")
        _canonical_identity(self.workspace_id, "workspace_id")
        _canonical_path(self.canonical_path, "canonical_path")
        _canonical_identity(self.principal_id, "principal_id")
        _canonical_identity(self.operation_id, "operation_id")
        if type(self.active) is not bool or type(self.version) is not int or self.version < 0:
            raise ValueError("file workspace claim state is malformed")
        if self.created_at.tzinfo is None or self.created_at.utcoffset() is None:
            raise ValueError("file workspace claim created_at must be timezone-aware")
        if self.released_at is not None and (
            self.released_at.tzinfo is None or self.released_at.utcoffset() is None
        ):
            raise ValueError("file workspace claim released_at must be timezone-aware")


class FileWorkspaceClaims:
    """Durable logical claims mounted in an existing coordination domain."""

    def __init__(self, policy: FileWorkspacePolicy, domain: CoordinationDomain) -> None:
        if type(policy) is not FileWorkspacePolicy:
            raise TypeError("file workspace claims require a FileWorkspacePolicy")
        if type(domain) is not CoordinationDomain:
            raise TypeError("file workspace claims require a CoordinationDomain")
        self.policy = policy
        self._domain = domain
        self._resource = cast(_SessionResource, domain.resource)

    async def initialize(self) -> None:
        """Persist and verify configuration before a claim can be acquired."""

        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            script = """
                CREATE TABLE IF NOT EXISTS file_workspace_provider_configuration (
                    workspace_id TEXT PRIMARY KEY,
                    configuration_digest TEXT NOT NULL,
                    configuration_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS file_workspace_claims (
                    claim_id TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL
                        REFERENCES file_workspace_provider_configuration(workspace_id),
                    canonical_path TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    version BIGINT NOT NULL,
                    created_at TEXT NOT NULL,
                    released_at TEXT,
                    UNIQUE(workspace_id, principal_id, operation_id, canonical_path),
                    CHECK(state IN ('active', 'released')),
                    CHECK(version >= 0)
                );
                CREATE INDEX IF NOT EXISTS file_workspace_claims_active_path
                    ON file_workspace_claims(workspace_id, state, canonical_path);
            """
            execute_script = getattr(connection, "executescript", None)
            if not callable(execute_script):
                raise FileWorkspaceClaimError(
                    "workspace claim resource cannot initialize SQL state"
                )
            execute_script(script)
            existing = connection.execute(
                "SELECT configuration_digest, configuration_json "
                "FROM file_workspace_provider_configuration WHERE workspace_id = ?",
                (self.policy.workspace_id,),
            ).fetchone()
            payload = _canonical_json(self.policy.configuration_payload)
            if existing is None:
                connection.execute(
                    "INSERT INTO file_workspace_provider_configuration("
                    "workspace_id, configuration_digest, configuration_json, created_at"
                    ") VALUES (?, ?, ?, ?)",
                    (
                        self.policy.workspace_id,
                        self.policy.configuration_digest,
                        payload,
                        _time(datetime.now(UTC)),
                    ),
                )
            elif (
                cast(str, existing["configuration_digest"]) != self.policy.configuration_digest
                or cast(str, existing["configuration_json"]) != payload
            ):
                raise FileWorkspaceClaimError(
                    "durable file workspace configuration does not match this deployment; "
                    "an explicit migration is required"
                )

    def provider_module(
        self,
        protected_runners: Mapping[str, ProtectedExecutionRunner] | None = None,
    ) -> ProviderModule:
        """Expose logical workspace state and protected filesystem effects."""

        def claimed(
            session: ResourceSession,
            arguments: tuple[Scalar | Duration, ...],
            _scope: str,
        ) -> tuple[Scalar, int]:
            if len(arguments) != 2:
                raise FileWorkspaceClaimError("workspace.claimed requires principal id and path")
            principal_id = _canonical_identity(arguments[0], "workspace.claimed principal_id")
            path = self.policy.canonical_path(arguments[1], "workspace.claimed path")
            matching = self._owned_ancestor_or_exact(
                _connection(session),
                path,
                principal_id,
            )
            return bool(matching), max((cast(int, row["version"]) for row in matching), default=0)

        def view_scope(arguments: tuple[Scalar | Duration, ...]) -> str:
            if len(arguments) != 2:
                raise FileWorkspaceClaimError("workspace.claimed requires principal id and path")
            principal_id = _canonical_identity(arguments[0], "workspace.claimed principal_id")
            del principal_id
            return self.policy.claim_view_scope(arguments[1])

        def footprint(request: ActionRequest, *, action: str) -> ResourceFootprint:
            if request.action != action:
                raise FileWorkspaceClaimError("file workspace footprint has an action mismatch")
            path = self.policy.canonical_path(request.arguments.get("path"), "effect path")
            expected = (
                {"path", "expected_current_digest"}
                if action == _DELETE_ACTION
                else {"path", "content", "expected_prior_digest"}
            )
            if set(request.arguments) != expected:
                raise FileWorkspaceClaimError("file workspace effect arguments are malformed")
            if action == _WRITE_ACTION:
                _canonical_identity(request.arguments["content"], "content")
                _expected_digest(
                    request.arguments["expected_prior_digest"],
                    "expected_prior_digest",
                    allow_absent=True,
                )
            else:
                _expected_digest(
                    request.arguments["expected_current_digest"], "expected_current_digest"
                )
            return ResourceFootprint(writes=_path_scopes(self.policy.workspace_id, path))

        def effect_footprint(action: str) -> Callable[[ActionRequest], ResourceFootprint]:
            def resolve(request: ActionRequest) -> ResourceFootprint:
                return footprint(request, action=action)

            return resolve

        view = GovernanceViewContract(
            name="workspace.claimed",
            argument_types=(TypeName.STRING, TypeName.STRING),
            return_type=TypeName.BOOL,
            owner=_MODULE_ID,
            consistency="scoped-policy-state",
            max_latency_ms=100,
            bounded=True,
            scope_resolver=view_scope,
            resolver=claimed,
            reservation_kind=ReservationViewKind.UNSUPPORTED,
            provider_identity=self.policy.provider_identity,
        )
        effects = tuple(
            EffectBinding(
                contract=EffectContract(
                    action=action,
                    argument_types=argument_types,
                    owner=_MODULE_ID,
                    required_guarantee=ConsistencyGuarantee.POLICY_STATE_SERIALIZABLE,
                    footprint_resolver=effect_footprint(action),
                    executor=ProtectedExternalExecutor(_CONNECTOR_ID),
                    provider_identity=self.policy.provider_identity,
                ),
                position=EffectExecutionPosition.PROTECTED_EXTERNAL,
                connector_id=_CONNECTOR_ID,
            )
            for action, argument_types in (
                (
                    _WRITE_ACTION,
                    {
                        "path": TypeName.STRING,
                        "content": TypeName.STRING,
                        "expected_prior_digest": TypeName.STRING,
                    },
                ),
                (
                    _DELETE_ACTION,
                    {"path": TypeName.STRING, "expected_current_digest": TypeName.STRING},
                ),
            )
        )
        runners = {} if protected_runners is None else dict(protected_runners)
        if set(runners) - {_WRITE_ACTION, _DELETE_ACTION}:
            raise FileWorkspaceClaimError("workspace module received an unknown protected runner")
        return ProviderModule(
            module_id=_MODULE_ID,
            identity=self.policy.provider_identity,
            domain=self._domain,
            scope_derivation_id=self._domain.scope_derivation_id,
            views=(view,),
            effects=effects,
            protected_executions=tuple(
                ProtectedExecutionRegistration(action, runner)
                for action, runner in sorted(runners.items())
            ),
        )

    async def acquire(
        self,
        *,
        principal_id: str,
        operation_id: str,
        path: str,
    ) -> FileWorkspaceClaim:
        """Atomically acquire one path/prefix claim, or fail on any overlap."""

        principal = _canonical_identity(principal_id, "principal_id")
        operation = _canonical_identity(operation_id, "operation_id")
        canonical_path = self.policy.canonical_path(path)
        async with self._resource.open_session(write=True) as session:
            return self._acquire_in_session(session, principal, operation, canonical_path)

    def _protect_for_request(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> frozenset[str]:
        """Protect the complete hierarchical effect footprint before evaluation."""

        if request.action not in {_WRITE_ACTION, _DELETE_ACTION}:
            raise FileWorkspaceClaimError("workspace protection received an unknown action")
        path = self.policy.canonical_path(request.arguments.get("path"), "effect path")
        expected = (
            {"path", "expected_current_digest"}
            if request.action == _DELETE_ACTION
            else {"path", "content", "expected_prior_digest"}
        )
        if set(request.arguments) != expected:
            raise FileWorkspaceClaimError("file workspace effect arguments are malformed")
        if request.action == _WRITE_ACTION:
            _canonical_identity(request.arguments["content"], "content")
            _expected_digest(
                request.arguments["expected_prior_digest"],
                "expected_prior_digest",
                allow_absent=True,
            )
        else:
            _expected_digest(
                request.arguments["expected_current_digest"], "expected_current_digest"
            )
        self._lock_path(_connection(session), path)
        return _path_scopes(self.policy.workspace_id, path)

    def _owned_ancestor_or_exact(
        self,
        connection: Any,
        canonical_path: str,
        principal_id: str,
    ) -> tuple[Mapping[str, object], ...]:
        """Return the owner claim that contains the requested path, if any.

        A descendant claim does not authorize an ancestor directory operation:
        owning a child file cannot authorize deleting its parent directory. The
        bounded ancestor-or-exact query preserves that directionality and
        leaves sibling claims independent.
        """

        ancestors = _path_prefixes(canonical_path)
        placeholders = ", ".join("?" for _ in ancestors)
        rows = connection.execute(
            "SELECT * FROM file_workspace_claims WHERE workspace_id = ? "
            "AND state = 'active' AND principal_id = ? AND canonical_path IN ("
            + placeholders
            + ") LIMIT 2",
            (self.policy.workspace_id, principal_id, *ancestors),
        ).fetchall()
        if len(rows) > 1:
            raise FileWorkspaceClaimError("multiple active owner claims contain one workspace path")
        return tuple(cast(Mapping[str, object], row) for row in rows)

    def _active_conflict(
        self,
        connection: Any,
        canonical_path: str,
    ) -> Mapping[str, object] | None:
        """Return one bounded ancestor/exact or descendant conflict, if any."""

        ancestors = _path_prefixes(canonical_path)
        placeholders = ", ".join("?" for _ in ancestors)
        ancestor = connection.execute(
            "SELECT * FROM file_workspace_claims WHERE workspace_id = ? "
            "AND state = 'active' AND canonical_path IN (" + placeholders + ") LIMIT 1",
            (self.policy.workspace_id, *ancestors),
        ).fetchone()
        if ancestor is not None:
            return cast(Mapping[str, object], ancestor)

        descendant_lower = "/" if canonical_path == "/" else canonical_path + "/"
        descendant_upper = "0" if canonical_path == "/" else canonical_path + "0"
        descendant = connection.execute(
            "SELECT * FROM file_workspace_claims WHERE workspace_id = ? "
            "AND state = 'active' AND canonical_path >= ? AND canonical_path < ? LIMIT 1",
            (self.policy.workspace_id, descendant_lower, descendant_upper),
        ).fetchone()
        return None if descendant is None else cast(Mapping[str, object], descendant)

    def _acquire_in_session(
        self,
        session: ResourceSession,
        principal_id: str,
        operation_id: str,
        canonical_path: str,
    ) -> FileWorkspaceClaim:
        connection = _connection(session)
        self._lock_path(connection, canonical_path)
        existing = connection.execute(
            "SELECT * FROM file_workspace_claims WHERE workspace_id = ? "
            "AND principal_id = ? AND operation_id = ? AND canonical_path = ?",
            (self.policy.workspace_id, principal_id, operation_id, canonical_path),
        ).fetchone()
        if existing is not None:
            claim = self._row(existing)
            if claim.active:
                return claim
            raise FileWorkspaceClaimError("released workspace claim cannot be replayed")

        active = self._active_conflict(connection, canonical_path)
        if active is not None:
            held_path = cast(str, active["canonical_path"])
            raise FileWorkspaceClaimConflict(
                f"workspace path {canonical_path!r} overlaps active claim {held_path!r}"
            )

        claim_id = "wclaim:" + str(
            uuid5(
                _OPERATION_NAMESPACE,
                f"{self.policy.workspace_id}:{principal_id}:{operation_id}:{canonical_path}",
            )
        )
        now = datetime.now(UTC)
        connection.execute(
            "INSERT INTO file_workspace_claims("
            "claim_id, workspace_id, canonical_path, principal_id, operation_id, state, "
            "version, created_at, released_at"
            ") VALUES (?, ?, ?, ?, ?, 'active', 1, ?, NULL)",
            (
                claim_id,
                self.policy.workspace_id,
                canonical_path,
                principal_id,
                operation_id,
                _time(now),
            ),
        )
        return FileWorkspaceClaim(
            claim_id=claim_id,
            workspace_id=self.policy.workspace_id,
            canonical_path=canonical_path,
            principal_id=principal_id,
            operation_id=operation_id,
            active=True,
            version=1,
            created_at=now,
            released_at=None,
        )

    async def release(self, *, claim_id: str, principal_id: str) -> FileWorkspaceClaim:
        """Release a claim only under its original principal identity."""

        claim_identity = _canonical_identity(claim_id, "claim_id")
        principal = _canonical_identity(principal_id, "principal_id")
        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            row = connection.execute(
                "SELECT canonical_path FROM file_workspace_claims "
                "WHERE claim_id = ? AND workspace_id = ?",
                (claim_identity, self.policy.workspace_id),
            ).fetchone()
            if row is None:
                raise FileWorkspaceClaimError("workspace claim is unknown")
            self._lock_path(connection, cast(str, row["canonical_path"]))
            row = connection.execute(
                "SELECT * FROM file_workspace_claims WHERE claim_id = ? AND workspace_id = ?",
                (claim_identity, self.policy.workspace_id),
            ).fetchone()
            if row is None:
                raise FileWorkspaceClaimError("workspace claim is unknown")
            claim = self._row(row)
            if claim.principal_id != principal:
                raise FileWorkspaceClaimError("workspace claim principal does not match")
            if not claim.active:
                return claim
            released_at = datetime.now(UTC)
            connection.execute(
                "UPDATE file_workspace_claims SET state = 'released', version = version + 1, "
                "released_at = ? WHERE claim_id = ?",
                (_time(released_at), claim.claim_id),
            )
            return FileWorkspaceClaim(
                claim_id=claim.claim_id,
                workspace_id=claim.workspace_id,
                canonical_path=claim.canonical_path,
                principal_id=claim.principal_id,
                operation_id=claim.operation_id,
                active=False,
                version=claim.version + 1,
                created_at=claim.created_at,
                released_at=released_at,
            )

    @staticmethod
    def _row(row: Mapping[str, object]) -> FileWorkspaceClaim:
        created_at = datetime.fromisoformat(cast(str, row["created_at"]))
        raw_released = row["released_at"]
        return FileWorkspaceClaim(
            claim_id=cast(str, row["claim_id"]),
            workspace_id=cast(str, row["workspace_id"]),
            canonical_path=cast(str, row["canonical_path"]),
            principal_id=cast(str, row["principal_id"]),
            operation_id=cast(str, row["operation_id"]),
            active=cast(str, row["state"]) == "active",
            version=int(cast(int, row["version"])),
            created_at=created_at,
            released_at=(
                None if raw_released is None else datetime.fromisoformat(cast(str, raw_released))
            ),
        )

    def _lock_path(self, connection: Any, canonical_path: str) -> None:
        """Serialize overlapping PostgreSQL claims without serializing siblings."""

        if not hasattr(connection, "raw"):
            return
        shared_scopes, exclusive_scope = _path_lock_scopes(
            self.policy.workspace_id,
            canonical_path,
        )
        locks = [(scope, True) for scope in shared_scopes]
        locks.append((exclusive_scope, False))
        for scope, shared in sorted(locks, key=lambda item: _advisory_key(item[0])):
            connection.execute(
                "SELECT pg_advisory_xact_lock_shared(?)"
                if shared
                else "SELECT pg_advisory_xact_lock(?)",
                (_advisory_key(scope),),
            )


__all__ = [
    "FileWorkspaceClaim",
    "FileWorkspaceClaimConflict",
    "FileWorkspaceClaimError",
    "FileWorkspaceClaims",
    "FileWorkspacePolicy",
]
