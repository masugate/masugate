"""Framework-neutral communications and policy-approval state providers.

The communications provider owns channel/peer coordination, delivery counters,
allowlist state, and first-contact facts in one existing resource session.
The approval provider stores only explicit MasuGate policy facts; it deliberately
does not import, observe, or trust a framework approval presentation callback.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Collection, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
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
    request_binding_digest,
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
from masugate.scope_versions import (
    SCOPE_VERSIONS_SCHEMA,
    advance_scope_version,
    scope_version,
)

_COMMUNICATIONS_MODULE_ID = "communications"
_APPROVAL_MODULE_ID = "approval-state"
_SEND_ACTION = "send_message"
_POST_ACTION = "channel.post"
_CONNECTOR_ID = "communications-runner-v1"
_COMMUNICATIONS_IMPLEMENTATION = "masugate.communications-v7"
_APPROVAL_IMPLEMENTATION = "masugate.policy-approval-state-v1"
_ACTION = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$", re.ASCII)
_NAMESPACE = UUID("fc7b1b78-581b-4d2b-b867-2a3ee9e9060f")


class CommunicationsError(ContractError):
    """A communications/approval state transition is malformed or unsafe."""


class CommunicationClaimConflict(CommunicationsError):
    """A same-peer or same-channel operation is already active."""


class _SessionResource(Protocol):
    def open_session(self, *, write: bool) -> AbstractAsyncContextManager[ResourceSession]: ...


def _identity(value: object, field_name: str) -> str:
    if not (
        type(value) is str
        and 0 < len(value) <= 255
        and value.strip() == value
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise ValueError(f"{field_name} must be a canonical identity")
    return value


def _action(value: object, field_name: str = "action") -> str:
    action = _identity(value, field_name)
    if _ACTION.fullmatch(action) is None:
        raise ValueError(f"{field_name} must be a canonical action")
    return action


def _json(value: JsonValue) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _digest(value: JsonValue) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("communications state time must be timezone-aware")
    return value.isoformat()


def _connection(session: ResourceSession) -> Any:
    connection = getattr(session, "connection", None)
    if connection is None or not callable(getattr(connection, "execute", None)):
        raise CommunicationsError("communications providers require a durable SQL resource session")
    return connection


def _advisory_key(scope: str) -> int:
    """Match the coordination resource advisory-key derivation exactly."""

    digest = hashlib.blake2b(scope.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, byteorder="big", signed=True)


def _lock(connection: Any, scopes: Collection[str]) -> None:
    """Lock only declared scopes on PostgreSQL; SQLite serializes writers."""

    if not hasattr(connection, "raw"):
        return
    for scope in sorted(scopes, key=_advisory_key):
        connection.execute("SELECT pg_advisory_xact_lock(?)", (_advisory_key(scope),))


def _delivery_peer_key(peer: str | None) -> str:
    """Make direct-message and channel-post counter keys unambiguous."""

    return "" if peer is None else peer


def _scope_component(value: str) -> str:
    """Encode an identity without delimiter collisions in a coordination scope."""

    return f"{len(value)}:{value}"


def _canonical_scope(value: object, field_name: str = "scope") -> str:
    """Validate a derived coordination scope without imposing identity length."""

    if not (
        type(value) is str
        and 0 < len(value) <= 1024
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise ValueError(f"{field_name} must be a canonical coordination scope")
    return value


def _claim_identifier(
    scope: str,
    principal_id: str,
    operation_id: str,
    request_digest: str,
) -> str:
    """Derive a collision-free opaque claim id from canonical structured inputs."""

    payload: dict[str, JsonValue] = {
        "operation_id": operation_id,
        "principal_id": principal_id,
        "request_digest": request_digest,
        "scope": scope,
    }
    return "commclaim:" + str(uuid5(_NAMESPACE, _json(payload)))


@dataclass(frozen=True)
class CommunicationsPolicy:
    """Versioned allowlist configuration for one communications deployment."""

    policy_id: str
    allowed_contacts: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        policy_id = _identity(self.policy_id, "communications policy_id")
        contacts = tuple(
            (_identity(channel, "allowlist channel"), _identity(peer, "allowlist peer"))
            for channel, peer in self.allowed_contacts
        )
        if contacts != tuple(sorted(set(contacts))):
            raise ValueError("communications allowlist contacts must be sorted and unique")
        object.__setattr__(self, "policy_id", policy_id)
        object.__setattr__(self, "allowed_contacts", contacts)

    @property
    def payload(self) -> dict[str, JsonValue]:
        return {
            "allowed_contacts": [list(contact) for contact in self.allowed_contacts],
            "policy_id": self.policy_id,
            "state_schema": "masugate.communications.length-delimited-scopes.v7",
        }

    @property
    def digest(self) -> str:
        return _digest(self.payload)

    @property
    def provider_identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="masugate.communications",
            implementation_version=_COMMUNICATIONS_IMPLEMENTATION,
            configuration_version=self.digest,
        )

    def contact_allowed(self, channel: object, peer: object) -> bool:
        return (_identity(channel, "channel"), _identity(peer, "peer")) in self.allowed_contacts


@dataclass(frozen=True)
class PolicyApprovalState:
    """Explicit MasuGate policy facts, deliberately distinct from presentation state."""

    state_id: str
    grants: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        state_id = _identity(self.state_id, "approval state_id")
        grants = tuple(
            (_identity(subject, "approval subject"), _action(action, "approval action"))
            for subject, action in self.grants
        )
        if grants != tuple(sorted(set(grants))):
            raise ValueError("approval grants must be sorted and unique")
        object.__setattr__(self, "state_id", state_id)
        object.__setattr__(self, "grants", grants)

    @property
    def payload(self) -> dict[str, JsonValue]:
        return {
            "grants": [list(grant) for grant in self.grants],
            "state_id": self.state_id,
            "state_schema": "masugate.policy-approval-state.v1",
        }

    @property
    def digest(self) -> str:
        return _digest(self.payload)

    @property
    def provider_identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="masugate.policy-approval-state",
            implementation_version=_APPROVAL_IMPLEMENTATION,
            configuration_version=self.digest,
        )


@dataclass(frozen=True)
class CommunicationClaim:
    claim_id: str
    scope: str
    action: str
    principal_id: str
    operation_id: str
    request_digest: str
    active: bool
    version: int

    def __post_init__(self) -> None:
        for name in ("claim_id", "principal_id", "operation_id", "request_digest"):
            _identity(getattr(self, name), name)
        _canonical_scope(self.scope)
        _action(self.action)
        if type(self.active) is not bool or type(self.version) is not int or self.version < 0:
            raise ValueError("communications claim state is malformed")


@dataclass(frozen=True)
class _CommunicationRequest:
    """Canonical request fields bound to one communications claim and delivery."""

    action: str
    scope: str
    channel: str
    peer: str | None
    principal_id: str
    operation_id: str
    request_digest: str


class CommunicationsProvider:
    """Durable channel/peer claims, counters, allowlists, and first-contact state."""

    def __init__(self, policy: CommunicationsPolicy, domain: CoordinationDomain) -> None:
        if type(policy) is not CommunicationsPolicy or type(domain) is not CoordinationDomain:
            raise TypeError("communications provider requires policy and coordination domain")
        self.policy = policy
        self._domain = domain
        self._resource = cast(_SessionResource, domain.resource)
        self._initialized = False

    def _require_initialized(self) -> None:
        if not self._initialized:
            raise CommunicationsError(
                "communications provider must be initialized before it can use durable state"
            )

    @staticmethod
    def _peer_scope(channel: object, peer: object) -> str:
        canonical_channel = _identity(channel, "channel")
        canonical_peer = _identity(peer, "peer")
        return (
            "communications:peer:"
            f"{_scope_component(canonical_channel)}:{_scope_component(canonical_peer)}"
        )

    @staticmethod
    def _channel_scope(channel: object) -> str:
        canonical_channel = _identity(channel, "channel")
        return f"communications:channel:{_scope_component(canonical_channel)}"

    def _scope(self, action: object, channel: object, peer: object | None = None) -> str:
        selected = _action(action)
        if selected == _SEND_ACTION:
            if peer is None:
                raise CommunicationsError("send_message requires a peer")
            return self._peer_scope(channel, peer)
        if selected == _POST_ACTION:
            if peer is not None:
                raise CommunicationsError("channel.post cannot name a peer")
            return self._channel_scope(channel)
        raise CommunicationsError("communications provider does not own this action")

    async def initialize(self) -> None:
        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            script = (
                SCOPE_VERSIONS_SCHEMA
                + """
                CREATE TABLE IF NOT EXISTS communications_provider_configuration (
                    policy_id TEXT PRIMARY KEY,
                    configuration_digest TEXT NOT NULL,
                    configuration_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS communication_claims (
                    claim_id TEXT PRIMARY KEY,
                    scope TEXT NOT NULL,
                    action TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    state TEXT NOT NULL,
                    version BIGINT NOT NULL,
                    UNIQUE(scope, principal_id, operation_id),
                    CHECK(state IN ('active', 'released')),
                    CHECK(version >= 0)
                );
                CREATE INDEX IF NOT EXISTS communication_claims_active_scope
                    ON communication_claims(scope, state);
                CREATE TABLE IF NOT EXISTS communication_deliveries (
                    claim_id TEXT PRIMARY KEY REFERENCES communication_claims(claim_id),
                    action TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    peer_key TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(action, channel, peer_key, principal_id, operation_id, request_digest)
                );
                CREATE TABLE IF NOT EXISTS communication_counters (
                    action TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    peer_key TEXT NOT NULL,
                    delivery_count BIGINT NOT NULL,
                    version BIGINT NOT NULL,
                    PRIMARY KEY(action, channel, peer_key),
                    CHECK(delivery_count >= 0),
                    CHECK(version >= 0)
                );
            """
            )
            execute_script = getattr(connection, "executescript", None)
            if not callable(execute_script):
                raise CommunicationsError("communications resource cannot initialize SQL state")
            execute_script(script)
            _lock(connection, {"communications:configuration"})
            payload = _json(self.policy.payload)
            rows = connection.execute(
                "SELECT policy_id, configuration_digest, configuration_json FROM "
                "communications_provider_configuration ORDER BY policy_id LIMIT 2"
            ).fetchall()
            if not rows:
                connection.execute(
                    "INSERT INTO communications_provider_configuration("
                    "policy_id, configuration_digest, configuration_json, created_at"
                    ") VALUES (?, ?, ?, ?)",
                    (self.policy.policy_id, self.policy.digest, payload, _time(datetime.now(UTC))),
                )
            elif len(rows) != 1:
                raise CommunicationsError(
                    "communications resource has multiple durable policy configurations"
                )
            else:
                row = rows[0]
                if (
                    row["policy_id"] != self.policy.policy_id
                    or row["configuration_digest"] != self.policy.digest
                    or row["configuration_json"] != payload
                ):
                    raise CommunicationsError(
                        "durable communications configuration does not match this deployment"
                    )
        self._initialized = True

    def _request_details(self, request: ActionRequest) -> _CommunicationRequest:
        """Validate and canonicalize the immutable request bound to a claim."""

        if type(request) is not ActionRequest:
            raise TypeError("communications claim operations require an ActionRequest")
        action = _action(request.action)
        principal_id = _identity(request.principal.id, "principal_id")
        operation_id = _identity(request.operation_id, "operation_id")
        request_digest = request_binding_digest(request)
        if action == _SEND_ACTION:
            if set(request.arguments) != {"channel", "peer", "content_digest"}:
                raise CommunicationsError("send_message arguments are malformed")
            channel = _identity(request.arguments["channel"], "channel")
            peer = _identity(request.arguments["peer"], "peer")
            _identity(request.arguments["content_digest"], "content_digest")
            scope = self._peer_scope(channel, peer)
            return _CommunicationRequest(
                action, scope, channel, peer, principal_id, operation_id, request_digest
            )
        if action == _POST_ACTION:
            if set(request.arguments) != {"channel", "content_digest", "broadcast"}:
                raise CommunicationsError("channel.post arguments are malformed")
            if type(request.arguments["broadcast"]) is not bool:
                raise CommunicationsError("channel.post broadcast must be bool")
            channel = _identity(request.arguments["channel"], "channel")
            _identity(request.arguments["content_digest"], "content_digest")
            scope = self._channel_scope(channel)
            return _CommunicationRequest(
                action, scope, channel, None, principal_id, operation_id, request_digest
            )
        raise CommunicationsError("communications provider does not own this action")

    async def acquire_for_request(self, request: ActionRequest) -> CommunicationClaim:
        """Create the request-bound claim required before protected admission."""

        self._require_initialized()
        details = self._request_details(request)
        return await self._acquire(
            action=details.action,
            principal_id=details.principal_id,
            operation_id=details.operation_id,
            request_digest=details.request_digest,
            channel=details.channel,
            peer=details.peer,
        )

    async def _acquire(
        self,
        *,
        action: str,
        principal_id: str,
        operation_id: str,
        request_digest: str,
        channel: str,
        peer: str | None,
    ) -> CommunicationClaim:
        scope = self._scope(action, channel, peer)
        principal = _identity(principal_id, "principal_id")
        operation = _identity(operation_id, "operation_id")
        digest = _identity(request_digest, "request_digest")
        selected = _action(action)
        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            _lock(connection, {scope})
            row = connection.execute(
                "SELECT * FROM communication_claims WHERE scope = ? AND principal_id = ? "
                "AND operation_id = ?",
                (scope, principal, operation),
            ).fetchone()
            if row is not None:
                claim = self._claim(row)
                if claim.active:
                    if claim.request_digest != digest:
                        raise CommunicationsError(
                            "communications claim operation has a different immutable request"
                        )
                    return claim
                raise CommunicationsError("released communications claim cannot be replayed")
            active = connection.execute(
                "SELECT 1 FROM communication_claims WHERE scope = ? AND state = 'active' LIMIT 1",
                (scope,),
            ).fetchone()
            if active is not None:
                raise CommunicationClaimConflict(
                    f"communications scope {scope!r} is already claimed"
                )
            version = advance_scope_version(connection, scope)
            claim_id = _claim_identifier(scope, principal, operation, digest)
            connection.execute(
                "INSERT INTO communication_claims("
                "claim_id, scope, action, principal_id, operation_id, request_digest, "
                "state, version"
                ") VALUES (?, ?, ?, ?, ?, ?, 'active', ?)",
                (claim_id, scope, selected, principal, operation, digest, version),
            )
            return CommunicationClaim(
                claim_id, scope, selected, principal, operation, digest, True, version
            )

    async def release(self, *, claim_id: str, principal_id: str) -> CommunicationClaim:
        self._require_initialized()
        claim_identity = _identity(claim_id, "claim_id")
        principal = _identity(principal_id, "principal_id")
        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            row = connection.execute(
                "SELECT scope FROM communication_claims WHERE claim_id = ?", (claim_identity,)
            ).fetchone()
            if row is None:
                raise CommunicationsError("communications claim is unknown")
            _lock(connection, {cast(str, row["scope"])})
            row = connection.execute(
                "SELECT * FROM communication_claims WHERE claim_id = ?", (claim_identity,)
            ).fetchone()
            if row is None:
                raise CommunicationsError("communications claim is unknown")
            claim = self._claim(row)
            if claim.principal_id != principal:
                raise CommunicationsError("communications claim principal does not match")
            if not claim.active:
                return claim
            version = advance_scope_version(connection, claim.scope)
            connection.execute(
                "UPDATE communication_claims SET state = 'released', version = ? "
                "WHERE claim_id = ?",
                (version, claim.claim_id),
            )
            return CommunicationClaim(
                claim.claim_id,
                claim.scope,
                claim.action,
                claim.principal_id,
                claim.operation_id,
                claim.request_digest,
                False,
                version,
            )

    async def record_delivery(self, *, request: ActionRequest, claim_id: str) -> int:
        """Record one protected delivery for the exact request-bound claim.

        The delivery row persists the claim id. A replay must present that same
        request/claim pair; an active claim for a different operation cannot
        authorize this request.
        """

        async with self._resource.open_session(write=True) as session:
            return self._record_delivery_in_session(session, request, claim_id)

    def _protect_for_request(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> frozenset[str]:
        self._require_initialized()
        details = self._request_details(request)
        _lock(_connection(session), {details.scope})
        return frozenset({details.scope})

    def _record_delivery_for_request_in_session(
        self,
        session: ResourceSession,
        request: ActionRequest,
    ) -> int:
        """Consume the unique active claim already proven by policy evaluation."""

        details = self._request_details(request)
        row = (
            _connection(session)
            .execute(
                "SELECT claim_id FROM communication_claims WHERE scope = ? AND action = ? "
                "AND principal_id = ? AND operation_id = ? AND request_digest = ? "
                "AND state = 'active' LIMIT 2",
                (
                    details.scope,
                    details.action,
                    details.principal_id,
                    details.operation_id,
                    details.request_digest,
                ),
            )
            .fetchall()
        )
        if len(row) != 1:
            raise CommunicationsError(
                "communications protected delivery needs exactly one active request claim"
            )
        return self._record_delivery_in_session(
            session,
            request,
            cast(str, row[0]["claim_id"]),
        )

    def _record_delivery_in_session(
        self,
        session: ResourceSession,
        request: ActionRequest,
        claim_id: str,
    ) -> int:
        self._require_initialized()
        details = self._request_details(request)
        claim_identity = _identity(claim_id, "claim_id")
        peer_key = _delivery_peer_key(details.peer)
        connection = _connection(session)
        _lock(connection, {details.scope})
        row = connection.execute(
            "SELECT action, channel, peer_key, principal_id, operation_id, request_digest "
            "FROM communication_deliveries WHERE claim_id = ?",
            (claim_identity,),
        ).fetchone()
        if row is not None:
            if (
                row["action"] != details.action
                or row["channel"] != details.channel
                or row["peer_key"] != peer_key
                or row["principal_id"] != details.principal_id
                or row["operation_id"] != details.operation_id
                or row["request_digest"] != details.request_digest
            ):
                raise CommunicationsError(
                    "communications delivery replay does not match its claim-bound request"
                )
        else:
            claim_row = connection.execute(
                "SELECT * FROM communication_claims WHERE claim_id = ?",
                (claim_identity,),
            ).fetchone()
            if claim_row is None:
                raise CommunicationsError("communications delivery claim is unknown")
            claim = self._claim(claim_row)
            if not claim.active:
                raise CommunicationsError("communications delivery claim is not active")
            if (
                claim.action != details.action
                or claim.scope != details.scope
                or claim.principal_id != details.principal_id
                or claim.operation_id != details.operation_id
                or claim.request_digest != details.request_digest
            ):
                raise CommunicationsError(
                    "communications delivery does not match its request-bound claim"
                )
            version = advance_scope_version(connection, details.scope)
            connection.execute(
                "INSERT INTO communication_deliveries("
                "claim_id, action, channel, peer_key, principal_id, operation_id, "
                "request_digest, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    claim.claim_id,
                    details.action,
                    details.channel,
                    peer_key,
                    details.principal_id,
                    details.operation_id,
                    details.request_digest,
                    _time(datetime.now(UTC)),
                ),
            )
            connection.execute(
                "INSERT INTO communication_counters("
                "action, channel, peer_key, delivery_count, version"
                ") VALUES (?, ?, ?, 1, ?) "
                "ON CONFLICT(action, channel, peer_key) DO UPDATE SET "
                "delivery_count = communication_counters.delivery_count + 1, "
                "version = excluded.version",
                (details.action, details.channel, peer_key, version),
            )
            connection.execute(
                "UPDATE communication_claims SET state = 'released', version = ? "
                "WHERE claim_id = ? AND state = 'active'",
                (version, claim.claim_id),
            )
        counter = connection.execute(
            "SELECT delivery_count FROM communication_counters WHERE action = ? "
            "AND channel = ? AND peer_key = ?",
            (details.action, details.channel, peer_key),
        ).fetchone()
        if counter is None:
            raise CommunicationsError("communications delivery counter is missing")
        return int(counter["delivery_count"])

    @staticmethod
    def _claim(row: Mapping[str, object]) -> CommunicationClaim:
        return CommunicationClaim(
            cast(str, row["claim_id"]),
            cast(str, row["scope"]),
            cast(str, row["action"]),
            cast(str, row["principal_id"]),
            cast(str, row["operation_id"]),
            cast(str, row["request_digest"]),
            cast(str, row["state"]) == "active",
            int(cast(int, row["version"])),
        )

    def provider_module(
        self,
        protected_runners: Mapping[str, ProtectedExecutionRunner] | None = None,
    ) -> ProviderModule:
        def allowed(
            session: ResourceSession,
            arguments: tuple[Scalar | Duration, ...],
            scope: str,
        ) -> tuple[Scalar, int]:
            self._require_initialized()
            if len(arguments) != 2:
                raise CommunicationsError("comms.peer_allowed requires channel and peer")
            version = scope_version(_connection(session), _canonical_scope(scope))
            return self.policy.contact_allowed(arguments[0], arguments[1]), version

        def delivery_counter(
            session: ResourceSession,
            *,
            action: str,
            channel: str,
            peer_key: str,
            scope: str,
        ) -> tuple[int, int]:
            self._require_initialized()
            row = (
                _connection(session)
                .execute(
                    "SELECT COALESCE((SELECT delivery_count "
                    "FROM communication_counters WHERE action = ? AND channel = ? "
                    "AND peer_key = ?), 0) AS delivery_count, "
                    "COALESCE((SELECT version FROM policy_scope_versions WHERE scope = ?), 0) "
                    "AS scope_version",
                    (action, channel, peer_key, _canonical_scope(scope)),
                )
                .fetchone()
            )
            if row is None:
                raise CommunicationsError("communications counter scope query returned no row")
            return int(row["delivery_count"]), int(row["scope_version"])

        def active_claim(
            session: ResourceSession,
            *,
            action: str,
            principal_id: object,
            operation_id: object,
            request_digest: object,
            channel: object,
            peer: object | None,
        ) -> tuple[Scalar, int]:
            self._require_initialized()
            principal = _identity(principal_id, "principal_id")
            operation = _identity(operation_id, "operation_id")
            digest = _identity(request_digest, "request_digest")
            scope = self._scope(action, channel, peer)
            row = (
                _connection(session)
                .execute(
                    "SELECT (SELECT COUNT(*) FROM (SELECT 1 FROM communication_claims "
                    "WHERE scope = ? AND action = ? AND principal_id = ? "
                    "AND operation_id = ? AND request_digest = ? AND state = 'active' "
                    "LIMIT 2) AS matching_claims) AS active_count, "
                    "COALESCE((SELECT version FROM policy_scope_versions WHERE scope = ?), 0) "
                    "AS scope_version",
                    (scope, _action(action), principal, operation, digest, scope),
                )
                .fetchone()
            )
            if row is None:
                raise CommunicationsError("communications claim scope query returned no row")
            active_count = int(row["active_count"])
            if active_count > 1:
                raise CommunicationsError("communications scope has multiple active claims")
            return active_count == 1, int(row["scope_version"])

        def send_claimed(
            session: ResourceSession,
            arguments: tuple[Scalar | Duration, ...],
            _scope: str,
        ) -> tuple[Scalar, int]:
            if len(arguments) != 5:
                raise CommunicationsError(
                    "comms.send_claimed requires principal id, operation id, request digest, "
                    "channel, and peer"
                )
            return active_claim(
                session,
                action=_SEND_ACTION,
                principal_id=arguments[0],
                operation_id=arguments[1],
                request_digest=arguments[2],
                channel=arguments[3],
                peer=arguments[4],
            )

        def channel_post_claimed(
            session: ResourceSession,
            arguments: tuple[Scalar | Duration, ...],
            _scope: str,
        ) -> tuple[Scalar, int]:
            if len(arguments) != 4:
                raise CommunicationsError(
                    "comms.channel_post_claimed requires principal id, operation id, request "
                    "digest, and channel"
                )
            return active_claim(
                session,
                action=_POST_ACTION,
                principal_id=arguments[0],
                operation_id=arguments[1],
                request_digest=arguments[2],
                channel=arguments[3],
                peer=None,
            )

        def first_contact(
            session: ResourceSession,
            arguments: tuple[Scalar | Duration, ...],
            _scope: str,
        ) -> tuple[Scalar, int]:
            if len(arguments) != 2:
                raise CommunicationsError("comms.first_contact requires channel and peer")
            channel, peer = _identity(arguments[0], "channel"), _identity(arguments[1], "peer")
            count, version = delivery_counter(
                session,
                action=_SEND_ACTION,
                channel=channel,
                peer_key=_delivery_peer_key(peer),
                scope=self._peer_scope(channel, peer),
            )
            return count == 0, version

        def sent_count(
            session: ResourceSession,
            arguments: tuple[Scalar | Duration, ...],
            _scope: str,
        ) -> tuple[Scalar, int]:
            if len(arguments) != 2:
                raise CommunicationsError("comms.message_count requires channel and peer")
            channel, peer = _identity(arguments[0], "channel"), _identity(arguments[1], "peer")
            count, version = delivery_counter(
                session,
                action=_SEND_ACTION,
                channel=channel,
                peer_key=_delivery_peer_key(peer),
                scope=self._peer_scope(channel, peer),
            )
            return count, version

        def post_count(
            session: ResourceSession,
            arguments: tuple[Scalar | Duration, ...],
            _scope: str,
        ) -> tuple[Scalar, int]:
            if len(arguments) != 1:
                raise CommunicationsError("comms.channel_post_count requires a channel")
            channel = _identity(arguments[0], "channel")
            count, version = delivery_counter(
                session,
                action=_POST_ACTION,
                channel=channel,
                peer_key=_delivery_peer_key(None),
                scope=self._channel_scope(channel),
            )
            return count, version

        def peer_scope(arguments: tuple[Scalar | Duration, ...]) -> str:
            if len(arguments) != 2:
                raise CommunicationsError("communications peer view requires channel and peer")
            return self._peer_scope(arguments[0], arguments[1])

        def channel_scope(arguments: tuple[Scalar | Duration, ...]) -> str:
            if len(arguments) != 1:
                raise CommunicationsError("communications channel view requires a channel")
            return self._channel_scope(arguments[0])

        def send_claim_scope(arguments: tuple[Scalar | Duration, ...]) -> str:
            if len(arguments) != 5:
                raise CommunicationsError(
                    "comms.send_claimed requires principal id, operation id, request digest, "
                    "channel, and peer"
                )
            _identity(arguments[0], "principal_id")
            _identity(arguments[1], "operation_id")
            _identity(arguments[2], "request_digest")
            return self._peer_scope(arguments[3], arguments[4])

        def channel_post_claim_scope(arguments: tuple[Scalar | Duration, ...]) -> str:
            if len(arguments) != 4:
                raise CommunicationsError(
                    "comms.channel_post_claimed requires principal id, operation id, request "
                    "digest, and channel"
                )
            _identity(arguments[0], "principal_id")
            _identity(arguments[1], "operation_id")
            _identity(arguments[2], "request_digest")
            return self._channel_scope(arguments[3])

        def footprint(action: str) -> Callable[[ActionRequest], ResourceFootprint]:
            def resolve(request: ActionRequest) -> ResourceFootprint:
                if request.action != action:
                    raise CommunicationsError("communications effect action mismatch")
                if action == _SEND_ACTION:
                    if set(request.arguments) != {"channel", "peer", "content_digest"}:
                        raise CommunicationsError("send_message arguments are malformed")
                    scope = self._scope(
                        action, request.arguments["channel"], request.arguments["peer"]
                    )
                    _identity(request.arguments["content_digest"], "content_digest")
                else:
                    if set(request.arguments) != {"channel", "content_digest", "broadcast"}:
                        raise CommunicationsError("channel.post arguments are malformed")
                    if type(request.arguments["broadcast"]) is not bool:
                        raise CommunicationsError("channel.post broadcast must be bool")
                    scope = self._scope(action, request.arguments["channel"])
                    _identity(request.arguments["content_digest"], "content_digest")
                return ResourceFootprint(writes=frozenset({scope}))

            return resolve

        identity = self.policy.provider_identity
        views = (
            GovernanceViewContract(
                "comms.peer_allowed",
                (TypeName.STRING, TypeName.STRING),
                TypeName.BOOL,
                _COMMUNICATIONS_MODULE_ID,
                "scoped-policy-state",
                100,
                True,
                peer_scope,
                allowed,
                ReservationViewKind.UNSUPPORTED,
                provider_identity=identity,
            ),
            GovernanceViewContract(
                "comms.send_claimed",
                (
                    TypeName.STRING,
                    TypeName.STRING,
                    TypeName.STRING,
                    TypeName.STRING,
                    TypeName.STRING,
                ),
                TypeName.BOOL,
                _COMMUNICATIONS_MODULE_ID,
                "scoped-policy-state",
                100,
                True,
                send_claim_scope,
                send_claimed,
                ReservationViewKind.UNSUPPORTED,
                provider_identity=identity,
            ),
            GovernanceViewContract(
                "comms.first_contact",
                (TypeName.STRING, TypeName.STRING),
                TypeName.BOOL,
                _COMMUNICATIONS_MODULE_ID,
                "scoped-policy-state",
                100,
                True,
                peer_scope,
                first_contact,
                ReservationViewKind.UNSUPPORTED,
                provider_identity=identity,
            ),
            GovernanceViewContract(
                "comms.message_count",
                (TypeName.STRING, TypeName.STRING),
                TypeName.INT,
                _COMMUNICATIONS_MODULE_ID,
                "scoped-policy-state",
                100,
                True,
                peer_scope,
                sent_count,
                ReservationViewKind.UNSUPPORTED,
                provider_identity=identity,
            ),
            GovernanceViewContract(
                "comms.channel_post_count",
                (TypeName.STRING,),
                TypeName.INT,
                _COMMUNICATIONS_MODULE_ID,
                "scoped-policy-state",
                100,
                True,
                channel_scope,
                post_count,
                ReservationViewKind.UNSUPPORTED,
                provider_identity=identity,
            ),
            GovernanceViewContract(
                "comms.channel_post_claimed",
                (TypeName.STRING, TypeName.STRING, TypeName.STRING, TypeName.STRING),
                TypeName.BOOL,
                _COMMUNICATIONS_MODULE_ID,
                "scoped-policy-state",
                100,
                True,
                channel_post_claim_scope,
                channel_post_claimed,
                ReservationViewKind.UNSUPPORTED,
                provider_identity=identity,
            ),
        )
        bindings = tuple(
            EffectBinding(
                EffectContract(
                    action,
                    arguments,
                    _COMMUNICATIONS_MODULE_ID,
                    ConsistencyGuarantee.POLICY_STATE_SERIALIZABLE,
                    footprint(action),
                    ProtectedExternalExecutor(_CONNECTOR_ID),
                    provider_identity=identity,
                ),
                EffectExecutionPosition.PROTECTED_EXTERNAL,
                _CONNECTOR_ID,
            )
            for action, arguments in (
                (
                    _SEND_ACTION,
                    {
                        "channel": TypeName.STRING,
                        "peer": TypeName.STRING,
                        "content_digest": TypeName.STRING,
                    },
                ),
                (
                    _POST_ACTION,
                    {
                        "channel": TypeName.STRING,
                        "content_digest": TypeName.STRING,
                        "broadcast": TypeName.BOOL,
                    },
                ),
            )
        )
        runners = {} if protected_runners is None else dict(protected_runners)
        if set(runners) - {_SEND_ACTION, _POST_ACTION}:
            raise CommunicationsError("communications module received an unknown protected runner")
        return ProviderModule(
            _COMMUNICATIONS_MODULE_ID,
            identity,
            self._domain,
            self._domain.scope_derivation_id,
            views,
            bindings,
            protected_executions=tuple(
                ProtectedExecutionRegistration(action, runner)
                for action, runner in sorted(runners.items())
            ),
        )


class ApprovalStateProvider:
    """Persistent MasuGate policy approval facts, independent of host presentation."""

    def __init__(self, state: PolicyApprovalState, domain: CoordinationDomain) -> None:
        if type(state) is not PolicyApprovalState or type(domain) is not CoordinationDomain:
            raise TypeError("approval state provider requires state and coordination domain")
        self.state = state
        self._domain = domain
        self._resource = cast(_SessionResource, domain.resource)

    async def initialize(self) -> None:
        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            script = """
                CREATE TABLE IF NOT EXISTS approval_state_provider_configuration (
                    state_id TEXT PRIMARY KEY,
                    configuration_digest TEXT NOT NULL,
                    configuration_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS approval_policy_grants (
                    state_id TEXT NOT NULL REFERENCES
                        approval_state_provider_configuration(state_id),
                    subject TEXT NOT NULL,
                    action TEXT NOT NULL,
                    PRIMARY KEY(state_id, subject, action)
                );
            """
            execute_script = getattr(connection, "executescript", None)
            if not callable(execute_script):
                raise CommunicationsError("approval state resource cannot initialize SQL state")
            execute_script(script)
            payload = _json(self.state.payload)
            row = connection.execute(
                "SELECT configuration_digest, configuration_json FROM "
                "approval_state_provider_configuration WHERE state_id = ?",
                (self.state.state_id,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO approval_state_provider_configuration("
                    "state_id, configuration_digest, configuration_json, created_at"
                    ") VALUES (?, ?, ?, ?)",
                    (self.state.state_id, self.state.digest, payload, _time(datetime.now(UTC))),
                )
                for subject, action in self.state.grants:
                    connection.execute(
                        "INSERT INTO approval_policy_grants("
                        "state_id, subject, action) VALUES (?, ?, ?)",
                        (self.state.state_id, subject, action),
                    )
            elif (
                row["configuration_digest"] != self.state.digest
                or row["configuration_json"] != payload
            ):
                raise CommunicationsError("durable approval policy state does not match")
            durable_grants = tuple(
                (
                    cast(str, grant["subject"]),
                    cast(str, grant["action"]),
                )
                for grant in connection.execute(
                    "SELECT subject, action FROM approval_policy_grants "
                    "WHERE state_id = ? ORDER BY subject, action",
                    (self.state.state_id,),
                ).fetchall()
            )
            if durable_grants != self.state.grants:
                raise CommunicationsError("durable approval grants do not match configuration")

    def provider_module(self) -> ProviderModule:
        def granted(
            session: ResourceSession,
            arguments: tuple[Scalar | Duration, ...],
            _scope: str,
        ) -> tuple[Scalar, int]:
            if len(arguments) != 2:
                raise CommunicationsError("approval.policy_granted requires subject and action")
            subject, action = _identity(arguments[0], "subject"), _action(arguments[1])
            row = (
                _connection(session)
                .execute(
                    "SELECT 1 FROM approval_policy_grants WHERE state_id = ? AND subject = ? "
                    "AND action = ?",
                    (self.state.state_id, subject, action),
                )
                .fetchone()
            )
            return row is not None, 1

        def scope(arguments: tuple[Scalar | Duration, ...]) -> str:
            if len(arguments) != 2:
                raise CommunicationsError("approval policy view requires subject and action")
            subject = _identity(arguments[0], "subject")
            action = _action(arguments[1])
            return (
                "approval:policy:"
                f"{_scope_component(self.state.state_id)}:"
                f"{_scope_component(subject)}:{_scope_component(action)}"
            )

        view = GovernanceViewContract(
            "approval.policy_granted",
            (TypeName.STRING, TypeName.STRING),
            TypeName.BOOL,
            _APPROVAL_MODULE_ID,
            "scoped-policy-state",
            100,
            True,
            scope,
            granted,
            ReservationViewKind.UNSUPPORTED,
            provider_identity=self.state.provider_identity,
        )
        return ProviderModule(
            _APPROVAL_MODULE_ID,
            self.state.provider_identity,
            self._domain,
            self._domain.scope_derivation_id,
            (view,),
        )


__all__ = [
    "ApprovalStateProvider",
    "CommunicationClaim",
    "CommunicationClaimConflict",
    "CommunicationsError",
    "CommunicationsPolicy",
    "CommunicationsProvider",
    "PolicyApprovalState",
]
