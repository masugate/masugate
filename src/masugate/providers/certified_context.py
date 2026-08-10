"""Certified clocks and principal capability context for governed policy input.

The provider intentionally models only a small, configuration-backed reference
context.  It is the trust boundary that turns a protected server clock and a
deployment-owned capability map into the typed ``certified.*`` facts policy can
read.  It does not accept timezone, clock, identity, or capability assertions
from an :class:`~masugate.model.ActionRequest`.

The three facts have deliberately different temporal semantics:

* ``certified.request_time_window_open`` is evaluated at the immutable,
  provider-certified request-time anchor and is request-bound immutable;
* ``certified.live_resolution_window_open`` is evaluated at every protected
  authorization evaluation and is resolution-volatile; and
* ``certified.capability_permitted`` is a request-bound immutable lookup in the
  versioned deployment capability context.

All values pass through the generic certified-context surface, which records
source identity/version, observation and certification times, TTL, stability,
and evaluation phase in durable authorization provenance.
"""

from __future__ import annotations

import hashlib
import json
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, cast
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from masugate.contracts import (
    CertifiedInputContract,
    CertifiedInputObservation,
    ProviderIdentity,
    ResourceSession,
)
from masugate.errors import ResourceError
from masugate.model import (
    ActionRequest,
    CertifiedInputStability,
    CertifiedInputStabilityProof,
    Duration,
    JsonValue,
    TypeName,
)
from masugate.provider_assembly import CoordinationDomain, ProviderModule

_MODULE_ID = "certified-context"
_IMPLEMENTATION_VERSION = "masugate.certified-context-v1"
_CLOCK_SOURCE_ID = "masugate.reference.clock"
_CAPABILITY_SOURCE_ID = "masugate.reference.capabilities"
_CONTRACT_VERSION = "certified-context-v1"
_REQUEST_WINDOW = "certified.request_time_window_open"
_LIVE_WINDOW = "certified.live_resolution_window_open"
_CAPABILITY = "certified.capability_permitted"
_DAY_MINUTES = 24 * 60


class CertifiedContextError(ResourceError):
    """A trusted clock or capability source cannot provide safe policy input."""


class _SessionResource(Protocol):
    def open_session(self, *, write: bool) -> AbstractAsyncContextManager[ResourceSession]: ...


class CertifiedContextClock(Protocol):
    """Read one authoritative time while the caller holds a resource session."""

    def now(self, session: ResourceSession) -> datetime: ...


class CertifiedContextSource(Protocol):
    """Trusted source adapter for the three declared certified facts."""

    def request_time_window(
        self,
        session: ResourceSession,
        request: ActionRequest,
        observation_time: datetime,
    ) -> CertifiedInputObservation: ...

    def live_resolution_window(
        self,
        session: ResourceSession,
        request: ActionRequest,
        observation_time: datetime,
    ) -> CertifiedInputObservation: ...

    def capability_permitted(
        self,
        session: ResourceSession,
        request: ActionRequest,
        observation_time: datetime,
    ) -> CertifiedInputObservation: ...


def _canonical(value: object, field_name: str) -> str:
    if not (
        type(value) is str
        and 0 < len(value) <= 255
        and value.strip() == value
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise ValueError(f"{field_name} must be a canonical identity")
    return value


def _action(value: object, field_name: str) -> str:
    result = _canonical(value, field_name)
    pieces = result.split(".")
    if any(not piece or not (piece[0].isalpha() or piece[0] == "_") for piece in pieces):
        raise ValueError(f"{field_name} must be a canonical action")
    if any(
        not all(character.isalnum() or character == "_" for character in piece) for piece in pieces
    ):
        raise ValueError(f"{field_name} must be a canonical action")
    return result


def _aware(value: object, field_name: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise CertifiedContextError(f"{field_name} must be timezone-aware")
    return value


def _json(value: JsonValue) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _digest(value: JsonValue) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _connection(session: ResourceSession) -> Any:
    connection = getattr(session, "connection", None)
    if connection is None or not callable(getattr(connection, "execute", None)):
        raise CertifiedContextError(
            "certified context requires a resource-owned durable SQL session"
        )
    return connection


@dataclass(frozen=True)
class CertifiedContextPolicy:
    """Immutable timezone/window and principal-capability configuration.

    The daily half-open window is expressed in minutes in ``timezone``.  A
    window may span midnight; equal endpoints explicitly mean an all-day
    window, so configuration has no ambient-clock or empty-window ambiguity.
    Principal capabilities are a sorted, closed configuration map keyed by
    the already-authenticated identity supplied at the outer MasuGate boundary.
    """

    context_id: str
    configuration_version: str
    timezone: str
    window_start_minute: int
    window_end_minute: int
    principal_capabilities: tuple[tuple[str, tuple[str, ...]], ...]
    freshness_ttl_seconds: int = 60

    def __post_init__(self) -> None:
        _canonical(self.context_id, "certified context_id")
        configuration_version = _canonical(
            self.configuration_version, "certified context configuration_version"
        )
        if len(configuration_version) + 1 + 64 > 255:
            raise ValueError(
                "certified context configuration_version is too long for source version"
            )
        timezone = _canonical(self.timezone, "certified context timezone")
        try:
            ZoneInfo(timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("certified context timezone is unknown") from exc
        for field_name in ("window_start_minute", "window_end_minute"):
            value = getattr(self, field_name)
            if type(value) is not int or not 0 <= value < _DAY_MINUTES:
                raise ValueError(f"{field_name} must be a minute in one day")
        if type(self.freshness_ttl_seconds) is not int or self.freshness_ttl_seconds <= 0:
            raise ValueError("freshness_ttl_seconds must be a positive integer")

        capabilities = tuple(
            (
                _canonical(principal_id, "certified capability principal_id"),
                tuple(_action(action, "certified capability action") for action in actions),
            )
            for principal_id, actions in self.principal_capabilities
        )
        if capabilities != tuple(sorted(capabilities, key=lambda item: item[0])):
            raise ValueError("principal_capabilities must be sorted by principal identity")
        if len({principal_id for principal_id, _actions in capabilities}) != len(capabilities):
            raise ValueError("principal_capabilities must have unique principal identities")
        for _principal_id, actions in capabilities:
            if (
                not actions
                or actions != tuple(sorted(actions))
                or len(set(actions)) != len(actions)
            ):
                raise ValueError(
                    "each principal capability set must be sorted, non-empty, and unique"
                )
        object.__setattr__(self, "principal_capabilities", capabilities)

    @property
    def payload(self) -> dict[str, JsonValue]:
        return {
            "principal_capabilities": [
                {"principal_id": principal_id, "actions": list(actions)}
                for principal_id, actions in self.principal_capabilities
            ],
            "configuration_version": self.configuration_version,
            "context_id": self.context_id,
            "freshness_ttl_seconds": self.freshness_ttl_seconds,
            "schema": "masugate.certified-context.v1",
            "timezone": self.timezone,
            "window_end_minute": self.window_end_minute,
            "window_start_minute": self.window_start_minute,
        }

    @property
    def digest(self) -> str:
        return _digest(self.payload)

    @property
    def source_version(self) -> str:
        """The immutable source/configuration identity recorded in evidence."""

        return f"{self.configuration_version}-{self.digest}"

    @property
    def provider_identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="masugate.certified-context",
            implementation_version=_IMPLEMENTATION_VERSION,
            configuration_version=self.digest,
        )

    @property
    def freshness_ttl(self) -> Duration:
        return Duration(self.freshness_ttl_seconds)

    def window_open(self, at: datetime) -> bool:
        instant = _aware(at, "certified context clock")
        local = instant.astimezone(ZoneInfo(self.timezone))
        minute = local.hour * 60 + local.minute
        if self.window_start_minute == self.window_end_minute:
            return True
        if self.window_start_minute < self.window_end_minute:
            return self.window_start_minute <= minute < self.window_end_minute
        return minute >= self.window_start_minute or minute < self.window_end_minute

    def capability_permitted(self, principal_id: object, action: object) -> bool:
        principal = _canonical(principal_id, "certified capability principal_id")
        requested_action = _action(action, "certified capability action")
        for configured_principal, actions in self.principal_capabilities:
            if configured_principal == principal:
                return requested_action in actions
        return False


class SqlSessionCertifiedClock:
    """Read UTC server time from the current SQLite/PostgreSQL transaction."""

    def now(self, session: ResourceSession) -> datetime:
        connection = _connection(session)
        if hasattr(connection, "raw"):
            row = connection.execute("SELECT clock_timestamp() AS certified_at").fetchone()
        else:
            row = connection.execute(
                "SELECT strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now') AS certified_at"
            ).fetchone()
        if row is None:
            raise CertifiedContextError("certified context clock did not return a timestamp")
        raw = row["certified_at"]
        if type(raw) is str:
            try:
                observed = datetime.fromisoformat(raw)
            except ValueError as exc:
                raise CertifiedContextError(
                    "certified context clock returned malformed time"
                ) from exc
        else:
            observed = raw
        return _aware(observed, "certified context clock").astimezone(UTC)


class ReferenceCertifiedContextSource:
    """The reference configuration projection used by the default provider."""

    def __init__(self, policy: CertifiedContextPolicy) -> None:
        self._policy = policy

    def _observation(self, value: bool, observed_at: datetime) -> CertifiedInputObservation:
        return CertifiedInputObservation(
            value=value,
            source_version=self._policy.source_version,
            observed_at=observed_at,
        )

    def request_time_window(
        self,
        session: ResourceSession,
        request: ActionRequest,
        observation_time: datetime,
    ) -> CertifiedInputObservation:
        del session, observation_time
        return self._observation(self._policy.window_open(request.timestamp), request.timestamp)

    def live_resolution_window(
        self,
        session: ResourceSession,
        request: ActionRequest,
        observation_time: datetime,
    ) -> CertifiedInputObservation:
        del session, request
        return self._observation(self._policy.window_open(observation_time), observation_time)

    def capability_permitted(
        self,
        session: ResourceSession,
        request: ActionRequest,
        observation_time: datetime,
    ) -> CertifiedInputObservation:
        del session
        return self._observation(
            self._policy.capability_permitted(request.principal.id, request.action),
            request.timestamp if request.timestamp <= observation_time else observation_time,
        )


class CertifiedContextProvider:
    """Expose clocks and principal capabilities in one coordination domain."""

    def __init__(
        self,
        policy: CertifiedContextPolicy,
        domain: CoordinationDomain,
        *,
        source: CertifiedContextSource | None = None,
        clock: CertifiedContextClock | None = None,
    ) -> None:
        if type(policy) is not CertifiedContextPolicy or type(domain) is not CoordinationDomain:
            raise TypeError("certified context provider requires policy and coordination domain")
        self.policy = policy
        self._domain = domain
        self._resource = cast(_SessionResource, domain.resource)
        self._source = source or ReferenceCertifiedContextSource(policy)
        self._clock = clock or SqlSessionCertifiedClock()
        self._contracts = (
            self._contract(
                name=_REQUEST_WINDOW,
                source_id=_CLOCK_SOURCE_ID,
                stability=CertifiedInputStability.ADMISSION_STABLE,
                resolver=self._request_time_window,
            ),
            self._contract(
                name=_LIVE_WINDOW,
                source_id=_CLOCK_SOURCE_ID,
                stability=CertifiedInputStability.RESOLUTION_VOLATILE,
                resolver=self._live_resolution_window,
            ),
            self._contract(
                name=_CAPABILITY,
                source_id=_CAPABILITY_SOURCE_ID,
                stability=CertifiedInputStability.ADMISSION_STABLE,
                resolver=self._capability_permitted,
            ),
        )

    def _contract(
        self,
        *,
        name: str,
        source_id: str,
        stability: CertifiedInputStability,
        resolver: object,
    ) -> CertifiedInputContract:
        proof = (
            CertifiedInputStabilityProof.REQUEST_BOUND_IMMUTABLE_V1
            if stability is CertifiedInputStability.ADMISSION_STABLE
            else None
        )
        return CertifiedInputContract(
            name=name,
            value_type=TypeName.BOOL,
            stability=stability,
            stability_proof=proof,
            source_id=source_id,
            contract_version=_CONTRACT_VERSION,
            freshness_ttl=self.policy.freshness_ttl,
            resolver=cast(Any, resolver),
            provider_identity=self.policy.provider_identity,
            expected_source_version=self.policy.source_version,
        )

    def _checked_observation(self, value: object) -> CertifiedInputObservation:
        if type(value) is not CertifiedInputObservation:
            raise CertifiedContextError("certified context source returned a malformed observation")
        observation = value
        if observation.source_version != self.policy.source_version:
            raise CertifiedContextError(
                "certified context source version does not match configuration"
            )
        return observation

    def _request_time_window(
        self,
        session: ResourceSession,
        request: ActionRequest,
        observation_time: datetime,
    ) -> CertifiedInputObservation:
        return self._checked_observation(
            self._source.request_time_window(session, request, observation_time)
        )

    def _live_resolution_window(
        self,
        session: ResourceSession,
        request: ActionRequest,
        observation_time: datetime,
    ) -> CertifiedInputObservation:
        return self._checked_observation(
            self._source.live_resolution_window(session, request, observation_time)
        )

    def _capability_permitted(
        self,
        session: ResourceSession,
        request: ActionRequest,
        observation_time: datetime,
    ) -> CertifiedInputObservation:
        return self._checked_observation(
            self._source.capability_permitted(session, request, observation_time)
        )

    @property
    def certified_input_contracts(self) -> tuple[CertifiedInputContract, ...]:
        return self._contracts

    def certified_now(self, session: ResourceSession) -> datetime:
        """Read an authoritative clock only from the protected resource session."""

        return _aware(self._clock.now(session), "certified context clock").astimezone(UTC)

    async def initialize(self) -> None:
        """Persist and reject drift in the immutable context configuration."""

        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            execute_script = getattr(connection, "executescript", None)
            script = """
                CREATE TABLE IF NOT EXISTS certified_context_provider_configuration (
                    context_id TEXT PRIMARY KEY,
                    configuration_digest TEXT NOT NULL,
                    configuration_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """
            if callable(execute_script):
                execute_script(script)
            else:
                connection.execute(script)
            existing = connection.execute(
                "SELECT configuration_digest, configuration_json "
                "FROM certified_context_provider_configuration WHERE context_id = ?",
                (self.policy.context_id,),
            ).fetchone()
            payload = _json(self.policy.payload)
            if existing is None:
                connection.execute(
                    "INSERT INTO certified_context_provider_configuration "
                    "(context_id, configuration_digest, configuration_json, created_at) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        self.policy.context_id,
                        self.policy.digest,
                        payload,
                        self.certified_now(session).isoformat(),
                    ),
                )
            elif (
                existing["configuration_digest"] != self.policy.digest
                or existing["configuration_json"] != payload
            ):
                raise CertifiedContextError("certified context configuration drifted")

    def provider_module(self) -> ProviderModule:
        return ProviderModule(
            module_id=_MODULE_ID,
            identity=self.policy.provider_identity,
            domain=self._domain,
            scope_derivation_id=self._domain.scope_derivation_id,
            certified_inputs=self._contracts,
        )


__all__ = [
    "CertifiedContextClock",
    "CertifiedContextError",
    "CertifiedContextPolicy",
    "CertifiedContextProvider",
    "CertifiedContextSource",
    "ReferenceCertifiedContextSource",
    "SqlSessionCertifiedClock",
]
