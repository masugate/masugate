"""Narrow, durable policy state for one MasuGate-managed calendar.

The provider owns the authorization-time event ledger. It makes no claim that
external calendar edits are serialized; the connector only receives identifiers
derived and recorded here through a protected execution binding.
"""

from __future__ import annotations

import hashlib
import inspect
import json
from collections.abc import Callable, Mapping
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, time, timedelta
from typing import Any, Protocol, cast
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from masugate.contracts import EffectContract, ProviderIdentity, ResourceSession
from masugate.errors import ContractError
from masugate.model import (
    ActionRequest,
    ConsistencyGuarantee,
    JsonValue,
    ResourceFootprint,
    TypeName,
)
from masugate.protected_execution import (
    ProtectedExecutionBinding,
    ProtectedExecutionRecord,
    ProtectedExecutionRunner,
    ProtectedExecutionStatus,
)
from masugate.provider_assembly import (
    CoordinationDomain,
    EffectBinding,
    EffectExecutionPosition,
    ProtectedExecutionRegistration,
    ProtectedExternalExecutor,
    ProviderModule,
)
from masugate.scope_versions import SCOPE_VERSIONS_SCHEMA

_MODULE_ID = "calendar"
_CREATE = "calendar.event.create"
_CANCEL = "calendar.event.cancel"
_IMPLEMENTATION = "masugate.calendar-provider-v1"


class CalendarError(ContractError):
    """A calendar request or durable state transition is unsafe."""


class _SessionResource(Protocol):
    def open_session(self, *, write: bool) -> AbstractAsyncContextManager[ResourceSession]: ...


def _identity(value: object, field_name: str) -> str:
    if not (
        type(value) is str
        and 0 < len(value) <= 255
        and value.strip() == value
        and all(0x21 <= ord(char) <= 0x7E for char in value)
    ):
        raise ValueError(f"{field_name} must be a canonical identity")
    return value


def _digest(value: JsonValue) -> str:
    return hashlib.sha256(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _request_digest(request: ActionRequest) -> str:
    """Digest only governed, model-visible request facts for durable replay."""

    return _digest(
        {
            "action": request.action,
            "arguments": dict(request.arguments),
            "idempotency_key": request.idempotency_key,
            "operation_id": request.operation_id,
            "principal_id": request.principal.id,
        }
    )


def _connection(session: ResourceSession) -> Any:
    if callable(getattr(session, "execute", None)) and hasattr(session, "connection"):
        # AsyncPostgresLedger yields its resource-owned PostgresSession. Keeping
        # that wrapper preserves transaction accounting and lets this provider
        # issue PostgreSQL statements without reaching around it.
        return session
    connection = getattr(session, "connection", None)
    if connection is None or not callable(getattr(connection, "execute", None)):
        raise CalendarError("calendar provider requires a durable SQL resource session")
    return connection


def _is_postgres(connection: Any) -> bool:
    return callable(getattr(connection, "execute", None)) and hasattr(connection, "connection")


def _sql(connection: Any, statement: str) -> str:
    """Adapt this provider's fixed internal SQL to psycopg placeholders."""

    return statement.replace("?", "%s") if _is_postgres(connection) else statement


async def _execute(connection: Any, statement: str, params: tuple[object, ...] = ()) -> Any:
    result = connection.execute(_sql(connection, statement), params)
    return await result if inspect.isawaitable(result) else result


async def _fetchone(connection: Any, statement: str, params: tuple[object, ...] = ()) -> Any | None:
    cursor = await _execute(connection, statement, params)
    result = cursor.fetchone()
    return await result if inspect.isawaitable(result) else result


async def _execute_script(connection: Any, script: str) -> None:
    if not _is_postgres(connection):
        execute_script = getattr(connection, "executescript", None)
        if not callable(execute_script):
            raise CalendarError("calendar resource cannot initialize SQL state")
        execute_script(script)
        return
    # The schema below is fixed, contains no data values, and has no embedded
    # semicolons. Splitting it keeps initialization portable across sqlite and
    # psycopg without accepting caller-provided SQL.
    for statement in script.split(";"):
        if statement.strip():
            await _execute(connection, statement)


async def _advance_scope_version(connection: Any, scope: str) -> int:
    await _execute(
        connection,
        "INSERT INTO policy_scope_versions(scope, version) VALUES (?, 1) "
        "ON CONFLICT(scope) DO UPDATE SET "
        "version = policy_scope_versions.version + 1",
        (scope,),
    )
    row = await _fetchone(
        connection, "SELECT version FROM policy_scope_versions WHERE scope = ?", (scope,)
    )
    if row is None or int(row["version"]) <= 0:
        raise CalendarError(f"policy scope {scope!r} did not advance")
    return int(row["version"])


async def _lock(connection: Any, scope: str) -> None:
    if _is_postgres(connection):
        key = int.from_bytes(
            hashlib.blake2b(scope.encode("utf-8"), digest_size=8).digest(), "big", signed=True
        )
        await _execute(connection, "SELECT pg_advisory_xact_lock(?)", (key,))


def _parse_time(value: object, field_name: str) -> datetime:
    if type(value) is not str or not value or len(value) > 64:
        raise CalendarError(f"{field_name} must be a bounded RFC3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CalendarError(f"{field_name} must be RFC3339") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CalendarError(f"{field_name} must include an explicit offset")
    return parsed


def _utcnow() -> datetime:
    return datetime.now(UTC)


def google_event_id(event_ref: str) -> str:
    """A Google base32hex-valid, immutable id derived from MasuGate state."""

    _identity(event_ref, "event_ref")
    # All characters in ``masugate`` + lowercase hex are Google base32hex characters.
    return "masugate" + hashlib.sha256(event_ref.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CalendarPolicy:
    calendar_id: str
    connector_id: str
    allowed_timezones: tuple[str, ...]
    working_days: tuple[int, ...] = (0, 1, 2, 3, 4)
    workday_start: time = time(9)  # noqa: RUF009 - immutable fixed policy default
    workday_end: time = time(17)  # noqa: RUF009 - immutable fixed policy default
    future_horizon_days: int = 90
    max_duration_minutes: int = 120

    def __post_init__(self) -> None:
        calendar_id = _identity(self.calendar_id, "calendar_id")
        connector_id = _identity(self.connector_id, "connector_id")
        zones = tuple(_identity(zone, "allowed timezone") for zone in self.allowed_timezones)
        if not zones or zones != tuple(sorted(set(zones))):
            raise ValueError("calendar allowed_timezones must be sorted and unique")
        for zone in zones:
            try:
                ZoneInfo(zone)
            except ZoneInfoNotFoundError as exc:
                raise ValueError("calendar allowed timezone is not an IANA timezone") from exc
        days = tuple(self.working_days)
        if not days or days != tuple(sorted(set(days))) or any(day not in range(7) for day in days):
            raise ValueError("calendar working_days must be sorted unique weekdays")
        if type(self.workday_start) is not time or type(self.workday_end) is not time:
            raise TypeError("calendar working hours must be time values")
        if self.workday_start.tzinfo is not None or self.workday_end.tzinfo is not None:
            raise ValueError("calendar working hours must be local naive times")
        if self.workday_start >= self.workday_end:
            raise ValueError("calendar workday_start must precede workday_end")
        if type(self.future_horizon_days) is not int or not 1 <= self.future_horizon_days <= 366:
            raise ValueError("calendar future_horizon_days must be between 1 and 366")
        if type(self.max_duration_minutes) is not int or not 1 <= self.max_duration_minutes <= 720:
            raise ValueError("calendar max_duration_minutes must be between 1 and 720")
        object.__setattr__(self, "calendar_id", calendar_id)
        object.__setattr__(self, "connector_id", connector_id)
        object.__setattr__(self, "allowed_timezones", zones)
        object.__setattr__(self, "working_days", days)

    @property
    def payload(self) -> dict[str, JsonValue]:
        return {
            "allowed_timezones": list(self.allowed_timezones),
            "calendar_id": self.calendar_id,
            "connector_id": self.connector_id,
            "future_horizon_days": self.future_horizon_days,
            "max_duration_minutes": self.max_duration_minutes,
            "scope_scheme": "masugate.calendar.one-calendar.v1",
            "workday_end": self.workday_end.isoformat(),
            "workday_start": self.workday_start.isoformat(),
            "working_days": list(self.working_days),
        }

    @property
    def digest(self) -> str:
        return _digest(self.payload)

    @property
    def provider_identity(self) -> ProviderIdentity:
        return ProviderIdentity("masugate.calendar", _IMPLEMENTATION, self.digest)


@dataclass(frozen=True)
class CalendarReservation:
    event_ref: str
    action: str
    request_digest: str
    external_event_id: str
    state: str


class CalendarProvider:
    """Durable event ledger and one conservative calendar-wide write scope."""

    def __init__(
        self,
        policy: CalendarPolicy,
        domain: CoordinationDomain,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if type(policy) is not CalendarPolicy or type(domain) is not CoordinationDomain:
            raise TypeError("calendar provider needs CalendarPolicy and CoordinationDomain")
        self.policy = policy
        self._domain = domain
        self._resource = cast(_SessionResource, domain.resource)
        self._clock: Callable[[], datetime] = _utcnow if clock is None else clock
        self._initialized = False

    @property
    def scope(self) -> str:
        return "calendar:managed:" + self.policy.calendar_id

    @property
    def domain_id(self) -> str:
        """Configured durable coordination-domain identifier."""
        return self._domain.domain_id

    def _now(self) -> datetime:
        now = self._clock()
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset() is None:
            raise CalendarError("calendar clock must return a timezone-aware datetime")
        return now

    async def initialize(self) -> None:
        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            await _execute_script(
                connection,
                SCOPE_VERSIONS_SCHEMA
                + """
                CREATE TABLE IF NOT EXISTS calendar_provider_configuration (
                  calendar_id TEXT PRIMARY KEY, configuration_digest TEXT NOT NULL,
                  configuration_json TEXT NOT NULL, created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS calendar_event_ledger (
                  event_ref TEXT PRIMARY KEY, request_digest TEXT NOT NULL UNIQUE,
                  principal_id TEXT NOT NULL, operation_id TEXT NOT NULL, action TEXT NOT NULL,
                  title TEXT NOT NULL, description TEXT NOT NULL, start_at TEXT NOT NULL,
                  end_at TEXT NOT NULL, timezone TEXT NOT NULL, external_event_id TEXT NOT NULL,
                  execution_id TEXT, state TEXT NOT NULL, created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  UNIQUE(principal_id, operation_id, action)
                );
                CREATE TABLE IF NOT EXISTS calendar_cancellation_ledger (
                  request_digest TEXT PRIMARY KEY, principal_id TEXT NOT NULL,
                  operation_id TEXT NOT NULL,
                  event_ref TEXT NOT NULL REFERENCES calendar_event_ledger(event_ref),
                  execution_id TEXT,
                  state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                  UNIQUE(principal_id, operation_id)
                );
                """,
            )
            payload = json.dumps(
                self.policy.payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            )
            row = await _fetchone(
                connection,
                "SELECT configuration_digest, configuration_json "
                "FROM calendar_provider_configuration "
                "WHERE calendar_id = ?",
                (self.policy.calendar_id,),
            )
            if row is None:
                await _execute(
                    connection,
                    "INSERT INTO calendar_provider_configuration("
                    "calendar_id, configuration_digest, "
                    "configuration_json, created_at) VALUES (?, ?, ?, ?)",
                    (self.policy.calendar_id, self.policy.digest, payload, self._now().isoformat()),
                )
            elif (
                row["configuration_digest"] != self.policy.digest
                or row["configuration_json"] != payload
            ):
                raise CalendarError("durable calendar configuration does not match deployment")
        self._initialized = True

    def _require_initialized(self) -> None:
        if not self._initialized:
            raise CalendarError("calendar provider must be initialized")

    def _create_arguments(
        self, request: ActionRequest, *, enforce_future_horizon: bool = True
    ) -> dict[str, str]:
        if request.action != _CREATE or set(request.arguments) != {
            "title",
            "description",
            "start_at",
            "end_at",
            "timezone",
        }:
            raise CalendarError("calendar create request has an unsupported shape")
        title, description = request.arguments["title"], request.arguments["description"]
        if (
            type(title) is not str
            or not 1 <= len(title) <= 120
            or any(ord(c) < 0x20 for c in title)
        ):
            raise CalendarError("calendar title must be 1..120 printable characters")
        if type(description) is not str or len(description) > 1024:
            raise CalendarError("calendar description must be at most 1024 characters")
        timezone = request.arguments["timezone"]
        if type(timezone) is not str or timezone not in self.policy.allowed_timezones:
            raise CalendarError("calendar timezone is not allowed")
        start, end = (
            _parse_time(request.arguments["start_at"], "start_at"),
            _parse_time(request.arguments["end_at"], "end_at"),
        )
        zone = ZoneInfo(timezone)
        local_start, local_end = start.astimezone(zone), end.astimezone(zone)
        if local_start.replace(tzinfo=None) != start.replace(tzinfo=None) or local_end.replace(
            tzinfo=None
        ) != end.replace(tzinfo=None):
            raise CalendarError("calendar timestamp offset does not match its IANA timezone")
        if end <= start or end - start > timedelta(minutes=self.policy.max_duration_minutes):
            raise CalendarError("calendar duration is outside configured bounds")
        if enforce_future_horizon:
            now = self._now()
            if start <= now or end > now + timedelta(days=self.policy.future_horizon_days):
                raise CalendarError("calendar event is outside the configured future horizon")
        if (
            local_start.date() != local_end.date()
            or local_start.weekday() not in self.policy.working_days
            or local_start.time() < self.policy.workday_start
            or local_end.time() > self.policy.workday_end
        ):
            raise CalendarError("calendar event is outside configured working hours")
        return {
            "title": title,
            "description": description,
            "start_at": start.isoformat(),
            "end_at": end.isoformat(),
            "timezone": timezone,
        }

    async def reserve(self, request: ActionRequest) -> CalendarReservation:
        self._require_initialized()
        if type(request) is not ActionRequest:
            raise TypeError("calendar reservation requires an ActionRequest")
        if request.action == _CREATE:
            return await self._reserve_create(request)
        if request.action == _CANCEL:
            return await self._reserve_cancel(request)
        raise CalendarError("calendar provider does not own this action")

    async def _reserve_create(
        self, request: ActionRequest, *, enforce_future_horizon: bool = True
    ) -> CalendarReservation:
        arguments = self._create_arguments(request, enforce_future_horizon=enforce_future_horizon)
        digest = _request_digest(request)
        event_ref = "calendar:" + digest
        principal, operation = (
            _identity(request.principal.id, "principal_id"),
            _identity(request.operation_id, "operation_id"),
        )
        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            await _lock(connection, self.scope)
            row = await _fetchone(
                connection,
                "SELECT * FROM calendar_event_ledger WHERE principal_id = ? AND "
                "operation_id = ? AND action = ?",
                (principal, operation, _CREATE),
            )
            if row is not None:
                if row["request_digest"] != digest:
                    raise CalendarError("calendar operation id collides with different content")
                return CalendarReservation(
                    row["event_ref"], _CREATE, digest, row["external_event_id"], row["state"]
                )
            now, external_id = self._now().isoformat(), google_event_id(event_ref)
            await _execute(
                connection,
                "INSERT INTO calendar_event_ledger("
                "event_ref, request_digest, principal_id, operation_id, "
                "action, title, description, start_at, end_at, timezone, external_event_id, "
                "state, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)",
                (
                    event_ref,
                    digest,
                    principal,
                    operation,
                    _CREATE,
                    arguments["title"],
                    arguments["description"],
                    arguments["start_at"],
                    arguments["end_at"],
                    arguments["timezone"],
                    external_id,
                    now,
                    now,
                ),
            )
            await _advance_scope_version(connection, self.scope)
        return CalendarReservation(event_ref, _CREATE, digest, external_id, "pending")

    async def _reserve_cancel(self, request: ActionRequest) -> CalendarReservation:
        if (
            set(request.arguments) != {"event_ref"}
            or type(request.arguments["event_ref"]) is not str
        ):
            raise CalendarError("calendar cancellation request has an unsupported shape")
        event_ref, digest = (
            _identity(request.arguments["event_ref"], "event_ref"),
            _request_digest(request),
        )
        principal, operation = (
            _identity(request.principal.id, "principal_id"),
            _identity(request.operation_id, "operation_id"),
        )
        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            await _lock(connection, self.scope)
            event = await _fetchone(
                connection,
                "SELECT external_event_id, state FROM calendar_event_ledger WHERE event_ref = ?",
                (event_ref,),
            )
            row = await _fetchone(
                connection,
                "SELECT * FROM calendar_cancellation_ledger WHERE principal_id = ? "
                "AND operation_id = ?",
                (principal, operation),
            )
            if row is not None:
                if row["request_digest"] != digest or row["event_ref"] != event_ref:
                    raise CalendarError(
                        "calendar cancellation operation id collides with different content"
                    )
                if event is None:
                    raise CalendarError("calendar cancellation references an unknown event")
                return CalendarReservation(
                    event_ref, _CANCEL, digest, event["external_event_id"], row["state"]
                )
            if event is None or event["state"] != "created":
                raise CalendarError("calendar cancellation requires a connector-created event")
            now = self._now().isoformat()
            await _execute(
                connection,
                "INSERT INTO calendar_cancellation_ledger("
                "request_digest, principal_id, operation_id, event_ref, "
                "state, created_at, updated_at) VALUES (?, ?, ?, ?, 'pending', ?, ?)",
                (digest, principal, operation, event_ref, now, now),
            )
            await _advance_scope_version(connection, self.scope)
        return CalendarReservation(
            event_ref, _CANCEL, digest, event["external_event_id"], "pending"
        )

    async def preview_binding(
        self, request: ActionRequest, binding: ProtectedExecutionBinding
    ) -> ProtectedExecutionBinding:
        """Derive a final execution identity without changing durable provider state.

        A pending-resolution fence needs this identity before it may reserve an
        event or cancellation ledger row. The preview reads only the bounded
        provider state needed to derive server-owned arguments; ``bind``
        repeats the validation while performing the durable reservation.
        """

        self._require_initialized()
        self._validate_binding(request, binding)
        return self._bound_binding(binding, await self._preview_reservation(request))

    async def _preview_reservation(
        self, request: ActionRequest, *, enforce_future_horizon: bool = True
    ) -> CalendarReservation:
        if type(request) is not ActionRequest:
            raise TypeError("calendar reservation requires an ActionRequest")
        if request.action == _CREATE:
            self._create_arguments(request, enforce_future_horizon=enforce_future_horizon)
            digest = _request_digest(request)
            event_ref = "calendar:" + digest
            principal, operation = (
                _identity(request.principal.id, "principal_id"),
                _identity(request.operation_id, "operation_id"),
            )
            async with self._resource.open_session(write=False) as session:
                row = await _fetchone(
                    _connection(session),
                    "SELECT * FROM calendar_event_ledger WHERE principal_id = ? AND "
                    "operation_id = ? AND action = ?",
                    (principal, operation, _CREATE),
                )
            if row is not None:
                if row["request_digest"] != digest:
                    raise CalendarError("calendar operation id collides with different content")
                return CalendarReservation(
                    row["event_ref"], _CREATE, digest, row["external_event_id"], row["state"]
                )
            return CalendarReservation(
                event_ref, _CREATE, digest, google_event_id(event_ref), "pending"
            )
        if request.action == _CANCEL:
            if (
                set(request.arguments) != {"event_ref"}
                or type(request.arguments["event_ref"]) is not str
            ):
                raise CalendarError("calendar cancellation request has an unsupported shape")
            event_ref, digest = (
                _identity(request.arguments["event_ref"], "event_ref"),
                _request_digest(request),
            )
            principal, operation = (
                _identity(request.principal.id, "principal_id"),
                _identity(request.operation_id, "operation_id"),
            )
            async with self._resource.open_session(write=False) as session:
                connection = _connection(session)
                event = await _fetchone(
                    connection,
                    "SELECT external_event_id, state FROM calendar_event_ledger "
                    "WHERE event_ref = ?",
                    (event_ref,),
                )
                row = await _fetchone(
                    connection,
                    "SELECT * FROM calendar_cancellation_ledger WHERE principal_id = ? "
                    "AND operation_id = ?",
                    (principal, operation),
                )
            if row is not None:
                if row["request_digest"] != digest or row["event_ref"] != event_ref:
                    raise CalendarError(
                        "calendar cancellation operation id collides with different content"
                    )
                if event is None:
                    raise CalendarError("calendar cancellation references an unknown event")
                return CalendarReservation(
                    event_ref, _CANCEL, digest, event["external_event_id"], row["state"]
                )
            if event is None or event["state"] != "created":
                raise CalendarError("calendar cancellation requires a connector-created event")
            return CalendarReservation(
                event_ref, _CANCEL, digest, event["external_event_id"], "pending"
            )
        raise CalendarError("calendar provider does not own this action")

    def _validate_binding(self, request: ActionRequest, binding: ProtectedExecutionBinding) -> None:
        if binding.action != request.action or dict(binding.arguments) != dict(request.arguments):
            raise CalendarError("calendar binding must contain exactly the governed public request")
        if (
            binding.provider_identity != self.policy.provider_identity
            or binding.coordination_domain_id != self._domain.domain_id
            or binding.connector_id != self.policy.connector_id
        ):
            raise CalendarError("calendar binding does not match the installed provider route")

    def _bound_binding(
        self, binding: ProtectedExecutionBinding, reservation: CalendarReservation
    ) -> ProtectedExecutionBinding:
        arguments = dict(binding.arguments)
        arguments["event_ref"] = reservation.event_ref
        if reservation.action == _CANCEL:
            arguments["external_event_id"] = reservation.external_event_id
        return replace(binding, arguments=arguments)

    async def bind(
        self, request: ActionRequest, binding: ProtectedExecutionBinding
    ) -> ProtectedExecutionBinding:
        """Add only server-derived arguments after durable event reservation."""

        self._require_initialized()
        self._validate_binding(request, binding)
        reservation = await self.reserve(request)
        prepared = self._bound_binding(binding, reservation)
        return await self._persist_binding(reservation, prepared)

    async def bind_fenced(
        self,
        request: ActionRequest,
        binding: ProtectedExecutionBinding,
        *,
        expected_execution_id: str,
    ) -> ProtectedExecutionBinding:
        """Persist a binding already validated by a durable pending fence.

        The pre-fence preview validated all request facts, including the
        current-time horizon. A recovery must preserve that decision, so this
        path repeats shape and policy checks but deliberately skips only the
        wall-clock horizon check for a create.
        """

        self._require_initialized()
        self._validate_binding(request, binding)
        preview = self._bound_binding(
            binding,
            await self._preview_reservation(request, enforce_future_horizon=False),
        )
        if preview.execution_id != expected_execution_id:
            raise CalendarError("calendar fenced binding does not match its execution identity")
        reservation = (
            await self._reserve_create(request, enforce_future_horizon=False)
            if request.action == _CREATE
            else await self.reserve(request)
        )
        prepared = self._bound_binding(binding, reservation)
        if prepared.execution_id != expected_execution_id:
            raise CalendarError("calendar fenced binding does not match its execution identity")
        return await self._persist_binding(reservation, prepared)

    async def _persist_binding(
        self, reservation: CalendarReservation, prepared: ProtectedExecutionBinding
    ) -> ProtectedExecutionBinding:
        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            await _lock(connection, self.scope)
            if reservation.action == _CREATE:
                await _execute(
                    connection,
                    "UPDATE calendar_event_ledger SET execution_id = ?, updated_at = ? "
                    "WHERE event_ref = ? AND request_digest = ?",
                    (
                        prepared.execution_id,
                        self._now().isoformat(),
                        reservation.event_ref,
                        reservation.request_digest,
                    ),
                )
            else:
                await _execute(
                    connection,
                    "UPDATE calendar_cancellation_ledger SET execution_id = ?, updated_at = ? "
                    "WHERE request_digest = ? AND event_ref = ?",
                    (
                        prepared.execution_id,
                        self._now().isoformat(),
                        reservation.request_digest,
                        reservation.event_ref,
                    ),
                )
            await _advance_scope_version(connection, self.scope)
        return prepared

    async def record_terminal(self, record: ProtectedExecutionRecord) -> CalendarReservation:
        """Project a verified terminal record only when its durable state changes."""

        self._require_initialized()
        if (
            type(record) is not ProtectedExecutionRecord
            or record.binding.connector_id != self.policy.connector_id
        ):
            raise CalendarError("calendar terminal record names the wrong connector")
        if record.status not in {
            ProtectedExecutionStatus.SUCCEEDED,
            ProtectedExecutionStatus.FAILED,
            ProtectedExecutionStatus.OUTCOME_UNKNOWN,
        }:
            raise CalendarError("calendar record is not terminal")
        event_ref = record.binding.arguments.get("event_ref")
        if type(event_ref) is not str:
            raise CalendarError("calendar terminal record lacks a server-derived event reference")
        state = {
            ProtectedExecutionStatus.SUCCEEDED: "created",
            ProtectedExecutionStatus.FAILED: "failed",
            ProtectedExecutionStatus.OUTCOME_UNKNOWN: "unknown",
        }[record.status]
        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            await _lock(connection, self.scope)
            event = await _fetchone(
                connection, "SELECT * FROM calendar_event_ledger WHERE event_ref = ?", (event_ref,)
            )
            if event is None:
                raise CalendarError("calendar terminal record names an unknown event")
            if record.external_operation_id not in {None, event["external_event_id"]}:
                raise CalendarError("calendar connector changed the immutable event id")
            changed = False
            if record.binding.action == _CREATE:
                if event["execution_id"] != record.execution_id:
                    raise CalendarError("calendar create record has the wrong execution identity")
                if event["state"] == "cancelled":
                    return CalendarReservation(
                        event_ref,
                        _CREATE,
                        "",
                        cast(str, event["external_event_id"]),
                        "cancelled",
                    )
                if event["state"] not in {"pending", "unknown", state}:
                    raise CalendarError(
                        "calendar create terminal state conflicts with durable ledger"
                    )
                if event["state"] != state:
                    await _execute(
                        connection,
                        "UPDATE calendar_event_ledger SET state = ?, updated_at = ? "
                        "WHERE event_ref = ?",
                        (state, self._now().isoformat(), event_ref),
                    )
                    changed = True
            elif record.binding.action == _CANCEL:
                cancellation = await _fetchone(
                    connection,
                    "SELECT * FROM calendar_cancellation_ledger WHERE event_ref = ? "
                    "AND execution_id = ?",
                    (event_ref, record.execution_id),
                )
                if cancellation is None:
                    raise CalendarError(
                        "calendar cancellation record has the wrong execution identity"
                    )
                cancellation_state = (
                    "cancelled" if record.status is ProtectedExecutionStatus.SUCCEEDED else state
                )
                if cancellation["state"] not in {"pending", "unknown", cancellation_state}:
                    raise CalendarError(
                        "calendar cancellation terminal state conflicts with durable ledger"
                    )
                if cancellation["state"] != cancellation_state:
                    await _execute(
                        connection,
                        "UPDATE calendar_cancellation_ledger SET state = ?, updated_at = ? "
                        "WHERE request_digest = ?",
                        (
                            cancellation_state,
                            self._now().isoformat(),
                            cancellation["request_digest"],
                        ),
                    )
                    changed = True
                if record.status is ProtectedExecutionStatus.SUCCEEDED:
                    if event["state"] not in {"created", "cancelled"}:
                        raise CalendarError("calendar cancellation does not follow a created event")
                    if event["state"] != "cancelled":
                        await _execute(
                            connection,
                            "UPDATE calendar_event_ledger SET state = 'cancelled', updated_at = ? "
                            "WHERE event_ref = ?",
                            (self._now().isoformat(), event_ref),
                        )
                        changed = True
            else:
                raise CalendarError("calendar provider does not own this action")
            if changed:
                await _advance_scope_version(connection, self.scope)
            updated = await _fetchone(
                connection,
                "SELECT state, external_event_id FROM calendar_event_ledger WHERE event_ref = ?",
                (event_ref,),
            )
        if updated is None:
            raise CalendarError("calendar terminal projection was not persisted")
        return CalendarReservation(
            event_ref,
            record.binding.action,
            "",
            cast(str, updated["external_event_id"]),
            cast(str, updated["state"]),
        )

    def provider_module(
        self, protected_runners: Mapping[str, ProtectedExecutionRunner] | None = None
    ) -> ProviderModule:
        def footprint(action: str) -> Callable[[ActionRequest], ResourceFootprint]:
            def resolve(request: ActionRequest) -> ResourceFootprint:
                if request.action != action:
                    raise CalendarError("calendar effect action mismatch")
                if action == _CREATE:
                    self._create_arguments(request)
                elif set(request.arguments) != {"event_ref"}:
                    raise CalendarError("calendar cancellation request has an unsupported shape")
                return ResourceFootprint(writes=frozenset({self.scope}))

            return resolve

        identity = self.policy.provider_identity
        schemas = (
            (
                _CREATE,
                {
                    "title": TypeName.STRING,
                    "description": TypeName.STRING,
                    "start_at": TypeName.STRING,
                    "end_at": TypeName.STRING,
                    "timezone": TypeName.STRING,
                },
            ),
            (_CANCEL, {"event_ref": TypeName.STRING}),
        )
        effects = tuple(
            EffectBinding(
                EffectContract(
                    action,
                    arguments,
                    _MODULE_ID,
                    ConsistencyGuarantee.POLICY_STATE_SERIALIZABLE,
                    footprint(action),
                    ProtectedExternalExecutor(self.policy.connector_id),
                    provider_identity=identity,
                ),
                EffectExecutionPosition.PROTECTED_EXTERNAL,
                self.policy.connector_id,
            )
            for action, arguments in schemas
        )
        runners = {} if protected_runners is None else dict(protected_runners)
        if set(runners) - {_CREATE, _CANCEL}:
            raise CalendarError("calendar module received an unknown protected runner")
        return ProviderModule(
            _MODULE_ID,
            identity,
            self._domain,
            self._domain.scope_derivation_id,
            effects=effects,
            protected_executions=tuple(
                ProtectedExecutionRegistration(action, runner)
                for action, runner in sorted(runners.items())
            ),
        )


__all__ = [
    "CalendarError",
    "CalendarPolicy",
    "CalendarProvider",
    "CalendarReservation",
    "google_event_id",
]
