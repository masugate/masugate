"""Exact Google Calendar v3 connector profile, authored only against the public SDK."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

from masugate_connector_sdk import (
    SDK_CONTRACT_VERSION,
    ConnectorAmbiguousOutcome,
    ConnectorCapabilities,
    ConnectorEvidence,
    ConnectorInvocation,
    ConnectorOutcome,
    ConnectorSDKError,
)

_CREATE = "calendar.event.create"
_CANCEL = "calendar.event.cancel"
_ORIGIN = "https://www.googleapis.com"
_TOKEN_INFO_ORIGIN = "https://oauth2.googleapis.com/tokeninfo"
_CALENDAR_DESTINATION = "google-calendar-api-v3"
_TOKEN_INFO_DESTINATION = "google-oauth2-tokeninfo"
_DESTINATIONS = (_CALENDAR_DESTINATION, _TOKEN_INFO_DESTINATION)
_SCOPE = "https://www.googleapis.com/auth/calendar.events"
_MAX_RESPONSE_BYTES = 8 * 1024
_RESULT_FIELDS = (
    "id,status,summary,description,start(dateTime,timeZone),end(dateTime,timeZone),"
    "reminders(useDefault,overrides),eventType"
)
_RESPONSE_FIELDS = frozenset(
    {"id", "status", "summary", "description", "start", "end", "reminders", "eventType"}
)
_CREATE_REMINDERS = {"useDefault": False, "overrides": []}
_DISABLED_REMINDER_SHAPES = ({"useDefault": False}, _CREATE_REMINDERS)
_CAPABILITIES = ConnectorCapabilities(
    idempotent_dispatch=True,
    status_query=True,
    cancellation=True,
    fencing=True,
    max_payload_bytes=_MAX_RESPONSE_BYTES,
    max_result_bytes=_MAX_RESPONSE_BYTES,
    ambiguity_handling="status-query",
)
type HttpResult = tuple[int, Mapping[str, str], bytes]
type HttpTransport = Callable[[str, str, Mapping[str, str], bytes | None], Awaitable[HttpResult]]


def _identity(value: object, field_name: str) -> str:
    if not (
        type(value) is str
        and 0 < len(value) <= 255
        and value.strip() == value
        and all(0x21 <= ord(char) <= 0x7E for char in value)
    ):
        raise ConnectorSDKError(f"{field_name} must be a canonical identifier")
    return value


def _event_id(event_ref: str) -> str:
    _identity(event_ref, "event_ref")
    return "masugate" + hashlib.sha256(event_ref.encode("utf-8")).hexdigest()


def _mounted_token(value: bytes) -> bytes:
    """Accept exactly one conventional final line ending from a secret file."""

    if value.endswith(b"\r\n"):
        return value[:-2]
    if value.endswith(b"\n"):
        return value[:-1]
    return value


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, *_args: object) -> None:
        return None


@dataclass(frozen=True)
class GoogleCalendarProfile:
    """Trusted fixed configuration, with no caller-selectable API surface."""

    calendar_id: str
    oauth_secret_ref: str

    oauth_scope: str = _SCOPE

    def __post_init__(self) -> None:
        object.__setattr__(self, "calendar_id", _identity(self.calendar_id, "calendar_id"))
        object.__setattr__(
            self, "oauth_secret_ref", _identity(self.oauth_secret_ref, "oauth_secret_ref")
        )
        if self.oauth_scope != _SCOPE:
            raise ConnectorSDKError(
                "Google Calendar profile requires the exact event-only OAuth scope"
            )

    @property
    def digest(self) -> str:
        payload = {
            "calendar_id": self.calendar_id,
            "destinations": _DESTINATIONS,
            "oauth_scope": self.oauth_scope,
            "origins": (_ORIGIN, _TOKEN_INFO_ORIGIN),
            "profile": "masugate.google-calendar.v3.narrow.v1",
            "result_fields": _RESULT_FIELDS,
            "send_updates": "none",
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


async def _stdlib_transport(
    method: str, url: str, headers: Mapping[str, str], body: bytes | None
) -> HttpResult:
    def bounded_read(response: object) -> bytes:
        reader = getattr(response, "read", None)
        if not callable(reader):
            raise ConnectorSDKError("Google Calendar transport returned an unreadable response")
        result = reader(_MAX_RESPONSE_BYTES + 1)
        if type(result) is not bytes or len(result) > _MAX_RESPONSE_BYTES:
            raise ConnectorSDKError("Google Calendar response exceeds the declared result bound")
        return result

    def send() -> HttpResult:
        request = Request(url, data=body, headers=dict(headers), method=method)
        try:
            with build_opener(_RejectRedirects()).open(request, timeout=15) as response:
                return response.status, dict(response.headers.items()), bounded_read(response)
        except HTTPError as error:
            return error.code, dict(error.headers.items()), bounded_read(error)

    return await asyncio.to_thread(send)


class GoogleCalendarConnector:
    """Only accepts the calendar provider's exact server-derived invocation shapes."""

    connector_id = "google-calendar-v1"
    sdk_contract_version = SDK_CONTRACT_VERSION
    capabilities = _CAPABILITIES

    def __init__(
        self, profile: GoogleCalendarProfile, *, transport: HttpTransport = _stdlib_transport
    ) -> None:
        if type(profile) is not GoogleCalendarProfile or not callable(transport):
            raise TypeError("GoogleCalendarConnector requires a profile and HTTP transport")
        self.profile = profile
        self._transport = transport
        self._verified_token_digests: set[str] = set()

    def _collection_url(self) -> str:
        calendar = quote(self.profile.calendar_id, safe="")
        fields = quote(_RESULT_FIELDS, safe=",")
        return f"{_ORIGIN}/calendar/v3/calendars/{calendar}/events?sendUpdates=none&fields={fields}"

    def _event_url(self, event_id: str, *, send_updates: bool = False) -> str:
        calendar = quote(self.profile.calendar_id, safe="")
        event = quote(event_id, safe="")
        fields = quote(_RESULT_FIELDS, safe=",")
        url = f"{_ORIGIN}/calendar/v3/calendars/{calendar}/events/{event}?fields={fields}"
        return url + "&sendUpdates=none" if send_updates else url

    def _validate(self, invocation: ConnectorInvocation) -> tuple[str, str, bytes]:
        if invocation.artifacts:
            raise ConnectorSDKError("Google Calendar profile refuses artifacts")
        if invocation.allowed_destinations != _DESTINATIONS:
            raise ConnectorSDKError("Google Calendar profile has an unexpected destination set")
        if tuple(invocation.secrets) != (self.profile.oauth_secret_ref,):
            raise ConnectorSDKError("Google Calendar profile has an unexpected secret reference")
        token = _mounted_token(invocation.secrets[self.profile.oauth_secret_ref].read())
        if not token or any(byte < 0x21 or byte > 0x7E for byte in token):
            raise ConnectorSDKError(
                "Google Calendar OAuth token must be one printable secret value"
            )
        event_ref = invocation.arguments.get("event_ref")
        if type(event_ref) is not str or not event_ref.startswith("calendar:"):
            raise ConnectorSDKError("Google Calendar requires a server-derived event_ref")
        event_id = _event_id(event_ref)
        if invocation.action == _CREATE:
            if set(invocation.arguments) != {
                "title",
                "description",
                "start_at",
                "end_at",
                "timezone",
                "event_ref",
            } or not all(type(value) is str for value in invocation.arguments.values()):
                raise ConnectorSDKError("Google Calendar profile refuses unsupported create fields")
        elif invocation.action == _CANCEL:
            if set(invocation.arguments) != {"event_ref", "external_event_id"}:
                raise ConnectorSDKError("Google Calendar profile refuses unsupported cancel fields")
            if invocation.arguments["external_event_id"] != event_id:
                raise ConnectorSDKError("Google Calendar cancellation names a non-MasuGate event")
        else:
            raise ConnectorSDKError("Google Calendar profile does not own this action")
        return event_ref, event_id, token

    async def _request(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None
    ) -> HttpResult:
        result = await self._transport(method, url, headers, body)
        if (
            type(result) is not tuple
            or len(result) != 3
            or type(result[0]) is not int
            or not isinstance(result[1], Mapping)
            or type(result[2]) is not bytes
            or len(result[2]) > _MAX_RESPONSE_BYTES
        ):
            raise ConnectorSDKError("Google Calendar response exceeds the declared result bound")
        return result

    async def _verify_exact_token_scope(self, token: bytes) -> None:
        """Fail closed unless Google's token-info endpoint reports exactly our grant."""

        token_digest = hashlib.sha256(token).hexdigest()
        if token_digest in self._verified_token_digests:
            return
        try:
            code, _headers, body = await self._request(
                "GET",
                _TOKEN_INFO_ORIGIN + "?access_token=" + quote(token.decode("ascii"), safe=""),
                MappingProxyType({"Accept": "application/json"}),
                None,
            )
        except (OSError, TimeoutError) as exc:
            raise ConnectorSDKError("Google Calendar token scope could not be verified") from exc
        if code != 200:
            raise ConnectorSDKError("Google Calendar token scope could not be verified")
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConnectorSDKError("Google Calendar token-info response was malformed") from exc
        scope = payload.get("scope") if isinstance(payload, dict) else None
        if type(scope) is not str or frozenset(scope.split()) != {_SCOPE}:
            raise ConnectorSDKError(
                "Google Calendar token does not have the exact event-only OAuth scope"
            )
        self._verified_token_digests.add(token_digest)

    @staticmethod
    def _headers(token: bytes, *, content: bool = False) -> Mapping[str, str]:
        headers = {"Authorization": "Bearer " + token.decode("ascii"), "Accept": "application/json"}
        if content:
            headers["Content-Type"] = "application/json"
        return MappingProxyType(headers)

    def _evidence(
        self,
        invocation: ConnectorInvocation,
        event_id: str,
        status: str,
        *,
        outcome: ConnectorOutcome = ConnectorOutcome.SUCCEEDED,
    ) -> ConnectorEvidence:
        return ConnectorEvidence(
            connector_id=self.connector_id,
            evidence_id=f"google-calendar:{invocation.action}:{event_id}:{status}",
            idempotency_key=invocation.idempotency_key,
            external_operation_id=event_id,
            outcome=outcome,
            observed_at=datetime.now(UTC),
            payload={"event_ref": invocation.arguments["event_ref"], "status": status},
        )

    @staticmethod
    def _event_response(
        body: bytes, event_id: str, *, allow_cancelled: bool
    ) -> Mapping[str, object]:
        if len(body) > _MAX_RESPONSE_BYTES:
            raise ConnectorSDKError("Google Calendar response exceeds the declared result bound")
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConnectorSDKError("Google Calendar returned malformed JSON") from exc
        if not isinstance(payload, dict) or payload.get("id") != event_id:
            raise ConnectorSDKError("Google Calendar response names the wrong event")
        if set(payload) - _RESPONSE_FIELDS:
            raise ConnectorSDKError("Google Calendar response exceeds the exact event projection")
        status = payload.get("status")
        if allow_cancelled and (status == "cancelled" or set(payload) == {"id"}):
            # Google may either reduce a deleted event to its immutable id or
            # retain the bounded fields requested by this connector. Both are
            # legal cancelled projections and normalize to one terminal fact.
            return {"id": event_id, "status": "cancelled"}
        if payload.get("reminders") not in _DISABLED_REMINDER_SHAPES:
            raise ConnectorSDKError("Google Calendar response has non-disabled reminders")
        if payload.get("eventType") != "default":
            raise ConnectorSDKError("Google Calendar response exposes an unsupported event type")
        if status != "confirmed":
            raise ConnectorSDKError("Google Calendar response has an unsupported event status")
        return payload

    @staticmethod
    def _matches_create(invocation: ConnectorInvocation, payload: Mapping[str, object]) -> bool:
        start, end = payload.get("start"), payload.get("end")
        return (
            payload.get("summary") == invocation.arguments["title"]
            and payload.get("description") == invocation.arguments["description"]
            and isinstance(start, Mapping)
            and isinstance(end, Mapping)
            and start.get("dateTime") == invocation.arguments["start_at"]
            and start.get("timeZone") == invocation.arguments["timezone"]
            and end.get("dateTime") == invocation.arguments["end_at"]
            and end.get("timeZone") == invocation.arguments["timezone"]
        )

    def _failed_evidence(
        self, invocation: ConnectorInvocation, event_id: str, status: str
    ) -> ConnectorEvidence:
        return ConnectorEvidence(
            connector_id=self.connector_id,
            evidence_id=f"google-calendar:{invocation.action}:{event_id}:{status}",
            idempotency_key=invocation.idempotency_key,
            external_operation_id=event_id,
            outcome=ConnectorOutcome.FAILED,
            observed_at=datetime.now(UTC),
            payload={"event_ref": invocation.arguments["event_ref"], "status": status},
        )

    async def _get(
        self, invocation: ConnectorInvocation, event_id: str, token: bytes, *, allow_cancelled: bool
    ) -> ConnectorEvidence:
        try:
            code, _headers, body = await self._request(
                "GET", self._event_url(event_id), self._headers(token), None
            )
        except (OSError, TimeoutError) as exc:
            raise ConnectorAmbiguousOutcome(
                "Google Calendar GET failed", external_operation_id=event_id
            ) from exc
        if code == 404:
            if invocation.action == _CANCEL and allow_cancelled:
                return self._evidence(invocation, event_id, "cancelled")
            return ConnectorEvidence(
                connector_id=self.connector_id,
                evidence_id=f"google-calendar:get:{event_id}:absent",
                idempotency_key=invocation.idempotency_key,
                external_operation_id=event_id,
                outcome=ConnectorOutcome.FAILED,
                observed_at=datetime.now(UTC),
                payload={"event_ref": invocation.arguments["event_ref"], "status": "absent"},
            )
        if code != 200:
            raise ConnectorAmbiguousOutcome(
                "Google Calendar GET was not conclusive", external_operation_id=event_id
            )
        payload = self._event_response(body, event_id, allow_cancelled=allow_cancelled)
        if invocation.action == _CREATE and not self._matches_create(invocation, payload):
            raise ConnectorAmbiguousOutcome(
                "Google Calendar event was externally modified", external_operation_id=event_id
            )
        if invocation.action == _CANCEL and payload.get("status") != "cancelled":
            return self._failed_evidence(invocation, event_id, "not-cancelled")

        return self._evidence(invocation, event_id, str(payload.get("status", "created")))

    async def execute(self, invocation: ConnectorInvocation) -> ConnectorEvidence:
        _event_ref, event_id, token = self._validate(invocation)
        await self._verify_exact_token_scope(token)
        if invocation.action == _CANCEL:
            return await self._delete(invocation, event_id, token)
        body = json.dumps(
            {
                "id": event_id,
                "summary": invocation.arguments["title"],
                "description": invocation.arguments["description"],
                "start": {
                    "dateTime": invocation.arguments["start_at"],
                    "timeZone": invocation.arguments["timezone"],
                },
                "end": {
                    "dateTime": invocation.arguments["end_at"],
                    "timeZone": invocation.arguments["timezone"],
                },
                "reminders": _CREATE_REMINDERS,
            },
            ensure_ascii=True,
            separators=(",", ":"),
        ).encode("utf-8")
        try:
            code, _headers, response = await self._request(
                "POST", self._collection_url(), self._headers(token, content=True), body
            )
        except (OSError, TimeoutError) as exc:
            raise ConnectorAmbiguousOutcome(
                "Google Calendar create response lost", external_operation_id=event_id
            ) from exc
        if code == 409:
            # A deterministic id makes conflict recovery a status query, never a second create.
            return await self._get(invocation, event_id, token, allow_cancelled=False)
        if code not in {200, 201}:
            raise ConnectorAmbiguousOutcome(
                "Google Calendar create was not conclusive", external_operation_id=event_id
            )
        payload = self._event_response(response, event_id, allow_cancelled=False)
        if not self._matches_create(invocation, payload):
            raise ConnectorAmbiguousOutcome(
                "Google Calendar created a modified event", external_operation_id=event_id
            )
        return self._evidence(invocation, event_id, "created")

    async def query_status(
        self, invocation: ConnectorInvocation, *, external_operation_id: str | None
    ) -> ConnectorEvidence:
        _event_ref, event_id, token = self._validate(invocation)
        await self._verify_exact_token_scope(token)
        if external_operation_id != event_id:
            raise ConnectorSDKError("Google Calendar status query names the wrong event")
        return await self._get(
            invocation, event_id, token, allow_cancelled=invocation.action == _CANCEL
        )

    async def _delete(
        self,
        invocation: ConnectorInvocation,
        event_id: str,
        token: bytes,
        *,
        outcome: ConnectorOutcome = ConnectorOutcome.SUCCEEDED,
    ) -> ConnectorEvidence:
        try:
            code, _headers, _body = await self._request(
                "DELETE", self._event_url(event_id, send_updates=True), self._headers(token), None
            )
        except (OSError, TimeoutError) as exc:
            raise ConnectorAmbiguousOutcome(
                "Google Calendar cancel response lost", external_operation_id=event_id
            ) from exc
        if code not in {200, 204}:
            raise ConnectorAmbiguousOutcome(
                "Google Calendar cancellation was not conclusive", external_operation_id=event_id
            )
        return self._evidence(invocation, event_id, "cancelled", outcome=outcome)

    async def cancel(
        self, invocation: ConnectorInvocation, *, external_operation_id: str | None
    ) -> ConnectorEvidence:
        _event_ref, event_id, token = self._validate(invocation)
        await self._verify_exact_token_scope(token)
        if external_operation_id != event_id:
            raise ConnectorSDKError("Google Calendar lifecycle cancellation names the wrong event")
        return await self._delete(invocation, event_id, token, outcome=ConnectorOutcome.FAILED)


class _EnvironmentConnector:
    """Lazy entry point: deployment configuration is read only inside the worker."""

    connector_id = GoogleCalendarConnector.connector_id
    sdk_contract_version = SDK_CONTRACT_VERSION
    capabilities = _CAPABILITIES

    @staticmethod
    def _configured() -> GoogleCalendarConnector:
        try:
            profile = GoogleCalendarProfile(
                os.environ["MASUGATE_GOOGLE_CALENDAR_ID"],
                os.environ["MASUGATE_GOOGLE_CALENDAR_OAUTH_SECRET_REF"],
                os.environ["MASUGATE_GOOGLE_CALENDAR_OAUTH_SCOPE"],
            )
        except KeyError as exc:
            raise ConnectorSDKError("Google Calendar worker configuration is missing") from exc
        return GoogleCalendarConnector(profile)

    async def execute(self, invocation: ConnectorInvocation) -> ConnectorEvidence:
        return await self._configured().execute(invocation)

    async def query_status(
        self, invocation: ConnectorInvocation, *, external_operation_id: str | None
    ) -> ConnectorEvidence:
        return await self._configured().query_status(
            invocation, external_operation_id=external_operation_id
        )

    async def cancel(
        self, invocation: ConnectorInvocation, *, external_operation_id: str | None
    ) -> ConnectorEvidence:
        return await self._configured().cancel(
            invocation, external_operation_id=external_operation_id
        )


connector = _EnvironmentConnector()

__all__ = ["GoogleCalendarConnector", "GoogleCalendarProfile", "connector"]
