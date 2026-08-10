"""Asynchronous client for ``masugated``."""

from __future__ import annotations

import base64
import json
from collections.abc import AsyncIterator, Mapping
from contextlib import suppress
from hashlib import sha256
from types import TracebackType
from typing import cast
from urllib.parse import quote

import httpx

from ._parsing import (
    json_object,
    parse_action_result,
    parse_audit_record,
    parse_error_envelope,
    parse_pending_event,
    parse_pending_list,
    parse_pending_lookup,
    parse_staged_artifact,
)
from .adapter_contract import AdapterCancellationEnvelope, validate_adapter_cancellation_envelope
from .errors import MasuGateAPIError, MasuGateProtocolError, MasuGateTransportError
from .models import (
    ActionResult,
    AuditRecord,
    ExpectedActionOwner,
    JsonValue,
    PendingEvent,
    PendingList,
    PendingLookup,
    Scalar,
    StagedArtifact,
)

_IDEMPOTENCY_PREFIX = "masugate:v1:"
_SAFE_INTEGER_MIN = -9_007_199_254_740_991
_SAFE_INTEGER_MAX = 9_007_199_254_740_991
_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024


def derive_idempotency_key(stable_id: str) -> str:
    """Derive the bounded wire key for one caller-defined logical operation."""

    if not isinstance(stable_id, str) or not stable_id:
        raise ValueError("stable_id must be a non-empty string")
    digest = sha256(stable_id.encode("utf-8")).hexdigest()
    return f"{_IDEMPOTENCY_PREFIX}{digest}"


def _nonempty(value: str, name: str, *, max_length: int | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    if max_length is not None and len(value) > max_length:
        raise ValueError(f"{name} must contain at most {max_length} characters")
    return value


def _action_args(args: Mapping[str, Scalar]) -> dict[str, Scalar]:
    copied: dict[str, Scalar] = {}
    for key, value in args.items():
        if not isinstance(key, str):
            raise ValueError("args keys must be strings")
        if isinstance(value, bool | str):
            copied[key] = value
            continue
        if type(value) is int and _SAFE_INTEGER_MIN <= value <= _SAFE_INTEGER_MAX:
            copied[key] = value
            continue
        raise ValueError(f"args.{key} must be a string, boolean, or safe integer")
    return copied


def _evidence(value: Mapping[str, JsonValue] | None) -> dict[str, JsonValue]:
    if value is None:
        return {}
    try:
        return json_object(dict(value), "evidence")
    except MasuGateProtocolError as exc:
        raise ValueError(str(exc)) from exc


class MasuGateClient:
    """Typed async wrapper around the Governed Action Protocol.

    The client owns its HTTP transport and should normally be used with
    ``async with``. Supplying an HTTPX transport makes in-process ASGI use and
    custom networking policies possible without changing the SDK surface.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float | httpx.Timeout | None = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
        principal_id: str | None = None,
    ) -> None:
        _nonempty(base_url, "base_url")
        _nonempty(token, "token")
        if principal_id is not None and (
            not isinstance(principal_id, str)
            or not principal_id.strip()
            or principal_id != principal_id.strip()
        ):
            raise ValueError("principal_id must be a non-empty, trimmed string")
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "masugate-client-python/0.1.0",
        }
        if principal_id is not None:
            headers["MasuGate-Expected-Principal"] = principal_id
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/") + "/",
            headers=headers,
            timeout=timeout,
            transport=transport,
        )
        self._closed = False

    async def __aenter__(self) -> MasuGateClient:
        if self._closed:
            raise RuntimeError("MasuGateClient is closed")
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        await self.aclose()

    async def aclose(self) -> None:
        if not self._closed:
            self._closed = True
            await self._http.aclose()

    async def execute(
        self,
        action: str,
        args: Mapping[str, Scalar],
        stable_id: str,
        trace_id: str | None = None,
        *,
        owner: ExpectedActionOwner | None = None,
        expected_principal: str | None = None,
        adapter_invocation: str | None = None,
    ) -> ActionResult:
        """Execute one logical action, deriving idempotency from ``stable_id``."""

        body: dict[str, object] = {
            "action": _nonempty(action, "action", max_length=255),
            "args": _action_args(args),
            "idempotency_key": derive_idempotency_key(stable_id),
        }
        if trace_id is not None:
            body["trace_id"] = _nonempty(trace_id, "trace_id", max_length=255)
        if adapter_invocation is not None:
            body["adapter_invocation"] = _nonempty(
                adapter_invocation, "adapter_invocation", max_length=16_384
            )
        headers: dict[str, str] | None = None
        if expected_principal is not None:
            headers = {
                "MasuGate-Expected-Principal": _nonempty(
                    expected_principal, "expected_principal", max_length=256
                )
            }
        if owner is not None:
            headers = (headers or {}) | {
                "MasuGate-Expected-Provider": owner.provider_id,
                "MasuGate-Expected-Position": owner.position,
            }
            if owner.position == "protected-external":
                assert owner.connector_id is not None
                headers["MasuGate-Expected-Connector"] = owner.connector_id
        raw = await self._request_json("POST", "/v1/actions", json_body=body, headers=headers)
        try:
            return parse_action_result(raw)
        except MasuGateProtocolError as exc:
            raise MasuGateProtocolError(str(exc), endpoint="POST /v1/actions") from exc

    async def stage_artifact(
        self,
        *,
        action: str,
        field: str,
        content: bytes,
        media_type: str,
        stable_id: str,
        adapter_invocation: str,
    ) -> StagedArtifact:
        """Stage declared bytes before a matching connector ecosystem operation handoff.

        ``stable_id`` must be the same logical-operation id later supplied to
        the generated operation runtime.  The response's opaque reference is
        deliberately not accepted by :meth:`execute`; only the trusted server
        can resolve it into a provider/connector handoff.
        """

        if not isinstance(content, bytes):
            raise ValueError("content must be bytes")
        if len(content) > _MAX_ARTIFACT_BYTES:
            raise ValueError("content exceeds the connector ecosystem artifact byte limit")
        body = {
            "action": _nonempty(action, "action", max_length=255),
            "field": _nonempty(field, "field", max_length=256),
            "idempotency_key": derive_idempotency_key(stable_id),
            "media_type": _nonempty(media_type, "media_type", max_length=128),
            "content_base64": base64.b64encode(content).decode("ascii"),
            "adapter_invocation": _nonempty(
                adapter_invocation, "adapter_invocation", max_length=16_384
            ),
        }
        raw = await self._request_json("POST", "/v1/artifacts", json_body=body)
        try:
            return parse_staged_artifact(raw)
        except MasuGateProtocolError as exc:
            raise MasuGateProtocolError(str(exc), endpoint="POST /v1/artifacts") from exc

    async def resolve_pending(
        self,
        pending_id: str,
        approved: bool,
        evidence: Mapping[str, JsonValue] | None = None,
    ) -> ActionResult:
        """Approve or reject a pending operation through the coordinator."""

        if not isinstance(approved, bool):
            raise ValueError("approved must be a boolean")
        safe_id = quote(_nonempty(pending_id, "pending_id"), safe="")
        path = f"/v1/pending/{safe_id}/resolve"
        raw = await self._request_json(
            "POST",
            path,
            json_body={"approved": approved, "evidence": _evidence(evidence)},
        )
        try:
            result = parse_action_result(raw)
        except MasuGateProtocolError as exc:
            raise MasuGateProtocolError(str(exc), endpoint=f"POST {path}") from exc
        if result.status == "pending":
            raise MasuGateProtocolError(
                "resolution returned another pending result", endpoint=f"POST {path}"
            )
        return result

    async def list_pending(self) -> PendingList:
        """Fetch the durable snapshot used to seed pending streams."""

        raw = await self._request_json("GET", "/v1/pending")
        try:
            return parse_pending_list(raw)
        except MasuGateProtocolError as exc:
            raise MasuGateProtocolError(str(exc), endpoint="GET /v1/pending") from exc

    async def get_pending(self, pending_id: str) -> PendingLookup:
        """Fetch one durable pending locator or its terminal replay after restart."""

        safe_id = quote(_nonempty(pending_id, "pending_id"), safe="")
        path = f"/v1/pending/{safe_id}"
        raw = await self._request_json("GET", path)
        try:
            return parse_pending_lookup(raw)
        except MasuGateProtocolError as exc:
            raise MasuGateProtocolError(str(exc), endpoint=f"GET {path}") from exc

    async def cancel_pending(self, pending_id: str) -> AdapterCancellationEnvelope:
        """Request bounded cancellation; re-read the locator for a terminal result."""

        safe_id = quote(_nonempty(pending_id, "pending_id"), safe="")
        path = f"/v1/pending/{safe_id}/cancel"
        raw = await self._request_json("POST", path, json_body={})
        try:
            cancellation = validate_adapter_cancellation_envelope(raw)
            locator = cast(Mapping[str, object], cancellation["locator"])
            if locator.get("pending_id") != pending_id:
                raise ValueError("cancellation pending_id does not match the requested id")
            return cancellation
        except ValueError as exc:
            raise MasuGateProtocolError(str(exc), endpoint=f"POST {path}") from exc

    async def stream_pending(
        self,
        *,
        last_event_id: str | None = None,
        once: bool = False,
    ) -> AsyncIterator[PendingEvent]:
        """Yield typed ``pending.created`` events from the server-sent stream.

        ``last_event_id`` resumes a durable catch-up stream. ``once=True`` asks
        the CoreRuntime server to emit only its current snapshot, which is useful
        for finite workers and tests.
        """

        headers = {"Accept": "text/event-stream"}
        if last_event_id is not None:
            headers["Last-Event-ID"] = _nonempty(last_event_id, "last_event_id")
        try:
            stream = self._http.stream(
                "GET",
                "/v1/pending/stream",
                params={"once": "true" if once else "false"},
                headers=headers,
                # SSE reads are intentionally open-ended. HTTPX still owns
                # connection setup/teardown through the response context.
                timeout=None,
            )
            async with stream as response:
                await self._raise_for_status(response)
                content_type = response.headers.get("content-type", "").lower()
                if "text/event-stream" not in content_type:
                    raise MasuGateProtocolError(
                        "response Content-Type is not text/event-stream",
                        endpoint="GET /v1/pending/stream",
                    )
                event_name: str | None = None
                event_id: str | None = None
                data_lines: list[str] = []
                async for line in response.aiter_lines():
                    if line == "":
                        event = self._decode_sse_event(event_name, event_id, data_lines)
                        event_name = None
                        event_id = None
                        data_lines = []
                        if event is not None:
                            yield event
                        continue
                    if line.startswith(":"):
                        continue
                    field, separator, value = line.partition(":")
                    if separator and value.startswith(" "):
                        value = value[1:]
                    if field == "event":
                        event_name = value
                    elif field == "id" and "\x00" not in value:
                        event_id = value
                    elif field == "data":
                        data_lines.append(value)
                    # retry and future extension fields are intentionally ignored.
                event = self._decode_sse_event(event_name, event_id, data_lines)
                if event is not None:
                    yield event
        except MasuGateProtocolError:
            raise
        except httpx.HTTPError as exc:
            raise MasuGateTransportError("GET", "/v1/pending/stream", exc) from exc

    async def get_audit(self, operation_id: str) -> AuditRecord:
        """Fetch the governance receipt for a server-assigned operation id."""

        safe_id = quote(_nonempty(operation_id, "operation_id"), safe="")
        path = f"/v1/audit/{safe_id}"
        raw = await self._request_json("GET", path)
        try:
            record = parse_audit_record(raw)
        except MasuGateProtocolError as exc:
            raise MasuGateProtocolError(str(exc), endpoint=f"GET {path}") from exc
        if record.operation_id != operation_id:
            raise MasuGateProtocolError(
                "audit operation_id does not match the requested id", endpoint=f"GET {path}"
            )
        return record

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        json_body: object | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> object:
        if self._closed:
            raise RuntimeError("MasuGateClient is closed")
        try:
            response = await self._http.request(method, path, json=json_body, headers=headers)
        except httpx.HTTPError as exc:
            raise MasuGateTransportError(method, path, exc) from exc
        await self._raise_for_status(response)
        try:
            return cast(object, response.json())
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise MasuGateProtocolError(
                "response body is not valid JSON", endpoint=f"{method} {path}"
            ) from exc

    async def _raise_for_status(self, response: httpx.Response) -> None:
        if 200 <= response.status_code < 300:
            return
        await response.aread()
        parsed: tuple[str, str, dict[str, JsonValue] | None] | None = None
        with suppress(json.JSONDecodeError, UnicodeDecodeError):
            parsed = parse_error_envelope(cast(object, response.json()))
        if parsed is None:
            preview = response.text.strip().replace("\n", " ")[:200]
            message = preview or response.reason_phrase or "HTTP request failed"
            parsed = ("http_error", message, None)
        code, message, details = parsed
        raise MasuGateAPIError(response.status_code, code, message, details=details)

    @staticmethod
    def _decode_sse_event(
        event_name: str | None,
        event_id: str | None,
        data_lines: list[str],
    ) -> PendingEvent | None:
        if not data_lines:
            return None
        if event_name != "pending.created":
            raise MasuGateProtocolError(
                f"unexpected SSE event type {event_name or 'message'!r}",
                endpoint="GET /v1/pending/stream",
            )
        if event_id is None or not event_id:
            raise MasuGateProtocolError(
                "pending SSE event is missing id",
                endpoint="GET /v1/pending/stream",
            )
        try:
            raw = cast(object, json.loads("\n".join(data_lines)))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise MasuGateProtocolError(
                "pending SSE data is not valid JSON",
                endpoint="GET /v1/pending/stream",
            ) from exc
        try:
            event = parse_pending_event(raw)
        except MasuGateProtocolError as exc:
            raise MasuGateProtocolError(str(exc), endpoint="GET /v1/pending/stream") from exc
        if event.event_id != event_id:
            raise MasuGateProtocolError(
                "SSE id does not match data.event_id",
                endpoint="GET /v1/pending/stream",
            )
        return event
