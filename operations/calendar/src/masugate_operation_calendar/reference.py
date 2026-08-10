"""Fault-injectable executable oracle for the narrow calendar operation pack."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

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


@dataclass(frozen=True)
class ReferenceCalendarEvent:
    """One oracle event, including the immutable governed create payload."""

    event_id: str
    event_ref: str
    request_digest: str
    status: str


class ReferenceCalendarState:
    """Durable remote state plus one-shot faults at each remote boundary.

    A ``state_path`` restores the independent remote service's events after a
    worker/service restart. Fault switches are intentionally process-local:
    they represent a single transport boundary rather than durable remote state.
    """

    def __init__(self, state_path: Path | None = None) -> None:
        if state_path is not None and not isinstance(state_path, Path):
            raise TypeError("reference calendar state_path must be a Path")
        self._state_path = state_path
        self.events: dict[str, ReferenceCalendarEvent] = {}
        self.fail_next_create_before = False
        self.lose_next_create_response = False
        self.fail_next_cancel_before = False
        self.lose_next_cancel_response = False
        self.lose_next_status_response = False
        self.wrong_next_status_event = False
        if state_path is not None:
            self._initialize_store()
            self._load()

    def _connect(self) -> sqlite3.Connection:
        if self._state_path is None:
            raise RuntimeError("in-memory reference calendar has no state store")
        connection = sqlite3.connect(self._state_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_store(self) -> None:
        assert self._state_path is not None
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS reference_calendar_events ("
                "event_id TEXT PRIMARY KEY, event_ref TEXT NOT NULL, "
                "request_digest TEXT NOT NULL, status TEXT NOT NULL)"
            )

    def _load(self) -> None:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT event_id, event_ref, request_digest, status "
                "FROM reference_calendar_events ORDER BY event_id"
            ).fetchall()
        self.events = {
            row["event_id"]: ReferenceCalendarEvent(
                row["event_id"], row["event_ref"], row["request_digest"], row["status"]
            )
            for row in rows
        }

    def record(self, event: ReferenceCalendarEvent) -> None:
        if type(event) is not ReferenceCalendarEvent:
            raise TypeError("reference calendar event must be a ReferenceCalendarEvent")
        self.events[event.event_id] = event
        if self._state_path is not None:
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO reference_calendar_events("
                    "event_id, event_ref, request_digest, status) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(event_id) DO UPDATE SET "
                    "event_ref = excluded.event_ref, "
                    "request_digest = excluded.request_digest, status = excluded.status",
                    (event.event_id, event.event_ref, event.request_digest, event.status),
                )

    def snapshot(self) -> tuple[ReferenceCalendarEvent, ...]:
        return tuple(self.events[event_id] for event_id in sorted(self.events))

    @classmethod
    def from_snapshot(
        cls, snapshot: tuple[ReferenceCalendarEvent, ...], state_path: Path | None = None
    ) -> ReferenceCalendarState:
        state = cls(state_path)
        for event in snapshot:
            if type(event) is not ReferenceCalendarEvent or event.event_id in state.events:
                raise ValueError("reference calendar snapshot is invalid")
            state.record(event)
        return state

    def external_delete(self, event_id: str) -> None:
        self.events.pop(event_id, None)
        if self._state_path is not None:
            with self._connect() as connection:
                connection.execute(
                    "DELETE FROM reference_calendar_events WHERE event_id = ?", (event_id,)
                )

    def external_modify(self, event_id: str) -> None:
        event = self.events.get(event_id)
        if event is None:
            raise KeyError(event_id)
        self.record(replace(event, status="externally-modified"))


class ReferenceCalendarConnector:
    """Deterministic oracle for before/after-boundary, query, and substitution faults."""

    connector_id = "calendar-reference-v1"
    sdk_contract_version = SDK_CONTRACT_VERSION
    capabilities = ConnectorCapabilities(
        idempotent_dispatch=True,
        status_query=True,
        cancellation=True,
        fencing=True,
        max_payload_bytes=8 * 1024,
        max_result_bytes=8 * 1024,
        ambiguity_handling="status-query",
    )

    def __init__(self, state: ReferenceCalendarState | None = None) -> None:
        self._state = ReferenceCalendarState() if state is None else state
        if type(self._state) is not ReferenceCalendarState:
            raise TypeError("reference calendar connector needs ReferenceCalendarState")

    @property
    def events(self) -> dict[str, ReferenceCalendarEvent]:
        return self._state.events

    @staticmethod
    def _fault_property(name: str) -> property:
        def read(self: ReferenceCalendarConnector) -> bool:
            return bool(getattr(self._state, name))

        def write(self: ReferenceCalendarConnector, value: bool) -> None:
            if type(value) is not bool:
                raise TypeError("reference calendar fault injection must be bool")
            setattr(self._state, name, value)

        return property(read, write)

    fail_next_create_before = _fault_property("fail_next_create_before")
    lose_next_create_response = _fault_property("lose_next_create_response")
    fail_next_cancel_before = _fault_property("fail_next_cancel_before")
    lose_next_cancel_response = _fault_property("lose_next_cancel_response")
    lose_next_status_response = _fault_property("lose_next_status_response")
    wrong_next_status_event = _fault_property("wrong_next_status_event")

    @staticmethod
    def _event_id(event_ref: str) -> str:
        return "masugate" + hashlib.sha256(event_ref.encode("utf-8")).hexdigest()

    @staticmethod
    def _create_digest(invocation: ConnectorInvocation) -> str:
        return hashlib.sha256(
            json.dumps(
                dict(invocation.arguments), ensure_ascii=True, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()

    @staticmethod
    def _require_common(invocation: ConnectorInvocation) -> str:
        if invocation.artifacts or invocation.secrets or invocation.allowed_destinations:
            raise ConnectorSDKError(
                "reference calendar refuses artifacts, secrets, and destinations"
            )
        event_ref = invocation.arguments.get("event_ref")
        if type(event_ref) is not str or not event_ref.startswith("calendar:"):
            raise ConnectorSDKError("reference calendar requires a server-derived event_ref")
        return event_ref

    def _validate(self, invocation: ConnectorInvocation) -> str:
        event_ref = self._require_common(invocation)
        if invocation.action == _CREATE:
            if set(invocation.arguments) != {
                "title",
                "description",
                "start_at",
                "end_at",
                "timezone",
                "event_ref",
            }:
                raise ConnectorSDKError("reference calendar refuses unsupported create fields")
            if not all(type(value) is str for value in invocation.arguments.values()):
                raise ConnectorSDKError("reference calendar requires string create fields")
        elif invocation.action == _CANCEL:
            if set(invocation.arguments) != {"event_ref", "external_event_id"}:
                raise ConnectorSDKError("reference calendar refuses unsupported cancel fields")
            if invocation.arguments["external_event_id"] != self._event_id(event_ref):
                raise ConnectorSDKError("reference calendar cancellation names the wrong event")
        else:
            raise ConnectorSDKError("reference calendar does not own this action")
        return event_ref

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
            evidence_id=f"reference-calendar:{invocation.action}:{event_id}:{status}",
            idempotency_key=invocation.idempotency_key,
            external_operation_id=event_id,
            outcome=outcome,
            observed_at=datetime.now(UTC),
            payload={"event_ref": self._require_common(invocation), "status": status},
        )

    @staticmethod
    def _quarantine(event: ReferenceCalendarEvent) -> None:
        if event.status == "externally-modified":
            raise ConnectorAmbiguousOutcome(
                "reference calendar event was externally modified",
                external_operation_id=event.event_id,
            )

    async def execute(self, invocation: ConnectorInvocation) -> ConnectorEvidence:
        event_ref = self._validate(invocation)
        event_id = self._event_id(event_ref)
        if invocation.action == _CANCEL:
            return self._cancel_event(invocation, event_id, ConnectorOutcome.SUCCEEDED)
        if self.fail_next_create_before:
            self.fail_next_create_before = False
            raise ConnectorAmbiguousOutcome(
                "reference create failed before the remote boundary", external_operation_id=event_id
            )
        digest = self._create_digest(invocation)
        event = self.events.get(event_id)
        if event is None:
            event = ReferenceCalendarEvent(event_id, event_ref, digest, "created")
            self._state.record(event)
        else:
            self._quarantine(event)
            if event.request_digest != digest:
                raise ConnectorSDKError(
                    "reference calendar id collides with different governed content"
                )
            if event.status != "created":
                raise ConnectorAmbiguousOutcome(
                    "reference calendar create outcome is not reusable",
                    external_operation_id=event_id,
                )
        if self.lose_next_create_response:
            self.lose_next_create_response = False
            raise ConnectorAmbiguousOutcome(
                "reference create response lost", external_operation_id=event_id
            )
        return self._evidence(invocation, event_id, event.status)

    def _cancel_event(
        self, invocation: ConnectorInvocation, event_id: str, outcome: ConnectorOutcome
    ) -> ConnectorEvidence:
        if self.fail_next_cancel_before:
            self.fail_next_cancel_before = False
            raise ConnectorAmbiguousOutcome(
                "reference cancel failed before the remote boundary", external_operation_id=event_id
            )
        event = self.events.get(event_id)
        if event is None:
            raise ConnectorAmbiguousOutcome(
                "reference calendar cancellation names an absent event",
                external_operation_id=event_id,
            )
        self._quarantine(event)
        if event.status == "created":
            event = replace(event, status="cancelled")
            self._state.record(event)
        elif event.status != "cancelled":
            raise ConnectorAmbiguousOutcome(
                "reference calendar cancellation outcome is not reusable",
                external_operation_id=event_id,
            )
        if self.lose_next_cancel_response:
            self.lose_next_cancel_response = False
            raise ConnectorAmbiguousOutcome(
                "reference cancel response lost", external_operation_id=event_id
            )
        return self._evidence(invocation, event_id, event.status, outcome=outcome)

    async def query_status(
        self, invocation: ConnectorInvocation, *, external_operation_id: str | None
    ) -> ConnectorEvidence:
        event_ref = self._validate(invocation)
        event_id = self._event_id(event_ref)
        if external_operation_id != event_id:
            raise ConnectorSDKError("reference status query names the wrong external event")
        if self.lose_next_status_response:
            self.lose_next_status_response = False
            raise ConnectorAmbiguousOutcome(
                "reference status response lost", external_operation_id=event_id
            )
        event = self.events.get(event_id)
        if event is None:
            raise ConnectorAmbiguousOutcome(
                "reference calendar has no matching event", external_operation_id=event_id
            )
        self._quarantine(event)
        if self.wrong_next_status_event:
            self.wrong_next_status_event = False
            return self._evidence(invocation, event_id + "substituted", event.status)
        if invocation.action == _CREATE and event.status != "created":
            raise ConnectorAmbiguousOutcome(
                "reference calendar event was externally cancelled", external_operation_id=event_id
            )
        if invocation.action == _CANCEL and event.status != "cancelled":
            return self._evidence(
                invocation, event_id, "not-cancelled", outcome=ConnectorOutcome.FAILED
            )
        return self._evidence(invocation, event_id, event.status)

    async def cancel(
        self, invocation: ConnectorInvocation, *, external_operation_id: str | None
    ) -> ConnectorEvidence:
        event_ref = self._validate(invocation)
        event_id = self._event_id(event_ref)
        if external_operation_id != event_id:
            raise ConnectorSDKError(
                "reference lifecycle cancellation names the wrong external event"
            )
        return self._cancel_event(invocation, event_id, ConnectorOutcome.FAILED)


__all__ = ["ReferenceCalendarConnector", "ReferenceCalendarEvent", "ReferenceCalendarState"]
