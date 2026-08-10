"""Versioned reference sanctions, position, trade-window, and export inputs.

The provider is a deliberately bounded certification surface for deployment
configuration.  It transforms the governed action target, authenticated MasuGate
principal, and protected evaluation time into auditable ``certified.*`` facts.
It does not accept caller assertions about counterparties, regions, positions,
market time, classifications, or destinations, and it does not claim an
authoritative sanctions, position, market, export, or legal-data service.
"""

from __future__ import annotations

import hashlib
import json
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, cast
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from masugate.contracts import (
    CertifiedInputContract,
    CertifiedInputObservation,
    ProviderIdentity,
    ResourceSession,
)
from masugate.errors import ResourceError
from masugate.model import ActionRequest, CertifiedInputStability, Duration, JsonValue, TypeName
from masugate.provider_assembly import CoordinationDomain, ProviderModule

_MODULE_ID = "regulatory-context"
_IMPLEMENTATION_VERSION = "masugate.regulatory-context-v1"
_CONTRACT_VERSION = "regulatory-context-v1"
_SANCTIONS_SOURCE_ID = "masugate.reference.sanctions-counterparty"
_POSITION_SOURCE_ID = "masugate.reference.position-limit"
_TRADE_WINDOW_SOURCE_ID = "masugate.reference.trade-window"
_EXPORT_SOURCE_ID = "masugate.reference.export-destination"
_SANCTIONS = "certified.sanctions_counterparty_permitted"
_POSITION = "certified.position_limit_permitted"
_TRADE_WINDOW = "certified.trade_execution_window_open"
_EXPORT = "certified.export_destination_permitted"
_DAY_MINUTES = 24 * 60
_ALL_PRINCIPALS = "all-principals"


class RegulatoryContextError(ResourceError):
    """A reference regulatory source cannot safely certify policy input."""


class _SessionResource(Protocol):
    def open_session(self, *, write: bool) -> AbstractAsyncContextManager[ResourceSession]: ...


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


def _json(value: JsonValue) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _digest(value: JsonValue) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _connection(session: ResourceSession) -> Any:
    connection = getattr(session, "connection", None)
    if connection is None or not callable(getattr(connection, "execute", None)):
        raise RegulatoryContextError(
            "regulatory context requires a resource-owned durable SQL session"
        )
    return connection


def _window_open(start: int, end: int, at: datetime, timezone: str) -> bool:
    local = at.astimezone(ZoneInfo(timezone))
    minute = local.hour * 60 + local.minute
    if start == end:
        return True
    if start < end:
        return start <= minute < end
    return minute >= start or minute < end


@dataclass(frozen=True)
class SanctionsCounterpartyRule:
    """Configured action-target counterparty/region screening projection."""

    action: str
    target: str
    counterparty_id: str
    region: str
    permitted: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", _action(self.action, "sanctions action"))
        for field_name in ("target", "counterparty_id", "region"):
            _canonical(getattr(self, field_name), f"sanctions {field_name}")
        if type(self.permitted) is not bool:
            raise TypeError("sanctions permitted must be bool")

    @property
    def payload(self) -> dict[str, JsonValue]:
        return {
            "action": self.action,
            "counterparty_id": self.counterparty_id,
            "permitted": self.permitted,
            "region": self.region,
            "target": self.target,
        }


@dataclass(frozen=True)
class PositionLimitRule:
    """Configured principal/action current position and hard position limit.

    ``all-principals`` is an explicit deployment-wide fallback.  A matching
    exact principal rule takes precedence over that fallback.
    """

    action: str
    principal_id: str
    current_position: int
    limit: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", _action(self.action, "position action"))
        _canonical(self.principal_id, "position principal_id")
        for field_name in ("current_position", "limit"):
            value = getattr(self, field_name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{field_name} must be a non-negative integer")

    @property
    def payload(self) -> dict[str, JsonValue]:
        return {
            "action": self.action,
            "current_position": self.current_position,
            "limit": self.limit,
            "principal_id": self.principal_id,
        }

    @property
    def permitted(self) -> bool:
        return self.current_position < self.limit


@dataclass(frozen=True)
class TradeWindowRule:
    """Configured IANA market/execution window for one governed action."""

    action: str
    timezone: str
    window_start_minute: int
    window_end_minute: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", _action(self.action, "trade window action"))
        timezone = _canonical(self.timezone, "trade window timezone")
        try:
            ZoneInfo(timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("trade window timezone is unknown") from exc
        for field_name in ("window_start_minute", "window_end_minute"):
            value = getattr(self, field_name)
            if type(value) is not int or not 0 <= value < _DAY_MINUTES:
                raise ValueError(f"{field_name} must be a minute in one day")

    @property
    def payload(self) -> dict[str, JsonValue]:
        return {
            "action": self.action,
            "timezone": self.timezone,
            "window_end_minute": self.window_end_minute,
            "window_start_minute": self.window_start_minute,
        }


@dataclass(frozen=True)
class ExportDestinationRule:
    """Configured export class and destination projection for an action target."""

    action: str
    target: str
    export_class: str
    destination: str
    permitted: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", _action(self.action, "export action"))
        for field_name in ("target", "export_class", "destination"):
            _canonical(getattr(self, field_name), f"export {field_name}")
        if type(self.permitted) is not bool:
            raise TypeError("export permitted must be bool")

    @property
    def payload(self) -> dict[str, JsonValue]:
        return {
            "action": self.action,
            "destination": self.destination,
            "export_class": self.export_class,
            "permitted": self.permitted,
            "target": self.target,
        }


def _target_keys(rules: tuple[SanctionsCounterpartyRule | ExportDestinationRule, ...]) -> None:
    keys = [(rule.action, rule.target) for rule in rules]
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        raise ValueError("action-target rules must be sorted and unique")


@dataclass(frozen=True)
class RegulatoryContextPolicy:
    """Immutable reference configuration for the four regulatory projections."""

    context_id: str
    configuration_version: str
    sanctions_counterparties: tuple[SanctionsCounterpartyRule, ...]
    position_limits: tuple[PositionLimitRule, ...]
    trade_windows: tuple[TradeWindowRule, ...]
    export_destinations: tuple[ExportDestinationRule, ...]
    freshness_ttl_seconds: int = 60

    def __post_init__(self) -> None:
        _canonical(self.context_id, "regulatory context_id")
        configuration_version = _canonical(
            self.configuration_version, "regulatory context configuration_version"
        )
        if len(configuration_version) + 1 + 64 > 255:
            raise ValueError(
                "regulatory context configuration_version is too long for source version"
            )
        if type(self.freshness_ttl_seconds) is not int or self.freshness_ttl_seconds <= 0:
            raise ValueError("regulatory context freshness_ttl_seconds must be a positive integer")
        if not self.sanctions_counterparties or any(
            type(rule) is not SanctionsCounterpartyRule for rule in self.sanctions_counterparties
        ):
            raise TypeError("sanctions counterparty rules must be non-empty and typed")
        _target_keys(self.sanctions_counterparties)
        if not self.export_destinations or any(
            type(rule) is not ExportDestinationRule for rule in self.export_destinations
        ):
            raise TypeError("export destination rules must be non-empty and typed")
        _target_keys(self.export_destinations)
        if not self.position_limits or any(
            type(rule) is not PositionLimitRule for rule in self.position_limits
        ):
            raise TypeError("position limit rules must be non-empty and typed")
        position_keys = [(rule.action, rule.principal_id) for rule in self.position_limits]
        if position_keys != sorted(position_keys) or len(set(position_keys)) != len(position_keys):
            raise ValueError("position limit rules must be sorted and unique")
        if not self.trade_windows or any(
            type(rule) is not TradeWindowRule for rule in self.trade_windows
        ):
            raise TypeError("trade window rules must be non-empty and typed")
        actions = [rule.action for rule in self.trade_windows]
        if actions != sorted(actions) or len(set(actions)) != len(actions):
            raise ValueError("trade window rules must be sorted and unique")

    @property
    def payload(self) -> dict[str, JsonValue]:
        return {
            "configuration_version": self.configuration_version,
            "context_id": self.context_id,
            "export_destinations": [rule.payload for rule in self.export_destinations],
            "freshness_ttl_seconds": self.freshness_ttl_seconds,
            "position_limits": [rule.payload for rule in self.position_limits],
            "sanctions_counterparties": [rule.payload for rule in self.sanctions_counterparties],
            "schema": "masugate.regulatory-context.v1",
            "trade_windows": [rule.payload for rule in self.trade_windows],
        }

    @property
    def digest(self) -> str:
        return _digest(self.payload)

    @property
    def source_version(self) -> str:
        return f"{self.configuration_version}-{self.digest}"

    @property
    def provider_identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="masugate.regulatory-context",
            implementation_version=_IMPLEMENTATION_VERSION,
            configuration_version=self.digest,
        )

    @property
    def freshness_ttl(self) -> Duration:
        return Duration(self.freshness_ttl_seconds)


class RegulatoryContextSource(Protocol):
    """Trusted source adapter for every registered regulatory fact."""

    def sanctions_counterparty_permitted(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation: ...

    def position_limit_permitted(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation: ...

    def trade_execution_window_open(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation: ...

    def export_destination_permitted(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation: ...


class ReferenceRegulatoryContextSource:
    """Configuration-backed projection over the governed target and principal."""

    def __init__(self, policy: RegulatoryContextPolicy) -> None:
        self._policy = policy

    def _observation(self, value: bool, observation_time: datetime) -> CertifiedInputObservation:
        return CertifiedInputObservation(
            value=value,
            source_version=self._policy.source_version,
            observed_at=observation_time,
        )

    @staticmethod
    def _target(request: ActionRequest) -> str | None:
        name = "service" if request.action == "api_spend" else "destination"
        value = request.arguments.get(name)
        return value if type(value) is str else None

    def _target_rule(
        self,
        rules: tuple[SanctionsCounterpartyRule | ExportDestinationRule, ...],
        request: ActionRequest,
    ) -> SanctionsCounterpartyRule | ExportDestinationRule | None:
        target = self._target(request)
        if target is None:
            return None
        for rule in rules:
            if rule.action == request.action and rule.target == target:
                return rule
        return None

    def sanctions_counterparty_permitted(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation:
        del session
        rule = self._target_rule(self._policy.sanctions_counterparties, request)
        return self._observation(rule is not None and rule.permitted, observation_time)

    def position_limit_permitted(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation:
        del session
        fallback: PositionLimitRule | None = None
        for rule in self._policy.position_limits:
            if rule.action == request.action and rule.principal_id == request.principal.id:
                return self._observation(rule.permitted, observation_time)
            if rule.action == request.action and rule.principal_id == _ALL_PRINCIPALS:
                fallback = rule
        if fallback is not None:
            return self._observation(fallback.permitted, observation_time)
        return self._observation(False, observation_time)

    def trade_execution_window_open(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation:
        del session
        for rule in self._policy.trade_windows:
            if rule.action == request.action:
                return self._observation(
                    _window_open(
                        rule.window_start_minute,
                        rule.window_end_minute,
                        observation_time,
                        rule.timezone,
                    ),
                    observation_time,
                )
        return self._observation(False, observation_time)

    def export_destination_permitted(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation:
        del session
        rule = self._target_rule(self._policy.export_destinations, request)
        return self._observation(rule is not None and rule.permitted, observation_time)


class RegulatoryContextProvider:
    """Expose volatile, configuration-bound regulatory policy facts."""

    def __init__(
        self,
        policy: RegulatoryContextPolicy,
        domain: CoordinationDomain,
        *,
        source: RegulatoryContextSource | None = None,
    ) -> None:
        if type(policy) is not RegulatoryContextPolicy or type(domain) is not CoordinationDomain:
            raise TypeError("regulatory context provider requires policy and coordination domain")
        self.policy = policy
        self._domain = domain
        self._resource = cast(_SessionResource, domain.resource)
        self._source = source or ReferenceRegulatoryContextSource(policy)
        self._contracts = (
            self._contract(_SANCTIONS, _SANCTIONS_SOURCE_ID, self._sanctions),
            self._contract(_POSITION, _POSITION_SOURCE_ID, self._position),
            self._contract(_TRADE_WINDOW, _TRADE_WINDOW_SOURCE_ID, self._trade_window),
            self._contract(_EXPORT, _EXPORT_SOURCE_ID, self._export),
        )

    def _contract(self, name: str, source_id: str, resolver: object) -> CertifiedInputContract:
        return CertifiedInputContract(
            name=name,
            value_type=TypeName.BOOL,
            stability=CertifiedInputStability.RESOLUTION_VOLATILE,
            stability_proof=None,
            source_id=source_id,
            contract_version=_CONTRACT_VERSION,
            freshness_ttl=self.policy.freshness_ttl,
            resolver=cast(Any, resolver),
            provider_identity=self.policy.provider_identity,
            expected_source_version=self.policy.source_version,
        )

    def _checked_observation(self, value: object) -> CertifiedInputObservation:
        if type(value) is not CertifiedInputObservation:
            raise RegulatoryContextError(
                "regulatory context source returned a malformed observation"
            )
        observation = value
        if observation.source_version != self.policy.source_version:
            raise RegulatoryContextError(
                "regulatory context source version does not match configuration"
            )
        return observation

    def _sanctions(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation:
        return self._checked_observation(
            self._source.sanctions_counterparty_permitted(session, request, observation_time)
        )

    def _position(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation:
        return self._checked_observation(
            self._source.position_limit_permitted(session, request, observation_time)
        )

    def _trade_window(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation:
        return self._checked_observation(
            self._source.trade_execution_window_open(session, request, observation_time)
        )

    def _export(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation:
        return self._checked_observation(
            self._source.export_destination_permitted(session, request, observation_time)
        )

    @property
    def certified_input_contracts(self) -> tuple[CertifiedInputContract, ...]:
        return self._contracts

    async def initialize(self) -> None:
        """Persist immutable source configuration and reject configuration drift."""

        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            execute_script = getattr(connection, "executescript", None)
            script = """
                CREATE TABLE IF NOT EXISTS regulatory_context_provider_configuration (
                    context_id TEXT PRIMARY KEY,
                    configuration_digest TEXT NOT NULL,
                    configuration_json TEXT NOT NULL
                );
            """
            if callable(execute_script):
                execute_script(script)
            else:
                connection.execute(script)
            existing = connection.execute(
                "SELECT configuration_digest, configuration_json "
                "FROM regulatory_context_provider_configuration WHERE context_id = ?",
                (self.policy.context_id,),
            ).fetchone()
            payload = _json(self.policy.payload)
            if existing is None:
                connection.execute(
                    "INSERT INTO regulatory_context_provider_configuration "
                    "(context_id, configuration_digest, configuration_json) VALUES (?, ?, ?)",
                    (self.policy.context_id, self.policy.digest, payload),
                )
            elif (
                existing["configuration_digest"] != self.policy.digest
                or existing["configuration_json"] != payload
            ):
                raise RegulatoryContextError("regulatory context configuration drifted")

    def provider_module(self) -> ProviderModule:
        return ProviderModule(
            module_id=_MODULE_ID,
            identity=self.policy.provider_identity,
            domain=self._domain,
            scope_derivation_id=self._domain.scope_derivation_id,
            certified_inputs=self._contracts,
        )


__all__ = [
    "ExportDestinationRule",
    "PositionLimitRule",
    "ReferenceRegulatoryContextSource",
    "RegulatoryContextError",
    "RegulatoryContextPolicy",
    "RegulatoryContextProvider",
    "RegulatoryContextSource",
    "SanctionsCounterpartyRule",
    "TradeWindowRule",
]
