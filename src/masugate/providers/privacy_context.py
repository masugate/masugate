"""Versioned reference privacy, PHI, consent, and optional PII projections.

This module is deliberately a narrow certification boundary, not a legal-data
service.  It turns a deployment-owned, immutable reference configuration into
four boolean ``certified.*`` facts.  It never accepts a caller's asserted
classification, jurisdiction, recipient, purpose, consent, or local time.

Every fact is resolution-volatile: a later protected evaluation must fetch a
new observation from the active source.  The optional PII classifier is a
one-way risk signal.  A positive result may deny; a negative result does not
attest that content contains no PII and is never a legal determination.
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
from masugate.model import (
    ActionRequest,
    CertifiedInputStability,
    Duration,
    JsonValue,
    TypeName,
)
from masugate.provider_assembly import CoordinationDomain, ProviderModule

_MODULE_ID = "privacy-context"
_IMPLEMENTATION_VERSION = "masugate.privacy-context-v1"
_CONTRACT_VERSION = "privacy-context-v1"
_PRIVACY_SOURCE_ID = "masugate.reference.privacy-transfer"
_PHI_SOURCE_ID = "masugate.reference.phi-recipient"
_CONSENT_SOURCE_ID = "masugate.reference.consent-marketing"
_CLASSIFIER_SOURCE_ID = "masugate.reference.pii-classifier"
_PRIVACY_TRANSFER = "certified.privacy_transfer_permitted"
_PHI_RECIPIENT = "certified.phi_recipient_permitted"
_CONSENT_MARKETING = "certified.consent_marketing_permitted"
_PII_CLASSIFIER_FLAGGED = "certified.pii_classifier_flagged"
_DAY_MINUTES = 24 * 60


class PrivacyContextError(ResourceError):
    """A privacy/PHI/consent source cannot safely certify policy input."""


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
        raise PrivacyContextError("privacy context requires a resource-owned durable SQL session")
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
class PrivacyTransferRule:
    """One trusted action-target projection for cross-border transfer policy."""

    action: str
    target: str
    permitted: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", _action(self.action, "privacy transfer action"))
        object.__setattr__(self, "target", _canonical(self.target, "privacy transfer target"))
        if type(self.permitted) is not bool:
            raise TypeError("privacy transfer permitted must be bool")

    @property
    def payload(self) -> dict[str, JsonValue]:
        return {"action": self.action, "permitted": self.permitted, "target": self.target}


@dataclass(frozen=True)
class PhiRecipientRule:
    """One trusted action-target projection for PHI-recipient authorization."""

    action: str
    target: str
    permitted: bool

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", _action(self.action, "PHI recipient action"))
        object.__setattr__(self, "target", _canonical(self.target, "PHI recipient target"))
        if type(self.permitted) is not bool:
            raise TypeError("PHI recipient permitted must be bool")

    @property
    def payload(self) -> dict[str, JsonValue]:
        return {"action": self.action, "permitted": self.permitted, "target": self.target}


@dataclass(frozen=True)
class ConsentMarketingRule:
    """One consented-recipient and recipient-local contact-window projection."""

    action: str
    target: str
    consented: bool
    timezone: str
    window_start_minute: int
    window_end_minute: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "action", _action(self.action, "consent marketing action"))
        object.__setattr__(self, "target", _canonical(self.target, "consent marketing target"))
        if type(self.consented) is not bool:
            raise TypeError("consent marketing consented must be bool")
        timezone = _canonical(self.timezone, "consent marketing timezone")
        try:
            ZoneInfo(timezone)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("consent marketing timezone is unknown") from exc
        for field_name in ("window_start_minute", "window_end_minute"):
            value = getattr(self, field_name)
            if type(value) is not int or not 0 <= value < _DAY_MINUTES:
                raise ValueError(f"{field_name} must be a minute in one day")

    @property
    def payload(self) -> dict[str, JsonValue]:
        return {
            "action": self.action,
            "consented": self.consented,
            "target": self.target,
            "timezone": self.timezone,
            "window_end_minute": self.window_end_minute,
            "window_start_minute": self.window_start_minute,
        }


@dataclass(frozen=True)
class PiiClassifierConfig:
    """Optional, bounded classifier lookup for known immutable content digests.

    The configuration is intentionally a reference projection rather than a
    content-analysis engine.  An omitted digest returns ``False`` but does not
    prove the payload is PII-free; callers must not treat that result as a
    classifier completeness or legal-sufficiency assertion.
    """

    classifier_id: str
    classifier_version: str
    detections: tuple[tuple[str, bool], ...]

    def __post_init__(self) -> None:
        _canonical(self.classifier_id, "PII classifier id")
        _canonical(self.classifier_version, "PII classifier version")
        detections = tuple(
            (_canonical(digest, "PII classifier content digest"), flagged)
            for digest, flagged in self.detections
        )
        if detections != tuple(sorted(detections, key=lambda item: item[0])):
            raise ValueError("PII classifier detections must be sorted by content digest")
        if len({digest for digest, _flagged in detections}) != len(detections):
            raise ValueError("PII classifier detections must have unique content digests")
        if any(type(flagged) is not bool for _digest_value, flagged in detections):
            raise TypeError("PII classifier detection flags must be bool")
        object.__setattr__(self, "detections", detections)

    @property
    def payload(self) -> dict[str, JsonValue]:
        return {
            "classifier_id": self.classifier_id,
            "classifier_version": self.classifier_version,
            "detections": [
                {"content_digest": content_digest, "flagged": flagged}
                for content_digest, flagged in self.detections
            ],
        }

    def flagged(self, content_digest: object) -> bool:
        if type(content_digest) is not str:
            return False
        return dict(self.detections).get(content_digest, False)


def _unique_rules[Rule: (PrivacyTransferRule, PhiRecipientRule, ConsentMarketingRule)](
    rules: tuple[Rule, ...], label: str
) -> tuple[Rule, ...]:
    keys = [(rule.action, rule.target) for rule in rules]
    if keys != sorted(keys):
        raise ValueError(f"{label} rules must be sorted by action and target")
    if len(set(keys)) != len(keys):
        raise ValueError(f"{label} rules must have unique action-target pairs")
    return rules


@dataclass(frozen=True)
class PrivacyContextPolicy:
    """Immutable configuration for privacy, PHI, consent, and classifier facts."""

    context_id: str
    configuration_version: str
    privacy_transfers: tuple[PrivacyTransferRule, ...]
    phi_recipients: tuple[PhiRecipientRule, ...]
    consent_marketing: tuple[ConsentMarketingRule, ...]
    pii_classifier: PiiClassifierConfig | None = None
    freshness_ttl_seconds: int = 60

    def __post_init__(self) -> None:
        _canonical(self.context_id, "privacy context_id")
        configuration_version = _canonical(
            self.configuration_version, "privacy context configuration_version"
        )
        if len(configuration_version) + 1 + 64 > 255:
            raise ValueError("privacy context configuration_version is too long for source version")
        if type(self.freshness_ttl_seconds) is not int or self.freshness_ttl_seconds <= 0:
            raise ValueError("privacy context freshness_ttl_seconds must be a positive integer")
        if not self.privacy_transfers or any(
            type(rule) is not PrivacyTransferRule for rule in self.privacy_transfers
        ):
            raise TypeError("privacy context privacy transfer rules must be non-empty and typed")
        _unique_rules(self.privacy_transfers, "privacy transfer")
        if not self.phi_recipients or any(
            type(rule) is not PhiRecipientRule for rule in self.phi_recipients
        ):
            raise TypeError("privacy context PHI recipient rules must be non-empty and typed")
        _unique_rules(self.phi_recipients, "PHI recipient")
        if not self.consent_marketing or any(
            type(rule) is not ConsentMarketingRule for rule in self.consent_marketing
        ):
            raise TypeError("privacy context consent marketing rules must be non-empty and typed")
        _unique_rules(self.consent_marketing, "consent marketing")
        if self.pii_classifier is not None and type(self.pii_classifier) is not PiiClassifierConfig:
            raise TypeError("privacy context pii_classifier must be PiiClassifierConfig or None")

    @property
    def payload(self) -> dict[str, JsonValue]:
        return {
            "configuration_version": self.configuration_version,
            "consent_marketing": [rule.payload for rule in self.consent_marketing],
            "context_id": self.context_id,
            "freshness_ttl_seconds": self.freshness_ttl_seconds,
            "phi_recipients": [rule.payload for rule in self.phi_recipients],
            "pii_classifier": None if self.pii_classifier is None else self.pii_classifier.payload,
            "privacy_transfers": [rule.payload for rule in self.privacy_transfers],
            "schema": "masugate.privacy-context.v1",
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
            provider_id="masugate.privacy-context",
            implementation_version=_IMPLEMENTATION_VERSION,
            configuration_version=self.digest,
        )

    @property
    def freshness_ttl(self) -> Duration:
        return Duration(self.freshness_ttl_seconds)


class PrivacyContextSource(Protocol):
    """Trusted source adapter for the configured privacy projections."""

    def privacy_transfer_permitted(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation: ...

    def phi_recipient_permitted(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation: ...

    def consent_marketing_permitted(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation: ...

    def pii_classifier_flagged(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation: ...


class ReferencePrivacyContextSource:
    """Configuration-backed source that ignores non-governed caller assertions."""

    def __init__(self, policy: PrivacyContextPolicy) -> None:
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

    def _rule[Rule: (PrivacyTransferRule, PhiRecipientRule, ConsentMarketingRule)](
        self,
        rules: tuple[Rule, ...],
        request: ActionRequest,
    ) -> Rule | None:
        target = self._target(request)
        if target is None:
            return None
        for rule in rules:
            if rule.action == request.action and rule.target == target:
                return rule
        return None

    def privacy_transfer_permitted(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation:
        del session
        rule = self._rule(self._policy.privacy_transfers, request)
        return self._observation(rule is not None and rule.permitted, observation_time)

    def phi_recipient_permitted(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation:
        del session
        rule = self._rule(self._policy.phi_recipients, request)
        return self._observation(rule is not None and rule.permitted, observation_time)

    def consent_marketing_permitted(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation:
        del session
        rule = self._rule(self._policy.consent_marketing, request)
        permitted = (
            rule is not None
            and rule.consented
            and _window_open(
                rule.window_start_minute,
                rule.window_end_minute,
                observation_time,
                rule.timezone,
            )
        )
        return self._observation(permitted, observation_time)

    def pii_classifier_flagged(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation:
        del session
        classifier = self._policy.pii_classifier
        content_digest = request.arguments.get("content_digest")
        flagged = classifier is not None and classifier.flagged(content_digest)
        return self._observation(flagged, observation_time)


class PrivacyContextProvider:
    """Export versioned volatile privacy inputs in one coordination domain."""

    def __init__(
        self,
        policy: PrivacyContextPolicy,
        domain: CoordinationDomain,
        *,
        source: PrivacyContextSource | None = None,
    ) -> None:
        if type(policy) is not PrivacyContextPolicy or type(domain) is not CoordinationDomain:
            raise TypeError("privacy context provider requires policy and coordination domain")
        self.policy = policy
        self._domain = domain
        self._resource = cast(_SessionResource, domain.resource)
        self._source = source or ReferencePrivacyContextSource(policy)
        contracts = [
            self._contract(_PRIVACY_TRANSFER, _PRIVACY_SOURCE_ID, self._privacy_transfer),
            self._contract(_PHI_RECIPIENT, _PHI_SOURCE_ID, self._phi_recipient),
            self._contract(_CONSENT_MARKETING, _CONSENT_SOURCE_ID, self._consent_marketing),
        ]
        if policy.pii_classifier is not None:
            contracts.append(
                self._contract(
                    _PII_CLASSIFIER_FLAGGED,
                    _CLASSIFIER_SOURCE_ID,
                    self._pii_classifier_flagged,
                )
            )
        self._contracts = tuple(contracts)

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
            raise PrivacyContextError("privacy context source returned a malformed observation")
        observation = value
        if observation.source_version != self.policy.source_version:
            raise PrivacyContextError("privacy context source version does not match configuration")
        return observation

    def _privacy_transfer(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation:
        return self._checked_observation(
            self._source.privacy_transfer_permitted(session, request, observation_time)
        )

    def _phi_recipient(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation:
        return self._checked_observation(
            self._source.phi_recipient_permitted(session, request, observation_time)
        )

    def _consent_marketing(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation:
        return self._checked_observation(
            self._source.consent_marketing_permitted(session, request, observation_time)
        )

    def _pii_classifier_flagged(
        self, session: ResourceSession, request: ActionRequest, observation_time: datetime
    ) -> CertifiedInputObservation:
        return self._checked_observation(
            self._source.pii_classifier_flagged(session, request, observation_time)
        )

    @property
    def certified_input_contracts(self) -> tuple[CertifiedInputContract, ...]:
        return self._contracts

    async def initialize(self) -> None:
        """Persist immutable configuration and fail closed on source drift."""

        async with self._resource.open_session(write=True) as session:
            connection = _connection(session)
            execute_script = getattr(connection, "executescript", None)
            script = """
                CREATE TABLE IF NOT EXISTS privacy_context_provider_configuration (
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
                "FROM privacy_context_provider_configuration WHERE context_id = ?",
                (self.policy.context_id,),
            ).fetchone()
            payload = _json(self.policy.payload)
            if existing is None:
                connection.execute(
                    "INSERT INTO privacy_context_provider_configuration "
                    "(context_id, configuration_digest, configuration_json) VALUES (?, ?, ?)",
                    (self.policy.context_id, self.policy.digest, payload),
                )
            elif (
                existing["configuration_digest"] != self.policy.digest
                or existing["configuration_json"] != payload
            ):
                raise PrivacyContextError("privacy context configuration drifted")

    def provider_module(self) -> ProviderModule:
        return ProviderModule(
            module_id=_MODULE_ID,
            identity=self.policy.provider_identity,
            domain=self._domain,
            scope_derivation_id=self._domain.scope_derivation_id,
            certified_inputs=self._contracts,
        )


__all__ = [
    "ConsentMarketingRule",
    "PhiRecipientRule",
    "PiiClassifierConfig",
    "PrivacyContextError",
    "PrivacyContextPolicy",
    "PrivacyContextProvider",
    "PrivacyContextSource",
    "PrivacyTransferRule",
    "ReferencePrivacyContextSource",
]
