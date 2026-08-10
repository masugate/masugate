"""Exact Stripe PaymentIntent v1 test-mode connector using only the public SDK."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
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

_ACTION = "spend.purchase"
_ORIGIN = "https://api.stripe.com"
_DESTINATION = "stripe-api-v1"
_DESTINATIONS = (_DESTINATION,)
_API_VERSION = "2025-11-17.clover"
_CURRENCY = "usd"
_RETRY_RETENTION = timedelta(hours=23)
_MAX_RESPONSE_BYTES = 32 * 1024
_MIN_AMOUNT_CENTS = 50
_MAX_AMOUNT_CENTS = 99_999_999
_CAPABILITIES = ConnectorCapabilities(
    idempotent_dispatch=True,
    status_query=True,
    cancellation=True,
    fencing=True,
    max_payload_bytes=2 * 1024,
    max_result_bytes=_MAX_RESPONSE_BYTES,
    ambiguity_handling="status-query",
)
type HttpResult = tuple[int, Mapping[str, str], bytes]
type HttpTransport = Callable[[str, str, Mapping[str, str], bytes | None], Awaitable[HttpResult]]
type Clock = Callable[[], datetime]


def _system_clock() -> datetime:
    return datetime.now(UTC)


def _identity(value: object, field_name: str) -> str:
    if not (
        type(value) is str
        and 0 < len(value) <= 255
        and value.strip() == value
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise ConnectorSDKError(f"{field_name} must be a canonical identifier")
    return value


def _prefixed(value: object, field_name: str, prefix: str) -> str:
    result = _identity(value, field_name)
    if not result.startswith(prefix):
        raise ConnectorSDKError(f"{field_name} must start with {prefix}")
    return result


def _aware(value: object, field_name: str) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise ConnectorSDKError(f"{field_name} must be timezone-aware")
    return value


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, *_args: object) -> None:
        return None


@dataclass(frozen=True)
class StripePaymentIntentProfile:
    """Trusted exact PaymentIntent configuration; no invocation selects it."""

    stripe_account_id: str
    customer_id: str
    payment_method_id: str
    stripe_secret_ref: str
    merchant_ids: tuple[str, ...]
    currency: str = _CURRENCY
    api_version: str = _API_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "stripe_account_id",
            _prefixed(self.stripe_account_id, "stripe_account_id", "acct_"),
        )
        object.__setattr__(self, "customer_id", _prefixed(self.customer_id, "customer_id", "cus_"))
        object.__setattr__(
            self, "payment_method_id", _prefixed(self.payment_method_id, "payment_method_id", "pm_")
        )
        object.__setattr__(
            self, "stripe_secret_ref", _identity(self.stripe_secret_ref, "stripe_secret_ref")
        )
        if type(self.merchant_ids) is not tuple:
            raise ConnectorSDKError("Stripe profile merchant_ids must be a tuple")
        merchants = tuple(sorted(_identity(value, "merchant_id") for value in self.merchant_ids))
        if not merchants or len(set(merchants)) != len(merchants):
            raise ConnectorSDKError("Stripe profile merchant_ids must be non-empty and unique")
        object.__setattr__(self, "merchant_ids", merchants)
        if self.currency != _CURRENCY:
            raise ConnectorSDKError("Stripe PaymentIntent profile requires the exact USD currency")
        if self.api_version != _API_VERSION:
            raise ConnectorSDKError("Stripe PaymentIntent profile requires the exact API version")

    @property
    def digest(self) -> str:
        payload = {
            "api_version": self.api_version,
            "capture_method": "automatic",
            "confirmation_method": "manual",
            "currency": self.currency,
            "customer_id": self.customer_id,
            "destinations": _DESTINATIONS,
            "merchant_ids": self.merchant_ids,
            "origin": _ORIGIN,
            "payment_method_id": self.payment_method_id,
            "profile": "masugate.stripe.payment-intent.v1.test-mode",
            "stripe_account_id": self.stripe_account_id,
            "test_mode": True,
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
            raise ConnectorSDKError("Stripe transport returned an unreadable response")
        result = reader(_MAX_RESPONSE_BYTES + 1)
        if type(result) is not bytes or len(result) > _MAX_RESPONSE_BYTES:
            raise ConnectorSDKError("Stripe response exceeds the declared result bound")
        return result

    def send() -> HttpResult:
        request = Request(url, data=body, headers=dict(headers), method=method)
        try:
            with build_opener(_RejectRedirects()).open(request, timeout=15) as response:
                return response.status, dict(response.headers.items()), bounded_read(response)
        except HTTPError as error:
            return error.code, dict(error.headers.items()), bounded_read(error)

    return await asyncio.to_thread(send)


class StripePaymentIntentConnector:
    """Accept only the existing spend provider's exact immutable binding."""

    connector_id = "stripe-payment-intent-v1"
    sdk_contract_version = SDK_CONTRACT_VERSION
    capabilities = _CAPABILITIES

    def __init__(
        self,
        profile: StripePaymentIntentProfile,
        *,
        transport: HttpTransport = _stdlib_transport,
        clock: Clock | None = None,
    ) -> None:
        if type(profile) is not StripePaymentIntentProfile or not callable(transport):
            raise TypeError("StripePaymentIntentConnector requires a profile and HTTP transport")
        if clock is not None and not callable(clock):
            raise TypeError("StripePaymentIntentConnector clock must be callable")
        self.profile = profile
        self._transport = transport
        self._clock: Clock = _system_clock if clock is None else clock

    @property
    def configuration_digest(self) -> str:
        """Expose the exact trusted profile to the worker's drift check."""

        return self.profile.digest

    def _validate(self, invocation: ConnectorInvocation) -> tuple[int, str, str, bytes]:
        if invocation.action != _ACTION:
            raise ConnectorSDKError("Stripe PaymentIntent profile does not own this action")
        if invocation.connector_id != self.connector_id:
            raise ConnectorSDKError("Stripe PaymentIntent profile has the wrong connector identity")
        if invocation.connector_configuration_digest != self.configuration_digest:
            raise ConnectorSDKError("Stripe PaymentIntent profile configuration drifted")
        if invocation.artifacts:
            raise ConnectorSDKError("Stripe PaymentIntent profile refuses artifacts")
        if invocation.allowed_destinations != _DESTINATIONS:
            raise ConnectorSDKError(
                "Stripe PaymentIntent profile has an unexpected destination set"
            )
        if tuple(invocation.secrets) != (self.profile.stripe_secret_ref,):
            raise ConnectorSDKError(
                "Stripe PaymentIntent profile has an unexpected secret reference"
            )
        token = invocation.secrets[self.profile.stripe_secret_ref].read()
        if not token.startswith(b"sk_test_") or any(byte < 0x21 or byte > 0x7E for byte in token):
            raise ConnectorSDKError(
                "Stripe PaymentIntent profile requires one printable sk_test_ secret"
            )
        if set(invocation.arguments) != {"amount_cents", "merchant_id", "request_ref"}:
            raise ConnectorSDKError(
                "Stripe PaymentIntent profile refuses unsupported payment fields"
            )
        amount = invocation.arguments["amount_cents"]
        merchant = invocation.arguments["merchant_id"]
        request_ref = invocation.arguments["request_ref"]
        if type(amount) is not int or not _MIN_AMOUNT_CENTS <= amount <= _MAX_AMOUNT_CENTS:
            raise ConnectorSDKError(
                "Stripe PaymentIntent amount is outside the exact USD test profile"
            )
        merchant_id = _identity(merchant, "merchant_id")
        if merchant_id not in self.profile.merchant_ids:
            raise ConnectorSDKError("Stripe PaymentIntent merchant is not allowlisted")
        return amount, merchant_id, _identity(request_ref, "request_ref"), token

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
            raise ConnectorSDKError("Stripe response exceeds the declared result bound")
        return result

    def _headers(self, token: bytes, *, idempotency_key: str | None = None) -> Mapping[str, str]:
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token.decode("ascii"),
            "Stripe-Account": self.profile.stripe_account_id,
            "Stripe-Version": self.profile.api_version,
        }
        if idempotency_key is not None:
            headers["Idempotency-Key"] = _identity(idempotency_key, "idempotency_key")
        return MappingProxyType(headers)

    def _payment_intent(
        self, body: bytes, *, expected_id: str | None = None
    ) -> Mapping[str, object]:
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ConnectorSDKError("Stripe returned malformed JSON") from exc
        if not isinstance(payload, dict):
            raise ConnectorSDKError("Stripe response must be a PaymentIntent object")
        identifier = _prefixed(payload.get("id"), "Stripe PaymentIntent id", "pi_")
        if expected_id is not None and identifier != expected_id:
            raise ConnectorSDKError("Stripe response names the wrong PaymentIntent")
        if payload.get("object") != "payment_intent":
            raise ConnectorSDKError("Stripe response is not a PaymentIntent")
        if type(payload.get("amount")) is not int or payload["amount"] < _MIN_AMOUNT_CENTS:
            raise ConnectorSDKError("Stripe PaymentIntent response has an invalid amount")
        if payload.get("currency") != self.profile.currency:
            raise ConnectorSDKError("Stripe PaymentIntent response has the wrong currency")
        if payload.get("customer") != self.profile.customer_id:
            raise ConnectorSDKError("Stripe PaymentIntent response has the wrong customer")
        if payload.get("payment_method") != self.profile.payment_method_id:
            raise ConnectorSDKError("Stripe PaymentIntent response has the wrong payment method")
        if payload.get("livemode") is not False:
            raise ConnectorSDKError("Stripe PaymentIntent response is not test mode")
        if payload.get("capture_method") != "automatic":
            raise ConnectorSDKError("Stripe PaymentIntent response has the wrong capture method")
        if payload.get("confirmation_method") != "manual":
            raise ConnectorSDKError(
                "Stripe PaymentIntent response has the wrong confirmation method"
            )
        status = payload.get("status")
        if status not in {
            "succeeded",
            "canceled",
            "processing",
            "requires_action",
            "requires_capture",
            "requires_confirmation",
            "requires_payment_method",
        }:
            raise ConnectorSDKError("Stripe PaymentIntent response has an unsupported status")
        return MappingProxyType(payload)

    def _error_payment_intent(self, body: bytes) -> Mapping[str, object] | None:
        try:
            payload = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict) or not isinstance(payload.get("error"), dict):
            return None
        payment_intent = payload["error"].get("payment_intent")
        if not isinstance(payment_intent, dict):
            return None
        return self._payment_intent(json.dumps(payment_intent).encode("utf-8"))

    def _evidence(
        self,
        invocation: ConnectorInvocation,
        payment_intent: Mapping[str, object],
        merchant_id: str,
        request_ref: str,
        *,
        outcome: ConnectorOutcome,
    ) -> ConnectorEvidence:
        payment_intent_id = _prefixed(payment_intent["id"], "Stripe PaymentIntent id", "pi_")
        status = payment_intent["status"]
        amount = payment_intent["amount"]
        assert type(status) is str
        assert type(amount) is int
        return ConnectorEvidence(
            connector_id=self.connector_id,
            evidence_id=f"stripe-payment-intent:{payment_intent_id}:{status}",
            idempotency_key=invocation.idempotency_key,
            external_operation_id=payment_intent_id,
            outcome=outcome,
            observed_at=_aware(self._clock(), "Stripe connector clock"),
            payload={
                "amount_cents": amount,
                "currency": self.profile.currency,
                "merchant_id": merchant_id,
                "request_ref": request_ref,
                "status": status,
            },
        )

    def _outcome(
        self,
        invocation: ConnectorInvocation,
        payment_intent: Mapping[str, object],
        merchant_id: str,
        request_ref: str,
        *,
        cancellation: bool = False,
    ) -> ConnectorEvidence:
        amount = payment_intent["amount"]
        assert type(amount) is int
        if amount != invocation.arguments["amount_cents"]:
            raise ConnectorSDKError("Stripe PaymentIntent response has the wrong amount")
        status = payment_intent["status"]
        assert type(status) is str
        if status == "succeeded":
            if payment_intent.get("amount_received") != amount:
                raise ConnectorSDKError(
                    "Stripe succeeded PaymentIntent has the wrong received amount"
                )
            return self._evidence(
                invocation,
                payment_intent,
                merchant_id,
                request_ref,
                outcome=ConnectorOutcome.SUCCEEDED,
            )
        if status == "canceled":
            return self._evidence(
                invocation,
                payment_intent,
                merchant_id,
                request_ref,
                outcome=ConnectorOutcome.FAILED,
            )
        label = "cancellation" if cancellation else "dispatch"
        raise ConnectorAmbiguousOutcome(
            f"Stripe PaymentIntent {label} is not terminal",
            external_operation_id=_prefixed(payment_intent["id"], "Stripe PaymentIntent id", "pi_"),
        )

    async def _create_outcome(
        self,
        invocation: ConnectorInvocation,
        payment_intent: Mapping[str, object],
        merchant_id: str,
        request_ref: str,
    ) -> ConnectorEvidence:
        """Cancel a retryable decline before releasing its spend reservation."""

        status = payment_intent["status"]
        assert type(status) is str
        if status == "requires_payment_method":
            payment_intent_id = _prefixed(payment_intent["id"], "Stripe PaymentIntent id", "pi_")
            # A failed confirmation may remain mutable and confirmable. Do not
            # report a terminal MasuGate failure until Stripe has authoritatively
            # canceled this exact PaymentIntent; cancellation failure remains
            # outcome-unknown with the returned pi_ identity.
            return await self.cancel(invocation, external_operation_id=payment_intent_id)
        return self._outcome(invocation, payment_intent, merchant_id, request_ref)

    def _create_body(self, amount: int) -> bytes:
        return urlencode(
            {
                "amount": str(amount),
                "capture_method": "automatic",
                "confirm": "true",
                "confirmation_method": "manual",
                "currency": self.profile.currency,
                "customer": self.profile.customer_id,
                "off_session": "true",
                "payment_method": self.profile.payment_method_id,
                "payment_method_types[0]": "card",
            }
        ).encode("ascii")

    async def execute(self, invocation: ConnectorInvocation) -> ConnectorEvidence:
        amount, merchant_id, request_ref, token = self._validate(invocation)
        headers = dict(self._headers(token, idempotency_key=invocation.idempotency_key))
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            code, _headers, body = await self._request(
                "POST",
                _ORIGIN + "/v1/payment_intents",
                MappingProxyType(headers),
                self._create_body(amount),
            )
        except (OSError, TimeoutError) as exc:
            raise ConnectorAmbiguousOutcome("Stripe PaymentIntent response lost") from exc
        if code in {200, 201}:
            return await self._create_outcome(
                invocation, self._payment_intent(body), merchant_id, request_ref
            )
        if code in {400, 402}:
            payment_intent = self._error_payment_intent(body)
            if payment_intent is not None:
                return await self._create_outcome(
                    invocation, payment_intent, merchant_id, request_ref
                )
        raise ConnectorAmbiguousOutcome("Stripe PaymentIntent creation was not conclusive")

    async def _get(
        self,
        invocation: ConnectorInvocation,
        payment_intent_id: str,
        token: bytes,
        merchant_id: str,
        request_ref: str,
    ) -> ConnectorEvidence:
        try:
            code, _headers, body = await self._request(
                "GET",
                _ORIGIN + "/v1/payment_intents/" + quote(payment_intent_id, safe=""),
                self._headers(token),
                None,
            )
        except (OSError, TimeoutError) as exc:
            raise ConnectorAmbiguousOutcome(
                "Stripe PaymentIntent status query failed", external_operation_id=payment_intent_id
            ) from exc
        if code != 200:
            raise ConnectorAmbiguousOutcome(
                "Stripe PaymentIntent status query was not conclusive",
                external_operation_id=payment_intent_id,
            )
        return self._outcome(
            invocation,
            self._payment_intent(body, expected_id=payment_intent_id),
            merchant_id,
            request_ref,
        )

    def _retry_allowed(self, invocation: ConnectorInvocation) -> bool:
        started_at = invocation.idempotency_started_at
        if started_at is None:
            return False
        return (
            _aware(self._clock(), "Stripe connector clock")
            <= _aware(started_at, "idempotency_started_at") + _RETRY_RETENTION
        )

    async def query_status(
        self, invocation: ConnectorInvocation, *, external_operation_id: str | None
    ) -> ConnectorEvidence:
        _amount, merchant_id, request_ref, token = self._validate(invocation)
        if external_operation_id is None:
            if not self._retry_allowed(invocation):
                raise ConnectorAmbiguousOutcome(
                    "Stripe PaymentIntent id is absent outside the idempotency retry window"
                )
            # Stripe v1 returns the original POST result for the same key while
            # it retains that key. This is the sole retry path without a pi_ id.
            return await self.execute(invocation)
        payment_intent_id = _prefixed(external_operation_id, "Stripe external_operation_id", "pi_")
        return await self._get(invocation, payment_intent_id, token, merchant_id, request_ref)

    async def cancel(
        self, invocation: ConnectorInvocation, *, external_operation_id: str | None
    ) -> ConnectorEvidence:
        _amount, merchant_id, request_ref, token = self._validate(invocation)
        if external_operation_id is None:
            raise ConnectorAmbiguousOutcome("Stripe cancellation has no PaymentIntent id")
        payment_intent_id = _prefixed(external_operation_id, "Stripe external_operation_id", "pi_")
        key = (
            "masugate-cancel-"
            + hashlib.sha256(invocation.idempotency_key.encode("utf-8")).hexdigest()
        )
        headers = dict(self._headers(token, idempotency_key=key))
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            code, _headers, body = await self._request(
                "POST",
                _ORIGIN + "/v1/payment_intents/" + quote(payment_intent_id, safe="") + "/cancel",
                MappingProxyType(headers),
                b"cancellation_reason=abandoned",
            )
        except (OSError, TimeoutError) as exc:
            raise ConnectorAmbiguousOutcome(
                "Stripe PaymentIntent cancellation response lost",
                external_operation_id=payment_intent_id,
            ) from exc
        if code == 200:
            return self._outcome(
                invocation,
                self._payment_intent(body, expected_id=payment_intent_id),
                merchant_id,
                request_ref,
                cancellation=True,
            )
        # A non-cancelable intent may already be terminal. Query rather than
        # reporting a cancellation outcome from Stripe's error envelope.
        return await self._get(invocation, payment_intent_id, token, merchant_id, request_ref)


class _EnvironmentConnector:
    """Lazy worker entry point; trusted configuration is read only at dispatch."""

    connector_id = StripePaymentIntentConnector.connector_id
    sdk_contract_version = SDK_CONTRACT_VERSION
    capabilities = _CAPABILITIES

    @property
    def configuration_digest(self) -> str:
        # Read per operation so an environment change cannot reinterpret an
        # existing committed handoff under a new account or payment profile.
        return self._configured().configuration_digest

    @staticmethod
    def _configured() -> StripePaymentIntentConnector:
        try:
            merchants = tuple(
                merchant
                for merchant in os.environ["MASUGATE_STRIPE_MERCHANT_IDS"].split(",")
                if merchant
            )
            profile = StripePaymentIntentProfile(
                os.environ["MASUGATE_STRIPE_ACCOUNT_ID"],
                os.environ["MASUGATE_STRIPE_CUSTOMER_ID"],
                os.environ["MASUGATE_STRIPE_PAYMENT_METHOD_ID"],
                os.environ["MASUGATE_STRIPE_SECRET_REF"],
                merchants,
                os.environ["MASUGATE_STRIPE_CURRENCY"],
                os.environ["MASUGATE_STRIPE_API_VERSION"],
            )
        except KeyError as exc:
            raise ConnectorSDKError("Stripe worker configuration is missing") from exc
        return StripePaymentIntentConnector(profile)

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

__all__ = ["StripePaymentIntentConnector", "StripePaymentIntentProfile", "connector"]
