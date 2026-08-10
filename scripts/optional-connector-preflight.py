#!/usr/bin/env python3
"""Preflight or deliberately run bounded optional Calendar and Stripe checks.

The default command is a safe preflight: it reads only configuration names and
never resolves a secret or opens a socket.  ``--execute-live`` is deliberately
separate, requires an explicit side-effect acknowledgement, and creates then
cleans up one disposable provider object per selected profile.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

_REQUIRED: dict[str, tuple[str, ...]] = {
    "calendar": (
        "MASUGATE_GOOGLE_CALENDAR_ID",
        "MASUGATE_GOOGLE_CALENDAR_OAUTH_SECRET_REF",
        "MASUGATE_GOOGLE_CALENDAR_OAUTH_SCOPE",
    ),
    "stripe": (
        "MASUGATE_STRIPE_ACCOUNT_ID",
        "MASUGATE_STRIPE_CUSTOMER_ID",
        "MASUGATE_STRIPE_PAYMENT_METHOD_ID",
        "MASUGATE_STRIPE_SECRET_REF",
        "MASUGATE_STRIPE_MERCHANT_IDS",
        "MASUGATE_STRIPE_CURRENCY",
        "MASUGATE_STRIPE_API_VERSION",
    ),
}
_SECRET_FILES = {
    "calendar": "MASUGATE_GOOGLE_CALENDAR_OAUTH_SECRET_FILE",
    "stripe": "MASUGATE_STRIPE_SECRET_FILE",
}


def _profiles(profile: str) -> tuple[str, ...]:
    return ("calendar", "stripe") if profile == "both" else (profile,)


def _missing(profiles: tuple[str, ...]) -> list[str]:
    return [name for profile in profiles for name in _REQUIRED[profile] if not os.environ.get(name)]


def _missing_live_secret_files(profiles: tuple[str, ...]) -> list[str]:
    """Report an unusable secret-file prerequisite without opening a secret.

    This check deliberately uses only environment names and file metadata.  A
    live run must never reach ``_secret_file`` merely to discover that an
    absent, symlinked, directory, or empty file cannot be a safe mounted
    secret.  The file bytes remain unread until this preflight and the explicit
    side-effect acknowledgement have both succeeded.
    """

    missing: list[str] = []
    for profile in profiles:
        name = _SECRET_FILES[profile]
        raw = os.environ.get(name)
        if not raw:
            missing.append(name)
            continue
        path = Path(raw)
        try:
            metadata = path.lstat()
        except OSError:
            missing.append(name)
            continue
        if path.is_symlink() or not path.is_file() or metadata.st_size <= 0:
            missing.append(name)
    return missing


def _write(payload: dict[str, object]) -> None:
    print(json.dumps(payload, sort_keys=True))


def _secret_file(profile: str) -> bytes:
    name = _SECRET_FILES[profile]
    raw = os.environ.get(name)
    if not raw:
        raise RuntimeError(f"{name} is required for live execution")
    path = Path(raw)
    if not path.is_file() or path.is_symlink():
        raise RuntimeError(f"{name} must name a regular non-symlink secret file")
    value = path.read_bytes()
    if not value:
        raise RuntimeError(f"{name} is empty")
    return value


def _identity(profile: str) -> tuple[str, str, str]:
    nonce = secrets.token_hex(12)
    execution_id = f"optional-live-{profile}-{nonce}"
    binding_digest = hashlib.sha256(execution_id.encode("utf-8")).hexdigest()
    idempotency_key = f"masugate-{execution_id}"
    return execution_id, binding_digest, idempotency_key


async def _calendar_live_check() -> None:
    from masugate_connector_google_calendar import GoogleCalendarConnector, GoogleCalendarProfile
    from masugate_connector_sdk import ConnectorInvocation, SecretHandle

    profile = GoogleCalendarProfile(
        os.environ["MASUGATE_GOOGLE_CALENDAR_ID"],
        os.environ["MASUGATE_GOOGLE_CALENDAR_OAUTH_SECRET_REF"],
        os.environ["MASUGATE_GOOGLE_CALENDAR_OAUTH_SCOPE"],
    )
    execution_id, binding_digest, idempotency_key = _identity("calendar")
    event_ref = f"calendar:masugate-live-{secrets.token_hex(12)}"
    start = datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5)
    end = start + timedelta(minutes=10)
    token = SecretHandle(_secret_file("calendar"))
    invocation = ConnectorInvocation(
        action="calendar.event.create",
        arguments={
            "title": "MasuGate optional connector validation",
            "description": "Disposable validation event; removed automatically.",
            "start_at": start.isoformat(),
            "end_at": end.isoformat(),
            "timezone": "UTC",
            "event_ref": event_ref,
        },
        execution_id=execution_id,
        binding_digest=binding_digest,
        connector_id=GoogleCalendarConnector.connector_id,
        idempotency_key=idempotency_key,
        fence_token=1,
        artifacts={},
        secrets={profile.oauth_secret_ref: token},
        allowed_destinations=("google-calendar-api-v3", "google-oauth2-tokeninfo"),
    )
    connector = GoogleCalendarConnector(profile)
    created = await connector.execute(invocation)
    if created.external_operation_id is None:
        raise RuntimeError("Calendar validation did not return an event identifier for cleanup")
    cancellation = ConnectorInvocation(
        action="calendar.event.cancel",
        arguments={"event_ref": event_ref, "external_event_id": created.external_operation_id},
        execution_id=execution_id,
        binding_digest=binding_digest,
        connector_id=GoogleCalendarConnector.connector_id,
        idempotency_key=idempotency_key,
        fence_token=2,
        artifacts={},
        secrets={profile.oauth_secret_ref: token},
        allowed_destinations=("google-calendar-api-v3", "google-oauth2-tokeninfo"),
    )
    await connector.cancel(cancellation, external_operation_id=created.external_operation_id)


async def _stripe_live_check() -> None:
    from masugate_connector_sdk import ConnectorInvocation, SecretHandle
    from masugate_connector_stripe_payment_intent import (
        StripePaymentIntentConnector,
        StripePaymentIntentProfile,
    )

    profile = StripePaymentIntentProfile(
        os.environ["MASUGATE_STRIPE_ACCOUNT_ID"],
        os.environ["MASUGATE_STRIPE_CUSTOMER_ID"],
        os.environ["MASUGATE_STRIPE_PAYMENT_METHOD_ID"],
        os.environ["MASUGATE_STRIPE_SECRET_REF"],
        tuple(
            merchant
            for merchant in os.environ["MASUGATE_STRIPE_MERCHANT_IDS"].split(",")
            if merchant
        ),
        os.environ["MASUGATE_STRIPE_CURRENCY"],
        os.environ["MASUGATE_STRIPE_API_VERSION"],
    )
    execution_id, binding_digest, idempotency_key = _identity("stripe")
    secret = SecretHandle(_secret_file("stripe"))
    connector = StripePaymentIntentConnector(profile)
    invocation = ConnectorInvocation(
        action="spend.purchase",
        arguments={
            "amount_cents": 50,
            "merchant_id": profile.merchant_ids[0],
            "request_ref": f"masugate-live-{secrets.token_hex(12)}",
        },
        execution_id=execution_id,
        binding_digest=binding_digest,
        connector_id=connector.connector_id,
        idempotency_key=idempotency_key,
        fence_token=1,
        artifacts={},
        secrets={profile.stripe_secret_ref: secret},
        allowed_destinations=("stripe-api-v1",),
        connector_configuration_digest=profile.digest,
    )
    created = await connector.execute(invocation)
    if created.external_operation_id is None:
        raise RuntimeError(
            "Stripe validation did not return a PaymentIntent identifier for cleanup"
        )
    await connector.cancel(invocation, external_operation_id=created.external_operation_id)


async def _run_live(profiles: tuple[str, ...]) -> None:
    for profile in profiles:
        if profile == "calendar":
            await _calendar_live_check()
        else:
            await _stripe_live_check()


def main() -> None:
    parser = argparse.ArgumentParser(description="safe optional connector preflight")
    parser.add_argument("profile", choices=("calendar", "stripe", "both"))
    parser.add_argument(
        "--execute-live",
        action="store_true",
        help="create then clean up the selected disposable provider object",
    )
    parser.add_argument(
        "--confirm-side-effects",
        action="store_true",
        help="acknowledge the documented disposable Calendar event or Stripe test PaymentIntent",
    )
    args = parser.parse_args()
    profiles = _profiles(args.profile)
    missing = _missing(profiles)
    if missing:
        _write(
            {
                "credentials_read": False,
                "missing_configuration": missing,
                "network_access": False,
                "profile": args.profile,
                "reason": "missing required configuration",
                "result": "SKIPPED",
            }
        )
        return
    if not args.execute_live:
        _write(
            {
                "credentials_read": False,
                "missing_configuration": [],
                "network_access": False,
                "profile": args.profile,
                "reason": "live execution was not requested",
                "result": "SKIPPED",
            }
        )
        return
    if not args.confirm_side_effects:
        _write(
            {
                "credentials_read": False,
                "missing_configuration": [],
                "network_access": False,
                "profile": args.profile,
                "reason": "live execution requires --confirm-side-effects",
                "result": "SKIPPED",
            }
        )
        return
    missing_secret_files = _missing_live_secret_files(profiles)
    if missing_secret_files:
        _write(
            {
                "credentials_read": False,
                "missing_configuration": missing_secret_files,
                "network_access": False,
                "profile": args.profile,
                "reason": "missing required live secret-file prerequisite",
                "result": "SKIPPED",
            }
        )
        return
    try:
        asyncio.run(_run_live(profiles))
    except Exception as exc:
        raise SystemExit(f"optional connector live validation failed: {exc}") from exc
    _write(
        {
            "credentials_read": True,
            "missing_configuration": [],
            "network_access": True,
            "profile": args.profile,
            "result": "PASS",
            "side_effects": "created and cleaned up one disposable provider object per profile",
        }
    )


if __name__ == "__main__":
    main()
