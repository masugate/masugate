"""Regression tests for the no-network optional connector preflight command."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import cast

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts/optional-connector-preflight.py"

CALENDAR_ENV = {
    "MASUGATE_GOOGLE_CALENDAR_ID": "calendar_configured",
    "MASUGATE_GOOGLE_CALENDAR_OAUTH_SECRET_REF": "calendar_secret",
    "MASUGATE_GOOGLE_CALENDAR_OAUTH_SCOPE": "https://www.googleapis.com/auth/calendar",
}
STRIPE_ENV = {
    "MASUGATE_STRIPE_ACCOUNT_ID": "acct_configured",
    "MASUGATE_STRIPE_CUSTOMER_ID": "cus_configured",
    "MASUGATE_STRIPE_PAYMENT_METHOD_ID": "pm_configured",
    "MASUGATE_STRIPE_SECRET_REF": "stripe_secret",
    "MASUGATE_STRIPE_MERCHANT_IDS": "merchant_configured",
    "MASUGATE_STRIPE_CURRENCY": "usd",
    "MASUGATE_STRIPE_API_VERSION": "2025-06-30.basil",
}


def _run(
    profile: str,
    extra_environment: dict[str, str] | None = None,
    *arguments: str,
) -> dict[str, object]:
    environment = {"PATH": os.environ["PATH"]}
    if extra_environment is not None:
        environment.update(extra_environment)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), profile, *arguments],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    return cast(dict[str, object], json.loads(result.stdout))


def test_calendar_without_deployment_configuration_is_a_safe_skip() -> None:
    result = _run("calendar")
    assert result["result"] == "SKIPPED"
    assert result["network_access"] is False
    assert result["credentials_read"] is False
    assert result["missing_configuration"] == [
        "MASUGATE_GOOGLE_CALENDAR_ID",
        "MASUGATE_GOOGLE_CALENDAR_OAUTH_SECRET_REF",
        "MASUGATE_GOOGLE_CALENDAR_OAUTH_SCOPE",
    ]


def test_stripe_with_configuration_still_does_not_attempt_a_live_service() -> None:
    result = _run(
        "stripe",
        {
            "MASUGATE_STRIPE_ACCOUNT_ID": "configured",
            "MASUGATE_STRIPE_CUSTOMER_ID": "configured",
            "MASUGATE_STRIPE_PAYMENT_METHOD_ID": "configured",
            "MASUGATE_STRIPE_SECRET_REF": "configured",
            "MASUGATE_STRIPE_MERCHANT_IDS": "configured",
            "MASUGATE_STRIPE_CURRENCY": "configured",
            "MASUGATE_STRIPE_API_VERSION": "configured",
        },
    )
    assert result == {
        "credentials_read": False,
        "missing_configuration": [],
        "network_access": False,
        "profile": "stripe",
        "reason": "live execution was not requested",
        "result": "SKIPPED",
    }


def test_combined_profile_reports_the_union_of_missing_configuration() -> None:
    result = _run("both")
    assert result["result"] == "SKIPPED"
    assert result["profile"] == "both"
    assert result["credentials_read"] is False
    assert result["network_access"] is False
    assert result["missing_configuration"] == [
        "MASUGATE_GOOGLE_CALENDAR_ID",
        "MASUGATE_GOOGLE_CALENDAR_OAUTH_SECRET_REF",
        "MASUGATE_GOOGLE_CALENDAR_OAUTH_SCOPE",
        "MASUGATE_STRIPE_ACCOUNT_ID",
        "MASUGATE_STRIPE_CUSTOMER_ID",
        "MASUGATE_STRIPE_PAYMENT_METHOD_ID",
        "MASUGATE_STRIPE_SECRET_REF",
        "MASUGATE_STRIPE_MERCHANT_IDS",
        "MASUGATE_STRIPE_CURRENCY",
        "MASUGATE_STRIPE_API_VERSION",
    ]


def test_live_execution_requires_an_explicit_side_effect_acknowledgement() -> None:
    result = _run("stripe", STRIPE_ENV, "--execute-live")
    assert result == {
        "credentials_read": False,
        "missing_configuration": [],
        "network_access": False,
        "profile": "stripe",
        "reason": "live execution requires --confirm-side-effects",
        "result": "SKIPPED",
    }


def test_calendar_live_request_with_no_secret_file_is_a_safe_skip() -> None:
    result = _run("calendar", CALENDAR_ENV, "--execute-live", "--confirm-side-effects")
    assert result == {
        "credentials_read": False,
        "missing_configuration": ["MASUGATE_GOOGLE_CALENDAR_OAUTH_SECRET_FILE"],
        "network_access": False,
        "profile": "calendar",
        "reason": "missing required live secret-file prerequisite",
        "result": "SKIPPED",
    }


def test_stripe_live_request_with_no_secret_file_is_a_safe_skip() -> None:
    result = _run("stripe", STRIPE_ENV, "--execute-live", "--confirm-side-effects")
    assert result == {
        "credentials_read": False,
        "missing_configuration": ["MASUGATE_STRIPE_SECRET_FILE"],
        "network_access": False,
        "profile": "stripe",
        "reason": "missing required live secret-file prerequisite",
        "result": "SKIPPED",
    }


def test_combined_live_request_with_no_secret_files_is_a_safe_skip() -> None:
    result = _run(
        "both", {**CALENDAR_ENV, **STRIPE_ENV}, "--execute-live", "--confirm-side-effects"
    )
    assert result == {
        "credentials_read": False,
        "missing_configuration": [
            "MASUGATE_GOOGLE_CALENDAR_OAUTH_SECRET_FILE",
            "MASUGATE_STRIPE_SECRET_FILE",
        ],
        "network_access": False,
        "profile": "both",
        "reason": "missing required live secret-file prerequisite",
        "result": "SKIPPED",
    }


def test_invalid_secret_file_is_a_safe_skip_before_any_live_connector_runs(tmp_path: Path) -> None:
    empty_secret = tmp_path / "empty-secret"
    empty_secret.touch()
    result = _run(
        "calendar",
        {**CALENDAR_ENV, "MASUGATE_GOOGLE_CALENDAR_OAUTH_SECRET_FILE": str(empty_secret)},
        "--execute-live",
        "--confirm-side-effects",
    )
    assert result["result"] == "SKIPPED"
    assert result["credentials_read"] is False
    assert result["network_access"] is False
    assert result["missing_configuration"] == ["MASUGATE_GOOGLE_CALENDAR_OAUTH_SECRET_FILE"]
