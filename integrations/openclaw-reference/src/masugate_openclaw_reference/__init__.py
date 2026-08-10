"""Bounded OpenClaw reference deployment assembly for reference spend.

This typed source package is intentionally excluded from the reusable MasuGate
distribution. It composes public MasuGate provider/protocol APIs with this
deployment's OpenClaw fleet and reference purchase service.
"""

from importlib import import_module
from typing import cast

from masugate_openclaw_reference.release import REFERENCE_RELEASE_VERSION

__version__ = REFERENCE_RELEASE_VERSION

from masugate_openclaw_reference.communications import (
    ReferenceCommunicationsResource,
    reference_communications_catalog,
    reference_communications_operational_catalog,
)
from masugate_openclaw_reference.deployment import (
    ReferenceSpendResource,
    build_postgres_reference_spend_resource,
    create_spend_reference_app,
    reference_spend_catalog,
    validate_openclaw_reference_roster,
)
from masugate_openclaw_reference.operational import (
    OperationalExecutionResult,
    OperationalResolverCredential,
    ReferenceOperationalResource,
    reference_certified_context_policy,
    reference_complete_operational_catalog,
    reference_operational_limits_catalog,
    reference_privacy_context_catalog,
    reference_privacy_context_policy,
    reference_regulatory_context_catalog,
    reference_regulatory_context_policy,
)
from masugate_openclaw_reference.purchase_api import create_reference_purchase_api_app

_CALENDAR_EXPORTS = frozenset(
    {
        "CalendarReferenceResource",
        "build_calendar_reference_resource",
        "create_calendar_reference_app",
    }
)


def __getattr__(name: str) -> object:
    """Load the optional calendar connector worker calendar profile only when it is requested.

    The reference platform reference-release wheel intentionally has no dependency on a
    connector ecosystem operation pack.  Keeping this import lazy preserves the clean
    legacy release and containment gates while retaining the established
    package-level calendar API for installations that include the pack.
    """

    if name not in _CALENDAR_EXPORTS:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    calendar = import_module(".calendar", __name__)
    return cast(object, getattr(calendar, name))


__all__ = [
    "CalendarReferenceResource",
    "OperationalExecutionResult",
    "OperationalResolverCredential",
    "ReferenceCommunicationsResource",
    "ReferenceOperationalResource",
    "ReferenceSpendResource",
    "build_calendar_reference_resource",
    "build_postgres_reference_spend_resource",
    "create_calendar_reference_app",
    "create_reference_purchase_api_app",
    "create_spend_reference_app",
    "reference_certified_context_policy",
    "reference_communications_catalog",
    "reference_communications_operational_catalog",
    "reference_complete_operational_catalog",
    "reference_operational_limits_catalog",
    "reference_privacy_context_catalog",
    "reference_privacy_context_policy",
    "reference_regulatory_context_catalog",
    "reference_regulatory_context_policy",
    "reference_spend_catalog",
    "validate_openclaw_reference_roster",
]
