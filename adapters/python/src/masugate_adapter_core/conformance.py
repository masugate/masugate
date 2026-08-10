"""Published fixture and helpers for adapter-core conformance runners."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from importlib.resources import files
from typing import Literal, cast

from masugate_client import MasuGateAPIError, Scalar, canonical_adapter_envelope

from .runtime import (
    AdapterCapabilities,
    AdapterCoreError,
    AdapterModelArgumentsError,
    ChangedInvocationConflictError,
    GovernedActionClient,
    GovernedLifecycle,
    GovernedRouteParser,
    GovernedToolRuntime,
    PendingLocatorMismatchError,
    TrustedInvocation,
    UnsupportedAdapterCapabilityError,
)


@dataclass(frozen=True, slots=True)
class AdapterCoreConformanceFixture:
    """Trusted inputs and canonical bytes shared by every host binding test."""

    manifest: object
    principal_id: str
    source_namespace: str
    source_id: str
    adapter_id: str
    capabilities: tuple[str, ...]
    model_arguments: dict[str, object]
    canonical_route_manifest: str
    canonical_trusted_invocation: str
    conformance_version: Literal["masugate.adapter-core-conformance.v1"]
    scenarios: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class AdapterCoreConformanceReport:
    """Language-neutral result representation for the shared scenario corpus."""

    conformance_version: str
    passed_case_ids: tuple[str, ...]


# The caller supplies one configured public GAP client per scenario. This keeps
# the corpus independent of any framework/policy while making every published
# scenario executable rather than a repository-only unit test.
AdapterCoreConformanceClientFactory = Callable[[str], GovernedActionClient]


def load_adapter_core_conformance_fixture() -> AdapterCoreConformanceFixture:
    """Load the fixture shipped with this distribution, not a repository-relative file."""

    raw = json.loads(
        files("masugate_adapter_core")
        .joinpath("adapter-core-conformance.json")
        .read_text(encoding="utf-8")
    )
    root = _record(raw, "adapter core conformance fixture")
    trusted = _record(root.get("trusted_invocation"), "trusted_invocation")
    capabilities = trusted.get("capabilities")
    model_arguments = _record(root.get("model_arguments"), "model_arguments")
    version = _string(root.get("conformance_version"), "conformance_version")
    if version != "masugate.adapter-core-conformance.v1":
        raise AdapterCoreError("adapter core conformance version is unsupported")
    return AdapterCoreConformanceFixture(
        manifest=root.get("manifest"),
        principal_id=_string(trusted.get("principal_id"), "trusted_invocation.principal_id"),
        source_namespace=_string(
            trusted.get("source_namespace"), "trusted_invocation.source_namespace"
        ),
        source_id=_string(trusted.get("source_id"), "trusted_invocation.source_id"),
        adapter_id=_string(trusted.get("adapter_id"), "trusted_invocation.adapter_id"),
        capabilities=_strings(capabilities, "trusted_invocation.capabilities"),
        model_arguments=dict(model_arguments),
        canonical_route_manifest=_string(
            root.get("canonical_route_manifest"), "canonical_route_manifest"
        ),
        canonical_trusted_invocation=_string(
            root.get("canonical_trusted_invocation"), "canonical_trusted_invocation"
        ),
        conformance_version="masugate.adapter-core-conformance.v1",
        scenarios=_scenarios(root.get("scenarios")),
    )


def create_adapter_core_conformance_runtime(
    client: GovernedActionClient,
    fixture: AdapterCoreConformanceFixture | None = None,
    *,
    source_id: str | None = None,
) -> GovernedToolRuntime:
    """Build a runtime for either a fake GAP client or a real ``masugated`` client."""

    case = fixture or load_adapter_core_conformance_fixture()
    return GovernedToolRuntime(
        client=client,
        routes=GovernedRouteParser(case.manifest),
        invocation=TrustedInvocation(
            principal_id=case.principal_id,
            source_namespace=case.source_namespace,
            # ``""`` is an invalid trusted identity, not an omitted option.
            # Let ``TrustedInvocation`` reject it rather than aliasing the
            # fixture call identity as Python's truthiness would.
            source_id=case.source_id if source_id is None else source_id,
            adapter=AdapterCapabilities(
                adapter_id=case.adapter_id,
                capabilities=case.capabilities,
            ),
        ),
    )


def assert_adapter_core_conformance_canonical_bytes(
    runtime: GovernedToolRuntime,
    fixture: AdapterCoreConformanceFixture | None = None,
) -> None:
    """Fail when a binding's route or trusted invocation diverges from the fixture."""

    case = fixture or load_adapter_core_conformance_fixture()
    route = runtime.routes.select("purchase")
    invocation = runtime.invocation.adapter_invocation(
        route,
        cast(dict[str, Scalar], case.model_arguments),
    )
    if runtime.routes.canonical_manifest != case.canonical_route_manifest:
        raise AdapterCoreError("conformance route canonical bytes differ from the shared fixture")
    if canonical_adapter_envelope(invocation) != case.canonical_trusted_invocation:
        raise AdapterCoreError(
            "conformance trusted-invocation bytes differ from the shared fixture"
        )


async def run_adapter_core_conformance(
    client_factory: AdapterCoreConformanceClientFactory,
    fixture: AdapterCoreConformanceFixture | None = None,
) -> AdapterCoreConformanceReport:
    """Run the complete portable adapter-core corpus through public clients."""

    case = fixture or load_adapter_core_conformance_fixture()
    expected = (
        ("canonical-bytes", "match"),
        ("forged-fields", "rejected"),
        ("exact-retry", "same-operation"),
        ("changed-content", "conflict"),
        ("distinct-calls", "distinct-operations"),
        ("lifecycle-committed", "committed"),
        ("lifecycle-denied", "denied"),
        ("lifecycle-pending", "pending"),
        ("lifecycle-in-progress", "in_progress"),
        ("lifecycle-outcome-unknown", "outcome_unknown"),
        ("pending-resume", "same-locator"),
        ("pending-terminal", "same-operation"),
        ("locator-checks", "mismatch-rejected"),
        ("capability-gates", "unsupported-rejected"),
    )
    if case.scenarios != expected:
        raise AdapterCoreError("adapter core conformance scenarios are unsupported")

    def runtime_for(
        scenario: str,
        *,
        source_id: str | None = None,
        capabilities: tuple[str, ...] | None = None,
    ) -> GovernedToolRuntime:
        client = client_factory(scenario)
        if capabilities is None:
            return create_adapter_core_conformance_runtime(client, case, source_id=source_id)
        return GovernedToolRuntime(
            client=client,
            routes=GovernedRouteParser(case.manifest),
            invocation=TrustedInvocation(
                principal_id=case.principal_id,
                source_namespace=case.source_namespace,
                source_id=case.source_id if source_id is None else source_id,
                adapter=AdapterCapabilities(case.adapter_id, capabilities),
            ),
        )

    assert_adapter_core_conformance_canonical_bytes(runtime_for("canonical-bytes"), case)

    forged_runtime = runtime_for("forged-fields")
    for name in ("principal_id", "owner", "locator", "pending_id"):
        forged = dict(case.model_arguments)
        forged[name] = "model-controlled"
        try:
            await forged_runtime.invoke("purchase", forged)
        except AdapterModelArgumentsError:
            pass
        else:
            raise AdapterCoreError(f"model arguments could forge {name}")

    retry_runtime = runtime_for("exact-retry")
    first = await retry_runtime.invoke("purchase", case.model_arguments)
    replay = await retry_runtime.invoke("purchase", case.model_arguments)
    if replay.result.operation_id != first.result.operation_id or not replay.result.replayed:
        raise AdapterCoreError("exact retry did not replay one authoritative operation")

    changed_runtime = runtime_for("changed-content")
    await changed_runtime.invoke("purchase", case.model_arguments)
    changed_arguments = dict(case.model_arguments)
    changed_arguments["amount_cents"] = 1251
    try:
        await changed_runtime.invoke("purchase", changed_arguments)
    except ChangedInvocationConflictError:
        pass
    except MasuGateAPIError as exc:
        if exc.status_code != 409 or exc.code != "resource_conflict":
            raise AdapterCoreError("changed content failed for a non-conflict reason") from exc
    else:
        raise AdapterCoreError("changed content did not conflict for one trusted invocation")

    distinct_client = client_factory("distinct-calls")
    first_distinct = create_adapter_core_conformance_runtime(
        distinct_client, case, source_id="call-001"
    )
    second_distinct = create_adapter_core_conformance_runtime(
        distinct_client, case, source_id="call-002"
    )
    first_operation = await first_distinct.invoke("purchase", case.model_arguments)
    second_operation = await second_distinct.invoke("purchase", case.model_arguments)
    if first_operation.result.operation_id == second_operation.result.operation_id:
        raise AdapterCoreError("distinct trusted calls reused one authoritative operation")

    for status in ("committed", "denied", "pending", "in_progress", "outcome_unknown"):
        presentation = await runtime_for(f"lifecycle-{status}").invoke(
            "purchase", case.model_arguments
        )
        if (
            presentation.status != status
            or presentation.native_effect_permitted is not False
            or presentation.retry_as_new_action is not False
        ):
            raise AdapterCoreError(f"{status} did not remain a replacement-only lifecycle")

    pending_runtime = runtime_for("pending-resume")
    pending = await pending_runtime.invoke("purchase", case.model_arguments)
    if pending.result.pending_id is None:
        raise AdapterCoreError("pending scenario did not return a pending locator")
    resumed = await pending_runtime.resume_pending(pending.locator)
    if (
        getattr(resumed, "status", None) != "pending"
        or getattr(resumed, "operation_id", None) != pending.result.operation_id
        or getattr(resumed, "pending_id", None) != pending.result.pending_id
    ):
        raise AdapterCoreError("pending resume did not preserve the original locator")

    terminal_runtime = runtime_for("pending-terminal")
    terminal_pending = await terminal_runtime.invoke("purchase", case.model_arguments)
    terminal = await terminal_runtime.resume_pending(terminal_pending.locator)
    if (
        not isinstance(terminal, GovernedLifecycle)
        or terminal.result.operation_id != terminal_pending.result.operation_id
    ):
        raise AdapterCoreError("pending terminal read did not preserve the operation")

    mismatch_runtime = runtime_for("locator-checks")
    mismatch_pending = await mismatch_runtime.invoke("purchase", case.model_arguments)
    for control in (
        mismatch_runtime.resume_pending,
        mismatch_runtime.cancel_pending,
        mismatch_runtime.get_receipt,
    ):
        try:
            await control(mismatch_pending.locator)
        except PendingLocatorMismatchError:
            pass
        else:
            raise AdapterCoreError("control-plane locator mismatch was accepted")

    no_capabilities = runtime_for("capability-gates", capabilities=())
    locator = {
        "operation_id": "00000000-0000-4000-8000-000000000001",
        "pending_id": "11111111-1111-4111-8111-111111111111",
    }
    for control in (
        no_capabilities.resume_pending,
        no_capabilities.cancel_pending,
        no_capabilities.get_receipt,
    ):
        try:
            await control(locator)
        except UnsupportedAdapterCapabilityError:
            pass
        else:
            raise AdapterCoreError("undeclared control-plane capability was accepted")
    return AdapterCoreConformanceReport(
        conformance_version=case.conformance_version,
        passed_case_ids=tuple(identifier for identifier, _expected in case.scenarios),
    )


def _record(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(type(key) is str for key in value):
        raise AdapterCoreError(f"{field} must be an object with string keys")
    return cast(dict[str, object], value)


def _string(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise AdapterCoreError(f"{field} must be a non-empty string")
    return value


def _strings(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(type(item) is not str for item in value):
        raise AdapterCoreError(f"{field} must be an array of strings")
    return tuple(cast(list[str], value))


def _scenarios(value: object) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, list):
        raise AdapterCoreError("scenarios must be an array")
    parsed: list[tuple[str, str]] = []
    for index, raw in enumerate(value):
        scenario = _record(raw, f"scenarios[{index}]")
        if set(scenario) != {"id", "expected"}:
            raise AdapterCoreError(f"scenarios[{index}] has unsupported fields")
        parsed.append(
            (
                _string(scenario.get("id"), f"scenarios[{index}].id"),
                _string(scenario.get("expected"), f"scenarios[{index}].expected"),
            )
        )
    return tuple(parsed)
