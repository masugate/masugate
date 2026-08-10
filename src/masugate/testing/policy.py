"""Small, dependency-free helpers for policy-author unit tests.

The helpers in this module deliberately exercise the shipping compiler and
evaluator.  They replace only provider I/O with immutable, typed view results,
so policy authors can test decision examples without a database or a resource
provider.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import NoReturn

from masugate.catalog.model import LoadedPolicy
from masugate.contracts import (
    CertifiedInputContract,
    CertifiedInputObservation,
    ContractRegistry,
    EffectContract,
    GovernanceViewContract,
    ReservationViewKind,
    ResourceSession,
)
from masugate.language import PolicyCompiler, parse_policy
from masugate.language.ast import PolicyDefinition
from masugate.model import (
    ActionRequest,
    CertificationPhase,
    CertifiedInputEvidence,
    CertifiedInputStability,
    ConsistencyGuarantee,
    DecisionEffect,
    Duration,
    PolicyDecision,
    ResourceFootprint,
    Scalar,
    TypeName,
)
from masugate.policy import PolicyRuntime, PolicySet

type StubArgument = Scalar | Duration
type PolicySource = str | Path | LoadedPolicy


def _stub_certified_resolver(
    session: ResourceSession,
    request: ActionRequest,
    observed_at: datetime,
) -> CertifiedInputObservation:
    """Fail if an author test accidentally calls a stub certifier."""

    del session, request, observed_at
    raise AssertionError("policy-author certified fixtures must not resolve provider I/O")


def _fixture_error(message: str) -> NoReturn:
    raise TypeError(message)


def _matches_type(value: StubArgument, expected: TypeName) -> bool:
    """Match DSL types exactly (notably, ``bool`` is not an ``int``)."""

    if expected is TypeName.BOOL:
        return type(value) is bool
    if expected is TypeName.INT:
        return type(value) is int
    if expected is TypeName.STRING:
        return type(value) is str
    if expected is TypeName.DURATION:
        return type(value) is Duration and type(value.seconds) is int
    return False


def _type_name(value: StubArgument, context: str) -> TypeName:
    if type(value) is bool:
        return TypeName.BOOL
    if type(value) is int:
        return TypeName.INT
    if type(value) is str:
        return TypeName.STRING
    if type(value) is Duration and type(value.seconds) is int:
        return TypeName.DURATION
    _fixture_error(
        f"{context} has unsupported value type {type(value).__name__}; "
        "expected bool, int, str, or Duration"
    )


@dataclass(frozen=True)
class StubViewResult:
    """One authoritative result returned by a :class:`StubView`.

    ``scope`` and ``version`` are explicit because they are part of the
    governance record and often matter as much as the scalar value in an author
    test.
    """

    value: Scalar
    scope: str
    version: int = 1

    def __post_init__(self) -> None:
        if type(self.scope) is not str or not self.scope:
            _fixture_error("StubViewResult.scope must be a non-empty string")
        if type(self.version) is not int or self.version < 0:
            _fixture_error("StubViewResult.version must be a non-negative integer")


@dataclass(frozen=True)
class StubView:
    """A typed governance-view contract backed by deterministic examples.

    Results are keyed by the exact argument tuple used in policy source.  The
    mapping is copied on construction so later caller mutation cannot change a
    test's value, version, or scope.
    """

    name: str
    argument_types: tuple[TypeName, ...]
    return_type: TypeName
    results: Mapping[tuple[StubArgument, ...], StubViewResult]

    def __post_init__(self) -> None:
        if type(self.name) is not str or not self.name:
            _fixture_error("StubView.name must be a non-empty string")
        if type(self.argument_types) is not tuple or not all(
            type(value_type) is TypeName for value_type in self.argument_types
        ):
            _fixture_error("StubView.argument_types must be a tuple of TypeName values")
        if type(self.return_type) is not TypeName:
            _fixture_error("StubView.return_type must be a TypeName value")
        if not isinstance(self.results, Mapping):
            _fixture_error("StubView.results must be a mapping")

        copied: dict[tuple[StubArgument, ...], StubViewResult] = {}
        for arguments, result in self.results.items():
            if type(arguments) is not tuple:
                _fixture_error(f"stub view {self.name!r} result key must be an argument tuple")
            if len(arguments) != len(self.argument_types):
                _fixture_error(
                    f"stub view {self.name!r} result key has {len(arguments)} arguments; "
                    f"expected {len(self.argument_types)}"
                )
            for index, (value, expected) in enumerate(
                zip(arguments, self.argument_types, strict=True)
            ):
                if not _matches_type(value, expected):
                    _fixture_error(
                        f"stub view {self.name!r} argument {index} must be {expected.value}; "
                        f"got {type(value).__name__}"
                    )
            if type(result) is not StubViewResult:
                _fixture_error(
                    f"stub view {self.name!r} results must contain StubViewResult values"
                )
            if not _matches_type(result.value, self.return_type):
                _fixture_error(
                    f"stub view {self.name!r} result must be {self.return_type.value}; "
                    f"got {type(result.value).__name__}"
                )
            copied[arguments] = result
        object.__setattr__(self, "results", MappingProxyType(copied))

    def _result_for(self, arguments: tuple[StubArgument, ...]) -> StubViewResult:
        try:
            return self.results[arguments]
        except KeyError as exc:
            available = ", ".join(repr(key) for key in self.results) or "<none>"
            raise AssertionError(
                f"stub view {self.name!r} has no result for arguments {arguments!r}; "
                f"available argument tuples: {available}"
            ) from exc

    def _contract(self) -> GovernanceViewContract:
        def scope_resolver(arguments: tuple[StubArgument, ...]) -> str:
            return self._result_for(arguments).scope

        def resolver(
            session: object,
            arguments: tuple[StubArgument, ...],
            scope: str,
        ) -> tuple[Scalar, int]:
            del session
            result = self._result_for(arguments)
            if scope != result.scope:
                raise AssertionError(
                    f"stub view {self.name!r} resolved non-deterministic scope: "
                    f"expected {result.scope!r}, got {scope!r}"
                )
            return result.value, result.version

        return GovernanceViewContract(
            name=self.name,
            argument_types=self.argument_types,
            return_type=self.return_type,
            owner="masugate.testing",
            consistency="author-test-stub",
            max_latency_ms=1_000,
            bounded=True,
            scope_resolver=scope_resolver,
            resolver=resolver,
            reservation_kind=ReservationViewKind.UNSUPPORTED,
        )


def _definition(policy: PolicySource) -> PolicyDefinition:
    if isinstance(policy, LoadedPolicy):
        return policy.definition
    if isinstance(policy, Path):
        return parse_policy(policy.read_text(encoding="utf-8"))
    if isinstance(policy, str):
        return parse_policy(policy)
    _fixture_error(
        f"policy must be source text, pathlib.Path, or LoadedPolicy; got {type(policy).__name__}"
    )


def _inferred_types(values: Mapping[str, Scalar], context: str) -> dict[str, TypeName]:
    types: dict[str, TypeName] = {}
    for name, value in values.items():
        if type(name) is not str or not name:
            _fixture_error(f"{context} names must be non-empty strings")
        types[name] = _type_name(value, f"{context} {name!r}")
    return types


def _evaluate(
    policy: PolicySource,
    request: ActionRequest,
    views: Iterable[StubView],
    certified_inputs: Mapping[str, StubArgument],
) -> PolicyDecision:
    if type(request) is not ActionRequest:
        _fixture_error(f"request must be an ActionRequest; got {type(request).__name__}")
    definition = _definition(policy)
    if definition.action != request.action:
        raise AssertionError(
            f"policy action {definition.action!r} does not match request action {request.action!r}"
        )

    registry = ContractRegistry()
    for view in views:
        if type(view) is not StubView:
            _fixture_error(f"views must contain StubView values; got {type(view).__name__}")
        registry.register_view(view._contract())
    evaluation_at = datetime.now(UTC)
    evidence: dict[str, CertifiedInputEvidence] = {}
    for name, value in certified_inputs.items():
        if type(name) is not str or not name.startswith("certified."):
            _fixture_error("certified input names must be flat certified.<name> paths")
        value_type = _type_name(value, f"certified input {name!r}")
        registry.register_certified_input(
            CertifiedInputContract(
                name=name,
                value_type=value_type,
                stability=CertifiedInputStability.RESOLUTION_VOLATILE,
                stability_proof=None,
                source_id="masugate.testing",
                contract_version="masugate.testing.v1",
                freshness_ttl=Duration(3_600),
                resolver=_stub_certified_resolver,
            )
        )
        evidence[name] = CertifiedInputEvidence(
            name=name,
            value=value,
            value_type=value_type,
            stability=CertifiedInputStability.RESOLUTION_VOLATILE,
            stability_proof=None,
            source_id="masugate.testing",
            source_version="masugate.testing.v1",
            contract_version="masugate.testing.v1",
            observed_at=evaluation_at,
            certified_at=evaluation_at,
            freshness_ttl=Duration(3_600),
            phase=CertificationPhase.ADMISSION,
        )
    registry.register_effect(
        EffectContract(
            action=request.action,
            argument_types=_inferred_types(request.arguments, "request argument"),
            owner="masugate.testing",
            required_guarantee=ConsistencyGuarantee.POLICY_STATE_SERIALIZABLE,
            footprint_resolver=lambda ignored: ResourceFootprint(),
            executor=lambda session, ignored: {},
        )
    )
    principal_types = _inferred_types(request.principal.attributes, "principal attribute")
    compiled = PolicyCompiler(registry, principal_types).compile(definition)
    policies = PolicySet()
    policies.add(compiled)
    return PolicyRuntime(registry, policies).evaluate(
        request if not evidence else replace(request, certified_inputs=evidence),
        object(),
        evaluation_at=evaluation_at,
        evaluation_phase=CertificationPhase.ADMISSION,
    )


def _assert_effect(
    expected: DecisionEffect,
    policy: PolicySource,
    request: ActionRequest,
    views: Iterable[StubView],
    *,
    rule_id: str | None,
    certified_inputs: Mapping[str, StubArgument],
) -> PolicyDecision:
    decision = _evaluate(policy, request, views, certified_inputs)
    if decision.effect is not expected:
        reads = (
            ", ".join(
                f"{read.function}{read.arguments!r}->{read.value!r}@{read.scope}#{read.version}"
                for read in decision.reads
            )
            or "<none>"
        )
        raise AssertionError(
            f"expected policy decision {expected.value}, got {decision.effect.value} "
            f"(policy={decision.policy_id!r}, rule={decision.rule_id!r}, "
            f"reason={decision.reason!r}, reads={reads})"
        )
    if rule_id is not None and decision.rule_id != rule_id:
        raise AssertionError(
            f"expected policy rule {rule_id!r}, got {decision.rule_id!r} "
            f"for {decision.effect.value} decision"
        )
    return decision


def assert_allow(
    policy: PolicySource,
    request: ActionRequest,
    views: Iterable[StubView] = (),
    *,
    rule_id: str | None = None,
    certified_inputs: Mapping[str, StubArgument] = MappingProxyType({}),
) -> PolicyDecision:
    """Evaluate one author example and assert that it allows."""

    return _assert_effect(
        DecisionEffect.ALLOW,
        policy,
        request,
        views,
        rule_id=rule_id,
        certified_inputs=certified_inputs,
    )


def assert_deny(
    policy: PolicySource,
    request: ActionRequest,
    views: Iterable[StubView] = (),
    *,
    rule_id: str | None = None,
    certified_inputs: Mapping[str, StubArgument] = MappingProxyType({}),
) -> PolicyDecision:
    """Evaluate one author example and assert that it denies."""

    return _assert_effect(
        DecisionEffect.DENY,
        policy,
        request,
        views,
        rule_id=rule_id,
        certified_inputs=certified_inputs,
    )


def assert_escalate(
    policy: PolicySource,
    request: ActionRequest,
    views: Iterable[StubView] = (),
    *,
    rule_id: str | None = None,
    certified_inputs: Mapping[str, StubArgument] = MappingProxyType({}),
) -> PolicyDecision:
    """Evaluate one author example and assert that it escalates."""

    return _assert_effect(
        DecisionEffect.ESCALATE,
        policy,
        request,
        views,
        rule_id=rule_id,
        certified_inputs=certified_inputs,
    )


__all__ = [
    "PolicySource",
    "StubView",
    "StubViewResult",
    "assert_allow",
    "assert_deny",
    "assert_escalate",
]
