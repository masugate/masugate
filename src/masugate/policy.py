"""Deterministic policy evaluation over trusted governance views."""

from __future__ import annotations

import inspect
from dataclasses import replace
from datetime import datetime
from time import perf_counter
from typing import TypeGuard

from masugate.certification import validate_certified_input_evidence
from masugate.contracts import ContractRegistry, ResourceSession
from masugate.errors import (
    CertificationError,
    ContractError,
    PolicyEvaluationError,
    PolicyValidationError,
)
from masugate.language.ast import (
    BinaryExpr,
    CallExpr,
    Expr,
    LiteralExpr,
    PathExpr,
    UnaryExpr,
)
from masugate.language.compiler import CompiledPolicy, compiled_policy_version
from masugate.model import (
    ActionRequest,
    CertificationPhase,
    DecisionEffect,
    Duration,
    PolicyDecision,
    PolicyProvenance,
    Scalar,
    ViewRead,
    request_binding_digest,
)

type ExpressionValue = Scalar | Duration


def policy_version(policy: CompiledPolicy) -> str:
    """Content hash of a compiled policy (0.16).

    Hashes the **canonical AST-JSON** (0.4's ``dumps``), not the source text, so
    the version is stable across formatting/comment changes and changes only
    when the *enforced logic* changes — which is what a governance audit cares
    about (two sources that compile identically enforce identically). Ties the
    governance version to the canonical serialized policy form.
    """
    return compiled_policy_version(policy)


# Deny-overrides precedence: strictest effect wins. DENY > ESCALATE > ALLOW.
_EFFECT_RANK = {DecisionEffect.DENY: 0, DecisionEffect.ESCALATE: 1, DecisionEffect.ALLOW: 2}


def _combine(decisions: list[PolicyDecision]) -> PolicyDecision:
    """Combine per-policy decisions **deny-overrides** (0.16).

    The winner is the strictest effect (DENY > ESCALATE > ALLOW); among policies
    with that effect the first in add-order wins (deterministic; explicit
    priority is a deferred extension — deny-overrides is order-independent on the
    *effect*, so ordering only names the winner). The combined decision carries
    the winner's rule/reason, the UNION of every policy's reads (deduped by
    function/scope/version — the full audit of what was read), and
    ``evaluated_policies`` = every (policy_id, version) that ran.
    """
    if not decisions:
        raise PolicyEvaluationError("no policy produced a decision")
    versions_by_scope: dict[str, int] = {}
    for decision in decisions:
        for read in decision.reads:
            if type(read.version) is not int or read.version < 0:
                raise PolicyEvaluationError(
                    f"view {read.function} returned an invalid version for scope {read.scope}"
                )
            existing = versions_by_scope.setdefault(read.scope, read.version)
            if existing != read.version:
                raise PolicyEvaluationError(
                    "one policy evaluation observed inconsistent versions for "
                    f"scope {read.scope}: {existing} and {read.version}"
                )
    winner = min(decisions, key=lambda d: _EFFECT_RANK[d.effect])
    merged_reads: list[ViewRead] = []
    seen: set[tuple[str, str, int]] = set()
    for d in decisions:
        for read in d.reads:
            key = (read.function, read.scope, read.version)
            if key not in seen:
                seen.add(key)
                merged_reads.append(read)
    evaluated = tuple((d.policy_id, d.policy_version) for d in decisions)
    provenance = tuple(item for decision in decisions for item in decision.policy_provenance)
    if len(decisions) == 1:
        # Single governing policy: keep it verbatim but record its own (id,ver).
        return replace(
            winner,
            reads=tuple(merged_reads),
            evaluated_policies=evaluated,
            policy_provenance=provenance,
        )
    return replace(
        winner,
        reason=f"{winner.reason} [deny-overrides across {len(decisions)} policies]",
        reads=tuple(merged_reads),
        evaluated_policies=evaluated,
        policy_provenance=provenance,
    )


class PolicySet:
    """Compiled policies per action. Since 0.16 an action may have MULTIPLE
    policies (e.g. a regulatory layer + the owner's + a safety floor); they are
    combined **deny-overrides** at evaluation. ``add`` appends; evaluation order
    within an action is add-order (only affects which same-effect policy is
    named the winner, not the decision)."""

    def __init__(self) -> None:
        self._policies: dict[str, list[CompiledPolicy]] = {}
        self._provenance: dict[tuple[str, str], PolicyProvenance] = {}
        self._frozen = False

    def add(
        self,
        policy: CompiledPolicy,
        *,
        provenance: PolicyProvenance | None = None,
    ) -> None:
        if self._frozen:
            raise PolicyEvaluationError("policy set is frozen after runtime admission")
        action_policies = self._policies.setdefault(policy.definition.action, [])
        if any(existing.definition.name == policy.definition.name for existing in action_policies):
            raise PolicyValidationError(
                "duplicate policy id for action "
                f"{policy.definition.action}: {policy.definition.name}"
            )
        if provenance is not None:
            runtime_version = policy_version(policy)
            if provenance.policy_id != policy.definition.name:
                raise PolicyValidationError("policy provenance id does not match compiled policy")
            if provenance.policy_runtime_version != runtime_version:
                raise PolicyValidationError(
                    "policy provenance runtime version does not match compiled policy"
                )
            self._provenance[(policy.definition.action, policy.definition.name)] = provenance
        action_policies.append(policy)

    def freeze(self) -> PolicySet:
        """Prevent policy changes after a runtime takes its admission snapshot."""

        self._frozen = True
        return self

    @property
    def frozen(self) -> bool:
        return self._frozen

    def all_for_action(self, action: str) -> tuple[CompiledPolicy, ...]:
        try:
            return tuple(self._policies[action])
        except KeyError as exc:
            raise PolicyEvaluationError(f"no policy for action: {action}") from exc

    def compiled(self) -> tuple[CompiledPolicy, ...]:
        """Every compiled policy across all actions (for startup admission
        checks, e.g. 0.13 reservation-eligibility)."""
        return tuple(p for policies in self._policies.values() for p in policies)

    def provenance_for(self, policy: CompiledPolicy) -> PolicyProvenance | None:
        """Return trusted catalog identity attached at policy-set construction."""

        return self._provenance.get((policy.definition.action, policy.definition.name))


class PolicyRuntime:
    def __init__(
        self,
        registry: ContractRegistry,
        policies: PolicySet,
        *,
        enforce_view_latency: bool = True,
    ) -> None:
        self._registry = registry
        # A runtime's policy set is an admitted artifact. Freezing here prevents
        # later additions from bypassing reservation admission performed by the
        # coordinator over this exact snapshot.
        self._policies = policies.freeze()
        # When True (frozen default), a view read exceeding its max_latency_ms
        # raises PolicyEvaluationError. ReferencePlatform hardening flips this to treat a
        # latency-contract breach as a non-fatal signal rather than a deny.
        self._enforce_view_latency = enforce_view_latency

    @property
    def policies(self) -> PolicySet:
        """The compiled policy set (for startup admission, e.g. 0.13 eligibility)."""
        return self._policies

    def dependency_scopes(self, request: ActionRequest) -> frozenset[str]:
        # Union across ALL policies on the action (0.16), so every policy's view
        # scopes are locked before evaluation.
        scopes: set[str] = set()
        for policy in self._policies.all_for_action(request.action):
            for call in policy.host_calls:
                arguments = tuple(
                    self._evaluate_static(argument, request) for argument in call.arguments
                )
                scopes.add(self._registry.view(call.name).scope_resolver(arguments))
        return frozenset(scopes)

    def certified_input_dependencies(self, action: str) -> tuple[str, ...]:
        """Canonical union of certified facts used by the complete policy set."""

        return tuple(
            sorted(
                {
                    name
                    for policy in self._policies.all_for_action(action)
                    for name in policy.certified_inputs
                }
            )
        )

    def evaluate(
        self,
        request: ActionRequest,
        session: ResourceSession,
        *,
        evaluation_at: datetime | None = None,
        evaluation_phase: CertificationPhase = CertificationPhase.ADMISSION,
    ) -> PolicyDecision:
        decisions = [
            self._evaluate_one(
                policy,
                request,
                session,
                evaluation_at=evaluation_at,
                evaluation_phase=evaluation_phase,
                provenance=self._policies.provenance_for(policy),
            )
            for policy in self._policies.all_for_action(request.action)
        ]
        return _combine(decisions)

    def _evaluate_one(
        self,
        policy: CompiledPolicy,
        request: ActionRequest,
        session: ResourceSession,
        *,
        evaluation_at: datetime | None,
        evaluation_phase: CertificationPhase,
        provenance: PolicyProvenance | None,
    ) -> PolicyDecision:
        version = policy_version(policy)
        reads: list[ViewRead] = []
        for rule in policy.definition.rules:
            if rule.condition is None:
                return PolicyDecision(
                    effect=rule.effect,
                    policy_id=policy.definition.name,
                    rule_id=rule.rule_id,
                    reason="default rule",
                    reads=tuple(reads),
                    policy_version=version,
                    policy_provenance=(() if provenance is None else (provenance,)),
                )
            value = self._evaluate(
                rule.condition,
                request,
                session,
                reads,
                evaluation_at=evaluation_at,
                evaluation_phase=evaluation_phase,
            )
            if not isinstance(value, bool):
                raise PolicyEvaluationError(f"rule {rule.rule_id} did not evaluate to Bool")
            if value:
                return PolicyDecision(
                    effect=rule.effect,
                    policy_id=policy.definition.name,
                    rule_id=rule.rule_id,
                    reason=f"rule {rule.rule_id} evaluated to true",
                    reads=tuple(reads),
                    policy_version=version,
                    policy_provenance=(() if provenance is None else (provenance,)),
                )
        raise PolicyEvaluationError("compiled policy has no default rule")

    def _evaluate(
        self,
        expression: Expr,
        request: ActionRequest,
        session: ResourceSession,
        reads: list[ViewRead],
        *,
        evaluation_at: datetime | None,
        evaluation_phase: CertificationPhase,
    ) -> ExpressionValue:
        if isinstance(expression, CallExpr):
            contract = self._registry.view(expression.name)
            arguments = tuple(
                self._evaluate(
                    argument,
                    request,
                    session,
                    reads,
                    evaluation_at=evaluation_at,
                    evaluation_phase=evaluation_phase,
                )
                for argument in expression.arguments
            )
            scope = contract.scope_resolver(arguments)
            started = perf_counter()
            resolved = contract.resolver(session, arguments, scope)
            if inspect.isawaitable(resolved):
                # An async resolver reached the sync evaluator — refuse loudly
                # (closing the coroutine so it doesn't warn) instead of
                # mis-treating the awaitable as a (value, version) pair.
                if inspect.iscoroutine(resolved):
                    resolved.close()
                raise PolicyEvaluationError(
                    f"{contract.name} resolver is async; use AsyncPolicyRuntime.aevaluate"
                )
            value, version = resolved
            latency_ms = (perf_counter() - started) * 1000
            if self._enforce_view_latency and latency_ms > contract.max_latency_ms:
                raise PolicyEvaluationError(
                    f"{contract.name} exceeded {contract.max_latency_ms} ms latency contract"
                )
            reads.append(
                ViewRead(
                    function=contract.name,
                    arguments=arguments,
                    value=value,
                    scope=scope,
                    version=version,
                    latency_ms=latency_ms,
                )
            )
            return value

        if isinstance(expression, LiteralExpr):
            return expression.value
        if isinstance(expression, PathExpr):
            return self._resolve_path(
                expression,
                request,
                evaluation_at=evaluation_at,
                evaluation_phase=evaluation_phase,
            )
        if isinstance(expression, UnaryExpr):
            operand = self._evaluate(
                expression.operand,
                request,
                session,
                reads,
                evaluation_at=evaluation_at,
                evaluation_phase=evaluation_phase,
            )
            if expression.operator == "not" and isinstance(operand, bool):
                return not operand
        if isinstance(expression, BinaryExpr):
            if expression.operator == "and":
                left = self._evaluate(
                    expression.left,
                    request,
                    session,
                    reads,
                    evaluation_at=evaluation_at,
                    evaluation_phase=evaluation_phase,
                )
                if not isinstance(left, bool):
                    raise PolicyEvaluationError("'and' left operand is not Bool")
                return left and bool(
                    self._evaluate(
                        expression.right,
                        request,
                        session,
                        reads,
                        evaluation_at=evaluation_at,
                        evaluation_phase=evaluation_phase,
                    )
                )
            if expression.operator == "or":
                left = self._evaluate(
                    expression.left,
                    request,
                    session,
                    reads,
                    evaluation_at=evaluation_at,
                    evaluation_phase=evaluation_phase,
                )
                if not isinstance(left, bool):
                    raise PolicyEvaluationError("'or' left operand is not Bool")
                return left or bool(
                    self._evaluate(
                        expression.right,
                        request,
                        session,
                        reads,
                        evaluation_at=evaluation_at,
                        evaluation_phase=evaluation_phase,
                    )
                )
            left = self._evaluate(
                expression.left,
                request,
                session,
                reads,
                evaluation_at=evaluation_at,
                evaluation_phase=evaluation_phase,
            )
            right = self._evaluate(
                expression.right,
                request,
                session,
                reads,
                evaluation_at=evaluation_at,
                evaluation_phase=evaluation_phase,
            )
            return self._binary(expression.operator, left, right)
        raise PolicyEvaluationError(f"unsupported expression: {expression!r}")

    def _evaluate_static(self, expression: Expr, request: ActionRequest) -> ExpressionValue:
        if isinstance(expression, LiteralExpr):
            return expression.value
        if isinstance(expression, PathExpr):
            return self._resolve_path(expression, request)
        if isinstance(expression, UnaryExpr):
            value = self._evaluate_static(expression.operand, request)
            if expression.operator == "not" and isinstance(value, bool):
                return not value
        if isinstance(expression, BinaryExpr):
            left = self._evaluate_static(expression.left, request)
            right = self._evaluate_static(expression.right, request)
            return self._binary(expression.operator, left, right)
        raise PolicyEvaluationError("host-call scope depends on another host call")

    def _resolve_path(
        self,
        path: PathExpr,
        request: ActionRequest,
        *,
        evaluation_at: datetime | None = None,
        evaluation_phase: CertificationPhase = CertificationPhase.ADMISSION,
    ) -> ExpressionValue:
        root, field = path.parts
        if root == "args":
            try:
                return request.arguments[field]
            except KeyError as exc:
                raise PolicyEvaluationError(f"missing action argument: {field}") from exc
        if root == "principal":
            if field == "id":
                return request.principal.id
            try:
                return request.principal.attributes[field]
            except KeyError as exc:
                raise PolicyEvaluationError(f"missing principal attribute: {field}") from exc
        if root == "request":
            if field == "digest":
                return request_binding_digest(request)
            if field == "operation_id":
                return request.operation_id
            raise PolicyEvaluationError(f"unknown request field: {field}")
        if root == "certified":
            if evaluation_at is None:
                raise PolicyEvaluationError(
                    "certified input requires an explicit authorization evaluation point"
                )
            name = f"certified.{field}"
            try:
                contract = self._registry.certified_input(name)
            except ContractError as exc:
                raise PolicyEvaluationError(str(exc)) from exc
            try:
                evidence = request.certified_inputs[name]
            except KeyError as exc:
                raise PolicyEvaluationError(f"missing certified input evidence: {name}") from exc
            try:
                return validate_certified_input_evidence(
                    contract,
                    evidence,
                    at=evaluation_at,
                    evaluation_phase=evaluation_phase,
                )
            except CertificationError as exc:
                raise PolicyEvaluationError(str(exc)) from exc
        raise PolicyEvaluationError(f"unknown path root: {root}")

    def _binary(
        self,
        operator: str,
        left: ExpressionValue,
        right: ExpressionValue,
    ) -> Scalar:
        if operator in {"+", "-"}:
            if not self._is_int(left) or not self._is_int(right):
                raise PolicyEvaluationError("arithmetic operands are not Int")
            left_int = int(left)
            right_int = int(right)
            return left_int + right_int if operator == "+" else left_int - right_int
        if operator in {"and", "or"}:
            if not isinstance(left, bool) or not isinstance(right, bool):
                raise PolicyEvaluationError("boolean operands are not Bool")
            return left and right if operator == "and" else left or right
        if type(left) is not type(right):
            raise PolicyEvaluationError("comparison operands have different types")
        if operator == "==":
            return left == right
        if operator == "!=":
            return left != right
        if isinstance(left, Duration) and isinstance(right, Duration):
            return self._compare_int(operator, left.seconds, right.seconds)
        if self._is_int(left) and self._is_int(right):
            return self._compare_int(operator, left, right)
        if isinstance(left, str) and isinstance(right, str):
            return self._compare_str(operator, left, right)
        raise PolicyEvaluationError("operands do not support ordered comparison")

    @staticmethod
    def _compare_int(operator: str, left: int, right: int) -> bool:
        if operator == "<":
            return left < right
        if operator == "<=":
            return left <= right
        if operator == ">":
            return left > right
        if operator == ">=":
            return left >= right
        raise PolicyEvaluationError(f"unsupported operator: {operator}")

    @staticmethod
    def _compare_str(operator: str, left: str, right: str) -> bool:
        if operator == "<":
            return left < right
        if operator == "<=":
            return left <= right
        if operator == ">":
            return left > right
        if operator == ">=":
            return left >= right
        raise PolicyEvaluationError(f"unsupported operator: {operator}")

    @staticmethod
    def _is_int(value: object) -> TypeGuard[int]:
        return isinstance(value, int) and not isinstance(value, bool)


class AsyncPolicyRuntime(PolicyRuntime):
    """Async policy evaluation for the async core (0.12 — NEW, not ported).

    Same decision semantics as the sync ``evaluate`` (same rule walk, same
    fail conditions, same ViewRead recording); the only difference is that a
    view resolver's result is awaited when it is awaitable, so the async
    provider's ``async def`` resolvers work. Sync resolvers keep working too
    (useful for fakes in unit tests).

    Inherits ``dependency_scopes`` (pure — scope resolvers are sync by
    contract) and all the pure expression helpers.
    """

    async def aevaluate(
        self,
        request: ActionRequest,
        session: ResourceSession,
        *,
        evaluation_at: datetime | None = None,
        evaluation_phase: CertificationPhase = CertificationPhase.ADMISSION,
    ) -> PolicyDecision:
        decisions = [
            await self._aevaluate_one(
                policy,
                request,
                session,
                evaluation_at=evaluation_at,
                evaluation_phase=evaluation_phase,
                provenance=self._policies.provenance_for(policy),
            )
            for policy in self._policies.all_for_action(request.action)
        ]
        return _combine(decisions)

    async def _aevaluate_one(
        self,
        policy: CompiledPolicy,
        request: ActionRequest,
        session: ResourceSession,
        *,
        evaluation_at: datetime | None,
        evaluation_phase: CertificationPhase,
        provenance: PolicyProvenance | None,
    ) -> PolicyDecision:
        version = policy_version(policy)
        reads: list[ViewRead] = []
        for rule in policy.definition.rules:
            if rule.condition is None:
                return PolicyDecision(
                    effect=rule.effect,
                    policy_id=policy.definition.name,
                    rule_id=rule.rule_id,
                    reason="default rule",
                    reads=tuple(reads),
                    policy_version=version,
                    policy_provenance=(() if provenance is None else (provenance,)),
                )
            value = await self._aevaluate(
                rule.condition,
                request,
                session,
                reads,
                evaluation_at=evaluation_at,
                evaluation_phase=evaluation_phase,
            )
            if not isinstance(value, bool):
                raise PolicyEvaluationError(f"rule {rule.rule_id} did not evaluate to Bool")
            if value:
                return PolicyDecision(
                    effect=rule.effect,
                    policy_id=policy.definition.name,
                    rule_id=rule.rule_id,
                    reason=f"rule {rule.rule_id} evaluated to true",
                    reads=tuple(reads),
                    policy_version=version,
                    policy_provenance=(() if provenance is None else (provenance,)),
                )
        raise PolicyEvaluationError("compiled policy has no default rule")

    async def _aevaluate(
        self,
        expression: Expr,
        request: ActionRequest,
        session: ResourceSession,
        reads: list[ViewRead],
        *,
        evaluation_at: datetime | None,
        evaluation_phase: CertificationPhase,
    ) -> ExpressionValue:
        if isinstance(expression, CallExpr):
            contract = self._registry.view(expression.name)
            arguments_list: list[ExpressionValue] = []
            for argument in expression.arguments:
                arguments_list.append(
                    await self._aevaluate(
                        argument,
                        request,
                        session,
                        reads,
                        evaluation_at=evaluation_at,
                        evaluation_phase=evaluation_phase,
                    )
                )
            arguments = tuple(arguments_list)
            scope = contract.scope_resolver(arguments)
            started = perf_counter()
            resolved = contract.resolver(session, arguments, scope)
            if inspect.isawaitable(resolved):
                value, version = await resolved
            else:
                value, version = resolved
            latency_ms = (perf_counter() - started) * 1000
            if self._enforce_view_latency and latency_ms > contract.max_latency_ms:
                raise PolicyEvaluationError(
                    f"{contract.name} exceeded {contract.max_latency_ms} ms latency contract"
                )
            reads.append(
                ViewRead(
                    function=contract.name,
                    arguments=arguments,
                    value=value,
                    scope=scope,
                    version=version,
                    latency_ms=latency_ms,
                )
            )
            return value

        if isinstance(expression, LiteralExpr):
            return expression.value
        if isinstance(expression, PathExpr):
            return self._resolve_path(
                expression,
                request,
                evaluation_at=evaluation_at,
                evaluation_phase=evaluation_phase,
            )
        if isinstance(expression, UnaryExpr):
            operand = await self._aevaluate(
                expression.operand,
                request,
                session,
                reads,
                evaluation_at=evaluation_at,
                evaluation_phase=evaluation_phase,
            )
            if expression.operator == "not" and isinstance(operand, bool):
                return not operand
        if isinstance(expression, BinaryExpr):
            if expression.operator == "and":
                left = await self._aevaluate(
                    expression.left,
                    request,
                    session,
                    reads,
                    evaluation_at=evaluation_at,
                    evaluation_phase=evaluation_phase,
                )
                if not isinstance(left, bool):
                    raise PolicyEvaluationError("'and' left operand is not Bool")
                return left and bool(
                    await self._aevaluate(
                        expression.right,
                        request,
                        session,
                        reads,
                        evaluation_at=evaluation_at,
                        evaluation_phase=evaluation_phase,
                    )
                )
            if expression.operator == "or":
                left = await self._aevaluate(
                    expression.left,
                    request,
                    session,
                    reads,
                    evaluation_at=evaluation_at,
                    evaluation_phase=evaluation_phase,
                )
                if not isinstance(left, bool):
                    raise PolicyEvaluationError("'or' left operand is not Bool")
                return left or bool(
                    await self._aevaluate(
                        expression.right,
                        request,
                        session,
                        reads,
                        evaluation_at=evaluation_at,
                        evaluation_phase=evaluation_phase,
                    )
                )
            left = await self._aevaluate(
                expression.left,
                request,
                session,
                reads,
                evaluation_at=evaluation_at,
                evaluation_phase=evaluation_phase,
            )
            right = await self._aevaluate(
                expression.right,
                request,
                session,
                reads,
                evaluation_at=evaluation_at,
                evaluation_phase=evaluation_phase,
            )
            return self._binary(expression.operator, left, right)
        raise PolicyEvaluationError(f"unsupported expression: {expression!r}")


def replayed(result: PolicyDecision) -> PolicyDecision:
    """Keep an explicit helper for adapters that annotate replayed outcomes."""

    return replace(result)
