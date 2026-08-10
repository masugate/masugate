"""Static validation, dependency extraction, and reservation admission."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

from masugate.contracts import (
    CertifiedInputContract,
    ContractRegistry,
    ProviderIdentity,
    ReservationViewKind,
)
from masugate.errors import ContractError, PolicyValidationError
from masugate.language.ast import (
    BinaryExpr,
    CallExpr,
    Expr,
    LiteralExpr,
    PathExpr,
    PolicyDefinition,
    UnaryExpr,
)
from masugate.language.serialize import dumps
from masugate.model import (
    CertifiedInputStability,
    CertifiedInputStabilityProof,
    ConsistencyGuarantee,
    Duration,
    Scalar,
    TypeName,
)


@dataclass(frozen=True)
class CompiledPolicy:
    definition: PolicyDefinition
    host_calls: tuple[CallExpr, ...]
    principal_attributes: tuple[tuple[str, TypeName], ...]
    certified_inputs: tuple[str, ...]
    compiler_context_digest: str


def compiled_policy_version(policy: CompiledPolicy) -> str:
    """Stable semantic version shared by decisions and admission certificates."""

    return hashlib.sha256(dumps(policy.definition).encode("utf-8")).hexdigest()[:16]


class ReservationProofFamily(StrEnum):
    """Runtime-verifiable reservation proof algorithms."""

    MONOTONE_CAPACITY_V1 = "monotone-capacity-v1"


def _reservation_literal_constraints_payload(
    constraints: Mapping[int, Scalar | Duration],
) -> list[dict[str, object]]:
    """Canonical JSON shape for provider-declared proof literal premises."""

    payload: list[dict[str, object]] = []
    for argument_index, value in sorted(constraints.items()):
        if type(value) is Duration:
            literal: dict[str, object] = {
                "type": TypeName.DURATION.value,
                "seconds": value.seconds,
            }
        else:
            if type(value) is bool:
                value_type = TypeName.BOOL
            elif type(value) is int:
                value_type = TypeName.INT
            else:
                value_type = TypeName.STRING
            literal = {"type": value_type.value, "value": value}
        payload.append({"argument_index": argument_index, "literal": literal})
    return payload


def _provider_identity_payload(identity: ProviderIdentity | None) -> dict[str, str]:
    if identity is None:  # guarded by every caller; keeps type narrowing local
        raise PolicyValidationError("provider identity unexpectedly missing")
    return {
        "configuration_version": identity.configuration_version,
        "implementation_version": identity.implementation_version,
        "provider_id": identity.provider_id,
    }


def _certified_input_contract_payload(
    contract: CertifiedInputContract,
) -> dict[str, object]:
    """Canonical compiler/proof identity for a certified input contract."""

    payload: dict[str, object] = {
        "contract_version": contract.contract_version,
        "expected_source_version": contract.expected_source_version,
        "freshness_ttl_seconds": contract.freshness_ttl.seconds,
        "name": contract.name,
        "source_id": contract.source_id,
        "stability": contract.stability.value,
        "stability_proof": (
            contract.stability_proof.value if contract.stability_proof is not None else None
        ),
        "value_type": contract.value_type.value,
    }
    if contract.provider_identity is not None:
        payload["provider_identity"] = _provider_identity_payload(contract.provider_identity)
    return payload


@dataclass(frozen=True)
class ReservationSafetyCertificate:
    """Deterministic evidence that one exact policy is reservation-safe.

    ``reservation_proof`` binds the policy's accepted capacity views to the
    effect/provider escrow family. ``proof_digest`` additionally binds the
    exact policy AST, consumable, proof algorithm, and view-role declarations.
    """

    action: str
    policy_id: str
    policy_version: str
    consumable_arg: str
    proof_family: ReservationProofFamily
    reservation_proof: str
    capacity_views: tuple[str, ...]
    proof_digest: str


class PolicyCompiler:
    def __init__(
        self,
        registry: ContractRegistry,
        principal_attributes: dict[str, TypeName] | None = None,
        max_host_calls: int = 16,
    ) -> None:
        self._registry = registry
        self._principal_attributes = principal_attributes or {}
        self._max_host_calls = max_host_calls

    def compile(self, definition: PolicyDefinition) -> CompiledPolicy:
        try:
            effect = self._registry.effect(definition.action)
        except ContractError as exc:
            raise PolicyValidationError(str(exc)) from exc

        if not definition.rules:
            raise PolicyValidationError("policy must contain at least one rule")

        defaults = [rule for rule in definition.rules if rule.condition is None]
        if len(defaults) != 1 or defaults[0] is not definition.rules[-1]:
            raise PolicyValidationError("policy must end with exactly one 'allow otherwise' rule")

        host_calls: list[CallExpr] = []
        certified_inputs: set[str] = set()
        for rule in definition.rules:
            if rule.condition is None:
                continue
            inferred = self._infer(
                rule.condition,
                effect.argument_types,
                host_calls,
                certified_inputs,
            )
            if inferred is not TypeName.BOOL:
                raise PolicyValidationError(f"rule {rule.rule_id} condition must be Bool")

        if len(host_calls) > self._max_host_calls:
            raise PolicyValidationError(
                f"policy uses {len(host_calls)} host calls; maximum is {self._max_host_calls}"
            )
        principal_attributes = tuple(sorted(self._principal_attributes.items()))
        certified_input_names = tuple(sorted(certified_inputs))
        context_payload = {
            "action": effect.action,
            "effect_consumable_arg": effect.consumable_arg,
            "effect_arguments": {
                name: value_type.value for name, value_type in sorted(effect.argument_types.items())
            },
            "effect_owner": effect.owner,
            **(
                {"effect_provider_identity": _provider_identity_payload(effect.provider_identity)}
                if effect.provider_identity is not None
                else {}
            ),
            "effect_required_guarantee": effect.required_guarantee.value,
            "effect_reservation_implementation": (effect.reservation_effect_implementation),
            "effect_reservation_proof": effect.reservation_proof,
            "host_calls": [
                {
                    "argument_types": [
                        value_type.value
                        for value_type in self._registry.view(call.name).argument_types
                    ],
                    "consistency": self._registry.view(call.name).consistency,
                    "name": call.name,
                    "owner": self._registry.view(call.name).owner,
                    **(
                        {
                            "provider_identity": _provider_identity_payload(
                                self._registry.view(call.name).provider_identity
                            )
                        }
                        if self._registry.view(call.name).provider_identity is not None
                        else {}
                    ),
                    "reservation_kind": self._registry.view(call.name).reservation_kind.value,
                    "reservation_literal_constraints": (
                        _reservation_literal_constraints_payload(
                            self._registry.view(call.name).reservation_literal_constraints
                        )
                    ),
                    "reservation_proof": self._registry.view(call.name).reservation_proof,
                    "return_type": self._registry.view(call.name).return_type.value,
                }
                for call in host_calls
            ],
            "certified_inputs": [
                _certified_input_contract_payload(self._registry.certified_input(name))
                for name in certified_input_names
            ],
            "principal_attributes": {
                name: value_type.value for name, value_type in principal_attributes
            },
        }
        compiler_context_digest = hashlib.sha256(
            json.dumps(
                context_payload,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        return CompiledPolicy(
            definition=definition,
            host_calls=tuple(host_calls),
            principal_attributes=principal_attributes,
            certified_inputs=certified_input_names,
            compiler_context_digest=compiler_context_digest,
        )

    def _infer(
        self,
        expression: Expr,
        action_arguments: Mapping[str, TypeName],
        host_calls: list[CallExpr],
        certified_inputs: set[str],
        *,
        inside_view_argument: bool = False,
    ) -> TypeName:
        if isinstance(expression, LiteralExpr):
            if isinstance(expression.value, bool):
                return TypeName.BOOL
            if isinstance(expression.value, int):
                return TypeName.INT
            if isinstance(expression.value, str):
                return TypeName.STRING
            if isinstance(expression.value, Duration):
                return TypeName.DURATION

        if isinstance(expression, PathExpr):
            return self._path_type(
                expression,
                action_arguments,
                certified_inputs,
                inside_view_argument=inside_view_argument,
            )

        if isinstance(expression, CallExpr):
            try:
                contract = self._registry.view(expression.name)
            except ContractError as exc:
                raise PolicyValidationError(str(exc)) from exc
            if len(expression.arguments) != len(contract.argument_types):
                raise PolicyValidationError(
                    f"{expression.name} expects {len(contract.argument_types)} arguments"
                )
            for argument, expected in zip(
                expression.arguments, contract.argument_types, strict=True
            ):
                if self._contains_call(argument):
                    raise PolicyValidationError("nested governance-view calls are not supported")
                actual = self._infer(
                    argument,
                    action_arguments,
                    host_calls,
                    certified_inputs,
                    inside_view_argument=True,
                )
                if actual is not expected:
                    raise PolicyValidationError(
                        f"{expression.name} expects {expected}, got {actual}"
                    )
            host_calls.append(expression)
            return contract.return_type

        if isinstance(expression, UnaryExpr):
            operand_type = self._infer(
                expression.operand,
                action_arguments,
                host_calls,
                certified_inputs,
                inside_view_argument=inside_view_argument,
            )
            if expression.operator != "not" or operand_type is not TypeName.BOOL:
                raise PolicyValidationError("'not' requires a Bool operand")
            return TypeName.BOOL

        if isinstance(expression, BinaryExpr):
            left = self._infer(
                expression.left,
                action_arguments,
                host_calls,
                certified_inputs,
                inside_view_argument=inside_view_argument,
            )
            right = self._infer(
                expression.right,
                action_arguments,
                host_calls,
                certified_inputs,
                inside_view_argument=inside_view_argument,
            )
            if expression.operator in {"+", "-"}:
                if left is not TypeName.INT or right is not TypeName.INT:
                    raise PolicyValidationError("arithmetic requires Int operands")
                return TypeName.INT
            if expression.operator in {"and", "or"}:
                if left is not TypeName.BOOL or right is not TypeName.BOOL:
                    raise PolicyValidationError("boolean operators require Bool operands")
                return TypeName.BOOL
            if expression.operator in {"==", "!=", "<", "<=", ">", ">="}:
                if left is not right:
                    raise PolicyValidationError("comparison operands must have the same type")
                return TypeName.BOOL

        raise PolicyValidationError(f"unsupported expression: {expression!r}")

    def _path_type(
        self,
        path: PathExpr,
        action_arguments: Mapping[str, TypeName],
        certified_inputs: set[str],
        *,
        inside_view_argument: bool,
    ) -> TypeName:
        if path.parts and path.parts[0] == "certified":
            if len(path.parts) != 2:
                raise PolicyValidationError(
                    "certified input paths must be flat certified.<name> paths"
                )
            if inside_view_argument:
                raise PolicyValidationError(
                    "governance-view arguments cannot depend on certified inputs"
                )
            name = ".".join(path.parts)
            try:
                contract = self._registry.certified_input(name)
            except ContractError as exc:
                raise PolicyValidationError(str(exc)) from exc
            certified_inputs.add(name)
            return contract.value_type
        if len(path.parts) != 2:
            raise PolicyValidationError("only two-segment paths are supported")
        root, field = path.parts
        if root == "args":
            try:
                return action_arguments[field]
            except KeyError as exc:
                raise PolicyValidationError(f"unknown action argument: {field}") from exc
        if root == "principal":
            if field == "id":
                return TypeName.STRING
            try:
                return self._principal_attributes[field]
            except KeyError as exc:
                raise PolicyValidationError(f"unknown principal attribute: {field}") from exc
        if root == "request":
            if field in {"digest", "operation_id"}:
                return TypeName.STRING
            raise PolicyValidationError(f"unknown request field: {field}")
        raise PolicyValidationError(f"unknown path root: {root}")

    def _contains_call(self, expression: Expr) -> bool:
        if isinstance(expression, CallExpr):
            return True
        if isinstance(expression, UnaryExpr):
            return self._contains_call(expression.operand)
        if isinstance(expression, BinaryExpr):
            return self._contains_call(expression.left) or self._contains_call(expression.right)
        return False


class ReservationEligibilityChecker:
    """Proof-producing admission for monotone escrow-capacity policies.

    Accepted stateful predicates are intentionally narrow:

    * ``amount > available_capacity(...)`` (or its strict inverse).

    Conjunctions of accepted predicates and immutable expressions over request
    arguments/principal attributes are closed under the proof. Other mutable
    facts, including consumed counters with policy literals and
    ``COMMIT_GUARDED`` views, require hold or revalidation. V1 deliberately
    admits only provider-declared available-capacity predicates.
    """

    def __init__(self, registry: ContractRegistry) -> None:
        self._registry = registry
        # Set per-validate() from the effect contract; None disables amount-vs-
        # capacity matching (an effect with no declared consumable can't reserve
        # over a "consumable + amount > limit" pattern).
        self._consumable_arg: str | None = None
        self._reservation_proof: str | None = None
        self._capacity_views: set[str] = set()

    def validate(self, policy: CompiledPolicy) -> ReservationSafetyCertificate:
        # A compiled policy is valid only under the exact type context that
        # produced it. Recompile against the active registry before proving
        # reservation safety; this catches registry/schema swaps and forged
        # host-call metadata that would otherwise desynchronize locking from
        # the evaluated AST.
        try:
            active = PolicyCompiler(
                self._registry,
                principal_attributes=dict(policy.principal_attributes),
            ).compile(policy.definition)
        except PolicyValidationError as exc:
            raise PolicyValidationError(
                f"policy is not valid under the active reservation contracts: {exc}"
            ) from exc
        if active != policy:
            raise PolicyValidationError(
                "compiled policy context does not match the active reservation contracts"
            )

        # Resolve the consumable argument name from the effect contract rather
        # than hardcoding "amount_cents" for every governed action.
        try:
            effect = self._registry.effect(policy.definition.action)
        except ContractError as exc:
            raise PolicyValidationError(str(exc)) from exc
        self._consumable_arg = effect.consumable_arg
        self._reservation_proof = effect.reservation_proof
        self._capacity_views = set()

        if effect.required_guarantee is not ConsistencyGuarantee.POLICY_STATE_SERIALIZABLE:
            raise PolicyValidationError(
                f"effect {effect.action} must require policy-state-serializable consistency "
                "for reservation mode"
            )
        if self._consumable_arg is None:
            raise PolicyValidationError(
                f"effect {effect.action} has no Int consumable_arg for reservation mode"
            )
        if effect.argument_types.get(self._consumable_arg) is not TypeName.INT:
            # ContractRegistry rejects this too. Retain the check here because a
            # certificate should defend its own proof premises.
            raise PolicyValidationError(
                f"effect {effect.action} consumable_arg must name an Int argument"
            )
        if self._reservation_proof is None or not self._reservation_proof.strip():
            raise PolicyValidationError(
                f"effect {effect.action} has no reservation_proof for reservation mode"
            )
        if effect.reservation_effect_implementation is None:
            raise PolicyValidationError(
                f"effect {effect.action} has no reservation effect implementation identity"
            )

        for rule in policy.definition.rules:
            if rule.condition is None:
                continue
            if not self._eligible(rule.condition):
                raise PolicyValidationError(
                    f"rule {rule.rule_id} is not eligible for reservation mode; "
                    "use masugate-transaction or pending revalidation, or rewrite the policy "
                    "to use reservation-safe available-capacity views"
                )

        policy_semantic_sha256 = hashlib.sha256(
            dumps(policy.definition).encode("utf-8")
        ).hexdigest()
        proof_family = ReservationProofFamily.MONOTONE_CAPACITY_V1
        capacity_views = tuple(sorted(self._capacity_views))
        proof_payload = {
            "action": policy.definition.action,
            "capacity_views": [
                {
                    "argument_types": [
                        argument_type.value
                        for argument_type in self._registry.view(name).argument_types
                    ],
                    "consistency": self._registry.view(name).consistency,
                    "name": name,
                    "owner": self._registry.view(name).owner,
                    **(
                        {
                            "provider_identity": _provider_identity_payload(
                                self._registry.view(name).provider_identity
                            )
                        }
                        if self._registry.view(name).provider_identity is not None
                        else {}
                    ),
                    "reservation_kind": self._registry.view(name).reservation_kind.value,
                    "reservation_literal_constraints": (
                        _reservation_literal_constraints_payload(
                            self._registry.view(name).reservation_literal_constraints
                        )
                    ),
                    "reservation_proof": self._registry.view(name).reservation_proof,
                    "return_type": self._registry.view(name).return_type.value,
                }
                for name in capacity_views
            ],
            "certified_inputs": [
                _certified_input_contract_payload(self._registry.certified_input(name))
                for name in policy.certified_inputs
            ],
            "consumable_arg": self._consumable_arg,
            "effect": {
                "action": effect.action,
                "argument_types": {
                    name: value_type.value
                    for name, value_type in sorted(effect.argument_types.items())
                },
                "owner": effect.owner,
                **(
                    {"provider_identity": _provider_identity_payload(effect.provider_identity)}
                    if effect.provider_identity is not None
                    else {}
                ),
                "required_guarantee": effect.required_guarantee.value,
                "reservation_effect_implementation": (effect.reservation_effect_implementation),
                "reservation_proof": effect.reservation_proof,
            },
            "policy_id": policy.definition.name,
            "policy_semantic_sha256": policy_semantic_sha256,
            "proof_family": proof_family.value,
            "reservation_proof": self._reservation_proof,
        }
        proof_digest = hashlib.sha256(
            json.dumps(
                proof_payload,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        return ReservationSafetyCertificate(
            action=policy.definition.action,
            policy_id=policy.definition.name,
            policy_version=compiled_policy_version(policy),
            consumable_arg=self._consumable_arg,
            proof_family=proof_family,
            reservation_proof=self._reservation_proof,
            capacity_views=capacity_views,
            proof_digest=proof_digest,
        )

    def _eligible(self, expression: Expr) -> bool:
        if not self._contains_call(expression):
            return self._is_immutable(expression)
        if isinstance(expression, BinaryExpr):
            if expression.operator == "and":
                return self._eligible(expression.left) and self._eligible(expression.right)
            if expression.operator == "or":
                return False
            if expression.operator in {"==", "!="}:
                return False
            if expression.operator in {"<", ">", "<=", ">="}:
                return self._available_capacity_comparison(expression)
        return False

    def _available_capacity_comparison(self, expression: BinaryExpr) -> bool:
        if expression.operator == ">":
            return self._is_amount(expression.left) and self._is_available_view(expression.right)
        if expression.operator == "<":
            return self._is_available_view(expression.left) and self._is_amount(expression.right)
        return False

    def _is_available_view(self, expression: Expr) -> bool:
        return self._call_has_kind(expression, ReservationViewKind.AVAILABLE_CAPACITY)

    def _call_has_kind(self, expression: Expr, kind: ReservationViewKind) -> bool:
        if not isinstance(expression, CallExpr):
            return False
        try:
            contract = self._registry.view(expression.name)
        except ContractError:
            return False
        if any(not self._is_immutable(argument) for argument in expression.arguments):
            return False
        if contract.return_type is not TypeName.INT:
            return False
        if self._reservation_proof is None or contract.reservation_proof != self._reservation_proof:
            return False
        if contract.reservation_kind is not kind:
            return False
        for argument_index, required_literal in contract.reservation_literal_constraints.items():
            argument = expression.arguments[argument_index]
            if not isinstance(argument, LiteralExpr):
                return False
            if type(argument.value) is not type(required_literal):
                return False
            if argument.value != required_literal:
                return False
        self._capacity_views.add(contract.name)
        return True

    def _is_amount(self, expression: Expr) -> bool:
        # The consumable argument name is provider-declared (effect.consumable_arg),
        # not a hardcoded "amount_cents". If the effect declares no consumable,
        # no path matches as the amount.
        if self._consumable_arg is None:
            return False
        return isinstance(expression, PathExpr) and expression.parts == (
            "args",
            self._consumable_arg,
        )

    def _contains_call(self, expression: Expr) -> bool:
        if isinstance(expression, CallExpr):
            return True
        if isinstance(expression, UnaryExpr):
            return self._contains_call(expression.operand)
        if isinstance(expression, BinaryExpr):
            return self._contains_call(expression.left) or self._contains_call(expression.right)
        return False

    def _is_immutable(self, expression: Expr) -> bool:
        """Whether an expression depends only on admission-fixed request data."""

        if isinstance(expression, LiteralExpr):
            return True
        if isinstance(expression, PathExpr):
            if len(expression.parts) != 2:
                return False
            if expression.parts[0] in {"args", "principal"}:
                return True
            if expression.parts[0] != "certified":
                return False
            try:
                contract = self._registry.certified_input(".".join(expression.parts))
            except ContractError:
                return False
            return (
                contract.stability is CertifiedInputStability.ADMISSION_STABLE
                and contract.stability_proof
                is CertifiedInputStabilityProof.REQUEST_BOUND_IMMUTABLE_V1
            )
        if isinstance(expression, UnaryExpr):
            return self._is_immutable(expression.operand)
        if isinstance(expression, BinaryExpr):
            return self._is_immutable(expression.left) and self._is_immutable(expression.right)
        return False
