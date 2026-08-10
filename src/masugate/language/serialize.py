"""Canonical JSON serialization of the MasuGate policy AST.

Every node has an explicit type tag and serialization has a deterministic key
order. ``ast_to_json`` returns a plain mapping; ``dumps`` returns canonical
JSON text suitable for stable policy-version calculation.
"""

from __future__ import annotations

import json
from typing import Any

from masugate.language.ast import (
    BinaryExpr,
    CallExpr,
    Expr,
    LiteralExpr,
    PathExpr,
    PolicyDefinition,
    Rule,
    UnaryExpr,
)
from masugate.model import Duration


def _literal_value_type(value: bool | int | str) -> str:
    # bool must be checked before int (bool is an int subclass in Python).
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    return "string"


def _expr_to_json(expr: Expr) -> dict[str, Any]:
    if isinstance(expr, LiteralExpr):
        value = expr.value
        if isinstance(value, Duration):
            return {"type": "literal", "value_type": "duration", "seconds": value.seconds}
        return {
            "type": "literal",
            "value_type": _literal_value_type(value),
            "value": value,
        }
    if isinstance(expr, PathExpr):
        return {"type": "path", "parts": list(expr.parts)}
    if isinstance(expr, CallExpr):
        return {
            "type": "call",
            "name": expr.name,
            "arguments": [_expr_to_json(arg) for arg in expr.arguments],
        }
    if isinstance(expr, UnaryExpr):
        return {"type": "unary", "operator": expr.operator, "operand": _expr_to_json(expr.operand)}
    if isinstance(expr, BinaryExpr):
        return {
            "type": "binary",
            "operator": expr.operator,
            "left": _expr_to_json(expr.left),
            "right": _expr_to_json(expr.right),
        }
    raise TypeError(f"cannot serialize expression node: {type(expr).__name__}")


def _rule_to_json(rule: Rule) -> dict[str, Any]:
    return {
        "type": "rule",
        "effect": rule.effect.value,
        "rule_id": rule.rule_id,
        "condition": None if rule.condition is None else _expr_to_json(rule.condition),
    }


def ast_to_json(policy: PolicyDefinition) -> dict[str, Any]:
    """Canonical JSON-able dict for a parsed policy (the Rust-parity contract)."""
    return {
        "type": "policy",
        "name": policy.name,
        "action": policy.action,
        "rules": [_rule_to_json(rule) for rule in policy.rules],
    }


def dumps(policy: PolicyDefinition) -> str:
    """Canonical serialized text: sorted keys, compact, newline-terminated.

    ``sort_keys=True`` makes the byte output independent of the insertion order
    above, so a Rust emitter only has to agree on the *set* of keys and values,
    not their order — the single stable string golden files and the differential
    test compare against.
    """
    return json.dumps(ast_to_json(policy), sort_keys=True, ensure_ascii=True) + "\n"
