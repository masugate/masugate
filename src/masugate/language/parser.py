"""Lark parser for the MasuGate policy language."""

from __future__ import annotations

import json
from typing import cast

from lark import Lark, Token, Transformer
from lark.exceptions import LarkError

from masugate.errors import PolicySyntaxError
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
from masugate.model import DecisionEffect, Duration

_GRAMMAR = r"""
    start: policy
    policy: "policy" CNAME "on" action_name "{" rule+ "}"
    action_name: CNAME ("." CNAME)*

    rule: EFFECT CNAME "when" expr ";"  -> conditional_rule
        | "allow" "otherwise" ";"       -> allow_otherwise

    ?expr: or_expr
    ?or_expr: and_expr
            | or_expr "or" and_expr     -> or_op
    ?and_expr: not_expr
             | and_expr "and" not_expr  -> and_op
    ?not_expr: comparison
             | "not" not_expr           -> not_op
    ?comparison: sum
               | sum COMP_OP sum        -> compare
    ?sum: atom
        | sum ADD_OP atom                -> arithmetic
    ?atom: literal
         | call
         | path
         | "(" expr ")"

    call: dotted_name "(" [arguments] ")"
    arguments: expr ("," expr)*
    path: CNAME ("." CNAME)+
    dotted_name: CNAME ("." CNAME)+

    literal: DURATION                    -> duration
           | SIGNED_INT                  -> integer
           | ESCAPED_STRING              -> string
           | "true"                      -> true
           | "false"                     -> false

    EFFECT.2: "deny" | "escalate"
    COMP_OP: "==" | "!=" | "<=" | ">=" | "<" | ">"
    ADD_OP: "+" | "-"
    DURATION.2: /[0-9]+[smhd]/

    %import common.CNAME
    %import common.ESCAPED_STRING
    %import common.SIGNED_INT
    %import common.WS
    %ignore WS
    %ignore /#[^\n]*/
"""


def _duration_seconds(raw: str) -> int:
    value = int(raw[:-1])
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[raw[-1]]
    return value * multiplier


class _ASTTransformer(Transformer[Token, object]):
    def start(self, items: list[object]) -> PolicyDefinition:
        return cast(PolicyDefinition, items[0])

    def policy(self, items: list[object]) -> PolicyDefinition:
        return PolicyDefinition(
            name=str(items[0]),
            action=str(items[1]),
            rules=tuple(cast(Rule, item) for item in items[2:]),
        )

    def action_name(self, items: list[object]) -> str:
        return ".".join(str(item) for item in items)

    def conditional_rule(self, items: list[object]) -> Rule:
        return Rule(
            effect=DecisionEffect(str(items[0])),
            rule_id=str(items[1]),
            condition=cast(Expr, items[2]),
        )

    def allow_otherwise(self, _: list[object]) -> Rule:
        return Rule(effect=DecisionEffect.ALLOW, rule_id="otherwise", condition=None)

    def or_op(self, items: list[object]) -> BinaryExpr:
        return BinaryExpr("or", cast(Expr, items[0]), cast(Expr, items[1]))

    def and_op(self, items: list[object]) -> BinaryExpr:
        return BinaryExpr("and", cast(Expr, items[0]), cast(Expr, items[1]))

    def not_op(self, items: list[object]) -> UnaryExpr:
        return UnaryExpr("not", cast(Expr, items[0]))

    def compare(self, items: list[object]) -> BinaryExpr:
        return BinaryExpr(str(items[1]), cast(Expr, items[0]), cast(Expr, items[2]))

    def arithmetic(self, items: list[object]) -> BinaryExpr:
        return BinaryExpr(str(items[1]), cast(Expr, items[0]), cast(Expr, items[2]))

    def call(self, items: list[object]) -> CallExpr:
        arguments: tuple[Expr, ...] = ()
        if len(items) == 2:
            arguments = tuple(cast("list[Expr]", items[1]))
        return CallExpr(name=str(items[0]), arguments=arguments)

    def arguments(self, items: list[object]) -> list[Expr]:
        return [cast(Expr, item) for item in items]

    def dotted_name(self, items: list[object]) -> str:
        return ".".join(str(item) for item in items)

    def path(self, items: list[object]) -> PathExpr:
        return PathExpr(tuple(str(item) for item in items))

    def duration(self, items: list[object]) -> LiteralExpr:
        return LiteralExpr(Duration(_duration_seconds(str(items[0]))))

    def integer(self, items: list[object]) -> LiteralExpr:
        return LiteralExpr(int(str(items[0])))

    def string(self, items: list[object]) -> LiteralExpr:
        return LiteralExpr(cast(str, json.loads(str(items[0]))))

    def true(self, _: list[object]) -> LiteralExpr:
        return LiteralExpr(True)

    def false(self, _: list[object]) -> LiteralExpr:
        return LiteralExpr(False)


_PARSER = Lark(_GRAMMAR, parser="lalr", transformer=_ASTTransformer())


def parse_policy(source: str) -> PolicyDefinition:
    try:
        parsed = _PARSER.parse(source)
    except (LarkError, TypeError, ValueError) as exc:
        raise PolicySyntaxError(str(exc)) from exc
    if not isinstance(parsed, PolicyDefinition):
        raise PolicySyntaxError("parser did not produce a policy")
    return parsed
