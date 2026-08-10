"""Abstract syntax tree for the bounded MasuGate policy language."""

from __future__ import annotations

from dataclasses import dataclass

from masugate.model import DecisionEffect, Duration, Scalar


class Expr:
    pass


@dataclass(frozen=True)
class LiteralExpr(Expr):
    value: Scalar | Duration


@dataclass(frozen=True)
class PathExpr(Expr):
    parts: tuple[str, ...]


@dataclass(frozen=True)
class CallExpr(Expr):
    name: str
    arguments: tuple[Expr, ...]


@dataclass(frozen=True)
class UnaryExpr(Expr):
    operator: str
    operand: Expr


@dataclass(frozen=True)
class BinaryExpr(Expr):
    operator: str
    left: Expr
    right: Expr


@dataclass(frozen=True)
class Rule:
    effect: DecisionEffect
    rule_id: str
    condition: Expr | None


@dataclass(frozen=True)
class PolicyDefinition:
    name: str
    action: str
    rules: tuple[Rule, ...]
