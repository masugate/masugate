"""Server-certified principal attributes for governed requests."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from masugate.errors import MasuGateError
from masugate.model import Principal, Scalar


class UnknownPrincipalError(MasuGateError):
    """The request's principal id has no entry in the trusted registry."""


class PrincipalRegistry:
    def __init__(self, principals: Mapping[str, Mapping[str, Scalar]]) -> None:
        self._principals: dict[str, dict[str, Scalar]] = {
            pid: dict(attrs) for pid, attrs in principals.items()
        }

    @classmethod
    def from_file(cls, path: Path | str) -> PrincipalRegistry:
        """Load ``{"<principal-id>": {"<attr>": <scalar>, ...}, ...}`` from JSON."""
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("principals file must be a JSON object of id -> attributes")
        return cls(raw)

    def resolve(self, principal: Principal) -> Principal:
        """Return the principal with **certified** attributes.

        Caller-asserted ``principal.attributes`` are discarded — the returned
        attributes come from the registry only. Raises
        :class:`UnknownPrincipalError` for an unregistered id (fail closed).
        """
        attrs = self._principals.get(principal.id)
        if attrs is None:
            raise UnknownPrincipalError(f"unknown principal: {principal.id}")
        return Principal(id=principal.id, attributes=dict(attrs))

    def __contains__(self, principal_id: str) -> bool:
        return principal_id in self._principals
