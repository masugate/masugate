"""Public exception hierarchy for ``masugate-client``."""

from __future__ import annotations

from .models import JsonValue


class MasuGateClientError(Exception):
    """Base class for errors raised by the SDK."""


class MasuGateTransportError(MasuGateClientError):
    """The HTTP request could not be completed."""

    def __init__(self, method: str, path: str, cause: Exception) -> None:
        self.method = method
        self.path = path
        self.cause = cause
        super().__init__(f"{method} {path} failed: {cause}")


class MasuGateProtocolError(MasuGateClientError):
    """A successful response or SSE event did not match the protocol."""

    def __init__(self, message: str, *, endpoint: str | None = None) -> None:
        self.endpoint = endpoint
        prefix = f"{endpoint}: " if endpoint is not None else ""
        super().__init__(f"{prefix}{message}")


class MasuGateHTTPError(MasuGateClientError):
    """An HTTP response reported failure."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        *,
        details: dict[str, JsonValue] | None = None,
    ) -> None:
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details
        super().__init__(f"MasuGate API error {status_code} ({code}): {message}")


class MasuGateAPIError(MasuGateHTTPError):
    """A protocol error envelope returned by ``masugated``."""
