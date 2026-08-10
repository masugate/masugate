"""Mounted-file secret resolution for connector-only processes.

Secret references occur only in a trusted deployment binding.  Resolution is
allowlisted, returns bytes rather than a path, and deliberately gives secret
values a redacted representation so ordinary diagnostics cannot disclose them.
"""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path
from typing import Protocol

from masugate_connector_sdk import SecretHandle

from .schema import require_identifier

MAX_SECRET_BYTES = 64 * 1024


class SecretResolutionError(ValueError):
    """A trusted connector configuration named an unavailable secret."""


# Backward-compatible internal spelling. The value is defined by the public
# SDK so a connector never imports this MasuGate-owned resolver module.
SecretValue = SecretHandle


class SecretResolver(Protocol):
    """Resolve only trusted binding references in a connector process."""

    def resolve(self, reference: str) -> SecretHandle: ...


class MountedFileSecretResolver:
    """Allowlisted reader for one connector's dedicated secret mount.

    The constructor receives symbolic references mapped to mount-relative file
    names.  A resolver never accepts a model-controlled pathname and refuses
    symlinks, directories, traversal, oversized content, and files escaping
    the configured mount root.
    """

    def __init__(
        self,
        root: Path,
        allowed_files: dict[str, str],
        *,
        maximum_secret_bytes: int = MAX_SECRET_BYTES,
    ) -> None:
        if not isinstance(root, Path):
            raise TypeError("secret mount root must be a Path")
        self.root = root.resolve(strict=True)
        if not self.root.is_dir():
            raise ValueError("secret mount root must be a directory")
        if type(maximum_secret_bytes) is not int or maximum_secret_bytes <= 0:
            raise ValueError("maximum secret bytes must be positive")
        parsed: dict[str, Path] = {}
        for reference, relative_name in allowed_files.items():
            require_identifier(reference, "secret reference")
            if (
                type(relative_name) is not str
                or not relative_name
                or Path(relative_name).is_absolute()
            ):
                raise ValueError("secret mount file names must be non-empty relative paths")
            relative = Path(relative_name)
            if any(part in {"", ".", ".."} for part in relative.parts):
                raise ValueError("secret mount file names must not traverse the mount")
            if reference in parsed:
                raise ValueError("secret resolver repeats a reference")
            parsed[reference] = relative
        if not parsed:
            raise ValueError("secret resolver needs at least one allowlisted reference")
        self._allowed_files = parsed
        self.maximum_secret_bytes = maximum_secret_bytes

    def resolve(self, reference: str) -> SecretHandle:
        require_identifier(reference, "secret reference")
        try:
            relative = self._allowed_files[reference]
        except KeyError as exc:
            raise SecretResolutionError("secret reference is not allowlisted") from exc
        try:
            root_fd = os.open(
                self.root,
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
        except OSError as exc:
            raise SecretResolutionError("secret mount root is unavailable") from exc
        try:
            parent_fd = root_fd
            try:
                # Traverse trusted mount-relative components entirely through
                # directory descriptors. This makes a replacement/symlink
                # between validation and open impossible to follow.
                for component in relative.parts[:-1]:
                    next_fd = os.open(
                        component,
                        os.O_RDONLY
                        | os.O_DIRECTORY
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=parent_fd,
                    )
                    if parent_fd != root_fd:
                        os.close(parent_fd)
                    parent_fd = next_fd
                secret_fd = os.open(
                    relative.parts[-1],
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=parent_fd,
                )
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise SecretResolutionError(
                        "allowlisted secret must be a regular non-symlink file"
                    ) from exc
                raise SecretResolutionError("allowlisted secret file is unavailable") from exc
            finally:
                if parent_fd != root_fd:
                    os.close(parent_fd)
            try:
                metadata = os.fstat(secret_fd)
                if not stat.S_ISREG(metadata.st_mode):
                    raise SecretResolutionError(
                        "allowlisted secret must be a regular non-symlink file"
                    )
                if metadata.st_size <= 0 or metadata.st_size > self.maximum_secret_bytes:
                    raise SecretResolutionError("allowlisted secret exceeds configured size limits")
                chunks: list[bytes] = []
                remaining = self.maximum_secret_bytes + 1
                while remaining:
                    chunk = os.read(secret_fd, min(64 * 1024, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                value = b"".join(chunks)
                if len(value) != metadata.st_size or len(value) > self.maximum_secret_bytes:
                    raise SecretResolutionError("allowlisted secret changed while being read")
            except OSError as exc:
                raise SecretResolutionError("allowlisted secret file is unreadable") from exc
            finally:
                os.close(secret_fd)
        finally:
            os.close(root_fd)
        return SecretHandle(value)


__all__ = [
    "MAX_SECRET_BYTES",
    "MountedFileSecretResolver",
    "SecretResolutionError",
    "SecretResolver",
    "SecretValue",
]
