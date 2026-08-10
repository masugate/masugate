"""Exact Linux/ext4 filesystem connector using only the public SDK.

The connector deliberately has no generic path or storage abstraction.  Its
only authority is a preconfigured, dedicated ext4 mount and the two governed
logical operations declared by ``masugate-operation-filesystem``.
"""

from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import json
import os
import platform
import posixpath
import secrets
import sqlite3
import stat
from collections.abc import Generator, Mapping
from contextlib import closing, contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, Protocol, cast

from masugate_connector_sdk import (
    SDK_CONTRACT_VERSION,
    ArtifactDescriptor,
    ConnectorAmbiguousOutcome,
    ConnectorCapabilities,
    ConnectorEvidence,
    ConnectorInvocation,
    ConnectorOutcome,
    ConnectorSDKError,
)

_WRITE = "fs.write"
_DELETE = "fs.delete"
_LOGICAL_PREFIX = "/workspace"
_CONNECTOR_ID = "filesystem-v1"
_PRIVATE_DIRECTORY = ".masugate-filesystem-v1"
_QUARANTINE_DIRECTORY = "quarantine"
_LOCK_DIRECTORY = "locks"
_JOURNAL_FILE = "journal.sqlite3"
_PROVENANCE_ATTRIBUTE = "user.pvl.filesystem.operation"
_MAX_CONTENT_BYTES = 16_384
_EXT4_MAGIC = 0xEF53
_RENAME_NOREPLACE = 1
_RESOLVE_NO_XDEV = 0x01
_RESOLVE_NO_MAGICLINKS = 0x02
_RESOLVE_NO_SYMLINKS = 0x04
_RESOLVE_BENEATH = 0x08
_CAPABILITIES = ConnectorCapabilities(
    idempotent_dispatch=True,
    status_query=True,
    cancellation=True,
    fencing=True,
    max_payload_bytes=_MAX_CONTENT_BYTES,
    max_result_bytes=4 * 1024,
    ambiguity_handling="status-query",
)


class _OpenHow(ctypes.Structure):
    _fields_: ClassVar[Any] = [
        ("flags", ctypes.c_ulonglong),
        ("mode", ctypes.c_ulonglong),
        ("resolve", ctypes.c_ulonglong),
    ]


def _openat2_number() -> int:
    """Return the Linux ABI number, rejecting platforms without this contract."""

    numbers = {"x86_64": 437, "aarch64": 437}
    try:
        return numbers[platform.machine()]
    except KeyError as exc:
        raise ConnectorSDKError(
            "filesystem reference connector requires openat2 Linux ABI"
        ) from exc


def _openat2_beneath(directory_fd: int, path: str, flags: int) -> int:
    """Open only below ``directory_fd``; bind mounts are an escape too."""

    if platform.system() != "Linux":
        raise ConnectorSDKError("filesystem reference connector requires Linux openat2")
    how = _OpenHow(
        flags=flags,
        mode=0,
        resolve=_RESOLVE_BENEATH | _RESOLVE_NO_XDEV | _RESOLVE_NO_MAGICLINKS | _RESOLVE_NO_SYMLINKS,
    )
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(
        ctypes.c_long(_openat2_number()),
        ctypes.c_int(directory_fd),
        ctypes.c_char_p(os.fsencode(path)),
        ctypes.byref(how),
        ctypes.c_size_t(ctypes.sizeof(how)),
    )
    if result >= 0:
        return int(result)
    error = ctypes.get_errno()
    if error in {errno.ENOSYS, errno.EINVAL}:
        raise ConnectorSDKError("filesystem reference connector requires openat2 containment")
    raise ConnectorSDKError("filesystem path cannot be resolved below the protected root")


def _canonical_json(value: Mapping[str, object]) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _identifier(value: object, field: str, *, maximum: int = 255) -> str:
    if not (
        type(value) is str
        and 0 < len(value) <= maximum
        and value.strip() == value
        and all(0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise ConnectorSDKError(f"{field} must be a canonical identifier")
    return value


def _digest(value: object, field: str, *, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    parsed = _identifier(value, field, maximum=64)
    if len(parsed) != 64 or any(character not in "0123456789abcdef" for character in parsed):
        raise ConnectorSDKError(f"{field} must be a lowercase SHA-256 digest")
    return parsed


def _absolute_path(value: object, field: str) -> Path:
    if not isinstance(value, Path) or not value.is_absolute():
        raise ConnectorSDKError(f"{field} must be an absolute Path")
    return value


def _logical_path(value: object, *, prefix: str) -> tuple[str, tuple[str, ...]]:
    if (
        type(value) is not str
        or not value
        or len(value) > 1024
        or not value.startswith(prefix + "/")
        or value.startswith("//")
        or "\\" in value
        or "\x00" in value
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
        or posixpath.normpath(value) != value
        or value.endswith("/")
    ):
        raise ConnectorSDKError("filesystem path must be a canonical non-root logical POSIX path")
    suffix = value.removeprefix(prefix + "/")
    parts = tuple(suffix.split("/"))
    if (
        not parts
        or any(part in {"", ".", ".."} for part in parts)
        or parts[0] == _PRIVATE_DIRECTORY
        or any(part.startswith(".masugate-fs-") for part in parts)
    ):
        raise ConnectorSDKError("filesystem path names a reserved or unsafe logical path")
    return value, parts


def _fingerprint(file_stat: os.stat_result) -> tuple[int, int, int, int]:
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_size,
        file_stat.st_ctime_ns,
    )


def _safe_regular(file_stat: os.stat_result, *, root_device: int, label: str) -> None:
    if file_stat.st_dev != root_device:
        raise ConnectorSDKError(f"filesystem {label} crosses the protected mount")
    if not stat.S_ISREG(file_stat.st_mode):
        raise ConnectorSDKError(f"filesystem {label} must be a regular file")
    if file_stat.st_nlink != 1:
        raise ConnectorSDKError(f"filesystem {label} must not have hard links")


def _read_descriptor(fd: int, *, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, min(64 * 1024, maximum + 1 - total))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise ConnectorSDKError("filesystem file exceeds the exact content bound")


def _unescape_mount(value: str) -> str:
    result: list[str] = []
    position = 0
    while position < len(value):
        if value[position] == "\\" and position + 3 < len(value):
            escaped = value[position + 1 : position + 4]
            if escaped.isdigit():
                result.append(chr(int(escaped, 8)))
                position += 4
                continue
        result.append(value[position])
        position += 1
    return "".join(result)


@dataclass(frozen=True, slots=True)
class FilesystemProfileFacts:
    """Observed host facts for the one supported reference deployment."""

    kernel_release: str
    container_runtime: str
    filesystem_type: str
    mount_options: tuple[str, ...]
    mount_source: str

    def __post_init__(self) -> None:
        for name in ("kernel_release", "container_runtime", "filesystem_type", "mount_source"):
            _identifier(getattr(self, name), f"filesystem profile {name}", maximum=1024)
        options = tuple(
            sorted(_identifier(value, "filesystem mount option") for value in self.mount_options)
        )
        if not options or len(set(options)) != len(options):
            raise ConnectorSDKError("filesystem profile mount options must be non-empty and unique")
        object.__setattr__(self, "mount_options", options)

    def payload(self) -> dict[str, object]:
        return {
            "container_runtime": self.container_runtime,
            "filesystem_type": self.filesystem_type,
            "kernel_release": self.kernel_release,
            "mount_options": list(self.mount_options),
            "mount_source": self.mount_source,
        }


class FilesystemProfileVerifier(Protocol):
    """The small injectable host-observation seam used by deterministic tests."""

    def observe(self, profile: FilesystemProfile) -> FilesystemProfileFacts: ...


@dataclass(frozen=True, slots=True)
class FilesystemProfile:
    """Trusted exact profile; no invocation can supply any of these values."""

    root: Path
    excluded_roots: tuple[Path, ...]
    kernel_release: str
    container_runtime: str
    mount_source: str
    mount_options: tuple[str, ...]
    logical_prefix: str = _LOGICAL_PREFIX

    def __post_init__(self) -> None:
        root = _absolute_path(self.root, "filesystem root")
        excluded = tuple(
            _absolute_path(path, "filesystem excluded root") for path in self.excluded_roots
        )
        if not excluded:
            raise ConnectorSDKError("filesystem profile must name agent/framework roots to exclude")
        if self.logical_prefix != _LOGICAL_PREFIX:
            raise ConnectorSDKError(
                "filesystem profile supports only the /workspace logical prefix"
            )
        facts = FilesystemProfileFacts(
            self.kernel_release,
            self.container_runtime,
            "ext4",
            self.mount_options,
            self.mount_source,
        )
        if len(set(excluded)) != len(excluded):
            raise ConnectorSDKError("filesystem excluded roots must be unique")
        try:
            resolved_root = root.resolve(strict=False)
            resolved_excluded = tuple(path.resolve(strict=False) for path in excluded)
        except OSError as exc:
            raise ConnectorSDKError("filesystem profile roots cannot be resolved") from exc
        if any(
            resolved_root == candidate
            or resolved_root.is_relative_to(candidate)
            or candidate.is_relative_to(resolved_root)
            for candidate in resolved_excluded
        ):
            raise ConnectorSDKError("filesystem root overlaps an agent/framework workspace")
        object.__setattr__(self, "root", root)
        object.__setattr__(self, "excluded_roots", excluded)
        object.__setattr__(self, "kernel_release", facts.kernel_release)
        object.__setattr__(self, "container_runtime", facts.container_runtime)
        object.__setattr__(self, "mount_source", facts.mount_source)
        object.__setattr__(self, "mount_options", facts.mount_options)

    @property
    def digest(self) -> str:
        root_locator = hashlib.sha256(
            str(self.root.resolve(strict=False)).encode("utf-8")
        ).hexdigest()
        excluded_locators = sorted(
            hashlib.sha256(str(path.resolve(strict=False)).encode("utf-8")).hexdigest()
            for path in self.excluded_roots
        )
        payload = {
            "container_runtime": self.container_runtime,
            "filesystem_type": "ext4",
            "kernel_release": self.kernel_release,
            "logical_prefix": self.logical_prefix,
            "mount_options": list(self.mount_options),
            "mount_source": self.mount_source,
            "profile": "masugate.filesystem.ext4.v1",
            "root_locator_sha256": root_locator,
            "excluded_root_locators_sha256": excluded_locators,
        }
        return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()

    def expected_facts(self) -> FilesystemProfileFacts:
        return FilesystemProfileFacts(
            self.kernel_release,
            self.container_runtime,
            "ext4",
            self.mount_options,
            self.mount_source,
        )


class LinuxExt4ProfileVerifier:
    """Verify an exact local Linux ext4 mount without shelling out to tools."""

    @staticmethod
    def _mount(profile: FilesystemProfile) -> tuple[str, tuple[str, ...], str, str, int]:
        wanted = str(profile.root)
        try:
            lines = Path("/proc/self/mountinfo").read_text("utf-8").splitlines()
        except OSError as exc:
            raise ConnectorSDKError(
                "filesystem profile cannot inspect Linux mount metadata"
            ) from exc
        candidates: list[tuple[list[str], list[str]]] = []
        for line in lines:
            before, separator, after = line.partition(" - ")
            if not separator:
                continue
            fields = before.split()
            post = after.split()
            if len(fields) < 6 or len(post) < 3:
                continue
            if _unescape_mount(fields[4]) != wanted:
                continue
            candidates.append((fields, post))
        if not candidates:
            raise ConnectorSDKError("filesystem root is not its own mounted connector root")
        candidate_ids = {int(fields[0]) for fields, _post in candidates}
        visible = [
            (fields, post)
            for fields, post in candidates
            if int(fields[0]) not in {int(other[1]) for other, _post in candidates}
        ]
        if len(visible) != 1 or not candidate_ids:
            raise ConnectorSDKError("filesystem root has an ambiguous stacked mount profile")
        fields, post = visible[0]
        if _unescape_mount(fields[3]) != "/":
            raise ConnectorSDKError(
                "filesystem root must be a dedicated mount, not a bind-mounted subtree"
            )
        return (
            post[0],
            tuple(sorted(set(fields[5].split(",")) | set(post[2].split(",")))),
            post[1],
            fields[2],
            int(fields[0]),
        )

    @classmethod
    def mount_id(cls, profile: FilesystemProfile) -> int:
        return cls._mount(profile)[4]

    @staticmethod
    def _statfs_type(root: Path) -> int:
        if platform.system() != "Linux":
            raise ConnectorSDKError("filesystem reference connector requires Linux")

        class _StatFs(ctypes.Structure):
            _fields_: ClassVar[Any] = [("f_type", ctypes.c_long), ("_rest", ctypes.c_byte * 248)]

        result = _StatFs()
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.statfs(os.fsencode(str(root)), ctypes.byref(result)) != 0:
            error = ctypes.get_errno()
            raise ConnectorSDKError(f"filesystem profile statfs failed: errno={error}")
        return int(result.f_type)

    def observe(self, profile: FilesystemProfile) -> FilesystemProfileFacts:
        try:
            listed = os.lstat(profile.root)
            resolved = profile.root.resolve(strict=True)
        except OSError as exc:
            raise ConnectorSDKError("filesystem root is unavailable") from exc
        if (
            stat.S_ISLNK(listed.st_mode)
            or not stat.S_ISDIR(listed.st_mode)
            or resolved != profile.root
        ):
            raise ConnectorSDKError("filesystem root must be a non-symlink canonical directory")
        root_resolved = resolved
        for excluded in profile.excluded_roots:
            try:
                listed_excluded = os.lstat(excluded)
                excluded_resolved = excluded.resolve(strict=True)
            except OSError as exc:
                raise ConnectorSDKError("filesystem excluded root is unavailable") from exc
            if stat.S_ISLNK(listed_excluded.st_mode) or not stat.S_ISDIR(listed_excluded.st_mode):
                raise ConnectorSDKError("filesystem excluded root must be a canonical directory")
            if excluded_resolved != excluded:
                raise ConnectorSDKError("filesystem excluded root must not traverse a symlink")
            if (
                root_resolved == excluded_resolved
                or root_resolved.is_relative_to(excluded_resolved)
                or excluded_resolved.is_relative_to(root_resolved)
            ):
                raise ConnectorSDKError("filesystem root overlaps an agent/framework workspace")
        filesystem_type, options, source, mount_device, _mount_id = self._mount(profile)
        if filesystem_type != "ext4" or self._statfs_type(profile.root) != _EXT4_MAGIC:
            raise ConnectorSDKError("filesystem reference connector requires a local ext4 mount")
        for excluded in profile.excluded_roots:
            metadata = os.stat(excluded.resolve(strict=True), follow_symlinks=False)
            excluded_device = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
            if excluded_device == mount_device:
                raise ConnectorSDKError(
                    "filesystem root shares a backing filesystem with an excluded workspace"
                )
        runtime = os.environ.get("MASUGATE_FILESYSTEM_CONTAINER_RUNTIME")
        if runtime is None:
            raise ConnectorSDKError("filesystem container runtime identity is unavailable")
        return FilesystemProfileFacts(platform.release(), runtime, filesystem_type, options, source)


@dataclass(frozen=True, slots=True)
class _FileState:
    digest: str
    content_bytes: int
    fingerprint: tuple[int, int, int, int]
    provenance_token: str | None


@dataclass(frozen=True, slots=True)
class _Invocation:
    logical_path: str
    parts: tuple[str, ...]
    expected_digest: str
    content: bytes | None
    content_descriptor: ArtifactDescriptor | None


class FilesystemConnector:
    """One-profile, journaled file write/quarantine-delete connector."""

    connector_id = _CONNECTOR_ID
    sdk_contract_version = SDK_CONTRACT_VERSION
    capabilities = _CAPABILITIES

    def __init__(
        self,
        profile: FilesystemProfile,
        *,
        verifier: FilesystemProfileVerifier | None = None,
        lose_response_after_commit: bool = False,
    ) -> None:
        if type(profile) is not FilesystemProfile:
            raise TypeError("filesystem connector requires a FilesystemProfile")
        if verifier is not None and not callable(getattr(verifier, "observe", None)):
            raise TypeError("filesystem connector verifier must provide observe")
        if type(lose_response_after_commit) is not bool:
            raise TypeError("filesystem connector response-loss flag must be bool")
        self.profile = profile
        self._verifier: FilesystemProfileVerifier = (
            LinuxExt4ProfileVerifier() if verifier is None else verifier
        )
        self.lose_response_after_commit = lose_response_after_commit
        self._root_fd = -1
        self._private_fd = -1
        self._quarantine_fd = -1
        self._locks_fd = -1
        self._root_device = -1
        self._journal_path: Path | None = None
        self.startup_profile = self._start()

    @property
    def configuration_digest(self) -> str:
        return self.profile.digest

    def close(self) -> None:
        for attribute in ("_locks_fd", "_quarantine_fd", "_private_fd", "_root_fd"):
            descriptor = getattr(self, attribute)
            if descriptor >= 0:
                os.close(descriptor)
                setattr(self, attribute, -1)

    def _start(self) -> FilesystemProfileFacts:
        observed = self._verifier.observe(self.profile)
        if type(observed) is not FilesystemProfileFacts:
            raise ConnectorSDKError("filesystem profile verifier returned malformed facts")
        if observed != self.profile.expected_facts():
            raise ConnectorSDKError("filesystem runtime profile drifted from the exact deployment")
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        try:
            self._root_fd = os.open(self.profile.root, directory_flags)
            self._verify_root_mount_identity()
            root_stat = os.fstat(self._root_fd)
            if not stat.S_ISDIR(root_stat.st_mode):
                raise ConnectorSDKError("filesystem root is not a directory")
            self._root_device = root_stat.st_dev
            probe = _openat2_beneath(
                self._root_fd,
                ".",
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            os.close(probe)
            self._private_fd = self._open_or_create_directory(self._root_fd, _PRIVATE_DIRECTORY)
            self._quarantine_fd = self._open_or_create_directory(
                self._private_fd, _QUARANTINE_DIRECTORY
            )
            self._locks_fd = self._open_or_create_directory(self._private_fd, _LOCK_DIRECTORY)
            self._probe_provenance_xattr()
            self._journal_path = self._secure_journal_path()
            self._initialize_journal(observed)
        except BaseException:
            self.close()
            raise
        return observed

    def _verify_root_mount_identity(self) -> None:
        if not isinstance(self._verifier, LinuxExt4ProfileVerifier):
            return
        try:
            fdinfo = Path(f"/proc/self/fdinfo/{self._root_fd}").read_text("utf-8")
            observed_id = next(
                int(line.removeprefix("mnt_id:"))
                for line in fdinfo.splitlines()
                if line.startswith("mnt_id:")
            )
        except (OSError, StopIteration, ValueError) as exc:
            raise ConnectorSDKError(
                "filesystem root descriptor mount identity is unavailable"
            ) from exc
        if observed_id != LinuxExt4ProfileVerifier.mount_id(self.profile):
            raise ConnectorSDKError("filesystem root descriptor is not the visible profiled mount")

    def _open_or_create_directory(self, parent_fd: int, name: str) -> int:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except FileExistsError:
            pass
        try:
            descriptor = _openat2_beneath(
                parent_fd,
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
        except OSError as exc:
            raise ConnectorSDKError("connector-private filesystem directory is unsafe") from exc
        metadata = os.fstat(descriptor)
        if metadata.st_dev != self._root_device or not stat.S_ISDIR(metadata.st_mode):
            os.close(descriptor)
            raise ConnectorSDKError("connector-private filesystem directory crosses the mount")
        return descriptor

    def _probe_provenance_xattr(self) -> None:
        token = secrets.token_hex(16).encode("ascii")
        try:
            os.setxattr(self._private_fd, _PROVENANCE_ATTRIBUTE, token)
            if os.getxattr(self._private_fd, _PROVENANCE_ATTRIBUTE) != token:
                raise OSError(errno.EIO, "xattr round trip changed")
            os.removexattr(self._private_fd, _PROVENANCE_ATTRIBUTE)
            os.fsync(self._private_fd)
        except OSError as exc:
            raise ConnectorSDKError(
                "filesystem reference connector requires durable user xattr provenance"
            ) from exc

    def _secure_journal_path(self) -> Path:
        try:
            metadata = os.stat(_JOURNAL_FILE, dir_fd=self._private_fd, follow_symlinks=False)
        except FileNotFoundError:
            try:
                descriptor = os.open(
                    _JOURNAL_FILE,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=self._private_fd,
                )
            except OSError as exc:
                raise ConnectorSDKError("cannot create connector filesystem journal") from exc
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(self._private_fd)
            metadata = os.stat(_JOURNAL_FILE, dir_fd=self._private_fd, follow_symlinks=False)
        if (
            metadata.st_dev != self._root_device
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
        ):
            raise ConnectorSDKError("connector filesystem journal is unsafe")
        return Path(f"/proc/self/fd/{self._private_fd}") / _JOURNAL_FILE

    def _connect(self) -> sqlite3.Connection:
        if self._journal_path is None:
            raise ConnectorSDKError("filesystem connector is closed")
        connection = sqlite3.connect(self._journal_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _initialize_journal(self, facts: FilesystemProfileFacts) -> None:
        with closing(self._connect()) as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS filesystem_connector_profile (
                    id INTEGER PRIMARY KEY CHECK(id = 1),
                    profile_digest TEXT NOT NULL,
                    facts_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS filesystem_connector_journal (
                    execution_id TEXT PRIMARY KEY,
                    binding_digest TEXT NOT NULL,
                    action TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    fence_token INTEGER NOT NULL,
                    logical_path TEXT NOT NULL,
                    expected_digest TEXT NOT NULL,
                    artifact_digest TEXT,
                    content_bytes INTEGER NOT NULL,
                    artifact_reference TEXT,
                    before_digest TEXT NOT NULL,
                    after_digest TEXT NOT NULL,
                    quarantine_id TEXT NOT NULL,
                    provenance_token TEXT NOT NULL DEFAULT '',
                    state TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    CHECK(state IN ('prepared', 'succeeded', 'failed'))
                );
                """
            )
            columns = {
                cast(str, row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(filesystem_connector_journal)"
                ).fetchall()
            }
            if "provenance_token" not in columns:
                connection.execute(
                    "ALTER TABLE filesystem_connector_journal "
                    "ADD COLUMN provenance_token TEXT NOT NULL DEFAULT ''"
                )
            payload = _canonical_json(cast(Mapping[str, object], facts.payload()))
            existing = connection.execute(
                "SELECT profile_digest, facts_json FROM filesystem_connector_profile WHERE id = 1"
            ).fetchone()
            if existing is None:
                connection.execute(
                    "INSERT INTO filesystem_connector_profile("
                    "id, profile_digest, facts_json) VALUES (1, ?, ?)",
                    (self.configuration_digest, payload),
                )
            elif (
                cast(str, existing["profile_digest"]) != self.configuration_digest
                or cast(str, existing["facts_json"]) != payload
            ):
                raise ConnectorSDKError("filesystem connector journal profile drifted")
            connection.commit()

    @staticmethod
    def _operation_id(invocation: ConnectorInvocation) -> str:
        material = (
            f"{invocation.action}:{invocation.execution_id}:{invocation.binding_digest}".encode()
        )
        return "fsop_" + hashlib.sha256(material).hexdigest()

    @staticmethod
    def _quarantine_id(invocation: ConnectorInvocation) -> str:
        material = f"{invocation.execution_id}:{invocation.binding_digest}:quarantine".encode()
        return "q_" + hashlib.sha256(material).hexdigest()

    def _validate_common(
        self, invocation: ConnectorInvocation, *, for_execute: bool
    ) -> _Invocation:
        self._verify_runtime_profile()
        if invocation.action not in {_WRITE, _DELETE}:
            raise ConnectorSDKError("filesystem connector does not own this action")
        if invocation.connector_id != self.connector_id:
            raise ConnectorSDKError("filesystem connector has the wrong identity")
        if invocation.connector_configuration_digest != self.configuration_digest:
            raise ConnectorSDKError("filesystem connector configuration drifted")
        if invocation.secrets or invocation.allowed_destinations:
            raise ConnectorSDKError("filesystem connector refuses secrets and destinations")
        if invocation.action == _WRITE:
            expected_fields = {"content", "expected_prior_digest", "path"}
            if set(invocation.arguments) != expected_fields:
                raise ConnectorSDKError("filesystem write has unsupported arguments")
            path, parts = _logical_path(
                invocation.arguments["path"], prefix=self.profile.logical_prefix
            )
            expected = _digest(
                invocation.arguments["expected_prior_digest"],
                "expected_prior_digest",
                allow_empty=True,
            )
            content = invocation.arguments["content"]
            if type(content) is not str or not content.startswith("art:"):
                raise ConnectorSDKError(
                    "filesystem write content must be a MasuGate artifact reference"
                )
            if for_execute and tuple(invocation.artifacts) != ("content",):
                raise ConnectorSDKError(
                    "filesystem write requires exactly one sealed content artifact"
                )
            if not for_execute and invocation.artifacts:
                raise ConnectorSDKError(
                    "filesystem status requests cannot reopen content artifacts"
                )
            return _Invocation(path, parts, expected, None, None)
        if set(invocation.arguments) != {"expected_current_digest", "path"}:
            raise ConnectorSDKError("filesystem delete has unsupported arguments")
        if invocation.artifacts:
            raise ConnectorSDKError("filesystem delete refuses artifacts")
        path, parts = _logical_path(
            invocation.arguments["path"], prefix=self.profile.logical_prefix
        )
        return _Invocation(
            path,
            parts,
            _digest(invocation.arguments["expected_current_digest"], "expected_current_digest"),
            None,
            None,
        )

    def _verify_runtime_profile(self) -> None:
        observed = self._verifier.observe(self.profile)
        if type(observed) is not FilesystemProfileFacts or observed != self.startup_profile:
            raise ConnectorSDKError("filesystem runtime profile drifted from startup verification")
        self._verify_root_mount_identity()

    async def _write_invocation(self, invocation: ConnectorInvocation) -> _Invocation:
        parsed = self._validate_common(invocation, for_execute=True)
        reader = invocation.artifacts["content"]
        metadata = reader.metadata
        if type(metadata) is not ArtifactDescriptor:
            raise ConnectorSDKError("filesystem content artifact metadata is malformed")
        if invocation.arguments["content"] != metadata.reference:
            raise ConnectorSDKError(
                "filesystem content argument does not match the sealed artifact"
            )
        content = await reader.read(maximum_bytes=_MAX_CONTENT_BYTES)
        if (
            not isinstance(content, bytes)
            or len(content) > _MAX_CONTENT_BYTES
            or len(content) != metadata.content_bytes
        ):
            raise ConnectorSDKError("filesystem sealed content length changed")
        if hashlib.sha256(content).hexdigest() != metadata.content_digest:
            raise ConnectorSDKError("filesystem sealed content digest changed")
        if not content:
            raise ConnectorSDKError("filesystem write content must not be empty")
        return _Invocation(
            parsed.logical_path,
            parsed.parts,
            parsed.expected_digest,
            content,
            metadata,
        )

    def _open_parent(self, parts: tuple[str, ...]) -> tuple[int, str]:
        if len(parts) == 1:
            return os.dup(self._root_fd), parts[0]
        descriptor = _openat2_beneath(
            self._root_fd,
            "/".join(parts[:-1]),
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        metadata = os.fstat(descriptor)
        if metadata.st_dev != self._root_device or not stat.S_ISDIR(metadata.st_mode):
            os.close(descriptor)
            raise ConnectorSDKError("filesystem parent escapes the dedicated mount")
        return descriptor, parts[-1]

    def _state(self, parent_fd: int, name: str) -> _FileState | None:
        try:
            listed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return None
        _safe_regular(listed, root_device=self._root_device, label="target")
        try:
            descriptor = _openat2_beneath(
                parent_fd, name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
            )
        except OSError as exc:
            raise ConnectorSDKError(
                "filesystem target cannot be opened without following links"
            ) from exc
        try:
            opened = os.fstat(descriptor)
            _safe_regular(opened, root_device=self._root_device, label="target")
            if _fingerprint(opened) != _fingerprint(listed):
                raise ConnectorSDKError("filesystem target changed during no-follow resolution")
            content = _read_descriptor(descriptor, maximum=_MAX_CONTENT_BYTES)
            try:
                marker = os.getxattr(descriptor, _PROVENANCE_ATTRIBUTE)
            except OSError as exc:
                if exc.errno in {errno.ENODATA, getattr(errno, "ENOATTR", errno.ENODATA)}:
                    marker = None
                else:
                    raise ConnectorSDKError("filesystem target provenance cannot be read") from exc
        finally:
            os.close(descriptor)
        if marker is not None:
            try:
                provenance_token = marker.decode("ascii")
            except UnicodeDecodeError as exc:
                raise ConnectorSDKError("filesystem target provenance is malformed") from exc
        else:
            provenance_token = None
        return _FileState(
            hashlib.sha256(content).hexdigest(),
            len(content),
            _fingerprint(listed),
            provenance_token,
        )

    def _unchanged(self, parent_fd: int, name: str, previous: _FileState) -> None:
        current = self._state(parent_fd, name)
        if current is None or current.fingerprint != previous.fingerprint:
            raise ConnectorSDKError("filesystem target changed during protected resolution")

    def _temp_name(self, invocation: ConnectorInvocation) -> str:
        return ".masugate-fs-" + self._operation_id(invocation)[5:] + ".tmp"

    def _write_temp(self, parent_fd: int, name: str, content: bytes, provenance_token: str) -> None:
        try:
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=parent_fd,
            )
        except FileExistsError as exc:
            raise ConnectorAmbiguousOutcome(
                "filesystem write has an unresolved prior temporary file"
            ) from exc
        try:
            offset = 0
            while offset < len(content):
                offset += os.write(descriptor, content[offset:])
            try:
                os.setxattr(descriptor, _PROVENANCE_ATTRIBUTE, provenance_token.encode("ascii"))
            except OSError as exc:
                raise ConnectorSDKError(
                    "filesystem reference connector requires durable user xattr provenance"
                ) from exc
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _mark_existing(
        self, parent_fd: int, name: str, previous: _FileState, provenance_token: str
    ) -> None:
        try:
            descriptor = _openat2_beneath(parent_fd, name, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
        except OSError as exc:
            raise ConnectorSDKError(
                "filesystem target cannot be marked without following links"
            ) from exc
        try:
            opened = os.fstat(descriptor)
            _safe_regular(opened, root_device=self._root_device, label="target")
            if _fingerprint(opened) != previous.fingerprint:
                raise ConnectorSDKError("filesystem target changed before quarantine provenance")
            try:
                os.setxattr(descriptor, _PROVENANCE_ATTRIBUTE, provenance_token.encode("ascii"))
            except OSError as exc:
                raise ConnectorSDKError(
                    "filesystem reference connector requires durable user xattr provenance"
                ) from exc
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @contextmanager
    def _path_lock(self, parsed: _Invocation) -> Generator[None, None, None]:
        """Serialize every state check and rename for one logical target across workers."""

        name = hashlib.sha256(parsed.logical_path.encode("utf-8")).hexdigest() + ".lock"
        try:
            descriptor = os.open(
                name,
                os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=self._locks_fd,
            )
        except OSError as exc:
            raise ConnectorSDKError("filesystem path lock cannot be opened safely") from exc
        try:
            metadata = os.fstat(descriptor)
            _safe_regular(metadata, root_device=self._root_device, label="path lock")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            os.close(descriptor)

    @staticmethod
    def _rename_no_replace(
        source_parent_fd: int,
        source: str,
        destination_parent_fd: int,
        destination: str,
    ) -> None:
        """Use Linux renameat2 so quarantine can never overwrite a prior file."""

        renameat2 = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
        if renameat2 is None:
            raise ConnectorSDKError("filesystem reference connector requires Linux renameat2")
        renameat2.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        renameat2.restype = ctypes.c_int
        result = renameat2(
            source_parent_fd,
            os.fsencode(source),
            destination_parent_fd,
            os.fsencode(destination),
            _RENAME_NOREPLACE,
        )
        if result == 0:
            return
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(error, "filesystem quarantine identity exists", destination)
        raise ConnectorSDKError(f"filesystem quarantine rename failed: errno={error}")

    def _journal_row(self, execution_id: str) -> sqlite3.Row | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM filesystem_connector_journal WHERE execution_id = ?", (execution_id,)
            ).fetchone()
        return None if row is None else cast(sqlite3.Row, row)

    def _assert_journal_matches(
        self,
        row: sqlite3.Row,
        invocation: ConnectorInvocation,
        parsed: _Invocation,
        *,
        require_exact_fence: bool = True,
    ) -> None:
        artifact_reference = (
            cast(str, invocation.arguments["content"]) if invocation.action == _WRITE else ""
        )
        expected = (
            invocation.binding_digest,
            invocation.action,
            invocation.idempotency_key,
            parsed.logical_path,
            parsed.expected_digest,
            artifact_reference,
        )
        actual = (
            row["binding_digest"],
            row["action"],
            row["idempotency_key"],
            row["logical_path"],
            row["expected_digest"],
            row["artifact_reference"] or "",
        )
        if actual != expected:
            raise ConnectorSDKError("filesystem journal rejects replay with changed binding")
        stored_fence = cast(int, row["fence_token"])
        if (require_exact_fence and invocation.fence_token != stored_fence) or (
            not require_exact_fence and invocation.fence_token < stored_fence
        ):
            raise ConnectorSDKError("filesystem journal rejects a stale or changed fence")

    def _begin(
        self,
        invocation: ConnectorInvocation,
        parsed: _Invocation,
    ) -> tuple[sqlite3.Row, bool]:
        artifact_digest = (
            "" if parsed.content_descriptor is None else parsed.content_descriptor.content_digest
        )
        artifact_reference = (
            cast(str, invocation.arguments["content"]) if invocation.action == _WRITE else ""
        )
        content_bytes = (
            0 if parsed.content_descriptor is None else parsed.content_descriptor.content_bytes
        )
        quarantine_id = self._quarantine_id(invocation) if invocation.action == _DELETE else ""
        provenance_token = secrets.token_hex(32)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM filesystem_connector_journal WHERE execution_id = ?",
                (invocation.execution_id,),
            ).fetchone()
            created = existing is None
            if existing is None:
                connection.execute(
                    "INSERT INTO filesystem_connector_journal("
                    "execution_id, binding_digest, action, idempotency_key, "
                    "fence_token, logical_path, expected_digest, artifact_digest, "
                    "content_bytes, artifact_reference, before_digest, after_digest, "
                    "quarantine_id, provenance_token, state, created_at, observed_at) VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?, 'prepared', ?, ?)",
                    (
                        invocation.execution_id,
                        invocation.binding_digest,
                        invocation.action,
                        invocation.idempotency_key,
                        invocation.fence_token,
                        parsed.logical_path,
                        parsed.expected_digest,
                        artifact_digest,
                        content_bytes,
                        artifact_reference,
                        artifact_digest,
                        quarantine_id,
                        provenance_token,
                        datetime.now(UTC).isoformat(),
                        datetime.now(UTC).isoformat(),
                    ),
                )
                existing = connection.execute(
                    "SELECT * FROM filesystem_connector_journal WHERE execution_id = ?",
                    (invocation.execution_id,),
                ).fetchone()
            else:
                self._assert_journal_matches(existing, invocation, parsed)
                if (
                    (existing["artifact_digest"] or "") != artifact_digest
                    or existing["quarantine_id"] != quarantine_id
                    or (existing["state"] == "prepared" and not existing["provenance_token"])
                    or (invocation.action == _WRITE and existing["content_bytes"] != content_bytes)
                ):
                    raise ConnectorSDKError(
                        "filesystem journal rejects replay with changed sealed content"
                    )
            connection.commit()
        assert existing is not None
        return existing, created

    def _finish(
        self,
        execution_id: str,
        *,
        state: str,
        before_digest: str,
        after_digest: str,
    ) -> sqlite3.Row:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE filesystem_connector_journal SET state = ?, before_digest = ?, "
                "after_digest = ?, observed_at = ? "
                "WHERE execution_id = ? AND state = 'prepared'",
                (state, before_digest, after_digest, datetime.now(UTC).isoformat(), execution_id),
            )
            row = connection.execute(
                "SELECT * FROM filesystem_connector_journal WHERE execution_id = ?", (execution_id,)
            ).fetchone()
            connection.commit()
        if row is None:
            raise ConnectorSDKError("filesystem journal lost an execution")
        return cast(sqlite3.Row, row)

    def _record_prestate(
        self, execution_id: str, *, before_digest: str, content_bytes: int
    ) -> sqlite3.Row:
        """Make recovery facts durable before provenance marking or rename."""

        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "UPDATE filesystem_connector_journal SET before_digest = ?, content_bytes = ?, "
                "observed_at = ? WHERE execution_id = ? AND state = 'prepared'",
                (before_digest, content_bytes, datetime.now(UTC).isoformat(), execution_id),
            )
            row = connection.execute(
                "SELECT * FROM filesystem_connector_journal WHERE execution_id = ?", (execution_id,)
            ).fetchone()
            connection.commit()
        if row is None:
            raise ConnectorSDKError("filesystem journal lost an execution")
        return cast(sqlite3.Row, row)

    def _evidence(self, invocation: ConnectorInvocation, row: sqlite3.Row) -> ConnectorEvidence:
        state = cast(str, row["state"])
        if state not in {"succeeded", "failed"}:
            raise ConnectorAmbiguousOutcome(
                "filesystem operation remains prepared in the durable journal",
                external_operation_id=self._operation_id(invocation),
            )
        action = cast(str, row["action"])
        before_digest = cast(str, row["before_digest"])
        after_digest = cast(str, row["after_digest"])
        payload: dict[str, object] = {
            "after_digest": after_digest,
            "before_digest": before_digest,
            "bytes": cast(int, row["content_bytes"]),
            "logical_path": cast(str, row["logical_path"]),
            "status": "written"
            if action == _WRITE and state == "succeeded"
            else ("deleted" if action == _DELETE and state == "succeeded" else "conflict"),
        }
        if action == _DELETE:
            payload["quarantine_id"] = cast(str, row["quarantine_id"])
        return ConnectorEvidence(
            connector_id=self.connector_id,
            evidence_id=f"filesystem:{action}:{self._operation_id(invocation)}:{state}",
            idempotency_key=invocation.idempotency_key,
            external_operation_id=self._operation_id(invocation),
            outcome=ConnectorOutcome.SUCCEEDED if state == "succeeded" else ConnectorOutcome.FAILED,
            observed_at=datetime.fromisoformat(cast(str, row["observed_at"])),
            payload=cast(Mapping[str, Any], payload),
        )

    def _reconcile_prepared(
        self, invocation: ConnectorInvocation, parsed: _Invocation
    ) -> sqlite3.Row:
        row = self._journal_row(invocation.execution_id)
        if row is None:
            raise ConnectorSDKError("filesystem journal lacks the prepared operation")
        if row["state"] != "prepared":
            return row
        parent_fd, name = self._open_parent(parsed.parts)
        try:
            if invocation.action == _WRITE:
                state = self._state(parent_fd, name)
                target_digest = cast(str, row["after_digest"])
                if (
                    state is not None
                    and state.digest == target_digest
                    and state.content_bytes == row["content_bytes"]
                    and state.provenance_token == row["provenance_token"]
                ):
                    return self._finish(
                        invocation.execution_id,
                        state="succeeded",
                        before_digest=cast(str, row["before_digest"]),
                        after_digest=target_digest,
                    )
            else:
                target = self._state(parent_fd, name)
                quarantine_name = cast(str, row["quarantine_id"])
                quarantined = self._state(self._quarantine_fd, quarantine_name)
                if (
                    target is None
                    and quarantined is not None
                    and quarantined.digest == cast(str, row["before_digest"])
                    and quarantined.content_bytes == row["content_bytes"]
                    and quarantined.provenance_token == row["provenance_token"]
                ):
                    return self._finish(
                        invocation.execution_id,
                        state="succeeded",
                        before_digest=cast(str, row["before_digest"]),
                        after_digest="",
                    )
        finally:
            os.close(parent_fd)
        raise ConnectorAmbiguousOutcome(
            "filesystem prepared operation cannot be reconciled safely",
            external_operation_id=self._operation_id(invocation),
        )

    def _record_conflict(
        self, invocation: ConnectorInvocation, *, before_digest: str, after_digest: str = ""
    ) -> ConnectorEvidence:
        row = self._finish(
            invocation.execution_id,
            state="failed",
            before_digest=before_digest,
            after_digest=after_digest,
        )
        return self._evidence(invocation, row)

    def _execute_write(
        self, invocation: ConnectorInvocation, parsed: _Invocation
    ) -> ConnectorEvidence:
        assert parsed.content is not None and parsed.content_descriptor is not None
        with self._path_lock(parsed):
            row, created = self._begin(invocation, parsed)
            if row["state"] != "prepared":
                return self._evidence(invocation, row)
            if not created:
                row = self._reconcile_prepared(invocation, parsed)
                return self._evidence(invocation, row)
            parent_fd, name = self._open_parent(parsed.parts)
            temporary = self._temp_name(invocation)
            try:
                existing = self._state(parent_fd, name)
                before_digest = "" if existing is None else existing.digest
                if (existing is None and parsed.expected_digest) or (
                    existing is not None
                    and (not parsed.expected_digest or parsed.expected_digest != existing.digest)
                ):
                    return self._record_conflict(invocation, before_digest=before_digest)
                row = self._record_prestate(
                    invocation.execution_id,
                    before_digest=before_digest,
                    content_bytes=len(parsed.content),
                )
                self._write_temp(
                    parent_fd, temporary, parsed.content, cast(str, row["provenance_token"])
                )
                if existing is None:
                    try:
                        self._rename_no_replace(parent_fd, temporary, parent_fd, name)
                    except FileExistsError:
                        return self._record_conflict(
                            invocation,
                            before_digest=(
                                self._state(parent_fd, name)
                                or _FileState("", 0, (0, 0, 0, 0), None)
                            ).digest,
                        )
                else:
                    self._unchanged(parent_fd, name, existing)
                    os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                os.fsync(parent_fd)
                row = self._finish(
                    invocation.execution_id,
                    state="succeeded",
                    before_digest=before_digest,
                    after_digest=parsed.content_descriptor.content_digest,
                )
            finally:
                with suppress(FileNotFoundError):
                    os.unlink(temporary, dir_fd=parent_fd)
                os.close(parent_fd)
        if self.lose_response_after_commit:
            self.lose_response_after_commit = False
            raise ConnectorAmbiguousOutcome(
                "filesystem connector lost the response after its durable transition",
                external_operation_id=self._operation_id(invocation),
            )
        return self._evidence(invocation, row)

    def _execute_delete(
        self, invocation: ConnectorInvocation, parsed: _Invocation
    ) -> ConnectorEvidence:
        with self._path_lock(parsed):
            row, created = self._begin(invocation, parsed)
            if row["state"] != "prepared":
                return self._evidence(invocation, row)
            if not created:
                row = self._reconcile_prepared(invocation, parsed)
                return self._evidence(invocation, row)
            parent_fd, name = self._open_parent(parsed.parts)
            try:
                existing = self._state(parent_fd, name)
                if existing is None or existing.digest != parsed.expected_digest:
                    return self._record_conflict(
                        invocation, before_digest="" if existing is None else existing.digest
                    )
                row = self._record_prestate(
                    invocation.execution_id,
                    before_digest=existing.digest,
                    content_bytes=existing.content_bytes,
                )
                self._mark_existing(parent_fd, name, existing, cast(str, row["provenance_token"]))
                quarantine_id = cast(str, row["quarantine_id"])
                try:
                    self._rename_no_replace(parent_fd, name, self._quarantine_fd, quarantine_id)
                except FileExistsError as exc:
                    raise ConnectorAmbiguousOutcome(
                        "filesystem quarantine identity already exists",
                        external_operation_id=self._operation_id(invocation),
                    ) from exc
                os.fsync(parent_fd)
                os.fsync(self._quarantine_fd)
                row = self._finish(
                    invocation.execution_id,
                    state="succeeded",
                    before_digest=existing.digest,
                    after_digest="",
                )
            finally:
                os.close(parent_fd)
        if self.lose_response_after_commit:
            self.lose_response_after_commit = False
            raise ConnectorAmbiguousOutcome(
                "filesystem connector lost the response after its durable transition",
                external_operation_id=self._operation_id(invocation),
            )
        return self._evidence(invocation, row)

    async def execute(self, invocation: ConnectorInvocation) -> ConnectorEvidence:
        if invocation.action == _WRITE:
            return self._execute_write(invocation, await self._write_invocation(invocation))
        return self._execute_delete(invocation, self._validate_common(invocation, for_execute=True))

    async def query_status(
        self, invocation: ConnectorInvocation, *, external_operation_id: str | None
    ) -> ConnectorEvidence:
        parsed = self._validate_common(invocation, for_execute=False)
        expected = self._operation_id(invocation)
        if external_operation_id != expected:
            raise ConnectorSDKError("filesystem status query names the wrong operation")
        row = self._journal_row(invocation.execution_id)
        if row is None:
            raise ConnectorAmbiguousOutcome(
                "filesystem journal has no operation", external_operation_id=expected
            )
        self._assert_journal_matches(row, invocation, parsed, require_exact_fence=False)
        if row["state"] == "prepared":
            with self._path_lock(parsed):
                row = self._reconcile_prepared(invocation, parsed)
        return self._evidence(invocation, row)

    async def cancel(
        self, invocation: ConnectorInvocation, *, external_operation_id: str | None
    ) -> ConnectorEvidence:
        # A rename cannot be safely reversed as a lifecycle cancellation.
        # Querying the journal is the only honest cancellation implementation.
        return await self.query_status(invocation, external_operation_id=external_operation_id)


class _EnvironmentConnector:
    """Lazy exact-worker entry point with no caller-selected profile knobs."""

    connector_id = FilesystemConnector.connector_id
    sdk_contract_version = SDK_CONTRACT_VERSION
    capabilities = _CAPABILITIES

    @staticmethod
    def _profile() -> FilesystemProfile:
        try:
            excluded = tuple(
                Path(value)
                for value in os.environ["MASUGATE_FILESYSTEM_EXCLUDED_ROOTS"].split(",")
                if value
            )
            options = tuple(
                value
                for value in os.environ["MASUGATE_FILESYSTEM_MOUNT_OPTIONS"].split(",")
                if value
            )
            profile = FilesystemProfile(
                Path(os.environ["MASUGATE_FILESYSTEM_ROOT"]),
                excluded,
                os.environ["MASUGATE_FILESYSTEM_KERNEL_RELEASE"],
                os.environ["MASUGATE_FILESYSTEM_CONTAINER_RUNTIME"],
                os.environ["MASUGATE_FILESYSTEM_MOUNT_SOURCE"],
                options,
                os.environ.get("MASUGATE_FILESYSTEM_LOGICAL_PREFIX", _LOGICAL_PREFIX),
            )
        except KeyError as exc:
            raise ConnectorSDKError("filesystem worker configuration is missing") from exc
        return profile

    @classmethod
    def _configured(cls) -> FilesystemConnector:
        return FilesystemConnector(cls._profile())

    @property
    def configuration_digest(self) -> str:
        return self._profile().digest

    async def execute(self, invocation: ConnectorInvocation) -> ConnectorEvidence:
        configured = self._configured()
        try:
            return await configured.execute(invocation)
        finally:
            configured.close()

    async def query_status(
        self, invocation: ConnectorInvocation, *, external_operation_id: str | None
    ) -> ConnectorEvidence:
        configured = self._configured()
        try:
            return await configured.query_status(
                invocation, external_operation_id=external_operation_id
            )
        finally:
            configured.close()

    async def cancel(
        self, invocation: ConnectorInvocation, *, external_operation_id: str | None
    ) -> ConnectorEvidence:
        configured = self._configured()
        try:
            return await configured.cancel(invocation, external_operation_id=external_operation_id)
        finally:
            configured.close()


connector = _EnvironmentConnector()

__all__ = [
    "FilesystemConnector",
    "FilesystemProfile",
    "FilesystemProfileFacts",
    "FilesystemProfileVerifier",
    "LinuxExt4ProfileVerifier",
    "connector",
]
