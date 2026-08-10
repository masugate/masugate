"""Bounded, immutable payload staging for protected operation connectors.

The public action path never receives a filesystem path, caller-provided
digest, classification, or retention value.  A staging binding joins one
authenticated adapter invocation, action, idempotency key, and declared pack
field to exactly one byte sequence.  The reference implementation persists
the bytes in SQLite solely so a restarted connector worker can obtain a
verified reader without a shared agent-visible volume.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol, cast

from masugate.errors import ContractError
from masugate.model import JsonValue

from .schema import canonical_json, require_digest, require_identifier, require_model_field

MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
DEFAULT_ARTIFACT_TOTAL_BYTES = 64 * 1024 * 1024
MAX_ARTIFACT_RECORDS = 4_096
DEFAULT_ARTIFACT_TTL = timedelta(hours=1)
MAX_ARTIFACT_MEDIA_TYPE_LENGTH = 128
MAX_ARTIFACT_CLASSIFICATION_LENGTH = 255
REFERENCE_INSPECTOR_VERSION = "reference-inspector.v1"
_UNSUPPORTED_COMPRESSED_MEDIA_TYPES = frozenset(
    {
        "application/gzip",
        "application/x-bzip2",
        "application/x-gzip",
        "application/x-tar",
        "application/x-xz",
        "application/zip",
    }
)


class ArtifactError(ContractError):
    """A caller attempted an invalid protected-payload transition."""


class ArtifactConflict(ArtifactError):
    """One immutable staging identity was reused with different content."""


class ArtifactUnavailable(ArtifactError):
    """An artifact is missing, expired, or failed its read-time verification."""


def _aware(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value


def _utc(value: datetime, field: str) -> datetime:
    """Validate and normalize every persisted instant to UTC.

    SQLite compares text lexically.  Storing a single UTC representation keeps
    that implementation detail from changing expiry semantics for callers that
    supplied an otherwise valid non-UTC instant.
    """

    return _aware(value, field).astimezone(UTC)


def _media_type(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_ARTIFACT_MEDIA_TYPE_LENGTH
        or value != value.strip()
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value)
        or value.count("/") != 1
    ):
        raise ValueError("artifact media_type must be a bounded ASCII media type")
    major, minor = value.split("/", maxsplit=1)
    if not major or not minor or any(character in ";\\\\" for character in value):
        raise ValueError("artifact media_type must not include parameters")
    return value.lower()


def _positive_limit(value: object, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


@dataclass(frozen=True, slots=True)
class ArtifactBinding:
    """Server-authenticated identity for one declared staged input field."""

    principal_id: str
    action: str
    idempotency_key: str
    adapter_invocation_digest: str
    field: str

    def __post_init__(self) -> None:
        require_identifier(self.principal_id, "artifact principal_id")
        require_identifier(self.action, "artifact action", max_length=255)
        require_identifier(self.idempotency_key, "artifact idempotency_key", max_length=255)
        require_digest(self.adapter_invocation_digest, "artifact adapter_invocation_digest")
        require_model_field(self.field, "artifact field")

    def payload(self) -> dict[str, JsonValue]:
        return cast(
            dict[str, JsonValue],
            {
                "action": self.action,
                "adapter_invocation_digest": self.adapter_invocation_digest,
                "field": self.field,
                "idempotency_key": self.idempotency_key,
                "principal_id": self.principal_id,
            },
        )

    @property
    def digest(self) -> str:
        return hashlib.sha256(canonical_json(self.payload()).encode("utf-8")).hexdigest()

    @property
    def logical_digest(self) -> str:
        """Stable replay identity, excluding the content-bearing invocation bytes.

        A content change necessarily changes the canonical invocation digest.
        The source idempotency domain must nevertheless reject it rather than
        silently creating a second staged payload for one logical operation.
        """

        stable_payload: dict[str, JsonValue] = {
            "action": self.action,
            "field": self.field,
            "idempotency_key": self.idempotency_key,
            "principal_id": self.principal_id,
        }
        return hashlib.sha256(canonical_json(stable_payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ArtifactInspection:
    """Deterministic metadata computed from bytes, never trusted from a host."""

    content_digest: str
    content_bytes: int
    media_type: str
    classification: str
    inspector_version: str = REFERENCE_INSPECTOR_VERSION

    def __post_init__(self) -> None:
        require_digest(self.content_digest, "artifact content_digest")
        if type(self.content_bytes) is not int or self.content_bytes < 0:
            raise ValueError("artifact content_bytes must be non-negative")
        _media_type(self.media_type)
        require_identifier(
            self.classification,
            "artifact classification",
            max_length=MAX_ARTIFACT_CLASSIFICATION_LENGTH,
        )
        require_identifier(
            self.inspector_version,
            "artifact inspector_version",
            max_length=MAX_ARTIFACT_CLASSIFICATION_LENGTH,
        )


@dataclass(frozen=True, slots=True)
class ArtifactMetadata:
    """Non-secret server-owned handle returned to a trusted operation runtime."""

    artifact_id: str
    binding_digest: str
    content_digest: str
    content_bytes: int
    media_type: str
    classification: str
    expires_at: datetime
    inspector_version: str = REFERENCE_INSPECTOR_VERSION

    def __post_init__(self) -> None:
        require_identifier(self.artifact_id, "artifact id")
        require_digest(self.binding_digest, "artifact binding_digest")
        require_digest(self.content_digest, "artifact content_digest")
        if type(self.content_bytes) is not int or self.content_bytes < 0:
            raise ValueError("artifact content_bytes must be non-negative")
        _media_type(self.media_type)
        require_identifier(
            self.classification,
            "artifact classification",
            max_length=MAX_ARTIFACT_CLASSIFICATION_LENGTH,
        )
        _utc(self.expires_at, "artifact expires_at")
        require_identifier(
            self.inspector_version,
            "artifact inspector_version",
            max_length=MAX_ARTIFACT_CLASSIFICATION_LENGTH,
        )

    def payload(self) -> dict[str, str | int]:
        """Return the only artifact shape that may cross a trusted API boundary."""

        return {
            "classification": self.classification,
            "content_bytes": self.content_bytes,
            "content_digest": self.content_digest,
            "media_type": self.media_type,
            "reference": self.artifact_id,
            "expires_at": self.expires_at.isoformat(),
        }


class ArtifactInspector(Protocol):
    """Trusted byte inspector used before data becomes connector-visible."""

    def inspect(self, content: bytes, *, declared_media_type: str) -> ArtifactInspection: ...


class ArtifactReader(Protocol):
    """Read-only, verified content access for a connector invocation."""

    @property
    def metadata(self) -> ArtifactMetadata: ...

    async def read(self, *, maximum_bytes: int | None = None) -> bytes: ...


class ArtifactStore(Protocol):
    """Durable sealed-payload storage; no method returns a filesystem path."""

    async def initialize(self) -> None: ...

    async def stage(
        self,
        binding: ArtifactBinding,
        content: bytes,
        *,
        declared_media_type: str,
        now: datetime,
        ttl: timedelta = DEFAULT_ARTIFACT_TTL,
    ) -> ArtifactMetadata: ...

    async def lookup(
        self,
        binding: ArtifactBinding,
        *,
        now: datetime,
        allow_expired: bool = False,
    ) -> ArtifactMetadata: ...

    async def open(
        self,
        reference: str,
        *,
        binding: ArtifactBinding,
        now: datetime,
        expected_metadata: ArtifactMetadata | None = None,
    ) -> ArtifactReader: ...

    async def discard(self, binding: ArtifactBinding) -> bool: ...

    async def expire(self, *, now: datetime) -> int: ...


class ReferenceArtifactInspector:
    """Small deterministic inspector for the reference substrate.

    Operation-specific classifiers belong to the later pack/connector steps.
    This inspector establishes the important generic facts: exact digest,
    length, normalized media type, and a deterministic non-caller-controlled
    classification label.
    """

    def inspect(self, content: bytes, *, declared_media_type: str) -> ArtifactInspection:
        if not isinstance(content, bytes):
            raise TypeError("artifact content must be bytes")
        media_type = _media_type(declared_media_type)
        if (
            media_type in _UNSUPPORTED_COMPRESSED_MEDIA_TYPES
            or media_type.endswith("+gzip")
            or media_type.endswith("+zip")
        ):
            # The substrate does not decompress opaque uploads.  This keeps
            # quota and reader bounds meaningful and gives operation packs an
            # explicit, reviewable place to add a bounded decompressor later.
            raise ArtifactError("compressed artifacts are unsupported by the reference inspector")
        classification = "reference-binary"
        if media_type == "application/json":
            try:
                json.loads(content.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ArtifactError("application/json artifact is not valid UTF-8 JSON") from exc
            classification = "reference-json"
        elif media_type.startswith("text/"):
            try:
                content.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ArtifactError("text artifact is not valid UTF-8") from exc
            classification = "reference-text"
        return ArtifactInspection(
            content_digest=hashlib.sha256(content).hexdigest(),
            content_bytes=len(content),
            media_type=media_type,
            classification=classification,
            inspector_version=REFERENCE_INSPECTOR_VERSION,
        )


class _SqliteArtifactReader:
    def __init__(
        self,
        store: SqliteArtifactStore,
        metadata: ArtifactMetadata,
        binding_digest: str,
        expected_metadata: ArtifactMetadata | None,
    ) -> None:
        self._store = store
        self._metadata = metadata
        self._binding_digest = binding_digest
        self._expected_metadata = expected_metadata

    @property
    def metadata(self) -> ArtifactMetadata:
        return self._metadata

    async def read(self, *, maximum_bytes: int | None = None) -> bytes:
        return self._store._read_verified(
            self._metadata.artifact_id,
            binding_digest=self._binding_digest,
            expected_metadata=self._expected_metadata,
            now=self._store.clock(),
            maximum_bytes=maximum_bytes,
        )


class SqliteArtifactStore:
    """Bounded durable reference store with verified reads and TTL cleanup."""

    def __init__(
        self,
        path: str,
        *,
        inspector: ArtifactInspector | None = None,
        maximum_artifact_bytes: int = MAX_ARTIFACT_BYTES,
        maximum_total_bytes: int = DEFAULT_ARTIFACT_TOTAL_BYTES,
        maximum_artifact_records: int = MAX_ARTIFACT_RECORDS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.path = path
        self.inspector = inspector or ReferenceArtifactInspector()
        self.maximum_artifact_bytes = _positive_limit(
            maximum_artifact_bytes, "maximum artifact bytes"
        )
        self.maximum_total_bytes = _positive_limit(
            maximum_total_bytes, "maximum total artifact bytes"
        )
        self.maximum_artifact_records = _positive_limit(
            maximum_artifact_records, "maximum artifact records"
        )
        if self.maximum_artifact_bytes > MAX_ARTIFACT_BYTES:
            raise ValueError("maximum artifact bytes cannot exceed the protocol bound")
        if self.maximum_total_bytes > DEFAULT_ARTIFACT_TOTAL_BYTES:
            raise ValueError("maximum total artifact bytes cannot exceed the reference bound")
        if self.maximum_artifact_records > MAX_ARTIFACT_RECORDS:
            raise ValueError("maximum artifact records cannot exceed the reference bound")
        self.clock = clock or (lambda: datetime.now(UTC))

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    async def initialize(self) -> None:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS operation_artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    binding_digest TEXT NOT NULL UNIQUE,
                    logical_binding_digest TEXT NOT NULL UNIQUE,
                    content_digest TEXT NOT NULL,
                    content_bytes INTEGER NOT NULL,
                    media_type TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    inspector_version TEXT NOT NULL DEFAULT 'reference-inspector.v1',
                    content BLOB NOT NULL,
                    expires_at TEXT NOT NULL,
                    CHECK(content_bytes >= 0)
                );
                CREATE INDEX IF NOT EXISTS operation_artifacts_expiry
                    ON operation_artifacts(expires_at);
                CREATE TABLE IF NOT EXISTS expired_operation_artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    binding_digest TEXT NOT NULL UNIQUE,
                    logical_binding_digest TEXT NOT NULL UNIQUE,
                    content_digest TEXT NOT NULL,
                    content_bytes INTEGER NOT NULL,
                    media_type TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    inspector_version TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    CHECK(content_bytes >= 0)
                );
                """
            )
            columns = {
                cast(str, row["name"])
                for row in connection.execute("PRAGMA table_info(operation_artifacts)").fetchall()
            }
            if "logical_binding_digest" not in columns:
                # connector worker is the first writer, but retaining this small
                # migration makes a crashed pre-release process fail closed
                # rather than lose its already sealed replay records.
                connection.execute(
                    "ALTER TABLE operation_artifacts ADD COLUMN logical_binding_digest TEXT"
                )
                connection.execute(
                    "UPDATE operation_artifacts SET logical_binding_digest = binding_digest"
                )
            if "inspector_version" not in columns:
                connection.execute(
                    "ALTER TABLE operation_artifacts ADD COLUMN inspector_version TEXT"
                )
                connection.execute(
                    "UPDATE operation_artifacts SET inspector_version = ? "
                    "WHERE inspector_version IS NULL",
                    (REFERENCE_INSPECTOR_VERSION,),
                )
            # Legacy pre-release rows may have recorded equivalent instants
            # with non-UTC offsets.  Normalize once before text comparisons.
            for row in connection.execute(
                "SELECT artifact_id, expires_at FROM operation_artifacts"
            ).fetchall():
                normalized = _utc(
                    datetime.fromisoformat(str(row["expires_at"])), "artifact expires_at"
                ).isoformat()
                if normalized != row["expires_at"]:
                    connection.execute(
                        "UPDATE operation_artifacts SET expires_at = ? WHERE artifact_id = ?",
                        (normalized, row["artifact_id"]),
                    )
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS operation_artifacts_logical_binding "
                "ON operation_artifacts(logical_binding_digest)"
            )
            connection.commit()
        finally:
            connection.close()

    @staticmethod
    def _metadata(row: sqlite3.Row) -> ArtifactMetadata:
        expires_at = _utc(datetime.fromisoformat(str(row["expires_at"])), "artifact expires_at")
        return ArtifactMetadata(
            artifact_id=str(row["artifact_id"]),
            binding_digest=str(row["binding_digest"]),
            content_digest=str(row["content_digest"]),
            content_bytes=int(row["content_bytes"]),
            media_type=str(row["media_type"]),
            classification=str(row["classification"]),
            expires_at=expires_at,
            inspector_version=str(row["inspector_version"]),
        )

    def _delete_expired(self, connection: sqlite3.Connection, now: datetime) -> int:
        """Retain a bounded metadata-only replay window.

        Payload bytes are deleted at their TTL.  Keeping a small metadata
        window lets an adapter repeat its staging call before an exact durable
        action replay, but it must never turn a finite staging store into a
        lifetime write quota.  The oldest replay metadata is therefore evicted
        once the configured active-record bound is exceeded.
        """

        connection.execute(
            """
            INSERT OR IGNORE INTO expired_operation_artifacts(
                artifact_id, binding_digest, logical_binding_digest, content_digest,
                content_bytes, media_type, classification, inspector_version, expires_at
            )
            SELECT artifact_id, binding_digest, logical_binding_digest, content_digest,
                content_bytes, media_type, classification, inspector_version, expires_at
            FROM operation_artifacts WHERE expires_at <= ?
            """,
            (now.isoformat(),),
        )
        cursor = connection.execute(
            "DELETE FROM operation_artifacts WHERE expires_at <= ?", (now.isoformat(),)
        )
        retained = connection.execute(
            "SELECT COUNT(*) AS total FROM expired_operation_artifacts"
        ).fetchone()
        assert retained is not None
        excess = int(retained["total"]) - self.maximum_artifact_records
        if excess > 0:
            connection.execute(
                """
                DELETE FROM expired_operation_artifacts
                WHERE artifact_id IN (
                    SELECT artifact_id FROM expired_operation_artifacts
                    ORDER BY expires_at, artifact_id
                    LIMIT ?
                )
                """,
                (excess,),
            )
        return cursor.rowcount

    @staticmethod
    def _reference(
        binding_digest: str,
        *,
        content_digest: str,
        content_bytes: int,
        media_type: str,
        classification: str,
        expires_at: datetime,
        inspector_version: str,
    ) -> str:
        """Derive an opaque handle from every certified artifact fact.

        The SQLite row is a durable availability cache, not a trust root.  A
        pre-handoff mutation of any certified metadata must therefore change
        the recomputed handle and fail closed during lookup/admission.
        """

        certified: dict[str, str | int] = {
            "binding_digest": binding_digest,
            "classification": classification,
            "content_bytes": content_bytes,
            "content_digest": content_digest,
            "expires_at": _utc(expires_at, "artifact expires_at").isoformat(),
            "inspector_version": inspector_version,
            "media_type": media_type,
        }
        return (
            "art:"
            + hashlib.sha256(canonical_json(cast(JsonValue, certified)).encode("utf-8")).hexdigest()
        )

    async def stage(
        self,
        binding: ArtifactBinding,
        content: bytes,
        *,
        declared_media_type: str,
        now: datetime,
        ttl: timedelta = DEFAULT_ARTIFACT_TTL,
    ) -> ArtifactMetadata:
        if type(binding) is not ArtifactBinding:
            raise TypeError("artifact staging needs an ArtifactBinding")
        now = _utc(now, "artifact staging now")
        if not isinstance(content, bytes):
            raise TypeError("artifact content must be bytes")
        if len(content) > self.maximum_artifact_bytes:
            raise ArtifactError("artifact exceeds configured payload limit")
        if type(ttl) is not timedelta or ttl <= timedelta(0):
            raise ValueError("artifact ttl must be positive")
        inspection = self.inspector.inspect(content, declared_media_type=declared_media_type)
        if (
            inspection.content_bytes != len(content)
            or inspection.content_digest != hashlib.sha256(content).hexdigest()
        ):
            raise ArtifactError("artifact inspector did not certify supplied bytes")
        expires_at = _utc(now + ttl, "artifact expiry")
        artifact_id = self._reference(
            binding.digest,
            content_digest=inspection.content_digest,
            content_bytes=inspection.content_bytes,
            media_type=inspection.media_type,
            classification=inspection.classification,
            expires_at=expires_at,
            inspector_version=inspection.inspector_version,
        )
        with self._transaction() as connection:
            self._delete_expired(connection, now)
            existing = connection.execute(
                "SELECT * FROM operation_artifacts WHERE logical_binding_digest = ?",
                (binding.logical_digest,),
            ).fetchone()
            if existing is not None:
                metadata = self._metadata(existing)
                if (
                    metadata.binding_digest != binding.digest
                    or metadata.content_digest != inspection.content_digest
                    or metadata.content_bytes != inspection.content_bytes
                    or metadata.media_type != inspection.media_type
                    or metadata.classification != inspection.classification
                    or metadata.inspector_version != inspection.inspector_version
                ):
                    raise ArtifactConflict(
                        "artifact staging identity was reused with different content or invocation"
                    )
                return metadata
            expired = connection.execute(
                "SELECT * FROM expired_operation_artifacts WHERE logical_binding_digest = ?",
                (binding.logical_digest,),
            ).fetchone()
            if expired is not None:
                metadata = self._metadata(expired)
                if (
                    metadata.binding_digest != binding.digest
                    or metadata.content_digest != inspection.content_digest
                    or metadata.content_bytes != inspection.content_bytes
                    or metadata.media_type != inspection.media_type
                    or metadata.classification != inspection.classification
                    or metadata.inspector_version != inspection.inspector_version
                ):
                    raise ArtifactConflict(
                        "artifact staging identity was reused with different content or invocation"
                    )
                # An expired reference remains only as replay metadata.  Never
                # create a new reference with a different retention bound for
                # the same logical operation.  A generated adapter stages on
                # every retry, so returning this metadata is what lets the
                # action boundary prove an exact durable replay without
                # restoring expired bytes.
                return metadata
            records = connection.execute(
                "SELECT COUNT(*) AS total FROM operation_artifacts"
            ).fetchone()
            assert records is not None
            if int(records["total"]) >= self.maximum_artifact_records:
                raise ArtifactError("artifact store record quota is exhausted")
            total = connection.execute(
                "SELECT COALESCE(SUM(content_bytes), 0) AS total FROM operation_artifacts"
            ).fetchone()
            assert total is not None
            if int(total["total"]) + inspection.content_bytes > self.maximum_total_bytes:
                raise ArtifactError("artifact store quota is exhausted")
            connection.execute(
                """
                INSERT INTO operation_artifacts(
                    artifact_id, binding_digest, logical_binding_digest, content_digest,
                    content_bytes, media_type, classification, inspector_version,
                    content, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact_id,
                    binding.digest,
                    binding.logical_digest,
                    inspection.content_digest,
                    inspection.content_bytes,
                    inspection.media_type,
                    inspection.classification,
                    inspection.inspector_version,
                    content,
                    expires_at.isoformat(),
                ),
            )
        return ArtifactMetadata(
            artifact_id=artifact_id,
            binding_digest=binding.digest,
            content_digest=inspection.content_digest,
            content_bytes=inspection.content_bytes,
            media_type=inspection.media_type,
            classification=inspection.classification,
            expires_at=expires_at,
            inspector_version=inspection.inspector_version,
        )

    async def open(
        self,
        reference: str,
        *,
        binding: ArtifactBinding,
        now: datetime,
        expected_metadata: ArtifactMetadata | None = None,
    ) -> ArtifactReader:
        if type(binding) is not ArtifactBinding:
            raise TypeError("artifact opening needs an ArtifactBinding")
        if expected_metadata is not None:
            if type(expected_metadata) is not ArtifactMetadata:
                raise TypeError("artifact expected metadata must be an ArtifactMetadata")
            if (
                expected_metadata.artifact_id != reference
                or expected_metadata.binding_digest != binding.digest
            ):
                raise ArtifactUnavailable("artifact does not match committed handoff metadata")
        now = _utc(now, "artifact opening now")
        require_identifier(reference, "artifact reference")
        with self._transaction() as connection:
            self._delete_expired(connection, now)
            row = connection.execute(
                "SELECT * FROM operation_artifacts WHERE artifact_id = ?", (reference,)
            ).fetchone()
            if row is None:
                raise ArtifactUnavailable("artifact is unavailable")
            metadata = self._metadata(row)
            if metadata.binding_digest != binding.digest:
                raise ArtifactUnavailable("artifact binding does not match the protected handoff")
            if metadata.artifact_id != self._reference(
                binding.digest,
                content_digest=metadata.content_digest,
                content_bytes=metadata.content_bytes,
                media_type=metadata.media_type,
                classification=metadata.classification,
                expires_at=metadata.expires_at,
                inspector_version=metadata.inspector_version,
            ):
                raise ArtifactUnavailable("artifact reference verification failed")
            if expected_metadata is not None and metadata != expected_metadata:
                raise ArtifactUnavailable("artifact metadata does not match committed handoff")
        return _SqliteArtifactReader(self, metadata, binding.digest, expected_metadata)

    async def lookup(
        self,
        binding: ArtifactBinding,
        *,
        now: datetime,
        allow_expired: bool = False,
    ) -> ArtifactMetadata:
        """Find a payload from trusted binding facts only.

        This is deliberately separate from ``open``: providers can construct
        a committed handoff without accepting a caller-provided artifact
        reference.  Only the worker later receives the opaque reference and
        a verified reader.  Expired metadata is available only to the action
        boundary for an exact durable replay; it never re-enables content
        reads or a fresh connector execution.
        """

        if type(binding) is not ArtifactBinding:
            raise TypeError("artifact lookup needs an ArtifactBinding")
        if type(allow_expired) is not bool:
            raise TypeError("artifact allow_expired must be a bool")
        now = _utc(now, "artifact lookup now")
        with self._transaction() as connection:
            self._delete_expired(connection, now)
            row = connection.execute(
                "SELECT * FROM operation_artifacts WHERE binding_digest = ?",
                (binding.digest,),
            ).fetchone()
            if row is None and allow_expired:
                row = connection.execute(
                    "SELECT * FROM expired_operation_artifacts WHERE binding_digest = ?",
                    (binding.digest,),
                ).fetchone()
            if row is None:
                raise ArtifactUnavailable("artifact is unavailable")
            metadata = self._metadata(row)
            if metadata.binding_digest != binding.digest:
                raise ArtifactUnavailable("artifact binding does not match the protected handoff")
            if metadata.artifact_id != self._reference(
                binding.digest,
                content_digest=metadata.content_digest,
                content_bytes=metadata.content_bytes,
                media_type=metadata.media_type,
                classification=metadata.classification,
                expires_at=metadata.expires_at,
                inspector_version=metadata.inspector_version,
            ):
                raise ArtifactUnavailable("artifact reference verification failed")
            return metadata

    def _read_verified(
        self,
        reference: str,
        *,
        binding_digest: str,
        expected_metadata: ArtifactMetadata | None,
        now: datetime,
        maximum_bytes: int | None,
    ) -> bytes:
        if maximum_bytes is not None:
            _positive_limit(maximum_bytes, "artifact reader maximum bytes")
        now = _utc(now, "artifact reader now")
        with self._transaction() as connection:
            self._delete_expired(connection, now)
            row = connection.execute(
                "SELECT * FROM operation_artifacts WHERE artifact_id = ?", (reference,)
            ).fetchone()
            if row is None:
                raise ArtifactUnavailable("artifact is unavailable")
            metadata = self._metadata(row)
            if metadata.binding_digest != binding_digest:
                raise ArtifactUnavailable("artifact binding does not match the protected handoff")
            if metadata.artifact_id != self._reference(
                binding_digest,
                content_digest=metadata.content_digest,
                content_bytes=metadata.content_bytes,
                media_type=metadata.media_type,
                classification=metadata.classification,
                expires_at=metadata.expires_at,
                inspector_version=metadata.inspector_version,
            ):
                raise ArtifactUnavailable("artifact reference verification failed")
            if expected_metadata is not None and metadata != expected_metadata:
                raise ArtifactUnavailable("artifact metadata does not match committed handoff")
            if maximum_bytes is not None and metadata.content_bytes > maximum_bytes:
                raise ArtifactError("artifact exceeds connector reader limit")
            raw = row["content"]
            if not isinstance(raw, bytes):
                raise ArtifactUnavailable("artifact content is malformed")
            if (
                len(raw) != metadata.content_bytes
                or hashlib.sha256(raw).hexdigest() != metadata.content_digest
            ):
                raise ArtifactUnavailable("artifact content verification failed")
            return raw

    async def discard(self, binding: ArtifactBinding) -> bool:
        if type(binding) is not ArtifactBinding:
            raise TypeError("artifact discard needs an ArtifactBinding")
        with self._transaction() as connection:
            cursor = connection.execute(
                "DELETE FROM operation_artifacts WHERE binding_digest = ?", (binding.digest,)
            )
            expired = connection.execute(
                "DELETE FROM expired_operation_artifacts WHERE binding_digest = ?",
                (binding.digest,),
            )
            return cursor.rowcount + expired.rowcount == 1

    async def expire(self, *, now: datetime) -> int:
        now = _utc(now, "artifact expiry now")
        with self._transaction() as connection:
            return self._delete_expired(connection, now)


__all__ = [
    "DEFAULT_ARTIFACT_TOTAL_BYTES",
    "DEFAULT_ARTIFACT_TTL",
    "MAX_ARTIFACT_BYTES",
    "MAX_ARTIFACT_CLASSIFICATION_LENGTH",
    "MAX_ARTIFACT_RECORDS",
    "REFERENCE_INSPECTOR_VERSION",
    "ArtifactBinding",
    "ArtifactConflict",
    "ArtifactError",
    "ArtifactInspection",
    "ArtifactInspector",
    "ArtifactMetadata",
    "ArtifactReader",
    "ArtifactStore",
    "ArtifactUnavailable",
    "ReferenceArtifactInspector",
    "SqliteArtifactStore",
]
