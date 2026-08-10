"""Async, isolated test backends over PostgreSQL and SQLite.

A ``Backend`` provisions an isolated, empty database and hands out async
connections to it, then tears it down. Isolation is per acquired backend:
Postgres uses a throwaway schema on a shared container; SQLite uses a
throwaway file. Both expose the same minimal async connection surface
(``execute`` / ``fetchone`` / ``fetchall`` / ``commit``) so tests and the
conformance kit (2.4) can be written once and run against either.

Postgres normally uses a container runtime. ``MASUGATE_TEST_POSTGRES_DSN`` may point
at an explicitly managed test service instead (useful in restricted local
environments). With neither, ``PostgresBackend.available()`` returns False and
PG-marked tests skip; the SQLite path always works.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Protocol, runtime_checkable

Row = tuple[Any, ...]


@runtime_checkable
class BackendConn(Protocol):
    """Minimal async DB connection surface shared by both backends."""

    async def execute(self, sql: str, params: Sequence[Any] = ()) -> None: ...

    async def fetchone(self, sql: str, params: Sequence[Any] = ()) -> Row | None: ...

    async def fetchall(self, sql: str, params: Sequence[Any] = ()) -> list[Row]: ...

    async def commit(self) -> None: ...


@runtime_checkable
class Backend(Protocol):
    """A provisioned, isolated database that yields async connections.

    Use as an async context manager (``async with backend.connect() as conn``)
    to get a connection scoped to this backend's isolated database.
    """

    name: str

    def connect(self) -> Any:  # returns an async context manager yielding BackendConn
        ...


# --------------------------------------------------------------------------- #
# SQLite backend (fast local dev/test path)
# --------------------------------------------------------------------------- #


class _SqliteConn:
    def __init__(self, raw: Any) -> None:
        self._raw = raw

    async def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        await self._raw.execute(sql, tuple(params))

    async def fetchone(self, sql: str, params: Sequence[Any] = ()) -> Row | None:
        cur = await self._raw.execute(sql, tuple(params))
        row = await cur.fetchone()
        return tuple(row) if row is not None else None

    async def fetchall(self, sql: str, params: Sequence[Any] = ()) -> list[Row]:
        cur = await self._raw.execute(sql, tuple(params))
        return [tuple(r) for r in await cur.fetchall()]

    async def commit(self) -> None:
        await self._raw.commit()


class SqliteBackend:
    """Isolated SQLite database in a throwaway temp file.

    Async via ``aiosqlite``. A fresh file per backend instance gives full
    isolation between tests without any shared-state teardown.
    """

    name = "sqlite"

    def __init__(self) -> None:
        self._tmp: TemporaryDirectory[str] | None = None
        self._path: Path | None = None

    @staticmethod
    def available() -> bool:
        try:
            import aiosqlite  # noqa: F401
        except ImportError:
            return False
        return True

    async def __aenter__(self) -> SqliteBackend:
        self._tmp = TemporaryDirectory(prefix="masugate-sqlite-")
        self._path = Path(self._tmp.name) / "test.sqlite3"
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp = None
            self._path = None

    @asynccontextmanager
    async def connect(self) -> AsyncIterator[BackendConn]:
        import aiosqlite

        if self._path is None:
            raise RuntimeError("SqliteBackend must be entered before connect()")
        raw = await aiosqlite.connect(self._path)
        try:
            await raw.execute("PRAGMA foreign_keys=ON")
            yield _SqliteConn(raw)
        finally:
            await raw.close()


# --------------------------------------------------------------------------- #
# Postgres backend (shipping backend; needs a container runtime)
# --------------------------------------------------------------------------- #


class _PostgresConn:
    def __init__(self, raw: Any) -> None:
        self._raw = raw

    async def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        await self._raw.execute(sql, tuple(params))

    async def fetchone(self, sql: str, params: Sequence[Any] = ()) -> Row | None:
        cur = await self._raw.execute(sql, tuple(params))
        row = await cur.fetchone()
        return tuple(row) if row is not None else None

    async def fetchall(self, sql: str, params: Sequence[Any] = ()) -> list[Row]:
        cur = await self._raw.execute(sql, tuple(params))
        return [tuple(r) for r in await cur.fetchall()]

    async def commit(self) -> None:
        await self._raw.commit()


class _ExternalPostgres:
    """Testcontainers-compatible handle for an explicitly supplied test DSN."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn

    def get_connection_url(self) -> str:
        return self._dsn

    def stop(self) -> None:
        # The caller owns an external service's lifecycle.
        return


class PostgresBackend:
    """Isolated Postgres via a per-instance throwaway schema.

    Shares one testcontainers Postgres per process (or the service selected by
    ``MASUGATE_TEST_POSTGRES_DSN``); each backend instance gets its own schema set
    as the ``search_path``, so tests never see each other's tables.
    """

    name = "postgres"
    _container: Any = None  # class-level: one container per process

    def __init__(self) -> None:
        self._schema: str | None = None
        self._dsn: str | None = None

    @staticmethod
    def available() -> bool:
        """True when an external DSN or a reachable container runtime exists."""
        if os.environ.get("MASUGATE_TEST_POSTGRES_DSN"):
            return True
        try:
            import docker  # testcontainers pulls this in
            from testcontainers.postgres import PostgresContainer  # noqa: F401
        except ImportError:
            return False
        try:
            docker.from_env().ping()
        except Exception:
            return False
        return True

    @classmethod
    def _ensure_container(cls) -> Any:
        if cls._container is None:
            external_dsn = os.environ.get("MASUGATE_TEST_POSTGRES_DSN")
            if external_dsn:
                cls._container = _ExternalPostgres(external_dsn)
                return cls._container
            # Colima (and other socket-forwarding runtimes) can't bind-mount the
            # Docker socket that testcontainers' Ryuk reaper wants, which fails
            # container start with an obscure 500. We do explicit teardown in
            # __aexit__, so the reaper is unnecessary — disable it if the caller
            # hasn't already chosen a setting.
            os.environ.setdefault("TESTCONTAINERS_RYUK_DISABLED", "true")

            import atexit

            from testcontainers.postgres import PostgresContainer

            container = PostgresContainer("postgres:16-alpine", driver=None)
            container.start()
            cls._container = container
            # With Ryuk disabled we own cleanup: stop the shared container at
            # process exit so runs don't leak containers across invocations.
            atexit.register(cls._stop_container)
        return cls._container

    @classmethod
    def _stop_container(cls) -> None:
        if cls._container is not None:
            try:
                cls._container.stop()
            finally:
                cls._container = None

    async def __aenter__(self) -> PostgresBackend:
        container = self._ensure_container()
        self._dsn = container.get_connection_url()  # postgresql://... (psycopg3 driver=None)
        self._schema = f"masugate_test_{secrets.token_hex(6)}"
        async with self._raw_connect() as raw:
            await raw.execute(f'CREATE SCHEMA "{self._schema}"')
            await raw.commit()
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._schema is not None:
            async with self._raw_connect() as raw:
                await raw.execute(f'DROP SCHEMA IF EXISTS "{self._schema}" CASCADE')
                await raw.commit()
            self._schema = None

    @asynccontextmanager
    async def _raw_connect(self) -> AsyncIterator[Any]:
        import psycopg

        if self._dsn is None:
            raise RuntimeError("PostgresBackend must be entered before connecting")
        conn = await psycopg.AsyncConnection.connect(self._dsn, autocommit=False)
        try:
            yield conn
        finally:
            await conn.close()

    @asynccontextmanager
    async def connect(self) -> AsyncIterator[BackendConn]:
        if self._schema is None:
            raise RuntimeError("PostgresBackend must be entered before connect()")
        async with self._raw_connect() as raw:
            await raw.execute(f'SET search_path TO "{self._schema}"')
            yield _PostgresConn(raw)


# --------------------------------------------------------------------------- #
# Selection
# --------------------------------------------------------------------------- #


def available_backends() -> list[str]:
    """Names of test backends selected for this invocation.

    ``MASUGATE_TEST_BACKENDS`` makes the otherwise shared parametrized test matrix
    explicit in CI: use ``sqlite`` and ``postgres`` in separate jobs, or the
    default ``all`` for the complete local matrix.  It selects among usable
    backends; it does not make an unavailable backend appear available.
    """

    selection = os.environ.get("MASUGATE_TEST_BACKENDS", "all").strip().lower()
    if selection not in {"all", "sqlite", "postgres"}:
        raise ValueError("MASUGATE_TEST_BACKENDS must be one of 'all', 'sqlite', or 'postgres'")

    names = []
    if selection in {"all", "sqlite"} and SqliteBackend.available():
        names.append("sqlite")
    if selection in {"all", "postgres"} and PostgresBackend.available():
        names.append("postgres")
    return names
