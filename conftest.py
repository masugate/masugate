"""Shared pytest fixtures — backend parameterization for MasuGate tests.

The ``backend`` fixture yields a provisioned, isolated async DB over each
available backend (SQLite always; Postgres when a container or explicit test
DSN is reachable). Tests written against it run on every backend automatically — this
is the surface the conformance kit (2.4) reuses.

``@pytest.mark.postgres`` marks a test as requiring the Postgres backend. When
neither Docker nor ``MASUGATE_TEST_POSTGRES_DSN`` is available, an unprovisioned
laptop skips those tests while CI fails closed instead of silently going green.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import AsyncIterator, Iterator
from typing import TYPE_CHECKING

import pytest

from masugate.testing import Backend, PostgresBackend, SqliteBackend, available_backends

if TYPE_CHECKING:
    from masugate.resources.postgres import AsyncPostgresLedger

_BACKENDS = available_backends()
_FALSE_ENV_VALUES = frozenset({"", "0", "false", "no", "off"})


def _running_in_ci() -> bool:
    value = os.environ.get("CI")
    return value is not None and value.strip().lower() not in _FALSE_ENV_VALUES


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Require Postgres in CI; skip marked tests on unprovisioned local hosts."""
    if not item.get_closest_marker("postgres") or PostgresBackend.available():
        return

    message = "Postgres backend unavailable (no external DSN or container runtime)"
    if _running_in_ci():
        pytest.fail(f"{message}; @pytest.mark.postgres tests are required in CI")
    pytest.skip(message)


@pytest.fixture
async def pg_ledger() -> AsyncIterator[AsyncPostgresLedger]:
    """An AsyncPostgresLedger bound to a fresh throwaway schema on the shared PG.

    Shared by the 0.11 provider suite and the 0.12+ coordinator suites. The
    provider's pool is pointed at an isolated schema via a ``search_path``
    option on the DSN; the schema is dropped on teardown.
    """
    import psycopg

    from masugate.resources.postgres import AsyncPostgresLedger

    container = PostgresBackend._ensure_container()
    base_dsn = container.get_connection_url()
    schema = f"masugate_prov_{secrets.token_hex(6)}"
    async with await psycopg.AsyncConnection.connect(base_dsn, autocommit=True) as admin:
        await admin.execute(f'CREATE SCHEMA "{schema}"')
    sep = "&" if "?" in base_dsn else "?"
    scoped_dsn = f"{base_dsn}{sep}options=-csearch_path%3D{schema}"

    led = AsyncPostgresLedger(scoped_dsn, min_size=1, max_size=8)
    await led.open(initialize=True)
    try:
        yield led
    finally:
        await led.close()
        async with await psycopg.AsyncConnection.connect(base_dsn, autocommit=True) as admin:
            await admin.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


@pytest.fixture
def reference_postgres_dsn() -> Iterator[str]:
    """A clean schema for reference-deployment initialization tests.

    Unlike ``pg_ledger``, this fixture deliberately installs no platform
    tables. Reference resources must record their release marker before they
    initialize any provider or protected-execution schema.
    """
    import psycopg

    container = PostgresBackend._ensure_container()
    base_dsn = container.get_connection_url()
    schema = f"masugate_release_{secrets.token_hex(6)}"
    with psycopg.connect(base_dsn, autocommit=True) as admin:
        admin.execute(f'CREATE SCHEMA "{schema}"')
    separator = "&" if "?" in base_dsn else "?"
    scoped_dsn = f"{base_dsn}{separator}options=-csearch_path%3D{schema}"
    try:
        yield scoped_dsn
    finally:
        with psycopg.connect(base_dsn, autocommit=True) as admin:
            admin.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')


@pytest.fixture(params=_BACKENDS)
async def backend(request: pytest.FixtureRequest) -> AsyncIterator[Backend]:
    """Parameterized over every available backend; yields an isolated DB."""
    name = request.param
    impl: Backend
    if name == "sqlite":
        async with SqliteBackend() as impl:
            yield impl
    elif name == "postgres":
        async with PostgresBackend() as impl:
            yield impl
    else:  # pragma: no cover - defensive
        raise ValueError(f"unknown backend: {name}")
