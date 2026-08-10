"""Release identity and clean-install schema boundary for the reference deployment.

This module belongs to ``masugate-openclaw-reference``, not the reusable platform:
the platform must not own an OpenClaw release pin or deployment lifecycle.
The reference release preview supports a fresh install only. A database created by an
earlier development build has no trustworthy schema identity, so it is refused
before any provider DDL can alter it.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any, cast

import psycopg
from psycopg.rows import dict_row

REFERENCE_RELEASE_VERSION = "0.1.0"
REFERENCE_RELEASE_ID = f"masugate-openclaw-reference/{REFERENCE_RELEASE_VERSION}"
REFERENCE_SCHEMA_ID = "masugate-openclaw-reference"
REFERENCE_SCHEMA_VERSION = 1
_METADATA_TABLE = "masugate_release_metadata"
_REQUIRED_SPEND_ENTITLEMENT_COLUMNS = frozenset({"adapter_invocation_digest"})


class ReferenceSchemaBoundaryError(RuntimeError):
    """Raised when a database is outside this preview's clean-install boundary."""


def _incompatible_schema_message(found: object) -> str:
    return (
        "reference database schema is incompatible with "
        f"{REFERENCE_RELEASE_ID}: expected {REFERENCE_SCHEMA_ID!r} version "
        f"{REFERENCE_SCHEMA_VERSION}, found {found!r}; this research preview "
        "supports clean installation only and will not migrate existing state"
    )


def _incompatible_spend_schema_message(missing: set[str]) -> str:
    return (
        "reference spend_entitlements schema is incompatible with "
        f"{REFERENCE_RELEASE_ID}: missing required columns {sorted(missing)!r}; "
        "this research preview supports clean installation only and will not "
        "migrate existing state"
    )


def _sqlite_metadata(connection: sqlite3.Connection) -> tuple[tuple[str, int, str], ...]:
    rows = connection.execute(
        f"SELECT schema_id, schema_version, release_id FROM {_METADATA_TABLE}"
    ).fetchall()
    return tuple((cast(str, row[0]), int(cast(int, row[1])), cast(str, row[2])) for row in rows)


def _sqlite_configuration_state(
    connection: sqlite3.Connection, *, require_pristine_schema: bool
) -> tuple[tuple[str, int], ...]:
    names = ["application_id", "user_version"]
    if require_pristine_schema:
        names.append("schema_version")
    configured: list[tuple[str, int]] = []
    for name in names:
        row = connection.execute(f"PRAGMA {name}").fetchone()
        value = 0 if row is None else int(cast(int, row[0]))
        if value != 0:
            configured.append((name, value))
    return tuple(configured)


def _validate_sqlite_spend_entitlement_shape(connection: sqlite3.Connection) -> None:
    table = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'spend_entitlements'"
    ).fetchone()
    if table is None:
        return
    columns = {
        cast(str, row[1])
        for row in connection.execute("PRAGMA table_info(spend_entitlements)").fetchall()
    }
    missing = set(_REQUIRED_SPEND_ENTITLEMENT_COLUMNS - columns)
    if missing:
        raise ReferenceSchemaBoundaryError(_incompatible_spend_schema_message(missing))


def _postgres_configuration_state(cursor: Any) -> tuple[tuple[str, object], ...]:
    cursor.execute(
        """
        SELECT namespace.nspname AS schema_name,
               owner.rolname AS owner_name,
               (
                   namespace.nspowner = execution_role.oid
                   OR (
                       owner.rolname = 'pg_database_owner'
                       AND database_entry.datdba = execution_role.oid
                   )
               ) AS trusted_owner,
               pg_catalog.has_schema_privilege(
                   current_user, namespace.oid, 'CREATE'
               ) AS can_create,
               COALESCE(
                   bool_or(
                       acl_entry.privilege_type = 'CREATE'
                       AND acl_entry.grantee <> namespace.nspowner
                   ),
                   FALSE
               ) AS foreign_create
        FROM pg_catalog.pg_namespace AS namespace
        JOIN pg_catalog.pg_roles AS owner
          ON owner.oid = namespace.nspowner
        JOIN pg_catalog.pg_roles AS execution_role
          ON execution_role.rolname = current_user
        JOIN pg_catalog.pg_database AS database_entry
          ON database_entry.datname = current_database()
        LEFT JOIN LATERAL pg_catalog.aclexplode(
            COALESCE(
                namespace.nspacl,
                pg_catalog.acldefault('n', namespace.nspowner)
            )
        ) AS acl_entry ON TRUE
        WHERE namespace.nspname = current_schema()
        GROUP BY namespace.oid, namespace.nspname, namespace.nspowner,
                 owner.rolname, execution_role.oid, database_entry.datdba
        """
    )
    access = cursor.fetchone()
    if access is None:
        return (("schema", "current_schema() does not resolve to an existing schema"),)
    issues: list[tuple[str, object]] = []
    if not bool(access["trusted_owner"]):
        issues.append(("owner", access["owner_name"]))
    if not bool(access["can_create"]):
        issues.append(("create_privilege", False))
    if bool(access["foreign_create"]):
        issues.append(("foreign_create_privilege", True))

    cursor.execute(
        """
        SELECT default_owner.rolname AS owner_name,
               COALESCE(namespace.nspname, '*') AS schema_name,
               default_acl.defaclobjtype AS object_type
        FROM pg_catalog.pg_default_acl AS default_acl
        JOIN pg_catalog.pg_roles AS default_owner
          ON default_owner.oid = default_acl.defaclrole
        LEFT JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = default_acl.defaclnamespace
        JOIN pg_catalog.pg_roles AS execution_role
          ON execution_role.rolname = current_user
        WHERE default_acl.defaclnamespace = (
                  SELECT oid
                  FROM pg_catalog.pg_namespace
                  WHERE nspname = current_schema()
              )
           OR (
                  default_acl.defaclnamespace = 0
                  AND default_acl.defaclrole = execution_role.oid
              )
        ORDER BY owner_name, schema_name, object_type
        """
    )
    defaults = tuple(
        (
            cast(str, row["owner_name"]),
            cast(str, row["schema_name"]),
            cast(str, row["object_type"]),
        )
        for row in cursor.fetchall()
    )
    if defaults:
        issues.append(("default_privileges", defaults))
    return tuple(issues)


def _validate_postgres_spend_entitlement_shape(cursor: Any) -> None:
    cursor.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = current_schema() AND table_name = 'spend_entitlements'
        """
    )
    columns = {cast(str, row["column_name"]) for row in cursor.fetchall()}
    if not columns:
        return
    missing = set(_REQUIRED_SPEND_ENTITLEMENT_COLUMNS - columns)
    if missing:
        raise ReferenceSchemaBoundaryError(_incompatible_spend_schema_message(missing))


def ensure_sqlite_reference_schema(path: Path) -> None:
    """Record or verify the reference schema before any provider DDL runs.

    The transaction obtains SQLite's writer lock first. Any pre-marker schema
    object is evidence of an older or foreign state and is never modified.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30.0)
    try:
        connection.execute("BEGIN IMMEDIATE")
        metadata_exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (_METADATA_TABLE,),
        ).fetchone()
        configuration = _sqlite_configuration_state(
            connection, require_pristine_schema=metadata_exists is None
        )
        if configuration:
            raise ReferenceSchemaBoundaryError(_incompatible_schema_message(configuration))
        if metadata_exists is None:
            existing = tuple(
                (cast(str, row[0]), cast(str, row[1]))
                for row in connection.execute(
                    "SELECT type, name FROM sqlite_master "
                    "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
                ).fetchall()
            )
            if existing:
                raise ReferenceSchemaBoundaryError(_incompatible_schema_message(existing))
            connection.execute(
                f"""
                CREATE TABLE {_METADATA_TABLE} (
                    schema_id TEXT PRIMARY KEY,
                    schema_version INTEGER NOT NULL,
                    release_id TEXT NOT NULL
                )
                """
            )
            connection.execute(
                f"INSERT INTO {_METADATA_TABLE}(schema_id, schema_version, release_id) "
                "VALUES (?, ?, ?)",
                (REFERENCE_SCHEMA_ID, REFERENCE_SCHEMA_VERSION, REFERENCE_RELEASE_ID),
            )
        else:
            metadata = _sqlite_metadata(connection)
            if metadata != (
                (
                    REFERENCE_SCHEMA_ID,
                    REFERENCE_SCHEMA_VERSION,
                    REFERENCE_RELEASE_ID,
                ),
            ):
                raise ReferenceSchemaBoundaryError(_incompatible_schema_message(metadata))
        _validate_sqlite_spend_entitlement_shape(connection)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def ensure_postgres_reference_schema(dsn: str) -> None:
    """Record or verify the PostgreSQL reference schema before provider DDL.

    The advisory lock makes concurrent clean startups observe one boundary.
    ``current_schema()`` honours the deployment/test search path, so the marker
    and all later provider tables stay in the same isolated schema.
    """

    with (
        psycopg.connect(dsn, autocommit=False, row_factory=dict_row) as connection,
        connection.cursor() as cursor,
    ):
        cursor.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
            ("masugate-openclaw-reference:schema-boundary",),
        )
        configuration = _postgres_configuration_state(cursor)
        if configuration:
            raise ReferenceSchemaBoundaryError(_incompatible_schema_message(configuration))
        cursor.execute(
            "SELECT EXISTS ("
            "SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = current_schema() AND table_name = %s"
            ") AS exists",
            (_METADATA_TABLE,),
        )
        row = cast(dict[str, Any], cursor.fetchone())
        if not bool(row["exists"]):
            cursor.execute(
                """
                SELECT object_type, object_name
                FROM (
                    SELECT 'relation:' || relation.relkind::text AS object_type,
                           relation.relname AS object_name
                    FROM pg_catalog.pg_class AS relation
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = relation.relnamespace
                    WHERE namespace.nspname = current_schema()
                      AND relation.relkind IN ('r', 'p', 'i', 'I', 'S', 'v', 'm', 'c', 'f')
                    UNION ALL
                    SELECT 'routine',
                           routine.proname || '(' ||
                           pg_catalog.pg_get_function_identity_arguments(routine.oid) || ')'
                    FROM pg_catalog.pg_proc AS routine
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = routine.pronamespace
                    WHERE namespace.nspname = current_schema()
                    UNION ALL
                    SELECT 'type', type_entry.typname
                    FROM pg_catalog.pg_type AS type_entry
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = type_entry.typnamespace
                    WHERE namespace.nspname = current_schema()
                    UNION ALL
                    SELECT 'collation', collation_entry.collname
                    FROM pg_catalog.pg_collation AS collation_entry
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = collation_entry.collnamespace
                    WHERE namespace.nspname = current_schema()
                    UNION ALL
                    SELECT 'conversion', conversion.conname
                    FROM pg_catalog.pg_conversion AS conversion
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = conversion.connamespace
                    WHERE namespace.nspname = current_schema()
                    UNION ALL
                    SELECT 'text-search-config', configuration.cfgname
                    FROM pg_catalog.pg_ts_config AS configuration
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = configuration.cfgnamespace
                    WHERE namespace.nspname = current_schema()
                    UNION ALL
                    SELECT 'text-search-dictionary', dictionary.dictname
                    FROM pg_catalog.pg_ts_dict AS dictionary
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = dictionary.dictnamespace
                    WHERE namespace.nspname = current_schema()
                    UNION ALL
                    SELECT 'text-search-parser', parser.prsname
                    FROM pg_catalog.pg_ts_parser AS parser
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = parser.prsnamespace
                    WHERE namespace.nspname = current_schema()
                    UNION ALL
                    SELECT 'text-search-template', template.tmplname
                    FROM pg_catalog.pg_ts_template AS template
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = template.tmplnamespace
                    WHERE namespace.nspname = current_schema()
                    UNION ALL
                    SELECT 'operator', operator_entry.oprname
                    FROM pg_catalog.pg_operator AS operator_entry
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = operator_entry.oprnamespace
                    WHERE namespace.nspname = current_schema()
                    UNION ALL
                    SELECT 'operator-class', operator_class.opcname
                    FROM pg_catalog.pg_opclass AS operator_class
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = operator_class.opcnamespace
                    WHERE namespace.nspname = current_schema()
                    UNION ALL
                    SELECT 'operator-family', operator_family.opfname
                    FROM pg_catalog.pg_opfamily AS operator_family
                    JOIN pg_catalog.pg_namespace AS namespace
                      ON namespace.oid = operator_family.opfnamespace
                    WHERE namespace.nspname = current_schema()
                ) AS schema_objects
                ORDER BY object_type, object_name
                """
            )
            existing = tuple(
                (cast(str, found["object_type"]), cast(str, found["object_name"]))
                for found in cursor.fetchall()
            )
            if existing:
                raise ReferenceSchemaBoundaryError(_incompatible_schema_message(existing))
            cursor.execute(
                f"""
                CREATE TABLE {_METADATA_TABLE} (
                    schema_id TEXT PRIMARY KEY,
                    schema_version INTEGER NOT NULL,
                    release_id TEXT NOT NULL,
                    installed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            cursor.execute(
                f"INSERT INTO {_METADATA_TABLE}(schema_id, schema_version, release_id) "
                "VALUES (%s, %s, %s)",
                (REFERENCE_SCHEMA_ID, REFERENCE_SCHEMA_VERSION, REFERENCE_RELEASE_ID),
            )
            return
        cursor.execute(f"SELECT schema_id, schema_version, release_id FROM {_METADATA_TABLE}")
        metadata = tuple(
            (
                cast(str, metadata_row["schema_id"]),
                int(metadata_row["schema_version"]),
                cast(str, metadata_row["release_id"]),
            )
            for metadata_row in cursor.fetchall()
        )
        if metadata != (
            (
                REFERENCE_SCHEMA_ID,
                REFERENCE_SCHEMA_VERSION,
                REFERENCE_RELEASE_ID,
            ),
        ):
            raise ReferenceSchemaBoundaryError(_incompatible_schema_message(metadata))
        _validate_postgres_spend_entitlement_shape(cursor)


async def ensure_reference_schema_for_store(store: object) -> None:
    """Apply the preview boundary to a concrete reference spend store.

    The public store protocol deliberately has no deployment release lifecycle.
    Only the two durable production/reference implementations expose a path or
    DSN; in-memory conformance doubles remain outside this deployment boundary.
    """

    path = getattr(store, "path", None)
    if isinstance(path, Path):
        ensure_sqlite_reference_schema(path)
        return
    dsn = getattr(store, "dsn", None)
    if isinstance(dsn, str) and dsn:
        ensure_postgres_reference_schema(dsn)
