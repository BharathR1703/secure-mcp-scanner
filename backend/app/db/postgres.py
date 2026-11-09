"""PostgreSQL adapter built on asyncpg."""

from __future__ import annotations

import logging
from typing import Any, Dict, List

import asyncpg

from .base import DatabaseConnectionError, DatabaseQueryError, EngineAdapter, TableRef

logger = logging.getLogger(__name__)

#: Relation kinds we are willing to scan.
_KIND_MAP = {
    "r": "table",
    "p": "partitioned table",
    "v": "view",
    "m": "materialized view",
    "f": "foreign table",
}

_LIST_TABLES_SQL = """
SELECT n.nspname, c.relname, c.relkind
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY n.nspname, c.relname
"""


def _as_text(value: Any) -> str:
    """Normalise a value coming back from asyncpg to a plain string.

    Postgres' internal ``"char"`` type — which ``pg_class.relkind`` uses —
    is decoded by asyncpg as ``bytes`` rather than ``str``.
    """
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


class PostgresAdapter(EngineAdapter):
    """Scans Postgres tables, views, materialized views and foreign tables."""

    name = "postgres"
    default_schema = "public"
    supports_schemas = True

    def __init__(self, dsn) -> None:
        super().__init__(dsn)
        self._pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        try:
            self._pool = await asyncpg.create_pool(
                dsn=self.dsn.raw,
                min_size=1,
                max_size=5,
                command_timeout=30,
            )
        except Exception as exc:
            raise DatabaseConnectionError(
                f"Could not connect to the database: {exc}"
            ) from exc
        logger.info("Created Postgres pool for %s", self.dsn.redacted())

    def quote(self, identifier: str) -> str:
        return f'"{identifier.replace(chr(34), chr(34) * 2)}"'

    async def list_tables(self) -> List[TableRef]:
        pool = self._require_pool()
        try:
            rows = await pool.fetch(_LIST_TABLES_SQL)
        except asyncpg.PostgresError as exc:
            raise DatabaseQueryError(f"Could not list tables: {exc}") from exc
        return [
            TableRef(schema=row["nspname"], name=row["relname"],
                     kind=_KIND_MAP.get(_as_text(row["relkind"]), "table"))
            for row in rows
        ]

    async def fetch_rows(self, table: TableRef, limit: int) -> List[Dict[str, Any]]:
        pool = self._require_pool()
        query = f"SELECT * FROM {self.qualified(table)} LIMIT $1"
        try:
            async with pool.acquire() as connection:
                rows = await connection.fetch(query, limit)
        except asyncpg.PostgresError as exc:
            raise DatabaseQueryError(
                f"Failed to read data from table '{table.qualified_name}': {exc}"
            ) from exc
        return [dict(row) for row in rows]

    async def close(self) -> None:
        if self._pool is not None:
            try:
                await self._pool.close()
            except Exception:
                logger.warning("Failed to close Postgres pool", exc_info=True)
            self._pool = None

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise DatabaseConnectionError("Postgres pool is not open")
        return self._pool
