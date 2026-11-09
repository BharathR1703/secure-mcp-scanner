"""SQLite adapter built on aiosqlite."""

from __future__ import annotations

import logging
from typing import Any, Dict, List

import aiosqlite

from .base import DatabaseConnectionError, DatabaseQueryError, EngineAdapter, TableRef

logger = logging.getLogger(__name__)

_LIST_TABLES_SQL = """
SELECT name, type FROM sqlite_master
WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%'
ORDER BY name
"""


class SQLiteAdapter(EngineAdapter):
    """Scans SQLite tables and views.

    SQLite is file based, so the "database" in the connection string is a
    path. It has no schemas of its own beyond the implicit ``main``.
    """

    name = "sqlite"
    default_schema = "main"
    supports_schemas = False

    def __init__(self, dsn) -> None:
        super().__init__(dsn)
        self._connection: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        try:
            self._connection = await aiosqlite.connect(self.dsn.path or ":memory:")
            self._connection.row_factory = aiosqlite.Row
        except Exception as exc:
            raise DatabaseConnectionError(
                f"Could not open the SQLite database at "
                f"'{self.dsn.path}': {exc}"
            ) from exc
        logger.info("Opened SQLite database at %s", self.dsn.path)

    def quote(self, identifier: str) -> str:
        return f'"{identifier.replace(chr(34), chr(34) * 2)}"'

    async def list_tables(self) -> List[TableRef]:
        connection = self._require_connection()
        try:
            async with connection.execute(_LIST_TABLES_SQL) as cursor:
                rows = await cursor.fetchall()
        except Exception as exc:
            raise DatabaseQueryError(f"Could not list tables: {exc}") from exc
        return [
            TableRef(schema="main", name=row[0],
                     kind="view" if row[1] == "view" else "table")
            for row in rows
        ]

    async def fetch_rows(self, table: TableRef, limit: int) -> List[Dict[str, Any]]:
        connection = self._require_connection()
        query = f"SELECT * FROM {self.qualified(table)} LIMIT ?"
        try:
            async with connection.execute(query, (limit,)) as cursor:
                rows = await cursor.fetchall()
        except Exception as exc:
            raise DatabaseQueryError(
                f"Failed to read data from table '{table.qualified_name}': {exc}"
            ) from exc
        return [{key: row[key] for key in row.keys()} for row in rows]

    async def close(self) -> None:
        if self._connection is not None:
            try:
                await self._connection.close()
            except Exception:
                logger.warning("Failed to close SQLite connection", exc_info=True)
            self._connection = None

    def _require_connection(self) -> aiosqlite.Connection:
        if self._connection is None:
            raise DatabaseConnectionError("SQLite connection is not open")
        return self._connection
