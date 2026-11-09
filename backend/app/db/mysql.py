"""MySQL / MariaDB adapter built on aiomysql."""

from __future__ import annotations

import logging
from typing import Any, Dict, List

import aiomysql

from .base import DatabaseConnectionError, DatabaseQueryError, EngineAdapter, TableRef

logger = logging.getLogger(__name__)

_LIST_TABLES_SQL = """
SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE
FROM information_schema.TABLES
WHERE TABLE_SCHEMA NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
ORDER BY TABLE_SCHEMA, TABLE_NAME
"""


class MySQLAdapter(EngineAdapter):
    """Scans MySQL and MariaDB tables and views."""

    name = "mysql"
    supports_schemas = True

    def __init__(self, dsn) -> None:
        super().__init__(dsn)
        self._pool: aiomysql.Pool | None = None

    async def connect(self) -> None:
        try:
            self._pool = await aiomysql.create_pool(
                host=self.dsn.host,
                port=self.dsn.port or 3306,
                user=self.dsn.user or "root",
                password=self.dsn.password or "",
                db=self.dsn.database or None,
                autocommit=True,
                minsize=1,
                maxsize=5,
                connect_timeout=10,
            )
        except Exception as exc:
            raise DatabaseConnectionError(
                f"Could not connect to the database: {exc}"
            ) from exc
        logger.info("Created MySQL pool for %s", self.dsn.redacted())

    def quote(self, identifier: str) -> str:
        return f"`{identifier.replace('`', '``')}`"

    async def list_tables(self) -> List[TableRef]:
        pool = self._require_pool()
        try:
            async with pool.acquire() as connection:
                async with connection.cursor() as cursor:
                    await cursor.execute(_LIST_TABLES_SQL)
                    rows = await cursor.fetchall()
        except Exception as exc:
            raise DatabaseQueryError(f"Could not list tables: {exc}") from exc

        tables: List[TableRef] = []
        for schema, name, table_type in rows:
            kind = "view" if str(table_type).upper() == "VIEW" else "table"
            tables.append(TableRef(schema=schema, name=name, kind=kind))
        return tables

    async def fetch_rows(self, table: TableRef, limit: int) -> List[Dict[str, Any]]:
        pool = self._require_pool()
        query = f"SELECT * FROM {self.qualified(table)} LIMIT %s"
        try:
            async with pool.acquire() as connection:
                async with connection.cursor() as cursor:
                    await cursor.execute(query, (limit,))
                    rows = await cursor.fetchall()
                    columns = [desc[0] for desc in cursor.description or []]
        except Exception as exc:
            raise DatabaseQueryError(
                f"Failed to read data from table '{table.qualified_name}': {exc}"
            ) from exc
        return [dict(zip(columns, row)) for row in rows]

    async def close(self) -> None:
        if self._pool is not None:
            try:
                self._pool.close()
                await self._pool.wait_closed()
            except Exception:
                logger.warning("Failed to close MySQL pool", exc_info=True)
            self._pool = None

    def _require_pool(self) -> aiomysql.Pool:
        if self._pool is None:
            raise DatabaseConnectionError("MySQL pool is not open")
        return self._pool
