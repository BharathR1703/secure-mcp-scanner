"""ClickHouse adapter built on top of clickhouse-driver's native client.

clickhouse-driver ships a synchronous client only — there is no asyncio
sub-module in the published wheels. The driver is therefore used from a
dedicated single-worker thread, which keeps the FastAPI event loop free and
also guarantees that queries are serialised: one ClickHouse connection, one
query at a time, no concurrent use of a non-thread-safe client.
"""

from __future__ import annotations

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Tuple

from .base import DatabaseConnectionError, DatabaseQueryError, EngineAdapter, TableRef

logger = logging.getLogger(__name__)

_LIST_TABLES_SQL = """
SELECT database, name, engine
FROM system.tables
WHERE database NOT IN ('system', 'INFORMATION_SCHEMA', 'information_schema')
ORDER BY database, name
"""


class ClickHouseAdapter(EngineAdapter):
    """Scans ClickHouse tables and materialized views."""

    name = "clickhouse"
    default_schema = "default"
    supports_schemas = True

    def __init__(self, dsn) -> None:
        super().__init__(dsn)
        self._client = None
        self._executor: ThreadPoolExecutor | None = None

    async def connect(self) -> None:
        from clickhouse_driver import Client

        settings = {
            "host": self.dsn.host or "localhost",
            "port": self.dsn.port or 9000,
            "database": self.dsn.database or "default",
            "user": self.dsn.user or "default",
            "password": self.dsn.password or "",
            "connect_timeout": 10,
            "send_receive_timeout": 30,
        }
        self._executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="clickhouse-driver"
        )
        loop = asyncio.get_running_loop()
        try:
            self._client = await loop.run_in_executor(
                self._executor, lambda: Client(**settings)
            )
        except Exception as exc:
            self._shutdown_executor()
            raise DatabaseConnectionError(
                f"Could not connect to the database: {exc}"
            ) from exc
        logger.info("Connected to ClickHouse at %s", self.dsn.redacted())

    def quote(self, identifier: str) -> str:
        return f"`{identifier.replace('`', '``')}`"

    async def list_tables(self) -> List[TableRef]:
        rows, columns = await self._execute(_LIST_TABLES_SQL)

        names = [name for name, _ in columns]
        tables: List[TableRef] = []
        for row in rows:
            record = dict(zip(names, row))
            engine = str(record.get("engine", ""))
            name = str(record.get("name", ""))
            # ClickHouse stores the backing table of a materialized view as a
            # hidden relation named ".inner_id.<uuid>". It is an implementation
            # detail, not something a user wants to scan.
            if name.startswith("."):
                continue
            kind = "materialized view" if "View" in engine else "table"
            tables.append(
                TableRef(
                    schema=str(record.get("database", "default")),
                    name=name,
                    kind=kind,
                )
            )
        return tables

    async def fetch_rows(self, table: TableRef, limit: int) -> List[Dict[str, Any]]:
        # The limit is an integer we have already validated, so it is safe
        # to inline it; ClickHouse's server-side binding does not accept a
        # parameter in a LIMIT clause.
        query = f"SELECT * FROM {self.qualified(table)} LIMIT {int(limit)}"
        rows, columns = await self._execute(query)
        names = [name for name, _ in columns]
        return [dict(zip(names, row)) for row in rows]

    async def close(self) -> None:
        client, self._client = self._client, None
        if client is not None and self._executor is not None:
            loop = asyncio.get_running_loop()
            try:
                await loop.run_in_executor(self._executor, client.disconnect)
            except Exception:
                logger.warning("Failed to close ClickHouse connection", exc_info=True)
        self._shutdown_executor()

    async def _execute(self, query: str) -> Tuple[List[Any], List[Any]]:
        """Run ``query`` on the driver client in its worker thread."""

        client = self._require_client()
        loop = asyncio.get_running_loop()
        try:
            return await loop.run_in_executor(
                self._executor,
                lambda: client.execute(query, with_column_types=True),
            )
        except Exception as exc:
            raise DatabaseQueryError(f"ClickHouse query failed: {exc}") from exc

    def _shutdown_executor(self) -> None:
        executor, self._executor = self._executor, None
        if executor is not None:
            executor.shutdown(wait=False)

    def _require_client(self):
        if self._client is None:
            raise DatabaseConnectionError("ClickHouse connection is not open")
        return self._client
