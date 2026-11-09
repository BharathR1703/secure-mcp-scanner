"""MongoDB adapter built on pymongo's native async client."""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from .base import DatabaseConnectionError, DatabaseQueryError, EngineAdapter, TableRef

logger = logging.getLogger(__name__)

_SYSTEM_DATABASES = ("admin", "config", "local")


class MongoDBAdapter(EngineAdapter):
    """Scans MongoDB collections.

    MongoDB has no tables, so a collection is the unit of scanning and the
    "table" in a report is the collection name. Documents are nested, and
    nested fields are flattened into dotted paths before scanning.
    """

    name = "mongodb"
    supports_schemas = False

    def __init__(self, dsn) -> None:
        super().__init__(dsn)
        self._client = None
        self._database_name: str = dsn.database or ""

    async def connect(self) -> None:
        from pymongo import AsyncMongoClient

        try:
            self._client = AsyncMongoClient(
                self.dsn.raw,
                serverSelectionTimeoutMS=10000,
                connectTimeoutMS=10000,
            )
            await self._client.admin.command("ping")
        except Exception as exc:
            raise DatabaseConnectionError(
                f"Could not connect to the database: {exc}"
            ) from exc

        if not self._database_name:
            self._database_name = await self._pick_database()
        logger.info(
            "Connected to MongoDB database '%s' at %s",
            self._database_name,
            self.dsn.redacted(),
        )

    async def _pick_database(self) -> str:
        """Choose a database when the connection string does not name one."""
        names = await self._client.list_database_names()
        candidates = [name for name in names if name not in _SYSTEM_DATABASES]
        if not candidates:
            raise DatabaseConnectionError(
                "No user database found in the MongoDB instance; name one in "
                "the connection string, e.g. mongodb://host:27017/mydb"
            )
        return candidates[0]

    def quote(self, identifier: str) -> str:
        # Collection names are not interpolated into SQL.
        return identifier

    async def list_tables(self) -> List[TableRef]:
        self._require_client()
        try:
            names = await self._client[self._database_name].list_collection_names()
        except Exception as exc:
            raise DatabaseQueryError(f"Could not list collections: {exc}") from exc
        return [
            TableRef(schema=self._database_name, name=name, kind="collection")
            for name in names
        ]

    async def fetch_rows(self, table: TableRef, limit: int) -> List[Dict[str, Any]]:
        self._require_client()
        try:
            cursor = self._client[self._database_name][table.name].find({}).limit(limit)
            documents = await cursor.to_list(length=limit)
        except Exception as exc:
            raise DatabaseQueryError(
                f"Failed to read data from collection '{table.name}': {exc}"
            ) from exc
        return [dict(document) for document in documents]

    async def close(self) -> None:
        if self._client is not None:
            try:
                await self._client.close()
            except Exception:
                logger.warning("Failed to close MongoDB client", exc_info=True)
            self._client = None

    def _require_client(self):
        if self._client is None:
            raise DatabaseConnectionError("MongoDB client is not open")
        return self._client
