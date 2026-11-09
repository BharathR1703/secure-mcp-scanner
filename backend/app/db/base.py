"""Engine-agnostic types shared by every database adapter."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


class DatabaseConnectionError(Exception):
    """Raised when a database connection cannot be established."""


class DatabaseQueryError(Exception):
    """Raised when a query against an existing connection fails."""


class UnsupportedDatabaseError(Exception):
    """Raised when a connection string names an engine we do not support."""


@dataclass(frozen=True)
class TableRef:
    """A scannable relation in a database.

    ``schema`` is ``None`` for engines without schemas (SQLite, MongoDB).
    ``kind`` distinguishes base tables from views, materialized views and
    document collections.
    """

    schema: Optional[str]
    name: str
    kind: str = "table"

    @property
    def qualified_name(self) -> str:
        return f"{self.schema}.{self.name}" if self.schema else self.name


@dataclass(frozen=True)
class Dsn:
    """A parsed connection string."""

    raw: str
    scheme: str
    engine: str
    host: str = ""
    port: Optional[int] = None
    user: str = ""
    password: str = ""
    database: str = ""
    path: str = ""

    def redacted(self) -> str:
        """Return the DSN with the password masked, safe for logging."""
        if not self.password:
            return self.raw
        return self.raw.replace(f":{self.password}@", ":***@")


class EngineAdapter(ABC):
    """Base class for a database engine.

    Every adapter answers the same three questions: which relations exist,
    how do I read rows from one of them, and how do I quote an identifier
    safely for this dialect.
    """

    #: Key used to register and select this engine.
    name: str = ""

    #: Schema used when the caller does not qualify a table name.
    default_schema: Optional[str] = None

    #: Whether this engine has schemas at all.
    supports_schemas: bool = True

    def __init__(self, dsn: Dsn) -> None:
        self.dsn = dsn

    @abstractmethod
    async def connect(self) -> None:
        """Open the underlying connection or pool."""

    @abstractmethod
    async def list_tables(self) -> List[TableRef]:
        """Return every scannable relation in the database."""

    @abstractmethod
    async def fetch_rows(self, table: TableRef, limit: int) -> List[Dict[str, Any]]:
        """Return up to ``limit`` rows from ``table`` as dicts."""

    @abstractmethod
    def quote(self, identifier: str) -> str:
        """Quote a single identifier for this dialect."""

    @abstractmethod
    async def close(self) -> None:
        """Release the connection or pool."""

    def qualified(self, table: TableRef) -> str:
        """Return the fully quoted, dot-separated name of ``table``."""
        if table.schema and self.supports_schemas:
            return f"{self.quote(table.schema)}.{self.quote(table.name)}"
        return self.quote(table.name)
