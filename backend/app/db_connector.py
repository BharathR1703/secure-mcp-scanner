"""Async database access for the scanner.

This module is the stable public surface used by the MCP tools and the HTTP
endpoints. The real work lives in :mod:`app.db`, where every engine is
wrapped in an adapter with the same three operations: list relations, read
rows, quote identifiers.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .db import (
    DatabaseConnectionError,
    DatabaseQueryError,
    TableRef,
    UnsupportedDatabaseError,
    close_all_adapters,
    detect_engine,
    get_adapter,
    parse_table_ref,
)
from .db.registry import get_adapter as _get_adapter

logger = logging.getLogger(__name__)

__all__ = [
    "DatabaseConnectionError",
    "DatabaseQueryError",
    "UnsupportedDatabaseError",
    "close_all_pools",
    "detect_engine",
    "fetch_sample_data",
    "list_tables",
    "get_adapter",
]


async def fetch_sample_data(
    connection_string: str,
    table_name: str,
    limit: int = 100,
    db_type: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Fetch up to ``limit`` rows from ``table_name`` as a list of dicts.

    ``table_name`` may be qualified (``schema.table``). The engine is
    inferred from the connection string unless ``db_type`` overrides it.

    .. warning::
       This returns **raw** rows, unmasked. It is the low-level accessor
       for callers that need the data itself. The scanner's own paths --
       the MCP tools and the HTTP endpoints -- never use it; they go
       through :func:`app.mcp_server.run_scan_database`, which masks
       everything.
    """
    adapter = await get_adapter(connection_string, db_type)
    schema, name = parse_table_ref(table_name, adapter.default_schema)
    reference = TableRef(schema=schema, name=name)
    rows = await adapter.fetch_rows(reference, _validate_limit(limit))
    logger.info(
        "Fetched %d rows from '%s' using the %s adapter",
        len(rows),
        reference.qualified_name,
        adapter.name,
    )
    return rows


async def list_tables(
    connection_string: str, db_type: Optional[str] = None
) -> List[TableRef]:
    """List every scannable relation in the database."""
    adapter = await get_adapter(connection_string, db_type)
    return await adapter.list_tables()


def _validate_limit(limit: int) -> int:
    try:
        value = int(limit)
    except (TypeError, ValueError):
        raise ValueError("limit must be an integer between 1 and 1000")
    if value < 1 or value > 1000:
        raise ValueError("limit must be between 1 and 1000")
    return value


async def close_all_pools() -> None:
    """Close every cached adapter and pool (used on application shutdown)."""
    await close_all_adapters()
