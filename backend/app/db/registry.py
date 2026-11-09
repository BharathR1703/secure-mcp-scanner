"""Adapter registry: resolves a connection string to a live database adapter.

Adapters (and their pools) are cached per connection string so repeated
scans reuse connections instead of reconnecting every time.

The cache is bound to the event loop that created it. An asyncio pool
belongs to the loop it was opened on, and a client created on one loop
cannot be used from another -- asyncpg raises "Event loop is closed" and
pymongo raises "Cannot use AsyncMongoClient in different event loop". So
the registry remembers which loop each adapter was built on and rebuilds
it when a different loop asks for the same connection.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
from typing import Any, Dict, Optional, Tuple

from .base import Dsn, EngineAdapter
from .dsn import parse_dsn

logger = logging.getLogger(__name__)

#: engine -> (module, class)
_ENGINE_ADAPTERS = {
    "postgres": ("postgres", "PostgresAdapter"),
    "mysql": ("mysql", "MySQLAdapter"),
    "sqlite": ("sqlite", "SQLiteAdapter"),
    "clickhouse": ("clickhouse", "ClickHouseAdapter"),
    "mongodb": ("mongodb", "MongoDBAdapter"),
}

_adapters: Dict[Tuple[str, str], EngineAdapter] = {}

#: The event loop each cached adapter was created on.
_adapter_loops: Dict[Tuple[str, str], asyncio.AbstractEventLoop] = {}

#: One lock per event loop. A single module-level ``asyncio.Lock`` would
#: bind itself to the first loop that awaits it and then refuse to run on
#: any other, which is exactly the situation this module has to survive.
_locks: Dict[Any, asyncio.Lock] = {}


def _lock_for_loop() -> asyncio.Lock:
    """Return the lock belonging to the running event loop."""
    loop = asyncio.get_running_loop()
    lock = _locks.get(loop)
    if lock is None:
        lock = asyncio.Lock()
        _locks[loop] = lock
    return lock


def _adapter_class(engine: str):
    module_name, class_name = _ENGINE_ADAPTERS[engine]
    module = importlib.import_module(f".{module_name}", package=__package__)
    return getattr(module, class_name)


def detect_engine(connection_string: str, db_type: Optional[str] = None) -> str:
    """Return the engine a connection string refers to, without connecting."""
    return parse_dsn(connection_string, db_type).engine


async def _discard(adapter: EngineAdapter) -> None:
    """Close an adapter whose event loop is gone, best effort.

    The pool belongs to a loop that has already finished, so the close may
    raise -- or hang, if it tries to wake a closed loop. Either way it must
    not hold up the caller, so it is bounded by a timeout.
    """
    try:
        await asyncio.wait_for(adapter.close(), timeout=2.0)
    except Exception:
        logger.debug("Could not close a stale adapter cleanly", exc_info=True)


async def get_adapter(
    connection_string: str, db_type: Optional[str] = None
) -> EngineAdapter:
    """Return a connected adapter for ``connection_string``.

    The adapter is cached per (engine, connection string) so that pools are
    reused across scans -- but only within the event loop that created it.
    """
    dsn = parse_dsn(connection_string, db_type)
    key = (dsn.engine, dsn.raw)
    loop = asyncio.get_running_loop()

    async with _lock_for_loop():
        adapter = _adapters.get(key)
        if adapter is not None:
            if _adapter_loops.get(key) is loop:
                return adapter
            # The cached adapter belongs to a different event loop, so its
            # pool cannot serve this one. Drop it and build a fresh one.
            logger.info(
                "Rebuilding adapter for engine '%s' on a new event loop",
                dsn.engine,
            )
            _adapters.pop(key, None)
            _adapter_loops.pop(key, None)
            await _discard(adapter)

        adapter = _adapter_class(dsn.engine)(dsn)
        try:
            await adapter.connect()
        except Exception:
            await adapter.close()
            raise
        _adapters[key] = adapter
        _adapter_loops[key] = loop
        logger.info("Adapter ready for engine '%s'", dsn.engine)
        return adapter


async def close_all_adapters() -> None:
    """Close every cached adapter (used on application shutdown)."""
    async with _lock_for_loop():
        for adapter in list(_adapters.values()):
            try:
                await adapter.close()
            except Exception:
                logger.warning("Failed to close adapter", exc_info=True)
        _adapters.clear()
        _adapter_loops.clear()
