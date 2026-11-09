"""Multi-database support for the Secure MCP Scanner.

Every engine is wrapped in an :class:`EngineAdapter` so the scanner can
list relations, read rows and quote identifiers without knowing which
database it is talking to.
"""

from .base import (
    DatabaseConnectionError,
    DatabaseQueryError,
    Dsn,
    EngineAdapter,
    TableRef,
    UnsupportedDatabaseError,
)
from .dsn import (
    SCHEME_TO_ENGINE,
    SUPPORTED_ENGINES,
    parse_dsn,
    parse_table_ref,
    quote_identifier,
    supported_schemes,
    validate_identifier,
)
from .json_utils import flatten_value, row_to_text_fields
from .registry import close_all_adapters, detect_engine, get_adapter

__all__ = [
    "DatabaseConnectionError",
    "DatabaseQueryError",
    "Dsn",
    "EngineAdapter",
    "TableRef",
    "UnsupportedDatabaseError",
    "SCHEME_TO_ENGINE",
    "SUPPORTED_ENGINES",
    "parse_dsn",
    "parse_table_ref",
    "quote_identifier",
    "supported_schemes",
    "validate_identifier",
    "flatten_value",
    "row_to_text_fields",
    "close_all_adapters",
    "detect_engine",
    "get_adapter",
]
