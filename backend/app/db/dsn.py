"""Connection-string parsing, engine detection and identifier safety.

The engine is inferred from the URL scheme, so callers never have to
configure it: ``postgresql://`` and ``postgres://`` select Postgres,
``mysql://`` and ``mariadb://`` select MySQL, ``sqlite://`` selects SQLite,
``clickhouse://`` selects ClickHouse and ``mongodb://`` selects MongoDB.

Every identifier that reaches SQL is validated against a strict pattern
first and quoted per dialect afterwards, so a table name can never carry
SQL injection.
"""

from __future__ import annotations

import re
from typing import Optional, Tuple
from urllib.parse import unquote, urlparse

from .base import Dsn, UnsupportedDatabaseError

#: scheme -> engine key
SCHEME_TO_ENGINE = {
    "postgresql": "postgres",
    "postgres": "postgres",
    "mysql": "mysql",
    "mariadb": "mysql",
    "sqlite": "sqlite",
    "sqlite3": "sqlite",
    "clickhouse": "clickhouse",
    "ch": "clickhouse",
    "mongodb": "mongodb",
    "mongo": "mongodb",
}

#: engine -> default port
DEFAULT_PORTS = {
    "postgres": 5432,
    "mysql": 3306,
    "clickhouse": 9000,
    "mongodb": 27017,
}

#: Identifiers we are willing to interpolate into a statement. Letters,
#: digits, underscore and (for Postgres) dollar sign, not starting with a
#: digit, at most 63 characters.
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,62}$")

SUPPORTED_ENGINES = sorted(set(SCHEME_TO_ENGINE.values()))


def supported_schemes() -> list:
    """Return the connection-string schemes the scanner understands."""
    return sorted(SCHEME_TO_ENGINE)


def _parse_sqlite_path(netloc: str, path: str) -> str:
    """Work out the file path for a SQLite DSN.

    ``sqlite:///:memory:`` is an in-memory database, ``sqlite:////abs/x.db``
    is absolute and ``sqlite:///rel/x.db`` is relative.
    """
    if netloc == ":memory:" or path == ":memory:":
        return ":memory:"
    if netloc and not path.startswith("/"):
        # sqlite://file.db -- netloc carries the relative path.
        return netloc
    if path.startswith("//"):
        return path[1:]
    if path.startswith("/"):
        return path[1:]
    return path or netloc


def parse_dsn(connection_string: str, db_type: Optional[str] = None) -> Dsn:
    """Parse ``connection_string`` into a :class:`Dsn`.

    ``db_type`` forces a particular engine, which is useful for cloud
    connection strings whose scheme does not match the engine they use.
    """
    raw = (connection_string or "").strip()
    if not raw:
        raise ValueError("connection_string is required")

    if "://" not in raw:
        raise ValueError(
            "connection_string must include a scheme, e.g. "
            "postgresql://user:password@host:5432/database "
            f"(supported schemes: {', '.join(supported_schemes())})"
        )

    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()

    if db_type:
        engine = db_type.lower()
        if engine not in SUPPORTED_ENGINES:
            raise UnsupportedDatabaseError(
                f"Unsupported database type '{db_type}'. "
                f"Supported: {', '.join(SUPPORTED_ENGINES)}"
            )
    else:
        engine = SCHEME_TO_ENGINE.get(scheme)
        if engine is None:
            raise UnsupportedDatabaseError(
                f"Unsupported connection scheme '{scheme}'. "
                f"Supported schemes: {', '.join(supported_schemes())}"
            )

    if engine == "sqlite":
        return Dsn(
            raw=raw,
            scheme=scheme,
            engine=engine,
            path=_parse_sqlite_path(parsed.netloc, parsed.path),
        )

    database = parsed.path.lstrip("/")
    port = parsed.port or DEFAULT_PORTS.get(engine)
    return Dsn(
        raw=raw,
        scheme=scheme,
        engine=engine,
        host=parsed.hostname or "localhost",
        port=port,
        user=unquote(parsed.username) if parsed.username else "",
        password=unquote(parsed.password) if parsed.password else "",
        database=unquote(database),
    )


def validate_identifier(identifier: str) -> str:
    """Validate a single SQL identifier, returning it unchanged."""
    if not isinstance(identifier, str) or not _IDENTIFIER_RE.match(identifier):
        raise ValueError(
            f"Invalid identifier '{identifier}'. Use letters, digits and "
            "underscores (a leading underscore is fine), 1 to 63 characters."
        )
    return identifier


def parse_table_ref(
    table_name: str, default_schema: Optional[str] = None
) -> Tuple[Optional[str], str]:
    """Split ``schema.table`` into a validated ``(schema, name)`` pair."""
    name = (table_name or "").strip()
    if not name:
        raise ValueError("table_name is required")

    parts = name.split(".")
    if len(parts) == 1:
        return default_schema, validate_identifier(parts[0])
    if len(parts) == 2:
        schema, table = parts
        return validate_identifier(schema), validate_identifier(table)
    raise ValueError(
        f"Invalid table name '{table_name}'. Use 'table' or 'schema.table'."
    )


def quote_identifier(identifier: str, dialect: str) -> str:
    """Quote an identifier using the rules of ``dialect``."""
    validate_identifier(identifier)
    if dialect in ("mysql", "clickhouse"):
        return f"`{identifier.replace('`', '``')}`"
    return f'"{identifier.replace(chr(34), chr(34) * 2)}"'
