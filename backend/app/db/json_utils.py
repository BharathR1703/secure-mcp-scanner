"""Flatten rows into scannable text fields.

Relational databases can hide PII inside JSON columns, and MongoDB stores
every document as nested structure. Both are flattened here into
``(path, text)`` pairs so the scanner treats a JSON key the same way it
treats a column name.

Paths use dotted notation for objects (``profile.address.city``) and
bracketed indexes for arrays (``items[0].sku``).

Text leaves are always scanned. Numeric, date and other non-text leaves
are skipped by default, because scanning every ``bigint`` primary key as
text turns ordinary identifiers into false positives. A caller that knows
which columns hold identifiers -- the compliance layer does -- can pass a
predicate to have those leaves scanned too. The flattener itself stays
generic and knows nothing about regulatory domains.
"""

from __future__ import annotations

import datetime
import decimal
import json
import uuid
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

#: Signature of the optional predicate: ``(path, value) -> bool``. It is
#: consulted only for leaves that are not text.
LeafPredicate = Callable[[str, Any], bool]


def _looks_like_json(value: str) -> bool:
    stripped = value.strip()
    return len(stripped) > 1 and stripped[0] in "{[" and stripped[-1] in "}]"


def _scalar_text(value: Any) -> str:
    """Render a non-text leaf as the text a recognizer can read."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, datetime.datetime):
        return value.isoformat(sep=" ")
    if isinstance(value, datetime.date):
        return value.isoformat()
    if isinstance(value, datetime.time):
        return value.isoformat()
    if isinstance(value, decimal.Decimal):
        return format(value, "f")
    if isinstance(value, uuid.UUID):
        return str(value)
    return str(value)


def flatten_value(
    value: Any,
    path: str,
    predicate: Optional[LeafPredicate] = None,
) -> Iterator[Tuple[str, str]]:
    """Yield ``(path, text)`` pairs for every text leaf inside ``value``.

    ``predicate`` is consulted for leaves that are not text -- numbers,
    dates, decimals. Returning True yields the leaf rendered as text.
    """
    if isinstance(value, str):
        if _looks_like_json(value):
            try:
                parsed = json.loads(value)
            except (ValueError, TypeError):
                parsed = None
            if parsed is not None:
                yield from flatten_value(parsed, path, predicate)
                return
        yield (path, value)
    elif isinstance(value, dict):
        for key, nested in value.items():
            child = f"{path}.{key}" if path else str(key)
            yield from flatten_value(nested, child, predicate)
    elif isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            yield from flatten_value(nested, f"{path}[{index}]", predicate)
    elif predicate is not None:
        # Numbers, booleans, dates and binary values are not text fields
        # and are skipped unless the caller asks for them by name.
        if isinstance(value, (bool, bytes, bytearray, memoryview)):
            return
        try:
            if predicate(path, value):
                rendered = _scalar_text(value)
                if rendered:
                    yield (path, rendered)
        except Exception:
            return


def row_to_text_fields(
    row: Dict[str, Any],
    predicate: Optional[LeafPredicate] = None,
) -> List[Tuple[str, str]]:
    """Flatten one row into the text fields that should be scanned.

    Without a predicate the behaviour is unchanged: text leaves only.
    """
    fields: List[Tuple[str, str]] = []
    for key, value in row.items():
        fields.extend(flatten_value(value, str(key), predicate))
    return fields
