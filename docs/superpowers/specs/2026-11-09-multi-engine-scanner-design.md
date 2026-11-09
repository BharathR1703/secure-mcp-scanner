# Multi-Engine Scanner — Design

**Date:** 2026-11-09
**Status:** Implemented
**Supersedes:** the Postgres-only scanner in `backend/app/db_connector.py`

## Intent

Secure MCP Scanner started life as a Postgres-only PII compliance scanner
wrapped in an MCP server. The point of the project is that an LLM agent can
ask a real database "what personal data is in here?" and get an answer that
is safe to hand to a model. That promise is only interesting if it holds for
the databases people actually run — and a Postgres-only connector quietly
narrows it to the databases that already have the least sensitive data.

So the scanner now runs the same pipeline against every engine a demo
database is likely to be: PostgreSQL, MySQL/MariaDB, SQLite, ClickHouse and
MongoDB. It also stops assuming a "table" is the only thing worth scanning:
views, materialized views, foreign tables and document collections are all
relations that can hold PII, and all of them are now walked.

The second half of the change is about scope of a scan. A single named table
is a special case. The common case is "scan this database", so a scan can now
sweep every relation in one request and report a per-table breakdown.

## Goals

- One connection string, five engines, no per-engine code in the scan path.
- The engine is inferred from the DSN scheme; the caller can override it.
- Every scannable relation type is discovered from the database's own
  catalogue, not from a hard-coded list.
- One request can sweep every relation, with a per-table risk breakdown.
- Nested data — JSON columns and embedded documents — is scanned, and the
  finding says which path inside the document it came from.
- Adding a sixth engine is one new file and one line in a registry.

## Non-goals

- Writing to any database. Every adapter is read-only.
- Cross-database joins or a federated scan. One scan, one database.
- Sampling strategies beyond a per-relation row limit.
- Schema migration, indexing, or remediation of the findings.
- Authentication or authorisation of the scanner itself. It accepts a DSN
  and uses it.

## Anti-goals

- **No engine-specific branches in the scan path.** If `run_scan_database`
  ever grows an `if engine == "postgres"`, the abstraction has failed.
- **No raw values in any response, for any engine.** The masking guarantee
  has to hold for ClickHouse and MongoDB exactly as it does for Postgres.
- **No dialect-specific escaping that the adapter does not own.** Identifier
  quoting belongs to the adapter; the shared code never concatenates a
  caller-supplied string into SQL.

## Constraints

- The published `clickhouse-driver` wheels are **synchronous only** — there
  is no `clickhouse_driver.asyncio` module and no `async_connect` factory in
  0.2.11, which is the latest release. The ClickHouse adapter therefore runs
  the driver on a dedicated single-worker thread.
- `asyncpg` has no Python 3.13 wheels, so the local development environment
  runs Python 3.11. The Docker image uses 3.11 as well.
- Presidio's stock recognizer set is tuned for US/UK/EU formats and misfires
  badly on Indian data. The recognizer registry is curated, and this is a
  deliberate deviation from "use Presidio out of the box".
- spaCy's NER reads bare digit runs as dates and mislabels numeric dates as
  person names, so digit-only spans are filtered out of `DATE_TIME` and
  `PERSON` findings.

## The design

### The adapter contract

Everything the scanner needs from a database is five methods, defined in
`backend/app/db/base.py`:

```python
class EngineAdapter(ABC):
    name: str                    # registry key
    default_schema: Optional[str]
    supports_schemas: bool

    async def connect(self) -> None
    async def list_tables(self) -> List[TableRef]
    async def fetch_rows(self, table: TableRef, limit: int) -> List[Dict[str, Any]]
    def quote(self, identifier: str) -> str
    async def close(self) -> None
```

`TableRef` is `(schema, name, kind)`. `kind` is a human-readable string —
`table`, `view`, `materialized view`, `partitioned table`, `foreign table`,
`collection` — because the UI and the reports show it and a user should be
able to tell a view from a table at a glance.

`quote` is per-dialect: `"x"` for Postgres and SQLite, `` `x` `` for MySQL
and ClickHouse. The shared `qualified()` helper composes the two parts with a
dot, and only for engines that have schemas.

### DSN parsing and identifier safety

`backend/app/db/dsn.py` maps schemes to engines:

| Scheme | Engine | Default port |
| --- | --- | --- |
| `postgresql`, `postgres` | postgres | 5432 |
| `mysql`, `mariadb` | mysql | 3306 |
| `sqlite`, `sqlite3` | sqlite | — |
| `clickhouse`, `ch` | clickhouse | 9000 |
| `mongodb`, `mongo` | mongodb | 27017 |

Every identifier that reaches a query — a table name, a schema name — is
checked against `^[A-Za-z_][A-Za-z0-9_$]{0,62}$` before it is quoted. This
is the only thing standing between a caller-supplied table name and a SQL
injection, so it lives in the DSN layer and applies to every engine
uniformly, rather than being re-implemented per adapter.

`parse_table_ref("public.customers")` splits a schema-qualified name into
its two parts and validates both.

### Registry and lifecycle

`backend/app/db/registry.py` resolves a DSN to an adapter, caches it by
`(engine, raw DSN)` under an asyncio lock, and imports the adapter module
lazily with `importlib`. Lazy import matters: the MySQL driver is only
imported when a MySQL DSN is used, so a Postgres-only deployment does not
need the MySQL driver installed at all.

### Relation discovery

Each adapter reads its own catalogue:

- **Postgres** — `pg_class` joined to `pg_namespace`, filtered on
  `relkind IN ('r','p','v','m','f')`.
- **MySQL** — `information_schema.TABLES`, distinguishing `BASE TABLE` from
  `VIEW`.
- **SQLite** — `sqlite_master`.
- **ClickHouse** — `system.tables`, where the `engine` column distinguishes a
  `MaterializedView` from a `MergeTree` table. ClickHouse stores the backing
  table of a materialized view as a hidden relation named `.inner_id.<uuid>`;
  those are filtered out as an implementation detail.
- **MongoDB** — `list_collection_names()`, with a fallback to the first
  non-system database when the DSN names none.

Postgres exposes a wrinkle that cost an hour: `pg_class.relkind` is of the
internal `"char"` type, which asyncpg decodes as `bytes`, not `str`. Every
kind therefore silently fell through the lookup table and every relation was
reported as a plain `table`. The adapter now normalises the value before
looking it up.

### Nested data

`backend/app/db/json_utils.py` flattens a value into `(path, text)` pairs:

- A dict becomes dotted paths: `profile.address.city`.
- A list becomes indexed paths: `items[0].sku`.
- A string that parses as JSON is re-parsed and flattened in turn, which is
  how a `TEXT` column holding JSON (SQLite) and a MySQL `JSON` column both
  end up traversed.
- **Non-string leaves are skipped.** A `tier` of `"gold"` or a `count` of
  `42` is not PII, and feeding numbers to the recognisers only produces
  noise — the Aadhaar recognizer's checksum accepts roughly one random
  12-digit run in ten.

The path becomes the finding's `column`, so a report says
`metadata.kyc.aadhaar` rather than `metadata`.

### Bulk scanning

`table_name` is optional everywhere — in the request model, in the three MCP
tools, in the HTTP endpoints. When it is omitted, the scan walks every
relation the adapter lists, capped at `max_tables` (default 50), and the
report gains a per-table breakdown of rows, findings and risk level. The
overall risk is the most severe per-table risk, so one table full of PAN
numbers makes the whole database High.

### Masking

The whole cell is redacted, not just the matched span.

This was the one genuinely surprising decision in the change. The obvious
implementation masks only the detected span inside the cell, which is what
Presidio's own anonymizers do — but it leaks. A cell reading
`654 Connaught Place, New Delhi 110001, Aadhaar: 4589 6231 7452` produces a
`LOCATION` finding whose "masked" value is
`654 Connaught Place, [REDACTED] 110001, Aadhaar: [REDACTED]`: the street
address and the PIN code come straight back out. A scanner whose central
promise is that raw PII never leaves the process cannot do that.

So `masked_value` is always `[REDACTED]`. That loses the ability to see
*which* value was found, so each finding also carries `value_fingerprint` —
a keyed BLAKE2b digest under a per-process random key. Equal fingerprints
mean equal values, so the same Aadhaar number can be traced across several
tables without the number itself ever being returned. The key never leaves
the process, so fingerprints cannot be reversed or brute-forced, and they
are not comparable across restarts.

### ClickHouse threading

`clickhouse-driver` has no async client. The adapter owns a
`ThreadPoolExecutor(max_workers=1)`, creates the `Client` on that thread,
and runs every query there. One worker means one ClickHouse connection and
one query at a time, which also satisfies the driver's lack of thread
safety — the serialisation the lock would otherwise provide comes free.

## Decisions the builder should know about

- **Views and materialized views are scanned by default.** A view is often a
  join that replicates columns across tables, so scanning one can double
  the apparent finding count. This is correct behaviour — the view really
  does expose that PII — but it means counts across a bulk scan are not
  deduplicated. The fingerprint exists precisely to make that dedup
  possible.
- **Postgres `relkind` comes back as `bytes`.** Handled in
  `backend/app/db/postgres.py`; if the catalogue query changes, the
  normalisation has to come with it.
- **ClickHouse materialized views need `POPULATE`** to be back-filled with
  rows inserted before the view was created. Without it the relation is
  listed but is empty, and the scan reports zero rows against it.
- **The SQLite sample database is built at image build time**
  (`backend/seed_sqlite.py`), so the container has a file-backed database
  without needing a service.
- **The host's port 5432 may already be taken** by a native Postgres
  install, which intercepts `localhost:5432`. The compose-internal hostname
  `postgres:5432` always reaches the container.

## What is left

Nothing blocking. Possible follow-ups, in rough order of value:

- Deduplicate findings across relations by fingerprint in the bulk report, so
  a view that mirrors a table does not inflate the totals.
- Per-column confidence thresholds, so a caller can demand higher precision
  for a specific engine.
- A `--read-only` transaction mode for engines that support it, making the
  read-only guarantee enforced by the database rather than by convention.
- Streaming findings for very large scans, rather than accumulating the
  whole list in memory.
