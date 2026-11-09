# Secure MCP Scanner

[![Python 3.11](https://img.shields.io/badge/python-3.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![MCP](https://img.shields.io/badge/MCP-1.9-68217A)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A production-ready Model Context Protocol (MCP) server with built-in PII, PHI
and PCI masking, async database connectors and a real control-level compliance
assessment.

It scans **PostgreSQL, MySQL/MariaDB, SQLite, ClickHouse and MongoDB** —
tables, views, materialized views and document collections — and returns
masked findings only. The engine is inferred from the connection string.

One scan produces every classification. Each finding is classed as personal
data (PII), protected health information (PHI) or cardholder data (PCI), and
the compliance assessment reads from that single result — so the findings and
the control statuses can never disagree.

## What This Solves

Most MCP examples are toy demos that leak sensitive data. This is a
production-grade template that:

- Masks regulated data before it reaches the LLM
- Classifies each hit as PII, PHI or PCI, so the right frameworks apply
- Assesses seven regulatory frameworks control by control, and writes a
  downloadable audit file
- Provides async database connectors with connection pooling across five engines
- Scans every relation in a database in one pass, not just a named table

## Quick Start

```bash
git clone https://github.com/BharathR1703/secure-mcp-scanner.git
cd secure-mcp-scanner
docker compose up --build
```

Open http://localhost:3000. The form ships with a preset chip per engine —
pick one and the connection string fills itself in:

| Preset | Connection string |
| --- | --- |
| Postgres | `postgresql://postgres:postgres@postgres:5432/sample_db` |
| MySQL | `mysql://root:mysql@mysql:3306/sample_db` |
| SQLite | `sqlite:////app/data/sample.db` |
| ClickHouse | `clickhouse://default:@clickhouse:9000/sample_db` |
| MongoDB | `mongodb://mongo:27017/sample_db` |

Then either tick **Scan every table in the database** for a full sweep, or
enter a relation name such as `patients`. **List tables** shows everything the
scanner can reach in that database.

The form has three actions:

| Button | What it does |
| --- | --- |
| **Scan for regulated data** | Detects PII / PHI / PCI and returns the masked findings table |
| **Compliance report** | Runs the same scan and assesses it against the seven frameworks, control by control |
| **Download audit report** | Writes the assessment to a self-contained HTML file you can print to PDF |

Two chip groups narrow the work: **Regulatory classes** (PII, PHI, PCI) and
**Frameworks** (HIPAA, PCI DSS, GDPR, DPDP, CCPA, SOC 2, ISO 27001). Leave
both empty to scan for everything and assess against everything.

## Features

- **MCP Server**: Production-ready with masking middleware
- **Three regulatory classes**: PII, PHI (HIPAA) and PCI DSS, classified per finding
- **Control-level compliance**: ~110 controls across seven frameworks, each reported PASS / FAIL / REVIEW
- **Downloadable audit file**: self-contained HTML with a print stylesheet, or Markdown
- **Multi-Engine**: One connector interface, five databases, engine auto-detected from the DSN
- **Every Relation Type**: tables, views, materialized views, foreign tables and MongoDB collections
- **Bulk Scanning**: One request sweeps every table, with per-table risk aggregation
- **Nested Data**: JSON columns and embedded documents are flattened to dotted paths (`profile.address.city`, `items[0].sku`)
- **Async Connectors**: Connection pooling for Postgres and MySQL, async clients everywhere
- **Dockerized**: Single command deployment, five databases and the app

## Supported Engines

The engine is inferred from the connection-string scheme. Pass `db_type` to
force one explicitly if the scheme is ambiguous.

| Engine | Accepted schemes | Default port | Driver | Relation kinds |
| --- | --- | --- | --- | --- |
| PostgreSQL | `postgresql`, `postgres` | 5432 | `asyncpg` | table, partitioned table, view, materialized view, foreign table |
| MySQL / MariaDB | `mysql`, `mariadb` | 3306 | `aiomysql` | table, view |
| SQLite | `sqlite`, `sqlite3` | — | `aiosqlite` | table, view |
| ClickHouse | `clickhouse`, `ch` | 9000 | `clickhouse-driver` | table, materialized view |
| MongoDB | `mongodb`, `mongo` | 27017 | `pymongo` `AsyncMongoClient` | collection |

`GET /api/engines` returns the live list of supported engines and schemes.

### Connection string formats

```
postgresql://user:password@host:5432/database
mysql://user:password@host:3306/database
sqlite:////absolute/path/to/file.db
clickhouse://user:password@host:9000/database
mongodb://user:password@host:27017/database
```

Schema-qualified relation names are supported wherever the engine has
schemas: `public.customers`, `sample_db.customer_emails`.

> **ClickHouse note** — the published `clickhouse-driver` wheels are
> synchronous only. The adapter runs the driver on a dedicated single-worker
> thread, so the event loop stays free and one query runs at a time against
> one connection.

## Architecture

- Backend: Python FastAPI + MCP SDK + Presidio
- Frontend: React + Vite + Tailwind
- Databases: PostgreSQL 15, MySQL 8, MongoDB 7, ClickHouse 24, SQLite (file)
- Deployment: Docker Compose

```
┌──────────────┐   /api/scan    ┌──────────────────┐  engine adapter ┌────────────┐
│  React/Vite  │ ─────────────► │  FastAPI + MCP   │ ──────────────► │ PostgreSQL │
│  (port 3000) │ ◄───────────── │  (port 8000)     │ ◄────────────── │  MySQL     │
└──────────────┘  masked report └──────────────────┘     rows         │  SQLite    │
                                        │                            │  ClickHouse│
                                        │ Presidio + regex           │  MongoDB   │
                                        ▼                            └────────────┘
                          detection → classify → [REDACTED] masking
                                          │
                                          ▼
                          control assessment → PASS / FAIL / REVIEW
```

Every engine implements the same small adapter contract
(`connect` / `list_tables` / `fetch_rows` / `quote` / `close`), so adding
another database means adding one file under `backend/app/db/`.

### Detection → classification → assessment

```
 cell value
     │
     ├─ Presidio PII + PHI recognizers + PCI recognizers
     │      context gate: 48 chars before / 24 after, plus the column
     │      and relation the value was found in
     │
     ├─ classify:  type  →  class  →  frameworks
     │      type beats context; context only ever upgrades;
     │      PII is the floor
     │
     ├─ mask:       [REDACTED] + a keyed, non-reversible fingerprint
     │
     └─ assess:    110 controls across seven frameworks
                    FAIL if a finding matched
                    PASS if the control is verifiable and nothing matched
                    REVIEW otherwise  ← never PASS without evidence
```

The full design — every module, every decision and why it was made — is in
**[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

## Use Cases

1. **Compliance Scanning**: Detect PII, PHI and cardholder data before audits
2. **Audit Evidence**: Produce a control-level assessment and a printable audit file
3. **MCP Boilerplate**: Start your enterprise MCP project with security built-in
4. **Learning**: Understand how to build production-grade MCP servers

## Using the MCP Server

The MCP tools are available three ways:

1. **stdio** (any MCP client):

   ```bash
   cd backend
   pip install -r requirements.txt
   python -m spacy download en_core_web_sm
   python -m app.mcp_server
   ```

2. **SSE** (when the backend container is running): the MCP server is mounted
   at `http://localhost:8000/mcp/sse`.

3. **HTTP mirrors**: plain REST endpoints that run the exact same tool
   implementations:

   | Endpoint | Description |
   | --- | --- |
   | `GET /health` | Health check |
   | `GET /api/engines` | Supported engines and DSN schemes |
   | `GET /api/frameworks` | The seven frameworks and their control counts |
   | `POST /api/scan` | Full scan report (masked) |
   | `POST /api/compliance-report` | Scan + control-level assessment |
   | `POST /api/audit-report` | The assessment as a downloadable file |
   | `POST /api/tables` | List every relation available for scanning |
   | `GET /api/mcp/tools` | Tool catalog |
   | `POST /api/mcp/scan_database_for_pii` | MCP tool over HTTP |
   | `POST /api/mcp/get_compliance_report` | MCP tool over HTTP |
   | `POST /api/mcp/get_audit_report` | MCP tool over HTTP |
   | `POST /api/mcp/list_database_tables` | MCP tool over HTTP |

   Request body:

   ```json
   {
     "connection_string": "postgresql://postgres:postgres@postgres:5432/sample_db",
     "table_name": "customers",
     "limit": 100,
     "db_type": null,
     "max_tables": 50,
     "categories": ["PII", "PHI", "PCI"],
     "frameworks": ["HIPAA", "PCI_DSS", "GDPR", "DPDP", "CCPA", "SOC2", "ISO27001"]
   }
   ```

   Omit `table_name` (or send `null`) to scan every table in the database.
   Omit `categories` or `frameworks` (or send `null`) to include all of them.
   `POST /api/audit-report` takes the same body plus `"format": "html"` or
   `"markdown"`.

### MCP Tools

| Tool | Description |
| --- | --- |
| `scan_database_for_pii` | Samples rows from a table — or every table — detects regulated data on every text field and returns `table_name`, `total_rows_scanned` and `findings` (`{column, row, pii_type, classification, regulations, masked_value, value_fingerprint, table}`). Raw values are never returned — every hit is replaced with `[REDACTED]`. |
| `get_compliance_report` | Runs the same scan and assesses it against the seven frameworks, returning `overall_status`, a per-framework breakdown with every control's status, and `recommended_actions`. |
| `get_audit_report` | Returns the assessment as a downloadable audit file — self-contained HTML with inline CSS and a print stylesheet, or Markdown. |
| `list_database_tables` | Returns the detected engine and every relation available for scanning, as `{name, schema, kind, qualified_name}`. |
| `list_frameworks` | Returns each framework with its name, version, the regulatory classes it governs and its control count. |

### Masking

`masked_value` is always `[REDACTED]`. The *whole cell* is redacted, not
just the matched span: a cell holding an Aadhaar number usually holds a
street address and a PIN code too, and returning the remainder of the cell
would leak exactly the data this server exists to protect.

To keep the report useful, each finding also carries `value_fingerprint` — a
short, keyed, non-reversible token. Equal fingerprints mean the same value
was found in more than one place, so the same Aadhaar number can be traced
across several tables without the number itself ever leaving the process.
Fingerprints are generated with a per-process random key, so they cannot be
reversed and are not comparable across restarts.

### Scanning JSON and nested documents

Text columns are scanned as-is. JSON columns and embedded documents are
flattened first, and the finding's `column` carries the path to the value:

```
metadata.kyc.aadhaar      AADHAAR
metadata.kyc.email        EMAIL
contact.emergency.phone   PHONE
items[0].sku              —
```

Numeric leaves are skipped — a `tier` or a `count` is not PII, and feeding
them to the recognisers only produces noise.

## Classification: PII, PHI and PCI

Every finding carries a `classification` and the list of frameworks
(`regulations`) that care about it.

| Class | Meaning | Frameworks that govern it |
| --- | --- | --- |
| `PII` | Personal data — names, emails, phones, PAN, Aadhaar | GDPR, DPDP, CCPA, SOC 2, ISO 27001 |
| `PHI` | Protected health information — records, diagnoses, medications, devices | HIPAA, GDPR, DPDP, SOC 2, ISO 27001 |
| `PCI` | Cardholder data — PAN, CVV, expiry | PCI DSS, GDPR, DPDP, CCPA, SOC 2, ISO 27001 |

Classification runs in three steps, in order:

1. **Entity type.** `PCI_PAN` is cardholder data everywhere it appears.
   `PHI_MEDICAL_RECORD_NUMBER` is health data everywhere.
2. **Column.** A column called `diagnosis` puts its values in the health
   domain; `card_number` in the cardholder domain.
3. **Relation.** A table called `patient_records` puts its values in the
   health domain; `payments` in the cardholder domain.

**Type beats context, and context only ever upgrades.** A Luhn-valid
sixteen-digit number is a card number wherever it sits — including in a table
called `loyalty_points` — because the shape is stronger evidence than a table
name. A value can therefore never end up less protected than plain personal
data, which is the safe direction to err in.

`categories` filters the results *after* classification, so the same value
counts as personal data in one relation and health data in another.

### Risk Levels

- **Low** — no regulated data found
- **Medium** — personal data found (up to 20 instances)
- **High** — government identifiers (PAN/Aadhaar), protected health
  information or cardholder data found, or more than 20 instances

## Detection

Detection is powered by Microsoft Presidio with custom recognizers:

**PII**

- `EMAIL` / `PERSON_NAME` / `LOCATION` — standard Presidio recognizers
- `PHONE` — Indian mobile numbers, via a dedicated recognizer
- `PAN` — Indian Permanent Account Number (`ABCDE1234F`)
- `AADHAAR` — Indian Aadhaar number in its spaced format (`1234 5678 9012`)

**PHI** — identifiers plus context-gated conditions

- `PHI_MEDICAL_RECORD_NUMBER` — `MRN: 4471-B`, `Medical Record No. 88213`
- `PHI_HEALTH_PLAN_ID` — `PMJAY-HI-2023-889120`, `ESIC-22334455`, `CGHS-55667788`,
  `ABHA` / `TMC` / `Member ID` / `Policy Number`
- `PHI_MEDICAL_LICENSE` — `MCI-2019-114322`, `NMC`, `State Medical Council`
- `PHI_DEVICE_ID` — `SN: DEX-004512`, implant and pacemaker serials
- `PHI_DATE_OF_BIRTH` — a date in a `dob` / `birth` column
- `PHI_DIAGNOSIS` / `PHI_MEDICATION` — clinical lexicon, gated on context

**PCI**

- `PCI_PAN` — 13–19 digits with optional separators, Luhn-validated
  (ISO/IEC 7812 mod-10). A run of identical digits is rejected even though it
  passes the checksum.
- `PCI_CVV` — three or four digits, bare or after a `CVV` / `CVC` / `CID` label
- `PCI_EXPIRY` — `MM/YY` or `MM/YYYY`, bare or after an `Expiry` label

Two precision guards keep the output clean on Indian data:

- **The predefined recognizer set is curated.** Several stock Presidio
  recognizers are tuned to US/UK/EU formats and misfire badly on Indian
  values — `NhsRecognizer` scores a bare 10-digit Indian mobile number as a
  UK NHS number with confidence 1.0, and the US bank/licence recognizers tag
  every phone number. Those recognizers are removed from the registry.
- **NER artefacts are filtered out.** spaCy reads bare digit runs as dates
  (Indian PIN codes such as `560001`) and mislabels numeric dates as person
  names (`05/03/2024`), so those spans are discarded. A date is only
  reported when it contains a year, which keeps dates of birth — the reason
  dates matter as PII — while dropping PIN codes. Similarly, a `+91`
  prefixed mobile number is 12 digits once the country code is included and
  Presidio's checksum-based Aadhaar recognizer accepts roughly one such
  number in ten — an Aadhaar match sitting inside a `+91` number is
  discarded in favour of the phone reading.

A pure-regex fallback keeps scanning working (without name detection) if the
spaCy model is unavailable.

## Compliance Assessment

`get_compliance_report` (and `POST /api/compliance-report`) turns a scan into
a control-level assessment against seven frameworks:

| Framework | Version | Governs |
| --- | --- | --- |
| HIPAA | 45 CFR Parts 160 and 164 | PHI |
| PCI DSS | v4.0 | PCI |
| GDPR | EU 2016/679 | PII, PHI, PCI |
| DPDP | India, 2023 | PII, PHI, PCI |
| CCPA | Cal. Civ. Code 1798.100 et seq. | PII, PCI |
| SOC 2 | Trust Services Criteria | all three |
| ISO 27001 | 2022, Annex A | all three |

The catalogue is curated rather than exhaustive: it holds the controls a data
scan has something to say about, not every clause of every regulation.

### Status vocabularies

Two different vocabularies are used, and they are not interchangeable.

**Overall status** (one per report):

| Status | Meaning |
| --- | --- |
| `COMPLIANT` | Every applicable control passed |
| `NON_COMPLIANT` | At least one control failed |
| `NEEDS_REVIEW` | No control failed, but some need human verification |
| `NOT_APPLICABLE` | No data in scope falls under any framework |

**Control status** (one per control):

| Status | Meaning |
| --- | --- |
| `PASS` | The scan verified the requirement is met |
| `FAIL` | The scan found the requirement is broken |
| `REVIEW` | The scan cannot judge this control — a human must |

A control the scanner cannot verify is **always** `REVIEW`, never `PASS`. A
scanner that claims a passing audit control it cannot see is worse than one
that says "check this". This is why a report full of health data shows 19
`REVIEW` controls under HIPAA rather than quietly reporting a clean bill of
health: access reviews, audit trails and incident response are not things a
row scan can observe.

### Recommended actions

The report carries a de-duplicated list of remediation steps, ordered by
severity, each naming the data it applies to. For example: *"Delete the card
verification values found by this scan once authorisation completes, and stop
persisting them at all."*

## Audit File

`POST /api/audit-report` (and the MCP tool `get_audit_report`) writes the
assessment to a file:

- **HTML** — self-contained: inline CSS, a print stylesheet, no external
  scripts, stylesheets or fonts. It opens in a browser and prints to PDF with
  nothing to fetch. Served with
  `Content-Disposition: attachment; filename="compliance-audit.html"`.
- **Markdown** — the same content for pipelines and agents.

The file carries the overall status, the per-framework summary, every
control's status, severity, evidence and remediation, and the recommended
actions. **No raw personal, health or cardholder data appears in it** — the
evidence is written in terms of types and counts.

## Running Without Docker

```bash
# 1. Databases (any subset — you only need the ones you point at)
docker run -d --name scanner-pg -p 5432:5432 \
  -e POSTGRES_DB=sample_db -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -v "$PWD/init.sql":/docker-entrypoint-initdb.d/init.sql postgres:15

# 2. Backend (from backend/)
pip install -r requirements.txt
python -m spacy download en_core_web_sm
uvicorn app.main:app --reload --port 8000

# 3. Frontend (from frontend/)
npm install
npm run dev   # http://localhost:5173, proxying /api to :8000
```

When running locally (outside Docker), use `localhost` instead of the compose
service names:

```
postgresql://postgres:postgres@localhost:5432/sample_db
mysql://root:mysql@localhost:3306/sample_db
mongodb://mongo:localhost:27017/sample_db
clickhouse://default:@localhost:9000/sample_db
sqlite:///./sample.db
```

> If a native Postgres already occupies port 5432 on the host, it will
> intercept `localhost:5432` — check which server answers before assuming
> the demo data is missing. The compose-internal hostname `postgres:5432`
> always reaches the container.

## Tests

The suite has two halves: unit tests that need nothing, and integration
tests that run against the live databases.

```bash
# Unit tests only (no databases needed)
cd backend
pytest -q tests --ignore=tests/integration

# Unit + integration, against the compose databases
docker compose --profile test run --rm tests
```

The integration tests skip themselves when an engine is unreachable, so the
suite still passes on a machine without Docker — the skips are visible in the
summary rather than silent.

The integration suite checks, for each of the five engines, that relations
can be listed, that a scan finds the seeded personal, health and cardholder
data, that a compliance report covers all seven frameworks, that a category
filter narrows the results, that the audit file renders — and that **no raw
value ever leaves the scanner**.

## Project Structure

```
secure-mcp-scanner/
├── backend/
│   ├── app/
│   │   ├── main.py           # FastAPI app + MCP HTTP mirrors
│   │   ├── mcp_server.py     # MCP server (stdio/SSE) + shared tool logic
│   │   ├── pii_detector.py   # Presidio detection, masking, fingerprints
│   │   ├── db_connector.py   # Back-compatible facade over app.db
│   │   ├── models.py         # Pydantic models
│   │   ├── detectors/        # PHI and PCI recognizers (no Presidio dependency)
│   │   │   ├── context_gated.py  # The context-gating engine
│   │   │   ├── phi.py            # Health identifiers and conditions
│   │   │   ├── pci.py            # PAN, CVV, expiry
│   │   │   └── clinical.py       # Conditions, medications, clinical words
│   │   ├── compliance/       # What a finding means, never what it is
│   │   │   ├── context.py    # Column and relation domain hints
│   │   │   ├── mapping.py    # Entity type → class → frameworks
│   │   │   ├── frameworks.py # The control catalogue (7 frameworks, 110 controls)
│   │   │   ├── models.py     # Control/Framework dataclasses, status constants
│   │   │   ├── assessor.py   # Control-level assessment
│   │   │   └── rendering.py  # HTML and Markdown audit files
│   │   └── db/               # One adapter per engine
│   │       ├── base.py       # EngineAdapter contract, TableRef, Dsn
│   │       ├── dsn.py        # Scheme → engine mapping, identifier validation
│   │       ├── registry.py   # Adapter cache and lifecycle
│   │       ├── json_utils.py # JSON / document flattening
│   │       ├── postgres.py   # asyncpg
│   │       ├── mysql.py      # aiomysql
│   │       ├── sqlite.py     # aiosqlite
│   │       ├── clickhouse.py # clickhouse-driver (worker thread)
│   │       └── mongodb.py    # pymongo AsyncMongoClient
│   ├── tests/
│   │   ├── test_detectors.py     # Luhn, PAN, CVV, PHI labels, context gating
│   │   ├── test_classification.py
│   │   ├── test_assessor.py
│   │   ├── test_rendering.py
│   │   ├── test_api.py
│   │   └── integration/test_engines.py   # Live-database tests
│   ├── requirements.txt
│   ├── seed_sqlite.py        # Builds the sample SQLite file at image build time
│   └── Dockerfile
├── frontend/                 # React + Vite + Tailwind UI
├── docs/
│   ├── ARCHITECTURE.md       # The full design, module by module
│   └── superpowers/specs/    # The original design documents
├── docker-compose.yml
├── init.sql                  # Postgres sample data: table, view, materialized view
├── init_mysql.sql            # MySQL sample data: table, view, JSON column
├── init_mongo.js             # MongoDB sample data: nested collections
├── init_clickhouse.sql       # ClickHouse sample data: table, materialized view
├── LICENSE
└── README.md
```

Each engine's seed data includes the same eight patient rows and eight
payment rows, so the reports are comparable across engines.

## Safety Notes

- Identifiers are validated against a strict regex and quoted per dialect, so
  a table name can never carry SQL into a query.
- Connection strings are redacted in the logs — passwords are never written
  out.
- Findings are masked at detection time. The whole cell is redacted, so
  raw values never reach the API response, the MCP response, the browser or
  the audit file — not even the non-matching context around a detection.
- Controls the scanner cannot judge are reported as `REVIEW`, never `PASS`.

## License

MIT
