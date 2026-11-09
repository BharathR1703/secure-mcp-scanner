# Secure MCP Scanner — Architecture

A complete description of how the system is built, why it is built that way,
and what each layer is responsible for.

---

## 1. The one invariant

Everything in this system exists to serve a single property:

> **Raw personal, health, or cardholder data must never leave the process.**

Not "is usually redacted". Not "is redacted in the UI". *Never leaves the
process.* A finding that crosses a boundary carries `[REDACTED]` and a
non-reversible fingerprint, and nothing else.

That invariant propagates upward through the design:

| Layer | How the invariant is enforced |
|---|---|
| Detector | Returns entity type, offsets and score — never the value |
| Scanner | `masked_value` is the constant `"[REDACTED]"`; the raw value is used only inside the detection call |
| Fingerprint | Keyed BLAKE2b, per-process random key, 5-byte digest — lets you count distinct values without holding them |
| Logging | `Dsn.redacted()` replaces the password before anything is written |
| SQL | Identifiers are validated against a strict regex *and* quoted per dialect — a table name cannot carry SQL |
| Audit file | Rendered from the report object, which never held a raw value |
| Tests | `test_no_raw_value_ever_leaves_the_scanner` asserts eight seeded secrets are absent from the serialized report of every engine |

The one deliberate exception is `app.db_connector.fetch_sample_data`, which
returns raw rows. It is the low-level accessor for callers that need the
data itself, and it is documented as such. No scanner path uses it — the
MCP tools and HTTP endpoints all go through `run_scan_database`, which masks
everything.

---

## 2. Topology

```
                    ┌───────────────────────────────┐
                    │        MCP clients            │
                    │  (Claude Desktop, IDE agents) │
                    └──────────────┬────────────────┘
                                   │ SSE  /mcp
                                   │ stdio (python -m app.mcp_server)
┌──────────────────┐               │
│  FastAPI backend │◄──────────────┘
│      :8000       │   POST /api/scan
│                  │   POST /api/compliance-report
│  /api/*  /health │   POST /api/audit-report
│  /api/engines    │   GET  /api/frameworks
│  /api/mcp/tools  │
└────────┬─────────┘
         │
         │ asyncpg / aiomysql / aiosqlite / clickhouse-driver / pymongo
         │
   ┌─────┴──────┬─────────┬───────────┬────────────┐
   │  postgres  │  mysql  │  sqlite   │ clickhouse │  mongodb
   │   :5432    │  :3306  │ (file)    │  :9000     │  :27017
   └────────────┴─────────┴───────────┴────────────┘

┌──────────────────┐        ┌────────────────────────┐
│  Vite frontend   │───────►│  /api proxy → backend  │
│      :3000       │  fetch │                        │
└──────────────────┘        └────────────────────────┘
```

Six compose services: four databases, `backend`, `frontend`, plus a
`tests` service behind the `test` profile.

---

## 3. Layered module map

```
backend/app/
├── main.py            HTTP surface (FastAPI) + MCP SSE mount
├── mcp_server.py      MCP tool surface (FastMCP) + the scan orchestration
├── models.py          pydantic wire models (the HTTP/JSON contract)
├── pii_detector.py    PII detection: Presidio + curated recognizers
│
├── detectors/         PHI and PCI detection (no Presidio dependency)
│   ├── context_gated.py   the context-gating engine
│   ├── phi.py             health identifiers
│   ├── pci.py             cardholder data
│   └── clinical.py        conditions, medications, clinical words
│
├── compliance/        "what does this mean" — never imported by detectors
│   ├── context.py     column & relation domain hints
│   ├── mapping.py     entity type → class → frameworks
│   ├── frameworks.py  the 110-control catalogue
│   ├── models.py      dataclasses + status constants
│   ├── assessor.py    the assessment engine
│   └── rendering.py   HTML / Markdown audit files
│
└── db/                engine abstraction
    ├── base.py        EngineAdapter ABC, Dsn, TableRef, exceptions
    ├── dsn.py         scheme → engine, identifier validation & quoting
    ├── registry.py    adapter cache, per-event-loop
    ├── json_utils.py  row → flat (path, text) pairs
    └── postgres.py / mysql.py / sqlite.py / clickhouse.py / mongodb.py
```

### The import rule

The layers never reach back up. Concretely:

- `app.detectors` and `app.pii_detector` **never** import `app.compliance`.
- `app.compliance` **never** imports `app.detectors` or `app.pii_detector`.
- `app.compliance.models` holds only dataclasses and constants — no
  pydantic — specifically so that `app.models` (the pydantic wire models)
  can import it without a circular import.

The reason is stated in `app/compliance/__init__.py` and it is worth
repeating:

> The detection layer knows what a value *is*; the compliance layer knows
> what that *means*. Mixing the two is how a scanner ends up with framework
> logic inside a regex.

Consequence: adding a new regulation never touches a recognizer, and
adding a recognizer never touches a control.

---

## 4. The request path

### 4.1 `POST /api/scan`

```
main.py: scan()                  validate ScanRequest (pydantic)
  └─► mcp_server.run_scan_database()
        ├─ db.registry.get_adapter(dsn)          → connected EngineAdapter
        ├─ adapter.list_tables()                 → List[TableRef]
        ├─ for each relation (bounded by max_tables):
        │    └─ adapter.fetch_rows(ref, limit)   → List[Dict]
        │         └─ json_utils.row_to_text_fields(row, predicate)
        │              → [(column, text), ...]
        │    └─ for each (column, text):
        │         └─ pii_detector.detect_pii(text, context=f"{column} {relation.name}")
        │              └─ merges three engines into one finding list:
        │                   Presidio PII + detectors.phi + detectors.pci
        │         └─ compliance.mapping.classify(type, column, relation)
        │              → (refined_type, class, regulations)
        │         └─ Finding(column, row, pii_type, classification,
        │                     regulations, masked_value="[REDACTED]",
        │                     score, table, value_fingerprint)
        └─ ScanReport(db_type, total_rows_scanned, findings,
                      findings_by_type, findings_by_classification, risk_level)
```

`run_scan_database` is the single place where the raw value is in scope,
and it is used only to build the fingerprint — never stored.

### 4.2 `POST /api/compliance-report`

```
main.py: compliance_report()
  └─► mcp_server.run_compliance_report()
        ├─ report = await run_scan_database(...)      ← scan once
        └─ compliance.assessor.assess(report, frameworks)
              ├─ resolve frameworks (unknown key → ValueError → HTTP 400)
              ├─ group findings by class
              ├─ for each framework:
              │     ├─ applicable? (governs a class present, or always_applicable)
              │     ├─ for each control:
              │     │     ├─ match findings against control.triggers
              │     │     ├─ FAIL  if any finding matched
              │     │     ├─ PASS  if control.verifiable and nothing matched
              │     │     └─ REVIEW otherwise
              │     └─ aggregate → FrameworkAssessment
              ├─ recommended actions (dedup by remediation, ordered by severity)
              └─ ComplianceReport(overall_status, summary, ...)
```

### 4.3 `POST /api/audit-report`

Same as above, then `compliance.rendering.render(report, format)` →
`Response` with `Content-Disposition: attachment; filename="compliance-audit.{ext}"`.
Two formats: `html` (self-contained, no external resources) and `markdown`.

### 4.4 MCP tools

`app/mcp_server.py` builds a `FastMCP` instance with five tools:

| Tool | Purpose |
|---|---|
| `scan_database_for_pii` | Scan a database or a single relation |
| `get_compliance_report` | Scan + assess against the frameworks |
| `get_audit_report` | Scan + assess + render the audit file |
| `list_database_tables` | List scannable relations |
| `list_frameworks` | Describe the framework catalogue |

The MCP tools and the HTTP endpoints share `run_scan_database` and
`run_compliance_report`. There is no second implementation of the scan
logic — the MCP surface is a thin wrapper, not a parallel code path.

Two transports:
- **SSE** — `app.main` mounts `mcp_server.mcp.sse_app()` at `/mcp` inside a
  `try/except`, so an MCP import failure degrades the HTTP API instead of
  taking the process down.
- **stdio** — `python -m app.mcp_server` for editors that spawn the server
  as a subprocess.

---

## 5. The classification model

This is the core idea, and it is the part most worth understanding well.

### Two axes

A finding has two independent properties:

- **What the value is** — the entity type (`EMAIL_ADDRESS`, `PCI_PAN`,
  `PHI_MEDICAL_RECORD_NUMBER`, `IN_PAN`). This is a property of the
  *content*.
- **What it is regulated as** — the class (`PII`, `PHI`, `PCI`) and the
  frameworks that govern it. This is a property of the value *in context*.

The same 16-digit string can be a card number in a `payments` table (PCI)
and an order reference in a `journal` table (not regulated at all). The
entity type alone cannot tell you which.

### The algorithm

```
classify(pii_type, column, relation) -> (type, class, regulations)
```

1. **Refine the type.** `_refine_type` upgrades a generic type when the
   column demands it: `DATE_TIME` in a `dob` / `birth` / `birth_date`
   column becomes `PHI_DATE_OF_BIRTH`.
2. **Decide the class**, in strict precedence order — the first that
   matches wins:
   - the refined type's own domain, via `ENTITY_CLASS`
     (`PHI_MEDICAL_RECORD_NUMBER`, `PHI_HEALTH_PLAN_ID`,
     `PHI_MEDICAL_LICENSE`, `PHI_DEVICE_ID`, `PHI_DATE_OF_BIRTH`,
     `PHI_DIAGNOSIS`, `PHI_MEDICATION` → `PHI`; `PCI_PAN`, `PCI_CVV`,
     `PCI_EXPIRY` → `PCI`)
   - else the **column** domain (`domain_for_column`)
   - else the **relation** domain (`domain_for_relation`)
   - else `PII` — the floor
3. **Decide the regulations** from the class via `REGULATIONS`:

   | Class | Frameworks that care |
   |---|---|
   | PII | GDPR, DPDP, CCPA, SOC 2, ISO 27001 |
   | PHI | HIPAA, GDPR, DPDP, SOC 2, ISO 27001 |
   | PCI | PCI DSS, GDPR, DPDP, CCPA, SOC 2, ISO 27001 |

   Note this is per-*finding* applicability. Framework-level applicability
   in the assessment uses `FRAMEWORK_GOVERNS` plus `ALWAYS_APPLICABLE` —
   a framework applies if it governs any class present in the scan, or if
   it is always applicable.

### The precedence rule

> **Type beats context; context only ever upgrades; PII is the floor.**

- If the *type* says PCI, it is PCI — even in a column whose name looks
  clinical.
- If the *type* says PII but the *column and relation* say clinical
  (a `diagnosis` column in a `patient_records` table), it is upgraded to
  PHI.
- Context can never downgrade. A PAN in a `patient_records` table is still
  PCI.
- Nothing can fall below PII. Every finding is personal data at minimum.

The same rule governs entity-type collisions *inside* the detector:
`_ENTITY_PRECEDENCE` in `pii_detector.py` says that a PHI or PCI type
overrides a generic type in an overlapping span, even if the generic type
scored higher. `PHI_DATE_OF_BIRTH` beats `DATE_TIME`, `PERSON` and
`PERSON_NAME`; `PCI_PAN` beats `CREDIT_CARD`, `PHONE`, `IN_PHONE` and
`AADHAAR`; `PCI_EXPIRY` beats `DATE_TIME`.

Domain resolution in `compliance/context.py` uses the same idea at the
schema level: `COLUMN_DOMAIN_HINTS` holds 39 PCI tokens (`card`, `pan`,
`cvv`, `expiry`…) and 55 PHI tokens (`diagnosis`, `patient`, `mrn`,
`prescription`…), `RELATION_DOMAIN_HINTS` holds 40 more for table names,
and `IDENTIFIER_COLUMN_TOKENS` holds 46 that mark a column as an
identifier. `_match_domain` picks the domain with the most hint matches;
ties break on `DOMAIN_ORDER = (CLASS_PCI, CLASS_PHI)` — PCI wins a tie,
because cardholder data is the more strictly regulated of the two.

---

## 6. The detection layer

### 6.1 PII — `app/pii_detector.py`

Presidio's `AnalyzerEngine` is the primary engine, but it is wrapped, not
trusted. The pipeline:

```
detect_pii(text, context)
  ├─ _presidio_detect(text)      AnalyzerEngine, score_threshold=0.4
  │                              └─ _is_noise() drops the NER artefacts
  └─ _regex_detect(text)          fallback when Presidio is unavailable
       ↓
  ├─ + detect_phi(text, context)  the domain detectors, plain Python
  ├─ + detect_pci(text, context)  so card data survives a spaCy failure
  ↓
  ├─ filter score >= MIN_SCORE (0.4)
  └─ _resolve_overlaps(findings)
       ├─ drop an AADHAAR sitting inside a "+"-prefixed phone
       ├─ _apply_precedence()  PHI/PCI types beat generic types
       └─ keep the highest-scoring span of each overlapping set
```

**Curated recognizer set.** Fourteen stock Presidio recognizers are removed
(`NOISY_RECOGNIZERS`), including `CreditCardRecognizer` — its generic
pattern misfires on ordinary long numbers, and cardholder data is handled
by the dedicated PCI detector instead, which validates the Luhn checksum.

**Noise suppression.** `_is_noise` removes the classic false positives:

- digit-only `DATE_TIME` (a number that happened to parse as a date) —
  Indian PIN codes, Aadhaar digit groups and phone numbers all match that
  shape
- `DATE_TIME` with no year in it — a date worth reporting has a year, and
  dates of birth always do
- digit-token `PERSON` / `NRP` (a number that the NER model typed as a
  name)

**The Presidio fallback.** If spaCy or the model is missing, `_regex_detect`
runs a compiled-regex recognizer set instead. The scanner degrades to
regex-only detection rather than failing to start. This is why
`app/detectors/*` is written in plain Python with no Presidio dependency:
the PHI and PCI detectors keep working in degraded mode.

**Overlap resolution.** `_resolve_overlaps` handles the classic Indian-data
collision: an Aadhaar number embedded in a `+91`-prefixed phone number is
reported as a phone, not as an Aadhaar. The longer, more specific span wins.

### 6.2 PHI — `app/detectors/phi.py`

Two categories, per the "identifiers plus context-gated conditions" scope:

**Identifiers** (five recognizers) — regex + label patterns, with a label
separator of `\.?[\s:#\-]{0,6}` so `MRN: 4471-A` and `MRN - 4471A` both
match:

- medical record number (`MRN`)
- health plan / beneficiary id — including **PMJAY, AYUSHMAN, ABHA, ESIC,
  CGHS, TMC** (Indian government health schemes)
- medical council / licence number — including **MCI** and **NMC**
- device identifier — serial number, implant id, pacemaker
- date of birth

**Context-gated conditions** (two recognizers) — the `clinical.py` lexicons:

**Context-gated conditions** — the `clinical.py` lexicons:

- 116 conditions (`diabetes`, `hypertension`, `covid-19`, `epilepsy`, …)
- 113 medications (`metformin`, `warfarin`, `amoxicillin`, …)
- 40 clinical context words that license a condition

The licensing words are deliberately conservative. "report" and "history"
are **not** in the list — both are common in business text ("annual report",
"service history"), and including them turned every non-medical mention of
a condition in a company document into protected health information. The
clinical phrases that matter are listed instead ("clinical report",
"medical record", "history of").

A condition only becomes a finding when the words around it — or the column
and relation it was found in — look clinical.

### 6.3 PCI — `app/detectors/pci.py`

Three recognizers: PAN, CVV, expiry.

**PAN.** 13–19 digits with optional single space or hyphen separators
(`4111 1111 1111 1111`, `4111-1111-1111-1111`). The candidate is then
validated by `_is_pan`:

1. length in 13..19 after stripping separators
2. **not all identical digits** — `0000 0000 0000 0000` passes the Luhn
   checksum but is not a card number; this guard rejects it
3. **Luhn valid** — ISO/IEC 7812 mod-10

Both checks must pass. This is what separates a real PAN from a 16-digit
order id.

**CVV.** A labelled pattern (`cvv: 123`, `CVV - 123`) or a bare three-digit
pattern, which only fires in a card context.

**Expiry.** A labelled or bare `MM/YY` shape, validated as month 1–12.

**There is deliberately no cardholder-name recognizer.** A cardholder's name
is a person's name, and the scanner already detects those. Deciding that a
name is *cardholder data* needs the row context that a cell-by-cell
scanner does not have. Instead, the column and relation hints in the
compliance layer classify a `cardholder_name` column as PCI directly —
which is the "context upgrades, type decides" rule doing its job.

### 6.4 The context-gating engine — `app/detectors/context_gated.py`

This is the mechanism that makes condition and medication detection safe.

```
Rule
├── entity_type     e.g. "PHI_DIAGNOSIS"
├── pattern         compiled regex with EXACTLY ONE capture group
│                   (enforced in __post_init__)
├── context_words   the words that license this rule
└── label           "term:diabetes", "mrn", ...
```

`ContextGatedRecognizer.analyze(text, extra_context)`:

1. Find every match of the rule's pattern. The single capture group is the
   **value**; the full match is the span.
2. Decide whether the match is *contexted*, by any of three signals:
   - a **context word** appears in the window **48 characters before** or
     **24 characters after** the match, on word boundaries
   - the **caller-supplied context** (the column name and relation name)
     contains one of the rule's context words
   - the caller's context tokens are a superset of the rule's tokens
3. Score it:
   - contexted → **`CONTEXT_SCORE` = 0.85**
   - not contexted → **`NO_CONTEXT_SCORE` = 0.05**
4. `whole_value_is_valid` lets a rule demand that the *entire* cell is the
   value (not a substring of a sentence).

The 0.05 score is below `MIN_SCORE` (0.4), so an uncontexted finding is
dropped. But it is still *emitted* — deliberately. The low-scoring finding
stays visible to the overlap resolver, so if a higher-scoring, more
specific entity covers the same span, the overlap logic can make the right
choice rather than two findings fighting over one span.

**Tokenization** splits on separators *and* camelCase, so `patientId`,
`patient_id`, and `Patient ID` all reduce to `patient` + `id`. This is
what lets a `camelCase` Java-style schema and a `snake_case` SQL schema
both hit the same context rules.

---

## 7. The compliance layer

### 7.1 The catalogue — `app/compliance/frameworks.py`

Seven frameworks, 110 controls:

| Framework | Version | Governs | Always applicable | Controls | Verifiable |
|---|---|---|---|---:|---:|
| HIPAA | 45 CFR Parts 160 and 164 | PHI | no | 22 | 3 |
| PCI DSS | v4.0 | PCI | no | 17 | 3 |
| GDPR | EU 2016/679 | PII, PHI, PCI | no | 17 | 3 |
| DPDP | India, 2023 | PII, PHI, PCI | no | 12 | 1 |
| CCPA / CPRA | Cal. Civ. Code 1798.100 et seq. | PII, PCI | no | 10 | 2 |
| SOC 2 | 2017 (rev. 2022) | PII, PHI, PCI | **yes** | 13 | 0 |
| ISO 27001 | 2022, Annex A | PII, PHI, PCI | **yes** | 19 | 1 |

The catalogue is curated rather than exhaustive. Every GDPR article and
every ISO 27001 clause is not listed — that would bury the controls that
bear on stored data under ninety pages of governance clauses no scan can
speak to.

**Verifiable** is the load-bearing flag on every control:

- *Verifiable controls* — the scanner can judge them. Either the data
  violates the requirement (a card number stored in readable text, a
  verification value kept after authorisation) or it does not.
- *Operational controls* — the scanner cannot judge them. Access reviews,
  audit trails, incident response, training.

### 7.2 Triggers

A control fires on findings. A trigger is either:

- an **entity type** — `"PCI_PAN"`, `"PHI_MEDICAL_RECORD_NUMBER"`
- a **class** — `"class:PHI"`, `"class:PCI"`

`_matching_findings` in `assessor.py` resolves a trigger to the set of
findings it covers. The `class:` prefix (`CLASS_PREFIX`) is what lets a
control be written against "any PHI" without enumerating every PHI type.

### 7.3 The honesty mechanism

`_assess_control` is four lines and is the most important logic in the
compliance layer:

```
if the control matched a finding:      → FAIL
elif the control is verifiable:         → PASS
else:                                   → REVIEW
```

So a control the scanner cannot judge **never** reports `PASS`. It reports
`REVIEW` — meaning *a human needs to check this*. A scanner that claims a
passing audit control it cannot see is worse than one that says "check
this".

The same rule applies at the framework level: a framework with zero
verifiable controls (SOC 2 has none) can only ever be `FAIL` or `REVIEW`.
It can never be `COMPLIANT` on the strength of a scan, and the report says
so.

### 7.4 Two status vocabularies

They are deliberately different and never mixed.

**`risk_level`** — Low / Medium / High. A property of the *data*.
`compute_risk_level` in `mcp_server.py`, in order:

- no findings ⇒ Low
- any PAN or Aadhaar finding (`GOVERNMENT_ID_TYPES`) ⇒ High
- any PHI or PCI finding ⇒ High
- 20 or fewer findings (`MEDIUM_FINDING_THRESHOLD`) ⇒ Medium
- more than 20 ⇒ High

Combined across relations with `_combine_risk`, which takes the most
severe level.

**`overall_status`** — COMPLIANT / NON_COMPLIANT / NEEDS_REVIEW /
NOT_APPLICABLE. A property of the *assessment*.

**Control status** — PASS / FAIL / REVIEW / NOT_APPLICABLE.

A framework is `NOT_APPLICABLE` when no data in the scanned scope falls
under it. Verified behaviour: scanning the PII-only `customers` table
reports HIPAA and PCI DSS as `NOT_APPLICABLE`.

### 7.5 Evidence and recommended actions

`_evidence_text` builds the evidence string from the *matched findings'*
metadata — type, class, column, row — and **never** from a raw value.
That is why the audit file can be handed to an auditor without leaking
anything.

`_recommended_actions` collects the remediation strings of the failed
controls, deduplicates by remediation text, and orders them by severity
then occurrence count. This is the "what do I do on Monday" section.

### 7.6 Rendering — `app/compliance/rendering.py`

`render(report, format)` dispatches to `render_html` or `render_markdown`.

The HTML is **self-contained**: all CSS is inline in a `<style>` block with
CSS variables, there are no external stylesheets, fonts, or scripts. That
matters because the file gets emailed to auditors, filed into ticketing
systems, and opened on machines that cannot reach the internet — a report
that renders as unstyled markup is a report nobody reads.

There is a print stylesheet (`@media print`) that drops the sheet border
and prevents page breaks inside a framework block, so the file prints
cleanly to PDF.

---

## 8. The database layer

### 8.1 The adapter contract — `app/db/base.py`

Every engine implements the same four operations:

```python
class EngineAdapter(ABC):
    name: str
    supports_schemas: bool
    default_schema: str

    async def connect(self) -> None
    async def list_tables(self) -> List[TableRef]
    async def fetch_rows(self, ref: TableRef, limit: int) -> List[Dict[str, Any]]
    def quote(self, identifier: str) -> str
    async def close(self) -> None
```

Above it sit three exception types the HTTP layer maps to status codes:

- `DatabaseConnectionError` → 502
- `DatabaseQueryError` → 400
- `UnsupportedDatabaseError` → 400
- `ValueError` → 400
- anything else → 500

### 8.2 DSN parsing and identifier safety — `app/db/dsn.py`

Ten URL schemes map to five engines:

| Scheme | Engine |
|---|---|
| `postgresql`, `postgres` | postgres |
| `mysql`, `mariadb` | mysql |
| `sqlite`, `sqlite3` | sqlite |
| `clickhouse`, `ch` | clickhouse |
| `mongodb`, `mongo` | mongodb |

`parse_dsn` returns a frozen `Dsn` with `redacted()` — the password is
replaced before the DSN is ever logged.

`db_type` overrides scheme inference, for cloud connection strings whose
scheme does not match the engine they actually use.

**Injection defence is two-layered:**

1. `validate_identifier` — every identifier must match
   `^[A-Za-z_][A-Za-z0-9_$]{0,62}$`. Anything else is rejected outright.
2. `quote_identifier` — the identifier is then quoted per dialect
   (backticks for MySQL and ClickHouse, double quotes elsewhere).

Because validation happens first, a table name can never carry SQL into a
statement, even in the quoting step.

### 8.3 The five adapters

| Adapter | Driver | Listing query | Notes |
|---|---|---|---|
| `postgres.py` | `asyncpg` pool (min 1, max 5) | `pg_class` with relkinds `r p v m f` | tables, partitioned tables, views, matviews, foreign tables |
| `mysql.py` | `aiomysql` pool | `information_schema.TABLES` | excludes system schemas; column names from cursor `description` |
| `sqlite.py` | `aiosqlite` | `sqlite_master` | excludes `sqlite_%`; `row_factory = aiosqlite.Row` |
| `clickhouse.py` | `clickhouse-driver` in a `ThreadPoolExecutor(max_workers=1)` | `system.tables` | skips names starting with `.` — the hidden `.inner_id.<uuid>` MV backing table; kind is "materialized view" if "View" in engine |
| `mongodb.py` | `pymongo.AsyncMongoClient` | `list_collection_names` | 10 s timeouts, ping on connect, `_pick_database()` when the DSN names none; `supports_schemas = False` |

**ClickHouse is synchronous.** `clickhouse-driver` has no async variant, so
the adapter runs it in a dedicated single-worker thread pool. The adapter
interface stays async for every caller.

### 8.4 Flattening — `app/db/json_utils.py`

Not every column is a scalar. `flatten_value` turns any value into
`(path, text)` pairs:

- objects → dotted paths (`address.city`)
- arrays → `items[0]`, `items[1]`
- JSON embedded in a string → re-parsed and flattened
- non-string scalars (`date`, `Decimal`, `UUID`) → `_scalar_text` converts
  them to their string form

`row_to_text_fields(row, predicate)` applies a predicate to decide which
fields are worth scanning. The predicate comes from
`compliance/context.py:should_scan_non_text` — a numeric column named
`card_number` is worth scanning even though it is not text.

This is what makes MongoDB work through the same pipeline as SQL: a
document becomes a set of path/value pairs, and the scanner does not know
or care whether the source was a relational row or a document.

### 8.5 The registry and the event-loop problem — `app/db/registry.py`

Adapters are cached per `(engine, connection string)` so repeated scans
reuse pools instead of reconnecting. That caching has a subtle failure
mode, and this is a real bug that the integration tests exposed:

> An asyncio pool belongs to the loop it was opened on, and a client
> created on one loop cannot be used from another — asyncpg raises
> "Event loop is closed" and pymongo raises "Cannot use AsyncMongoClient
> in different event loop".

The same applies to `asyncio.Lock()`: a single module-level lock binds
itself to the first loop that awaits it and then refuses to run on any
other.

The fix, which is the current state of `registry.py`:

- `_adapter_loops` maps each cached adapter to the loop that created it
- `_locks` holds **one lock per event loop**, obtained via
  `_lock_for_loop()`
- `get_adapter` compares the cached adapter's loop with the running loop.
  Same loop → reuse. Different loop → drop the stale adapter (closing it
  best-effort with a 2-second timeout, since its loop is already gone),
  build a fresh one, and cache it against the new loop

This is not only a test artifact. Any embedding that calls `asyncio.run`
more than once — a script, a notebook, a test runner, a Lambda handler —
hits exactly this. Before the fix, the second call raised.

---

## 9. Security properties, enumerated

1. **Masking.** `MASK = "[REDACTED]"`. `mask_pii` replaces every detected
   span. `masked_value` is the constant, never a partial reveal.
2. **Fingerprinting.** `fingerprint(value)` is a keyed BLAKE2b:
   `hashlib.blake2b(value.encode(), key=_FINGERPRINT_KEY, digest_size=5)`,
   where `_FINGERPRINT_KEY = os.urandom(32)` is generated per process.
   Two findings in the same run with the same value share a fingerprint, so
   you can count distinct leaked values; you still cannot recover any of
   them, and the digests do not carry across process restarts (by design).
3. **Credential redaction.** `Dsn.redacted()` before logging.
4. **SQL injection defence.** Validate then quote, as described above.
5. **CORS.** `CORS_ORIGINS` from the environment, not a wildcard.
6. **No raw value in the audit file.** Guaranteed by construction — the
   renderer reads only the report object, which never held a raw value —
   and asserted by test.

---

## 10. The frontend

React 18 + Vite 5 + Tailwind 3. Four components:

| Component | Responsibility |
|---|---|
| `App.jsx` | state for the three results; header, footer, banner for the audit download |
| `ScannerForm.jsx` | the form: connection string, table, limit, category chips, framework chips, and three buttons |
| `ResultsDisplay.jsx` | the findings table — type, class, column, row, score, masked value |
| `CompliancePanel.jsx` | the assessment — overall status, summary grid, class breakdown, recommended actions, expandable per-framework control tables |

`constants.js` holds `CATEGORIES`, `FRAMEWORKS`, and the style maps
(`CATEGORY_STYLES`, `STATUS_STYLES`, `SEVERITY_STYLES`) so the colour
vocabulary lives in one place.

`ScannerForm` has three handlers: `handleScan`, `handleCompliance`,
`handleAudit`. `handleAudit` posts `format: 'html'`, receives a blob,
creates an object URL, and triggers a synthetic `<a download>` click.

`buildBody()` sends `categories` and `frameworks` as `null` when the chip
groups are empty, so "no filter" and "an empty filter" are not confused.

The compliance panel renders an explicit note that REVIEW controls need
human verification and that no raw data appears — the UI states the
guarantees rather than relying on the user noticing them.

---

## 11. The data model — `app/models.py`

pydantic v2 wire models, the HTTP and MCP JSON contract:

- `ScanRequest` — `connection_string`, `table_name`, `limit` (1–1000),
  `db_type`, `max_tables`, `categories`, `frameworks`
- `Finding` — `column`, `row`, `pii_type`, `classification`, `regulations`,
  `masked_value`, `score`, `table`, `value_fingerprint`
- `TableSummary`, `ScanReport`
- `ControlAssessment`, `FrameworkAssessment`, `ComplianceReport`
- `TableInfo` (with `schema_name` aliased to `schema`), `TableListResponse`

pydantic v2 does not let a field shadow `BaseModel.schema`, so the alias is
handled with `Field(alias=..., serialization_alias=...)` plus
`ConfigDict(populate_by_name=True)`.

---

## 12. Testing

171 tests: 131 unit, 40 integration.

**Unit** (`backend/tests/`):
- `test_detectors.py` — PII, PHI, PCI, context gating, Luhn, masking
- `test_classification.py` — the two-axis model and precedence rules
- `test_assessor.py` — control assessment, framework resolution, status
  aggregation, recommended actions
- `test_rendering.py` — HTML and Markdown output
- `test_api.py` — the HTTP surface via FastAPI `TestClient`

**Integration** (`backend/tests/integration/test_engines.py`):
parametrised over all five engines — list tables, scan, produce a
compliance report, render the audit file, narrow by category, and the
no-raw-value property.

Integration tests **skip, not fail**, when an engine is unreachable: a
missing database is an environment problem, not a defect in the scanner.
`engine_is_reachable` probes the TCP port first (or the file for SQLite)
so a skipped test fails fast rather than hanging on a connect timeout.

```bash
pytest -q tests --ignore=tests/integration                        # local
docker compose --profile test run --rm tests                       # with live DBs
```

`pytest.ini` sets `asyncio_mode = auto` and
`asyncio_default_fixture_loop_scope = function`.

---

## 13. Deployment

`docker-compose.yml`, six services.

- **postgres / mysql / mongo / clickhouse** — seeded on first boot by
  `init.sql`, `init_mysql.sql`, `init_mongo.js`, `init_clickhouse.sql`,
  each with a healthcheck. The backend and the test service both
  `depends_on: condition: service_healthy`.
- **backend** — built from `backend/Dockerfile`: Python 3.11 slim, pinned
  requirements, `python -m spacy download en_core_web_sm` at build time,
  and `seed_sqlite.py` runs at build time so SQLite can be scanned without
  a service.
- **frontend** — node:20-alpine, `npm install && npm run build`, then
  `npm run preview -- --host 0.0.0.0` on port 3000. `vite.config.js`
  proxies `/api` to `BACKEND_URL` (`http://backend:8000` in Docker,
  `http://localhost:8000` locally).

The ClickHouse healthcheck uses `127.0.0.1` rather than `localhost`,
because inside the container `localhost` resolves to `::1` first and
ClickHouse only listens on IPv4.

The ClickHouse DSN is `clickhouse://default:@clickhouse:9000/sample_db` —
the `clickhouse/clickhouse-server:24-alpine` image has only a `default`
user, with no password.

---

## 14. Extension points

**A new database engine** — write an adapter in `app/db/`, implement the
four methods, add the scheme to `SCHEME_TO_ENGINE`, add the class to
`_ENGINE_ADAPTERS` in `registry.py`. Nothing else changes; the scanner
treats it identically to the other five.

**A new framework** — add a tuple of `Control` objects and a `Framework`
entry in `frameworks.py`. Add the key to `FRAMEWORK_GOVERNS` if it governs
a class. The discovery endpoint, the assessor, the renderer, the MCP
`list_frameworks` tool, and the frontend chip group all pick it up from
the catalogue — the frontend needs one line in `constants.js`.

**A new detector** — write a `Rule` and a `ContextGatedRecognizer` in
`app/detectors/`. No changes to the scanner, the assessor, or the
framework catalogue.

**A new PII entity type** — add the recognizer to the curated set in
`pii_detector.py`, map it to a class in `compliance/mapping.py`, and
add it to the `ENTITY_CLASS` table.

---

## 15. Design decisions worth explaining

**Why scan once and assess twice?** `run_compliance_report` scans once and
reuses the report for the assessment. Scanning twice would double the
database load and could produce two different snapshots of a changing
table.

**Why is PII the floor?** Because it is the only class every finding is
certain to belong to. Something is always personal data about a person
when it is a card number, a medical record, or an email address. Downgrades
are how a scanner starts missing things.

**Why does `NO_CONTEXT_SCORE` exist at all?** The uncontexted finding is
kept so the overlap resolver can see it. Two findings covering the same
span need to be compared on score to pick a winner; dropping the loser
first would make the comparison impossible.

**Why is the control catalogue curated?** Because an exhaustive listing
would be ninety pages of governance clauses no scan can speak to, which
would bury the three controls per framework that a scan can actually
judge. A curated catalogue with an honest `REVIEW` status is more useful
than a complete one full of `REVIEW`.

**Why does SOC 2 have zero verifiable controls?** Because a Trust
Services Criterion is about the *operating effectiveness* of controls over
time — access reviews, change management, monitoring. A scan of stored data
cannot judge any of it. Reporting SOC 2 as `FAIL` on a data finding is
still correct (the finding is real evidence of a problem), but reporting it
as `PASS` would be a lie.

---

## 16. File map

```
README.md                              507    user guide
docs/ARCHITECTURE.md                          this document
docs/superpowers/specs/
    2026-11-09-multi-engine-scanner-design.md
    2026-11-09-compliance-classifications-design.md

backend/
  Dockerfile                             20
  requirements.txt                       20
  pytest.ini                             12
  seed_sqlite.py                        387
  app/
    main.py                             398    HTTP + MCP SSE mount
    mcp_server.py                       550    MCP tools + scan orchestration
    models.py                           201    pydantic wire models
    pii_detector.py                     423    PII detection
    db_connector.py                      91    back-compatible facade
    detectors/
      __init__.py                        45
      context_gated.py                  190    the context-gating engine
      phi.py                            237
      pci.py                            192
      clinical.py                       333
    compliance/
      __init__.py                        54
      context.py                        310    column/relation domain hints
      mapping.py                        126    type → class → frameworks
      frameworks.py                    1319    the control catalogue
      models.py                          79    dataclasses + constants
      assessor.py                       327    the assessment engine
      rendering.py                      439    HTML / Markdown
    db/
      __init__.py                        47
      base.py                           105
      dsn.py                            165
      registry.py                       128
      json_utils.py                     106
      postgres.py                       107
      mysql.py                           97
      sqlite.py                          86
      clickhouse.py                     135
      mongodb.py                        102
  tests/
    conftest.py                         114
    test_api.py                         133
    test_detectors.py                   250
    test_classification.py              175
    test_assessor.py                    261
    test_rendering.py                   157
    integration/test_engines.py         179

frontend/
  Dockerfile, index.html, package.json, vite.config.js, tailwind.config.js
  src/
    main.jsx, index.css, App.css
    App.jsx                             70
    constants.js                        89
    components/ScannerForm.jsx         413
    components/ResultsDisplay.jsx      261
    components/CompliancePanel.jsx     229

init.sql  init_mysql.sql  init_mongo.js  init_clickhouse.sql
docker-compose.yml                     114
```
