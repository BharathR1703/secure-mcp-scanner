# Regulatory Classification & Compliance Assessment — Design

**Date:** 2026-11-09
**Status:** Draft — decisions resolved, awaiting sign-off
**Builds on:** `docs/superpowers/specs/2026-11-09-multi-engine-scanner-design.md`

## Intent

The scanner answers one question today: *does this cell contain personal
data?* The answer is a flat list of entity types and a risk badge. That is
enough to say "this table has emails in it", and not enough to say anything a
compliance team can act on.

Compliance questions are not "is this PII" but "which controls does this
data break". A stored Aadhaar number and a stored card number are both
"High risk personal data" — but they trip completely different control
references, and they are detected by completely different means. A scanner
that cannot tell a PAN card number from an Indian tax PAN cannot tell a PCI
DSS assessor anything either.

So this adds a second axis to the scanner. Alongside *what* a value is, the
scanner now says *what kind of regulated data it is* — personal data (PII),
protected health information (PHI), or cardholder data (PCI) — and the
compliance report becomes an assessment of named controls across seven
frameworks, with the findings that trip each control attached as evidence.

The design principle throughout: **one scan, many frameworks.** A single
pass over the rows produces every classification, and every framework reads
from that one result. Separate PHI scans, PCI scans and PII scans would
mean three passes over the same data for one report, and three chances for
the results to disagree.

## Goals

- One scan classifies each finding as PII, PHI or PCI, and names the
  frameworks that care about it.
- The compliance report assesses named controls across HIPAA, PCI DSS v4.0,
  GDPR, DPDP Act 2023, SOC 2, ISO/IEC 27001 and CCPA/CPRA, and says which
  controls the data fails, which pass, and which cannot be judged from data
  alone.
- Every failed control carries evidence (the finding types and counts that
  tripped it) and a remediation action.
- The assessment can be downloaded as a self-contained audit file — HTML for
  a human, Markdown for a pipeline — that stands on its own without the
  scanner.
- The scanner still never returns a raw value.

## Non-goals

- Certifying compliance. A data scan can show exposure; it cannot show that
  access controls, training, incident response or contracts are in place.
  Controls that need operational evidence are reported as `REVIEW`, never
  as `PASS`.
- Detecting every HIPAA identifier. The Safe Harbor list has 18 categories;
  the identifiers that appear in real databases get first-class treatment, and
  the ones that do not are covered by the surrounding controls.
- Financial crime, AML, or tax compliance.
- Replacing a GRC tool. This is a data-exposure scanner with a regulatory
  lens, not a compliance management platform.

## Anti-goals

- **No framework logic in the detection layer.** Recognizers know what a
  value *is*. Frameworks know what that means. The two never mix.
- **No control ever reads as PASS without evidence.** A control that a scan
  cannot verify must say so.
- **No raw value ever reaches the assessment, the report or the audit file**,
  including in the evidence text.
- **No framework assessment for a framework with no matching data.** If a
  database has no card data, PCI DSS is reported as `NOT_APPLICABLE` rather
  than a wall of passing controls.

## Constraints

- Presidio has no PHI or PCI recognizers; both must be built. Presidio's
  `EntityRecognizer` is an abstract base with an overridable `analyze()`,
  which gives exact control over match spans and context gating — the
  stock `PatternRecognizer` matches the whole regex hit, so a rule for
  `MRN: 4471` would report the span `MRN: 4471` rather than the number.
- Context gating has to be explicit. A clinical-condition lexicon on its own
  matches "cancer" in "Cancer Research Institute" and "diabetes" in a
  product name. The user chose *context-gated* conditions: a condition only
  counts when the surrounding text or the column it sits in looks clinical.
- PCI cardholder data has no schema to key on, so detection is by shape:
  a 13–19 digit number passing the Luhn checksum.
- The Indian PAN (`ABCDE1234F`) and the Indian Aadhaar (`4589 6231 7452`)
  already look like identifiers but are neither PCI card numbers nor
  HIPAA identifiers; the new recognizers must not collide with them.

## The design

### 1. Two axes, one scan

Every finding gains a classification and a list of frameworks:

```python
class Finding(BaseModel):
    column: str                  # "diagnosis", "metadata.kyc.aadhaar"
    row: int
    pii_type: str                # entity type: "PCI_PAN", "PHI_DIAGNOSIS", "EMAIL"
    classification: str          # "PII" | "PHI" | "PCI"
    regulations: List[str]       # ["HIPAA", "GDPR", "DPDP"]
    masked_value: str            # always "[REDACTED]"
    value_fingerprint: Optional[str]
    score: float
    table: Optional[str]
```

`classification` is the most specific class that applies: a card number is
`PCI` even though it is also personal data; an Aadhaar number in a
`patient_records` table is `PHI`; an email address in a `customers` table
is `PII`.

### 2. Classification is partly contextual, not only type-driven

A type-only classification would be wrong in both directions. A person's
name in `patient_records` is PHI; an email address in `patient_records` is
PHI too, because HIPAA treats the identifiers of an individual as protected
whether or not the value itself is medical.

So classification combines three signals:

1. **Entity type** — `PCI_PAN` is always PCI, `PHI_MEDICAL_RECORD_NUMBER`
   is always PHI.
2. **Column name** — a column called `diagnosis`, `mrn`, `card_number`,
   `cvv` or `expiry` implies its domain. This is checked against the leaf
   path *and* its root key, so `metadata.card.cvv` is still recognised.
3. **Relation name** — a table called `patient_records`, `encounters`,
   `claims` or `transactions` implies a domain for the whole relation.

The domain inference lives in `backend/app/compliance/context.py` as two
hint tables. Signals 2 and 3 are what upgrade a generic `PERSON_NAME` to
PHI.

**Type beats context.** Context never downgrades. A 16-digit number that
passes the Luhn checksum is a card number wherever it sits, including in a
table called `loyalty_points`; the shape is the stronger evidence, and
downgrading it on the strength of a table name would be guesswork. Context
only ever *upgrades* a generic type into a domain class. The precedence
rule is therefore:

```
if pii_type is domain-specific:      class = that domain
elif column hint matches:            class = that domain
elif relation hint matches:          class = that domain
else:                                class = PII
```

with `PII` as the floor. A value can therefore never be *less* protected
than the plain personal-data class, which is the safe direction to err in.

### 3. New entity types

**PHI** (`backend/app/detectors/phi.py`, `clinical.py`):

| Type | What it is | How it is found |
| --- | --- | --- |
| `PHI_MEDICAL_RECORD_NUMBER` | MRN / hospital record number | Labelled identifier, context-gated |
| `PHI_HEALTH_PLAN_ID` | Health-plan or member ID, including Ayushman Bharat PMJAY IDs | Labelled identifier, context-gated |
| `PHI_MEDICAL_LICENSE` | Provider licence number | Labelled identifier, context-gated |
| `PHI_DEVICE_ID` | Device, implant or serial identifier | Labelled identifier, context-gated |
| `PHI_DATE_OF_BIRTH` | Date of birth | `DOB` / "date of birth" context |
| `PHI_DIAGNOSIS` | Clinical condition | Condition lexicon, clinical context required |
| `PHI_MEDICATION` | Medication or drug | Drug lexicon, clinical context required |

**PCI** (`backend/app/detectors/pci.py`):

| Type | What it is | How it is found |
| --- | --- | --- |
| `PCI_PAN` | Primary account number | 13–19 digits, separators allowed, Luhn valid |
| `PCI_CVV` | Card verification value | 3–4 digits, `cvv`/`cvc`/`csc` label required |
| `PCI_EXPIRY` | Card expiry date | `MM/YY` under an expiry label |

There is no `PCI_CARDHOLDER_NAME` recognizer. A cardholder's name is a
person's name, and the scanner already detects those with the NER
recognizer; deciding that a name is cardholder data needs the row context
the cell-by-cell scanner does not have. The column and relation hints
already do the job: a `cardholder_name` column, or any name in a
`payments` relation, is classified `PCI` without a second recognizer and
without restructuring the scan pipeline.

`PCI_PAN` replaces Presidio's stock `CreditCardRecognizer`, which is removed
from the registry. Reporting the same number as both `CREDIT_CARD` and
`PCI_PAN` would double-count it in every report.

The Indian identifiers stay distinct by construction: the Indian PAN is
letters and digits, the Aadhaar is 12 digits, an Indian mobile is 10 digits
— and a PCI PAN is 13 to 19 digits. A number of the wrong length is never
a card number. The Luhn check then removes roughly nine in ten candidates.

### 3a. Non-text columns

The flattener in `db/json_utils.py` deliberately skips non-string leaves,
so a `dob DATE` column and a `card_number BIGINT` column are invisible to
every recognizer. Card numbers really are often stored as integers, so
this needs a rule.

**Numeric and date leaves are scanned only in columns whose name marks them
as identifiers** — `card_number`, `cvv`, `mrn`, `aadhaar`, `pan`,
`patient_id`, `phone`, `pincode`, `zip` and the like. This is deliberately
narrow: emitting every numeric column as text would turn every `bigint`
primary key into a digit string for the recognisers to chew on, which is
exactly the false-positive surface the earlier design decision closed.

The rule lives in the compliance layer, not in the flattener.
`row_to_text_fields` gains an optional predicate over the root column key;
when it is absent the current behaviour is unchanged, so the flattener
stays generic and knows nothing about compliance domains.

### 3b. Overlap and degraded mode

The new recognizers are plain Python — regex plus context logic — with no
dependency on Presidio or spaCy. That has two consequences:

- They run in **both** modes. When Presidio or the spaCy model is
  unavailable and the scanner falls back to regex-only detection, PCI and
  PHI detection still work. A silent hole where card data becomes
  invisible is not acceptable.
- Overlaps with stock recognizers are resolved explicitly. `PHI_DATE_OF_BIRTH`
  wins over a `DATE_TIME` on the same span, because a date of birth is a
  more specific fact than a date. The generic overlap resolver keeps the
  highest-scoring span, so the specific recognizers are given scores above
  the stock ones they overlap with.

### 4. The context-gated recognizer

One base class, `ContextGatedRecognizer`, does the work for all of the
new rules. Each rule is a regex with exactly one capture group marking the
value; the recognizer reports the group's span, not the whole match. It
then looks for context words in a window around the match — by default 48
characters before and 24 after — and scores the finding accordingly:

- context found → score 0.85 (reported)
- no context → score 0.05 (dropped by the score threshold)

That is what makes "cancer" a finding in `diagnosis: carcinoma of the lung`
and not in `Cancer Research Institute, Bengaluru`.

Clinical context words are `patient`, `diagnosis`, `diagnosed`,
`condition`, `prescription`, `prescribed`, `medication`, `symptom`,
`treatment`, `prognosis`, `admitted`, `discharge`, `discharged`, `clinic`,
`hospital`, `ward`, `icu`, `therapy`, `test results`, `report`, and the
condition terms themselves.

### 5. The control catalogue

Seven frameworks, each a list of controls in
`backend/app/compliance/frameworks.py`:

```python
@dataclass(frozen=True)
class Control:
    id: str                    # "164.308(a)(3)(ii)(B)", "3.3.1", "Art. 9(1)"
    title: str
    category: str              # "Administrative Safeguards", "Requirement 3"
    severity: str              # critical | high | medium | low | informational
    description: str           # what the control requires
    remediation: str           # what to do about it
    triggers: Tuple[str, ...]  # entity types or "class:PHI" that fail it
    verifiable: bool           # True if absence of findings is evidence of compliance
```

`verifiable` is the honesty mechanism. A control like "audit controls
(§164.312(b))" cannot be judged by looking at a table of patient records;
it is reported as `REVIEW`, meaning *a human needs to check this*, never as
`PASS`. A control like "PAN must be masked when displayed" is verifiable —
if no card numbers are found, there is nothing to mask.

A control's status resolves as:

- **FAIL** — a finding of a triggering type exists.
- **PASS** — verifiable, and no triggering finding.
- **REVIEW** — not verifiable from data alone.
- **NOT_APPLICABLE** — the framework does not apply to this data at all.

#### Applicability

Each framework declares which classes it governs. The framework is
applicable when at least one finding of a governed class exists; otherwise
it is `NOT_APPLICABLE` and its controls are not listed at all.

| Framework | Governs | Always applicable |
| --- | --- | --- |
| HIPAA | PHI | no |
| PCI DSS | PCI | no |
| GDPR | PII, PHI, PCI | no |
| DPDP Act 2023 | PII, PHI, PCI | no |
| CCPA / CPRA | PII, PCI | no |
| SOC 2 | PII, PHI, PCI | yes |
| ISO/IEC 27001 | PII, PHI, PCI | yes |

SOC 2 and ISO 27001 are management-system frameworks: their controls are
about governance, access and monitoring rather than about the content of a
table, so nearly all of them resolve to `REVIEW` whether or not the data is
sensitive. Listing them only when there is something to say would hide
them; excluding them when there is no matching data would be arbitrary, so
they are always applicable.

Roughly 70 controls are curated across the seven frameworks — the
data-protection ones a scan can speak to, plus the operational ones marked
`REVIEW`. Every GDPR article and every ISO 27001 clause is not included;
the catalogue covers the controls that bear on stored data.

### 6. Mapping findings to controls

A trigger is either an entity type (`"PCI_PAN"`) or a class
(`"class:PHI"`). The assessor resolves each trigger against the scan
result:

- an entity-type trigger matches findings with that `pii_type`
- a class trigger matches findings with that `classification`

That is what lets HIPAA controls fire on `PERSON_NAME` findings in a
patient table without making `PERSON_NAME` globally PHI.

### 7. The assessment

```python
class ControlAssessment(BaseModel):
    id: str
    title: str
    category: str
    status: str            # PASS | FAIL | REVIEW | NOT_APPLICABLE
    severity: str
    description: str
    remediation: str
    evidence: str          # human-readable, no raw values
    finding_types: List[str]
    occurrences: int

class FrameworkAssessment(BaseModel):
    framework: str          # "HIPAA"
    name: str
    version: str
    status: str
    controls_total: int
    controls_failed: int
    controls_review: int
    controls_passed: int
    findings_matched: int
    controls: List[ControlAssessment]

class ComplianceAssessment(BaseModel):
    overall_status: str
    summary: str
    db_type: str
    table_name: str
    total_rows_scanned: int
    total_findings: int
    findings_by_type: Dict[str, int]
    findings_by_classification: Dict[str, int]
    risk_level: str
    frameworks: List[FrameworkAssessment]
    recommended_actions: List[str]
    tables: List[TableSummary]
```

`recommended_actions` is the remediation text of every failed control,
deduplicated and ordered by severity and then by how many findings backed
it — the thing a reader acts on first.

#### Two status vocabularies, one authority

`risk_level` and `overall_status` are different things and both stay.

`risk_level` keeps its existing meaning — `Low`, `Medium`, `High` — so the
badge the frontend already renders and the rule the MCP tool docstring
already states do not change underneath their users. It is extended in one
direction only: findings classified `PHI` or `PCI` also raise it to High,
because a stored card number is plainly High risk and was previously only
Medium (a credit card was detected as `CREDIT_CARD`, which is not in the
government-identifier set).

`overall_status` is new and uses the compliance vocabulary:
`COMPLIANT`, `NON_COMPLIANT`, `NEEDS_REVIEW`, `NOT_APPLICABLE`. It is
derived from the control statuses: any `FAIL` makes it `NON_COMPLIANT`;
otherwise any `REVIEW` makes it `NEEDS_REVIEW`; otherwise `COMPLIANT`.

Individual controls use the control vocabulary: `PASS`, `FAIL`, `REVIEW`,
`NOT_APPLICABLE`. The two vocabularies are never mixed in one field.

### 8. The audit file

`POST /api/audit-report` returns the same assessment rendered as a
self-contained file. `format` selects `html` or `markdown`.

The HTML is one file with inline CSS and a print stylesheet — no scripts, no
external fonts, nothing to fetch. It opens in a browser and prints to PDF
without further work. Sections: header with the database and scan scope,
an overall status block, a per-framework summary table, then each
framework's control table with status, evidence and remediation, then the
recommended actions. The Markdown version carries the same content for
pipelines and agents.

### 9. Interfaces

**HTTP**

| Endpoint | Purpose |
| --- | --- |
| `POST /api/scan` | Scan; findings now carry `classification` and `regulations` |
| `POST /api/compliance-report` | Scan + full assessment, all frameworks or a selected set |
| `POST /api/audit-report` | The downloadable audit file (HTML or Markdown) |
| `GET /api/frameworks` | The supported frameworks and their control counts |

**MCP**

`get_compliance_report` gains a `frameworks` parameter and returns the
extended compliance report: the existing fields plus `frameworks`,
`overall_status`, `findings_by_classification` and `recommended_actions`.
The old `summary` string stays, so an agent that reads prose still works.
`scan_database_for_pii` returns the new finding fields. A new
`get_audit_report` tool returns the audit file as text for agents that need
to write it somewhere — the HTTP endpoint returns the same content with the
right download headers.

`ScanRequest` gains `categories` (`["PII", "PHI", "PCI"]`, default all) so
a caller can ask only for the classes it cares about. The filter is applied
**after** classification, not at detection time, and it applies to the
assessment as well: a PHI-free scan leaves HIPAA `NOT_APPLICABLE`. Because
classification is contextual, the finding count for a given category
depends on the relation it was found in — `categories=["PII"]` on a patient
table returns fewer findings than on a customer table, and that is correct.

The existing response contracts are **extended, not replaced**.
`ComplianceReport` keeps every field it has today.

### 10. Seed data

Each engine gains two tables so the features are demonstrable:

- `patient_records` — MRN, name, DOB, phone, email, diagnosis, medication,
  provider name and licence, health-plan ID, device serial, notes.
- `payments` — cardholder name, card number, expiry, CVV, amount, billing
  postcode, customer email.

Card numbers and CVVs are stored as text so they survive the flattener;
the seed data demonstrates the common case, and the numeric-column rule in
§3a covers the `BIGINT` case for real schemas.

ClickHouse gets a `patient_records` MergeTree table and a `payments`
MergeTree table; MongoDB gets `patients` and `payments` collections with
nested documents; SQLite's `seed_sqlite.py` gains both tables and its
view. The same eight patient rows and eight payment rows are used
everywhere, so the reports are comparable across engines.

### 11. Frontend

The scan form gains two chip rows: **Categories** (PII / PHI / PCI) and
**Frameworks** (the seven, default all), plus a second action button,
**Compliance report**, alongside **Scan for PII**.

The two buttons hit two different endpoints — `/api/scan` and
`/api/compliance-report` — and each performs exactly one scan. The
compliance endpoint returns the findings *and* the assessment in one
response, so the assessment never comes from a second pass over the
database.

The results view gains a **Regulatory assessment** section below the
per-table summary: one card per framework with its status and control
counts, an expandable control table per framework showing status, evidence
and remediation, the recommended actions, and a **Download audit report**
button.

### 12. Testing

The repository has no test infrastructure today. This feature adds it.

**Unit tests** (`backend/tests/`) cover the pure logic, with no database
and no network: the Luhn check, PCI PAN length and separator handling,
context gating (that "Cancer Research Institute" is not a diagnosis but
"diagnosis: carcinoma" is), the classification precedence rule, the
applicability rule, control-status resolution, the two status
vocabularies, and the HTML and Markdown renderers. pytest and httpx are
added to `backend/requirements.txt`.

**Integration tests** (`backend/tests/integration/`) run against the five
live databases in Docker Compose: the same assertions per engine — the
relations that are listed, the PHI and PCI findings that appear, the
absence of raw values in any response, and the assessment the report
produces. They are skipped, not failed, when the databases are not
reachable, so the unit suite still runs on a bare checkout.

A `tests` service in `docker-compose.yml` runs the whole suite on demand:

```bash
docker compose --profile test run --rm tests
```

### Layout

```
backend/app/
  detectors/
    __init__.py
    context_gated.py   # the context-gated recognizer base
    phi.py             # PHI identifier recognizers
    pci.py             # PCI recognizers
    clinical.py        # clinical condition and medication lexicons
  compliance/
    __init__.py
    models.py          # Control, ControlAssessment, FrameworkAssessment, ...
    frameworks.py      # the seven control catalogues
    mapping.py         # entity type -> class -> regulations
    context.py         # column and relation domain hints
    assessor.py        # ScanReport -> ComplianceAssessment
    rendering.py       # HTML and Markdown audit file templates
  pii_detector.py      # registers the new recognizers
  models.py            # extended Finding, ScanRequest, ComplianceReport
  mcp_server.py        # classification and assessment wiring
  main.py              # /api/audit-report, /api/frameworks
backend/tests/
  conftest.py
  test_detectors.py
  test_classification.py
  test_assessor.py
  test_rendering.py
  integration/
    test_engines.py
```

## Decisions I made

- **Presidio's stock `CreditCardRecognizer` is removed** in favour of a
  single `PCI_PAN` recognizer with a strict length and Luhn check. Two
  entities for one card number would double-count it everywhere.
- **Conditions are context-gated, not globally matched** — the user's choice,
  and the difference between a useful scan and a noisy one.
- **Type beats context, and context never downgrades.** A Luhn-valid
  16-digit number is a card number wherever it sits; a table name is weaker
  evidence than a checksum.
- **Controls that a scan cannot verify report `REVIEW`, never `PASS`.** A
  scanner that claims a passing audit control it cannot see is worse than
  one that says "check this".
- **The audit file is generated server-side** as one self-contained
  document, rather than assembled in the browser, so the same bytes can be
  emailed, archived or piped into a pipeline.
- **The catalogue is curated (~70 controls), not exhaustive.** Listing all
  99 GDPR articles or all 93 ISO 27001 clauses would bury the data-exposure
  controls that a scan can actually speak to.
- **The new recognizers are standalone Python**, so PCI and PHI detection
  survives the degraded, no-Presidio path instead of silently vanishing.
- **Existing contracts are extended, not replaced.** `Finding` gains two
  fields, `ComplianceReport` gains four, and every field that exists today
  still exists with the same meaning.
- **The flattener stays generic.** Numeric columns are scanned only when
  the compliance layer asks for them, by predicate.

## Left for the builder

- Exact control wording for each of the seven frameworks, and the severity
  assigned to each.
- The clinical condition and medication lexicons, and the clinical context
  word list.
- The precise separator handling for PCI PAN candidates.

