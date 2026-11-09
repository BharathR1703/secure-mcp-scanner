"""Pydantic models shared by the FastAPI endpoints and MCP tools."""

from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ScanRequest(BaseModel):
    """Request body for the scan endpoints.

    ``table_name`` is optional: when it is omitted the scanner walks every
    table and view in the database and returns a per-table breakdown.
    """

    connection_string: str = Field(
        ...,
        description=(
            "Database DSN. The engine is inferred from the scheme: "
            "postgresql://, mysql://, sqlite://, clickhouse:// or mongodb://"
        ),
    )
    table_name: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Table or view to scan. Omit to scan every table.",
    )
    limit: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Maximum number of rows to sample from each table",
    )
    db_type: Optional[str] = Field(
        default=None,
        description="Force an engine instead of inferring it from the DSN",
    )
    max_tables: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Maximum number of tables to scan in a bulk scan",
    )
    categories: Optional[List[str]] = Field(
        default=None,
        description=(
            "Restrict the results to these regulatory classes: PII, PHI "
            "and/or PCI. The filter is applied after classification, so "
            "the same value can be PII in one relation and PHI in another."
        ),
    )
    frameworks: Optional[List[str]] = Field(
        default=None,
        description=(
            "Restrict the compliance assessment to these frameworks: "
            "HIPAA, PCI_DSS, GDPR, DPDP, CCPA, SOC2 and/or ISO27001. "
            "Omit to assess all of them."
        ),
    )


class Finding(BaseModel):
    """A single instance of regulated data found in a cell.

    The value itself is never returned.
    """

    column: str
    row: int
    pii_type: str
    classification: str = Field(
        default="PII",
        description=(
            "The regulatory class of the value: PII (personal data), "
            "PHI (protected health information) or PCI (cardholder data)."
        ),
    )
    regulations: List[str] = Field(
        default_factory=list,
        description="The frameworks that care about this class of data.",
    )
    masked_value: str
    score: float = 0.0
    table: Optional[str] = Field(
        default=None, description="Table or collection the finding came from"
    )
    value_fingerprint: Optional[str] = Field(
        default=None,
        description=(
            "Short non-reversible fingerprint of the detected value. Equal "
            "fingerprints mean the same value was found in more than one place."
        ),
    )


class TableSummary(BaseModel):
    """Per-table totals for a bulk scan."""

    table_name: str
    kind: str = "table"
    total_rows_scanned: int = 0
    total_findings: int = 0
    risk_level: str = "Low"


class ScanReport(BaseModel):
    """Structured report produced by the ``scan_database_for_pii`` tool."""

    table_name: str
    total_rows_scanned: int
    total_findings: int
    findings_by_type: Dict[str, int] = Field(default_factory=dict)
    findings_by_classification: Dict[str, int] = Field(default_factory=dict)
    risk_level: str = "Low"
    findings: List[Finding] = Field(default_factory=list)
    db_type: str = "postgres"
    scanned_all_tables: bool = False
    tables: List[TableSummary] = Field(default_factory=list)


class ControlAssessment(BaseModel):
    """The result of assessing one control against a scan."""

    id: str
    title: str
    category: str
    status: str
    severity: str
    description: str
    remediation: str
    evidence: str = ""
    finding_types: List[str] = Field(default_factory=list)
    occurrences: int = 0


class FrameworkAssessment(BaseModel):
    """The result of assessing one framework against a scan."""

    framework: str
    name: str
    version: str
    status: str
    applicable: bool = True
    controls_total: int = 0
    controls_failed: int = 0
    controls_review: int = 0
    controls_passed: int = 0
    findings_matched: int = 0
    controls: List[ControlAssessment] = Field(default_factory=list)


class ComplianceReport(BaseModel):
    """Compliance summary produced by ``get_compliance_report``.

    Every field this report had before the regulatory assessment was
    added still exists with the same meaning. The assessment is
    additive: ``frameworks``, ``overall_status``,
    ``findings_by_classification`` and ``recommended_actions``.
    """

    table_name: str
    total_rows_scanned: int
    total_findings: int
    findings_by_type: Dict[str, int] = Field(default_factory=dict)
    findings_by_classification: Dict[str, int] = Field(default_factory=dict)
    risk_level: str = "Low"
    summary: str
    db_type: str = "postgres"
    tables: List[TableSummary] = Field(default_factory=list)
    overall_status: str = "NOT_APPLICABLE"
    frameworks: List[FrameworkAssessment] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)


class TableInfo(BaseModel):
    """One relation available for scanning.

    The wire format calls the schema ``schema``, but ``schema`` is a
    deprecated attribute of pydantic's ``BaseModel``, and a field that
    shadows it earns a warning on every import. The field is therefore
    named ``schema_name`` and aliased, so the JSON a client sees is
    unchanged.
    """

    model_config = ConfigDict(populate_by_name=True)

    name: str
    schema_name: Optional[str] = Field(
        default=None,
        alias="schema",
        serialization_alias="schema",
    )
    kind: str = "table"
    qualified_name: str


class TableListResponse(BaseModel):
    """Every relation the scanner can reach in a database."""

    db_type: str
    tables: List[TableInfo] = Field(default_factory=list)
