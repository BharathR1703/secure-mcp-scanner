"""MCP server exposing database PII scanning tools.

The same tool implementations back both the MCP server (stdio via
``python -m app.mcp_server``; SSE when mounted by the FastAPI app) and the
HTTP endpoints, so results are identical no matter which transport an agent
uses. All values are masked before they leave the process.

Scanning is database-agnostic: the engine is inferred from the connection
string and the same pipeline runs against Postgres, MySQL, SQLite,
ClickHouse and MongoDB.

One scan produces every classification. Each finding is classified as
personal data (PII), protected health information (PHI) or cardholder
data (PCI), and the compliance report reads from that single result --
there is no second pass over the database and no way for the findings and
the assessment to disagree.
"""

import logging
from collections import Counter
from typing import Any, Dict, List, Optional, Sequence

from mcp.server.fastmcp import FastMCP

from .compliance import assess
from .compliance.context import should_scan_non_text
from .compliance.frameworks import FRAMEWORKS, framework_summaries
from .compliance.mapping import FRAMEWORK_ORDER, classify
from .db import TableRef, get_adapter, parse_table_ref, row_to_text_fields
from .db_connector import list_tables
from .models import (
    ComplianceReport,
    Finding,
    ScanReport,
    TableInfo,
    TableListResponse,
    TableSummary,
)
from .pii_detector import MASK, detect_pii, fingerprint

logger = logging.getLogger(__name__)

mcp = FastMCP(
    "secure-mcp-scanner",
    instructions=(
        "Scan databases for personally identifiable information (PII), "
        "protected health information (PHI) and cardholder data (PCI). "
        "Supports Postgres, MySQL, SQLite, ClickHouse and MongoDB; the "
        "engine is inferred from the connection string. Detected values are "
        "always replaced with [REDACTED] before any data is returned, so raw "
        "regulated data never leaves this server. Use get_compliance_report "
        "for a control-level assessment across HIPAA, PCI DSS, GDPR, DPDP, "
        "CCPA, SOC 2 and ISO 27001, and get_audit_report for a "
        "downloadable audit file."
    ),
)

#: Risk thresholds. Any finding warrants attention, and Indian government
#: identifiers (PAN / Aadhaar) are escalated to High regardless of count.
GOVERNMENT_ID_TYPES = {"PAN", "AADHAAR"}
MEDIUM_FINDING_THRESHOLD = 20

#: The regulatory classes a caller can ask for.
CATEGORIES = ("PII", "PHI", "PCI")

_RISK_ORDER = {"Low": 0, "Medium": 1, "High": 2}


def compute_risk_level(findings: List[Finding]) -> str:
    """Map findings to a Low / Medium / High risk level.

    Protected health information and cardholder data are High risk. A
    stored card number used to come out as a generic credit card, which
    is not a government identifier, and so was rated Medium. It plainly
    is not.
    """
    if not findings:
        return "Low"
    if any(finding.pii_type in GOVERNMENT_ID_TYPES for finding in findings):
        return "High"
    if any(finding.classification in ("PHI", "PCI") for finding in findings):
        return "High"
    if len(findings) <= MEDIUM_FINDING_THRESHOLD:
        return "Medium"
    return "High"


def _combine_risk(levels: List[str]) -> str:
    """Return the most severe risk level in ``levels``."""
    if not levels:
        return "Low"
    return max(levels, key=lambda level: _RISK_ORDER.get(level, 0))


def _validate_categories(categories: Optional[Sequence[str]]) -> Optional[set]:
    """Normalise the requested regulatory classes.

    ``None`` and an empty list both mean "all of them".
    """
    if not categories:
        return None
    wanted = {str(category).strip().upper() for category in categories}
    wanted.discard("")
    if not wanted:
        return None
    unknown = wanted - set(CATEGORIES)
    if unknown:
        raise ValueError(
            "unknown categories: "
            + ", ".join(sorted(unknown))
            + "; supported: "
            + ", ".join(CATEGORIES)
        )
    return wanted


def _validate_frameworks(frameworks: Optional[Sequence[str]]) -> Optional[set]:
    """Normalise the requested frameworks.

    Validation happens before the scan rather than after it: a bad
    framework name should be rejected immediately, not after a slow walk
    of the database.
    """
    if not frameworks:
        return None
    wanted = {str(framework).strip().upper() for framework in frameworks}
    wanted.discard("")
    if not wanted:
        return None
    unknown = wanted - set(FRAMEWORKS)
    if unknown:
        raise ValueError(
            "unknown framework(s): "
            + ", ".join(sorted(unknown))
            + "; supported: "
            + ", ".join(FRAMEWORK_ORDER)
        )
    return wanted


def _leaf_predicate(path: str, value: Any) -> bool:
    """Decide whether a non-text leaf is worth scanning.

    Card numbers are often stored as integers and dates of birth as
    ``DATE`` columns, so the flattener's text-only rule would hide them.
    Only columns whose name marks them as identifiers are converted, so
    that ordinary numeric columns stay out of the recognizers.
    """
    return should_scan_non_text(path)


async def _scan_relation(
    adapter, reference: TableRef, limit: int
) -> tuple[int, List[Finding]]:
    """Scan one relation and return its row count and findings."""
    rows = await adapter.fetch_rows(reference, limit)
    findings: List[Finding] = []

    for row_number, row in enumerate(rows, start=1):
        for column, text in row_to_text_fields(row, _leaf_predicate):
            detections = detect_pii(text, context=f"{column} {reference.name}")
            if not detections:
                continue
            for detection in detections:
                pii_type, classification, regulations = classify(
                    detection["type"], column, reference.name
                )
                findings.append(
                    Finding(
                        column=column,
                        row=row_number,
                        pii_type=pii_type,
                        classification=classification,
                        regulations=regulations,
                        # The whole cell is redacted, not just the matched
                        # span: a cell that holds one Aadhaar number usually
                        # holds a street address and a PIN code too, and
                        # returning the remainder of the cell would leak
                        # exactly the data this server exists to protect.
                        masked_value=MASK,
                        value_fingerprint=fingerprint(detection["value"]),
                        score=detection["score"],
                        table=reference.name,
                    )
                )
    return len(rows), findings


async def run_scan_database(
    connection_string: str,
    table_name: Optional[str] = None,
    limit: int = 100,
    db_type: Optional[str] = None,
    max_tables: int = 50,
    categories: Optional[Sequence[str]] = None,
) -> ScanReport:
    """Shared scan implementation used by MCP tools and HTTP endpoints.

    When ``table_name`` is given, only that relation is scanned. When it is
    omitted, every table and view in the database is scanned and the report
    carries a per-table breakdown.

    ``categories`` restricts the results to the named regulatory classes.
    The filter is applied after classification, so the same value counts as
    personal data in one relation and health data in another.
    """
    wanted = _validate_categories(categories)
    adapter = await get_adapter(connection_string, db_type)

    summaries: List[TableSummary] = []
    all_findings: List[Finding] = []
    total_rows = 0

    if table_name:
        schema, name = parse_table_ref(table_name, adapter.default_schema)
        references = [TableRef(schema=schema, name=name)]
        display_name = table_name
    else:
        references = (await adapter.list_tables())[:max_tables]
        display_name = "all tables"

    for reference in references:
        rows_scanned, findings = await _scan_relation(adapter, reference, limit)
        total_rows += rows_scanned
        if wanted is not None:
            findings = [f for f in findings if f.classification in wanted]
        all_findings.extend(findings)
        summaries.append(
            TableSummary(
                table_name=reference.qualified_name,
                kind=reference.kind,
                total_rows_scanned=rows_scanned,
                total_findings=len(findings),
                risk_level=compute_risk_level(findings),
            )
        )

    findings_by_type = dict(sorted(Counter(f.pii_type for f in all_findings).items()))
    findings_by_classification = dict(
        sorted(Counter(f.classification for f in all_findings).items())
    )
    risk_level = (
        compute_risk_level(all_findings)
        if table_name
        else _combine_risk([summary.risk_level for summary in summaries])
    )
    report = ScanReport(
        table_name=display_name,
        total_rows_scanned=total_rows,
        total_findings=len(all_findings),
        findings_by_type=findings_by_type,
        findings_by_classification=findings_by_classification,
        risk_level=risk_level,
        findings=all_findings,
        db_type=adapter.name,
        scanned_all_tables=table_name is None,
        tables=summaries,
    )
    logger.info(
        "Scan of %s complete: %d rows, %d findings, risk=%s, classes=%s",
        display_name,
        total_rows,
        len(all_findings),
        report.risk_level,
        findings_by_classification or "{}",
    )
    return report


async def run_list_tables(
    connection_string: str, db_type: Optional[str] = None
) -> TableListResponse:
    """List every relation the scanner can reach in a database."""
    adapter = await get_adapter(connection_string, db_type)
    references = await adapter.list_tables()
    return TableListResponse(
        db_type=adapter.name,
        tables=[
            TableInfo(
                name=reference.name,
                schema=reference.schema,
                kind=reference.kind,
                qualified_name=reference.qualified_name,
            )
            for reference in references
        ],
    )


def _build_summary(report: ScanReport) -> str:
    """The prose summary of a scan."""
    if report.total_findings == 0:
        if report.scanned_all_tables:
            return (
                f"No PII detected across {report.total_rows_scanned} scanned "
                f"row(s) in {len(report.tables)} table(s)."
            )
        return (
            f"No PII detected in {report.total_rows_scanned} row(s) of table "
            f"'{report.table_name}'."
        )
    type_list = ", ".join(
        f"{pii_type} ({count})" for pii_type, count in report.findings_by_type.items()
    )
    if report.scanned_all_tables:
        summary = (
            f"Detected {report.total_findings} PII instance(s) across "
            f"{report.total_rows_scanned} scanned row(s) in "
            f"{len(report.tables)} table(s) of the {report.db_type} database. "
            f"Types found: {type_list}."
        )
    else:
        summary = (
            f"Detected {report.total_findings} PII instance(s) across "
            f"{report.total_rows_scanned} scanned row(s) of table "
            f"'{report.table_name}'. Types found: {type_list}."
        )
    if report.risk_level == "High":
        summary += (
            " Risk is High: government identifiers (PAN/Aadhaar), protected "
            "health information or cardholder data were found, or the "
            f"number of instances exceeds {MEDIUM_FINDING_THRESHOLD}."
        )
    else:
        summary += " Risk is Medium: personal data is present and should be reviewed."
    return summary


def _risk_sentence(report: ScanReport) -> str:
    if report.risk_level == "High":
        return (
            "Risk is High: government identifiers (PAN/Aadhaar), protected "
            "health information or cardholder data were found, or the number "
            f"of instances exceeds {MEDIUM_FINDING_THRESHOLD}."
        )
    if report.total_findings == 0:
        return "Risk is Low: no personal data was detected."
    return "Risk is Medium: personal data is present and should be reviewed."


async def run_compliance_report(
    connection_string: str,
    table_name: Optional[str] = None,
    limit: int = 100,
    db_type: Optional[str] = None,
    max_tables: int = 50,
    categories: Optional[Sequence[str]] = None,
    frameworks: Optional[Sequence[str]] = None,
) -> ComplianceReport:
    """Shared compliance-report implementation used by MCP tools and HTTP.

    The scan runs once. The assessment reads from that result, so the
    findings and the control statuses can never disagree.
    """
    wanted_frameworks = _validate_frameworks(frameworks)
    report = await run_scan_database(
        connection_string, table_name, limit, db_type, max_tables, categories
    )
    assessment = assess(report, wanted_frameworks)
    summary = f"{assessment.summary} {_risk_sentence(report)}"
    return ComplianceReport(
        table_name=report.table_name,
        total_rows_scanned=report.total_rows_scanned,
        total_findings=report.total_findings,
        findings_by_type=report.findings_by_type,
        findings_by_classification=report.findings_by_classification,
        risk_level=report.risk_level,
        summary=summary,
        db_type=report.db_type,
        tables=report.tables,
        overall_status=assessment.overall_status,
        frameworks=assessment.frameworks,
        recommended_actions=assessment.recommended_actions,
        findings=report.findings,
    )


@mcp.tool()
async def scan_database_for_pii(
    connection_string: str,
    table_name: Optional[str] = None,
    limit: int = 100,
    db_type: Optional[str] = None,
    max_tables: int = 50,
    categories: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Scan a database for personal, health and cardholder data.

    Args:
        connection_string: Database DSN. The engine is inferred from the
            scheme: postgresql://, mysql://, sqlite://, clickhouse:// or
            mongodb://.
        table_name: Table or view to scan, optionally schema-qualified
            ("public.customers"). Omit to scan every table in the database.
        limit: Maximum number of rows to sample per table (1-1000, default 100).
        db_type: Force an engine instead of inferring it from the DSN.
        max_tables: Maximum tables to scan in a bulk scan (default 50).
        categories: Restrict the results to these regulatory classes:
            "PII", "PHI" and/or "PCI". Omit for all of them.

    Returns:
        A report with table_name, total_rows_scanned and findings (list of
        {column, row, pii_type, classification, regulations, masked_value,
        value_fingerprint, table}). The cell that produced a finding is
        reported as "[REDACTED]" in full -- the surrounding text is
        regulated data too -- and value_fingerprint is a short
        non-reversible token that is equal for equal values, so the same
        identifier can be traced across tables without ever being
        returned.
    """
    report = await run_scan_database(
        connection_string, table_name, limit, db_type, max_tables, categories
    )
    return report.model_dump()


@mcp.tool()
async def get_compliance_report(
    connection_string: str,
    table_name: Optional[str] = None,
    limit: int = 100,
    db_type: Optional[str] = None,
    max_tables: int = 50,
    categories: Optional[List[str]] = None,
    frameworks: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Scan a database and assess it against the regulatory frameworks.

    Risk levels: Low = no personal data found; Medium = personal data
    found; High = government identifiers, protected health information or
    cardholder data found, or more than 20 instances.

    Overall status: COMPLIANT, NON_COMPLIANT, NEEDS_REVIEW or
    NOT_APPLICABLE. Individual controls report PASS, FAIL or REVIEW; a
    control that a data scan cannot judge is always REVIEW, never PASS.

    Args:
        connection_string: Database DSN. The engine is inferred from the scheme.
        table_name: Table or view to scan. Omit to scan every table.
        limit: Maximum number of rows to sample per table (1-1000, default 100).
        db_type: Force an engine instead of inferring it from the DSN.
        max_tables: Maximum tables to scan in a bulk scan (default 50).
        categories: Restrict the results to these regulatory classes:
            "PII", "PHI" and/or "PCI". Omit for all of them.
        frameworks: Restrict the assessment to these frameworks: HIPAA,
            PCI_DSS, GDPR, DPDP, CCPA, SOC2 and/or ISO27001. Omit for all.
    """
    report = await run_compliance_report(
        connection_string,
        table_name,
        limit,
        db_type,
        max_tables,
        categories,
        frameworks,
    )
    return report.model_dump()


@mcp.tool()
async def get_audit_report(
    connection_string: str,
    table_name: Optional[str] = None,
    limit: int = 100,
    db_type: Optional[str] = None,
    max_tables: int = 50,
    categories: Optional[List[str]] = None,
    frameworks: Optional[List[str]] = None,
    format: str = "html",
) -> Dict[str, Any]:
    """Produce a downloadable audit file for a database scan.

    The file is self-contained: the HTML version has inline CSS and a
    print stylesheet, so it opens in a browser and prints to PDF with
    nothing to fetch. The Markdown version carries the same content for
    pipelines and agents. No raw personal, health or cardholder data
    appears in either.

    Args:
        connection_string: Database DSN. The engine is inferred from the scheme.
        table_name: Table or view to scan. Omit to scan every table.
        limit: Maximum number of rows to sample per table (1-1000, default 100).
        db_type: Force an engine instead of inferring it from the DSN.
        max_tables: Maximum tables to scan in a bulk scan (default 50).
        categories: Restrict the results to these regulatory classes.
        frameworks: Restrict the assessment to these frameworks.
        format: "html" or "markdown".

    Returns:
        The file content, its format and a suggested filename.
    """
    report = await run_compliance_report(
        connection_string,
        table_name,
        limit,
        db_type,
        max_tables,
        categories,
        frameworks,
    )
    content = render_audit(report, format)
    normalised = (format or "html").lower()
    extension = "md" if normalised in ("markdown", "md") else "html"
    return {
        "format": normalised,
        "filename": f"compliance-audit.{extension}",
        "content": content,
    }


@mcp.tool()
async def list_database_tables(
    connection_string: str, db_type: Optional[str] = None
) -> Dict[str, Any]:
    """List every table, view or collection available for scanning.

    Args:
        connection_string: Database DSN. The engine is inferred from the scheme.
        db_type: Force an engine instead of inferring it from the DSN.

    Returns:
        The detected engine and a list of {name, schema, kind, qualified_name}.
    """
    listing = await run_list_tables(connection_string, db_type)
    return listing.model_dump(by_alias=True)


@mcp.tool()
async def list_frameworks() -> Dict[str, Any]:
    """List the regulatory frameworks the scanner assesses against.

    Returns:
        Each framework with its name, version, the regulatory classes it
        governs and how many controls it contains.
    """
    return {"frameworks": framework_summaries()}


def render_audit(report: ComplianceReport, format: str = "html") -> str:
    """Render a compliance report as an audit file."""
    from .compliance.rendering import render

    return render(report, format)


if __name__ == "__main__":
    # Run the MCP server over stdio, e.g.:
    #   python -m app.mcp_server
    logging.basicConfig(level=logging.INFO)
    mcp.run()
