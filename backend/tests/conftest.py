"""Shared fixtures for the Secure MCP Scanner test suite."""

from __future__ import annotations

import os
import sys
from typing import List, Optional

import pytest

# Make the application package importable when pytest is run from the
# backend directory or from anywhere else.
BACKEND_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)

from app.models import Finding, ScanReport, TableSummary  # noqa: E402


def make_finding(
    pii_type: str,
    classification: str = "PII",
    column: str = "email",
    row: int = 1,
    table: str = "customers",
    score: float = 0.9,
) -> Finding:
    """Build a finding with no raw value in it.

    The scanner never returns a real value, so neither do the fixtures:
    a test that wanted to check for a leak would be checking against a
    value that was never there.
    """
    return Finding(
        column=column,
        row=row,
        pii_type=pii_type,
        classification=classification,
        regulations=[],
        masked_value="[REDACTED]",
        score=score,
        table=table,
        value_fingerprint="deadbeef00",
    )


def make_report(
    findings: Optional[List[Finding]] = None,
    table_name: str = "customers",
    rows: int = 10,
    db_type: str = "postgres",
    risk_level: str = "Medium",
) -> ScanReport:
    """Build a scan report around a list of findings."""
    findings = findings or []
    by_type = {}
    by_classification = {}
    for finding in findings:
        by_type[finding.pii_type] = by_type.get(finding.pii_type, 0) + 1
        by_classification[finding.classification] = (
            by_classification.get(finding.classification, 0) + 1
        )
    return ScanReport(
        table_name=table_name,
        total_rows_scanned=rows,
        total_findings=len(findings),
        findings_by_type=by_type,
        findings_by_classification=by_classification,
        risk_level=risk_level,
        findings=findings,
        db_type=db_type,
        scanned_all_tables=False,
        tables=[
            TableSummary(
                table_name=table_name,
                kind="table",
                total_rows_scanned=rows,
                total_findings=len(findings),
                risk_level=risk_level,
            )
        ],
    )


@pytest.fixture
def finding_factory():
    """Return the :func:`make_finding` helper."""
    return make_finding


@pytest.fixture
def report_factory():
    """Return the :func:`make_report` helper."""
    return make_report


@pytest.fixture
def empty_report(report_factory):
    """A scan that found nothing."""
    return report_factory()


@pytest.fixture
def mixed_report(report_factory):
    """A scan with one finding of each class."""
    return report_factory(
        [
            make_finding("EMAIL", "PII", column="email"),
            make_finding("PHI_DIAGNOSIS", "PHI", column="diagnosis"),
            make_finding("PCI_PAN", "PCI", column="card_number"),
        ],
        table_name="patient_records",
        rows=8,
    )
