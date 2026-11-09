"""Tests for the audit-file renderers.

The audit file is the artefact a human signs off on, so two properties
matter more than the rest: it must be self-contained, and it must not
contain a single raw value.
"""

from __future__ import annotations

import re

import pytest

from app.compliance import assess
from app.compliance.rendering import render, render_html, render_markdown
from app.models import Finding

FRAMEWORK_KEYS = (
    "HIPAA",
    "PCI_DSS",
    "GDPR",
    "DPDP",
    "CCPA",
    "SOC2",
    "ISO27001",
)


def make_findings():
    """One finding of each class, and none of them holding a value."""
    return [
        Finding(
            column="email",
            row=1,
            pii_type="EMAIL",
            classification="PII",
            regulations=[],
            masked_value="[REDACTED]",
            score=0.9,
            table="customers",
        ),
        Finding(
            column="diagnosis",
            row=2,
            pii_type="PHI_DIAGNOSIS",
            classification="PHI",
            regulations=[],
            masked_value="[REDACTED]",
            score=0.85,
            table="patient_records",
        ),
        Finding(
            column="card_number",
            row=3,
            pii_type="PCI_PAN",
            classification="PCI",
            regulations=[],
            masked_value="[REDACTED]",
            score=0.98,
            table="payments",
        ),
    ]


@pytest.fixture
def assessed_report(report_factory):
    """A report with one finding of each class, assessed."""
    return assess(report_factory(make_findings()))


def test_html_is_self_contained(assessed_report):
    html = render_html(assessed_report)
    assert html.lstrip().lower().startswith("<!doctype html>")
    assert "<style>" in html
    assert "<script" not in html.lower()
    # No external fetches: no stylesheet links, no fonts, no images.
    assert "<link" not in html.lower()
    assert "http://" not in html
    assert "https://" not in html


def test_html_has_a_print_stylesheet(assessed_report):
    assert "@media print" in render_html(assessed_report)


def test_html_names_every_framework(assessed_report):
    html = render_html(assessed_report)
    for key in FRAMEWORK_KEYS:
        assert key in html, key


def test_html_contains_no_raw_values(assessed_report):
    html = render_html(assessed_report)
    assert "4111111111111111" not in html
    assert "ananya.sharma@example.com" not in html
    assert "[REDACTED]" not in html  # the report never quotes a value at all


def test_markdown_names_every_framework(assessed_report):
    markdown = render_markdown(assessed_report)
    for key in FRAMEWORK_KEYS:
        assert key in markdown, key


def test_markdown_contains_no_raw_values(assessed_report):
    markdown = render_markdown(assessed_report)
    assert "4111111111111111" not in markdown


def test_markdown_has_a_control_table(assessed_report):
    markdown = render_markdown(assessed_report)
    assert "| Control | Requirement | Status | Severity | Evidence |" in markdown


def test_render_dispatches_on_format(assessed_report):
    assert render(assessed_report, "html") == render_html(assessed_report)
    assert render(assessed_report, "markdown") == render_markdown(assessed_report)
    assert render(assessed_report, "md") == render_markdown(assessed_report)


def test_render_falls_back_to_html_for_an_unknown_format(assessed_report):
    assert render(assessed_report, "pdf") == render_html(assessed_report)


def test_the_status_of_every_control_is_rendered(assessed_report):
    html = render_html(assessed_report)
    for status in ("FAIL", "REVIEW", "PASS"):
        assert status in html


def test_the_overall_status_is_rendered(assessed_report):
    html = render_html(assessed_report)
    assert "NON_COMPLIANT" in html


def test_the_recommended_actions_are_rendered(assessed_report):
    html = render_html(assessed_report)
    assert "Recommended actions" in html


def test_the_html_escapes_what_it_is_given(report_factory):
    """A table name is data, and data is escaped before it reaches HTML."""
    report = report_factory(
        make_findings(), table_name="<script>alert(1)</script>"
    )
    assessment = assess(report)
    html = render_html(assessment)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_no_html_tag_is_left_unclosed(assessed_report):
    html = render_html(assessed_report)
    for tag in ("table", "thead", "tbody", "tr", "td", "th"):
        opening = len(re.findall(rf"<{tag}[ >]", html))
        closing = len(re.findall(rf"</{tag}>", html))
        assert opening == closing, tag
