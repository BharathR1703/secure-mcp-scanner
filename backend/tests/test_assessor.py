"""Tests for the control assessor.

Two vocabularies are in play and they are never mixed in one field:
``risk_level`` (Low/Medium/High) and ``overall_status``
(COMPLIANT/NON_COMPLIANT/NEEDS_REVIEW/NOT_APPLICABLE). Individual
controls use PASS, FAIL, REVIEW and NOT_APPLICABLE.
"""

from __future__ import annotations

import pytest

from app.compliance import assess
from app.compliance.frameworks import FRAMEWORKS, total_control_count
from app.compliance.models import (
    OVERALL_NEEDS_REVIEW,
    OVERALL_NON_COMPLIANT,
    STATUS_FAIL,
    STATUS_NOT_APPLICABLE,
    STATUS_PASS,
    STATUS_REVIEW,
)
from app.models import Finding


def finding(pii_type, classification, column, table, row=1, score=0.9):
    """A finding with no raw value in it."""
    return Finding(
        column=column,
        row=row,
        pii_type=pii_type,
        classification=classification,
        regulations=[],
        masked_value="[REDACTED]",
        score=score,
        table=table,
    )


def pii_finding(row=1):
    return finding("EMAIL", "PII", "email", "customers", row=row)


def phi_finding(row=1):
    return finding(
        "PHI_DIAGNOSIS", "PHI", "diagnosis", "patient_records", row=row, score=0.85
    )


def pci_finding(row=1):
    return finding("PCI_PAN", "PCI", "card_number", "payments", row=row, score=0.98)


def cvv_finding(row=1):
    return finding("PCI_CVV", "PCI", "cvv", "payments", row=row, score=0.85)


def control(report, framework_key, control_id):
    """Find one control assessment by framework and control id."""
    for framework in report.frameworks:
        if framework.framework != framework_key:
            continue
        for item in framework.controls:
            if item.id == control_id:
                return item
    raise AssertionError(
        f"control {control_id} not found in framework {framework_key}"
    )


# ---------------------------------------------------------------------------
# Catalogue
# ---------------------------------------------------------------------------


def test_the_catalogue_covers_seven_frameworks():
    assert len(FRAMEWORKS) == 7


def test_the_catalogue_has_controls():
    assert total_control_count() >= 90


def test_every_control_has_a_remediation():
    for framework in FRAMEWORKS.values():
        for item in framework.controls:
            assert item.remediation, f"{framework.key} {item.id}"


def test_every_framework_has_at_least_one_control():
    for framework in FRAMEWORKS.values():
        assert framework.control_count() > 0, framework.key


# ---------------------------------------------------------------------------
# Applicability
# ---------------------------------------------------------------------------


def test_hipaa_is_not_applicable_without_health_data(report_factory):
    report = report_factory([pii_finding()])
    assessment = assess(report)
    hipaa = next(f for f in assessment.frameworks if f.framework == "HIPAA")
    assert hipaa.applicable is False
    assert hipaa.status == STATUS_NOT_APPLICABLE
    assert hipaa.controls_total == 0


def test_pci_is_not_applicable_without_card_data(report_factory):
    report = report_factory([pii_finding()])
    assessment = assess(report)
    pci = next(f for f in assessment.frameworks if f.framework == "PCI_DSS")
    assert pci.applicable is False


def test_hipaa_is_applicable_with_health_data(report_factory):
    report = report_factory([phi_finding()])
    assessment = assess(report)
    hipaa = next(f for f in assessment.frameworks if f.framework == "HIPAA")
    assert hipaa.applicable is True
    assert hipaa.controls_total > 0


def test_management_frameworks_are_always_applicable(report_factory):
    assessment = assess(report_factory([]))
    for key in ("SOC2", "ISO27001"):
        framework = next(f for f in assessment.frameworks if f.framework == key)
        assert framework.applicable is True


def test_an_empty_scan_still_needs_review(report_factory):
    """Nothing was found, but the management frameworks still need a human."""
    assessment = assess(report_factory([]))
    assert assessment.overall_status == OVERALL_NEEDS_REVIEW


# ---------------------------------------------------------------------------
# Control statuses
# ---------------------------------------------------------------------------


def test_a_triggered_control_fails(report_factory):
    report = report_factory([pci_finding()])
    assessment = assess(report, ["PCI_DSS"])
    assert control(assessment, "PCI_DSS", "3.4.1").status == STATUS_FAIL


def test_a_cvv_fails_the_retention_control(report_factory):
    report = report_factory([cvv_finding()])
    assessment = assess(report, ["PCI_DSS"])
    assert control(assessment, "PCI_DSS", "3.3.3").status == STATUS_FAIL


def test_health_data_fails_the_de_identification_control(report_factory):
    """Safe Harbor covers the identifiers, so a record number trips it."""
    report = report_factory(
        [
            finding(
                "PHI_MEDICAL_RECORD_NUMBER",
                "PHI",
                "mrn",
                "patient_records",
                score=0.85,
            )
        ]
    )
    assessment = assess(report, ["HIPAA"])
    assert control(assessment, "HIPAA", "164.514(b)").status == STATUS_FAIL


def test_a_diagnosis_is_not_a_safe_harbor_identifier(report_factory):
    """A diagnosis is health data, but it is not one of the eighteen."""
    report = report_factory([phi_finding()])
    assessment = assess(report, ["HIPAA"])
    assert control(assessment, "HIPAA", "164.514(b)").status == STATUS_PASS


def test_an_unverifiable_control_is_never_a_pass(report_factory):
    """A scan cannot prove an operational control was met."""
    report = report_factory([phi_finding()])
    assessment = assess(report, ["HIPAA"])
    assert control(assessment, "HIPAA", "164.312(a)(1)").status == STATUS_REVIEW


def test_a_verifiable_control_passes_when_nothing_trips_it(report_factory):
    """Data minimisation is judged by the data; no Aadhaar means no breach."""
    report = report_factory([pii_finding()])
    assessment = assess(report, ["GDPR"])
    assert control(assessment, "GDPR", "Art. 5(1)(c)").status == STATUS_PASS


def test_the_overall_status_is_non_compliant_when_a_control_fails(report_factory):
    report = report_factory([pci_finding()])
    assessment = assess(report, ["PCI_DSS"])
    assert assessment.overall_status == OVERALL_NON_COMPLIANT


def test_the_overall_status_is_needs_review_when_nothing_fails(report_factory):
    report = report_factory([pii_finding()])
    assessment = assess(report, ["GDPR"])
    assert assessment.overall_status == OVERALL_NEEDS_REVIEW


# ---------------------------------------------------------------------------
# Evidence and recommendations
# ---------------------------------------------------------------------------


def test_evidence_never_contains_a_raw_value(report_factory):
    report = report_factory([pci_finding()])
    assessment = assess(report, ["PCI_DSS"])
    evidence = control(assessment, "PCI_DSS", "3.4.1").evidence
    assert "4111111111111111" not in evidence
    assert "PCI_PAN" in evidence


def test_a_failed_control_produces_a_recommendation(report_factory):
    report = report_factory([pci_finding()])
    assessment = assess(report, ["PCI_DSS"])
    assert assessment.recommended_actions
    assert any(
        "tokenis" in action.lower() for action in assessment.recommended_actions
    )


def test_recommendations_are_deduplicated(report_factory):
    report = report_factory(
        [pci_finding(row=1), pci_finding(row=2), cvv_finding(row=3)]
    )
    assessment = assess(report, ["PCI_DSS"])
    assert len(assessment.recommended_actions) == len(
        set(assessment.recommended_actions)
    )


def test_the_summary_mentions_the_classifications(report_factory):
    report = report_factory([phi_finding(), pci_finding()])
    assessment = assess(report)
    assert "PHI" in assessment.summary
    assert "PCI" in assessment.summary


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------


def test_an_unknown_framework_is_rejected(report_factory):
    with pytest.raises(ValueError, match="unknown framework"):
        assess(report_factory([]), ["NOPE"])


def test_only_the_requested_frameworks_are_assessed(report_factory):
    assessment = assess(report_factory([]), ["GDPR"])
    assert [f.framework for f in assessment.frameworks] == ["GDPR"]


def test_frameworks_are_reported_in_a_fixed_order(report_factory):
    assessment = assess(report_factory([]))
    keys = [f.framework for f in assessment.frameworks]
    assert keys.index("HIPAA") < keys.index("PCI_DSS") < keys.index("GDPR")
