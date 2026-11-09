"""Tests for the PHI and PCI recognizers."""

from __future__ import annotations

import pytest

from app.detectors import (
    CONTEXT_SCORE,
    NO_CONTEXT_SCORE,
    detect_phi,
    detect_pci,
    luhn_checksum_valid,
)
from app.detectors.context_gated import tokenize, whole_value_is_valid
from app.detectors.pci import PAN_MAX_DIGITS, PAN_MIN_DIGITS

#: The scanner's global score threshold. A finding below it is discarded,
#: so the tests filter on it the same way the pipeline does.
MIN_SCORE = 0.4


def significant(findings):
    """The findings that survive the scanner's score threshold."""
    return [finding for finding in findings if finding["score"] >= MIN_SCORE]


def types_of(findings):
    return [finding["type"] for finding in findings]


def values_of(findings, entity_type):
    return [
        finding["value"] for finding in findings if finding["type"] == entity_type
    ]


# ---------------------------------------------------------------------------
# Luhn
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "number",
    [
        "4111111111111111",
        "5500005555555559",
        "378282246310005",
        "4012888888881881",
        "5105101051051000",
        "2223003122003222",
        "371449635398431",
        "4222222222222",
    ],
)
def test_seeded_card_numbers_pass_luhn(number):
    assert luhn_checksum_valid(number) is True


@pytest.mark.parametrize(
    "number",
    ["4111111111111112", "1234567890123456", "5500005555555558"],
)
def test_invalid_card_numbers_fail_luhn(number):
    assert luhn_checksum_valid(number) is False


def test_a_run_of_identical_digits_is_not_a_card_number():
    """All zeros sums to zero, so it passes the checksum but is not a card."""
    assert luhn_checksum_valid("0000000000000") is True
    findings = significant(detect_pci("0000000000000", "card_number"))
    assert "PCI_PAN" not in types_of(findings)


def test_luhn_rejects_non_digits():
    assert luhn_checksum_valid("4111-1111-1111-1111") is False
    assert luhn_checksum_valid("") is False


# ---------------------------------------------------------------------------
# Primary account numbers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "number",
    [
        "4111111111111111",
        "5500 0055 5555 5559",
        "4012 8888 8888 1881",
        "3714 4963 5398 431",
        "4222 2222 2222 2",
    ],
)
def test_pan_is_detected_with_and_without_separators(number):
    findings = significant(detect_pci(number, "card_number payments"))
    assert "PCI_PAN" in types_of(findings)
    assert values_of(findings, "PCI_PAN") == [number]


def test_pan_is_not_detected_when_luhn_fails():
    # Right length, wrong checksum: an order reference, not a card number.
    findings = significant(detect_pci("4111111111111112", "card_number"))
    assert "PCI_PAN" not in types_of(findings)


def test_pan_length_bounds_are_enforced():
    too_short = "4" * (PAN_MIN_DIGITS - 1)
    too_long = "4" * (PAN_MAX_DIGITS + 1)
    assert "PCI_PAN" not in types_of(significant(detect_pci(too_short, "card_number")))
    assert "PCI_PAN" not in types_of(significant(detect_pci(too_long, "card_number")))


def test_aadhaar_length_is_not_a_card_number():
    """Twelve digits is an Aadhaar number, not a primary account number."""
    findings = significant(detect_pci("4589 6231 7452", "aadhaar"))
    assert "PCI_PAN" not in types_of(findings)


# ---------------------------------------------------------------------------
# Verification values and expiry dates
# ---------------------------------------------------------------------------


def test_bare_cvv_is_detected_in_a_cvv_column():
    findings = significant(detect_pci("123", "cvv payments"))
    assert "PCI_CVV" in types_of(findings)
    assert values_of(findings, "PCI_CVV") == ["123"]


def test_bare_cvv_is_not_detected_in_an_unrelated_column():
    """The same three digits in an unrelated column are not a CVV."""
    findings = significant(detect_pci("123", "quantity orders"))
    assert "PCI_CVV" not in types_of(findings)


def test_labelled_cvv_is_detected_anywhere():
    findings = significant(detect_pci("CVV: 456", "note"))
    assert "PCI_CVV" in types_of(findings)


def test_bare_expiry_is_detected_in_an_expiry_column():
    findings = significant(detect_pci("12/28", "expiry payments"))
    assert "PCI_EXPIRY" in types_of(findings)


def test_impossible_expiry_month_is_rejected():
    findings = significant(detect_pci("13/28", "expiry payments"))
    assert "PCI_EXPIRY" not in types_of(findings)


def test_whole_value_guard_requires_the_whole_cell():
    assert whole_value_is_valid("123", "123") is True
    assert whole_value_is_valid("123", "order 123") is False


# ---------------------------------------------------------------------------
# Context gating
# ---------------------------------------------------------------------------


def test_a_condition_without_clinical_context_is_not_a_finding():
    """'Diabetes' in a company name is not protected health information."""
    findings = significant(detect_phi("Diabetes Care Ltd", "company_name customers"))
    assert "PHI_DIAGNOSIS" not in types_of(findings)


def test_a_condition_in_a_diagnosis_column_is_a_finding():
    findings = significant(
        detect_phi("Type 2 Diabetes Mellitus", "diagnosis patient_records")
    )
    assert "PHI_DIAGNOSIS" in types_of(findings)


def test_a_condition_with_clinical_words_nearby_is_a_finding():
    findings = significant(detect_phi("Patient diagnosed with asthma", "notes"))
    assert "PHI_DIAGNOSIS" in types_of(findings)


def test_a_match_without_context_scores_below_the_threshold():
    """The rule still fires, but too weakly to survive the filter."""
    findings = detect_phi("Diabetes Care Ltd", "company_name customers")
    assert findings, "expected the rule to fire"
    assert all(finding["score"] == NO_CONTEXT_SCORE for finding in findings)
    assert all(finding["score"] < CONTEXT_SCORE for finding in findings)


# ---------------------------------------------------------------------------
# PHI identifiers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,column,expected",
    [
        ("MRN: 4471-B", "mrn", "PHI_MEDICAL_RECORD_NUMBER"),
        ("MCI-2019-114322", "provider_license", "PHI_MEDICAL_LICENSE"),
        ("PMJAY-HI-2023-889120", "health_plan_id", "PHI_HEALTH_PLAN_ID"),
        ("ESIC-22334455", "health_plan_id", "PHI_HEALTH_PLAN_ID"),
        ("SN: DEX-004512", "device_serial", "PHI_DEVICE_ID"),
    ],
)
def test_phi_identifiers_are_detected(value, column, expected):
    findings = significant(detect_phi(value, f"{column} patient_records"))
    assert expected in types_of(findings)


def test_mrn_value_excludes_the_label():
    """Only the identifier is reported, not the label that introduced it."""
    findings = significant(detect_phi("MRN: 4471-B", "mrn patient_records"))
    assert values_of(findings, "PHI_MEDICAL_RECORD_NUMBER") == ["4471-B"]


def test_device_serial_value_excludes_the_label():
    findings = significant(detect_phi("SN: DEX-004512", "device_serial patient_records"))
    assert values_of(findings, "PHI_DEVICE_ID") == ["DEX-004512"]


def test_medication_is_detected_in_a_medication_column():
    findings = significant(detect_phi("Metformin 500mg", "medication patient_records"))
    assert "PHI_MEDICATION" in types_of(findings)


def test_medication_without_context_is_not_a_finding():
    findings = significant(detect_phi("Metformin 500mg", "product_name shop"))
    assert "PHI_MEDICATION" not in types_of(findings)


def test_an_unlabelled_identifier_alone_is_not_a_finding():
    """A bare medical record number with no label and no column is not enough."""
    findings = significant(detect_phi("4471-B", "notes"))
    assert "PHI_MEDICAL_RECORD_NUMBER" not in types_of(findings)


# ---------------------------------------------------------------------------
# Tokenisation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "identifier,expected",
    [
        ("cardNumber", {"card", "number"}),
        ("card_number", {"card", "number"}),
        ("card-number", {"card", "number"}),
        ("Card Number", {"card", "number"}),
        ("health_plan_id", {"health", "plan", "id"}),
    ],
)
def test_tokenize_splits_on_separators_and_camel_case(identifier, expected):
    assert tokenize(identifier) == expected
