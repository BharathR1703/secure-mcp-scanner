"""Tests for the classification layer.

Two things are being checked here: that a finding is put in the right
regulatory class, and that the class is right for the right reason. A
value's type beats its surroundings; its surroundings can only upgrade a
generic type. A value is never left less protected than plain personal
data.
"""

from __future__ import annotations

import pytest

from app.compliance.context import (
    domain_for_column,
    domain_for_relation,
    is_identifier_column,
    should_scan_non_text,
)
from app.compliance.mapping import (
    ALWAYS_APPLICABLE,
    CLASSES,
    ENTITY_CLASS,
    FRAMEWORK_GOVERNS,
    FRAMEWORK_ORDER,
    REGULATIONS,
    classify,
)


def test_every_class_is_known():
    assert set(CLASSES) == {"PII", "PHI", "PCI"}


@pytest.mark.parametrize(
    "entity_type,expected",
    [
        ("PHI_MEDICAL_RECORD_NUMBER", "PHI"),
        ("PHI_HEALTH_PLAN_ID", "PHI"),
        ("PHI_MEDICAL_LICENSE", "PHI"),
        ("PHI_DEVICE_ID", "PHI"),
        ("PHI_DATE_OF_BIRTH", "PHI"),
        ("PHI_DIAGNOSIS", "PHI"),
        ("PHI_MEDICATION", "PHI"),
        ("PCI_PAN", "PCI"),
        ("PCI_CVV", "PCI"),
        ("PCI_EXPIRY", "PCI"),
    ],
)
def test_a_domain_type_keeps_its_class_anywhere(entity_type, expected):
    """Type beats context: a card number is card data wherever it sits."""
    _, classification, _ = classify(entity_type, "loyalty_points", "loyalty")
    assert classification == expected


def test_a_generic_type_is_upgraded_by_the_column():
    _, classification, _ = classify("DATE_TIME", "dob", "customers")
    assert classification == "PHI"


def test_a_generic_type_is_upgraded_by_the_relation():
    _, classification, _ = classify("PERSON_NAME", "full_name", "patient_records")
    assert classification == "PHI"


def test_a_generic_type_stays_pii_by_default():
    _, classification, _ = classify("EMAIL_ADDRESS", "email", "customers")
    assert classification == "PII"


def test_a_date_in_an_unrelated_column_stays_pii():
    _, classification, _ = classify("DATE_TIME", "invoice_date", "orders")
    assert classification == "PII"


def test_the_refined_type_is_returned():
    refined, classification, _ = classify("DATE_TIME", "dob", "customers")
    assert refined == "PHI_DATE_OF_BIRTH"
    assert classification == "PHI"


def test_regulations_follow_the_class():
    _, _, phi_regulations = classify("PHI_DIAGNOSIS", "diagnosis", "patients")
    assert "HIPAA" in phi_regulations
    assert "PCI_DSS" not in phi_regulations

    _, _, pci_regulations = classify("PCI_PAN", "card_number", "payments")
    assert "PCI_DSS" in pci_regulations
    assert "HIPAA" not in pci_regulations


def test_every_class_maps_to_at_least_one_framework():
    for class_name in CLASSES:
        assert REGULATIONS[class_name]


def test_the_framework_order_covers_every_framework():
    assert len(FRAMEWORK_ORDER) == 7
    assert set(FRAMEWORK_ORDER) == set(FRAMEWORK_GOVERNS)


def test_management_frameworks_are_always_applicable():
    assert set(ALWAYS_APPLICABLE) == {"SOC2", "ISO27001"}


def test_a_pan_in_a_loyalty_table_is_still_card_data():
    """Downgrading on the strength of a table name would be guesswork."""
    refined, classification, _ = classify("PCI_PAN", "points", "loyalty")
    assert refined == "PCI_PAN"
    assert classification == "PCI"


# ---------------------------------------------------------------------------
# Column and relation hints
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "column,expected",
    [
        ("card_number", "PCI"),
        ("cvv", "PCI"),
        ("expiry", "PCI"),
        ("patient_name", "PHI"),
        ("diagnosis", "PHI"),
        ("dob", "PHI"),
    ],
)
def test_domain_for_column(column, expected):
    assert domain_for_column(column) == expected


@pytest.mark.parametrize(
    "relation,expected",
    [
        ("payments", "PCI"),
        ("payment_transactions", "PCI"),
        ("patient_records", "PHI"),
        ("medical_encounters", "PHI"),
    ],
)
def test_domain_for_relation(relation, expected):
    assert domain_for_relation(relation) == expected


def test_an_ordinary_column_has_no_domain():
    assert domain_for_column("quantity") is None


def test_an_ordinary_primary_key_is_not_an_identifier_column():
    """A plain integer primary key is not personal data."""
    assert is_identifier_column("id") is False
    assert is_identifier_column("customer_id") is False


def test_a_named_identifier_column_is_an_identifier_column():
    assert is_identifier_column("aadhaar") is True
    assert is_identifier_column("card_number") is True
    assert is_identifier_column("mrn") is True


def test_non_text_columns_are_scanned_only_when_they_are_identifiers():
    """A card number stored as an integer still has to be found."""
    assert should_scan_non_text("card_number") is True
    assert should_scan_non_text("id") is False


# ---------------------------------------------------------------------------
# The entity-class table
# ---------------------------------------------------------------------------


def test_every_entity_class_is_a_known_class():
    for entity_type, class_name in ENTITY_CLASS.items():
        assert class_name in CLASSES, entity_type
