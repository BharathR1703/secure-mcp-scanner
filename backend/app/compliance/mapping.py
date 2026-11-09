"""Mapping between entity types, regulatory classes and frameworks.

Three steps, in order:

1. **Entity type.** ``PCI_PAN`` is cardholder data everywhere it
   appears. ``PHI_MEDICAL_RECORD_NUMBER`` is health data everywhere.
2. **Column.** A column called ``diagnosis`` puts its values in the
   health domain; ``card_number`` in the cardholder domain.
3. **Relation.** A table called ``patient_records`` puts its values in
   the health domain; ``payments`` in the cardholder domain.

Type beats context, and context only ever *upgrades* a generic type.
A Luhn-valid sixteen-digit number is a card number wherever it sits --
including in a table called ``loyalty_points`` -- because the shape is
stronger evidence than a table name, and downgrading it on the strength
of a name would be guesswork. A value can therefore never end up less
protected than plain personal data, which is the safe direction to err
in.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from .context import (
    CLASS_PCI,
    CLASS_PHI,
    CLASS_PII,
    column_tokens,
    domain_for_column,
    domain_for_relation,
)

#: The three regulatory classes.
CLASSES: Tuple[str, ...] = (CLASS_PII, CLASS_PHI, CLASS_PCI)

#: Entity types that belong to a domain outright.
ENTITY_CLASS: Dict[str, str] = {
    "PHI_MEDICAL_RECORD_NUMBER": CLASS_PHI,
    "PHI_HEALTH_PLAN_ID": CLASS_PHI,
    "PHI_MEDICAL_LICENSE": CLASS_PHI,
    "PHI_DEVICE_ID": CLASS_PHI,
    "PHI_DATE_OF_BIRTH": CLASS_PHI,
    "PHI_DIAGNOSIS": CLASS_PHI,
    "PHI_MEDICATION": CLASS_PHI,
    "PCI_PAN": CLASS_PCI,
    "PCI_CVV": CLASS_PCI,
    "PCI_EXPIRY": CLASS_PCI,
}

#: Entity types that are health data when they sit in a health column.
#: A date in a column called ``dob`` is a date of birth; the same date
#: in a column called ``invoice_date`` is not.
CONDITIONAL_PHI_TYPES: Dict[str, Tuple[str, ...]] = {
    "DATE_TIME": ("dob", "birth", "birthdate", "birthdateofbirth"),
}

#: Frameworks and the classes they govern.
FRAMEWORK_GOVERNS: Dict[str, Tuple[str, ...]] = {
    "HIPAA": (CLASS_PHI,),
    "PCI_DSS": (CLASS_PCI,),
    "GDPR": (CLASS_PII, CLASS_PHI, CLASS_PCI),
    "DPDP": (CLASS_PII, CLASS_PHI, CLASS_PCI),
    "CCPA": (CLASS_PII, CLASS_PCI),
    "SOC2": (CLASS_PII, CLASS_PHI, CLASS_PCI),
    "ISO27001": (CLASS_PII, CLASS_PHI, CLASS_PCI),
}

#: Frameworks that always apply, because they are management-system
#: frameworks: their controls are about governance rather than about the
#: content of a table.
ALWAYS_APPLICABLE: Tuple[str, ...] = ("SOC2", "ISO27001")

#: Frameworks in reporting order.
FRAMEWORK_ORDER: Tuple[str, ...] = (
    "HIPAA",
    "PCI_DSS",
    "GDPR",
    "DPDP",
    "CCPA",
    "SOC2",
    "ISO27001",
)

#: The frameworks that care about each class, in reporting order.
REGULATIONS: Dict[str, Tuple[str, ...]] = {
    CLASS_PII: ("GDPR", "DPDP", "CCPA", "SOC2", "ISO27001"),
    CLASS_PHI: ("HIPAA", "GDPR", "DPDP", "SOC2", "ISO27001"),
    CLASS_PCI: ("PCI_DSS", "GDPR", "DPDP", "CCPA", "SOC2", "ISO27001"),
}


def _refine_type(pii_type: str, column: str) -> str:
    """Upgrade a generic type to a domain type when the column demands it.

    A date in a column called ``dob`` is a date of birth, which is a
    HIPAA identifier rather than a date.
    """
    tokens = CONDITIONAL_PHI_TYPES.get(pii_type)
    if not tokens:
        return pii_type
    if column_tokens(column) & set(tokens):
        return "PHI_DATE_OF_BIRTH"
    return pii_type


def classify(
    pii_type: str, column: str = "", relation: str = ""
) -> Tuple[str, str, List[str]]:
    """Classify a finding.

    Returns ``(pii_type, classification, regulations)`` where the type is
    the refined entity type, the classification is ``PII``, ``PHI`` or
    ``PCI``, and the regulations are the frameworks that care.
    """
    refined = _refine_type(pii_type, column)

    domain = ENTITY_CLASS.get(refined)
    if domain is None:
        domain = domain_for_column(column)
    if domain is None:
        domain = domain_for_relation(relation)
    if domain is None:
        domain = CLASS_PII

    return refined, domain, list(REGULATIONS[domain])
