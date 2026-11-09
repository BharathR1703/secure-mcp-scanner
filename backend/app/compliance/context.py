"""Column and relation hints: how a value's *home* narrows its class.

A person's name in ``patient_records`` is protected health information.
The same person's name in ``customers`` is personal data. The value is
the same; the context is not. This module holds the two hint tables that
make that distinction, plus the rule that decides which non-text columns
are worth scanning at all.

Nothing here knows about frameworks. A hint says "this looks like health
data"; it does not say "HIPAA cares". Keeping that line crisp is what
stops the detection layer and the compliance layer from tangling.
"""

from __future__ import annotations

import re
from typing import Dict, Optional, Set, Tuple

from ..detectors.context_gated import tokenize

CLASS_PII = "PII"
CLASS_PHI = "PHI"
CLASS_PCI = "PCI"

#: Domain classes, most specific first. The order breaks ties when a
#: column name matches hints from more than one domain.
DOMAIN_ORDER: Tuple[str, ...] = (CLASS_PCI, CLASS_PHI)

#: Column-name tokens that place a column in a regulatory domain.
COLUMN_DOMAIN_HINTS: Dict[str, str] = {
    # --- Cardholder data -------------------------------------------------
    "card": CLASS_PCI,
    "cards": CLASS_PCI,
    "cardnumber": CLASS_PCI,
    "cardholder": CLASS_PCI,
    "cardholders": CLASS_PCI,
    "cardexpiry": CLASS_PCI,
    "cardverification": CLASS_PCI,
    "securitycode": CLASS_PCI,
    "cvv": CLASS_PCI,
    "cvc": CLASS_PCI,
    "csc": CLASS_PCI,
    "cid": CLASS_PCI,
    "expiry": CLASS_PCI,
    "expiration": CLASS_PCI,
    "expdate": CLASS_PCI,
    "payment": CLASS_PCI,
    "payments": CLASS_PCI,
    "transaction": CLASS_PCI,
    "transactions": CLASS_PCI,
    "checkout": CLASS_PCI,
    "billing": CLASS_PCI,
    "creditcard": CLASS_PCI,
    "debitcard": CLASS_PCI,
    "prepaid": CLASS_PCI,
    "paymentmethod": CLASS_PCI,
    "stripe": CLASS_PCI,
    "paypal": CLASS_PCI,
    "paytm": CLASS_PCI,
    "razorpay": CLASS_PCI,
    "gateway": CLASS_PCI,
    "acquirer": CLASS_PCI,
    "visa": CLASS_PCI,
    "mastercard": CLASS_PCI,
    "amex": CLASS_PCI,
    "maestro": CLASS_PCI,
    "rupay": CLASS_PCI,
    "iban": CLASS_PCI,
    "swift": CLASS_PCI,
    "routing": CLASS_PCI,
    # --- Protected health information ------------------------------------
    "patient": CLASS_PHI,
    "patients": CLASS_PHI,
    "mrn": CLASS_PHI,
    "medical": CLASS_PHI,
    "medicine": CLASS_PHI,
    "health": CLASS_PHI,
    "healthcare": CLASS_PHI,
    "healthplan": CLASS_PHI,
    "diagnosis": CLASS_PHI,
    "diagnoses": CLASS_PHI,
    "diagnostic": CLASS_PHI,
    "condition": CLASS_PHI,
    "conditions": CLASS_PHI,
    "symptom": CLASS_PHI,
    "symptoms": CLASS_PHI,
    "medication": CLASS_PHI,
    "medications": CLASS_PHI,
    "prescription": CLASS_PHI,
    "prescriptions": CLASS_PHI,
    "clinical": CLASS_PHI,
    "clinic": CLASS_PHI,
    "hospital": CLASS_PHI,
    "ward": CLASS_PHI,
    "icu": CLASS_PHI,
    "admission": CLASS_PHI,
    "admissions": CLASS_PHI,
    "discharge": CLASS_PHI,
    "encounter": CLASS_PHI,
    "encounters": CLASS_PHI,
    "provider": CLASS_PHI,
    "providers": CLASS_PHI,
    "physician": CLASS_PHI,
    "clinician": CLASS_PHI,
    "dob": CLASS_PHI,
    "birth": CLASS_PHI,
    "birthdate": CLASS_PHI,
    "allergy": CLASS_PHI,
    "allergies": CLASS_PHI,
    "immunization": CLASS_PHI,
    "immunisation": CLASS_PHI,
    "vaccine": CLASS_PHI,
    "insurer": CLASS_PHI,
    "insurance": CLASS_PHI,
    "therapy": CLASS_PHI,
    "disability": CLASS_PHI,
    "disease": CLASS_PHI,
    "illness": CLASS_PHI,
    "hiv": CLASS_PHI,
    "covid": CLASS_PHI,
    "device": CLASS_PHI,
    "implant": CLASS_PHI,
    "prosthesis": CLASS_PHI,
    "chart": CLASS_PHI,
    "pharmacy": CLASS_PHI,
    "telehealth": CLASS_PHI,
}

#: Relation-name tokens that place a whole table in a regulatory domain.
RELATION_DOMAIN_HINTS: Dict[str, str] = {
    "patient": CLASS_PHI,
    "patients": CLASS_PHI,
    "medical": CLASS_PHI,
    "medicine": CLASS_PHI,
    "health": CLASS_PHI,
    "healthcare": CLASS_PHI,
    "encounter": CLASS_PHI,
    "encounters": CLASS_PHI,
    "admission": CLASS_PHI,
    "admissions": CLASS_PHI,
    "discharge": CLASS_PHI,
    "diagnosis": CLASS_PHI,
    "diagnoses": CLASS_PHI,
    "prescription": CLASS_PHI,
    "prescriptions": CLASS_PHI,
    "clinical": CLASS_PHI,
    "claim": CLASS_PHI,
    "claims": CLASS_PHI,
    "lab": CLASS_PHI,
    "labs": CLASS_PHI,
    "pharmacy": CLASS_PHI,
    "telehealth": CLASS_PHI,
    "vitals": CLASS_PHI,
    "immunization": CLASS_PHI,
    "immunisation": CLASS_PHI,
    "payment": CLASS_PCI,
    "payments": CLASS_PCI,
    "card": CLASS_PCI,
    "cards": CLASS_PCI,
    "cardholder": CLASS_PCI,
    "cardholders": CLASS_PCI,
    "billing": CLASS_PCI,
    "transaction": CLASS_PCI,
    "transactions": CLASS_PCI,
    "checkout": CLASS_PCI,
    "subscription": CLASS_PCI,
    "subscriptions": CLASS_PCI,
    "settlement": CLASS_PCI,
    "paymentmethods": CLASS_PCI,
    "cardtransactions": CLASS_PCI,
}

#: Tokens that mark a column as holding an identifier rather than a
#: quantity. Only columns like these have their non-text values scanned.
#:
#: The list is deliberately narrow. Emitting every numeric column as
#: text would turn every ``bigint`` primary key into a digit string for
#: the recognizers to chew on, which is exactly the false-positive
#: surface the scanner works to avoid.
IDENTIFIER_COLUMN_TOKENS: Set[str] = {
    "aadhaar",
    "aadhar",
    "account",
    "acct",
    "applicant",
    "beneficiary",
    "birth",
    "birthdate",
    "card",
    "cardholder",
    "cardnumber",
    "cid",
    "contact",
    "csc",
    "cvc",
    "cvv",
    "dob",
    "expiration",
    "expiry",
    "healthplan",
    "ifsc",
    "insurance",
    "licence",
    "license",
    "member",
    "mobile",
    "mrn",
    "nik",
    "pan",
    "passport",
    "patient",
    "phone",
    "pin",
    "pincode",
    "policy",
    "postal",
    "postcode",
    "serial",
    "ssn",
    "subscriber",
    "telephone",
    "uidai",
    "upi",
    "voter",
    "zip",
    "zipcode",
}

_SEGMENT_SPLIT_RE = re.compile(r"[.\[\]\(\)]+")


def _segments(identifier: str) -> Tuple[str, ...]:
    """Split a dotted or bracketed path into its segments."""
    return tuple(part for part in _SEGMENT_SPLIT_RE.split(identifier or "") if part)


def _tokens_of(identifier: str) -> Set[str]:
    """Every token in every segment of a path."""
    tokens: Set[str] = set()
    for segment in _segments(identifier):
        tokens |= tokenize(segment)
    return tokens


def column_tokens(column: str) -> Set[str]:
    """Every token in every segment of a column path."""
    return _tokens_of(column)


def _match_domain(
    tokens: Set[str], hints: Dict[str, str]
) -> Optional[str]:
    """Return the domain the tokens point at, if any.

    The domain with the most matching hints wins, so a column called
    ``card_holder_name`` is cardholder data rather than health data. Ties
    break on :data:`DOMAIN_ORDER`, which puts cardholder data first
    because its rules are the strictest.
    """
    scores: Dict[str, int] = {}
    for token in tokens:
        domain = hints.get(token)
        if domain is not None:
            scores[domain] = scores.get(domain, 0) + 1
    if not scores:
        return None
    best = max(scores.values())
    for domain in DOMAIN_ORDER:
        if scores.get(domain) == best:
            return domain
    return max(scores, key=lambda domain: scores[domain])


def domain_for_column(column: str) -> Optional[str]:
    """Return the regulatory domain a column name implies, if any.

    The leaf path and the root key are both consulted, so a nested
    ``metadata.card.cvv`` is recognised just as ``cvv`` is.
    """
    return _match_domain(_tokens_of(column), COLUMN_DOMAIN_HINTS)


def domain_for_relation(relation: str) -> Optional[str]:
    """Return the regulatory domain a relation name implies, if any."""
    return _match_domain(_tokens_of(relation), RELATION_DOMAIN_HINTS)


def root_key(column: str) -> str:
    """The first segment of a column path."""
    segments = _segments(column)
    return segments[0] if segments else ""


def is_identifier_column(column: str) -> bool:
    """Return True if a column's name marks it as holding an identifier.

    Used to decide whether a numeric or date column is worth scanning
    at all.
    """
    return bool(_tokens_of(column) & IDENTIFIER_COLUMN_TOKENS)


def should_scan_non_text(column: str) -> bool:
    """Return True if non-text leaves in ``column`` should be scanned.

    The rule lives here, in the compliance layer, rather than in the
    flattener: the flattener stays generic and knows nothing about
    regulatory domains.
    """
    return is_identifier_column(column)
