"""PCI DSS cardholder-data detectors.

Cardholder data has no schema to key on, so detection is by shape. A
primary account number is thirteen to nineteen digits that pass the Luhn
checksum; the verification value and expiry only make sense next to a
label, so those rules are context-gated.

There is deliberately no cardholder-name recognizer. A cardholder's name
is a person's name, and the scanner already detects those; deciding that
a name is cardholder data needs the row context that a cell-by-cell
scanner does not have. The column and relation hints in the compliance
layer classify a ``cardholder_name`` column as PCI without a second
recognizer.
"""

from __future__ import annotations

import re
from typing import Dict, List

from .context_gated import ContextGatedRecognizer, Rule, whole_value_is_valid

#: The minimum and maximum length of a primary account number, in digits.
PAN_MIN_DIGITS = 13
PAN_MAX_DIGITS = 19

#: Words that license a bare card verification value or expiry date.
CVV_CONTEXT_WORDS = (
    "cvv",
    "cvv2",
    "cvc",
    "cvc2",
    "csc",
    "cid",
    "security code",
    "card verification",
    "card verification value",
    "card verification code",
)

EXPIRY_CONTEXT_WORDS = (
    "expiry",
    "expiration",
    "exp",
    "exp date",
    "expiration date",
    "valid thru",
    "valid until",
    "valid through",
)

#: A run of digits with optional single separators between them. The
#: lookbehind and lookahead keep the match from starting or ending inside
#: a longer digit run, so a twenty-digit order number is never a card
#: number and an Aadhaar number (twelve digits) is never one either.
_PAN_PATTERN = re.compile(r"(?<![\d\-])((?:\d[ \-]?){12,18}\d)(?![\d\-])")

_LABELLED_CVV_PATTERN = re.compile(
    r"\b(?:cvv2?|cvc2?|csc|cid|security\s+code"
    r"|card\s+verification(?:\s+(?:value|code))?"
    r"|card\s+security\s+code)\b"
    r"[\s:#\-]{0,3}(\d{3,4})",
    re.IGNORECASE,
)

_BARE_CVV_PATTERN = re.compile(r"(?<![\d\-])(\d{3,4})(?![\d\-])")

_LABELLED_EXPIRY_PATTERN = re.compile(
    r"\b(?:exp(?:iry|iration|ires|s)?|valid\s+thru|valid\s+until|valid\s+through)\b"
    r"[\s:#\-]{0,3}(\d{1,2}\s?/\s?\d{2,4})",
    re.IGNORECASE,
)

_BARE_EXPIRY_PATTERN = re.compile(r"^(\d{1,2}\s?/\s?\d{2,4})$")


def luhn_checksum_valid(digits: str) -> bool:
    """Return True if ``digits`` passes the Luhn checksum.

    This is the standard ISO/IEC 7812 mod-10 check that every payment
    card number carries. It removes roughly nine candidates in ten.
    """
    if not digits or not digits.isdigit():
        return False
    total = 0
    parity = len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _is_pan(value: str, text: str) -> bool:
    """A primary account number: right length, right checksum."""
    digits = "".join(char for char in value if char.isdigit())
    if not (PAN_MIN_DIGITS <= len(digits) <= PAN_MAX_DIGITS):
        return False
    # A run of identical digits passes the checksum -- all zeros sums to
    # zero -- but no card number looks like that.
    if len(set(digits)) == 1:
        return False
    return luhn_checksum_valid(digits)


def _is_expiry_shape(value: str, text: str) -> bool:
    """An expiry date has a month and a year, and the month must be sane."""
    match = re.fullmatch(r"\s*(\d{1,2})\s*/\s*(\d{2,4})\s*", value)
    if match is None:
        return False
    month = int(match.group(1))
    return 1 <= month <= 12


PAN_RECOGNIZER = ContextGatedRecognizer(
    "PCI_PAN",
    [
        Rule(
            entity_type="PCI_PAN",
            pattern=_PAN_PATTERN,
            context_words=(),
            requires_context=False,
            score=0.98,
            value_validator=_is_pan,
            label="pan",
        )
    ],
    name="primary-account-number",
)

CVV_RECOGNIZER = ContextGatedRecognizer(
    "PCI_CVV",
    [
        Rule(
            entity_type="PCI_CVV",
            pattern=_LABELLED_CVV_PATTERN,
            context_words=(),
            requires_context=False,
            score=0.95,
            label="cvv-labelled",
        ),
        Rule(
            entity_type="PCI_CVV",
            pattern=_BARE_CVV_PATTERN,
            context_words=CVV_CONTEXT_WORDS,
            value_validator=whole_value_is_valid,
            label="cvv-bare",
        ),
    ],
    name="card-verification-value",
)

EXPIRY_RECOGNIZER = ContextGatedRecognizer(
    "PCI_EXPIRY",
    [
        Rule(
            entity_type="PCI_EXPIRY",
            pattern=_LABELLED_EXPIRY_PATTERN,
            context_words=(),
            requires_context=False,
            score=0.9,
            value_validator=_is_expiry_shape,
            label="expiry-labelled",
        ),
        Rule(
            entity_type="PCI_EXPIRY",
            pattern=_BARE_EXPIRY_PATTERN,
            context_words=EXPIRY_CONTEXT_WORDS,
            value_validator=_is_expiry_shape,
            label="expiry-bare",
        ),
    ],
    name="card-expiry",
)

#: Every PCI recognizer, in the order they run.
PCI_RECOGNIZERS = (
    PAN_RECOGNIZER,
    CVV_RECOGNIZER,
    EXPIRY_RECOGNIZER,
)


def detect_pci(text: str, extra_context: str = "") -> List[Dict[str, object]]:
    """Return the cardholder-data findings for ``text``."""
    findings: List[Dict[str, object]] = []
    for recognizer in PCI_RECOGNIZERS:
        findings.extend(recognizer.analyze(text, extra_context))
    return findings
