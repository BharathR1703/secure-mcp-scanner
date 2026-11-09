"""PII detection and masking built on Microsoft Presidio.

Detects common entity types (emails, phone numbers, person names) plus
India-specific identifiers (PAN, Aadhaar) using pattern recognizers. All
public functions are defensive: they never raise, and fall back to a pure
regex engine when the Presidio/spaCy stack is unavailable.

Two precision guards keep the output usable on Indian data:

* The predefined recognizer set is *curated*. Several stock Presidio
  recognizers are tuned to US/UK/EU formats and misfire badly on Indian
  values -- ``NhsRecognizer`` scores a bare 10-digit Indian mobile number
  as a UK NHS number with confidence 1.0, and the US bank/licence
  recognizers tag every phone number. Those are removed.
* spaCy's NER reads bare digit runs as dates and mislabels numeric dates as
  person names, so digit-only spans are dropped from ``DATE_TIME`` and
  ``PERSON`` findings.

The domain detectors for protected health information and cardholder data
live in :mod:`app.detectors`. They are plain Python, so they run in both
the Presidio path and the regex-only fallback: card data must not become
invisible because spaCy failed to load.
"""

import hashlib
import logging
import os
import re
from typing import Any, Dict, List, Optional, Set

from presidio_analyzer import (
    AnalyzerEngine,
    Pattern,
    PatternRecognizer,
    RecognizerRegistry,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider

from .detectors import detect_phi, detect_pci

logger = logging.getLogger(__name__)

MASK = "[REDACTED]"

#: Findings below this confidence are discarded.
MIN_SCORE = 0.4

PAN_REGEX = r"\b[A-Z]{5}\d{4}[A-Z]\b"
# Aadhaar numbers are 12 digits and never start with 0 or 1; the spaced form
# ("1234 5678 9012") is the canonical written format. Only the spaced form is
# matched to avoid false positives on phone numbers with country codes.
AADHAAR_REGEX = r"\b[2-9]\d{3}\s\d{4}\s\d{4}\b"
EMAIL_REGEX = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
# Indian mobile numbers: optional +91 prefix, then a 10-digit number that
# starts with 6-9.
PHONE_REGEX = r"(?:\+91[\s-]?)?[6-9]\d{9}\b"

#: Stock recognizers that are tuned for non-Indian formats and produce
#: false positives on Indian data. See the module docstring.
NOISY_RECOGNIZERS = frozenset(
    {
        "UsBankRecognizer",
        "UsLicenseRecognizer",
        "UsItinRecognizer",
        "UsPassportRecognizer",
        "UsSsnRecognizer",
        "NhsRecognizer",
        "SgFinRecognizer",
        "AuAbnRecognizer",
        "AuAcnRecognizer",
        "AuTfnRecognizer",
        "AuMedicareRecognizer",
        "CryptoRecognizer",
        "IbanRecognizer",
        # Presidio's credit-card recognizer is replaced by the PCI
        # recognizer, which applies the length bounds and the Luhn
        # checksum that actually distinguish a card number from an
        # Aadhaar number or an order reference. Reporting the same
        # digits as both CREDIT_CARD and PCI_PAN would double-count it
        # in every report.
        "CreditCardRecognizer",
    }
)

_ENTITY_LABELS = {
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "PHONE",
    "IN_PHONE": "PHONE",
    "PERSON": "PERSON_NAME",
    "IN_PAN": "PAN",
    "AADHAAR": "AADHAAR",
    "IN_AADHAAR": "AADHAAR",
    "LOCATION": "LOCATION",
    "ORG": "ORGANIZATION",
    "URL": "URL",
    "IP_ADDRESS": "IP_ADDRESS",
    "DATE_TIME": "DATE_TIME",
}

#: When two findings overlap, the more specific type wins even if the
#: other one scored higher. A date of birth is a more specific fact than
#: a date; a card number is a more specific fact than a phone number.
_ENTITY_PRECEDENCE: Dict[str, Set[str]] = {
    "PHI_DATE_OF_BIRTH": {"DATE_TIME", "PERSON", "PERSON_NAME"},
    "PHI_DIAGNOSIS": {"PERSON", "PERSON_NAME", "ORG", "ORGANIZATION"},
    "PHI_MEDICATION": {"PERSON", "PERSON_NAME", "ORG", "ORGANIZATION"},
    "PCI_PAN": {
        "CREDIT_CARD",
        "PHONE",
        "PHONE_NUMBER",
        "IN_PHONE",
        "AADHAAR",
        "IN_AADHAAR",
    },
    "PCI_CVV": {"PHONE", "PHONE_NUMBER", "IN_PHONE"},
    "PCI_EXPIRY": {"DATE_TIME"},
}

_NLP_CONFIGURATION = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
}

#: A span made only of digits and spaces is never a useful date: Indian PIN
#: codes, Aadhaar digit groups and phone numbers all match this shape.
_DIGITS_ONLY_RE = re.compile(r"^[\d\s]+$")

#: A date worth reporting has a year in it. Dates of birth -- the reason
#: dates matter as PII -- always do, while bare digit runs that spaCy reads
#: as dates ("Hyderabad 500034") do not.
_YEAR_RE = re.compile(r"\b(?:19|20)\d{2}\b")

#: A span made only of digits and separators is never a person name, but
#: spaCy happily labels "05/03/2024" as PERSON.
_DIGIT_TOKEN_RE = re.compile(r"^[\d\s/.,:;()\[\]-]+$")

_REGEX_RULES = [
    ("EMAIL", EMAIL_REGEX, 0.9),
    ("PHONE", PHONE_REGEX, 0.85),
    ("PAN", PAN_REGEX, 0.9),
    ("AADHAAR", AADHAAR_REGEX, 0.95),
]


class PanRecognizer(PatternRecognizer):
    """Recognizes Indian Permanent Account Numbers (PAN)."""

    def __init__(self) -> None:
        super().__init__(
            supported_entity="IN_PAN",
            patterns=[Pattern(name="indian_pan", regex=PAN_REGEX, score=0.9)],
            context=["pan", "permanent account number"],
        )


class AadhaarRecognizer(PatternRecognizer):
    """Recognizes Indian Aadhaar numbers in their spaced format."""

    def __init__(self) -> None:
        super().__init__(
            supported_entity="AADHAAR",
            patterns=[Pattern(name="aadhaar_spaced", regex=AADHAAR_REGEX, score=0.95)],
            context=["aadhaar", "aadhar", "uid"],
        )


class IndianPhoneRecognizer(PatternRecognizer):
    """Recognizes Indian mobile numbers.

    Presidio's generic phone recognizer scores Indian numbers low (0.4)
    because it cannot validate the country code, which puts them at risk of
    being filtered out. This recognizer gives them a confident score.
    """

    def __init__(self) -> None:
        super().__init__(
            supported_entity="IN_PHONE",
            patterns=[Pattern(name="indian_mobile", regex=PHONE_REGEX, score=0.85)],
            context=["phone", "mobile", "contact", "phone number"],
        )


_analyzer: Optional[AnalyzerEngine] = None


def _get_analyzer() -> AnalyzerEngine:
    """Build (once) and return the Presidio analyzer engine."""
    global _analyzer
    if _analyzer is not None:
        return _analyzer

    registry = RecognizerRegistry()
    registry.load_predefined_recognizers()
    for name in NOISY_RECOGNIZERS:
        registry.remove_recognizer(name)
    registry.add_recognizer(PanRecognizer())
    registry.add_recognizer(AadhaarRecognizer())
    registry.add_recognizer(IndianPhoneRecognizer())

    nlp_engine = None
    try:
        nlp_engine = NlpEngineProvider(nlp_configuration=_NLP_CONFIGURATION).create_engine()
        logger.info("Presidio NLP engine loaded (en_core_web_sm)")
    except Exception:
        # Without the spaCy model we let AnalyzerEngine raise its own error and
        # rely on the regex fallback in detect_pii().
        logger.warning(
            "spaCy NLP engine unavailable; Presidio will not start. "
            "PII detection falls back to regex-only mode.",
            exc_info=True,
        )
        raise

    _analyzer = AnalyzerEngine(registry=registry, nlp_engine=nlp_engine)
    logger.info(
        "Presidio analyzer ready with %d recognizers", len(registry.recognizers)
    )
    return _analyzer


def _is_noise(entity: str, value: str) -> bool:
    """Return True for spans that are known NER artefacts, not real PII."""
    if entity == "DATE_TIME":
        if _DIGITS_ONLY_RE.match(value) or not _YEAR_RE.search(value):
            return True
    if entity in ("PERSON", "NRP") and _DIGIT_TOKEN_RE.match(value):
        return True
    return False


def _presidio_detect(text: str) -> List[Dict[str, Any]]:
    analyzer = _get_analyzer()
    results = analyzer.analyze(
        text=text,
        language="en",
        return_decision_process=False,
        score_threshold=MIN_SCORE,
    )
    findings: List[Dict[str, Any]] = []
    for result in results:
        value = text[result.start : result.end]
        if _is_noise(result.entity_type, value):
            continue
        findings.append(
            {
                "type": _ENTITY_LABELS.get(result.entity_type, result.entity_type),
                "value": value,
                "start": result.start,
                "end": result.end,
                "score": round(float(result.score), 2),
            }
        )
    return findings


def _regex_detect(text: str) -> List[Dict[str, Any]]:
    """Standalone regex engine used when Presidio is unavailable."""
    findings: List[Dict[str, Any]] = []
    for entity, pattern, score in _REGEX_RULES:
        if score < MIN_SCORE:
            continue
        for match in re.finditer(pattern, text):
            findings.append(
                {
                    "type": entity,
                    "value": match.group(0),
                    "start": match.start(),
                    "end": match.end(),
                    "score": score,
                }
            )
    return findings


def _apply_precedence(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Drop findings that a more specific type overrides.

    The generic overlap resolver keeps the highest-scoring span, which is
    not always the right one: a date of birth overlaps a date, and a card
    number overlaps a phone number, and in both cases the specific type
    is the more useful answer even though the generic recognizer may
    have scored slightly higher.
    """
    kept: List[Dict[str, Any]] = []
    for finding in findings:
        dominated = False
        for other in findings:
            if other is finding:
                continue
            overrides = _ENTITY_PRECEDENCE.get(other["type"])
            if not overrides or finding["type"] not in overrides:
                continue
            if other["start"] < finding["end"] and finding["start"] < other["end"]:
                dominated = True
                break
        if not dominated:
            kept.append(finding)
    return kept


def _resolve_overlaps(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Keep the highest-scoring finding among overlapping spans."""
    # A "+91" prefixed mobile number is 12 digits once the country code is
    # included, and Presidio's checksum-based Aadhaar recognizer accepts
    # roughly one in ten such digit runs. The "+" prefix is what
    # distinguishes a phone number from a stored Aadhaar number, so an
    # Aadhaar match sitting inside one is discarded.
    country_code_phones = [
        (finding["start"], finding["end"])
        for finding in findings
        if finding["type"] == "PHONE" and finding["value"].startswith("+")
    ]
    if country_code_phones:
        findings = [
            finding
            for finding in findings
            if not (
                finding["type"] == "AADHAAR"
                and any(
                    start < finding["end"] and finding["start"] < end
                    for start, end in country_code_phones
                )
            )
        ]

    findings = _apply_precedence(findings)

    ordered = sorted(
        findings,
        key=lambda f: (-f["score"], -(f["end"] - f["start"]), f["start"]),
    )
    selected: List[Dict[str, Any]] = []
    for finding in ordered:
        if all(
            finding["end"] <= kept["start"] or finding["start"] >= kept["end"]
            for kept in selected
        ):
            selected.append(finding)
    return sorted(selected, key=lambda f: f["start"])


def detect_pii(text: str, context: str = "") -> List[Dict[str, Any]]:
    """Return PII findings for a piece of text.

    Each finding is a dict with keys ``type``, ``value``, ``start``, ``end``
    and ``score``. Positions are character offsets into ``text``.

    ``context`` is free text describing where the value was found --
    normally the column name and the relation name. Its words count
    towards the context gate of the health and cardholder rules, which is
    how a cell whose entire content is ``Type 2 Diabetes Mellitus`` is
    still recognised as a diagnosis because it sits in a column called
    ``diagnosis``.
    """
    if not isinstance(text, str) or not text.strip():
        return []

    try:
        findings = _presidio_detect(text)
    except Exception:
        logger.warning("Presidio analysis failed; using regex fallback", exc_info=True)
        findings = _regex_detect(text)

    # The domain detectors are plain Python, so they work in the
    # degraded mode too. Card data must not become invisible because
    # spaCy failed to load.
    try:
        findings = findings + detect_phi(text, context) + detect_pci(text, context)
    except Exception:
        logger.warning("Domain detection failed", exc_info=True)

    findings = [finding for finding in findings if finding["score"] >= MIN_SCORE]

    return _resolve_overlaps(
        [
            {
                "type": finding["type"],
                "value": text[finding["start"] : finding["end"]],
                "start": finding["start"],
                "end": finding["end"],
                "score": round(float(finding["score"]), 2),
            }
            for finding in findings
        ]
    )


def mask_pii(text: str) -> str:
    """Replace every detected PII instance in ``text`` with ``[REDACTED]``.

    This masks only the detected spans, so the text around them survives.
    That is the right behaviour for rendering a paragraph of prose, but it
    is *not* how the scanner reports findings: a cell holding an Aadhaar
    number usually holds a street address and a PIN code too, so the scan
    layer redacts the whole cell instead of calling this.
    """
    if not isinstance(text, str):
        return ""
    masked = text
    # Replacing from the end keeps earlier offsets valid.
    for finding in reversed(detect_pii(text)):
        masked = masked[: finding["start"]] + MASK + masked[finding["end"] :]
    return masked


#: Key used to fingerprint detected values. It is generated once per process
#: and never leaves it, so fingerprints cannot be reversed or compared
#: against a precomputed table of candidate values.
_FINGERPRINT_KEY = os.urandom(32)


def fingerprint(value: str) -> str:
    """Return a short, non-reversible fingerprint of ``value``.

    Two findings of the same value share a fingerprint, so the same Aadhaar
    number can be traced across several tables without the number itself
    ever being returned. The fingerprint is stable for the lifetime of the
    process and meaningless outside it.
    """
    digest = hashlib.blake2b(
        value.encode("utf-8"), key=_FINGERPRINT_KEY, digest_size=5
    )
    return digest.hexdigest()
