"""Protected health information detectors.

HIPAA's Safe Harbor list names eighteen categories of identifier. The ones
that actually turn up in a relational database -- a medical record
number, a health-plan member id, a provider's licence number, a device
serial, a date of birth -- get first-class treatment here. The rest are
covered by the surrounding controls in the compliance catalogue rather
than by a recognizer.

Every rule is context-gated, with one exception: a date of birth is
recognised by its label, which is the context.
"""

from __future__ import annotations

import re
from typing import Dict, List

from .clinical import CLINICAL_CONTEXT_WORDS, condition_rules, medication_rules
from .context_gated import ContextGatedRecognizer, Rule

#: A medical record number has to carry at least one digit. "MRN: ABCDE"
#: is a label pointing at something else.
_MUST_CONTAIN_DIGIT = lambda value, text: any(char.isdigit() for char in value)

#: A device identifier must be at least four characters and carry a digit.
_DEVICE_SHAPE = lambda value, text: (
    len(value) >= 4 and any(char.isdigit() for char in value)
)

#: A date of birth has to contain a plausible year.
_HAS_YEAR = lambda value, text: re.search(r"(?:19|20)\d{2}", value) is not None


#: The separator between a label and its value. Labels are written
#: ``MRN: 4471-B``, ``MRN 4471-B`` and ``MRN=4471-B``, and Indian scheme
#: identifiers are hyphenated straight after the label (``PMJAY-HI-2023``).
_LABEL_SEPARATOR = r"\.?[\s:#\-]{0,6}"

_MRN_PATTERN = re.compile(
    r"\b(?:MRN\b"
    r"|MEDICAL\s+RECORD\s+(?:NUMBER|NO)\b"
    r"|PATIENT\s+RECORD\s+(?:NUMBER|NO)\b"
    r"|HOSPITAL\s+RECORD\s+(?:NUMBER|NO)\b)"
    + _LABEL_SEPARATOR
    + r"([A-Z0-9][A-Z0-9\-/]{2,19})",
    re.IGNORECASE,
)

_HEALTH_PLAN_PATTERN = re.compile(
    r"\b(?:HEALTH\s+PLAN\s+(?:ID|NUMBER|NO)\b"
    r"|MEMBER\s+(?:ID|NUMBER|NO)\b"
    r"|INSURANCE\s+(?:ID|NUMBER|POLICY)\b"
    r"|POLICY\s+(?:ID|NUMBER|NO)\b"
    r"|PMJAY\b"
    r"|AYUSHMAN\s+(?:ID|NUMBER|CARD)\b"
    r"|ABHA\s+(?:ID|NUMBER|NO)\b"
    r"|ESIC\b"
    r"|CGHS\b"
    r"|TMC\b)"
    + _LABEL_SEPARATOR
    + r"([A-Z0-9][A-Z0-9\-/]{2,19})",
    re.IGNORECASE,
)

_LICENCE_PATTERN = re.compile(
    r"\b(?:MEDICAL\s+(?:LICENCE|LICENSE)(?:\s+NUMBER)?\b"
    r"|MCI\b"
    r"|NMC\b"
    r"|STATE\s+MEDICAL\s+COUNCIL(?:\s+(?:REGISTRATION|NUMBER))?\b"
    r"|COUNCIL\s+REGISTRATION\b)"
    + _LABEL_SEPARATOR
    + r"([A-Z0-9][A-Z0-9\-/]{2,19})",
    re.IGNORECASE,
)

_DEVICE_PATTERN = re.compile(
    r"\b(?:DEVICE\s+(?:ID|SERIAL(?:\s+NUMBER)?|NUMBER)\b"
    r"|SERIAL\s+(?:NUMBER|NO)?\b"
    r"|SN\b"
    r"|IMPLANT\s+(?:ID|SERIAL|LOT)\b"
    r"|PACEMAKER\s+(?:ID|SERIAL)\b)"
    + _LABEL_SEPARATOR
    + r"([A-Z0-9][A-Z0-9\-/]{2,19})",
    re.IGNORECASE,
)

_DOB_PATTERN = re.compile(
    r"\b(?:DOB|D\.O\.B|DATE\s+OF\s+BIRTH|BIRTH\s?DATE|BIRTHDATE)\b"
    r"\.?"
    r"[\s:#\-]{0,6}"
    r"(\d{1,4}\s?[-/.]\s?\d{1,2}\s?[-/.]\s?\d{1,4})",
    re.IGNORECASE,
)


MRN_RECOGNIZER = ContextGatedRecognizer(
    "PHI_MEDICAL_RECORD_NUMBER",
    [
        Rule(
            entity_type="PHI_MEDICAL_RECORD_NUMBER",
            pattern=_MRN_PATTERN,
            context_words=(
                "mrn",
                "medical record",
                "patient",
                "hospital",
                "chart",
                "encounter",
                "record",
            ),
            value_validator=_MUST_CONTAIN_DIGIT,
            label="mrn",
        )
    ],
    name="medical-record-number",
)

HEALTH_PLAN_RECOGNIZER = ContextGatedRecognizer(
    "PHI_HEALTH_PLAN_ID",
    [
        Rule(
            entity_type="PHI_HEALTH_PLAN_ID",
            pattern=_HEALTH_PLAN_PATTERN,
            context_words=(
                "health plan",
                "insurance",
                "member",
                "policy",
                "pmjay",
                "ayushman",
                "abha",
                "patient",
            ),
            value_validator=_MUST_CONTAIN_DIGIT,
            label="health-plan-id",
        )
    ],
    name="health-plan-id",
)

LICENCE_RECOGNIZER = ContextGatedRecognizer(
    "PHI_MEDICAL_LICENSE",
    [
        Rule(
            entity_type="PHI_MEDICAL_LICENSE",
            pattern=_LICENCE_PATTERN,
            context_words=(
                "medical",
                "licence",
                "license",
                "mci",
                "nmc",
                "council",
                "registration",
                "provider",
                "doctor",
                "physician",
            ),
            value_validator=_MUST_CONTAIN_DIGIT,
            label="medical-licence",
        )
    ],
    name="medical-licence",
)

DEVICE_RECOGNIZER = ContextGatedRecognizer(
    "PHI_DEVICE_ID",
    [
        Rule(
            entity_type="PHI_DEVICE_ID",
            pattern=_DEVICE_PATTERN,
            context_words=(
                "device",
                "implant",
                "serial",
                "patient",
                "medical",
                "hospital",
                "pacemaker",
                "prosthesis",
            ),
            value_validator=_DEVICE_SHAPE,
            label="device-id",
        )
    ],
    name="device-id",
)

DOB_RECOGNIZER = ContextGatedRecognizer(
    "PHI_DATE_OF_BIRTH",
    [
        Rule(
            entity_type="PHI_DATE_OF_BIRTH",
            pattern=_DOB_PATTERN,
            context_words=(),
            requires_context=False,
            score=0.9,
            value_validator=_HAS_YEAR,
            label="date-of-birth",
        )
    ],
    name="date-of-birth",
)

DIAGNOSIS_RECOGNIZER = ContextGatedRecognizer(
    "PHI_DIAGNOSIS",
    condition_rules(),
    context_words=CLINICAL_CONTEXT_WORDS,
    name="clinical-diagnosis",
)

MEDICATION_RECOGNIZER = ContextGatedRecognizer(
    "PHI_MEDICATION",
    medication_rules(),
    context_words=CLINICAL_CONTEXT_WORDS,
    name="clinical-medication",
)

#: Every PHI recognizer, in the order they run.
PHI_RECOGNIZERS = (
    DOB_RECOGNIZER,
    MRN_RECOGNIZER,
    HEALTH_PLAN_RECOGNIZER,
    LICENCE_RECOGNIZER,
    DEVICE_RECOGNIZER,
    DIAGNOSIS_RECOGNIZER,
    MEDICATION_RECOGNIZER,
)


def detect_phi(text: str, extra_context: str = "") -> List[Dict[str, object]]:
    """Return the protected-health-information findings for ``text``."""
    findings: List[Dict[str, object]] = []
    for recognizer in PHI_RECOGNIZERS:
        findings.extend(recognizer.analyze(text, extra_context))
    return findings
