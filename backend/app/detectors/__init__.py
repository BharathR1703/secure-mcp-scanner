"""Domain detectors for protected health information and cardholder data.

The scanners in :mod:`app.pii_detector` answer "is this personal data?".
These detectors answer the narrower, sharper question: *is this health
information or cardholder data?* They are deliberately plain Python with
no dependency on Presidio or spaCy, so they keep working in the
scanner's degraded, regex-only mode.
"""

from .clinical import (
    CLINICAL_CONTEXT_WORDS,
    CONDITIONS,
    MEDICATIONS,
    condition_rules,
    medication_rules,
)
from .context_gated import (
    CONTEXT_SCORE,
    CONTEXT_WINDOW_AFTER,
    CONTEXT_WINDOW_BEFORE,
    NO_CONTEXT_SCORE,
    ContextGatedRecognizer,
    Rule,
)
from .phi import PHI_RECOGNIZERS, detect_phi
from .pci import PCI_RECOGNIZERS, detect_pci, luhn_checksum_valid

__all__ = [
    "CLINICAL_CONTEXT_WORDS",
    "CONDITIONS",
    "CONTEXT_SCORE",
    "CONTEXT_WINDOW_AFTER",
    "CONTEXT_WINDOW_BEFORE",
    "ContextGatedRecognizer",
    "MEDICATIONS",
    "NO_CONTEXT_SCORE",
    "PHI_RECOGNIZERS",
    "PCI_RECOGNIZERS",
    "Rule",
    "condition_rules",
    "detect_phi",
    "detect_pci",
    "luhn_checksum_valid",
    "medication_rules",
]
