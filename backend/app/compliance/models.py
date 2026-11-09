"""Control and framework definitions, plus the status vocabularies.

The pydantic models that carry an assessment live in :mod:`app.models`,
next to the other wire contracts, so that the wire format has a single
home and the import graph stays acyclic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

#: Control status vocabulary.
STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_REVIEW = "REVIEW"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

#: Assessment status vocabulary.
OVERALL_COMPLIANT = "COMPLIANT"
OVERALL_NON_COMPLIANT = "NON_COMPLIANT"
OVERALL_NEEDS_REVIEW = "NEEDS_REVIEW"
OVERALL_NOT_APPLICABLE = "NOT_APPLICABLE"

#: Severity ordering, most severe first.
SEVERITY_ORDER: Tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "informational",
)

_SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}


def severity_rank(severity: str) -> int:
    """Return the sort rank of a severity label; unknown labels sort last."""
    return _SEVERITY_RANK.get(severity, len(SEVERITY_ORDER))


@dataclass(frozen=True)
class Control:
    """One assessable control within a framework.

    ``triggers`` names what makes the control fail: either an entity type
    (``"PCI_PAN"``) or a class (``"class:PHI"``).

    ``verifiable`` is the honesty mechanism. A control that a data scan
    can judge -- "a PAN must not be readable where it is stored" -- is
    ``True``, and passes when nothing triggers it. A control that needs
    operational evidence -- "audit controls", "incident response" -- is
    ``False``, and is reported as ``REVIEW`` forever. The scanner never
    claims a passing audit control it cannot see.
    """

    id: str
    title: str
    category: str
    severity: str
    description: str
    remediation: str
    triggers: Tuple[str, ...] = ()
    verifiable: bool = False


@dataclass(frozen=True)
class Framework:
    """One regulatory or assurance framework and its controls."""

    key: str
    name: str
    version: str
    governs: Tuple[str, ...]
    always_applicable: bool = False
    controls: Tuple[Control, ...] = ()

    def control_count(self) -> int:
        return len(self.controls)
