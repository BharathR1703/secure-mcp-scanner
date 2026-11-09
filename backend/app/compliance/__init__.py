"""Regulatory classification and compliance assessment.

The package is deliberately layered, and the layers never reach back up:

* :mod:`app.compliance.context` -- column and relation hints. Knows what
  health data and cardholder data look like in a schema.
* :mod:`app.compliance.mapping` -- entity type to class to frameworks.
* :mod:`app.compliance.frameworks` -- the control catalogue.
* :mod:`app.compliance.assessor` -- the assessment.
* :mod:`app.compliance.rendering` -- the downloadable audit file.

Nothing in this package is imported by :mod:`app.detectors` or
:mod:`app.pii_detector`. The detection layer knows what a value *is*; the
compliance layer knows what that *means*. Mixing the two is how a
scanner ends up with framework logic inside a regex.
"""

from ..models import ControlAssessment, FrameworkAssessment
from .assessor import assess
from .frameworks import FRAMEWORKS, framework_summaries, total_control_count
from .mapping import FRAMEWORK_ORDER, classify
from .models import (
    OVERALL_COMPLIANT,
    OVERALL_NEEDS_REVIEW,
    OVERALL_NON_COMPLIANT,
    OVERALL_NOT_APPLICABLE,
    STATUS_FAIL,
    STATUS_NOT_APPLICABLE,
    STATUS_PASS,
    STATUS_REVIEW,
    Control,
    Framework,
)

__all__ = [
    "FRAMEWORKS",
    "FRAMEWORK_ORDER",
    "OVERALL_COMPLIANT",
    "OVERALL_NEEDS_REVIEW",
    "OVERALL_NON_COMPLIANT",
    "OVERALL_NOT_APPLICABLE",
    "STATUS_FAIL",
    "STATUS_NOT_APPLICABLE",
    "STATUS_PASS",
    "STATUS_REVIEW",
    "Control",
    "ControlAssessment",
    "Framework",
    "FrameworkAssessment",
    "assess",
    "classify",
    "framework_summaries",
    "total_control_count",
]
