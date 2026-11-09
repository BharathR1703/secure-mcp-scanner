"""Assessing a scan against the control catalogue.

The assessment is derived entirely from the findings of one scan. No
second pass over the database, no separate query, no hidden state -- so
the compliance report and the findings list can never disagree.

Two vocabularies are in play and they are never mixed in one field.
``risk_level`` is the scanner's existing Low/Medium/High badge.
``overall_status`` is the compliance vocabulary: COMPLIANT,
NON_COMPLIANT, NEEDS_REVIEW, NOT_APPLICABLE. Individual controls use
PASS, FAIL, REVIEW and NOT_APPLICABLE.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ..models import (
    ComplianceReport,
    ControlAssessment,
    FrameworkAssessment,
    ScanReport,
)
from .context import CLASS_PCI, CLASS_PHI, CLASS_PII
from .frameworks import FRAMEWORKS
from .mapping import FRAMEWORK_GOVERNS, FRAMEWORK_ORDER
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
    severity_rank,
)

logger = logging.getLogger(__name__)

CLASS_PREFIX = "class:"

#: The regulatory classes, in reporting order.
CLASSES = (CLASS_PII, CLASS_PHI, CLASS_PCI)


def _matching_findings(
    findings: Sequence, trigger: str
) -> List:
    """Return the findings a trigger selects.

    A trigger is either an entity type (``"PCI_PAN"``) or a class
    (``"class:PHI"``). The class form is what lets a HIPAA control fire
    on a person name in a patient table without making every person name
    health data everywhere.
    """
    if trigger.startswith(CLASS_PREFIX):
        wanted = trigger[len(CLASS_PREFIX) :]
        return [f for f in findings if getattr(f, "classification", None) == wanted]
    return [f for f in findings if getattr(f, "pii_type", None) == trigger]


def _evidence_text(matches: Sequence) -> str:
    """Describe what tripped a control. Never contains a raw value."""
    if not matches:
        return "No triggering findings were detected in the scanned data."
    counts = Counter(finding.pii_type for finding in matches)
    breakdown = ", ".join(
        f"{entity_type} ({count})" for entity_type, count in sorted(counts.items())
    )
    classes = sorted(
        {getattr(finding, "classification", "PII") for finding in matches}
    )
    return (
        f"{len(matches)} finding(s) matched this control "
        f"[{breakdown}]. Classification: {', '.join(classes)}."
    )


def _assess_control(control: Control, findings: Sequence) -> Tuple[str, List, int]:
    """Resolve one control's status.

    Returns ``(status, matched_findings, occurrences)``.
    """
    matched: List = []
    for trigger in control.triggers:
        for finding in _matching_findings(findings, trigger):
            matched.append(finding)

    if matched:
        return STATUS_FAIL, matched, len(matched)
    if control.verifiable:
        return STATUS_PASS, [], 0
    return STATUS_REVIEW, [], 0


def _resolve_frameworks(
    selected: Sequence[str],
) -> List:
    """Order and validate the requested frameworks."""
    unknown = [key for key in selected if key not in FRAMEWORKS]
    if unknown:
        raise ValueError(
            "unknown framework(s): "
            + ", ".join(sorted(unknown))
            + "; supported: "
            + ", ".join(FRAMEWORK_ORDER)
        )
    wanted: Set[str] = set(selected)
    return [
        FRAMEWORKS[key]
        for key in FRAMEWORK_ORDER
        if key in wanted
    ]


def assess(
    report: ScanReport,
    frameworks: Optional[Sequence[str]] = None,
) -> ComplianceReport:
    """Assess a scan against the selected frameworks.

    ``frameworks`` restricts the assessment to the named frameworks. It
    defaults to all of them.
    """
    selected = list(frameworks) if frameworks else list(FRAMEWORK_ORDER)
    chosen = _resolve_frameworks(selected)

    findings = list(report.findings)
    by_class = Counter(
        getattr(finding, "classification", "PII") for finding in findings
    )

    assessments: List[FrameworkAssessment] = []
    failed_controls: List[Tuple[Control, int]] = []
    any_fail = False
    any_review = False
    any_applicable = False

    for framework in chosen:
        governed = FRAMEWORK_GOVERNS.get(framework.key, ())
        applicable = framework.always_applicable or any(
            by_class.get(name, 0) > 0 for name in governed
        )

        if not applicable:
            assessments.append(
                FrameworkAssessment(
                    framework=framework.key,
                    name=framework.name,
                    version=framework.version,
                    status=STATUS_NOT_APPLICABLE,
                    applicable=False,
                    controls_total=0,
                )
            )
            continue

        any_applicable = True
        control_assessments: List[ControlAssessment] = []
        matched_ids: Set[int] = set()
        counts = Counter()

        for control in framework.controls:
            status, matched, occurrences = _assess_control(control, findings)
            finding_types = sorted({finding.pii_type for finding in matched})
            control_assessments.append(
                ControlAssessment(
                    id=control.id,
                    title=control.title,
                    category=control.category,
                    status=status,
                    severity=control.severity,
                    description=control.description,
                    remediation=control.remediation,
                    evidence=(
                        _evidence_text(matched)
                        if status == STATUS_FAIL
                        else (
                            "No triggering findings were detected in the "
                            "scanned data."
                            if status == STATUS_PASS
                            else "This control needs operational evidence "
                            "that a data scan cannot verify."
                        )
                    ),
                    finding_types=finding_types,
                    occurrences=occurrences,
                )
            )
            if status == STATUS_FAIL:
                any_fail = True
                failed_controls.append((control, occurrences))
                counts.update(finding.pii_type for finding in matched)
                matched_ids.update(id(finding) for finding in matched)
            elif status == STATUS_REVIEW:
                any_review = True

        failed = sum(1 for c in control_assessments if c.status == STATUS_FAIL)
        review = sum(1 for c in control_assessments if c.status == STATUS_REVIEW)
        passed = sum(1 for c in control_assessments if c.status == STATUS_PASS)

        if failed:
            framework_status = OVERALL_NON_COMPLIANT
        elif review:
            framework_status = OVERALL_NEEDS_REVIEW
        else:
            framework_status = OVERALL_COMPLIANT

        assessments.append(
            FrameworkAssessment(
                framework=framework.key,
                name=framework.name,
                version=framework.version,
                status=framework_status,
                applicable=True,
                controls_total=len(control_assessments),
                controls_failed=failed,
                controls_review=review,
                controls_passed=passed,
                findings_matched=len(matched_ids),
                controls=control_assessments,
            )
        )

    if any_fail:
        overall = OVERALL_NON_COMPLIANT
    elif any_review:
        overall = OVERALL_NEEDS_REVIEW
    elif any_applicable:
        overall = OVERALL_COMPLIANT
    else:
        overall = OVERALL_NOT_APPLICABLE

    recommended = _recommended_actions(failed_controls)

    assessment = ComplianceReport(
        overall_status=overall,
        summary=_build_summary(report, overall, assessments, by_class),
        db_type=report.db_type,
        table_name=report.table_name,
        total_rows_scanned=report.total_rows_scanned,
        total_findings=report.total_findings,
        findings_by_type=dict(report.findings_by_type),
        findings_by_classification={
            name: by_class.get(name, 0) for name in CLASSES if by_class.get(name)
        },
        risk_level=report.risk_level,
        frameworks=assessments,
        recommended_actions=recommended,
        tables=report.tables,
        findings=list(findings),
    )
    logger.info(
        "Assessment complete for %s: status=%s, %d framework(s), %d failed "
        "control(s), %d recommended action(s)",
        report.table_name,
        overall,
        len(assessments),
        len(failed_controls),
        len(recommended),
    )
    return assessment


def _recommended_actions(failed_controls: Sequence[Tuple[Control, int]]) -> List[str]:
    """Deduplicated remediation text, most severe and best evidenced first."""
    by_text: Dict[str, Tuple[Control, int]] = {}
    for control, occurrences in failed_controls:
        existing = by_text.get(control.remediation)
        if existing is None or occurrences > existing[1]:
            by_text[control.remediation] = (control, occurrences)

    ordered = sorted(
        by_text.values(),
        key=lambda item: (severity_rank(item[0].severity), -item[1]),
    )
    return [control.remediation for control, _ in ordered]


def _build_summary(
    report: ScanReport,
    overall: str,
    assessments: Sequence[FrameworkAssessment],
    by_class: Counter,
) -> str:
    """A prose summary of the assessment."""
    applicable = [a for a in assessments if a.applicable]
    failed_total = sum(a.controls_failed for a in applicable)
    review_total = sum(a.controls_review for a in applicable)

    if report.total_findings == 0:
        return (
            f"No personal, health or cardholder data was detected in "
            f"{report.total_rows_scanned} scanned row(s). "
            f"{len(applicable)} framework(s) were assessed; "
            f"{review_total} control(s) still require human verification."
        )

    class_text = ", ".join(
        f"{name}: {count}" for name, count in sorted(by_class.items()) if count
    )
    parts = [
        f"Assessed {report.total_findings} finding(s) across "
        f"{report.total_rows_scanned} scanned row(s) of '{report.table_name}'. "
        f"Classifications: {class_text}."
    ]

    non_compliant = [
        a.framework for a in applicable if a.controls_failed
    ]
    if non_compliant:
        parts.append(
            f"{failed_total} control(s) failed across "
            f"{', '.join(non_compliant)}; the data as stored does not meet "
            f"those requirements."
        )
    if review_total:
        parts.append(
            f"{review_total} control(s) could not be judged from data alone "
            f"and require human verification."
        )
    parts.append(f"Overall status: {overall}.")
    return " ".join(parts)
