"""Rendering the assessment as a downloadable audit file.

Two formats, one content. The HTML is a single self-contained document
with inline CSS and a print stylesheet -- no scripts, no external fonts,
nothing to fetch. It opens in a browser and prints to PDF without further
work. The Markdown carries the same content for pipelines and agents.

The file is generated server-side rather than assembled in the browser,
so the same bytes can be emailed, archived, or piped into a pipeline.
"""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from typing import List

from ..models import ComplianceReport, FrameworkAssessment

#: Status colours, used by the HTML renderer and mirrored by the
#: frontend's badge styles.
STATUS_COLOURS = {
    "PASS": "#047857",
    "COMPLIANT": "#047857",
    "FAIL": "#b91c1c",
    "NON_COMPLIANT": "#b91c1c",
    "REVIEW": "#b45309",
    "NEEDS_REVIEW": "#b45309",
    "NOT_APPLICABLE": "#64748b",
}

_SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
}


def _generated_at() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _scope_label(report: ComplianceReport) -> str:
    if report.table_name == "all tables":
        return "Every relation in the database"
    return f"Relation: {report.table_name}"


def _status_cell(status: str) -> str:
    colour = STATUS_COLOURS.get(status, "#334155")
    return (
        f'<span class="badge" style="background:{colour}1a;color:{colour};'
        f'border-color:{colour}55">{escape(status)}</span>'
    )


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_HTML_STYLE = """
:root {
  --ink: #0f172a;
  --muted: #64748b;
  --line: #e2e8f0;
  --paper: #ffffff;
  --tint: #f8fafc;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 48px 40px;
  background: #f1f5f9;
  color: var(--ink);
  font: 14px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
        Helvetica, Arial, sans-serif;
}
.sheet {
  max-width: 1000px;
  margin: 0 auto;
  background: var(--paper);
  border: 1px solid var(--line);
  border-radius: 12px;
  overflow: hidden;
}
header {
  padding: 28px 32px;
  border-bottom: 1px solid var(--line);
  background: var(--tint);
}
h1 { margin: 0 0 4px; font-size: 20px; letter-spacing: -0.01em; }
.sub { color: var(--muted); font-size: 13px; }
section { padding: 24px 32px; border-bottom: 1px solid var(--line); }
section:last-child { border-bottom: 0; }
h2 {
  margin: 0 0 14px;
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.09em;
  color: var(--muted);
}
.overall {
  display: flex;
  align-items: baseline;
  gap: 12px;
}
.overall .state {
  font-size: 22px;
  font-weight: 700;
  letter-spacing: -0.02em;
}
.overall .why { color: var(--muted); }
.meta {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 14px;
  margin-top: 18px;
}
.meta div { border-left: 2px solid var(--line); padding-left: 10px; }
.meta dt {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  color: var(--muted);
  margin: 0 0 2px;
}
.meta dd { margin: 0; font-weight: 600; font-size: 13px; }
table { width: 100%; border-collapse: collapse; }
th, td {
  text-align: left;
  padding: 8px 10px;
  border-bottom: 1px solid var(--line);
  vertical-align: top;
  font-size: 13px;
}
th {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--muted);
  font-weight: 600;
  background: var(--tint);
}
tbody tr:last-child td { border-bottom: 0; }
td.id { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; white-space: nowrap; }
td.sev { white-space: nowrap; color: var(--muted); }
td.ev { color: #334155; }
td.rem { color: #334155; }
.badge {
  display: inline-block;
  padding: 1px 8px;
  border-radius: 999px;
  border: 1px solid;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.03em;
  white-space: nowrap;
}
.framework { margin-top: 26px; }
.framework header {
  padding: 0 0 10px;
  background: none;
  border: 0;
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}
.framework h3 { margin: 0; font-size: 15px; }
.framework .counts { color: var(--muted); font-size: 12px; }
ol.actions { margin: 0; padding-left: 20px; }
ol.actions li { margin-bottom: 9px; }
.muted { color: var(--muted); }
footer { padding: 18px 32px; color: var(--muted); font-size: 12px; }
@media print {
  body { background: #fff; padding: 0; }
  .sheet { border: 0; border-radius: 0; max-width: none; }
  section { page-break-inside: avoid; }
  .framework { page-break-inside: avoid; }
}
""".strip()


def render_html(report: ComplianceReport) -> str:
    """Render the assessment as a self-contained HTML document."""
    generated = _generated_at()

    rows = []
    for framework in report.frameworks:
        rows.append(
            "<tr>"
            f"<td class=\"id\">{escape(framework.framework)}</td>"
            f"<td>{escape(framework.name)}</td>"
            f"<td>{escape(framework.version)}</td>"
            f"<td>{_status_cell(framework.status)}</td>"
            f"<td>{framework.controls_total}</td>"
            f"<td>{framework.controls_failed}</td>"
            f"<td>{framework.controls_review}</td>"
            f"<td>{framework.findings_matched}</td>"
            "</tr>"
        )
    framework_table = (
        "<table><thead><tr><th>Framework</th><th>Name</th><th>Version</th>"
        "<th>Status</th><th>Controls</th><th>Failed</th><th>Review</th>"
        "<th>Findings</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )

    blocks = []
    for framework in report.frameworks:
        if not framework.applicable:
            blocks.append(
                '<div class="framework"><header>'
                f"<h3>{escape(framework.name)}</h3>"
                f"{_status_cell(framework.status)}"
                "</header>"
                '<p class="muted">No data in the scanned scope falls under '
                "this framework, so its controls do not apply.</p></div>"
            )
            continue

        control_rows = []
        for control in framework.controls:
            control_rows.append(
                "<tr>"
                f"<td class=\"id\">{escape(control.id)}</td>"
                f"<td>{escape(control.title)}"
                f"<div class=\"muted\">{escape(control.category)}</div></td>"
                f"<td>{_status_cell(control.status)}</td>"
                f"<td class=\"sev\">"
                f"{escape(_SEVERITY_LABELS.get(control.severity, control.severity))}"
                "</td>"
                f"<td class=\"ev\">{escape(control.evidence)}</td>"
                f"<td class=\"rem\">{escape(control.remediation)}</td>"
                "</tr>"
            )

        blocks.append(
            '<div class="framework"><header>'
            f"<h3>{escape(framework.name)} "
            f'<span class="muted">({escape(framework.version)})</span></h3>'
            f"{_status_cell(framework.status)}"
            f'<span class="counts">{framework.controls_total} controls &middot; '
            f"{framework.controls_failed} failed &middot; "
            f"{framework.controls_review} need review &middot; "
            f"{framework.controls_passed} passed</span>"
            "</header>"
            "<table><thead><tr><th>Control</th><th>Requirement</th>"
            "<th>Status</th><th>Severity</th><th>Evidence</th>"
            "<th>Remediation</th></tr></thead><tbody>"
            + "".join(control_rows)
            + "</tbody></table></div>"
        )

    if report.recommended_actions:
        actions = "".join(
            f"<li>{escape(action)}</li>" for action in report.recommended_actions
        )
        actions_html = f"<ol class=\"actions\">{actions}</ol>"
    else:
        actions_html = (
            "<p class=\"muted\">No control failures were detected, so no "
            "remediation is required by this scan.</p>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Compliance audit report &mdash; {escape(_scope_label(report))}</title>
<style>
{_HTML_STYLE}
</style>
</head>
<body>
<div class="sheet">
<header>
  <h1>Compliance audit report</h1>
  <p class="sub">Secure MCP Scanner &middot; generated {escape(generated)}</p>
</header>

<section>
  <h2>Overall status</h2>
  <div class="overall">
    <span class="state" style="color:{STATUS_COLOURS.get(report.overall_status, '#334155')}">
      {escape(report.overall_status)}</span>
    <span class="why">{escape(report.summary)}</span>
  </div>
  <dl class="meta">
    <div><dt>Engine</dt><dd>{escape(report.db_type)}</dd></div>
    <div><dt>Scope</dt><dd>{escape(_scope_label(report))}</dd></div>
    <div><dt>Rows scanned</dt><dd>{report.total_rows_scanned}</dd></div>
    <div><dt>Findings</dt><dd>{report.total_findings}</dd></div>
    <div><dt>Risk level</dt><dd>{escape(report.risk_level)}</dd></div>
    <div><dt>Classes found</dt><dd>{
        escape(', '.join(
            f'{name}: {count}'
            for name, count in sorted(report.findings_by_classification.items())
        )) or '&mdash;'
    }</dd></div>
  </dl>
</section>

<section>
  <h2>Framework summary</h2>
  {framework_table}
</section>

<section>
  <h2>Control assessment</h2>
  {''.join(blocks)}
</section>

<section>
  <h2>Recommended actions</h2>
  {actions_html}
</section>

<footer>
  This report was produced by a data scan. Controls marked REVIEW need
  operational evidence that a scan cannot verify, and are never reported
  as passing. No raw personal, health or cardholder data appears in this
  document.
</footer>
</div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


def render_markdown(report: ComplianceReport) -> str:
    """Render the assessment as a Markdown document."""
    generated = _generated_at()
    lines: List[str] = []

    lines.append("# Compliance audit report")
    lines.append("")
    lines.append(f"*Secure MCP Scanner — generated {generated}*")
    lines.append("")
    lines.append("## Overall status")
    lines.append("")
    lines.append(f"**{report.overall_status}** — {report.summary}")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Engine | {report.db_type} |")
    lines.append(f"| Scope | {_scope_label(report)} |")
    lines.append(f"| Rows scanned | {report.total_rows_scanned} |")
    lines.append(f"| Findings | {report.total_findings} |")
    lines.append(f"| Risk level | {report.risk_level} |")
    classes = ", ".join(
        f"{name}: {count}"
        for name, count in sorted(report.findings_by_classification.items())
    )
    lines.append(f"| Classes found | {classes or '—'} |")
    lines.append("")

    lines.append("## Framework summary")
    lines.append("")
    lines.append(
        "| Framework | Name | Version | Status | Controls | Failed | "
        "Review | Findings |"
    )
    lines.append("| --- | --- | --- | --- | ---: | ---: | ---: | ---: |")
    for framework in report.frameworks:
        lines.append(
            f"| {framework.framework} | {framework.name} | "
            f"{framework.version} | {framework.status} | "
            f"{framework.controls_total} | {framework.controls_failed} | "
            f"{framework.controls_review} | {framework.findings_matched} |"
        )
    lines.append("")

    lines.append("## Control assessment")
    lines.append("")
    for framework in report.frameworks:
        lines.append(f"### {framework.name} ({framework.version})")
        lines.append("")
        lines.append(f"**Status: {framework.status}**")
        lines.append("")
        if not framework.applicable:
            lines.append(
                "No data in the scanned scope falls under this framework, "
                "so its controls do not apply."
            )
            lines.append("")
            continue
        lines.append(
            "| Control | Requirement | Status | Severity | Evidence | "
            "Remediation |"
        )
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for control in framework.controls:
            lines.append(
                f"| `{control.id}` | {control.title} | {control.status} | "
                f"{_SEVERITY_LABELS.get(control.severity, control.severity)} | "
                f"{control.evidence} | {control.remediation} |"
            )
        lines.append("")

    lines.append("## Recommended actions")
    lines.append("")
    if report.recommended_actions:
        for action in report.recommended_actions:
            lines.append(f"- {action}")
    else:
        lines.append(
            "No control failures were detected, so no remediation is "
            "required by this scan."
        )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        "This report was produced by a data scan. Controls marked REVIEW "
        "need operational evidence that a scan cannot verify, and are never "
        "reported as passing. No raw personal, health or cardholder data "
        "appears in this document."
    )
    lines.append("")
    return "\n".join(lines)


def render(report: ComplianceReport, format: str = "html") -> str:
    """Render the audit file in the requested format."""
    normalised = (format or "html").lower()
    if normalised == "markdown" or normalised == "md":
        return render_markdown(report)
    return render_html(report)
