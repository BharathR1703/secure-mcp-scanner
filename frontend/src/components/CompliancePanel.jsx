import { useState } from 'react'
import { SEVERITY_STYLES, STATUS_STYLES } from '../constants'

const STATUS_FALLBACK = 'bg-slate-100 text-slate-600 ring-slate-200'

function StatusBadge({ status }) {
  return (
    <span
      className={`rounded-full px-2.5 py-0.5 text-xs font-semibold ring-1 ${
        STATUS_STYLES[status] ?? STATUS_FALLBACK
      }`}
    >
      {status}
    </span>
  )
}

function SeverityBadge({ severity }) {
  const label = severity ? severity.charAt(0).toUpperCase() + severity.slice(1) : '—'
  return (
    <span
      className={`rounded-md px-2 py-0.5 text-xs font-medium ring-1 ${
        SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.informational
      }`}
    >
      {label}
    </span>
  )
}

function FrameworkCard({ framework }) {
  const [open, setOpen] = useState(false)

  return (
    <div className="overflow-hidden rounded-lg border border-slate-200 bg-white">
      <button
        type="button"
        onClick={() => setOpen((current) => !current)}
        aria-expanded={open}
        className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left transition hover:bg-slate-50"
      >
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs font-semibold text-slate-500">
              {framework.framework}
            </span>
            <span className="truncate text-sm font-semibold text-slate-900">
              {framework.name}
            </span>
            <StatusBadge status={framework.status} />
          </div>
          <p className="mt-1 text-xs text-slate-500">
            {framework.version}
            {framework.applicable ? (
              <>
                {' · '}
                {framework.controls_total} controls · {framework.controls_failed} failed ·{' '}
                {framework.controls_review} need review · {framework.controls_passed} passed
              </>
            ) : (
              ' · no data in scope falls under this framework'
            )}
          </p>
        </div>
        <span className="shrink-0 text-xs font-medium text-indigo-600">
          {open ? 'Hide controls' : 'Show controls'}
        </span>
      </button>

      {open && framework.applicable && (
        <div className="overflow-x-auto border-t border-slate-200">
          <table className="w-full text-left text-sm">
            <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
              <tr>
                <th className="px-4 py-2">Control</th>
                <th className="px-4 py-2">Requirement</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Severity</th>
                <th className="px-4 py-2">Evidence</th>
                <th className="px-4 py-2">Remediation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {framework.controls.map((control) => (
                <tr key={control.id} className="align-top hover:bg-slate-50">
                  <td className="whitespace-nowrap px-4 py-2 font-mono text-xs text-slate-700">
                    {control.id}
                  </td>
                  <td className="px-4 py-2 text-slate-800">
                    {control.title}
                    <div className="text-xs text-slate-500">{control.category}</div>
                  </td>
                  <td className="px-4 py-2">
                    <StatusBadge status={control.status} />
                  </td>
                  <td className="px-4 py-2">
                    <SeverityBadge severity={control.severity} />
                  </td>
                  <td className="max-w-xs px-4 py-2 text-xs text-slate-600">
                    {control.evidence}
                  </td>
                  <td className="max-w-xs px-4 py-2 text-xs text-slate-600">
                    {control.remediation}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default function CompliancePanel({ result }) {
  if (!result) return null

  if (result.error) {
    return (
      <section className="rounded-xl border border-red-200 bg-red-50 p-6">
        <h2 className="text-lg font-semibold text-red-800">Compliance report failed</h2>
        <p className="mt-2 text-sm text-red-700">{result.error}</p>
      </section>
    )
  }

  const report = result.report
  const classes = Object.entries(report.findings_by_classification ?? {})
  const frameworks = report.frameworks ?? []
  const applicable = frameworks.filter((framework) => framework.applicable)
  const notApplicable = frameworks.filter((framework) => !framework.applicable)

  return (
    <section className="space-y-6">
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-slate-900">Regulatory assessment</h2>
            <p className="mt-1 max-w-2xl text-sm text-slate-600">{report.summary}</p>
          </div>
          <StatusBadge status={report.overall_status} />
        </div>

        <dl className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-lg border border-slate-200 px-3 py-2">
            <dt className="text-xs uppercase tracking-wide text-slate-500">Rows scanned</dt>
            <dd className="mt-0.5 text-lg font-semibold text-slate-900">
              {report.total_rows_scanned}
            </dd>
          </div>
          <div className="rounded-lg border border-slate-200 px-3 py-2">
            <dt className="text-xs uppercase tracking-wide text-slate-500">Findings</dt>
            <dd className="mt-0.5 text-lg font-semibold text-slate-900">
              {report.total_findings}
            </dd>
          </div>
          <div className="rounded-lg border border-slate-200 px-3 py-2">
            <dt className="text-xs uppercase tracking-wide text-slate-500">Frameworks</dt>
            <dd className="mt-0.5 text-lg font-semibold text-slate-900">
              {applicable.length}
              <span className="text-sm font-normal text-slate-400">
                {' '}
                of {frameworks.length}
              </span>
            </dd>
          </div>
          <div className="rounded-lg border border-slate-200 px-3 py-2">
            <dt className="text-xs uppercase tracking-wide text-slate-500">Risk</dt>
            <dd className="mt-0.5 text-lg font-semibold text-slate-900">{report.risk_level}</dd>
          </div>
        </dl>

        {classes.length > 0 && (
          <div className="mt-4 flex flex-wrap gap-2">
            {classes.map(([name, count]) => (
              <span
                key={name}
                className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-700"
              >
                {name}: {count}
              </span>
            ))}
          </div>
        )}
      </div>

      {report.recommended_actions?.length > 0 && (
        <div className="rounded-xl border border-amber-200 bg-amber-50 p-6">
          <h3 className="text-sm font-semibold text-amber-900">Recommended actions</h3>
          <ol className="mt-3 list-decimal space-y-2 pl-5">
            {report.recommended_actions.map((action, index) => (
              <li key={index} className="text-sm text-amber-900">
                {action}
              </li>
            ))}
          </ol>
        </div>
      )}

      <div>
        <h3 className="mb-3 text-sm font-semibold text-slate-700">Applicable frameworks</h3>
        <div className="space-y-3">
          {applicable.map((framework) => (
            <FrameworkCard key={framework.framework} framework={framework} />
          ))}
        </div>
      </div>

      {notApplicable.length > 0 && (
        <div>
          <h3 className="mb-3 text-sm font-semibold text-slate-700">
            Frameworks out of scope
          </h3>
          <div className="space-y-3">
            {notApplicable.map((framework) => (
              <FrameworkCard key={framework.framework} framework={framework} />
            ))}
          </div>
        </div>
      )}

      <p className="text-xs text-slate-400">
        Controls marked REVIEW need operational evidence that a data scan cannot
        verify; they are never reported as passing. No raw personal, health or
        cardholder data appears anywhere in this report.
      </p>
    </section>
  )
}
