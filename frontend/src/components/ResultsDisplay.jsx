import { CATEGORY_FALLBACK, CATEGORY_STYLES } from '../constants'

const RISK_STYLES = {
  Low: 'bg-emerald-100 text-emerald-800 ring-emerald-200',
  Medium: 'bg-amber-100 text-amber-800 ring-amber-200',
  High: 'bg-red-100 text-red-800 ring-red-200',
}

function ClassificationBadge({ classification }) {
  return (
    <span
      className={`rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ${
        CATEGORY_STYLES[classification] ?? CATEGORY_FALLBACK
      }`}
    >
      {classification || 'PII'}
    </span>
  )
}

const ENGINE_LABELS = {
  postgres: 'PostgreSQL',
  mysql: 'MySQL',
  sqlite: 'SQLite',
  clickhouse: 'ClickHouse',
  mongodb: 'MongoDB',
}

function groupByTable(findings) {
  const groups = new Map()
  for (const finding of findings) {
    const key = finding.table || ''
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key).push(finding)
  }
  return [...groups.entries()]
}

export default function ResultsDisplay({ result }) {
  if (!result) return null

  if (result.error) {
    return (
      <section className="rounded-xl border border-red-200 bg-red-50 p-6">
        <h2 className="text-lg font-semibold text-red-800">Scan failed</h2>
        <p className="mt-2 text-sm text-red-700">{result.error}</p>
      </section>
    )
  }

  const report = result.report
  const riskStyle = RISK_STYLES[report.risk_level] ?? RISK_STYLES.Low
  const findingsByType = Object.entries(report.findings_by_type ?? {})
  const findingsByClass = Object.entries(report.findings_by_classification ?? {})
  const isBulk = report.scanned_all_tables
  const groups = groupByTable(report.findings ?? [])

  const headline = isBulk
    ? `Scanned ${report.total_rows_scanned} ${
        report.total_rows_scanned === 1 ? 'row' : 'rows'
      } across ${report.tables?.length ?? 0} ${
        report.tables?.length === 1 ? 'table' : 'tables'
      }, found ${report.total_findings} regulated ${
        report.total_findings === 1 ? 'instance' : 'instances'
      }`
    : `Scanned ${report.total_rows_scanned} ${
        report.total_rows_scanned === 1 ? 'row' : 'rows'
      }, found ${report.total_findings} regulated ${
        report.total_findings === 1 ? 'instance' : 'instances'
      }`

  return (
    <section className="space-y-6">
      <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h2 className="text-lg font-semibold text-slate-900">{headline}</h2>
            <p className="mt-1 text-sm text-slate-500">
              {isBulk ? (
                <>Engine: {ENGINE_LABELS[report.db_type] ?? report.db_type}</>
              ) : (
                <>
                  Table: <span className="font-mono">{report.table_name}</span>
                </>
              )}
            </p>
          </div>
          <span className={`rounded-full px-3 py-1 text-sm font-semibold ring-1 ${riskStyle}`}>
            Risk: {report.risk_level}
          </span>
        </div>

        {findingsByClass.length > 0 && (
          <div className="mt-4">
            <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Regulatory classes
            </p>
            <div className="mt-2 flex flex-wrap gap-2">
              {findingsByClass.map(([classification, count]) => (
                <span
                  key={classification}
                  className={`rounded-full px-3 py-1 text-xs font-semibold ring-1 ${
                    CATEGORY_STYLES[classification] ?? CATEGORY_FALLBACK
                  }`}
                >
                  {classification}: {count}
                </span>
              ))}
            </div>
          </div>
        )}

        {findingsByType.length > 0 && (
          <div className="mt-4 flex flex-wrap gap-2">
            {findingsByType.map(([type, count]) => (
              <span
                key={type}
                className="rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-700"
              >
                {type}: {count}
              </span>
            ))}
          </div>
        )}
      </div>

      {isBulk && report.tables?.length > 0 && (
        <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="border-b border-slate-200 bg-slate-50 px-4 py-3">
            <h3 className="text-sm font-semibold text-slate-700">Per-table summary</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-white text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-3">Table</th>
                  <th className="px-4 py-3">Kind</th>
                  <th className="px-4 py-3">Rows</th>
                  <th className="px-4 py-3">Findings</th>
                  <th className="px-4 py-3">Risk</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {report.tables.map((table) => (
                  <tr key={table.table_name} className="hover:bg-slate-50">
                    <td className="px-4 py-3 font-mono text-xs text-slate-800">
                      {table.table_name}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-500">{table.kind}</td>
                    <td className="px-4 py-3 text-slate-600">{table.total_rows_scanned}</td>
                    <td className="px-4 py-3 text-slate-600">{table.total_findings}</td>
                    <td className="px-4 py-3">
                      <span
                        className={`rounded-full px-2 py-0.5 text-xs font-semibold ring-1 ${
                          RISK_STYLES[table.risk_level] ?? RISK_STYLES.Low
                        }`}
                      >
                        {table.risk_level}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {report.findings.length === 0 ? (
        <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-6">
          <p className="text-sm font-medium text-emerald-800">
            ✓ No personal, health or cardholder data found in the scanned rows
            — nothing to remediate.
          </p>
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  {isBulk && <th className="px-4 py-3">Table</th>}
                  <th className="px-4 py-3">Column Name</th>
                  <th className="px-4 py-3">Row #</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Class</th>
                  <th className="px-4 py-3">Masked Value</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {isBulk
                  ? groups.map(([table, findings]) =>
                      findings.map((finding, index) => (
                        <tr key={`${table}-${index}`} className="hover:bg-slate-50">
                          {index === 0 ? (
                            <td
                              rowSpan={findings.length}
                              className="border-r border-slate-100 px-4 py-3 align-top font-mono text-xs text-slate-700"
                            >
                              {table}
                            </td>
                          ) : null}
                          <td className="px-4 py-3 font-medium text-slate-800">
                            {finding.column}
                          </td>
                          <td className="px-4 py-3 text-slate-600">{finding.row}</td>
                          <td className="px-4 py-3">
                            <span className="rounded-md bg-indigo-50 px-2 py-0.5 text-xs font-semibold text-indigo-700">
                              {finding.pii_type}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <ClassificationBadge
                              classification={finding.classification}
                            />
                          </td>
                          <td className="max-w-xs px-4 py-3 font-mono text-xs text-slate-500">
                            {finding.masked_value}
                            {finding.value_fingerprint && (
                              <span className="ml-2 text-slate-400">
                                #{finding.value_fingerprint}
                              </span>
                            )}
                          </td>
                        </tr>
                      )),
                    )
                  : report.findings.map((finding, index) => (
                      <tr key={index} className="hover:bg-slate-50">
                        <td className="px-4 py-3 font-medium text-slate-800">
                          {finding.column}
                        </td>
                        <td className="px-4 py-3 text-slate-600">{finding.row}</td>
                        <td className="px-4 py-3">
                          <span className="rounded-md bg-indigo-50 px-2 py-0.5 text-xs font-semibold text-indigo-700">
                            {finding.pii_type}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <ClassificationBadge
                            classification={finding.classification}
                          />
                        </td>
                        <td className="max-w-xs px-4 py-3 font-mono text-xs text-slate-500">
                          {finding.masked_value}
                          {finding.value_fingerprint && (
                            <span className="ml-2 text-slate-400">
                              #{finding.value_fingerprint}
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </section>
  )
}
