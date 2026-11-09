import { useState } from 'react'
import { CATEGORIES, FRAMEWORKS } from '../constants'

const PRESETS = [
  {
    label: 'Postgres',
    dsn: 'postgresql://postgres:postgres@postgres:5432/sample_db',
  },
  {
    label: 'MySQL',
    dsn: 'mysql://root:mysql@mysql:3306/sample_db',
  },
  {
    label: 'SQLite',
    dsn: 'sqlite:////app/data/sample.db',
  },
  {
    label: 'ClickHouse',
    dsn: 'clickhouse://default:@clickhouse:9000/sample_db',
  },
  {
    label: 'MongoDB',
    dsn: 'mongodb://mongo:27017/sample_db',
  },
]

const ENGINE_OPTIONS = [
  { value: '', label: 'Auto-detect from DSN' },
  { value: 'postgres', label: 'PostgreSQL' },
  { value: 'mysql', label: 'MySQL / MariaDB' },
  { value: 'sqlite', label: 'SQLite' },
  { value: 'clickhouse', label: 'ClickHouse' },
  { value: 'mongodb', label: 'MongoDB' },
]

const DEFAULT_CONNECTION_STRING = PRESETS[0].dsn

function toggle(list, value) {
  return list.includes(value)
    ? list.filter((item) => item !== value)
    : [...list, value]
}

function ChipGroup({ legend, hint, options, selected, onToggle }) {
  return (
    <fieldset>
      <legend className="text-sm font-medium text-slate-700">{legend}</legend>
      <p className="mt-0.5 text-xs text-slate-500">{hint}</p>
      <div className="mt-2 flex flex-wrap gap-2">
        {options.map((option) => {
          const active = selected.includes(option.key)
          return (
            <button
              key={option.key}
              type="button"
              title={option.blurb}
              onClick={() => onToggle(option.key)}
              aria-pressed={active}
              className={`rounded-full border px-3 py-1 text-xs font-semibold transition ${
                active
                  ? 'border-indigo-600 bg-indigo-600 text-white'
                  : 'border-slate-300 bg-white text-slate-600 hover:border-indigo-300 hover:text-indigo-700'
              }`}
            >
              {option.label}
            </button>
          )
        })}
      </div>
    </fieldset>
  )
}

export default function ScannerForm({ onScan, onCompliance, onAudit }) {
  const [connectionString, setConnectionString] = useState(DEFAULT_CONNECTION_STRING)
  const [tableName, setTableName] = useState('customers')
  const [limit, setLimit] = useState(100)
  const [dbType, setDbType] = useState('')
  const [scanAll, setScanAll] = useState(false)
  const [categories, setCategories] = useState([])
  const [frameworks, setFrameworks] = useState([])
  const [loading, setLoading] = useState(null)
  const [listing, setListing] = useState(false)
  const [tables, setTables] = useState(null)
  const [detectedEngine, setDetectedEngine] = useState(null)
  const [listError, setListError] = useState(null)

  function buildBody() {
    return {
      connection_string: connectionString.trim(),
      table_name: scanAll ? null : tableName.trim() || null,
      limit: Number(limit) || 100,
      db_type: dbType || null,
      categories: categories.length ? categories : null,
      frameworks: frameworks.length ? frameworks : null,
    }
  }

  async function post(path, body) {
    const response = await fetch(path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    const data = await response.json().catch(() => ({}))
    if (!response.ok) {
      throw new Error(data.detail || `Request failed with status ${response.status}.`)
    }
    return data
  }

  async function handleListTables() {
    setListing(true)
    setListError(null)
    try {
      const data = await post('/api/tables', {
        connection_string: connectionString.trim(),
        db_type: dbType || null,
      })
      setTables(data.tables || [])
      setDetectedEngine(data.db_type)
      if (data.tables?.length) {
        setTableName(data.tables[0].qualified_name)
        setScanAll(false)
      }
    } catch (error) {
      setTables(null)
      setListError(error.message || 'Could not list tables.')
    } finally {
      setListing(false)
    }
  }

  async function handleScan(event) {
    event.preventDefault()
    setLoading('scan')
    try {
      const data = await post('/api/scan', buildBody())
      setDetectedEngine(data.db_type)
      onScan({ report: data })
    } catch (error) {
      onScan({ error: error.message || 'Could not reach the scanner backend.' })
    } finally {
      setLoading(null)
    }
  }

  async function handleCompliance() {
    setLoading('compliance')
    try {
      const data = await post('/api/compliance-report', buildBody())
      setDetectedEngine(data.db_type)
      onCompliance({ report: data })
    } catch (error) {
      onCompliance({ error: error.message || 'Could not reach the scanner backend.' })
    } finally {
      setLoading(null)
    }
  }

  async function handleAudit() {
    setLoading('audit')
    try {
      const response = await fetch('/api/audit-report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...buildBody(), format: 'html' }),
      })
      if (!response.ok) {
        const data = await response.json().catch(() => ({}))
        throw new Error(data.detail || `Audit file failed with status ${response.status}.`)
      }
      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = 'compliance-audit.html'
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(url)
      onAudit({ downloaded: 'compliance-audit.html' })
    } catch (error) {
      onAudit({ error: error.message || 'Could not reach the scanner backend.' })
    } finally {
      setLoading(null)
    }
  }

  const busy = loading !== null

  return (
    <form
      onSubmit={handleScan}
      className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm"
    >
      <div className="grid gap-6">
        <div>
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <label
              htmlFor="connection-string"
              className="block text-sm font-medium text-slate-700"
            >
              Database Connection String
            </label>
            {detectedEngine && (
              <span className="rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-600">
                Detected: {detectedEngine}
              </span>
            )}
          </div>
          <input
            id="connection-string"
            type="text"
            required
            value={connectionString}
            onChange={(e) => setConnectionString(e.target.value)}
            placeholder="postgresql://user:password@host:5432/database"
            className="mt-2 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm shadow-sm outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-100"
          />
          <div className="mt-2 flex flex-wrap items-center gap-2">
            {PRESETS.map((preset) => (
              <button
                key={preset.label}
                type="button"
                onClick={() => setConnectionString(preset.dsn)}
                className="rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-medium text-slate-600 transition hover:border-indigo-300 hover:text-indigo-700"
              >
                {preset.label}
              </button>
            ))}
            <span className="text-xs text-slate-400">
              Presets assume Docker Compose service names.
            </span>
          </div>
        </div>

        <div className="grid gap-6 sm:grid-cols-3">
          <div>
            <label htmlFor="table-name" className="block text-sm font-medium text-slate-700">
              Table Name
            </label>
            <input
              id="table-name"
              type="text"
              value={tableName}
              onChange={(e) => setTableName(e.target.value)}
              disabled={scanAll}
              placeholder="customers"
              className="mt-2 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm shadow-sm outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-100 disabled:bg-slate-100 disabled:text-slate-400"
            />
          </div>
          <div>
            <label htmlFor="rows-to-scan" className="block text-sm font-medium text-slate-700">
              Rows to Scan
            </label>
            <input
              id="rows-to-scan"
              type="number"
              min="1"
              max="1000"
              value={limit}
              onChange={(e) => setLimit(e.target.value)}
              className="mt-2 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm shadow-sm outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-100"
            />
          </div>
          <div>
            <label htmlFor="db-type" className="block text-sm font-medium text-slate-700">
              Engine
            </label>
            <select
              id="db-type"
              value={dbType}
              onChange={(e) => setDbType(e.target.value)}
              className="mt-2 w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm shadow-sm outline-none focus:border-indigo-500 focus:ring-2 focus:ring-indigo-100"
            >
              {ENGINE_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="grid gap-5 border-t border-slate-100 pt-5 sm:grid-cols-2">
          <ChipGroup
            legend="Regulatory classes"
            hint="Leave empty to scan for all three."
            options={CATEGORIES}
            selected={categories}
            onToggle={(key) => setCategories((current) => toggle(current, key))}
          />
          <ChipGroup
            legend="Frameworks"
            hint="Leave empty to assess all seven."
            options={FRAMEWORKS}
            selected={frameworks}
            onToggle={(key) => setFrameworks((current) => toggle(current, key))}
          />
        </div>

        <div className="flex flex-wrap items-center gap-4">
          <label className="flex items-center gap-2 text-sm text-slate-700">
            <input
              type="checkbox"
              checked={scanAll}
              onChange={(e) => setScanAll(e.target.checked)}
              className="h-4 w-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
            />
            Scan every table in the database
          </label>
          <button
            type="button"
            onClick={handleListTables}
            disabled={listing}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {listing && (
              <span
                className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-slate-400 border-t-transparent"
                aria-hidden="true"
              />
            )}
            {listing ? 'Listing…' : 'List tables'}
          </button>
        </div>

        {listError && (
          <p className="rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {listError}
          </p>
        )}

        {tables && tables.length > 0 && (
          <div className="max-h-56 overflow-y-auto rounded-lg border border-slate-200">
            <table className="w-full text-left text-sm">
              <thead className="sticky top-0 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-3 py-2">Relation</th>
                  <th className="px-3 py-2">Kind</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {tables.map((table) => (
                  <tr
                    key={table.qualified_name}
                    onClick={() => {
                      setTableName(table.qualified_name)
                      setScanAll(false)
                    }}
                    className={`cursor-pointer hover:bg-indigo-50 ${
                      table.qualified_name === tableName ? 'bg-indigo-50' : ''
                    }`}
                  >
                    <td className="px-3 py-2 font-mono text-xs text-slate-700">
                      {table.qualified_name}
                    </td>
                    <td className="px-3 py-2 text-xs text-slate-500">{table.kind}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="mt-6 flex flex-wrap items-center gap-3">
        <button
          type="submit"
          disabled={busy}
          className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {loading === 'scan' && (
            <span
              className="h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent"
              aria-hidden="true"
            />
          )}
          {loading === 'scan' ? 'Scanning…' : 'Scan for regulated data'}
        </button>
        <button
          type="button"
          onClick={handleCompliance}
          disabled={busy}
          className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-5 py-2.5 text-sm font-semibold text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {loading === 'compliance' && (
            <span
              className="h-4 w-4 animate-spin rounded-full border-2 border-slate-400 border-t-transparent"
              aria-hidden="true"
            />
          )}
          {loading === 'compliance' ? 'Assessing…' : 'Compliance report'}
        </button>
        <button
          type="button"
          onClick={handleAudit}
          disabled={busy}
          className="inline-flex items-center gap-2 rounded-lg border border-slate-300 bg-white px-5 py-2.5 text-sm font-semibold text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {loading === 'audit' && (
            <span
              className="h-4 w-4 animate-spin rounded-full border-2 border-slate-400 border-t-transparent"
              aria-hidden="true"
            />
          )}
          {loading === 'audit' ? 'Building…' : 'Download audit report'}
        </button>
      </div>
    </form>
  )
}
