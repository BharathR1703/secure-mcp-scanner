import { useState } from 'react'
import ScannerForm from './components/ScannerForm'
import ResultsDisplay from './components/ResultsDisplay'
import CompliancePanel from './components/CompliancePanel'
import './App.css'

export default function App() {
  const [scanResult, setScanResult] = useState(null)
  const [complianceResult, setComplianceResult] = useState(null)
  const [auditResult, setAuditResult] = useState(null)

  return (
    <div className="min-h-screen bg-slate-50">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto max-w-4xl px-4 py-10">
          <p className="text-xs font-semibold uppercase tracking-widest text-indigo-600">
            MCP · Compliance · Privacy
          </p>
          <h1 className="mt-2 text-3xl font-bold tracking-tight text-slate-900">
            Secure MCP Scanner
          </h1>
          <p className="mt-2 text-slate-600">
            Production-ready MCP server with built-in PII, PHI and PCI masking —
            scans Postgres, MySQL, SQLite, ClickHouse and MongoDB
          </p>
        </div>
      </header>

      <main className="mx-auto max-w-4xl space-y-8 px-4 py-8">
        <ScannerForm
          onScan={setScanResult}
          onCompliance={setComplianceResult}
          onAudit={setAuditResult}
        />

        {auditResult && !auditResult.error && (
          <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-6 py-4">
            <p className="text-sm font-medium text-emerald-800">
              ✓ Audit report downloaded —{' '}
              <span className="font-mono">{auditResult.downloaded}</span>. The file
              contains control statuses and masked evidence only; no raw values.
            </p>
          </div>
        )}

        {auditResult?.error && (
          <div className="rounded-xl border border-red-200 bg-red-50 px-6 py-4">
            <p className="text-sm font-medium text-red-700">
              Audit report failed: {auditResult.error}
            </p>
          </div>
        )}

        {scanResult && <ResultsDisplay result={scanResult} />}
        {complianceResult && <CompliancePanel result={complianceResult} />}
      </main>

      <footer className="border-t border-slate-200 bg-white py-6">
        <p className="mx-auto max-w-4xl px-4 text-xs text-slate-400">
          DataGov Lite demo · Personal, health and cardholder data are detected
          with Microsoft Presidio and always returned masked. Compliance
          assessment covers HIPAA, PCI DSS, GDPR, DPDP, CCPA, SOC 2 and ISO
          27001. MCP tools are available over stdio (
          <span className="font-mono">python -m app.mcp_server</span>) and SSE (
          <span className="font-mono">/mcp/sse</span>).
        </p>
      </footer>
    </div>
  )
}
