// Shared vocabulary for the scanner UI.
//
// The category list and the framework list mirror the backend's
// /api/frameworks endpoint. They are written out here so the form can
// render them before the first request, and so the badges and the
// selectors always agree with each other.

export const CATEGORIES = [
  {
    key: 'PII',
    label: 'PII',
    blurb: 'Personal data — names, emails, phone numbers, PAN, Aadhaar',
    styles: 'bg-sky-100 text-sky-800 ring-sky-200',
  },
  {
    key: 'PHI',
    label: 'PHI',
    blurb: 'Protected health information — records, diagnoses, medications',
    styles: 'bg-violet-100 text-violet-800 ring-violet-200',
  },
  {
    key: 'PCI',
    label: 'PCI',
    blurb: 'Cardholder data — card numbers, CVVs, expiry dates',
    styles: 'bg-rose-100 text-rose-800 ring-rose-200',
  },
]

export const FRAMEWORKS = [
  {
    key: 'HIPAA',
    label: 'HIPAA',
    blurb: 'Health data — 45 CFR Parts 160 and 164',
  },
  {
    key: 'PCI_DSS',
    label: 'PCI DSS',
    blurb: 'Cardholder data — PCI DSS v4.0',
  },
  {
    key: 'GDPR',
    label: 'GDPR',
    blurb: 'Personal data — EU 2016/679',
  },
  {
    key: 'DPDP',
    label: 'DPDP',
    blurb: 'Personal data — India, 2023',
  },
  {
    key: 'CCPA',
    label: 'CCPA',
    blurb: 'Personal data — Cal. Civ. Code 1798.100 et seq.',
  },
  {
    key: 'SOC2',
    label: 'SOC 2',
    blurb: 'Trust Services Criteria',
  },
  {
    key: 'ISO27001',
    label: 'ISO 27001',
    blurb: 'Information security — 2022, Annex A',
  },
]

export const CATEGORY_STYLES = Object.fromEntries(
  CATEGORIES.map((category) => [category.key, category.styles]),
)

export const CATEGORY_FALLBACK = 'bg-slate-100 text-slate-700 ring-slate-200'

export const STATUS_STYLES = {
  PASS: 'bg-emerald-100 text-emerald-800 ring-emerald-200',
  COMPLIANT: 'bg-emerald-100 text-emerald-800 ring-emerald-200',
  FAIL: 'bg-red-100 text-red-800 ring-red-200',
  NON_COMPLIANT: 'bg-red-100 text-red-800 ring-red-200',
  REVIEW: 'bg-amber-100 text-amber-800 ring-amber-200',
  NEEDS_REVIEW: 'bg-amber-100 text-amber-800 ring-amber-200',
  NOT_APPLICABLE: 'bg-slate-100 text-slate-600 ring-slate-200',
}

export const SEVERITY_STYLES = {
  critical: 'bg-red-50 text-red-700 ring-red-200',
  high: 'bg-orange-50 text-orange-700 ring-orange-200',
  medium: 'bg-amber-50 text-amber-700 ring-amber-200',
  low: 'bg-sky-50 text-sky-700 ring-sky-200',
  informational: 'bg-slate-50 text-slate-600 ring-slate-200',
}
