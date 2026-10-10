import { useEffect, useState } from 'react'
import { Download } from 'lucide-react'
import EmptyState from '../components/EmptyState'
import { Banner, Panel } from '../components/ui'
import { download } from '../lib/format'
import { api } from '../services/api'
import { useAnalysis } from '../services/AnalysisContext'

const CONTENTS = [
  'Analysis timestamp and data source (synthetic demo vs uploaded)',
  'Dataset summary: event, finding and incident counts, skipped rows, warnings',
  'Findings with rule ID, severity, risk score, explanation and the source events',
  'Incidents with score breakdown, correlation basis and chronological timeline',
  'Detection rule definitions, thresholds and the scoring model used',
]

export default function Reports() {
  const { analysis, loading } = useAnalysis()
  const [report, setReport] = useState(null)
  const [error, setError] = useState(null)
  const id = analysis?.analysis_id

  useEffect(() => {
    if (!id) return
    api.getReport(id).then(setReport).catch(setError)
  }, [id])

  if (!analysis) return loading ? <p className="muted">Analysing log…</p> : <EmptyState />
  const fresh = report?.analysis_id === id ? report : null
  const text = fresh ? JSON.stringify(fresh, null, 2) : ''
  const preview = text.split('\n').slice(0, 70).join('\n')

  return (
    <>
      <Panel title="Investigation report (JSON)"
        actions={
          <button className="btn primary" disabled={!fresh}
            onClick={() => download(`traceguard_report_${id}.json`, text, 'application/json')}>
            <Download size={14} /> Download report
          </button>}>
        <p className="explain muted" style={{ marginBottom: 12 }}>
          Generated from the current analysis only (<span className="mono">{analysis.analysis_id}</span>). It contains:
        </p>
        <ul className="steps">{CONTENTS.map((c) => <li key={c}>{c}</li>)}</ul>
      </Panel>
      {error && <Banner kind="error" title={error.message} details={error.details} />}
      {fresh && (
        <Panel title={`Preview · first 70 of ${text.split('\n').length} lines`} flush>
          <pre className="pre">{preview}</pre>
        </Panel>
      )}
    </>
  )
}
