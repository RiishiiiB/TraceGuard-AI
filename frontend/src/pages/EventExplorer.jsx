import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { Search } from 'lucide-react'
import EmptyState from '../components/EmptyState'
import { Pager, Panel } from '../components/ui'
import { fmtTime, matchesQuery } from '../lib/format'
import { useAnalysis } from '../services/AnalysisContext'

const PAGE = 50

export default function EventExplorer() {
  const { analysis, loading } = useAnalysis()
  const [q, setQ] = useState('')
  const [type, setType] = useState('all')
  const [status, setStatus] = useState('all')
  const [onlySuspicious, setOnlySuspicious] = useState(false)
  const [page, setPage] = useState(0)

  const findingToIncident = useMemo(
    () => Object.fromEntries((analysis?.findings ?? []).map((f) => [f.id, f.incident_id])), [analysis])

  const rows = useMemo(() => {
    if (!analysis) return []
    return analysis.events.filter((e) =>
      (type === 'all' || e.event_type === type) &&
      (status === 'all' || e.status === status) &&
      (!onlySuspicious || e.suspicious) &&
      matchesQuery(q, [e.username], [e.source_ip]))
  }, [analysis, q, type, status, onlySuspicious])

  if (!analysis) return loading ? <p className="muted">Analysing log…</p> : <EmptyState />

  const pages = Math.max(1, Math.ceil(rows.length / PAGE))
  const cur = Math.min(page, pages - 1)
  const slice = rows.slice(cur * PAGE, (cur + 1) * PAGE)
  const reset = (fn) => (v) => { fn(v); setPage(0) }

  return (
    <>
      <div className="filters">
        <label className="search">
          <Search size={14} />
          <input className="input" placeholder="Search username or source IP" value={q}
            onChange={(e) => reset(setQ)(e.target.value)} aria-label="Search username or source IP" />
        </label>
        <select className="select" value={type} onChange={(e) => reset(setType)(e.target.value)} aria-label="Event type">
          <option value="all">All event types</option>
          <option value="login">login</option>
          <option value="logout">logout</option>
          <option value="password_reset">password_reset</option>
        </select>
        <select className="select" value={status} onChange={(e) => reset(setStatus)(e.target.value)} aria-label="Status">
          <option value="all">Any status</option>
          <option value="success">success</option>
          <option value="failure">failure</option>
        </select>
        <label className="check">
          <input type="checkbox" checked={onlySuspicious} onChange={(e) => reset(setOnlySuspicious)(e.target.checked)} />
          Suspicious only
        </label>
        <span className="muted mono" style={{ marginLeft: 'auto' }}>{rows.length} of {analysis.events.length} events</span>
      </div>

      <Panel flush>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Event</th><th>Time (UTC)</th><th>Account</th><th>Source IP</th><th>Type</th><th>Status</th><th>Flagged by</th></tr></thead>
            <tbody>
              {slice.length === 0 && <tr className="empty-row"><td colSpan={7}>{analysis.events.length === 0 ? 'The dataset contains no events.' : 'No events match the current filters.'}</td></tr>}
              {slice.map((e) => (
                <tr key={e.id}>
                  <td className="mono muted">{e.id}</td>
                  <td className="mono">{fmtTime(e.timestamp)}</td>
                  <td className="mono">{e.username}</td>
                  <td className="mono">{e.source_ip}</td>
                  <td>{e.event_type.replace('_', ' ')}</td>
                  <td className={`st-${e.status}`}>{e.status}</td>
                  <td>
                    {e.finding_ids.length === 0 ? <span className="muted">—</span> :
                      [...new Set(e.finding_ids.map((f) => findingToIncident[f]))].map((inc) => (
                        <Link key={inc} className="incident-link" style={{ marginRight: 8 }} to={`/incidents/${inc}`}>{inc}</Link>
                      ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <Pager page={cur} pages={pages} total={rows.length} size={PAGE} onPage={setPage} />
      </Panel>
    </>
  )
}
