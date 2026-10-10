import { Fragment, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Search } from 'lucide-react'
import EmptyState from '../components/EmptyState'
import FindingDetail from '../components/FindingDetail'
import { Chips, Panel, ScoreCell, SeverityBadge, SeverityFilter } from '../components/ui'
import { fmtTime, matchesQuery } from '../lib/format'
import { useAnalysis } from '../services/AnalysisContext'

const shorten = (list, n = 3) => list.slice(0, n).join(', ') + (list.length > n ? ` +${list.length - n}` : '')

export default function Incidents() {
  const { analysis, loading } = useAnalysis()
  const navigate = useNavigate()
  const [view, setView] = useState('incidents')
  const [sev, setSev] = useState('ALL')
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(null)

  const rows = useMemo(() => {
    if (!analysis) return []
    const src = view === 'incidents' ? analysis.incidents : analysis.findings
    return src
      .filter((r) => matchesQuery(q, r.usernames, r.source_ips))
      .sort((a, b) => b.risk_score - a.risk_score || a.first_seen.localeCompare(b.first_seen))
  }, [analysis, view, q])

  if (!analysis) return loading ? <p className="muted">Analysing log…</p> : <EmptyState />

  const counts = { total: rows.length }
  rows.forEach((r) => { counts[r.severity] = (counts[r.severity] ?? 0) + 1 })
  const shown = sev === 'ALL' ? rows : rows.filter((r) => r.severity === sev)

  return (
    <>
      <div className="filters">
        <div className="seg" role="group" aria-label="View">
          <button className={view === 'incidents' ? 'on' : ''} onClick={() => { setView('incidents'); setOpen(null) }}>
            Incidents<span className="n">{analysis.incidents.length}</span>
          </button>
          <button className={view === 'findings' ? 'on' : ''} onClick={() => { setView('findings'); setOpen(null) }}>
            Findings<span className="n">{analysis.findings.length}</span>
          </button>
        </div>
        <SeverityFilter value={sev} onChange={setSev} counts={counts} />
        <label className="search">
          <Search size={14} />
          <input className="input" placeholder="Search username or source IP" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search username or source IP" />
        </label>
      </div>

      <Panel flush>
        <div className="table-wrap">
          {view === 'incidents' ? (
            <table className="table">
              <thead><tr><th>Incident</th><th>Severity</th><th>Risk score</th><th>Accounts</th><th>Source IPs</th><th>Rules</th><th className="num">Events</th><th className="num">Findings</th><th>First seen (UTC)</th></tr></thead>
              <tbody>
                {shown.length === 0 && <tr className="empty-row"><td colSpan={9}>{analysis.incidents.length === 0 ? 'No incidents detected in this dataset.' : 'No incidents match the current filters.'}</td></tr>}
                {shown.map((i) => (
                  <tr key={i.id} className="click" onClick={() => navigate(`/incidents/${i.id}`)}>
                    <td><Link className="incident-link" to={`/incidents/${i.id}`}>{i.id}</Link></td>
                    <td><SeverityBadge level={i.severity} /></td>
                    <td><ScoreCell score={i.risk_score} severity={i.severity} /></td>
                    <td className="mono">{shorten(i.usernames)}</td>
                    <td className="mono">{shorten(i.source_ips, 2)}</td>
                    <td><Chips items={i.rule_ids} /></td>
                    <td className="num mono">{i.event_count}</td>
                    <td className="num mono">{i.finding_count}</td>
                    <td className="mono muted">{fmtTime(i.first_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <table className="table">
              <thead><tr><th>Finding</th><th>Severity</th><th>Risk score</th><th>Rule</th><th>Accounts</th><th>Source IPs</th><th className="num">Events</th><th>First seen (UTC)</th><th>Incident</th></tr></thead>
              <tbody>
                {shown.length === 0 && <tr className="empty-row"><td colSpan={9}>{analysis.findings.length === 0 ? 'No findings detected in this dataset.' : 'No findings match the current filters.'}</td></tr>}
                {shown.map((f) => (
                  <Fragment key={f.id}>
                    <tr className={`click${open === f.id ? ' open' : ''}`} onClick={() => setOpen(open === f.id ? null : f.id)}>
                      <td className="mono">{f.id}</td>
                      <td><SeverityBadge level={f.severity} /></td>
                      <td><ScoreCell score={f.risk_score} severity={f.severity} /></td>
                      <td><span className="chip">{f.rule_id}</span> {f.rule_name}</td>
                      <td className="mono">{shorten(f.usernames)}</td>
                      <td className="mono">{shorten(f.source_ips, 2)}</td>
                      <td className="num mono">{f.event_ids.length}</td>
                      <td className="mono muted">{fmtTime(f.first_seen)}</td>
                      <td onClick={(e) => e.stopPropagation()}><Link className="incident-link" to={`/incidents/${f.incident_id}`}>{f.incident_id}</Link></td>
                    </tr>
                    {open === f.id && (
                      <tr><td colSpan={9} style={{ padding: 0, background: 'var(--wash)' }}><FindingDetail finding={f} /></td></tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </Panel>
    </>
  )
}
