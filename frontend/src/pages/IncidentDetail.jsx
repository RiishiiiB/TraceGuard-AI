import { useMemo } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArrowLeft } from 'lucide-react'
import EmptyState from '../components/EmptyState'
import FindingDetail from '../components/FindingDetail'
import Timeline from '../components/Timeline'
import { Chips, Panel, ScoreMeter, SeverityBadge } from '../components/ui'
import { fmtTime } from '../lib/format'
import { useAnalysis } from '../services/AnalysisContext'

export default function IncidentDetail() {
  const { id } = useParams()
  const { analysis, loading } = useAnalysis()
  const findingsById = useMemo(
    () => Object.fromEntries((analysis?.findings ?? []).map((f) => [f.id, f])), [analysis])

  if (!analysis) return loading ? <p className="muted">Analysing log…</p> : <EmptyState />
  const inc = analysis.incidents.find((i) => i.id === id)
  if (!inc) {
    return (
      <div className="empty-state">
        <h2>Incident {id} not found</h2>
        <p className="muted">It may belong to a previously loaded dataset.</p>
        <p style={{ marginTop: 14 }}><Link className="incident-link" to="/incidents">← Back to incidents</Link></p>
      </div>
    )
  }
  const findings = inc.finding_ids.map((f) => findingsById[f])
  const total = inc.score_factors.reduce((n, f) => n + f.points, 0)
  const flaggedInTimeline = inc.timeline.filter((e) => e.suspicious).length

  return (
    <>
      <Link to="/incidents" className="muted" style={{ display: 'inline-flex', gap: 6, alignItems: 'center', fontSize: 12.5 }}>
        <ArrowLeft size={14} /> All incidents
      </Link>

      <div className="detail-grid">
        <div className="stack">
          <Panel title="Why this was flagged">
            <div className="finding-head">
              <SeverityBadge level={inc.severity} />
              <h3 className="mono" style={{ fontSize: 16 }}>{inc.id}</h3>
              <Chips items={inc.rule_ids} />
            </div>
            <p className="explain">{inc.summary}</p>
            <dl className="kv" style={{ marginTop: 14 }}>
              <dt>Observed (UTC)</dt><dd>{fmtTime(inc.first_seen)} → {fmtTime(inc.last_seen)}</dd>
              <dt>Accounts</dt><dd>{inc.usernames.join(', ')}</dd>
              <dt>Source IPs</dt><dd>{inc.source_ips.join(', ')}</dd>
              <dt>Flagged events</dt><dd>{inc.event_count} unique · {inc.finding_count} finding(s)</dd>
            </dl>
          </Panel>

          <Panel title={`Detection explanations (${findings.length})`} flush>
            {findings.map((f) => <FindingDetail key={f.id} finding={f} />)}
          </Panel>

          <Panel title={`Evidence timeline · ${flaggedInTimeline} flagged, ${inc.timeline.length - flaggedInTimeline} context`}>
            <Timeline events={inc.timeline} findingsById={findingsById} />
            <p className="muted" style={{ fontSize: 12, marginTop: 10 }}>
              Context events are not flagged by any rule; they are shown because they share an account or IP
              with the incident near its time range, and are not counted in the score.
            </p>
          </Panel>
        </div>

        <div className="aside-stack">
          <Panel title="Risk score (heuristic)">
            <div className="score-big" style={{ color: inc.severity === 'CRITICAL' ? 'var(--coral)' : 'var(--paper)' }}>
              {inc.risk_score}<span className="muted" style={{ fontSize: 16 }}> / 100</span>
            </div>
            <div style={{ margin: '12px 0 4px' }}><ScoreMeter score={inc.risk_score} severity={inc.severity} ticks /></div>
            <div className="label" style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9.5 }}>
              <span>Low</span><span>30 Med</span><span>55 High</span><span>80 Crit</span>
            </div>
            <table className="factors" style={{ marginTop: 14 }}>
              <tbody>
                {inc.score_factors.map((f) => (
                  <tr key={f.factor}><td>{f.factor}<div className="muted" style={{ fontSize: 11.5 }}>{f.note}</div></td><td className="pts">+{f.points}</td></tr>
                ))}
                <tr className="total"><td>Total (capped at 100)</td><td className="pts">{Math.min(100, total)}</td></tr>
              </tbody>
            </table>
            <p className="muted" style={{ fontSize: 11.5, marginTop: 10 }}>
              A prioritisation heuristic, not a calibrated probability of compromise. Each event is counted once, even if several rules matched it.
            </p>
          </Panel>

          <Panel title="Correlation basis">
            <ul className="steps">{inc.correlation_basis.map((b) => <li key={b}>{b}</li>)}</ul>
          </Panel>

          <Panel title="Suggested investigation steps">
            <ol className="steps">{inc.suggested_steps.map((s) => <li key={s}>{s}</li>)}</ol>
          </Panel>
        </div>
      </div>
    </>
  )
}
