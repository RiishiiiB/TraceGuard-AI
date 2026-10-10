import { Link } from 'react-router-dom'
import { fmtTime } from '../lib/format'
import { SeverityBadge } from './ui'

// Full explanation for one finding: why it fired, the exact evidence, and how the score was built.
export default function FindingDetail({ finding: f, showIncident = false }) {
  return (
    <div className="finding-block">
      <div className="finding-head">
        <SeverityBadge level={f.severity} />
        <span className="chip">{f.rule_id}</span>
        <h3>{f.rule_name}</h3>
        <span className="mono muted">{f.id}</span>
        {showIncident && f.incident_id && (
          <Link className="incident-link" to={`/incidents/${f.incident_id}`}>{f.incident_id}</Link>
        )}
      </div>
      <p className="explain">{f.explanation}</p>
      <dl className="evidence">
        {f.evidence.map((ev) => (
          <div key={ev.label}><dt>{ev.label}</dt><dd>{ev.value}</dd></div>
        ))}
        <div><dt>Observed window (UTC)</dt><dd>{fmtTime(f.first_seen)} → {fmtTime(f.last_seen)}</dd></div>
        <div><dt>Source events</dt><dd>{f.event_ids.length} ({f.event_ids[0]} … {f.event_ids[f.event_ids.length - 1]})</dd></div>
      </dl>
      <table className="factors" style={{ maxWidth: 520, marginBottom: 12 }}>
        <tbody>
          {f.score_factors.map((s) => (
            <tr key={s.factor}><td>{s.factor} <span className="muted">— {s.note}</span></td><td className="pts">+{s.points}</td></tr>
          ))}
          <tr className="total"><td>Finding risk score (cap 100)</td><td className="pts">{f.risk_score}</td></tr>
        </tbody>
      </table>
      <p className="note"><strong style={{ color: 'var(--amber)', fontWeight: 500 }}>Possible benign explanation.</strong> {f.caveat}</p>
    </div>
  )
}
