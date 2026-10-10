import { fmtTime, SEVERITIES } from '../lib/format'

// Chronological evidence timeline. Flagged events carry a severity marker;
// unflagged "context" events (same IP/account near the incident) are dimmed.
export default function Timeline({ events, findingsById }) {
  return (
    <ol className="timeline">
      {events.map((e) => {
        const fs = e.finding_ids.map((id) => findingsById[id]).filter(Boolean)
        const top = SEVERITIES.find((s) => fs.some((f) => f.severity === s))
        const rules = [...new Set(fs.map((f) => f.rule_id))]
        return (
          <li key={e.id} className={`tl-item ${e.suspicious ? `flag sev-${top}-m` : 'context'}`}>
            <span className="tl-time">{fmtTime(e.timestamp)}</span>
            <span className="tl-main">
              <span className="mono">{e.username}</span>
              <span className="mono muted">{e.source_ip}</span>
              <span>{e.event_type.replace('_', ' ')}</span>
              <span className={`st-${e.status}`}>{e.status}</span>
              {rules.map((r) => <span key={r} className="chip">{r}</span>)}
              {!e.suspicious && <span className="label">context</span>}
            </span>
          </li>
        )
      })}
    </ol>
  )
}
