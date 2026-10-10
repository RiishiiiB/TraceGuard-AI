import { useMemo } from 'react'
import { Link } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import EmptyState from '../components/EmptyState'
import { Chips, Panel, ScoreCell, SeverityBadge } from '../components/ui'
import { fmtShort, fmtTime, SEV_COLOR, SEVERITIES } from '../lib/format'
import { useAnalysis } from '../services/AnalysisContext'

const Tip = ({ active, payload, label }) =>
  active && payload?.length ? (
    <div className="chart-tip">
      <div className="muted">{label}</div>
      {payload.map((p) => <div key={p.dataKey}>{p.name ?? p.dataKey}: {p.value}</div>)}
    </div>
  ) : null

function activityBuckets(events) {
  if (!events.length) return []
  const span = new Date(events.at(-1).timestamp) - new Date(events[0].timestamp)
  const daily = span > 72 * 3600 * 1000
  const map = new Map()
  for (const e of events) {
    const key = e.timestamp.slice(0, daily ? 10 : 13) // YYYY-MM-DD or YYYY-MM-DDTHH
    const b = map.get(key) ?? { key, label: daily ? key.slice(5) : key.slice(11) + ':00', normal: 0, suspicious: 0 }
    if (e.suspicious) b.suspicious++
    else b.normal++
    map.set(key, b)
  }
  return [...map.values()].sort((a, b) => a.key.localeCompare(b.key))
}

export default function Overview() {
  const { analysis, loading } = useAnalysis()
  const buckets = useMemo(() => (analysis ? activityBuckets(analysis.events) : []), [analysis])

  if (!analysis) return loading ? <p className="muted">Analysing log…</p> : <EmptyState />
  const s = analysis.summary
  const sevData = SEVERITIES.map((k) => ({ name: k, value: s.incidents_by_severity[k] ?? 0 }))
  const recent = [...analysis.incidents].sort((a, b) => b.last_seen.localeCompare(a.last_seen)).slice(0, 6)
  const multiDay = buckets.length > 0 && buckets[0].key.length === 10

  return (
    <>
      <div className="metrics">
        <div className="metric"><div className="label">Events analysed</div><div className="value">{s.total_events}</div>
          <div className="hint">{s.unique_users} accounts · {s.unique_ips} source IPs</div></div>
        <div className="metric key"><div className="label">Suspicious events</div><div className="value">{s.suspicious_events}</div>
          <div className="hint">{s.findings_count} finding(s) from detection rules</div></div>
        <div className="metric key"><div className="label">Incidents detected</div><div className="value">{s.incidents_count}</div>
          <div className="hint">correlated by IP, account and time</div></div>
        <div className={`metric ${s.high_critical_incidents ? 'alert' : ''}`}><div className="label">High / Critical</div><div className="value">{s.high_critical_incidents}</div>
          <div className="hint">incidents needing priority review</div></div>
      </div>

      <div className="grid-2">
        <Panel title="Incident severity distribution">
          {s.incidents_count === 0 ? <p className="muted">No incidents were detected in this dataset.</p> : (
            <div className="chart-box">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={sevData} layout="vertical" margin={{ left: 12, right: 24 }}>
                  <CartesianGrid horizontal={false} />
                  <XAxis type="number" allowDecimals={false} domain={[0, 'dataMax']} />
                  <YAxis type="category" dataKey="name" width={78} />
                  <Tooltip content={<Tip />} cursor={{ fill: 'rgba(232,230,217,0.05)' }} />
                  <Bar dataKey="value" name="Incidents" barSize={20} isAnimationActive={false}>
                    {sevData.map((d) => <Cell key={d.name} fill={SEV_COLOR[d.name]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>

        <Panel title={`Event activity per ${multiDay ? 'day' : 'hour'} (UTC)`}>
          {buckets.length === 0 ? <p className="muted">No events to chart.</p> : (
            <div className="chart-box">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={buckets} margin={{ left: -12, right: 8 }}>
                  <CartesianGrid vertical={false} />
                  <XAxis dataKey="label" interval="preserveStartEnd" />
                  <YAxis allowDecimals={false} />
                  <Tooltip content={<Tip />} cursor={{ fill: 'rgba(232,230,217,0.05)' }} />
                  <Bar dataKey="normal" name="Unflagged events" stackId="a" fill="#9CA99A" fillOpacity={0.55} isAnimationActive={false} />
                  <Bar dataKey="suspicious" name="Suspicious events" stackId="a" fill="#FF6B5F" isAnimationActive={false} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Panel>
      </div>

      <Panel title="Recent incident activity" flush
        actions={<Link className="incident-link" to="/incidents">All incidents →</Link>}>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Incident</th><th>Severity</th><th>Risk</th><th>Accounts</th><th>Source IPs</th><th>Rules</th><th>Last seen (UTC)</th></tr></thead>
            <tbody>
              {recent.length === 0 && <tr className="empty-row"><td colSpan={7}>No incidents detected. Ordinary activity produced no findings.</td></tr>}
              {recent.map((i) => (
                <tr key={i.id}>
                  <td><Link className="incident-link" to={`/incidents/${i.id}`}>{i.id}</Link></td>
                  <td><SeverityBadge level={i.severity} /></td>
                  <td><ScoreCell score={i.risk_score} severity={i.severity} /></td>
                  <td className="mono">{i.usernames.slice(0, 3).join(', ')}{i.usernames.length > 3 && ` +${i.usernames.length - 3}`}</td>
                  <td className="mono">{i.source_ips.slice(0, 2).join(', ')}{i.source_ips.length > 2 && ` +${i.source_ips.length - 2}`}</td>
                  <td><Chips items={i.rule_ids} /></td>
                  <td className="mono muted">{fmtTime(i.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
      <p className="muted" style={{ fontSize: 12 }}>
        Data window: <span className="mono">{fmtShort(s.first_event)}</span> to <span className="mono">{fmtShort(s.last_event)}</span> UTC ·
        {' '}{s.rows_received} rows received, {s.rows_skipped} skipped, {s.duplicates_removed} duplicate(s) removed.
      </p>
    </>
  )
}
