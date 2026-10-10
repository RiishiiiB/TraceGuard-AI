import { useEffect, useState } from 'react'
import { Banner, Panel } from '../components/ui'
import { api } from '../services/api'

export default function Rules() {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    api.getRules().then(setData).catch(setError)
  }, [])

  if (error) return <Banner kind="error" title={error.message} details={error.details} />
  if (!data) return <p className="muted">Loading rule reference…</p>

  return (
    <>
      <Panel title="Detection rules" flush>
        {data.rules.map((r) => (
          <div key={r.id} className="rule-card">
            <div>
              <div className="rule-id">{r.id}</div>
              <div className="label" style={{ marginTop: 4 }}>base {r.base_score}</div>
            </div>
            <div>
              <h3 style={{ fontSize: 14, fontWeight: 600 }}>{r.name}</h3>
              <p className="muted" style={{ margin: '2px 0 8px' }}>{r.description}</p>
              <p className="explain"><span className="label">Logic </span>{r.logic}</p>
              <p style={{ margin: '8px 0' }}>
                {Object.entries(r.parameters).map(([k, v]) => <span key={k} className="chip">{k} = {String(v)}</span>)}
              </p>
              <p className="note">{r.benign_causes}</p>
            </div>
          </div>
        ))}
      </Panel>

      <div className="grid-2" style={{ gridTemplateColumns: 'repeat(2, minmax(0, 1fr))' }}>
        <Panel title="Risk scoring model (0–100)">
          <p className="muted" style={{ marginBottom: 12 }}>{data.scoring_model.disclaimer}</p>
          <div className="label" style={{ marginBottom: 6 }}>Finding score</div>
          <table className="factors">
            <tbody>{data.scoring_model.finding_factors.map((f) => (
              <tr key={f.factor}><td>{f.factor}</td><td className="mono muted" style={{ textAlign: 'right' }}>{f.detail}</td></tr>
            ))}</tbody>
          </table>
          <div className="label" style={{ margin: '16px 0 6px' }}>Incident score</div>
          <table className="factors">
            <tbody>{data.scoring_model.incident_factors.map((f) => (
              <tr key={f.factor}><td>{f.factor}</td><td className="mono muted" style={{ textAlign: 'right' }}>{f.detail}</td></tr>
            ))}</tbody>
          </table>
          <div className="label" style={{ margin: '16px 0 6px' }}>Severity bands</div>
          <p>
            {[...data.scoring_model.severity_bands].reverse().map((b) => (
              <span key={b.severity} className={`badge sev-${b.severity}`} style={{ marginRight: 8 }}>{b.severity} ≥ {b.min_score}</span>
            ))}
          </p>
        </Panel>

        <div className="stack">
          <Panel title="Incident correlation">
            <p className="explain">{data.correlation_model.description}</p>
          </Panel>
          <Panel title="Scope and limitations">
            <ul className="steps">{data.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
          </Panel>
        </div>
      </div>
    </>
  )
}
