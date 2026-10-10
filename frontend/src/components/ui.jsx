import { AlertTriangle, FlaskConical, Info, X } from 'lucide-react'
import { SEVERITIES } from '../lib/format'

export const SeverityBadge = ({ level }) => <span className={`badge sev-${level}`}>{level}</span>

export function ScoreMeter({ score, severity, ticks = false }) {
  return (
    <div className="meter" role="meter" aria-valuenow={score} aria-valuemin={0} aria-valuemax={100} title={`Risk score ${score}/100`}>
      <i className={`meter-fill-${severity}`} style={{ width: `${score}%` }} />
      {ticks && [30, 55, 80].map((t) => <span key={t} className="tick" style={{ left: `${t}%` }} />)}
    </div>
  )
}

export function ScoreCell({ score, severity }) {
  return (
    <div className="score-cell">
      <span className="mono">{score}</span>
      <ScoreMeter score={score} severity={severity} />
    </div>
  )
}

export function Panel({ title, actions, flush, children }) {
  return (
    <section className="panel">
      {(title || actions) && (
        <div className="panel-head">
          <h2>{title}</h2>
          {actions}
        </div>
      )}
      <div className={`panel-body${flush ? ' flush' : ''}`}>{children}</div>
    </section>
  )
}

export function Banner({ kind = 'info', title, children, details, onClose }) {
  const Icon = kind === 'error' ? AlertTriangle : kind === 'demo' ? FlaskConical : Info
  const color = kind === 'error' ? 'var(--coral)' : kind === 'demo' ? 'var(--amber)' : 'var(--teal)'
  return (
    <div className={`banner ${kind}`} role={kind === 'error' ? 'alert' : 'status'}>
      <Icon size={16} color={color} />
      <div>
        {title && <div style={{ fontWeight: 600 }}>{title}</div>}
        {children && <div className="muted">{children}</div>}
        {details?.length > 0 && <ul>{details.map((d, i) => <li key={i}>{d}</li>)}</ul>}
      </div>
      {onClose && <button className="close" onClick={onClose} aria-label="Dismiss"><X size={14} /></button>}
    </div>
  )
}

export function SeverityFilter({ value, onChange, counts }) {
  return (
    <div className="seg" role="group" aria-label="Filter by severity">
      {['ALL', ...SEVERITIES].map((s) => (
        <button key={s} className={value === s ? 'on' : ''} onClick={() => onChange(s)}>
          {s === 'ALL' ? 'All' : s[0] + s.slice(1).toLowerCase()}
          <span className="n">{s === 'ALL' ? counts.total : counts[s] ?? 0}</span>
        </button>
      ))}
    </div>
  )
}

export function Chips({ items }) {
  return <>{items.map((i) => <span key={i} className="chip">{i}</span>)}</>
}

export function Pager({ page, pages, total, size, onPage }) {
  const from = total ? page * size + 1 : 0
  return (
    <div className="pager">
      <span>{from}–{Math.min(total, (page + 1) * size)} of {total}</span>
      <span className="btns">
        <button className="btn" disabled={page === 0} onClick={() => onPage(page - 1)}>Prev</button>
        <button className="btn" disabled={page >= pages - 1} onClick={() => onPage(page + 1)}>Next</button>
      </span>
    </div>
  )
}
