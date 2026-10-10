import { createContext, useContext, useRef, useState } from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import {
  BookOpenCheck, Download, FileJson, FlaskConical, LayoutDashboard,
  PanelLeftClose, PanelLeftOpen, ShieldAlert, Table2, Upload,
} from 'lucide-react'
import { api } from '../services/api'
import { useAnalysis } from '../services/AnalysisContext'
import { Banner } from './ui'

const PickerCtx = createContext(() => {})
export const useUploadPicker = () => useContext(PickerCtx)

const NAV = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/incidents', label: 'Incidents', icon: ShieldAlert },
  { to: '/events', label: 'Event Explorer', icon: Table2 },
  { to: '/rules', label: 'Detection Rules', icon: BookOpenCheck },
  { to: '/reports', label: 'Reports', icon: FileJson },
]

function pageTitle(pathname) {
  if (pathname.startsWith('/incidents/')) return 'Incident detail'
  return NAV.find((n) => (n.end ? pathname === n.to : pathname.startsWith(n.to)))?.label ?? 'TraceGuard AI'
}

export default function Shell({ children }) {
  const { analysis, loading, error, clearError, loadDemo: runDemo, uploadFile } = useAnalysis()
  const { pathname } = useLocation()
  const navigate = useNavigate()
  // A new dataset invalidates incident routes, so land on the overview after a successful analysis.
  const loadDemo = async () => { if (await runDemo()) navigate('/') }
  const [collapsed, setCollapsed] = useState(false)
  const input = useRef(null)
  const pick = () => input.current?.click()

  const onFile = (e) => {
    const file = e.target.files?.[0]
    e.target.value = '' // allow re-selecting the same file
    if (file) uploadFile(file).then((ok) => ok && navigate('/'))
  }

  return (
    <PickerCtx.Provider value={pick}>
      <div className={`app${collapsed ? ' collapsed' : ''}`}>
        <aside className="sidebar">
          <div className="brand">
            <div className="brand-mark">T</div>
            <div className="brand-text">
              <div className="brand-name">TRACEGUARD AI</div>
              <div className="brand-sub">Incident Investigator</div>
            </div>
          </div>
          <nav className="nav" aria-label="Primary">
            <div className="label nav-group">Investigation</div>
            {NAV.map(({ to, label, icon: Icon, end }) => (
              <NavLink key={to} to={to} end={end} title={label}>
                <Icon size={17} />
                <span className="nav-text">{label}</span>
              </NavLink>
            ))}
          </nav>
          <div className="side-foot">
            Academic prototype.<br />Deterministic rules, no ML or LLM. Scores are heuristics.
          </div>
          <button className="icon-btn" onClick={() => setCollapsed((c) => !c)} aria-label="Toggle sidebar">
            {collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
          </button>
        </aside>

        <div className="main">
          <header className="topbar">
            <div>
              <div className="label crumb">
                {analysis ? <>Dataset · <span className="mono" style={{ textTransform: 'none', letterSpacing: 0 }}>{analysis.source_name}</span></> : 'Digital forensics workstation'}
              </div>
              <h1>{pageTitle(pathname)}</h1>
            </div>
            <div className="topbar-actions">
              {analysis && (
                <span className={`badge ${analysis.is_demo ? 'tag-demo' : 'tag-real'}`}>
                  {analysis.is_demo ? 'SYNTHETIC DEMO DATA' : 'UPLOADED LOG'}
                </span>
              )}
              <a className="btn ghost" href={api.sampleCsvUrl} title="Download the synthetic sample CSV"><Download size={14} /> Sample CSV</a>
              <button className="btn" onClick={pick} disabled={loading}><Upload size={14} /> Upload CSV</button>
              <button className="btn primary" onClick={loadDemo} disabled={loading}><FlaskConical size={14} /> {loading ? 'Analysing…' : 'Load demo data'}</button>
              <input ref={input} type="file" accept=".csv,text/csv" hidden onChange={onFile} />
            </div>
          </header>
          {loading ? <div className="loading-bar" role="progressbar" aria-label="Analysing" /> : <div style={{ height: 2 }} />}

          <main className="content">
            <div className="content-inner">
              {error && <Banner kind="error" title={error.message} details={error.details} onClose={clearError} />}
              {analysis && (
                <Banner kind={analysis.is_demo ? 'demo' : 'info'} title={analysis.is_demo ? 'Synthetic demonstration data' : 'Heuristic analysis of an uploaded log'}>
                  {analysis.data_notice}
                </Banner>
              )}
              {analysis?.summary.warnings.length > 0 && (
                <Banner kind="info" title="Data quality notes" details={[...analysis.summary.warnings, ...analysis.summary.row_errors]} />
              )}
              {children}
            </div>
          </main>
        </div>
      </div>
    </PickerCtx.Provider>
  )
}
