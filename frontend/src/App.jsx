import { HashRouter, Route, Routes } from 'react-router-dom'
import Shell from './components/Shell'
import { AnalysisProvider } from './services/AnalysisContext'
import EventExplorer from './pages/EventExplorer'
import IncidentDetail from './pages/IncidentDetail'
import Incidents from './pages/Incidents'
import Overview from './pages/Overview'
import Reports from './pages/Reports'
import Rules from './pages/Rules'

export default function App() {
  return (
    <HashRouter>
      <AnalysisProvider>
        <Shell>
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            <Route path="/events" element={<EventExplorer />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="*" element={<Overview />} />
          </Routes>
        </Shell>
      </AnalysisProvider>
    </HashRouter>
  )
}
