import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { api, ApiError } from './api'

const Ctx = createContext(null)
const KEY = 'traceguard.analysisId'

export function AnalysisProvider({ children }) {
  const [analysis, setAnalysis] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const run = useCallback(async (fn) => {
    setLoading(true)
    setError(null)
    try {
      const result = await fn()
      setAnalysis(result)
      try { sessionStorage.setItem(KEY, result.analysis_id) } catch { /* storage unavailable */ }
      return true
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(e.message || 'Unexpected error'))
      return false
    } finally {
      setLoading(false)
    }
  }, [])

  // Restore the last analysis after a page refresh (the backend keeps results in memory).
  useEffect(() => {
    let id = null
    try { id = sessionStorage.getItem(KEY) } catch { /* ignore */ }
    if (id) api.getAnalysis(id).then(setAnalysis).catch(() => {})
  }, [])

  const value = useMemo(() => ({
    analysis, loading, error,
    loadDemo: () => run(api.analyzeDemo),
    uploadFile: (file) => run(() => api.analyzeFile(file)),
    clearError: () => setError(null),
  }), [analysis, loading, error, run])

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export const useAnalysis = () => useContext(Ctx)
