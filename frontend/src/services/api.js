// Thin REST client for the FastAPI backend. All errors become ApiError with a
// human-readable message and optional list of details.
export class ApiError extends Error {
  constructor(message, details = []) {
    super(message)
    this.details = details
  }
}

async function request(path, options) {
  let res
  try {
    res = await fetch(path, options)
  } catch {
    throw new ApiError('Cannot reach the TraceGuard backend.', [
      'Start it with: uvicorn app.main:app --port 8000 (from the backend folder).',
    ])
  }
  if (res.ok) return res
  let message = `Request failed (HTTP ${res.status}).`
  let details = []
  try {
    const body = await res.json()
    const d = body.detail
    if (typeof d === 'string') message = d
    else if (Array.isArray(d)) message = d.map((x) => x.msg).join('; ')
    else if (d?.message) {
      message = d.message
      details = d.details || []
    }
  } catch {
    /* non-JSON error body */
  }
  throw new ApiError(message, details)
}

export const api = {
  analyzeDemo: async () => (await request('/api/analyze/demo', { method: 'POST' })).json(),
  analyzeFile: async (file) => {
    const form = new FormData()
    form.append('file', file)
    return (await request('/api/analyze', { method: 'POST', body: form })).json()
  },
  getAnalysis: async (id) => (await request(`/api/analysis/${id}`)).json(),
  getRules: async () => (await request('/api/rules')).json(),
  getReport: async (id) => (await request(`/api/analysis/${id}/report`)).json(),
  sampleCsvUrl: '/api/demo-data',
}
