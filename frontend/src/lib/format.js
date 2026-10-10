// API timestamps are UTC ISO strings; show them compactly, always labelled UTC in the UI.
export const fmtTime = (iso) => (iso ? iso.slice(0, 19).replace('T', ' ') : '—')
export const fmtShort = (iso) => (iso ? iso.slice(5, 16).replace('T', ' ') : '—')
export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
export const SEV_COLOR = { CRITICAL: '#FF6B5F', HIGH: '#E9B44C', MEDIUM: '#9a7a35', LOW: '#70C7B4' }

export function matchesQuery(q, usernames = [], ips = []) {
  const s = q.trim().toLowerCase()
  if (!s) return true
  return usernames.some((u) => u.toLowerCase().includes(s)) || ips.some((i) => i.includes(s))
}

export function download(filename, text, mime) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
