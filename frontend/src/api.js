export function req(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json',
    Authorization: 'Bearer ' + localStorage.getItem('token'), ...(opts.headers || {}) }
  return fetch('/api' + path, { ...opts, headers }).then(async (r) => {
    if (r.status === 401) { localStorage.clear(); location.href = '/login' }
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.status)
    return r.json()
  })
}
export const post = (p, body) => req(p, { method: 'POST', body: JSON.stringify(body) })
