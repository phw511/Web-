// 统一请求封装：401 只清令牌并跳登录（不再无脑 location.href 造成死循环），
// 错误优先取后端 detail，便于界面显示"为什么被拒"而不是一个裸状态码。
export function req(path, opts = {}) {
  const token = localStorage.getItem('token')
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: 'Bearer ' + token } : {}),
    ...(opts.headers || {}),
  }
  return fetch('/api' + path, { ...opts, headers }).then(async (r) => {
    if (r.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('role')
      if (location.pathname !== '/login') location.href = '/login'
      throw new Error('登录已过期，请重新登录')
    }
    const text = await r.text()
    let data = null
    if (text) {
      try { data = JSON.parse(text) } catch { data = text }
    }
    if (!r.ok) {
      const detail = data && data.detail ? data.detail : r.status
      throw new Error(typeof detail === 'string' ? detail : JSON.stringify(detail))
    }
    return data
  })
}
export const post = (p, body) => req(p, { method: 'POST', body: JSON.stringify(body) })
