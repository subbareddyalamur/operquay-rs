const apiClient = {
  get: async (path, params = {}, opts = {}) => {
    const url = new URL(window.location.origin + path)
    Object.entries(params).forEach(([k, v]) => {
      if (v != null) url.searchParams.set(k, v)
    })
    const res = await fetch(url.toString(), opts.signal ? { signal: opts.signal } : undefined)
    if (!res.ok) throw new Error(await res.text())
    return res
  },

  post: async (path, body = {}, opts = {}) => {
    const res = await fetch(window.location.origin + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: opts.signal,
    })
    if (!res.ok) throw new Error(await res.text())
    return res
  },

  ws: (path, params = {}) => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const url = new URL(proto + '//' + window.location.host + path)
    Object.entries(params).forEach(([k, v]) => {
      if (v != null) url.searchParams.set(k, v)
    })
    return new WebSocket(url.toString())
  },
}

export function useApi() {
  return apiClient
}
