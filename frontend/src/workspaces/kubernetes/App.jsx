import React, { useState, useCallback, useEffect } from 'react'
import { notify, onNotify } from './notify.js'
import TopBar from './TopBar.jsx'
import Workspace from './Workspace.jsx'
import { useApi } from './useApi.js'
import { nodeHosting } from './cloudProvider.js'
import { savedTheme } from '@/lib/themes'
import './styles.css'

function Toasts() {
  const [toasts, setToasts] = useState([])
  useEffect(() => onNotify(toast => {
    setToasts(current => [...current, toast].slice(-4))
    setTimeout(() => setToasts(current => current.filter(t => t.id !== toast.id)), 7000)
  }), [])
  return <div className="toast-region">{toasts.map(t => (
    <div key={t.id} className={`toast toast-${t.tone}`} role={t.tone === 'danger' ? 'alert' : 'status'}>
      <span>{t.message}</span>
      <button type="button" aria-label="Dismiss notification" onClick={() => setToasts(current => current.filter(x => x.id !== t.id))}>×</button>
    </div>
  ))}</div>
}

const STORAGE_KEY = 'operquay:k8s:session'

function readSession() {
  try {
    const raw = JSON.parse(sessionStorage.getItem(STORAGE_KEY) || 'null')
    if (!raw || typeof raw !== 'object') return {}
    const connections = Array.isArray(raw.connections) ? raw.connections.filter(c => c && typeof c.id === 'string' && c.info) : []
    const ids = new Set(connections.map(c => c.id))
    const opened = Array.isArray(raw.opened) ? raw.opened.filter(id => ids.has(id)) : []
    const activeCluster = typeof raw.activeCluster === 'string' && ids.has(raw.activeCluster) ? raw.activeCluster : null
    const screen = raw.screen === 'workspace' && activeCluster ? 'workspace' : 'clusters'
    return { connections, opened, activeCluster, screen }
  } catch { return {} }
}

export default function App() {
  const initialSession = useState(readSession)[0]
  const [connections, setConnections] = useState(() => initialSession.connections || [])
  const [activeCluster, setActiveCluster] = useState(() => initialSession.activeCluster || null)
  const [opened, setOpened] = useState(() => initialSession.opened || [])
  const [screen, setScreen] = useState(() => initialSession.screen || 'clusters')
  const [catalog, setCatalog] = useState({ items: [], connect: null, reauthenticate: null })
  const api = useApi()

  useEffect(() => {
    try {
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify({ connections, activeCluster, opened, screen }))
      if (window.parent && window.parent !== window) {
        window.parent.postMessage({
          type: 'operquay:k8s-session-changed',
          session: { connections, activeCluster, opened, screen }
        }, window.location.origin)
      }
    } catch { /* Ignore quota or private mode storage restrictions. */ }
  }, [connections, activeCluster, opened, screen])

  useEffect(() => {
    const onSelectClusterParent = event => {
      if (event.origin !== window.location.origin || event.source !== window.parent) return
      if (event.data?.type === 'operquay-select-kube-cluster') {
        const target = event.data.cluster
        if (!target) return
        const now = Date.now()
        const matchingConn = connections.find(c =>
          (target.id && c.id === target.id) ||
          (target.cluster_name && c.info?.name === target.cluster_name) ||
          (target.label && c.info?.name === target.label) ||
          (target.name && c.info?.name === target.name)
        )
        const isConnExpired = Boolean(
          event.data.expired ||
          (matchingConn?.info?.expires_at &&
            Number.isFinite(Date.parse(matchingConn.info.expires_at)) &&
            Date.parse(matchingConn.info.expires_at) <= now)
        )
        if (matchingConn && !isConnExpired) {
          openDashboard(matchingConn.id)
          window.postMessage({
            type: 'operquay-k8s-navigate',
            resource: { name: '__overview', kind: 'Overview', group: '', version: '' }
          }, window.location.origin)
        } else {
          setScreen('clusters')
        }
      }
    }
    window.addEventListener('message', onSelectClusterParent)
    return () => window.removeEventListener('message', onSelectClusterParent)
  }, [connections])

  useEffect(() => {
    if (!initialSession.connections?.length) return
    let cancelled = false
    Promise.all(initialSession.connections.map(async c => {
      try {
        const res = await fetch(`/api/k8s/namespaces?cluster=${encodeURIComponent(c.id)}`)
        return { id: c.id, ok: res.status !== 400 && res.status !== 404 }
      } catch {
        return { id: c.id, ok: true }
      }
    })).then(results => {
      if (cancelled) return
      const stale = new Set(results.filter(r => !r.ok).map(r => r.id))
      if (!stale.size) return
      setConnections(current => current.filter(c => !stale.has(c.id)))
      setOpened(current => current.filter(id => !stale.has(id)))
      setActiveCluster(current => {
        if (current && !stale.has(current)) return current
        setScreen('clusters')
        return null
      })
    })
    return () => { cancelled = true }
  }, [initialSession])

  useEffect(() => {
    // The main app owns the choice; this frame follows it, including changes made while it is open.
    const media = window.matchMedia('(prefers-color-scheme: dark)')
    const syncTheme = () => { document.documentElement.dataset.theme = savedTheme() }
    syncTheme()
    window.addEventListener('storage', syncTheme); media.addEventListener('change', syncTheme)
    return () => { window.removeEventListener('storage', syncTheme); media.removeEventListener('change', syncTheme) }
  }, [])

  const handleConnected = useCallback((id, info) => {
    if (!id) { notify('The server did not return a cluster connection.'); return }
    setConnections(current => [...current.filter(c => c.id !== id), { id, info }])
    if (info.source !== 'aws') {
      const params = new URLSearchParams({ cluster: id, group: '', version: 'v1' })
      fetch(`/api/k8s/resources/nodes?${params}`).then(response => {
        if (!response.ok) throw new Error('Node information unavailable')
        return response.json()
      }).then(nodes => {
        const hosting = nodeHosting(nodes)
        if (hosting) setConnections(current => current.map(c => c.id === id && c.info === info ? { ...c, info: { ...c.info, nodeHosting: hosting } } : c))
      }).catch(() => {})
    }
    return id
  }, [])

  const handleConnect = useCallback(async (accountId, region, cluster) => {
    try {
      const res = await api.post('/api/k8s/connect', {
        account_id: accountId, region, cluster: cluster.name
      })
      const data = await res.json()
      if (!data.cluster_id) throw new Error(data.error || 'The server did not return a cluster connection.')
      handleConnected(data.cluster_id, { ...cluster, source: 'aws', accountId, region })
      return data.cluster_id
    } catch (err) {
      throw new Error('Connect failed: ' + err.message)
    }
  }, [api, handleConnected])

  const handleDisconnect = useCallback(async (id) => {
    if (id) {
      try {
        await api.post('/api/k8s/disconnect/' + encodeURIComponent(id))
        setConnections(current => current.filter(c => c.id !== id))
        setOpened(current => current.filter(c => c !== id))
        if (activeCluster === id) { setActiveCluster(null); setScreen('clusters') }
      } catch (err) { notify('Disconnect failed: ' + err.message) }
    }
  }, [activeCluster, api])

  const openDashboard = id => {
    setOpened(current => current.includes(id) ? current : [...current, id])
    setActiveCluster(id); setScreen('workspace')
  }

  return (
    <div className="app k8s-app">
      <Toasts />
      <div className="screen-slot" hidden={screen !== 'clusters'}>
      <TopBar
        connections={connections}
        onConnect={handleConnect}
        onConnected={handleConnected}
        onDisconnect={handleDisconnect}
        onDashboard={openDashboard}
        onCatalog={setCatalog}
      />
      </div>
      {connections.filter(c => opened.includes(c.id)).map(c => <div key={c.id} className="screen-slot" hidden={screen !== 'workspace' || activeCluster !== c.id}><Workspace clusterId={c.id} clusterInfo={c.info} connections={connections} catalog={catalog} visible={screen === 'workspace' && activeCluster === c.id} onSwitch={openDashboard} onClusters={() => setScreen('clusters')} onSignIn={() => { catalog.reauthenticate?.(); setScreen('clusters') }} /></div>)}
    </div>
  )
}
