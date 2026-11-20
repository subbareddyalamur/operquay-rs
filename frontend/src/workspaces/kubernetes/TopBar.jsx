import React, { useState, useEffect, useRef } from 'react'
import { notify } from './notify.js'
import { useApi } from './useApi.js'
import { cloudNames, clusterHosting } from './cloudProvider.js'
import CloudIcon from './CloudIcon.jsx'

const REGIONS = [
  'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
  'eu-west-1', 'eu-west-2', 'eu-central-1',
  'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-south-1'
]

function proxyKey(value) {
  try {
    const url = new URL(value.includes('://') ? value : `https://${value}`)
    return url.protocol === 'https:' && !url.username && !url.password && (!url.pathname || url.pathname === '/') && !url.search && !url.hash ? url.host.toLowerCase() : ''
  } catch { return '' }
}

export default function TopBar({ connections, onConnect, onConnected, onDisconnect, onDashboard, onCatalog }) {
  const [mode, setMode] = useState('teleport')
  const [step, setStep] = useState('signin')
  const [targetCluster, setTargetCluster] = useState(null)
  const [isTokenExpired, setIsTokenExpired] = useState(false)
  
  // AWS mode state
  const [accounts, setAccounts] = useState([])
  const [userAWS, setUserAWS] = useState(false)
  const [selectedAccount, setSelectedAccount] = useState('')
  const [selectedRegion, setSelectedRegion] = useState('')
  const [clusters, setClusters] = useState([])
  const [loading, setLoading] = useState(false)
  const [connecting, setConnecting] = useState('')
  const [now, setNow] = useState(Date.now())
  
  // Kubeconfig mode state
  const [kubeconfigClusters, setKubeconfigClusters] = useState([])
  const [selectedKubecluster, setSelectedKubecluster] = useState(null)

  const [teleportProxy, setTeleportProxy] = useState('')
  const [configuredClusters, setConfiguredClusters] = useState([])
  const [configuredChoice, setConfiguredChoice] = useState('manual')
  const [configuredError, setConfiguredError] = useState('')
  const clusterPicker = useRef(null)
  const [teleportMethod, setTeleportMethod] = useState('local')
  const [teleportAuth, setTeleportAuth] = useState('')
  const [teleportUsername, setTeleportUsername] = useState('')
  const [teleportPassword, setTeleportPassword] = useState('')
  const [teleportOTP, setTeleportOTP] = useState('')
  const [teleportClusters, setTeleportClusters] = useState(null)
  const [teleportBusy, setTeleportBusy] = useState(false)
  const [teleportError, setTeleportError] = useState('')
  const [connectionError, setConnectionError] = useState('')
  const [discoveryError, setDiscoveryError] = useState('')
  const teleportLogin = useRef({ generation: 0, id: null, popup: null, timer: null })
  const discovery = useRef(0)
  const passwordRef = useRef(null)
  const otpRef = useRef(null)
  
  const api = useApi()

  useEffect(() => {
    let live = true
    let generation = 0
    const load = async () => {
      const current = ++generation
      try {
        const response = await fetch('/api/k8s/configured-clusters')
        if (!response.ok) throw new Error('unavailable')
        const data = await response.json()
        if (!Array.isArray(data)) throw new Error('invalid')
        if (live && current === generation) { setConfiguredClusters(data); setConfiguredError('') }
      } catch { if (live && current === generation) setConfiguredError('Could not load configured clusters. You can enter a proxy manually.') }
    }
    const onMessage = event => { if (event.origin === window.location.origin && event.source === window.parent && event.data?.type === 'operquay-refresh-kube-clusters') void load() }
    window.addEventListener('message', onMessage)
    void load()
    return () => { live = false; window.removeEventListener('message', onMessage) }
  }, [])

  const chooseConfiguredCluster = id => {
    if (clusterPicker.current) { clusterPicker.current.open = false; clusterPicker.current.querySelector('summary')?.focus() }
    setConfiguredChoice(id); setTeleportClusters(null); setTeleportError(''); setTeleportPassword(''); setTeleportOTP('')
    const cluster = configuredClusters.find(item => item.id === id)
    if (cluster) { setTeleportProxy(cluster.proxy); setTeleportMethod(cluster.method); setTeleportAuth(cluster.connector || '') }
    else { setTeleportProxy(''); setTeleportAuth('') }
  }

  useEffect(() => {
    const onSelectClusterMessage = event => {
      if (event.origin !== window.location.origin || event.source !== window.parent) return
      if (event.data?.type === 'operquay-select-kube-cluster') {
        const target = event.data.cluster
        if (!target) return
        const matchingConn = connections.find(c =>
          (target.id && c.id === target.id) ||
          (target.cluster_name && c.info?.name === target.cluster_name) ||
          (target.label && c.info?.name === target.label) ||
          (target.name && c.info?.name === target.name)
        )
        const isConnExpired = Boolean(event.data.expired || (matchingConn?.info?.expires_at && Number.isFinite(Date.parse(matchingConn.info.expires_at)) && Date.parse(matchingConn.info.expires_at) <= now))
        if (matchingConn && !isConnExpired) {
          onDashboard(matchingConn.id)
          return
        }
        if (isConnExpired) {
          // Expired session -> Screen 2
          setTargetCluster(target)
          setIsTokenExpired(true)
          setMode('teleport')
          setStep('signin')
          setTeleportClusters(null)
          setTeleportError('')
          setTeleportPassword('')
          setTeleportOTP('')
          if (target.proxy || matchingConn?.info?.proxy) setTeleportProxy(target.proxy || matchingConn?.info?.proxy)
          if (target.method) setTeleportMethod(target.method)
          if (target.connector) setTeleportAuth(target.connector)
          setTimeout(() => {
            if (otpRef.current) otpRef.current.focus()
            else if (passwordRef.current) passwordRef.current.focus()
          }, 50)
          return
        }
        // New / disconnected target cluster -> Screen 1
        setTargetCluster(target)
        setIsTokenExpired(false)
        setMode('teleport')
        setStep('signin')
        setTeleportClusters(null)
        setTeleportError('')
        setTeleportPassword('')
        setTeleportOTP('')
        if (target.id && configuredClusters.some(item => item.id === target.id)) {
          setConfiguredChoice(target.id)
          const item = configuredClusters.find(c => c.id === target.id)
          if (item) {
            setTeleportProxy(item.proxy)
            setTeleportMethod(item.method)
            setTeleportAuth(item.connector || '')
          }
        } else if (target.proxy) {
          setConfiguredChoice(target.id || 'manual')
          setTeleportProxy(target.proxy)
          if (target.method) setTeleportMethod(target.method)
          setTeleportAuth(target.connector || '')
        }
        setTimeout(() => {
          if (otpRef.current) otpRef.current.focus()
          else if (passwordRef.current) passwordRef.current.focus()
        }, 50)
      } else if (event.data?.type === 'operquay-open-discovery-hub') {
        // Discovery Hub -> Screen 4
        setTargetCluster(null)
        setIsTokenExpired(false)
        setStep('signin')
      } else if (event.data?.type === 'operquay-fill-mfa') {
        const code = String(event.data.code || '').replace(/[\s-]/g, '')
        if (code) {
          setTeleportOTP(code)
          setTimeout(() => {
            otpRef.current?.focus()
          }, 30)
        }
      } else if (event.data?.type === 'operquay-refocus-mfa') {
        if (otpRef.current) {
          otpRef.current.focus()
        } else if (passwordRef.current) {
          passwordRef.current.focus()
        }
      }
    }
    window.addEventListener('message', onSelectClusterMessage)
    return () => window.removeEventListener('message', onSelectClusterMessage)
  }, [connections, configuredClusters, onDashboard, now])

  useEffect(() => {
    if (targetCluster) return
    if (configuredChoice === 'manual' || teleportBusy || step !== 'signin') return
    const cluster = configuredClusters.find(item => item.id === configuredChoice)
    if (!cluster) { setConfiguredChoice('manual'); setTeleportError('The configured cluster is no longer available.'); return }
    setTeleportProxy(cluster.proxy); setTeleportMethod(cluster.method); setTeleportAuth(cluster.connector || '')
    setTeleportPassword(''); setTeleportOTP('')
  }, [targetCluster, configuredClusters, configuredChoice, teleportBusy, step])

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30000)
    return () => clearInterval(timer)
  }, [])

  const cancelTeleport = () => {
    const login = teleportLogin.current
    login.generation++
    clearTimeout(login.timer)
    if (login.popup && !login.popup.closed) login.popup.close()
    if (login.id) {
      fetch('/api/teleport/cancel', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ callback_id: login.id }) }).catch(() => {})
    }
    login.id = null
    login.popup = null
  }

  useEffect(() => {
    discovery.current++
    setLoading(false)
    setTeleportBusy(false)
    setTeleportClusters(null)
    setTeleportError('')
    setTeleportPassword('')
    setTeleportOTP('')
    return () => { discovery.current++; cancelTeleport() }
  }, [mode])

  const teleportRequest = async (path, options) => {
    const response = await fetch(path, options)
    const data = await response.json()
    if (!response.ok || data.error) { const error = new Error(data.error || `Request failed (${response.status})`); error.status = response.status; throw error }
    return data
  }

  const startTeleport = async () => {
    cancelTeleport()
    setTeleportClusters(null)
    setTeleportError('')
    if (teleportMethod === 'local' && !window.isSecureContext) {
      setTeleportPassword('')
      setTeleportOTP('')
      setTeleportError('Password sign-in requires HTTPS, or a direct localhost connection.')
      return
    }
    const cleanOtp = teleportMethod === 'local' ? teleportOTP.trim().replace(/[\s-]/g, '') : ''
    if (teleportMethod === 'local') {
      if (!teleportUsername.trim()) {
        setTeleportError('Enter your Teleport username.')
        return
      }
      if (!teleportPassword) {
        setTeleportError('Enter your Teleport password.')
        passwordRef.current?.focus()
        return
      }
      if (!/^\d{6,10}$/.test(cleanOtp)) {
        setTeleportError('Enter the 6-to-10 digit authenticator code from your MFA app.')
        otpRef.current?.focus()
        return
      }
    }
    const popup = teleportMethod === 'sso' ? window.open('', 'TeleportSSO', 'width=800,height=600') : null
    if (teleportMethod === 'sso' && !popup) { setTeleportError('Popup blocked. Allow popups to sign in.'); return }
    const login = teleportLogin.current
    login.popup = popup
    const generation = login.generation
    setTeleportBusy(true)
    try {
      const local = teleportMethod === 'local'
      const result = await teleportRequest(local ? '/api/teleport/local-login' : '/api/teleport/request-credentials', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(local
          ? {
              proxy: teleportProxy.trim(),
              username: teleportUsername.trim(),
              password: teleportPassword,
              otp: cleanOtp,
              cluster_name: targetCluster?.cluster_name || targetCluster?.name || '',
            }
          : { proxy: teleportProxy.trim(), auth_type: teleportAuth.trim() || 'default' })
      })
      if (!result.callback_id || (popup && !result.auth_url)) throw new Error('Teleport did not return a login session.')
      if (login.generation !== generation || (popup && popup.closed)) {
        if (result.callback_id) fetch('/api/teleport/cancel', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ callback_id: result.callback_id }) }).catch(() => {})
        if (login.generation === generation) { setTeleportBusy(false); setTeleportError('Teleport sign-in cancelled.') }
        return
      }
      login.id = result.callback_id
      if (popup) popup.location.href = result.auth_url
      const poll = async () => {
        try {
          const status = await teleportRequest(`/api/teleport/status?callback_id=${encodeURIComponent(login.id)}`)
          if (login.generation !== generation) return
          if (status.status === 'connected') {
            if (popup && !popup.closed) popup.close()
            login.popup = null
            const data = await teleportRequest(`/api/k8s/teleport/clusters?callback_id=${encodeURIComponent(login.id)}`)
            if (login.generation !== generation) return
            if (!Array.isArray(data.clusters)) throw new Error('Teleport did not return a cluster list.')
            setTeleportClusters(data.clusters)
            setTeleportBusy(false)
            if (targetCluster) {
              const targetName = targetCluster.cluster_name || targetCluster.name || targetCluster.label
              const match = data.clusters.find(c => c === targetName || c.toLowerCase() === targetName.toLowerCase()) ||
                            data.clusters.find(c => targetCluster.label && c.includes(targetCluster.label)) ||
                            (data.clusters.length === 1 ? data.clusters[0] : null)
              if (match) {
                try {
                  const clusterId = await connectTeleport(match)
                  if (clusterId) {
                    setIsTokenExpired(false)
                    onDashboard(clusterId)
                    return
                  }
                } catch (connErr) {
                  setTeleportError(connErr.message)
                  setStep('clusters')
                  return
                }
              }
            }
            setStep('clusters')
          } else if (status.status === 'pending' && (!popup || !popup.closed)) {
            login.timer = setTimeout(poll, 1500)
          } else {
            throw new Error(status.error || (popup?.closed ? 'Teleport sign-in cancelled.' : 'Teleport sign-in failed.'))
          }
        } catch (error) {
          if (login.generation !== generation) return
          cancelTeleport()
          setTeleportBusy(false)
          setTeleportError(error.message)
        }
      }
      poll()
    } catch (error) {
      if (login.generation !== generation) return
      setTeleportPassword('')
      setTeleportOTP('')
      cancelTeleport()
      setTeleportBusy(false)
      setTeleportError(error.message)
    }
  }

  const connectTeleport = async (name) => {
    const login = teleportLogin.current
    if (!login.id) throw new Error('Teleport sign-in expired. Sign in again before connecting another cluster.')
    const generation = login.generation
    setTeleportBusy(true)
    setTeleportError('')
    try {
      const data = await teleportRequest('/api/k8s/teleport/connect', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ callback_id: login.id, cluster_name: name })
      })
      if (login.generation !== generation) return
      if (!data.cluster_id) throw new Error('The server did not return a cluster connection.')
      setTeleportBusy(false)
      onConnected(data.cluster_id, { name, source: 'teleport', proxy: teleportProxy.trim(), expires_at: data.expires_at })
      return data.cluster_id
    } catch (error) {
      if (login.generation !== generation) return
      setTeleportBusy(false)
      if (error.status === 404) login.id = null
      throw error
    }
  }

  // Load AWS accounts
  useEffect(() => {
    let active = true
    let generation = 0
    const load = async () => {
      const request = ++generation
      try {
        const config = await api.get('/api/auth/config').then(r => r.json()).catch(() => null)
        const scoped = config?.aws_access_mode === 'user'
        const data = await api.get(scoped ? '/api/aws/connected-roles' : '/aws-accounts').then(r => r.json())
        if (active && request === generation) {
          const next = scoped ? data.map(b => ({ id: b.id, name: `${b.label} · ${b.account_id}` })) : data
          setUserAWS(scoped); setAccounts(next); setDiscoveryError('')
          setSelectedAccount(current => next.some(account => account.id === current) ? current : '')
        }
      } catch {
        if (active && request === generation) { setAccounts([]); setSelectedAccount(''); setDiscoveryError('Could not load AWS connections.') }
      }
    }
    const refresh = () => { void load() }
    const onMessage = event => { if (event.origin === window.location.origin && event.source === window.parent && event.data?.type === 'operquay-refresh-aws-roles') refresh() }
    window.addEventListener('message', onMessage)
    refresh()
    return () => { active = false; window.removeEventListener('message', onMessage) }
  }, [])

  const findAWSClusters = async () => {
    if (!selectedAccount || (!userAWS && !selectedRegion)) return
    const generation = ++discovery.current
    setLoading(true)
    setDiscoveryError('')
    try {
      const data = await api.get('/api/k8s/clusters', userAWS ? { accountId: selectedAccount } : { accountId: selectedAccount, region: selectedRegion }).then(r => r.json())
      if (generation !== discovery.current) return
      if (data !== null && !Array.isArray(data)) throw new Error('The server did not return a cluster list.')
      setClusters(data || []); setStep('clusters')
    } catch (err) { if (generation === discovery.current) { setClusters([]); setDiscoveryError(err.message) } }
    finally { if (generation === discovery.current) setLoading(false) }
  }

  const handleKubeconfigUpload = (e) => {
    const file = e.target.files[0]
    if (!file) return
    const generation = ++discovery.current
    setLoading(true); setDiscoveryError('')

    const formData = new FormData()
    formData.append('kubeconfig', file)

    fetch('/api/k8s/kubeconfig/upload', {
      method: 'POST',
      body: formData
    })
      .then(async r => { if (!r.ok) throw new Error(await r.text()); return r.json() })
      .then(data => {
        if (generation !== discovery.current) return
        if (data.error) throw new Error(data.error)
        if (data.clusters !== null && !Array.isArray(data.clusters)) throw new Error('The server did not return a cluster list.')
        setKubeconfigClusters(data.clusters || [])
        if (data.clusters?.length > 0) {
          setSelectedKubecluster(data.clusters[0])
        }
        setStep('clusters')
      })
      .catch(err => { if (generation === discovery.current) setDiscoveryError('Failed to parse kubeconfig: ' + err.message) })
      .finally(() => { if (generation === discovery.current) setLoading(false) })
  }

  const handleAWSClusterConnect = (cluster) => {
    const region = cluster.region || selectedRegion
    if (!region) throw new Error('This cluster has no region from the scan.')
    return onConnect(selectedAccount, region, cluster)
  }

  const handleKubeconfigConnect = (selectedCluster = selectedKubecluster) => {
    if (!selectedCluster) {
      notify('Please select a cluster')
      return
    }

    // Get exec info from the selected cluster
    const cluster = kubeconfigClusters.find(c => c.name === selectedCluster.name)
    if (!cluster) {
      notify('No cluster info available')
      return
    }

    // If this cluster uses tsh, backend will try to execute it automatically
    // Create a fake cluster object
    const clusterObj = {
      name: cluster.name,
      source: 'kubeconfig',
      endpoint: cluster.server
    }
    
    // Connect via kubeconfig API - backend will execute tsh if needed
    return fetch('/api/k8s/kubeconfig/connect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        server: cluster.server,
        ca_data: cluster.certificateAuthority,
        cluster_name: cluster.name,
        exec_cmd: cluster.exec_cmd || '',
        exec_args: cluster.exec_args || [],
        is_teleport: cluster.is_teleport || false
      })
    })
      .then(r => r.json())
      .then(data => {
        if (data.auth_required === 'teleport') {
          return fetch('/api/teleport/request-credentials', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ proxy: data.proxy, auth_type: data.auth_type })
          })
            .then(res => res.json())
            .then(creds => {
              if (creds.error) {
                notify('Teleport Login Failed: ' + creds.error)
                return
              }
              const authWindow = window.open(creds.auth_url, 'TeleportSSO', 'width=800,height=600')
              if (!authWindow) {
                notify('Popup blocked. Please allow popups for the Teleport login window.')
                return
              }
              const pollId = setInterval(() => {
                fetch(`/api/teleport/status?callback_id=${creds.callback_id}`)
                  .then(r => r.json())
                  .then(st => {
                    if (st.status === 'connected') {
                      clearInterval(pollId)
                      if (!authWindow.closed) authWindow.close()
                      // Second pass with credentials
                      fetch('/api/k8s/kubeconfig/connect', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                          server: cluster.server,
                          ca_data: cluster.certificateAuthority,
                          cluster_name: cluster.name,
                          exec_cmd: cluster.exec_cmd || '',
                          exec_args: cluster.exec_args || [],
                          is_teleport: true,
                          teleport_session_id: creds.callback_id
                        })
                      })
                      .then(r2 => r2.json())
                      .then(final => {
                        if (final.error) {
                          notify(final.error)
                          return
                        }
                        onConnected(final.cluster_id, clusterObj)
                      })
                    } else if (st.status === 'failed') {
                      clearInterval(pollId)
                      notify('Teleport SSO failed: ' + st.error)
                    } else if (authWindow.closed && st.status === 'pending') {
                      clearInterval(pollId)
                      notify('Teleport login cancelled (window closed).')
                    }
                  })
              }, 2000)
            })
        }

        if (data.error) {
          let message = data.error
          if (cluster.is_teleport) {
            message += '\n\nTo connect to Teleport clusters, you need to run:\n' +
              'tsh login --proxy=<your-teleport-proxy>\n\n' +
              'This saves your Teleport session in ~/.tsh which is mounted to the container.'
          }
          notify(message)
          return
        }
        return onConnected(data.cluster_id, clusterObj)
      })
      .catch(err => { throw new Error('Connect failed: ' + err.message) })
  }

  const configuredCluster = configuredClusters.find(item => item.id === configuredChoice)
  const configuredFor = (name, proxy) => configuredClusters.find(item => item.cluster_name === name && proxyKey(item.proxy) && proxyKey(item.proxy) === proxyKey(proxy))
  const discovered = mode === 'teleport' ? (teleportClusters || []).filter(name => !configuredCluster || name === configuredCluster.cluster_name).map(name => ({ name })) : mode === 'aws' ? clusters : kubeconfigClusters
  const connect = async cluster => {
    setConnecting(cluster.name); setConnectionError('')
    try {
      const id = await (mode === 'teleport' ? connectTeleport(cluster.name) : mode === 'aws' ? handleAWSClusterConnect(cluster) : handleKubeconfigConnect(cluster))
      if (!id) throw new Error('Connection did not complete. Check the cluster sign-in screen.')
      return id
    } catch (err) { setConnectionError(err.message); throw err }
    finally { setConnecting('') }
  }
  const connected = cluster => connections.find(({ info }) => info.source === mode && info.name === cluster.name &&
    (mode === 'aws' ? info.accountId === selectedAccount && info.region === (cluster.region || selectedRegion) :
      mode === 'kubeconfig' ? info.endpoint === cluster.server : info.proxy === teleportProxy.trim()))
  const expired = connection => !!connection?.info.expires_at && Number.isFinite(Date.parse(connection.info.expires_at)) && Date.parse(connection.info.expires_at) <= now
  const visibleIds = new Set(discovered.map(c => connected(c)?.id).filter(Boolean))
  const rows = [
    ...discovered.map(cluster => ({ cluster, connection: connected(cluster), source: mode, discovered: true })),
    ...connections.filter(c => !visibleIds.has(c.id)).map(connection => ({ cluster: { name: connection.info.name }, connection, source: connection.info.source, discovered: false })),
  ]
  const groups = new Map()
  for (const row of rows) {
    const hosting = clusterHosting(row.connection?.info || { source: row.source, name: row.cluster.name })
    const group = groups.get(hosting.cloud) || []
    group.push({ ...row, hosting })
    groups.set(hosting.cloud, group)
  }
  useEffect(() => {
    onCatalog({
      items: discovered.map(cluster => ({ name: cluster.name, source: mode, hosting: clusterHosting(connected(cluster)?.info || { source: mode, name: cluster.name }), id: connected(cluster)?.id || null, expired: expired(connected(cluster)) })),
      connect: name => { const cluster = discovered.find(c => c.name === name); if (!cluster) return Promise.reject(new Error('Cluster is no longer available.')); return connect(cluster) },
      reauthenticate: () => { if (mode === 'teleport') { cancelTeleport(); setTeleportClusters(null) } setStep('signin') },
    })
  }, [mode, clusters, kubeconfigClusters, teleportClusters, connections, selectedAccount, selectedRegion, teleportProxy, teleportBusy, connecting, now, onCatalog])
  const sourceLabel = info => info.source === 'aws' ? `AWS${info.region ? ` · ${info.region}` : ''}` : info.source === 'kubeconfig' ? 'Kubeconfig' : 'Teleport'
  const home = connections.length > 0
  // SCREEN 2: Session Inactive / Token Expired Modal Overlay
  if (targetCluster && isTokenExpired && step === 'signin') {
    const clusterDisplayName = targetCluster.label || targetCluster.cluster_name || targetCluster.name || 'Cluster'
    const clusterProxy = targetCluster.proxy || teleportProxy
    return (
      <main className="connect-screen session-expired-stage">
        {/* Dimmed Background Overview Mock */}
        <div className="session-expired-backdrop" aria-hidden="true">
          <div className="expired-bg-metrics">
            <div className="expired-bg-card"><span>Nodes Ready</span><strong>— / —</strong></div>
            <div className="expired-bg-card"><span>Running Pods</span><strong>— / —</strong></div>
            <div className="expired-bg-card"><span>Deployments</span><strong>— / —</strong></div>
            <div className="expired-bg-card"><span>Warnings</span><strong>0</strong></div>
          </div>
          <div className="expired-bg-placeholder">Session certificate expired · Live workloads suspended</div>
        </div>

        {/* Centered Modal Dialog */}
        <div className="session-expired-dialog-wrap" role="dialog" aria-modal="true" aria-labelledby="expired-dialog-title">
          <div className="session-expired-dialog">
            <div className="session-dialog-header">
              <div className="session-status-badge">
                <span className="pulse-amber" />
                <span id="expired-dialog-title">Session Inactive</span>
              </div>
              <span className="session-cluster-pill">{clusterDisplayName}</span>
            </div>
            <p className="session-dialog-desc">
              Your session certificate for <strong>{clusterDisplayName}</strong> has expired. Re-authenticate to renew live workloads.
            </p>

            <form onSubmit={e => { e.preventDefault(); startTeleport() }} className="connect-fields">
              {teleportMethod === 'local' ? (
                <>
                  <label htmlFor="expired-username">Username
                    <input
                      id="expired-username"
                      aria-label="Teleport username"
                      autoComplete="username"
                      value={teleportUsername}
                      onChange={e => setTeleportUsername(e.target.value)}
                      readOnly={teleportBusy}
                      onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); passwordRef.current?.focus() } }}
                    />
                  </label>
                  <label htmlFor="expired-password">Password
                    <input
                      ref={passwordRef}
                      id="expired-password"
                      aria-label="Teleport password"
                      type="password"
                      autoComplete="current-password"
                      placeholder="••••••••••••••••"
                      value={teleportPassword}
                      onChange={e => setTeleportPassword(e.target.value)}
                      readOnly={teleportBusy}
                      onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); otpRef.current?.focus() } }}
                    />
                  </label>
                  <label htmlFor="expired-otp">
                    <div className="otp-label-row">
                      <span>Authenticator code</span>
                      <small className="otp-hint">Auto-formatted</small>
                    </div>
                    <input
                      ref={otpRef}
                      id="expired-otp"
                      aria-label="Authenticator code"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      maxLength={10}
                      placeholder="123456"
                      value={teleportOTP}
                      onChange={e => setTeleportOTP(e.target.value.replace(/[\s-]/g, ''))}
                      onPaste={e => {
                        const text = e.clipboardData?.getData('text')?.trim().replace(/[\s-]/g, '') || ''
                        if (/^\d{6,10}$/.test(text)) {
                          e.preventDefault()
                          setTeleportOTP(text.slice(0, 10))
                        }
                      }}
                      readOnly={teleportBusy}
                      onClick={e => e.currentTarget.focus()}
                    />
                  </label>
                </>
              ) : (
                <label htmlFor="expired-auth">SSO connector
                  <input
                    id="expired-auth"
                    aria-label="SSO connector"
                    placeholder="Optional"
                    value={teleportAuth}
                    onChange={e => setTeleportAuth(e.target.value)}
                    readOnly={teleportBusy}
                  />
                </label>
              )}

              {teleportError && <p className="teleport-error" role="alert">{teleportError}</p>}

              <div className="session-modal-actions">
                <button
                  type="button"
                  className="connect-secondary"
                  onClick={() => {
                    setIsTokenExpired(false)
                    setTargetCluster(null)
                  }}
                  disabled={teleportBusy}
                >
                  Cancel
                </button>
                <button
                  className="connect-primary"
                  type="submit"
                  aria-busy={teleportBusy}
                  disabled={!clusterProxy.trim() || teleportBusy || (teleportMethod === 'local' && (!teleportUsername.trim() || !teleportPassword || !/^\d{6,10}$/.test(teleportOTP.trim().replace(/[\s-]/g, ''))))}
                >
                  {teleportBusy ? <><span className="connect-spinner" aria-hidden="true" /> Unlocking…</> : 'Unlock Session'}
                </button>
              </div>
            </form>
          </div>
        </div>
      </main>
    )
  }

  // SCREEN 1: Dedicated In-Place Card for Selected Cluster
  if (targetCluster && !isTokenExpired && step === 'signin') {
    const clusterDisplayName = targetCluster.label || targetCluster.cluster_name || targetCluster.name || 'Cluster'
    const clusterProxy = targetCluster.proxy || teleportProxy
    return (
      <main className="connect-screen">
        <div className="connect-content connect-login">
          <section className="connect-card targeted-cluster-card">
            <div className="targeted-header">
              <div className="targeted-symbol">⎈</div>
              <div className="targeted-title-block">
                <h1>Sign in to <span className="cluster-name-highlight">{clusterDisplayName}</span></h1>
                <p className="targeted-subtitle" title={clusterProxy}>
                  {clusterProxy}
                </p>
              </div>
            </div>

            <div className="targeted-verified-badge">
              <span className="verified-host-info">
                <span className="verified-dot" />
                Teleport Proxy Gateway
              </span>
              <span className="verified-label">Verified Host</span>
            </div>

            <form className="connect-fields" onSubmit={e => { e.preventDefault(); startTeleport() }}>
              {teleportMethod === 'local' ? (
                <>
                  <label htmlFor="teleport-username">Username
                    <input
                      id="teleport-username"
                      aria-label="Teleport username"
                      autoComplete="username"
                      value={teleportUsername}
                      onChange={e => setTeleportUsername(e.target.value)}
                      readOnly={teleportBusy}
                      onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); passwordRef.current?.focus() } }}
                    />
                  </label>
                  <label htmlFor="teleport-password">Password
                    <input
                      ref={passwordRef}
                      id="teleport-password"
                      aria-label="Teleport password"
                      type="password"
                      autoComplete="current-password"
                      value={teleportPassword}
                      onChange={e => setTeleportPassword(e.target.value)}
                      readOnly={teleportBusy}
                      onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); otpRef.current?.focus() } }}
                    />
                  </label>
                  <label htmlFor="teleport-otp">
                    <div className="otp-label-row">
                      <span>Authenticator code</span>
                      <small className="otp-hint">Auto-formatted</small>
                    </div>
                    <input
                      ref={otpRef}
                      id="teleport-otp"
                      aria-label="Authenticator code"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      maxLength={10}
                      value={teleportOTP}
                      onChange={e => setTeleportOTP(e.target.value.replace(/[\s-]/g, ''))}
                      onPaste={e => {
                        const text = e.clipboardData?.getData('text')?.trim().replace(/[\s-]/g, '') || ''
                        if (/^\d{6,10}$/.test(text)) {
                          e.preventDefault()
                          setTeleportOTP(text.slice(0, 10))
                        }
                      }}
                      readOnly={teleportBusy}
                      onClick={e => e.currentTarget.focus()}
                    />
                  </label>
                </>
              ) : (
                <label htmlFor="teleport-auth">SSO connector
                  <input
                    id="teleport-auth"
                    aria-label="SSO connector"
                    placeholder="Optional"
                    value={teleportAuth}
                    onChange={e => setTeleportAuth(e.target.value)}
                    readOnly={teleportBusy}
                  />
                </label>
              )}

              <button
                className="connect-primary"
                type="submit"
                aria-busy={teleportBusy}
                disabled={!clusterProxy.trim() || teleportBusy || (teleportMethod === 'local' && (!teleportUsername.trim() || !teleportPassword || !/^\d{6,10}$/.test(teleportOTP.trim().replace(/[\s-]/g, ''))))}
              >
                {teleportBusy ? <><span className="connect-spinner" aria-hidden="true" /> Connecting to {clusterDisplayName}…</> : `Connect to ${clusterDisplayName}`}
              </button>
              {teleportBusy && (
                <button
                  type="button"
                  className="connect-secondary"
                  onClick={() => {
                    cancelTeleport()
                    setTeleportPassword('')
                    setTeleportOTP('')
                    setTeleportBusy(false)
                    setTeleportError('Teleport sign-in cancelled.')
                  }}
                >
                  Cancel
                </button>
              )}
              {teleportError && <p className="teleport-error" role="alert">{teleportError}</p>}
            </form>

            <div className="targeted-footer-escape">
              <span>Need to onboard a different cluster?</span>{' '}
              <button
                type="button"
                onClick={() => {
                  setTargetCluster(null)
                  setTeleportClusters(null)
                }}
                className="discovery-link-btn"
              >
                Open Discovery Catalog →
              </button>
            </div>
          </section>
        </div>
      </main>
    )
  }

  // SCREEN 4: Cluster Discovery Hub & Multi-Provider Onboarding
  return (
    <main className={`connect-screen ${home ? 'connect-home' : ''}`}>
      <div className={`connect-content ${!home && step === 'signin' ? 'connect-login' : ''}`}>
        {home && <header className="k8s-home-header">
          <div><h1>Kubernetes</h1><p>{connections.length} connected {connections.length === 1 ? 'cluster' : 'clusters'} · open one to browse workloads, logs and shells</p></div>
        </header>}
        {home && <section aria-label="Connected clusters" className="k8s-cards">
          {connections.map(connection => {
            const hosting = clusterHosting(connection.info)
            const isExpired = expired(connection)
            return <article className="k8s-card" key={connection.id} aria-label={connection.info.name}>
              <div className="k8s-card-title"><CloudIcon cloud={hosting.cloud} /><strong title={connection.info.name}>{connection.info.name}</strong><span className={isExpired ? 'status-disconnected' : 'status-connected'}><span aria-hidden="true">● </span>{isExpired ? 'Expired' : 'Connected'}</span></div>
              <p className="status-note">{hosting.detail} · {sourceLabel(connection.info)}</p>
              {connection.info.expires_at && <p className="status-note">Certificate expires {new Date(connection.info.expires_at).toLocaleString()}</p>}
              <div className="k8s-card-actions">
                {isExpired ? (
                  <button
                    className="connect-primary"
                    onClick={() => {
                      setTargetCluster({
                        label: connection.info.name,
                        cluster_name: connection.info.name,
                        proxy: connection.info.proxy || teleportProxy,
                        method: 'local'
                      })
                      setIsTokenExpired(true)
                      setStep('signin')
                    }}
                  >
                    Renew Session
                  </button>
                ) : (
                  <button className="connect-primary" onClick={() => onDashboard(connection.id)}>Open</button>
                )}
                <button className="connect-secondary" onClick={() => onDisconnect(connection.id)}>Disconnect</button>
              </div>
            </article>
          })}
        </section>}
        {home && <h2 className="k8s-section-title">Connect another cluster</h2>}
        <section className="connect-card discovery-hub-card">
          {!(home && step === 'signin') && (
            <div className="discovery-heading">
              <div className="discovery-heading-left">
                <span className="connect-symbol">⎈</span>
                <div>
                  <h1>{step === 'signin' ? 'Cluster Discovery & Onboarding' : 'Select a cluster'}</h1>
                  <p>{step === 'signin' ? 'Scan connected cloud providers, import kubeconfig, or discover Teleport clusters.' : 'Connect to a cluster, then open its dashboard.'}</p>
                </div>
              </div>
              {step === 'signin' && <span className="discovery-catalog-badge">Admin Catalog</span>}
            </div>
          )}
          {step === 'signin' && <>
          <div className="connection-mode-tabs" aria-label="Connection method">
            {[
              ['teleport', 'Teleport Discovery'],
              ['aws', 'AWS IAM Roles'],
              ['kubeconfig', 'Kubeconfig File']
            ].map(([id, label]) => (
              <button
                key={id}
                className={`mode-tab ${mode === id ? 'active' : ''}`}
                onClick={() => setMode(id)}
              >
                {label}
              </button>
            ))}
          </div>
          {mode === 'aws' && <form className="connect-fields" onSubmit={e => { e.preventDefault(); findAWSClusters() }}>
            <label>{userAWS ? 'Connected AWS account and role' : 'AWS account'}<select aria-label="AWS account" value={selectedAccount} onChange={e => setSelectedAccount(e.target.value)} disabled={loading}><option value="">{accounts.length ? 'Select account' : userAWS ? 'No AWS roles connected' : 'No AWS accounts configured'}</option>{accounts.map(a => <option key={a.id} value={a.id}>{a.name || a.id}</option>)}</select></label>
            {userAWS && <p className="status-note">Connect this role in the Instances workspace. Clusters are found in every region.</p>}
            {!userAWS && <label>Region<select aria-label="Region" value={selectedRegion} onChange={e => setSelectedRegion(e.target.value)} disabled={!selectedAccount || loading}><option value="">Select region</option>{REGIONS.map(r => <option key={r}>{r}</option>)}</select></label>}
            <button className="connect-primary" type="submit" aria-busy={loading} disabled={!selectedAccount || (!userAWS && !selectedRegion) || loading}>{loading ? <><span className="connect-spinner" aria-hidden="true" /> Finding clusters…</> : 'Find clusters'}</button>
            {discoveryError && <p className="teleport-error" role="alert">Could not discover clusters: {discoveryError}</p>}
          </form>}
          {mode === 'kubeconfig' && <div className="connect-fields"><label>Kubeconfig file<input type="file" onChange={handleKubeconfigUpload} accept=".yaml,.yml" disabled={loading} /></label>{loading && <p>Reading kubeconfig…</p>}{discoveryError && <p className="teleport-error" role="alert">{discoveryError}</p>}</div>}
          {mode === 'teleport' && <form className="connect-fields" onSubmit={e => { e.preventDefault(); startTeleport() }}>
            <div className="cluster-picker"><span>Cluster</span><details ref={clusterPicker} onKeyDown={e => { if (e.key === 'Escape' && clusterPicker.current?.open) { e.preventDefault(); clusterPicker.current.open = false; clusterPicker.current.querySelector('summary')?.focus() } }}><summary aria-label="Configured cluster" aria-disabled={teleportBusy} onClick={e => { if (teleportBusy) e.preventDefault() }}><span>{configuredCluster?.label || 'Enter your own proxy'}{configuredCluster && <small>{configuredCluster.proxy}</small>}</span><span aria-hidden="true">⌄</span></summary><div className="cluster-picker-options" role="group" aria-label="Cluster options"><button type="button" disabled={teleportBusy} aria-pressed={configuredChoice === 'manual'} onClick={() => chooseConfiguredCluster('manual')}>Enter your own proxy</button>{configuredClusters.map(c => <button type="button" key={c.id} disabled={teleportBusy} aria-pressed={configuredChoice === c.id} onClick={() => chooseConfiguredCluster(c.id)}><span>{c.label}</span><small>{c.proxy}</small></button>)}</div></details></div>
            {configuredError && <p className="status-note" role="status">{configuredError}</p>}
            {!configuredCluster && <label>Teleport proxy<input aria-label="Teleport proxy" placeholder="proxy.example.com" value={teleportProxy} onChange={e => { setTeleportProxy(e.target.value); setTeleportClusters(null) }} disabled={teleportBusy} /></label>}
            <label>Sign-in method<select aria-label="Teleport sign-in method" value={teleportMethod} onChange={e => { setTeleportMethod(e.target.value); setTeleportPassword(''); setTeleportOTP(''); setTeleportError('') }} disabled={teleportBusy}><option value="local">Password + code</option><option value="sso">SSO</option></select></label>
            {teleportMethod === 'local' ? <>
              <label htmlFor="teleport-username">Username<input id="teleport-username" aria-label="Teleport username" autoComplete="username" value={teleportUsername} onChange={e => setTeleportUsername(e.target.value)} readOnly={teleportBusy} onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); passwordRef.current?.focus() } }} /></label>
              <label htmlFor="teleport-password">Password<input ref={passwordRef} id="teleport-password" aria-label="Teleport password" type="password" autoComplete="current-password" value={teleportPassword} onChange={e => setTeleportPassword(e.target.value)} readOnly={teleportBusy} onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); otpRef.current?.focus() } }} /></label>
              <label htmlFor="teleport-otp">Authenticator code<input ref={otpRef} id="teleport-otp" aria-label="Authenticator code" inputMode="numeric" autoComplete="one-time-code" maxLength={10} value={teleportOTP} onChange={e => setTeleportOTP(e.target.value.replace(/[\s-]/g, ''))} onPaste={e => { const text = e.clipboardData?.getData('text')?.trim().replace(/[\s-]/g, '') || ''; if (/^\d{6,10}$/.test(text)) { e.preventDefault(); setTeleportOTP(text.slice(0, 10)) } }} readOnly={teleportBusy} onClick={e => e.currentTarget.focus()} /></label>
            </> : <label htmlFor="teleport-auth">SSO connector<input id="teleport-auth" aria-label="SSO connector" placeholder="Optional" value={teleportAuth} onChange={e => setTeleportAuth(e.target.value)} readOnly={teleportBusy} /></label>}
            <button className="connect-primary" type="submit" aria-busy={teleportBusy} disabled={!teleportProxy.trim() || teleportBusy || (teleportMethod === 'local' && (!teleportUsername.trim() || !teleportPassword || !/^\d{6,10}$/.test(teleportOTP.trim().replace(/[\s-]/g, ''))))}>{teleportBusy ? <><span className="connect-spinner" aria-hidden="true" /> Signing in…</> : 'Sign in'}</button>
            {teleportBusy && <button type="button" className="connect-secondary" onClick={() => { cancelTeleport(); setTeleportPassword(''); setTeleportOTP(''); setTeleportBusy(false); setTeleportError('Teleport sign-in cancelled.') }}>Cancel</button>}
            {teleportError && <p className="teleport-error" role="alert">{teleportError}</p>}
          </form>}
          {connections.length > 0 && <div className="connected-summary"><button onClick={() => setStep('clusters')}>Back to clusters</button></div>}
          </>}
          {step === 'clusters' && <section className="cluster-results">
            <div className="cluster-context"><span>{mode === 'teleport' ? <>{configuredCluster?.label || 'Teleport'}<span className="proxy-detail">{teleportProxy}</span></> : mode === 'aws' ? (userAWS ? 'AWS · all regions' : `AWS · ${selectedRegion}`) : 'Kubeconfig'}</span><button onClick={() => { if (mode === 'teleport' && teleportLogin.current.id) cancelTeleport(); setStep('signin') }}>Change connection</button></div>
            <div className="cluster-results-title"><h2>Clusters</h2><span>{discovered.length} available</span></div>
            {mode === 'teleport' && configuredCluster && teleportClusters && !teleportClusters.includes(configuredCluster.cluster_name) && <p className="teleport-error" role="alert">The configured cluster was not found or is not permitted for this sign-in.</p>}
            {rows.length ? [...groups].map(([cloud, entries]) => <div className="cluster-cloud" role="group" aria-label={`${cloudNames[cloud]} clusters`} key={cloud}>
              <details open><summary className="cluster-cloud-heading"><CloudIcon cloud={cloud} /><strong>{cloudNames[cloud]}</strong><span>{entries.length}</span></summary>
              <table><thead><tr><th>Cluster</th><th>Status</th><th>Actions</th></tr></thead><tbody>{entries.map(({ cluster, connection, source, discovered, hosting }) => <tr key={connection?.id || `${source}/${cluster.name}`}>
                <td>{source === 'teleport' ? configuredFor(cluster.name, connection?.info.proxy || teleportProxy)?.label || cluster.name : cluster.name}{source === 'teleport' && <div className="proxy-detail">{connection?.info.proxy || teleportProxy}</div>}<div className="status-note">{hosting.detail} · {source === 'aws' ? `AWS${(cluster.region || connection?.info.region) ? ` · ${cluster.region || connection.info.region}` : ''}` : source === 'kubeconfig' ? 'Kubeconfig' : 'Teleport'}</div>{connection?.info.expires_at && <div className="status-note">Certificate expires {new Date(connection.info.expires_at).toLocaleString()}</div>}</td><td><span className={connection && !expired(connection) ? 'status-connected' : 'status-disconnected'}><span aria-hidden="true">● </span><span>{!connection ? 'Disconnected' : expired(connection) ? 'Expired' : 'Connected'}</span></span></td>
                <td className="cluster-actions">{connection ? <><button disabled={expired(connection)} title={expired(connection) ? 'Disconnect and sign in again to renew the certificate' : undefined} onClick={() => onDashboard(connection.id)}>Dashboard</button><button onClick={() => onDisconnect(connection.id)}>Disconnect</button></> : discovered && <button onClick={() => connect(cluster).catch(() => {})} aria-busy={connecting === cluster.name} disabled={!!connecting || teleportBusy || (mode === 'teleport' && !teleportLogin.current.id)}>{connecting === cluster.name ? <><span className="connect-spinner" aria-hidden="true" /> Connecting…</> : 'Connect'}</button>}</td>
              </tr>)}</tbody></table></details>
            </div>) : <p>No permitted clusters found.</p>}
            <p className="status-note">Connection status reflects this Operquay session, not live cluster health.</p>
            {teleportBusy && <p className="status-note">Connecting…</p>}
            {mode === 'teleport' && teleportError && <p className="teleport-error" role="alert">{teleportError}</p>}
            {connectionError && <p className="teleport-error" role="alert">{connectionError}</p>}
            {mode === 'teleport' && !teleportLogin.current.id && discovered.some(c => !connected(c)) && <p className="status-note">Sign in again to connect another Teleport cluster.</p>}
            {mode === 'teleport' && teleportLogin.current.id && <p className="status-note">This Teleport sign-in can connect other clusters for up to 10 minutes.</p>}
          </section>}
        </section>
      </div>
    </main>
  )
}
