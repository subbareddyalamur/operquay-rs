import React, { useDeferredValue, useEffect, useMemo, useRef, useState } from 'react'
import DetailPanel from './DetailPanel.jsx'
import BottomPanel from './BottomPanel.jsx'
import CostPanel from './CostPanel.jsx'
import ResizableHeader from './ResizableHeader.jsx'
import NamespaceSelector from './NamespaceSelector.jsx'
import { parseDocument, stringify } from 'yaml'
import { useApi } from './useApi.js'
import { editableResource } from './resourceView.js'
import { cloudNames, clusterHosting } from './cloudProvider.js'
import CloudIcon from './CloudIcon.jsx'
import { WorkspaceTabBar, WorkspaceTab } from '@/components/primitives/WorkspaceTabs'
import { hasPermission } from '@/stores/auth'
import {
  LayoutDashboard,
  AppWindow,
  GitBranch,
  Server,
  Box,
  Settings,
  Network,
  Database,
  Cpu,
  FolderTree,
  Activity,
  Package,
  ShieldCheck,
  Code2,
  CircleDollarSign,
  ChevronDown,
  ChevronRight,
  PanelLeft,
  PanelLeftClose,
} from 'lucide-react'

const titles = { __overview: 'Overview', __applications: 'Applications', __helm: 'Helm Releases', __cost: 'Cost Monitoring', pods: 'Pods', deployments: 'Deployments', daemonsets: 'Daemon Sets', statefulsets: 'Stateful Sets', replicasets: 'Replica Sets', replicationcontrollers: 'Replication Controllers', jobs: 'Jobs', cronjobs: 'Cron Jobs', configmaps: 'Config Maps', secrets: 'Secrets', services: 'Services', ingresses: 'Ingresses', networkpolicies: 'Network Policies', persistentvolumeclaims: 'Persistent Volume Claims', persistentvolumes: 'Persistent Volumes', storageclasses: 'Storage Classes', serviceaccounts: 'Service Accounts', roles: 'Roles', rolebindings: 'Role Bindings', clusterroles: 'Cluster Roles', clusterrolebindings: 'Cluster Role Bindings', namespaces: 'Namespaces', nodes: 'Nodes', events: 'Events' }
Object.assign(titles, { resourcequotas: 'Resource Quotas', limitranges: 'Limit Ranges', horizontalpodautoscalers: 'Horizontal Pod Autoscalers', poddisruptionbudgets: 'Pod Disruption Budgets', priorityclasses: 'Priority Classes', runtimeclasses: 'Runtime Classes', leases: 'Leases', mutatingwebhookconfigurations: 'Mutating Webhook Configurations', validatingwebhookconfigurations: 'Validating Webhook Configurations', validatingadmissionpolicies: 'Validating Admission Policies', validatingadmissionpolicybindings: 'Validating Admission Policy Bindings', endpointslices: 'Endpoint Slices', endpoints: 'Endpoints', ingressclasses: 'Ingress Classes', deviceclasses: 'Device Classes', resourceclaims: 'Resource Claims', resourceclaimtemplates: 'Resource Claim Templates', resourceslices: 'Resource Slices', customresourcedefinitions: 'Definitions' })
titles.__helmcharts = 'Helm Charts'
const categoryIcons = { Workloads: Box, Config: Settings, Network: Network, Storage: Database, 'Access Control': ShieldCheck }
const resource = (name, kind, group = '', namespaced = true) => ({ name, kind, group, version: 'v1', namespaced })
const extra = [resource('replicasets', 'ReplicaSet', 'apps'), resource('replicationcontrollers', 'ReplicationController')]
const overviewType = resource('__overview', 'Overview', '', false)
const applicationsType = resource('__applications', 'Applications')
const helmType = resource('__helm', 'Helm Releases')
const helmChartsType = resource('__helmcharts', 'Helm Charts')
const costType = resource('__cost', 'Cost Monitoring', '', false)
const crdDefinitions = resource('customresourcedefinitions', 'CustomResourceDefinition', 'apiextensions.k8s.io', false)
const argoApps = { name: 'applications', kind: 'Argo CD Applications', group: 'argoproj.io', version: 'v1alpha1', namespaced: true }
const typeKey = t => `${t.group}/${t.version}/${t.name}`
function resourceTitle(t) {
  if (titles[t.name]) return titles[t.name]
  const singular = (t.kind || '').replace(/([a-z0-9])([A-Z])/g, '$1 $2')
  const base = (t.kind || '').toLowerCase()
  if (t.name === base) return singular
  if (t.name === base + 's') return singular + 's'
  if (t.name === base + 'es') return singular + 'es'
  if (base.endsWith('y') && t.name === base.slice(0, -1) + 'ies') return singular.slice(0, -1) + 'ies'
  return t.name.replace(/(^|-)([a-z])/g, (_, separator, letter) => (separator ? ' ' : '') + letter.toUpperCase())
}
function keepDialogFocus(e) {
  if (e.key !== 'Tab') return
  const controls = [...e.currentTarget.querySelectorAll('button:not(:disabled), textarea:not(:disabled), input:not(:disabled)')]
  if (controls.length && e.shiftKey && document.activeElement === controls[0]) { e.preventDefault(); controls[controls.length - 1].focus() }
  else if (controls.length && !e.shiftKey && document.activeElement === controls[controls.length - 1]) { e.preventDefault(); controls[0].focus() }
}

async function clusterFingerprint(info) {
  const fields = [info?.source, info?.name, info?.accountId || '', info?.region || '', info?.proxy || '', info?.endpoint || '']
  if (!fields[0] || !fields[1] || !globalThis.crypto?.subtle || (fields[0] === 'aws' && (!fields[2] || !fields[3])) || (fields[0] === 'teleport' && !fields[4]) || (fields[0] === 'kubeconfig' && !fields[5])) throw new Error('A secure connection and cluster identity are required for sharing.')
  if (fields[5]) { const endpoint = new URL(fields[5]); if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) throw new Error('Cannot share a cluster endpoint containing credentials or query parameters.') }
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(fields)))
  return [...new Uint8Array(digest)].map(n => n.toString(16).padStart(2, '0')).join('')
}

function age(timestamp) {
  if (!timestamp) return '—'
  const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(timestamp)) / 1000))
  if (!Number.isFinite(seconds)) return '—'
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`
  return `${Math.floor(seconds / 86400)}d`
}

function selected(item, type) {
  return { kind: type.kind, resource: type.name, group: type.group, version: type.version, name: item.metadata?.name, namespace: item.metadata?.namespace || '', uid: item.metadata?.uid, resourceVersion: item.metadata?.resourceVersion, containers: item.spec?.containers?.map(c => c.name) || [], shellContainers: [...(item.spec?.containers || []), ...(item.spec?.initContainers || [])].map(c => c.name) }
}

function ContainerStates({ item }) {
  const state = (status, init) => {
    const value = status?.state
    const label = value?.running ? 'Running' : value?.waiting ? 'Pending' : value?.terminated ? (value.terminated.reason === 'Completed' || (!value.terminated.reason && value.terminated.exitCode === 0) ? 'Succeeded' : 'Stopped') : 'Unknown'
    return { label: init ? `Init · ${label}` : label, tone: init ? 'init' : label === 'Running' ? 'running' : label === 'Pending' ? 'pending' : label === 'Unknown' ? 'unknown' : 'stopped' }
  }
  const containers = [
    ...(item.spec?.initContainers || item.status?.initContainerStatuses || []).map(c => ({ ...c, init: true })),
    ...(item.spec?.containers || item.status?.containerStatuses || []).map(c => ({ ...c, init: false })),
  ]
  return containers.length ? <div className="container-states">{containers.map(c => {
    const status = (c.init ? item.status?.initContainerStatuses : item.status?.containerStatuses)?.find(s => s.name === c.name)
    const { label, tone } = state(status, c.init)
    return <span key={`${c.init}/${c.name}`} className={`container-state ${tone}`} role="img" aria-label={`${c.name}: ${label}`} title={`${c.name}: ${label}`} tabIndex={0} />
  })}</div> : '—'
}

export default function Workspace({ clusterId, clusterInfo, connections, catalog, visible = true, onSwitch, onClusters, onSignIn }) {
  const api = useApi()
  const cacheRef = useRef(new Map())
  const searchInputRef = useRef(null)
  const [refreshing, setRefreshing] = useState(false)
  const [categories, setCategories] = useState([])
  const [me, setMe] = useState(null)
  const [authRequired, setAuthRequired] = useState(null)
  const [namespaces, setNamespaces] = useState([])
  const [selectedNamespaces, setSelectedNamespaces] = useState([])
  const [selectedEventNamespaces, setSelectedEventNamespaces] = useState([])
  const namespace = selectedNamespaces.join(',')
  const eventNamespace = selectedEventNamespaces.join(',')
  const setNamespace = val => {
    if (Array.isArray(val)) setSelectedNamespaces(val)
    else if (!val) setSelectedNamespaces([])
    else setSelectedNamespaces(val.split(',').map(s => s.trim()).filter(Boolean))
  }
  const setEventNamespace = val => {
    if (Array.isArray(val)) setSelectedEventNamespaces(val)
    else if (!val) setSelectedEventNamespaces([])
    else setSelectedEventNamespaces(val.split(',').map(s => s.trim()).filter(Boolean))
  }
  const [namespaceError, setNamespaceError] = useState('')
  const [navError, setNavError] = useState('')
  const [expanded, setExpanded] = useState({ Workloads: true })
  const [tabs, setTabs] = useState([resource('pods', 'Pod')])
  const [active, setActive] = useState('/v1/pods')
  const isEmbedded = typeof window !== 'undefined' && window.parent && window.parent !== window
  const [showInnerNav, setShowInnerNav] = useState(false)
  const [crds, setCrds] = useState(null)
  const [crdError, setCrdError] = useState('')
  const [crdLoading, setCrdLoading] = useState(false)
  const [deviceResources, setDeviceResources] = useState(null)
  const [deviceError, setDeviceError] = useState('')
  const [deviceLoading, setDeviceLoading] = useState(false)
  const [items, setItems] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [metrics, setMetrics] = useState({})
  const [metricsError, setMetricsError] = useState('')
  const [search, setSearch] = useState('')
  const [detail, setDetail] = useState(null)
  const [menu, setMenu] = useState(null)
  const [pod, setPod] = useState(null)
  const [shells, setShells] = useState([])
  const [shellChoice, setShellChoice] = useState(null)
  const shellId = useRef(0)
  const shellChoiceReturn = useRef(null)
  const [logPods, setLogPods] = useState([])
  const [selectedPods, setSelectedPods] = useState([])
  const [logError, setLogError] = useState('')
  const [logLoading, setLogLoading] = useState(false)
  const logRequest = useRef(0)
  const [bottomTab, setBottomTab] = useState('logs')
  const [height, setHeight] = useState(250)
  const [refresh, setRefresh] = useState(0)
  const [action, setAction] = useState(null)
  const [actionText, setActionText] = useState('')
  const [actionError, setActionError] = useState('')
  const [actionBusy, setActionBusy] = useState(false)
  const [replicas, setReplicas] = useState('')
  const [overview, setOverview] = useState(null)
  const [applications, setApplications] = useState(null)
  const [helm, setHelm] = useState(null)
  const [helmError, setHelmError] = useState('')
  const [share, setShare] = useState(null)
  const [linkError, setLinkError] = useState('')
  const [switching, setSwitching] = useState(false)
  const [switchError, setSwitchError] = useState('')
  const [columnWidths, setColumnWidths] = useState({})
  const navigationSnapshot = useRef(null)
  const type = tabs.find(t => typeKey(t) === active) || tabs[0]
  const isPod = type?.name === 'pods' && type?.group === '' && type?.version === 'v1'
  const isEvent = type?.name === 'events' && type?.group === '' && type?.version === 'v1'
  const isScalable = type?.group === 'apps' && type?.version === 'v1' && ['deployments', 'statefulsets', 'replicasets'].includes(type?.name)
  const isRestartable = type?.group === 'apps' && type?.version === 'v1' && ['deployments', 'statefulsets', 'daemonsets'].includes(type?.name)
  const k8sScope = clusterId ? { type: 'k8s_cluster', id: clusterId } : undefined
  const legacyOperator = Boolean(me && !me.permissions && (!me.grants || me.grants.length === 0) && (me.role === 'admin' || me.role === 'user'))
  const noAuth = authRequired === false && !me?.role
  const canOperate = Boolean(me && (hasPermission(me, 'k8s:mutate', k8sScope) || hasPermission(me, 'k8s:scale', k8sScope) || hasPermission(me, 'k8s:restart', k8sScope) || legacyOperator))
  const canExec = Boolean((me && (hasPermission(me, 'k8s:exec', k8sScope) || legacyOperator)) || noAuth)
  const canReadLogs = Boolean((me && (hasPermission(me, 'k8s:logs', k8sScope) || legacyOperator)) || noAuth)
  const canRevealSecrets = Boolean((me && (hasPermission(me, 'k8s:secrets', k8sScope) || legacyOperator)) || noAuth)

  useEffect(() => {
    let cancelled = false
    api.get('/api/auth/me').then(r => r.json()).then(data => { if (!cancelled) setMe(data?.role ? data : null) }).catch(() => { if (!cancelled) setMe(null) })
    api.get('/api/auth/config').then(r => r.json()).then(data => { if (!cancelled) setAuthRequired(data.required) }).catch(() => { if (!cancelled) setAuthRequired(null) })
    api.get('/api/k8s/categories', { cluster: clusterId }).then(r => r.json()).then(data => { if (!cancelled) setCategories(data || []) }).catch(e => { if (!cancelled) setNavError(e.message) })
    api.get('/api/k8s/namespaces', { cluster: clusterId }).then(r => r.json()).then(data => { if (!cancelled) setNamespaces(data || []) }).catch(e => { if (!cancelled) setNamespaceError(e.message) })
    return () => { cancelled = true }
  }, [clusterId])

  useEffect(() => {
    const onNavigateMsg = (event) => {
      if (event.origin !== window.location.origin) return
      if (event.data?.type !== 'operquay-k8s-navigate') return
      const target = event.data.resource
      if (!target) return
      const targetKey = typeKey(target)
      setActive(targetKey)
      setTabs(current => current.some(x => typeKey(x) === targetKey) ? current : [...current, target])
      setDetail(null)
    }
    window.addEventListener('message', onNavigateMsg)
    return () => window.removeEventListener('message', onNavigateMsg)
  }, [])

  useEffect(() => {
    if (isEmbedded) {
      window.parent?.postMessage({
        type: 'operquay-k8s-active-changed',
        activeKey: active,
        clusterId,
      }, window.location.origin)
    }
  }, [active, clusterId, isEmbedded])

  useEffect(() => { logRequest.current++; setSelectedPods([]); setLogError(''); setLogLoading(false); return () => { logRequest.current++ } }, [clusterId, active, namespace])

  useEffect(() => {
    if (!menu) return
    const dismiss = e => { if (!(e.target instanceof Element) || !e.target.closest('.lens-row-actions')) setMenu(null) }
    const escape = e => { if (e.key === 'Escape') setMenu(null) }
    document.addEventListener('pointerdown', dismiss)
    document.addEventListener('keydown', escape)
    return () => { document.removeEventListener('pointerdown', dismiss); document.removeEventListener('keydown', escape) }
  }, [menu])

  useEffect(() => {
    let cancelled = false
    let generation = 0
    const applyLink = () => {
      const current = ++generation
      const params = new URLSearchParams(window.location.hash.slice(1))
      if (params.get('view') !== 'resource') { setLinkError(''); return }
      const group = params.get('group') || '', version = params.get('version') || '', name = params.get('name') || '', plural = params.get('resource') || '', ns = params.get('namespace') || '', kind = params.get('kind') || ''
      const valid = /^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/.test(name) && /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(plural) && /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(version) && (!group || /^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$/.test(group)) && (!ns || /^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(ns)) && kind.length > 0 && kind.length <= 128
      if (!valid) { setLinkError('The shared resource link is invalid.'); return }
      clusterFingerprint(clusterInfo).then(hash => {
        if (cancelled || current !== generation) return
        if (hash !== params.get('cluster')) { setLinkError('This resource link belongs to a different cluster. Connect to the original cluster to open it.'); return }
        const t = { name: plural, kind, group, version, namespaced: params.get('namespaced') === 'true' }
        setTabs(prev => prev.some(x => typeKey(x) === typeKey(t)) ? prev : [...prev, t])
        setActive(typeKey(t)); setNamespace(ns); setDetail({ kind, resource: plural, group, version, name, namespace: ns, containers: [] }); setLinkError('')
      }).catch(err => { if (!cancelled && current === generation) setLinkError(err.message) })
    }
    applyLink()
    window.addEventListener('hashchange', applyLink)
    return () => { cancelled = true; window.removeEventListener('hashchange', applyLink) }
  }, [clusterId, clusterInfo])

  useEffect(() => {
    if (!type || ['__overview', '__applications', '__helm', '__helmcharts', '__cost'].includes(type.name)) return
    const controller = new AbortController()
    const targetNamespace = type.namespaced ? (isEvent ? eventNamespace : namespace) : ''
    const cacheKey = `res:${clusterId}:${typeKey(type)}:${targetNamespace || '*'}`
    const cached = cacheRef.current.get(cacheKey)
    setError(''); setMenu(null)
    if (cached) {
      setItems(cached)
      setLoading(false)
      setRefreshing(true)
    } else {
      setLoading(true)
      setItems([])
      setRefreshing(false)
    }
    api.get(`/api/k8s/resources/${type.name}`, { cluster: clusterId, group: type.group, version: type.version, namespace: targetNamespace }, { signal: controller.signal })
      .then(r => r.json())
      .then(data => {
        if (controller.signal.aborted) return
        const nextItems = data || []
        cacheRef.current.set(cacheKey, nextItems)
        setItems(nextItems)
      })
      .catch(e => {
        if (!controller.signal.aborted && e?.name !== 'AbortError') setError(e.message)
      })
      .finally(() => {
        if (!controller.signal.aborted) {
          setLoading(false)
          setRefreshing(false)
        }
      })
    return () => controller.abort()
  }, [clusterId, active, namespace, eventNamespace, refresh])

  useEffect(() => {
    if (type?.name !== '__applications') return
    const controller = new AbortController()
    const cacheKey = `apps:${clusterId}:${namespace || '*'}`
    const cached = cacheRef.current.get(cacheKey)
    if (cached) {
      setApplications(cached)
      setRefreshing(true)
    } else {
      setApplications(null)
      setRefreshing(false)
    }
    const kinds = [resource('deployments', 'Deployment', 'apps'), resource('statefulsets', 'StatefulSet', 'apps'), resource('daemonsets', 'DaemonSet', 'apps')]
    Promise.allSettled(kinds.map(t => api.get(`/api/k8s/resources/${t.name}`, { cluster: clusterId, group: t.group, version: t.version, namespace }, { signal: controller.signal }).then(r => r.json())))
      .then(results => {
        if (controller.signal.aborted) return
        const nextApps = results.map((result, i) => ({ result, type: kinds[i] }))
        cacheRef.current.set(cacheKey, nextApps)
        setApplications(nextApps)
        setRefreshing(false)
      })
    return () => controller.abort()
  }, [clusterId, active, namespace, refresh])

  useEffect(() => {
    if (type?.name !== '__helm' && type?.name !== '__helmcharts') return
    const controller = new AbortController()
    const cacheKey = `helm:${clusterId}:${namespace || '*'}`
    const cached = cacheRef.current.get(cacheKey)
    setHelmError('')
    if (cached) {
      setHelm(cached)
      setRefreshing(true)
    } else {
      setHelm(null)
      setRefreshing(false)
    }
    api.get('/api/k8s/helm/releases', { cluster: clusterId, namespace }, { signal: controller.signal }).then(r => r.json())
      .then(data => {
        if (controller.signal.aborted) return
        cacheRef.current.set(cacheKey, data)
        setHelm(data)
      })
      .catch(err => {
        if (!controller.signal.aborted && err?.name !== 'AbortError') setHelmError(err.message)
      })
      .finally(() => {
        if (!controller.signal.aborted) setRefreshing(false)
      })
    return () => controller.abort()
  }, [clusterId, active, namespace, refresh])

  useEffect(() => {
    if (type?.name !== '__overview') return
    const controller = new AbortController()
    const cacheKey = `overview:${clusterId}:${namespace || '*'}`
    const cached = cacheRef.current.get(cacheKey)
    if (cached) {
      setOverview(cached)
      setRefreshing(true)
    } else {
      setOverview(null)
      setRefreshing(false)
    }
    const resources = [resource('nodes', 'Node', '', false), resource('pods', 'Pod'), resource('deployments', 'Deployment', 'apps')]
    Promise.allSettled(resources.map(t => api.get(`/api/k8s/resources/${t.name}`, { cluster: clusterId, group: t.group, version: t.version, namespace: t.namespaced ? namespace : '' }, { signal: controller.signal }).then(r => r.json())))
      .then(results => {
        if (controller.signal.aborted) return
        cacheRef.current.set(cacheKey, results)
        setOverview(results)
        setRefreshing(false)
      })
    return () => controller.abort()
  }, [clusterId, active, namespace, refresh])

  useEffect(() => {
    const controller = new AbortController()
    setMetricsError('')
    if (!isPod) {
      setMetrics({})
      return () => controller.abort()
    }
    const cacheKey = `metrics:${clusterId}:${namespace || '*'}`
    const cached = cacheRef.current.get(cacheKey)
    if (cached) setMetrics(cached)
    else setMetrics({})
    api.get('/api/k8s/metrics/pods', { cluster: clusterId, namespace }, { signal: controller.signal }).then(r => r.json()).then(data => {
      if (controller.signal.aborted) return
      const nextMetrics = Object.fromEntries((data || []).map(m => [`${m.namespace}/${m.name}`, m]))
      cacheRef.current.set(cacheKey, nextMetrics)
      setMetrics(nextMetrics)
    }).catch(e => {
      if (!controller.signal.aborted && e?.name !== 'AbortError') setMetricsError('Metrics unavailable: check Metrics Server and your Kubernetes permissions.')
    })
    return () => controller.abort()
  }, [clusterId, active, namespace, refresh])

  const groups = useMemo(() => {
    const all = categories.flatMap(c => c.resources || [])
    const pick = names => names.filter(n => n !== 'secrets' || canRevealSecrets).map(n => all.find(r => r.name === n) || extra.find(r => r.name === n)).filter(Boolean)
    return [
      ['Workloads', pick(['pods', 'deployments', 'daemonsets', 'statefulsets', 'replicasets', 'replicationcontrollers', 'jobs', 'cronjobs'])],
      ['Config', pick(['configmaps', 'secrets', 'resourcequotas', 'limitranges', 'horizontalpodautoscalers', 'poddisruptionbudgets', 'priorityclasses', 'runtimeclasses', 'leases', 'mutatingwebhookconfigurations', 'validatingwebhookconfigurations', 'validatingadmissionpolicies', 'validatingadmissionpolicybindings'])], ['Network', pick(['services', 'endpointslices', 'endpoints', 'ingresses', 'ingressclasses', 'networkpolicies'])],
      ['Storage', pick(['persistentvolumeclaims', 'persistentvolumes', 'storageclasses'])],
      ['Access Control', pick(['serviceaccounts', 'roles', 'rolebindings', 'clusterroles', 'clusterrolebindings'])],
    ]
  }, [categories, canRevealSecrets])
  const open = t => {
    setTabs(prev => prev.some(x => typeKey(x) === typeKey(t)) ? prev : prev.map(x => typeKey(x) === active ? t : x))
    setActive(typeKey(t)); setDetail(null); setSearch('')
  }
  const navProps = t => ({
    onClick: e => {
      if (e.detail > 1) return
      navigationSnapshot.current = { tabs, active, target: typeKey(t) }
      open(t)
    },
    onDoubleClick: () => {
      const snapshot = navigationSnapshot.current
      if (!snapshot || snapshot.target !== typeKey(t)) return
      setTabs(snapshot.tabs.some(x => typeKey(x) === typeKey(t)) ? snapshot.tabs : [...snapshot.tabs, t])
      setActive(typeKey(t)); setDetail(null); setSearch('')
      navigationSnapshot.current = null
    },
  })
  const closeTab = key => {
    if (tabs.length === 1) return
    const next = tabs.filter(t => typeKey(t) !== key)
    setTabs(next)
    if (active === key) { setActive(typeKey(next[next.length - 1])); setDetail(null) }
  }
  const toggleCrds = async () => {
    setExpanded(x => ({ ...x, Custom: !x.Custom }))
    if (expanded.Custom || crds || crdLoading) return
    setCrdLoading(true); setCrdError('')
    try {
      const definitions = await api.get('/api/k8s/crds', { cluster: clusterId }).then(r => r.json())
      setCrds((definitions || []).map(item => {
        const spec = item.spec || {}
        const version = spec.versions?.find(v => v.served && v.storage) || spec.versions?.find(v => v.served)
        return version && spec.group && spec.names?.plural && spec.names?.kind ? { name: spec.names.plural, kind: spec.names.kind, group: spec.group, version: version.name, namespaced: spec.scope === 'Namespaced' } : null
      }).filter(Boolean))
    } catch (err) { setCrdError(err.message) }
    finally { setCrdLoading(false) }
  }
  const toggleDevices = async () => {
    setExpanded(x => ({ ...x, Device: !x.Device }))
    if (expanded.Device || deviceResources || deviceLoading) return
    setDeviceLoading(true); setDeviceError('')
    try { setDeviceResources(await api.get('/api/k8s/discover', { cluster: clusterId, group: 'resource.k8s.io' }).then(r => r.json())) }
    catch (err) { setDeviceError(err.message) }
    finally { setDeviceLoading(false) }
  }
  const deferredSearch = useDeferredValue(search)
  const rows = useMemo(() => {
    const query = deferredSearch.toLowerCase()
    if (!query) return items
    return items.filter(item => {
      const searchable = isEvent
        ? [item.metadata?.name, item.metadata?.namespace, item.type, item.reason, item.message, item.note, item.involvedObject?.kind, item.involvedObject?.name, item.regarding?.kind, item.regarding?.name].join(' ')
        : item.metadata?.name || ''
      return searchable.toLowerCase().includes(query)
    })
  }, [items, deferredSearch, isEvent])

  useEffect(() => {
    if (!visible) return
    const onKeyDown = e => {
      if ((e.metaKey || e.ctrlKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        window.parent?.postMessage({ type: 'operquay:open-command-palette' }, window.location.origin)
        return
      }
      if (shellChoice || action || share) return
      const target = e.target
      const inEditable = target instanceof Element && !!target.closest('input, textarea, select, [contenteditable="true"], .xterm')
      if ((e.metaKey || e.ctrlKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === 'f') {
        if (searchInputRef.current) {
          e.preventDefault()
          searchInputRef.current.focus()
          searchInputRef.current.select()
        }
        return
      }
      if (inEditable) {
        if (e.key === 'Escape' && target === searchInputRef.current && search) {
          e.preventDefault()
          setSearch('')
        }
        return
      }
      if (e.key === '/' && !e.metaKey && !e.ctrlKey && !e.altKey) {
        if (searchInputRef.current) {
          e.preventDefault()
          searchInputRef.current.focus()
          searchInputRef.current.select()
        }
        return
      }
      if (e.key.toLowerCase() === 'r' && !e.metaKey && !e.ctrlKey && !e.altKey) {
        e.preventDefault()
        setRefresh(n => n + 1)
        return
      }
      if (e.key === 'Escape') {
        if (menu) { e.preventDefault(); setMenu(null) }
        else if (detail) { e.preventDefault(); setDetail(null) }
        return
      }
      const isTableView = type && !['__overview', '__applications', '__helm', '__helmcharts', '__cost'].includes(type.name)
      if (isTableView && rows.length > 0 && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
        e.preventDefault()
        const idx = detail ? rows.findIndex(r => r.metadata?.name === detail.name && (r.metadata?.namespace || '') === (detail.namespace || '')) : -1
        const nextIdx = e.key === 'ArrowDown' ? (idx < rows.length - 1 ? idx + 1 : 0) : (idx > 0 ? idx - 1 : rows.length - 1)
        setDetail(selected(rows[nextIdx], type))
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [visible, shellChoice, action, share, search, menu, detail, type, rows])
  const header = (label, initial) => (
    <ResizableHeader
      key={label}
      label={label}
      width={columnWidths[`${active}:${label}`] ?? initial}
      onResize={width => setColumnWidths(value => ({ ...value, [`${active}:${label}`]: width }))}
      onBatchResize={updates =>
        setColumnWidths(value => {
          const next = { ...value }
          for (const [colLabel, w] of Object.entries(updates)) {
            next[`${active}:${colLabel}`] = w
          }
          return next
        })
      }
    />
  )
  const showLogs = targets => {
    setLogError('')
    if (!targets.length) { setLogError('No pods found for this selection.'); return }
    // shortcut: limit simultaneous streams to 100; select a smaller group for larger workloads.
    if (targets.reduce((n, p) => n + (p.containers?.length || 0), 0) > 100) { setLogError('Select at most 100 pod/container streams at a time.'); return }
    setLogPods(targets); setPod(targets[0]); setBottomTab('logs'); setMenu(null)
  }
  const showPanel = (tab, item) => {
    const target = selected(item, type)
    if (tab === 'logs') { showLogs([target]); return }
    requestShell(target)
  }
  const openShell = (target, container, mode = 'exec') => {
    const id = `shell-${++shellId.current}`
    setShells(previous => [...previous, { id, pod: target, container, mode }])
    setPod(target); setLogPods([]); setBottomTab(id); setMenu(null); setShellChoice(null)
  }
  const requestShell = target => {
    shellChoiceReturn.current = document.activeElement?.closest('.lens-row-actions')?.querySelector('button') || document.activeElement
    setMenu(null); setLogError('')
    const choices = target.shellContainers?.length ? target.shellContainers : target.containers || []
    if (choices.length > 1) setShellChoice({ ...target, choices })
    else if (choices.length === 1) openShell(target, choices[0])
    else setLogError('No containers are available for this pod.')
  }
  const cancelShellChoice = () => { setShellChoice(null); shellChoiceReturn.current?.focus() }
  const activatePanel = id => {
    setBottomTab(id)
    const shell = shells.find(s => s.id === id)
    if (shell) { setPod(shell.pod); setLogPods([]) }
  }
  const closeShell = id => {
    const remaining = shells.filter(shell => shell.id !== id)
    setShells(remaining)
    if (bottomTab === id) {
      if (remaining.length) activatePanel(remaining[remaining.length - 1].id)
      else { setPod(null); setLogPods([]) }
    }
  }
  const showWorkloadLogs = async item => {
    const generation = ++logRequest.current
    setMenu(null); setLogError(''); setLogLoading(true)
    try {
      const pods = await api.get('/api/k8s/workload-pods', { cluster: clusterId, namespace: item.metadata?.namespace, name: item.metadata?.name, uid: item.metadata?.uid, kind: type.kind }).then(r => r.json())
      if (generation === logRequest.current) showLogs(pods)
    } catch (err) { if (generation === logRequest.current) setLogError(err.message) }
    finally { if (generation === logRequest.current) setLogLoading(false) }
  }
  const shareResource = async item => {
    setMenu(null)
    try {
      const target = selected(item, type)
      const params = new URLSearchParams({ view: 'resource', cluster: await clusterFingerprint(clusterInfo), group: target.group, version: target.version, resource: target.resource, kind: target.kind, namespace: target.namespace, name: target.name, namespaced: String(type.namespaced) })
      const link = new URL('/k8s/', window.location.origin); link.hash = params.toString()
      setShare({ link: link.toString(), message: '' })
    } catch (err) { setShare({ link: '', message: err.message }) }
  }
  const openAction = async (operation, item) => {
    const target = selected(item, type)
    setMenu(null); setActionError(''); setActionText(''); setReplicas(item.spec?.replicas == null ? '' : String(item.spec.replicas)); setAction({ operation, target });
    if (operation !== 'edit') return
    setActionBusy(true)
    try {
      const obj = await api.get(`/api/k8s/resource/${target.resource}/${target.name}`, { cluster: clusterId, group: target.group, version: target.version, namespace: target.namespace }).then(r => r.json())
      if (obj.metadata?.uid !== target.uid || obj.metadata?.resourceVersion !== target.resourceVersion) throw new Error('This resource changed. Close this dialog and refresh before editing.')
      setActionText(stringify(editableResource(obj)))
    } catch (err) { setActionError(err.message) }
    finally { setActionBusy(false) }
  }
  const submitAction = async () => {
    const { operation, target } = action
    setActionError(''); setActionBusy(true)
    try {
      if (operation === 'attach') { if (target.containers?.length) openShell(target, target.containers[0], 'attach'); else setLogError('No containers are available for this pod.'); setAction(null); return }
      const payload = { cluster: clusterId, group: target.group, version: target.version, resource: target.resource, namespace: target.namespace, name: target.name, uid: target.uid, resource_version: target.resourceVersion }
      if (operation === 'edit') {
        const document = parseDocument(actionText, { stringKeys: true })
        if (document.errors.length || document.warnings.length) throw new Error((document.errors[0] || document.warnings[0]).message)
        payload.object = document.toJS({ maxAliasCount: 0 })
        if (!payload.object || typeof payload.object !== 'object' || Array.isArray(payload.object)) throw new Error('Enter a YAML resource object.')
      }
      if (operation === 'scale') {
        if (!/^\d+$/.test(replicas) || Number(replicas) > 2147483647) throw new Error('Enter a non-negative replica count.')
        payload.replicas = Number(replicas)
      }
      await api.post(`/api/k8s/actions/${operation}`, payload)
      for (const key of cacheRef.current.keys()) {
        if (key.startsWith(`res:${clusterId}:`) || key.startsWith(`apps:${clusterId}:`) || key.startsWith(`overview:${clusterId}:`)) {
          cacheRef.current.delete(key)
        }
      }
      setAction(null); setDetail(null); setRefresh(n => n + 1)
    } catch (err) { setActionError(err.message) }
    finally { setActionBusy(false) }
  }
  const named = name => categories.flatMap(c => c.resources || []).find(r => r.name === name)
  const available = (catalog?.items || []).filter(c => !c.id)
  const clusterGroups = new Map()
  for (const option of [
    ...connections.map(c => ({ value: c.id, name: c.info.name, detail: clusterHosting(c.info), disabled: !!c.info.expires_at && Date.parse(c.info.expires_at) <= Date.now() })),
    ...available.map((item, index) => ({ value: `available:${index}`, name: item.name, detail: item.hosting || clusterHosting({ source: item.source }), available: true })),
  ]) {
    const group = clusterGroups.get(option.detail.cloud) || []
    group.push(option); clusterGroups.set(option.detail.cloud, group)
  }
  const switchCluster = async value => {
    setSwitchError('')
    if (!value.startsWith('available:')) { onSwitch(value); return }
    const item = available[Number(value.slice('available:'.length))]
    if (!item || !catalog.connect) { setSwitchError('Cluster is no longer available.'); return }
    setSwitching(true)
    try { const id = await catalog.connect(item.name); if (id) onSwitch(id) }
    catch (err) { setSwitchError(err.message) }
    finally { setSwitching(false) }
  }
  return <div className="lens-workspace">
    {(!isEmbedded || showInnerNav) && <aside className="lens-rail"><button title="Clusters" aria-label="Clusters" onClick={onClusters}>⎈</button></aside>}
    {(!isEmbedded || showInnerNav) && <nav className="lens-nav" aria-label="Kubernetes navigator">
      <div className="lens-nav-title">Navigator</div>
      <select className="lens-cluster-select" aria-label="Switch cluster" value={clusterId} disabled={switching} onChange={e => switchCluster(e.target.value)}>
        {[...clusterGroups].map(([cloud, options]) => <optgroup key={cloud} label={cloudNames[cloud]}>{options.map(option => <option key={option.value} value={option.value} disabled={option.disabled}>{option.name} · {option.available ? 'Connect' : option.detail.detail}</option>)}</optgroup>)}
      </select>
      {switching && <p className="lens-switch-status" role="status"><span className="connect-spinner" aria-hidden="true" /> Connecting…</p>}
      {switchError && <div className="lens-switch-status" role="alert">{switchError} <button onClick={onSignIn}>Connection settings</button></div>}
      <div className="lens-tree"><div className="lens-cluster-label"><CloudIcon cloud={clusterHosting(clusterInfo).cloud} /><span className="lens-cluster-name" title={clusterInfo?.name ? `${clusterInfo.name} · ${clusterHosting(clusterInfo).detail}` : clusterHosting(clusterInfo).detail}>{clusterInfo?.name}</span><span className="lens-green">●</span></div>
        {navError && <p role="alert" className="lens-error">{navError}</p>}
        <button className={`lens-nav-item ${active === typeKey(overviewType) ? 'active' : ''}`} title="Overview" {...navProps(overviewType)}><LayoutDashboard size={15} className="lens-nav-icon shrink-0" /><span>Overview</span></button>
        <button className={`lens-nav-item ${active === typeKey(applicationsType) ? 'active' : ''}`} title="Applications" {...navProps(applicationsType)}><AppWindow size={15} className="lens-nav-icon shrink-0" /><span>Applications</span></button>
        <button className="lens-nav-item" title="Argo CD" aria-expanded={!!expanded.Argo} onClick={() => setExpanded(x => ({ ...x, Argo: !x.Argo }))}>{expanded.Argo ? <ChevronDown size={14} className="shrink-0" /> : <ChevronRight size={14} className="shrink-0" />}<GitBranch size={15} className="lens-nav-icon shrink-0" /><span>Argo CD</span></button>
        {expanded.Argo && <button className={`lens-nav-child ${active === typeKey(argoApps) ? 'active' : ''}`} title="Argo CD Applications" {...navProps(argoApps)}>Argo CD Applications</button>}
        {named('nodes') && <button className={`lens-nav-item ${active === typeKey(named('nodes')) ? 'active' : ''}`} title="Nodes" {...navProps(named('nodes'))}><Server size={15} className="lens-nav-icon shrink-0" /><span>Nodes</span></button>}
        {groups.filter(([name]) => name !== 'Access Control').map(([name, entries]) => {
          const CatIcon = categoryIcons[name] || Box
          return (
            <div key={name}>
              <button className="lens-nav-item" title={name} aria-expanded={!!expanded[name]} onClick={() => setExpanded(x => ({ ...x, [name]: !x[name] }))}>
                {expanded[name] ? <ChevronDown size={14} className="shrink-0" /> : <ChevronRight size={14} className="shrink-0" />}
                <CatIcon size={15} className="lens-nav-icon shrink-0" />
                <span>{name}</span>
              </button>
              {expanded[name] && entries.map(t => <button key={typeKey(t)} className={`lens-nav-child ${active === typeKey(t) ? 'active' : ''}`} title={resourceTitle(t)} {...navProps(t)}>{resourceTitle(t)}</button>)}
            </div>
          )
        })}
        <button className="lens-nav-item" title="Device Resources" aria-expanded={!!expanded.Device} onClick={toggleDevices}>{expanded.Device ? <ChevronDown size={14} className="shrink-0" /> : <ChevronRight size={14} className="shrink-0" />}<Cpu size={15} className="lens-nav-icon shrink-0" /><span>Device Resources</span></button>
        {expanded.Device && <>{deviceLoading && <p className="lens-nav-child">Loading…</p>}{deviceError && <p className="lens-error" role="alert">{deviceError}</p>}{deviceResources?.length === 0 && <p className="lens-nav-child">No listable device resources found</p>}{deviceResources?.map(t => <button key={typeKey(t)} className={`lens-nav-child ${active === typeKey(t) ? 'active' : ''}`} title={`${resourceTitle(t)} (${t.group}/${t.version})`} {...navProps(t)}>{resourceTitle(t)}</button>)}</>}
        {named('namespaces') && <button className={`lens-nav-item ${active === typeKey(named('namespaces')) ? 'active' : ''}`} title="Namespaces" {...navProps(named('namespaces'))}><FolderTree size={15} className="lens-nav-icon shrink-0" /><span>Namespaces</span></button>}
        {named('events') && <button className={`lens-nav-item ${active === typeKey(named('events')) ? 'active' : ''}`} title="Events" {...navProps(named('events'))}><Activity size={15} className="lens-nav-icon shrink-0" /><span>Events</span></button>}
        <button className="lens-nav-item" title="Helm" aria-expanded={!!expanded.Helm} onClick={() => setExpanded(x => ({ ...x, Helm: !x.Helm }))}>{expanded.Helm ? <ChevronDown size={14} className="shrink-0" /> : <ChevronRight size={14} className="shrink-0" />}<Package size={15} className="lens-nav-icon shrink-0" /><span>Helm</span></button>
        {expanded.Helm && <button className={`lens-nav-child ${active === typeKey(helmChartsType) ? 'active' : ''}`} title="Charts" {...navProps(helmChartsType)}>Charts</button>}
        {expanded.Helm && <button className={`lens-nav-child ${active === typeKey(helmType) ? 'active' : ''}`} title="Releases" {...navProps(helmType)}>Releases</button>}
        {groups.filter(([name]) => name === 'Access Control').map(([name, entries]) => (
          <div key={name}>
            <button className="lens-nav-item" title={name} aria-expanded={!!expanded[name]} onClick={() => setExpanded(x => ({ ...x, [name]: !x[name] }))}>
              {expanded[name] ? <ChevronDown size={14} className="shrink-0" /> : <ChevronRight size={14} className="shrink-0" />}
              <ShieldCheck size={15} className="lens-nav-icon shrink-0" />
              <span>{name}</span>
            </button>
            {expanded[name] && entries.map(t => <button key={typeKey(t)} className={`lens-nav-child ${active === typeKey(t) ? 'active' : ''}`} title={resourceTitle(t)} {...navProps(t)}>{resourceTitle(t)}</button>)}
          </div>
        ))}
        <button className="lens-nav-item" title="Custom Resources" aria-expanded={!!expanded.Custom} onClick={toggleCrds}>{expanded.Custom ? <ChevronDown size={14} className="shrink-0" /> : <ChevronRight size={14} className="shrink-0" />}<Code2 size={15} className="lens-nav-icon shrink-0" /><span>Custom Resources</span></button>
        {expanded.Custom && <>{crdLoading && <p className="lens-nav-child">Loading…</p>}{crdError && <p className="lens-error" role="alert">{crdError}</p>}{crds && <button className={`lens-nav-child ${active === typeKey(crdDefinitions) ? 'active' : ''}`} title="Definitions" {...navProps(crdDefinitions)}>Definitions</button>}{crds?.length === 0 && <p className="lens-nav-child">No custom resources found</p>}{[...new Set((crds || []).map(t => t.group))].sort().map(group => <div key={group}><button className="lens-nav-child" title={group} aria-expanded={!!expanded[`CRD:${group}`]} onClick={() => setExpanded(x => ({ ...x, [`CRD:${group}`]: !x[`CRD:${group}`] }))}>{expanded[`CRD:${group}`] ? <ChevronDown size={13} className="shrink-0" /> : <ChevronRight size={13} className="shrink-0" />}<span>{group}</span></button>{expanded[`CRD:${group}`] && crds.filter(t => t.group === group).sort((a, b) => resourceTitle(a).localeCompare(resourceTitle(b))).map(t => <button key={typeKey(t)} className={`lens-nav-child lens-nav-grandchild ${active === typeKey(t) ? 'active' : ''}`} title={`${resourceTitle(t)} (${t.group}/${t.version})`} {...navProps(t)}>{resourceTitle(t)}</button>)}</div>)}</>}
        <button className={`lens-nav-item ${active === typeKey(costType) ? 'active' : ''}`} title="Cost Monitoring" {...navProps(costType)}><CircleDollarSign size={15} className="lens-nav-icon shrink-0" /><span>Cost Monitoring</span></button>
      </div>
    </nav>}
    <div className="lens-main">
      <div className="lens-tabs-bar">
        {isEmbedded && (
          <button
            type="button"
            className="lens-nav-toggle-btn"
            onClick={() => setShowInnerNav(v => !v)}
            title={showInnerNav ? "Hide Navigator panel" : "Show Navigator panel"}
            aria-label={showInnerNav ? "Hide Navigator panel" : "Show Navigator panel"}
          >
            {showInnerNav ? <PanelLeftClose size={15} /> : <PanelLeft size={15} />}
          </button>
        )}
        <WorkspaceTabBar role="none" className="lens-tabs">
          {tabs.map(t => {
            const tabTitle = `${titles[t.name] || t.kind} - ${clusterInfo?.name}`
            return (
              <WorkspaceTab
                key={typeKey(t)}
                mode="split-button"
                className="lens-tab"
                active={active === typeKey(t)}
                icon={<span className="lens-pink">⎈</span>}
                label={tabTitle}
                title={tabTitle}
                onSelect={() => { setActive(typeKey(t)); setDetail(null) }}
                onClose={tabs.length > 1 ? () => closeTab(typeKey(t)) : undefined}
                closeLabel={`Close ${titles[t.name] || t.kind} tab`}
              />
            )
          })}
        </WorkspaceTabBar>
      </div>
      {type?.name !== '__cost' && <div className="lens-toolbar">
        {type?.name !== 'namespaces' && (
          <NamespaceSelector
            ariaLabel="Namespace"
            namespaces={namespaces}
            selected={isEvent ? selectedEventNamespaces : selectedNamespaces}
            onChange={isEvent ? setEventNamespace : setNamespace}
            disabled={!type?.namespaced && type?.name !== '__overview'}
          />
        )}
        {type?.name !== '__overview' && <input ref={searchInputRef} aria-label={`Search ${titles[type?.name] || 'resources'}`} placeholder={`Search ${titles[type?.name] || 'resources'}... (/)`} value={search} onChange={e => setSearch(e.target.value)} />}
        <button className={`lens-refresh ${refreshing ? 'spinning' : ''}`} onClick={() => setRefresh(n => n + 1)} title={refreshing ? 'Updating resources…' : 'Refresh (r)'} aria-label="Refresh resources">↻</button>{!['__overview', '__applications'].includes(type?.name) && <span>{['__helm', '__helmcharts'].includes(type?.name) ? (helm?.releases || []).filter(r => (type?.name === '__helmcharts' ? r.chart?.name || r.name : r.name).toLowerCase().includes(deferredSearch.toLowerCase())).length : rows.length} items</span>}
        {isPod && canReadLogs && selectedPods.length > 0 && <button className="lens-logs-selected" onClick={() => showLogs(items.filter(item => selectedPods.includes(`${item.metadata?.namespace || ''}/${item.metadata?.name || ''}`)).map(item => selected(item, type)))}>View logs ({selectedPods.length})</button>}
      </div>}
      {namespaceError && <div className="lens-error" role="alert">Could not load namespaces: {namespaceError}</div>}
      {linkError && <div className="lens-error" role="alert">{linkError}</div>}
      {metricsError && <div className="lens-metrics-note" role="status">{metricsError}</div>}
      {isEvent && <div className="lens-metrics-note">Events describe activity on resources; the involved object identifies the resource. Showing {eventNamespace || 'all accessible namespaces'}; Kubernetes may expire older events.</div>}
      {logLoading && <div className="lens-metrics-note" role="status">Finding workload pods…</div>}
      {logError && <div className="lens-error" role="alert">{logError}</div>}
      <div className="lens-content">
        {tabs.some(t => t.name === '__cost') && <div className="cost-holder" hidden={type?.name !== '__cost'}><CostPanel clusterId={clusterId} namespaces={namespaces} /></div>}
        {type?.name === '__cost' ? null : type?.name === '__overview' ? (() => {
          const nodesRes = overview?.[0]
          const podsRes = overview?.[1]
          const depsRes = overview?.[2]
          const pods = podsRes?.status === 'fulfilled' ? (podsRes.value || []) : []
          const deps = depsRes?.status === 'fulfilled' ? (depsRes.value || []) : []
          const podRunning = pods.filter(p => p.status?.phase === 'Running').length
          const podPending = pods.filter(p => p.status?.phase === 'Pending').length
          const podSucceeded = pods.filter(p => p.status?.phase === 'Succeeded').length
          const podOther = Math.max(0, pods.length - podRunning - podPending - podSucceeded)
          const podTotal = Math.max(1, pods.length)
          const depsReady = deps.filter(d => (d.spec?.replicas ?? 0) === 0 || (d.status?.readyReplicas ?? 0) >= (d.spec?.replicas ?? 0)).length
          const depsDegraded = Math.max(0, deps.length - depsReady)
          const sortedDeps = [...deps].sort((a, b) => {
            const aOk = (a.status?.readyReplicas ?? 0) >= (a.spec?.replicas ?? 0)
            const bOk = (b.status?.readyReplicas ?? 0) >= (b.spec?.replicas ?? 0)
            return Number(aOk) - Number(bOk)
          }).slice(0, 5)
          const hostCloud = clusterHosting(clusterInfo)
          const depsType = named('deployments')
          const eventsType = named('events')
          const nsType = named('namespaces')
          return <div className="lens-overview">
            <div className="lens-overview-head">
              <div>
                <div className="lens-overview-eyebrow">Precision Cluster Console</div>
                <h1>{clusterInfo?.name || 'Cluster overview'}</h1>
                <p>
                  {hostCloud ? `${cloudNames[hostCloud] || hostCloud} · ` : ''}
                  Resources {namespace ? `in ${namespace}` : 'across all namespaces'}. Nodes are cluster-wide.
                </p>
              </div>
              <div className="lens-overview-actions">
                <button type="button" onClick={() => open(applicationsType)}>Applications</button>
                {eventsType && <button type="button" onClick={() => open(eventsType)}>Events</button>}
                <button type="button" onClick={() => open(helmType)}>Helm Releases</button>
                <button type="button" onClick={() => open(costType)}>Cost Monitoring</button>
              </div>
            </div>

            <div className="lens-overview-cards">
              {[['Nodes', 'nodes', 0], ['Running pods', 'pods', 1], ['Deployments', 'deployments', 2]].map(([label, name, index]) => {
                const result = overview?.[index]
                const value = result?.status === 'fulfilled' ? (name === 'pods' ? podRunning : result.value.length) : null
                const sub = !result ? 'Fetching…' : result.status === 'rejected' ? null : name === 'pods' ? `${pods.length} total pods` : name === 'deployments' ? `${depsReady} ready · ${depsDegraded} scaling/degraded` : 'Cluster capacity'
                return <button key={name} type="button" onClick={() => { const t = named(name); if (t) open(t) }} disabled={!named(name)}>
                  <span>{label}</span>
                  <strong>{!result ? '…' : value === null ? 'Unavailable' : value}</strong>
                  {sub && <span className="lens-overview-sub">{sub}</span>}
                  {result?.status === 'rejected' && <small>{result.reason.message}</small>}
                </button>
              })}
              <button type="button" onClick={() => { if (nsType) open(nsType) }} disabled={!nsType}>
                <span>Namespaces</span>
                <strong>{namespaces.length}</strong>
                <span className="lens-overview-sub">{namespace ? `Filtered: ${namespace}` : 'All accessible scopes'}</span>
              </button>
            </div>

            <div className="lens-overview-grid">
              <section className="lens-overview-panel" aria-label="Pod phase breakdown">
                <div className="lens-overview-panel-head">
                  <h2>Pod Phase Breakdown</h2>
                  {named('pods') && <button type="button" className="lens-overview-link" onClick={() => open(named('pods'))}>Inspect pods →</button>}
                </div>
                {!podsRes ? <p className="lens-overview-muted">Loading pod status…</p> : podsRes.status === 'rejected' ? <p className="lens-overview-err">{podsRes.reason.message}</p> : <>
                  <div className="lens-phase-bar" role="img" aria-label={`Pods: ${podRunning} running, ${podPending} pending, ${podSucceeded} succeeded, ${podOther} other`}>
                    {podRunning > 0 && <span className="phase-running" style={{ width: `${(podRunning / podTotal) * 100}%` }} />}
                    {podPending > 0 && <span className="phase-pending" style={{ width: `${(podPending / podTotal) * 100}%` }} />}
                    {podSucceeded > 0 && <span className="phase-succeeded" style={{ width: `${(podSucceeded / podTotal) * 100}%` }} />}
                    {podOther > 0 && <span className="phase-other" style={{ width: `${(podOther / podTotal) * 100}%` }} />}
                  </div>
                  <div className="lens-phase-stats">
                    <div><span className="dot running" /><span>Running</span><strong>{podRunning}</strong></div>
                    <div><span className="dot pending" /><span>Pending</span><strong>{podPending}</strong></div>
                    <div><span className="dot succeeded" /><span>Succeeded</span><strong>{podSucceeded}</strong></div>
                    <div><span className="dot other" /><span>Failed / Other</span><strong>{podOther}</strong></div>
                  </div>
                </>}
              </section>

              <section className="lens-overview-panel" aria-label="Deployment readiness">
                <div className="lens-overview-panel-head">
                  <h2>Workload Readiness</h2>
                  {depsType && <button type="button" className="lens-overview-link" onClick={() => open(depsType)}>All deployments →</button>}
                </div>
                {!depsRes ? <p className="lens-overview-muted">Loading deployments…</p> : depsRes.status === 'rejected' ? <p className="lens-overview-err">{depsRes.reason.message}</p> : sortedDeps.length === 0 ? <p className="lens-overview-muted">No deployments in {namespace || 'this cluster'}.</p> : (
                  <div className="lens-workload-list">
                    {sortedDeps.map(d => {
                      const ready = d.status?.readyReplicas ?? 0
                      const desired = d.spec?.replicas ?? 0
                      const healthy = ready >= desired
                      return (
                        <button key={`${d.metadata?.namespace}/${d.metadata?.name}`} type="button" className="lens-workload-row" onClick={() => { if (depsType) { open(depsType); setDetail(selected(d, depsType)) } }}>
                          <span className="lens-workload-name">
                            <span className={`dot ${healthy ? 'running' : 'pending'}`} />
                            <span className="truncate">{d.metadata?.name}</span>
                          </span>
                          <span className="lens-workload-ns">{d.metadata?.namespace}</span>
                          <span className={`lens-workload-ready ${healthy ? 'ok' : 'warn'}`}>{ready}/{desired}</span>
                        </button>
                      )
                    })}
                  </div>
                )}
              </section>
            </div>
            {nodesRes?.status === 'fulfilled' && nodesRes.value.length > 0 && (
              <div className="lens-overview-foot">
                <span>Cluster health snapshot: {nodesRes.value.filter(n => (n.status?.conditions || []).some(c => c.type === 'Ready' && c.status === 'True')).length}/{nodesRes.value.length} Ready nodes</span>
              </div>
            )}
          </div>
        })() : type?.name === '__applications' ? <div className="lens-table-wrap"><p className="lens-metrics-note">Applications shown as Deployments, StatefulSets and DaemonSets. Argo CD and Helm are available separately.</p>
          {!applications && <p className="lens-empty">Loading workloads…</p>}
          {applications?.filter(a => a.result.status === 'rejected').map(a => <p role="status" className="lens-error" key={a.type.name}>{a.type.kind}: {a.result.reason.message}</p>)}
          {applications && <table className="lens-table"><thead><tr>{header('Name', '35%')}{header('Kind', '20%')}{header('Namespace', '20%')}{header('Ready', '15%')}{header('Age', '10%')}</tr></thead><tbody>{applications.flatMap(a => a.result.status === 'fulfilled' ? a.result.value.map(item => ({ item, type: a.type })) : []).filter(({ item }) => (item.metadata?.name || '').toLowerCase().includes(search.toLowerCase())).map(({ item, type: t }) => {
            const appName = item.metadata?.name || '—'
            const appNs = item.metadata?.namespace || '—'
            const readyText = `${item.status?.readyReplicas ?? item.status?.numberReady ?? '—'} / ${item.spec?.replicas ?? item.status?.desiredNumberScheduled ?? '—'}`
            const ageText = age(item.metadata?.creationTimestamp)
            return <tr key={`${typeKey(t)}/${item.metadata?.namespace}/${item.metadata?.name}`}><td><button className="lens-name" title={appName} onClick={() => { open(t); setDetail(selected(item, t)) }}>{appName}</button></td><td title={t.kind}>{t.kind}</td><td title={appNs}>{appNs}</td><td title={readyText}>{readyText}</td><td title={ageText}>{ageText}</td></tr>
          })}</tbody></table>}
        </div> : ['__helm', '__helmcharts'].includes(type?.name) ? <div className="lens-table-wrap"><p className="lens-metrics-note">{type.name === '__helmcharts' ? 'Charts from installed releases only; remote chart repositories are not included. ' : ''}Latest Helm release metadata from Secrets and ConfigMaps. SQL and other storage drivers are not included; release contents are not displayed.</p>
          {helm?.sources?.filter(s => s.error || s.omitted || s.chart_limited).map(s => <p className="lens-error" role="status" key={s.driver}>{s.driver}: {s.error || (s.chart_limited ? 'Some chart metadata was omitted due to the processing limit.' : `${s.omitted} entries had incomplete metadata`)}</p>)}
          {helmError && <p className="lens-error" role="alert">{helmError}</p>}
          {!helm && !helmError && <p className="lens-empty">Loading Helm releases…</p>}
          {helm && (type.name === '__helmcharts' ? <table className="lens-table"><thead><tr>{header('Chart', '25%')}{header('Version', '15%')}{header('App version', '15%')}{header('Release', '25%')}{header('Namespace', '20%')}</tr></thead><tbody>{helm.releases.filter(r => (r.chart?.name || r.name).toLowerCase().includes(search.toLowerCase())).map(r => <tr key={`${r.driver}/${r.namespace}/${r.name}`}><td title={r.chart?.name || 'Unavailable'}>{r.chart?.name || 'Unavailable'}</td><td title={r.chart?.version || '—'}>{r.chart?.version || '—'}</td><td title={r.chart?.appVersion || '—'}>{r.chart?.appVersion || '—'}</td><td title={r.name}>{r.name}</td><td title={r.namespace}>{r.namespace}</td></tr>)}</tbody></table> : <table className="lens-table"><thead><tr>{header('Name', '26%')}{header('Namespace', '24%')}{header('Revision', '12%')}{header('Status', '15%')}{header('Storage', '13%')}{header('Age', '10%')}</tr></thead><tbody>{helm.releases.filter(r => r.name.toLowerCase().includes(search.toLowerCase())).map(r => <tr key={`${r.driver}/${r.namespace}/${r.name}`}><td title={r.name}>{r.name}</td><td title={r.namespace}>{r.namespace}</td><td title={String(r.revision)}>{r.revision}</td><td className={r.status === 'deployed' ? 'lens-green' : ''} title={r.status || '—'}>{r.status || '—'}</td><td title={r.driver}>{r.driver}</td><td title={age(r.updated)}>{age(r.updated)}</td></tr>)}</tbody></table>)}
          {helm && !helm.releases.length && <p className="lens-empty">No releases found in the accessible storage sources.</p>}
        </div> : <>
        <div className="lens-table-wrap">
          <table className="lens-table"><thead><tr>{isPod && <th style={{ width: '34px' }}><input type="checkbox" aria-label="Select all visible pods" checked={rows.length > 0 && rows.every(item => selectedPods.includes(`${item.metadata?.namespace || ''}/${item.metadata?.name || ''}`))} onChange={e => { const keys = rows.map(item => `${item.metadata?.namespace || ''}/${item.metadata?.name || ''}`); setSelectedPods(prev => e.target.checked ? [...new Set([...prev, ...keys])] : prev.filter(k => !keys.includes(k))) }} /></th>}{header('Name', isPod ? '13%' : isEvent ? '15%' : '35%')}{type?.namespaced && header('Namespace', isPod ? '8%' : isEvent ? '11%' : '25%')}{isPod && <>{header('CPU', '5%')}{header('Memory', '7%')}{header('Containers', '8%')}{header('Restarts', '7%')}{header('Controller', '13%')}{header('Node', '11%')}{header('QoS', '8%')}</>}{isEvent ? <>{header('Type', '8%')}{header('Reason', '10%')}{header('Involved object', '14%')}{header('Message', '23%')}{header('Count', '6%')}{header('Last seen', '8%')}</> : <>{header('Status', isPod ? '7%' : '20%')}{header('Age', isPod ? '5%' : '15%')}</>}<th aria-label="Actions" style={{ width: '34px' }}></th></tr></thead>
            <tbody>{rows.map(item => {
              const name = item.metadata?.name || ''; const ns = item.metadata?.namespace || ''; const key = `${ns}/${name}`
              const isSelected = !!detail && detail.name === name && (detail.namespace || '') === ns && detail.resource === type?.name
              const statuses = item.status?.containerStatuses || []; const owner = item.metadata?.ownerReferences?.[0]
              const cpuLabel = metrics[key] ? `${metrics[key].cpu_millicores}m` : 'N/A'
              const memLabel = metrics[key] ? `${(metrics[key].memory_bytes / 1048576).toFixed(1)} MiB` : 'N/A'
              const restartsLabel = statuses.length ? String(statuses.reduce((n, s) => n + (s.restartCount || 0), 0)) : '—'
              const controllerLabel = owner ? `${owner.kind}/${owner.name}` : '—'
              const nodeLabel = item.spec?.nodeName || '—'
              const qosLabel = item.status?.qosClass || '—'
              const statusLabel = item.status?.phase || item.status?.sync?.status || '—'
              const ageLabel = age(item.metadata?.creationTimestamp)
              const involvedLabel = (item.involvedObject || item.regarding)?.kind ? `${(item.involvedObject || item.regarding).kind}/${(item.involvedObject || item.regarding).name || '—'}` : '—'
              const messageLabel = item.message || item.note || '—'
              const countLabel = String(item.series?.count ?? item.count ?? item.deprecatedCount ?? '—')
              const lastSeenLabel = age(item.series?.lastObservedTime || item.lastTimestamp || item.deprecatedLastTimestamp || item.eventTime || item.metadata?.creationTimestamp)
              return <tr key={key} className={isSelected ? 'selected' : undefined} aria-selected={isSelected || undefined}>{isPod && <td><input type="checkbox" aria-label={`Select ${name}`} checked={selectedPods.includes(key)} onChange={e => setSelectedPods(prev => e.target.checked ? [...prev, key] : prev.filter(k => k !== key))} /></td>}<td><button className="lens-name" title={name} onClick={() => setDetail(selected(item, type))}>{name}</button></td>{type.namespaced && <td className="lens-link" title={ns || '—'}>{ns || '—'}</td>}
                {isPod && <><td title={cpuLabel}>{cpuLabel}</td><td title={memLabel}>{memLabel}</td><td><ContainerStates item={item} /></td><td title={restartsLabel}>{restartsLabel}</td><td title={controllerLabel}>{controllerLabel}</td><td title={nodeLabel}>{nodeLabel}</td><td title={qosLabel}>{qosLabel}</td></>}
                {isEvent ? <><td title={item.type || '—'}>{item.type || '—'}</td><td title={item.reason || '—'}>{item.reason || '—'}</td><td title={involvedLabel}>{involvedLabel}</td><td title={messageLabel}>{messageLabel}</td><td title={countLabel}>{countLabel}</td><td title={lastSeenLabel}>{lastSeenLabel}</td></> : <><td className={item.status?.phase === 'Running' ? 'lens-green' : ''} title={statusLabel}>{statusLabel}</td><td title={ageLabel}>{ageLabel}</td></>}
                <td className="lens-row-actions"><button aria-label={`Actions for ${name}`} aria-haspopup="menu" aria-expanded={menu === key} onClick={() => setMenu(menu === key ? null : key)}>⋮</button>{menu === key && <div className="lens-menu" role="menu" onKeyDown={e => {
                  if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); setMenu(null); return }
                  const items = Array.from(e.currentTarget.querySelectorAll('button:not([disabled])'))
                  if (!items.length) return
                  const cur = items.indexOf(document.activeElement)
                  if (e.key === 'ArrowDown') { e.preventDefault(); items[(cur + 1) % items.length]?.focus() }
                  else if (e.key === 'ArrowUp') { e.preventDefault(); items[(cur <= 0 ? items.length - 1 : cur - 1)]?.focus() }
                  else if (e.key === 'Home') { e.preventDefault(); items[0]?.focus() }
                  else if (e.key === 'End') { e.preventDefault(); items[items.length - 1]?.focus() }
                }}><button autoFocus onClick={() => { setDetail(selected(item, type)); setMenu(null) }}>Show Details</button>{isPod && canExec && <><button disabled={!item.metadata?.uid} onClick={() => openAction('attach', item)}>Attach Pod</button><button onClick={() => showPanel('exec', item)}>Shell</button></>}{isPod && canOperate && <button disabled={!item.metadata?.uid || !item.metadata?.resourceVersion} onClick={() => openAction('evict', item)}>Evict</button>}{isScalable && <button disabled={!canOperate || !item.metadata?.uid || !item.metadata?.resourceVersion} onClick={() => openAction('scale', item)}>Scale</button>}{isRestartable && <button disabled={!canOperate || !item.metadata?.uid || !item.metadata?.resourceVersion} onClick={() => openAction('restart', item)}>Restart</button>}<button onClick={() => shareResource(item)}>Share</button>{isPod && canReadLogs && <button onClick={() => showPanel('logs', item)}>Logs</button>}{isRestartable && canReadLogs && <button disabled={!item.metadata?.uid || logLoading} onClick={() => showWorkloadLogs(item)}>Logs</button>}<button disabled={!canOperate || !item.metadata?.uid || !item.metadata?.resourceVersion || (type.name === 'secrets' && !type.group)} title={type.name === 'secrets' && !type.group ? 'Reveal values in Details to edit' : undefined} onClick={() => openAction('edit', item)}>Edit</button><button disabled={!canOperate || !item.metadata?.uid || !item.metadata?.resourceVersion} onClick={() => openAction('delete', item)}>Delete</button></div>}</td></tr>
            })}</tbody></table>
          {loading && <div className="lens-empty">Loading resources…</div>}{!loading && error && <div className="lens-error" role="alert">Could not load resources: {error}</div>}{!loading && !error && !rows.length && <div className="lens-empty">No resources found</div>}
        </div>
        {detail && <div className="lens-detail"><button className="lens-close-detail" aria-label="Close details" onClick={() => setDetail(null)}>×</button><DetailPanel key={JSON.stringify([clusterId, detail.group, detail.version, detail.resource, detail.namespace, detail.name, detail.uid])} clusterId={clusterId} resource={detail} canRevealSecrets={canRevealSecrets} metrics={metrics[`${detail.namespace}/${detail.name}`]} onOpenLogs={canReadLogs ? p => showLogs([p]) : null} onOpenExec={canExec ? requestShell : null} onEdit={canOperate && detail.uid && detail.resourceVersion ? () => openAction('edit', { metadata: { name: detail.name, namespace: detail.namespace, uid: detail.uid, resourceVersion: detail.resourceVersion } }) : null} /></div>}
        </>}
      </div>
      {pod && <div className="lens-bottom"><button className="lens-close-bottom" aria-label="Close terminal" onClick={() => bottomTab === 'logs' ? (shells.length ? activatePanel(shells[shells.length - 1].id) : (setPod(null), setLogPods([]))) : closeShell(bottomTab)}>×</button><BottomPanel clusterId={clusterId} pod={pod} pods={logPods} tab={bottomTab} onTabChange={activatePanel} shells={shells} onCloseShell={closeShell} onOpenExec={() => requestShell(pod)} onChangeShellContainer={(id, container) => setShells(previous => previous.map(shell => shell.id === id ? { ...shell, container } : shell))} height={height} onHeightChange={setHeight} canExec={canExec && logPods.length <= 1} /></div>}
      {!pod && <div className="lens-bottom-bar">Select a pod to open logs or shell</div>}
    </div>
    {shellChoice && <div className="lens-modal-backdrop" onKeyDown={e => { if (e.key === 'Escape') cancelShellChoice(); keepDialogFocus(e) }}><section className="lens-modal lens-shell-choice" role="dialog" aria-modal="true" aria-label={`Choose container for ${shellChoice.name}`}><h2>Choose container for {shellChoice.name}</h2><div>{shellChoice.choices.map((name, index) => <button key={name} autoFocus={index === 0} onClick={() => openShell(shellChoice, name)}>{name}</button>)}</div><div className="lens-modal-actions"><button onClick={cancelShellChoice}>Cancel</button></div></section></div>}
    {action && <div className="lens-modal-backdrop" onKeyDown={e => {
      if (e.key === 'Escape' && !actionBusy) setAction(null)
      keepDialogFocus(e)
    }}><section className="lens-modal" role="dialog" aria-modal="true" aria-labelledby="action-title">
      <h2 id="action-title">{action.operation === 'edit' ? 'Edit resource' : action.operation === 'attach' ? 'Attach to pod?' : action.operation === 'scale' ? 'Scale workload' : action.operation === 'restart' ? 'Restart workload?' : action.operation === 'evict' ? 'Evict pod?' : 'Delete resource?'}</h2>
      <p>{action.target.kind} <strong>{action.target.namespace ? `${action.target.namespace}/` : ''}{action.target.name}</strong> in {clusterInfo?.name}</p>
      {action.operation === 'evict' && <p>Eviction respects pod disruption budgets and can interrupt the workload.</p>}
      {action.operation === 'attach' && <p>Attaching connects to the existing container process. Input can affect the workload; Kubernetes cannot guarantee the pod will not be replaced during connection.</p>}
      {action.operation === 'scale' && <><p>Scaling changes the number of replicas and may interrupt the workload.</p><label>Replicas <input className="lens-scale-input" aria-label="Replicas" type="number" min="0" max="2147483647" step="1" value={replicas} onChange={e => setReplicas(e.target.value)} /></label></>}
      {action.operation === 'restart' && <p>This starts a rollout by updating the pod template and may interrupt the workload.</p>}
      {action.operation === 'delete' && <p>This deletes the selected resource and may interrupt the workload. This cannot be undone.</p>}
      {action.operation === 'edit' && <><p>Edit YAML. Name, namespace, UID and resource version cannot be changed.</p><textarea aria-label="Resource YAML" value={actionText} onChange={e => setActionText(e.target.value)} disabled={actionBusy} spellCheck={false} /></>}
      {actionError && <p className="lens-error" role="alert">{actionError}</p>}
      <div className="lens-modal-actions"><button autoFocus onClick={() => setAction(null)} disabled={actionBusy}>Cancel</button><button className={['delete', 'evict', 'scale', 'restart'].includes(action.operation) ? 'danger' : ''} onClick={submitAction} disabled={actionBusy || (action.operation === 'edit' && !actionText)}>{actionBusy ? 'Working…' : action.operation === 'edit' ? 'Save changes' : action.operation === 'attach' ? 'Attach' : action.operation === 'scale' ? 'Scale' : action.operation === 'restart' ? 'Restart' : action.operation === 'evict' ? 'Evict' : 'Delete'}</button></div>
    </section></div>}
    {share && <div className="lens-modal-backdrop" onKeyDown={e => { if (e.key === 'Escape') setShare(null); keepDialogFocus(e) }}><section className="lens-modal" role="dialog" aria-modal="true" aria-labelledby="share-title"><h2 id="share-title">Share resource</h2><p>The recipient must sign in and connect to the same cluster. The link contains no credentials.</p>{share.link && <input className="lens-share-link" aria-label="Resource link" value={share.link} readOnly onFocus={e => e.target.select()} />}{share.message && <p role="status">{share.message}</p>}<div className="lens-modal-actions"><button autoFocus onClick={() => setShare(null)}>Close</button>{share.link && <button onClick={async () => { try { await navigator.clipboard.writeText(share.link); setShare({ ...share, message: 'Link copied.' }) } catch { setShare({ ...share, message: 'Clipboard unavailable; select and copy the link.' }) } }}>Copy link</button>}</div></section></div>}
  </div>
}
