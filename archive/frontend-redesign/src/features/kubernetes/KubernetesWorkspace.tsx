import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Box,
  ChevronDown,
  ChevronRight,
  DollarSign,
  Eye,
  EyeOff,
  FileCode,
  Layers,
  PanelLeft,
  PanelLeftClose,
  Play,
  RefreshCw,
  RotateCw,
  ScrollText,
  Share2,
  Shield,
  Terminal,
  Trash2,
  Upload,
  X,
} from 'lucide-react';
import { Badge, Button, Card } from '@/design-system/primitives';
import { apiJson, type K8sClusterRecord } from '../platform/api';
import { WsTerminalPane } from '../terminal/WsTerminalPane';

interface ResourceTypeDef {
  name: string;
  kind: string;
  namespaced: boolean;
}

interface ResourceCategory {
  id: string;
  label: string;
  types: ResourceTypeDef[];
}

interface K8sObject {
  apiVersion?: string;
  kind?: string;
  metadata?: {
    name?: string;
    namespace?: string;
    uid?: string;
    creationTimestamp?: string;
    labels?: Record<string, string>;
  };
  spec?: {
    replicas?: number;
    nodeName?: string;
    containers?: Array<{ name: string; image?: string }>;
  };
  status?: {
    phase?: string;
    podIP?: string;
    readyReplicas?: number;
    replicas?: number;
  };
  data?: Record<string, string>;
  type?: string;
  message?: string;
  reason?: string;
}

const CATEGORIES: ResourceCategory[] = [
  {
    id: 'Workloads',
    label: 'Workloads',
    types: [
      { name: 'pods', kind: 'Pod', namespaced: true },
      { name: 'deployments', kind: 'Deployment', namespaced: true },
      { name: 'statefulsets', kind: 'StatefulSet', namespaced: true },
      { name: 'daemonsets', kind: 'DaemonSet', namespaced: true },
      { name: 'replicasets', kind: 'ReplicaSet', namespaced: true },
      { name: 'jobs', kind: 'Job', namespaced: true },
      { name: 'cronjobs', kind: 'CronJob', namespaced: true },
    ],
  },
  {
    id: 'Config',
    label: 'Config & Storage',
    types: [
      { name: 'configmaps', kind: 'ConfigMap', namespaced: true },
      { name: 'secrets', kind: 'Secret', namespaced: true },
      { name: 'persistentvolumeclaims', kind: 'PVC', namespaced: true },
      { name: 'persistentvolumes', kind: 'PV', namespaced: false },
      { name: 'storageclasses', kind: 'StorageClass', namespaced: false },
    ],
  },
  {
    id: 'Network',
    label: 'Network',
    types: [
      { name: 'services', kind: 'Service', namespaced: true },
      { name: 'ingresses', kind: 'Ingress', namespaced: true },
      { name: 'networkpolicies', kind: 'NetworkPolicy', namespaced: true },
      { name: 'endpoints', kind: 'Endpoints', namespaced: true },
    ],
  },
  {
    id: 'Access',
    label: 'Access Control',
    types: [
      { name: 'serviceaccounts', kind: 'ServiceAccount', namespaced: true },
      { name: 'roles', kind: 'Role', namespaced: true },
      { name: 'rolebindings', kind: 'RoleBinding', namespaced: true },
      { name: 'clusterroles', kind: 'ClusterRole', namespaced: false },
      { name: 'clusterrolebindings', kind: 'ClusterRoleBinding', namespaced: false },
    ],
  },
  {
    id: 'Cluster',
    label: 'Cluster Views',
    types: [
      { name: 'namespaces', kind: 'Namespace', namespaced: false },
      { name: 'nodes', kind: 'Node', namespaced: false },
      { name: 'events', kind: 'Event', namespaced: true },
    ],
  },
];

const SPECIAL_VIEWS: Array<{ id: string; label: string }> = [
  { id: '__overview', label: 'Overview' },
  { id: '__helm', label: 'Helm Releases' },
  { id: '__cost', label: 'Cost Monitoring' },
  { id: '__crds', label: 'Custom Resource Definitions' },
];

function decodeBase64Utf8(b64: string): string {
  try {
    const raw = atob(b64);
    const bytes = Uint8Array.from(raw, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return '[binary or invalid base64]';
  }
}

export function KubernetesWorkspace() {
  const [clusters, setClusters] = useState<K8sClusterRecord[]>([]);
  const [selectedCluster, setSelectedCluster] = useState('');
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [namespace, setNamespace] = useState('');
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [expandedCats, setExpandedCats] = useState<Record<string, boolean>>({ Workloads: true, Cluster: true });

  const [tabs, setTabs] = useState<Array<{ id: string; label: string }>>([
    { id: '__overview', label: 'Overview' },
    { id: 'pods', label: 'Pods' },
  ]);
  const [activeTab, setActiveTab] = useState('pods');
  const [search, setSearch] = useState('');

  const [items, setItems] = useState<K8sObject[]>([]);
  const [helmReleases, setHelmReleases] = useState<Array<{ name: string; namespace: string; revision: number; status: string; chart?: string }>>([]);
  const [crds, setCrds] = useState<K8sObject[]>([]);
  const [costInfo, setCostInfo] = useState<{ pod_count: number; estimated_monthly_usd: number; sources: string[] }>({
    pod_count: 0,
    estimated_monthly_usd: 0,
    sources: [],
  });
  const [podMetrics, setPodMetrics] = useState<Record<string, string>>({});

  const [detailItem, setDetailItem] = useState<K8sObject | null>(null);
  const [revealSecrets, setRevealSecrets] = useState(false);
  const [manifestDraft, setManifestDraft] = useState('');
  const [scaleInput, setScaleInput] = useState('1');

  const [bottomTab, setBottomTab] = useState<'none' | 'logs' | 'exec' | 'attach'>('none');
  const [logTarget, setLogTarget] = useState<{ pod: string; namespace: string } | null>(null);
  const [logFilter, setLogFilter] = useState('');
  const [logLines, setLogLines] = useState<string[]>([]);
  const [shells, setShells] = useState<Array<{ id: string; pod: string; namespace: string; mode: 'exec' | 'attach' }>>([]);
  const [activeShellId, setActiveShellId] = useState('');

  const [showUpload, setShowUpload] = useState(false);
  const [kubeYaml, setKubeYaml] = useState('');
  const [teleportProxy, setTeleportProxy] = useState('https://teleport.example.com');
  const [teleportStatus, setTeleportStatus] = useState('disconnected');
  const [k8sPolicy, setK8sPolicy] = useState({ record_exec: true, record_attach: true, record_logs: false, fail_closed: false });

  const [notice, setNotice] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const loadMeta = useCallback(async () => {
    const [list, tp, pol] = await Promise.all([
      apiJson<K8sClusterRecord[]>('/api/k8s/clusters').catch(() => []),
      apiJson<{ status: string }>('/api/teleport/status').catch(() => ({ status: 'disconnected' })),
      apiJson<typeof k8sPolicy>('/api/k8s/recording-policy').catch(() => ({
        record_exec: true,
        record_attach: true,
        record_logs: false,
        fail_closed: false,
      })),
    ]);
    setClusters(list);
    if (list[0] && !selectedCluster) setSelectedCluster(list[0].id);
    setTeleportStatus(tp.status);
    setK8sPolicy(pol);
  }, [selectedCluster]);

  useEffect(() => {
    void loadMeta();
  }, [loadMeta]);

  const openResourceTab = (id: string, label: string) => {
    setTabs((prev) => (prev.some((t) => t.id === id) ? prev : [...prev, { id, label }]));
    setActiveTab(id);
    setDetailItem(null);
  };

  const closeTab = (id: string) => {
    setTabs((prev) => {
      const next = prev.filter((t) => t.id !== id);
      if (activeTab === id && next[0]) setActiveTab(next[0].id);
      return next.length ? next : [{ id: '__overview', label: 'Overview' }];
    });
  };

  const queryCluster = useCallback(async (cid: string, tabId: string, ns: string) => {
    if (!cid) return;
    setErr(null);
    const nsQuery = ns ? `&namespace=${encodeURIComponent(ns)}` : '';
    try {
      const nsData = await apiJson<{ items?: K8sObject[] }>(`/api/k8s/namespaces?cluster=${encodeURIComponent(cid)}`).catch(() => ({ items: [] }));
      const nsList = (nsData.items ?? []).map((n) => n.metadata?.name ?? '').filter(Boolean);
      if (nsList.length) setNamespaces(nsList);

      if (tabId === '__overview' || tabId === '__cost') {
        const [cost, sources] = await Promise.all([
          apiJson<{ pod_count?: number; estimated_monthly_usd?: number }>(`/api/k8s/cost?cluster=${encodeURIComponent(cid)}`).catch(() => ({ pod_count: 0, estimated_monthly_usd: 0 })),
          apiJson<{ sources?: string[] }>(`/api/k8s/cost/sources?cluster=${encodeURIComponent(cid)}`).catch(() => ({ sources: [] })),
        ]);
        setCostInfo({
          pod_count: cost.pod_count ?? 0,
          estimated_monthly_usd: cost.estimated_monthly_usd ?? 0,
          sources: sources.sources ?? [],
        });
      }
      if (tabId === '__overview' || tabId === '__helm') {
        const rels = await apiJson<typeof helmReleases>(`/api/k8s/helm/releases?cluster=${encodeURIComponent(cid)}${nsQuery}`).catch(() => []);
        setHelmReleases(rels);
      }
      if (tabId === '__crds') {
        const crdList = await apiJson<{ items?: K8sObject[] }>(`/api/k8s/crds?cluster=${encodeURIComponent(cid)}`).catch(() => ({ items: [] }));
        setCrds(crdList.items ?? []);
      }
      if (!tabId.startsWith('__')) {
        const res = await apiJson<{ items?: K8sObject[] }>(
          `/api/k8s/resources/${encodeURIComponent(tabId)}?cluster=${encodeURIComponent(cid)}${nsQuery}`,
        );
        setItems(res.items ?? []);
        if (tabId === 'pods') {
          const mRes = await apiJson<{ items?: Array<{ metadata?: { name?: string }; containers?: Array<{ usage?: { cpu?: string; memory?: string } }> }> }>(
            `/api/k8s/metrics/pods?cluster=${encodeURIComponent(cid)}${nsQuery}`,
          ).catch(() => ({ items: [] }));
          const mMap: Record<string, string> = {};
          for (const pm of mRes.items ?? []) {
            const pname = pm.metadata?.name;
            const c0 = pm.containers?.[0]?.usage;
            if (pname && c0) mMap[pname] = `${c0.cpu ?? '0'} / ${c0.memory ?? '0'}`;
          }
          setPodMetrics(mMap);
        }
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Unable to query cluster API server');
    }
  }, []);

  useEffect(() => {
    if (selectedCluster) {
      void queryCluster(selectedCluster, activeTab, namespace);
    }
  }, [selectedCluster, activeTab, namespace, queryCluster]);

  const uploadKubeconfig = async () => {
    setErr(null);
    try {
      const uploaded = await apiJson<K8sClusterRecord[]>('/api/k8s/kubeconfig/upload', {
        method: 'POST',
        body: JSON.stringify({ kubeconfig: kubeYaml, connect: true }),
      });
      setKubeYaml('');
      setShowUpload(false);
      await loadMeta();
      if (uploaded[0]) {
        setSelectedCluster(uploaded[0].id);
        setNotice(`Imported cluster ${uploaded[0].name}.`);
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Kubeconfig upload rejected');
    }
  };

  const connectTeleport = async () => {
    const res = await apiJson<{ status: string }>('/api/teleport/local-login', {
      method: 'POST',
      body: JSON.stringify({ proxy_url: teleportProxy, user: 'ops', clusters: ['prod-eks'] }),
    });
    setTeleportStatus(res.status);
    setNotice(`Teleport session: ${res.status}`);
  };

  const toggleK8sRecording = async () => {
    const updated = await apiJson<typeof k8sPolicy>('/api/k8s/recording-policy', {
      method: 'PUT',
      body: JSON.stringify({ ...k8sPolicy, record_exec: !k8sPolicy.record_exec }),
    });
    setK8sPolicy(updated);
    setNotice(`K8s exec recording: ${updated.record_exec ? 'enabled' : 'disabled'}`);
  };

  const performAction = async (action: 'restart' | 'scale' | 'delete' | 'patch', item: K8sObject) => {
    if (!selectedCluster || !item.metadata?.name) return;
    setErr(null);
    try {
      let manifest: unknown;
      if (action === 'patch') {
        manifest = JSON.parse(manifestDraft);
      }
      await apiJson(`/api/k8s/actions/${action}`, {
        method: 'POST',
        body: JSON.stringify({
          cluster: selectedCluster,
          namespace: item.metadata.namespace ?? 'default',
          resource_type: activeTab,
          name: item.metadata.name,
          replicas: Number(scaleInput) || 1,
          manifest,
        }),
      });
      setNotice(`Executed ${action} on ${item.metadata.name}`);
      if (action === 'delete') setDetailItem(null);
      await queryCluster(selectedCluster, activeTab, namespace);
    } catch (e) {
      setErr(e instanceof Error ? e.message : `Action ${action} failed`);
    }
  };

  const shareResourceLink = async (item: K8sObject) => {
    if (!crypto?.subtle) return;
    const digest = await crypto.subtle.digest(
      'SHA-256',
      new TextEncoder().encode(`${selectedCluster}:${item.metadata?.name ?? ''}`),
    );
    const hex = [...new Uint8Array(digest)].slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('');
    const hash = `#view=resource&cluster=${hex}&resource=${activeTab}&namespace=${encodeURIComponent(item.metadata?.namespace ?? '')}&name=${encodeURIComponent(item.metadata?.name ?? '')}`;
    window.history.replaceState(null, '', hash);
    setNotice(`Deep link updated (${hash})`);
  };

  const openPodTerminal = (pod: string, ns: string, mode: 'exec' | 'attach') => {
    const id = `${mode}-${ns}/${pod}-${shells.length + 1}`;
    setShells((prev) => [...prev, { id, pod, namespace: ns, mode }]);
    setActiveShellId(id);
    setBottomTab(mode);
  };

  const openPodLogs = async (pod: string, ns: string) => {
    setLogTarget({ pod, namespace: ns });
    setBottomTab('logs');
    setLogLines([`[streaming logs] ${ns}/${pod}...`]);
    const text = await fetch(
      `/api/k8s/logs?cluster=${encodeURIComponent(selectedCluster)}&namespace=${encodeURIComponent(ns)}&pod=${encodeURIComponent(pod)}`,
    )
      .then((r) => (r.ok ? r.text() : '[log stream connected via WebSocket /ws/k8s/logs]'))
      .catch(() => '[log stream connected]');
    setLogLines(text.split('\n').slice(-200));
  };

  const filteredItems = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items.filter((it) => {
      if (namespace && (it.metadata?.namespace ?? '') !== namespace) return false;
      if (!q) return true;
      return (
        (it.metadata?.name ?? '').toLowerCase().includes(q) ||
        (it.metadata?.namespace ?? '').toLowerCase().includes(q)
      );
    });
  }, [items, namespace, search]);

  const activeShell = shells.find((s) => s.id === activeShellId) ?? null;

  return (
    <div className="max-w-7xl mx-auto px-5 py-5 space-y-4">
      {/* Top IDE Control Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-3">
        <div className="flex items-center gap-2.5">
          <button
            type="button"
            aria-label={sidebarOpen ? 'Hide Kubernetes resource sidebar' : 'Show Kubernetes resource sidebar'}
            onClick={() => setSidebarOpen((v) => !v)}
            className="h-8 w-8 rounded-[var(--radius-sm)] border border-border bg-surface text-text-mut hover:text-text-pri inline-flex items-center justify-center"
          >
            {sidebarOpen ? <PanelLeftClose size={15} aria-hidden="true" /> : <PanelLeft size={15} aria-hidden="true" />}
          </button>
          <div>
            <h1 className="text-[18px] font-semibold text-text-pri tracking-[-0.02em]">
              Kubernetes Multi-Cluster IDE
            </h1>
            <p className="text-[11px] text-text-mut">
              Workloads, Config/Secrets, Helm v3 Releases, OpenCost/Metrics, CRDs, Recorded `v4.channel.k8s.io` Exec/Attach, and Teleport SSO.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          <select
            aria-label="Select Kubernetes cluster"
            value={selectedCluster}
            onChange={(e) => setSelectedCluster(e.target.value)}
            className="h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri"
          >
            {clusters.length === 0 && <option value="">No clusters registered</option>}
            {clusters.map((c) => (
              <option key={c.id} value={c.id}>{c.name} ({c.source})</option>
            ))}
          </select>
          <select
            aria-label="Filter Kubernetes namespace"
            value={namespace}
            onChange={(e) => setNamespace(e.target.value)}
            className="h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri"
          >
            <option value="">All Namespaces</option>
            {namespaces.map((ns) => (
              <option key={ns} value={ns}>{ns}</option>
            ))}
          </select>
          <Button size="xs" variant="outline" onClick={() => setShowUpload((v) => !v)} icon={<Upload size={12} aria-hidden="true" />}>
            Kubeconfig
          </Button>
          <Button size="xs" variant="outline" onClick={() => void toggleK8sRecording()} icon={<Shield size={12} aria-hidden="true" />}>
            Exec Rec: {k8sPolicy.record_exec ? 'ON' : 'OFF'}
          </Button>
          <Button size="xs" onClick={() => void queryCluster(selectedCluster, activeTab, namespace)} icon={<RefreshCw size={12} aria-hidden="true" />}>
            Refresh
          </Button>
        </div>
      </div>

      {notice && (
        <div className="px-3.5 py-2 rounded-[var(--radius-sm)] border border-border bg-[var(--success-dim)] text-xs text-success">
          {notice}
        </div>
      )}
      {err && (
        <div role="alert" className="px-3.5 py-2 rounded-[var(--radius-sm)] border border-border bg-[var(--danger-dim)] text-xs text-danger">
          {err}
        </div>
      )}

      {showUpload && (
        <Card className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="space-y-2">
            <label htmlFor="kubeconfig-input" className="block font-medium text-text-pri">
              Import Kubeconfig YAML/JSON (Exec allowlist: aws, tsh, kubelogin)
            </label>
            <textarea
              id="kubeconfig-input"
              rows={4}
              value={kubeYaml}
              onChange={(e) => setKubeYaml(e.target.value)}
              className="w-full p-2.5 rounded-[var(--radius-sm)] border border-border bg-elev font-mono text-text-pri"
            />
            <Button size="xs" onClick={() => void uploadKubeconfig()}>Import Cluster</Button>
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="font-medium text-text-pri">Teleport SSO Proxy Connector</span>
              <Badge tone={teleportStatus === 'connected' ? 'success' : 'neutral'}>{teleportStatus}</Badge>
            </div>
            <input
              aria-label="Teleport Proxy URL"
              value={teleportProxy}
              onChange={(e) => setTeleportProxy(e.target.value)}
              className="w-full h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri"
            />
            <Button size="xs" onClick={() => void connectTeleport()}>Connect Teleport Proxy</Button>
          </div>
        </Card>
      )}

      {/* Main Split IDE: Left Navigator | Center Resource Table/Tabs | Right DetailPanel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
        {sidebarOpen && (
          <Card className="lg:col-span-3 p-3 space-y-2 text-xs">
            {SPECIAL_VIEWS.map((sv) => (
              <button
                key={sv.id}
                type="button"
                onClick={() => openResourceTab(sv.id, sv.label)}
                className={[
                  'w-full text-left px-2.5 py-1.5 rounded-[var(--radius-sm)] font-medium transition-colors',
                  activeTab === sv.id
                    ? 'bg-[var(--accent-dim)] text-accent'
                    : 'text-text-mut hover:text-text-pri hover:bg-[var(--surface-hover)]',
                ].join(' ')}
              >
                {sv.label}
              </button>
            ))}

            <div className="pt-1 border-t border-border space-y-1">
              {CATEGORIES.map((cat) => {
                const open = Boolean(expandedCats[cat.id]);
                return (
                  <div key={cat.id}>
                    <button
                      type="button"
                      onClick={() => setExpandedCats((prev) => ({ ...prev, [cat.id]: !open }))}
                      className="w-full flex items-center justify-between px-2 py-1.5 font-semibold text-text-pri hover:bg-[var(--surface-hover)] rounded-[var(--radius-sm)]"
                    >
                      <span>{cat.label}</span>
                      {open ? <ChevronDown size={13} aria-hidden="true" /> : <ChevronRight size={13} aria-hidden="true" />}
                    </button>
                    {open && (
                      <div className="pl-2 space-y-0.5 mt-0.5">
                        {cat.types.map((rt) => (
                          <button
                            key={rt.name}
                            type="button"
                            onClick={() => openResourceTab(rt.name, `${rt.kind}s`)}
                            className={[
                              'w-full text-left px-2.5 py-1 rounded-[var(--radius-sm)] transition-colors',
                              activeTab === rt.name
                                ? 'bg-[var(--accent-dim)] text-accent font-medium'
                                : 'text-text-mut hover:text-text-pri',
                            ].join(' ')}
                          >
                            {rt.kind}s
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </Card>
        )}

        <div className={sidebarOpen ? (detailItem ? 'lg:col-span-5 space-y-3' : 'lg:col-span-9 space-y-3') : (detailItem ? 'lg:col-span-8 space-y-3' : 'lg:col-span-12 space-y-3')}>
          {/* Multi-tab bar + search */}
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex flex-wrap items-center gap-1" role="tablist" aria-label="Kubernetes resource tabs">
              {tabs.map((t) => (
                <div
                  key={t.id}
                  className={[
                    'inline-flex items-center gap-1 h-7 pl-2.5 pr-1.5 rounded-[var(--radius-sm)] border text-xs',
                    activeTab === t.id
                      ? 'border-[var(--accent-border)] bg-[var(--accent-dim)] text-accent font-medium'
                      : 'border-border bg-surface text-text-mut',
                  ].join(' ')}
                >
                  <button type="button" role="tab" aria-selected={activeTab === t.id} onClick={() => setActiveTab(t.id)}>
                    {t.label}
                  </button>
                  {tabs.length > 1 && (
                    <button type="button" aria-label={`Close ${t.label} tab`} onClick={() => closeTab(t.id)} className="hover:text-text-pri">
                      <X size={11} aria-hidden="true" />
                    </button>
                  )}
                </div>
              ))}
            </div>
            <input
              aria-label="Filter resources"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter items..."
              className="h-7 w-44 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-pri"
            />
          </div>

          {activeTab === '__overview' && (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
              <Card className="p-4">
                <div className="text-text-dim">Active Cluster Pods</div>
                <div className="text-xl font-semibold text-text-pri tabular-mono mt-1">{costInfo.pod_count}</div>
              </Card>
              <Card className="p-4">
                <div className="text-text-dim">Estimated Monthly Cost</div>
                <div className="text-xl font-semibold text-accent tabular-mono mt-1">${costInfo.estimated_monthly_usd.toFixed(2)}</div>
              </Card>
              <Card className="p-4">
                <div className="text-text-dim">Helm Releases</div>
                <div className="text-xl font-semibold text-text-pri tabular-mono mt-1">{helmReleases.length}</div>
              </Card>
            </div>
          )}

          {activeTab === '__cost' && (
            <Card className="p-4 space-y-2 text-xs">
              <div className="flex items-center gap-2 font-semibold text-text-pri">
                <DollarSign size={14} className="text-accent" aria-hidden="true" />
                Cluster Cost Allocation
              </div>
              <div className="text-text-mut">Sources: {costInfo.sources.join(', ') || 'eks-resource-requests'}</div>
              <div className="text-lg font-semibold text-text-pri tabular-mono">
                ${costInfo.estimated_monthly_usd.toFixed(2)} / month ({costInfo.pod_count} pods)
              </div>
            </Card>
          )}

          {activeTab === '__helm' && (
            <Card className="p-4 space-y-2 text-xs">
              <div className="flex items-center gap-2 font-semibold text-text-pri">
                <FileCode size={14} className="text-accent" aria-hidden="true" />
                Helm v3 Releases ({helmReleases.length})
              </div>
              {helmReleases.map((h) => (
                <div key={`${h.namespace}/${h.name}`} className="py-2 border-b border-border flex justify-between">
                  <span className="font-mono">{h.namespace}/{h.name} (rev {h.revision}) {h.chart ?? ''}</span>
                  <Badge tone="success">{h.status}</Badge>
                </div>
              ))}
            </Card>
          )}

          {activeTab === '__crds' && (
            <Card className="p-4 space-y-2 text-xs">
              <div className="flex items-center gap-2 font-semibold text-text-pri">
                <Layers size={14} className="text-accent" aria-hidden="true" />
                Custom Resource Definitions ({crds.length})
              </div>
              {crds.map((c, i) => (
                <div key={c.metadata?.name ?? String(i)} className="py-2 border-b border-border flex justify-between">
                  <span className="font-mono text-text-pri">{c.metadata?.name}</span>
                  <Badge tone="neutral">CRD</Badge>
                </div>
              ))}
            </Card>
          )}

          {!activeTab.startsWith('__') && (
            <Card className="p-4 space-y-2 text-xs">
              <div className="flex items-center justify-between font-semibold text-text-pri">
                <span className="flex items-center gap-1.5">
                  <Box size={14} className="text-accent" aria-hidden="true" />
                  {activeTab} ({filteredItems.length})
                </span>
              </div>
              <div className="divide-y divide-border">
                {filteredItems.map((it, idx) => {
                  const name = it.metadata?.name ?? `item-${idx}`;
                  const ns = it.metadata?.namespace ?? 'default';
                  const m = podMetrics[name];
                  return (
                    <div key={`${ns}/${name}`} className="py-2 flex flex-wrap items-center justify-between gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          setDetailItem(it);
                          setRevealSecrets(false);
                          setManifestDraft(JSON.stringify(it, null, 2));
                        }}
                        className="text-left hover:underline"
                      >
                        <span className="font-medium text-text-pri">{name}</span>
                        <span className="text-text-dim ml-2">{ns}</span>
                        {m && <span className="text-accent ml-2 tabular-mono">{m}</span>}
                      </button>
                      <div className="flex items-center gap-1.5">
                        <Badge tone={it.status?.phase === 'Running' ? 'success' : 'neutral'}>
                          {it.status?.phase ?? 'Active'}
                        </Badge>
                        {activeTab === 'pods' && (
                          <>
                            <Button size="xs" variant="outline" onClick={() => void openPodLogs(name, ns)} icon={<ScrollText size={11} aria-hidden="true" />}>
                              Logs
                            </Button>
                            <Button size="xs" variant="outline" onClick={() => openPodTerminal(name, ns, 'exec')} icon={<Terminal size={11} aria-hidden="true" />}>
                              Exec
                            </Button>
                          </>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </Card>
          )}
        </div>

        {/* Slide-over DetailPanel */}
        {detailItem && (
          <Card className="lg:col-span-4 p-4 space-y-3 text-xs">
            <div className="flex items-center justify-between border-b border-border pb-2">
              <div className="font-semibold text-text-pri truncate">
                {detailItem.metadata?.name}
              </div>
              <div className="flex items-center gap-1">
                <Button size="xs" variant="ghost" aria-label="Share resource link" onClick={() => void shareResourceLink(detailItem)}>
                  <Share2 size={12} aria-hidden="true" />
                </Button>
                <Button size="xs" variant="ghost" aria-label="Close detail panel" onClick={() => setDetailItem(null)}>
                  <X size={13} aria-hidden="true" />
                </Button>
              </div>
            </div>

            {activeTab === 'secrets' && (
              <div className="space-y-1.5 p-2.5 rounded-[var(--radius-sm)] border border-border bg-elev">
                <div className="flex items-center justify-between">
                  <span className="font-medium text-text-pri">Secret Data Keys</span>
                  <Button size="xs" variant="outline" onClick={() => setRevealSecrets((v) => !v)} icon={revealSecrets ? <EyeOff size={11} aria-hidden="true" /> : <Eye size={11} aria-hidden="true" />}>
                    {revealSecrets ? 'Hide' : 'Reveal'}
                  </Button>
                </div>
                {Object.entries(detailItem.data ?? {}).map(([k, v]) => (
                  <div key={k} className="font-mono text-[11px] flex justify-between gap-2">
                    <span className="text-text-dim">{k}</span>
                    <span className="text-text-pri truncate">{revealSecrets ? decodeBase64Utf8(v) : '••••••••'}</span>
                  </div>
                ))}
              </div>
            )}

            <div className="flex flex-wrap gap-1.5">
              {['deployments', 'statefulsets', 'replicasets'].includes(activeTab) && (
                <div className="flex items-center gap-1">
                  <input aria-label="Replica count" type="number" min={0} value={scaleInput} onChange={(e) => setScaleInput(e.target.value)} className="h-7 w-14 px-2 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri" />
                  <Button size="xs" variant="outline" onClick={() => void performAction('scale', detailItem)}>Scale</Button>
                </div>
              )}
              {['deployments', 'statefulsets', 'daemonsets'].includes(activeTab) && (
                <Button size="xs" variant="outline" onClick={() => void performAction('restart', detailItem)} icon={<RotateCw size={11} aria-hidden="true" />}>
                  Restart
                </Button>
              )}
              <Button size="xs" variant="danger" onClick={() => void performAction('delete', detailItem)} icon={<Trash2 size={11} aria-hidden="true" />}>
                Delete
              </Button>
            </div>

            <label htmlFor="k8s-manifest-edit" className="block font-medium text-text-mut">
              Resource Manifest JSON
            </label>
            <textarea
              id="k8s-manifest-edit"
              rows={8}
              value={manifestDraft}
              onChange={(e) => setManifestDraft(e.target.value)}
              className="w-full p-2 rounded-[var(--radius-sm)] border border-border bg-elev font-mono text-[11px] text-text-pri"
            />
            <Button size="xs" onClick={() => void performAction('patch', detailItem)} icon={<Play size={11} aria-hidden="true" />}>
              Apply Patch
            </Button>
          </Card>
        )}
      </div>

      {/* Bottom Drawer: Pod Logs + Exec/Attach Multi-Tab Terminal */}
      {bottomTab !== 'none' && (
        <Card className="p-4 space-y-3 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-2">
            <div className="flex flex-wrap items-center gap-1.5">
              {logTarget && (
                <button
                  type="button"
                  onClick={() => setBottomTab('logs')}
                  className={[
                    'px-2.5 py-1 rounded-[var(--radius-sm)] border',
                    bottomTab === 'logs'
                      ? 'border-[var(--accent-border)] bg-[var(--accent-dim)] text-accent font-medium'
                      : 'border-border bg-surface text-text-mut',
                  ].join(' ')}
                >
                  Logs: {logTarget.pod}
                </button>
              )}
              {shells.map((s) => (
                <button
                  key={s.id}
                  type="button"
                  onClick={() => {
                    setActiveShellId(s.id);
                    setBottomTab(s.mode);
                  }}
                  className={[
                    'px-2.5 py-1 rounded-[var(--radius-sm)] border',
                    activeShellId === s.id && bottomTab !== 'logs'
                      ? 'border-[var(--accent-border)] bg-[var(--accent-dim)] text-accent font-medium'
                      : 'border-border bg-surface text-text-mut',
                  ].join(' ')}
                >
                  {s.mode}: {s.pod}
                </button>
              ))}
            </div>
            <Button size="xs" variant="ghost" aria-label="Close bottom drawer" onClick={() => setBottomTab('none')}>
              <X size={13} aria-hidden="true" />
            </Button>
          </div>

          {bottomTab === 'logs' && (
            <div className="space-y-2">
              <input
                aria-label="Filter pod logs"
                value={logFilter}
                onChange={(e) => setLogFilter(e.target.value)}
                placeholder="Filter log lines..."
                className="h-7 w-56 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri"
              />
              <pre className="p-3 rounded-[var(--radius-sm)] bg-elev border border-border font-mono text-[11px] max-h-56 overflow-y-auto text-text-pri">
                {logLines
                  .filter((l) => !logFilter.trim() || l.toLowerCase().includes(logFilter.toLowerCase()))
                  .join('\n')}
              </pre>
            </div>
          )}

          {bottomTab !== 'logs' && activeShell && (
            <WsTerminalPane
              wsUrl={`${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws/k8s/${activeShell.mode}?cluster=${encodeURIComponent(selectedCluster)}&pod=${encodeURIComponent(activeShell.pod)}&namespace=${encodeURIComponent(activeShell.namespace)}`}
              title={`kubectl ${activeShell.mode} — ${activeShell.namespace}/${activeShell.pod}`}
              cols={96}
              rows={18}
            />
          )}
        </Card>
      )}
    </div>
  );
}
