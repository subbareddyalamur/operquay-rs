import { useEffect, useState, useCallback, type RefObject } from 'react';
import { RefreshCw, Terminal, Boxes, AlertTriangle, CheckCircle2, ArrowRight, Server } from 'lucide-react';
import { Button, Badge } from '@/components/primitives';
import { api } from '@/lib/api';
import { canSendCredentials } from '@/lib/credentialTransport';
import { hasPermission, useAuthStore } from '@/stores/auth';
import { useLayoutStore } from '@/stores/layout';

interface ConfiguredCluster {
  id?: string;
  label?: string;
  name?: string;
  proxy?: string;
  cluster_name?: string;
  method?: string;
  connector?: string;
  auth_type?: string;
}

interface StoredK8sConnection {
  id: string;
  info?: {
    name?: string;
    cluster_name?: string;
    source?: string;
    proxy?: string;
  };
}

interface K8sLiveStats {
  nodesReady: number;
  nodesTotal: number;
  podsRunning: number;
  podsPending: number;
  podsTotal: number;
  deploysReady: number;
  deploysTotal: number;
  cpuPct: number;
  memPct: number;
  podPct: number;
  cpuUsedLabel: string;
  memUsedLabel: string;
  events: Array<{ type: string; reason: string; object: string; message: string; age: string }>;
  samplePod?: { namespace: string; name: string };
}

type K8sSubView = 'overview' | 'catalog' | 'workloads';

const K8S_STORAGE_KEY = 'operquay:k8s:session';

function readStoredSession(): { connections: StoredK8sConnection[]; activeId: string | null } {
  try {
    const raw = JSON.parse(window.sessionStorage.getItem(K8S_STORAGE_KEY) || 'null') as {
      connections?: StoredK8sConnection[];
      activeCluster?: string | null;
    } | null;
    if (!raw || typeof raw !== 'object') return { connections: [], activeId: null };
    return {
      connections: Array.isArray(raw.connections) ? raw.connections : [],
      activeId: typeof raw.activeCluster === 'string' ? raw.activeCluster : null,
    };
  } catch {
    return { connections: [], activeId: null };
  }
}

function parseCpuMilli(val: unknown): number {
  if (typeof val !== 'string') return 0;
  if (val.endsWith('m')) return Number.parseFloat(val.slice(0, -1)) || 0;
  return (Number.parseFloat(val) || 0) * 1000;
}

function parseMemMiB(val: unknown): number {
  if (typeof val !== 'string') return 0;
  if (val.endsWith('Ki')) return (Number.parseFloat(val.slice(0, -2)) || 0) / 1024;
  if (val.endsWith('Mi')) return Number.parseFloat(val.slice(0, -2)) || 0;
  if (val.endsWith('Gi')) return (Number.parseFloat(val.slice(0, -2)) || 0) * 1024;
  if (val.endsWith('Ti')) return (Number.parseFloat(val.slice(0, -2)) || 0) * 1024 * 1024;
  return (Number.parseFloat(val) || 0) / (1024 * 1024);
}

export interface KubernetesWorkspaceProps {
  visible: boolean;
  iframeRef: RefObject<HTMLIFrameElement | null>;
  userId?: string;
  userAWS?: boolean;
  onFrameKeyDown?: (event: KeyboardEvent) => void;
}

export function KubernetesWorkspace({
  visible,
  iframeRef,
  userId,
  userAWS,
  onFrameKeyDown,
}: KubernetesWorkspaceProps) {
  const canManageClusters = useAuthStore((s) => hasPermission(s.me, 'k8s_clusters:manage'));
  const openSettings = useLayoutStore((s) => s.openSettings);
  const [subView, setSubView] = useState<K8sSubView>('overview');
  const [configuredClusters, setConfiguredClusters] = useState<ConfiguredCluster[]>([]);
  const [sessionState, setSessionState] = useState(() => readStoredSession());
  const [liveStats, setLiveStats] = useState<K8sLiveStats | null>(null);
  const [sampleLogs, setSampleLogs] = useState<string[]>([]);
  const [loadingStats, setLoadingStats] = useState(false);

  const activeConnection =
    sessionState.connections.find((c) => c.id === sessionState.activeId) ?? sessionState.connections[0] ?? null;

  const refreshConfigured = useCallback(async () => {
    setSessionState(readStoredSession());
    if (!canSendCredentials('/api/k8s/configured-clusters')) return;
    try {
      const res = await api.get<{ clusters?: ConfiguredCluster[] }>('/api/k8s/configured-clusters');
      if (res.ok && res.data && Array.isArray(res.data.clusters)) {
        setConfiguredClusters(res.data.clusters);
      } else if (res.ok && Array.isArray(res.data)) {
        setConfiguredClusters(res.data as unknown as ConfiguredCluster[]);
      }
    } catch {
      // Cluster catalog unavailable in standalone preview/tests
    }
  }, []);

  const refreshLiveMetrics = useCallback(async (clusterId: string) => {
    if (!canSendCredentials('/api/k8s/resources/nodes')) return;
    setLoadingStats(true);
    try {
      const [nodesRes, podsRes, deploysRes, eventsRes] = await Promise.all([
        fetch(`/api/k8s/resources/nodes?cluster=${encodeURIComponent(clusterId)}&group=&version=v1`),
        fetch(`/api/k8s/resources/pods?cluster=${encodeURIComponent(clusterId)}&group=&version=v1`),
        fetch(`/api/k8s/resources/deployments?cluster=${encodeURIComponent(clusterId)}&group=apps&version=v1`),
        fetch(`/api/k8s/resources/events?cluster=${encodeURIComponent(clusterId)}&group=&version=v1`),
      ]);
      const nodesJson = nodesRes.ok ? await nodesRes.json() : [];
      const podsJson = podsRes.ok ? await podsRes.json() : [];
      const deploysJson = deploysRes.ok ? await deploysRes.json() : [];
      const eventsJson = eventsRes.ok ? await eventsRes.json() : [];

      const parseItems = (raw: unknown): Array<Record<string, unknown>> => {
        if (Array.isArray(raw)) return raw as Array<Record<string, unknown>>;
        if (raw && typeof raw === 'object' && Array.isArray((raw as { items?: unknown[] }).items)) {
          return (raw as { items: Array<Record<string, unknown>> }).items;
        }
        return [];
      };

      const nodes = parseItems(nodesJson);
      const pods = parseItems(podsJson);
      const deploys = parseItems(deploysJson);
      const rawEvents = parseItems(eventsJson);

      const nodesReady = nodes.filter((n) => {
        const conds = ((n.status as { conditions?: Array<{ type: string; status: string }> })?.conditions) ?? [];
        return conds.some((c) => c.type === 'Ready' && c.status === 'True');
      }).length;

      let podsRunning = 0;
      let podsPending = 0;
      let reqCpuMilli = 0;
      let reqMemMiB = 0;
      let samplePod: { namespace: string; name: string } | undefined;

      for (const p of pods) {
        const status = p.status as { phase?: string } | undefined;
        const meta = p.metadata as { name?: string; namespace?: string } | undefined;
        if (status?.phase === 'Running') {
          podsRunning++;
          if (!samplePod && meta?.name && meta?.namespace) {
            samplePod = { namespace: meta.namespace, name: meta.name };
          }
        } else if (status?.phase === 'Pending') {
          podsPending++;
        }
        const containers = ((p.spec as { containers?: Array<{ resources?: { requests?: Record<string, string> } }> })?.containers) ?? [];
        for (const c of containers) {
          reqCpuMilli += parseCpuMilli(c.resources?.requests?.cpu);
          reqMemMiB += parseMemMiB(c.resources?.requests?.memory);
        }
      }

      let allocCpuMilli = 0;
      let allocMemMiB = 0;
      let allocPods = 0;
      for (const n of nodes) {
        const alloc = (n.status as { allocatable?: Record<string, string> })?.allocatable;
        allocCpuMilli += parseCpuMilli(alloc?.cpu);
        allocMemMiB += parseMemMiB(alloc?.memory);
        allocPods += Number.parseInt(alloc?.pods ?? '0', 10) || 0;
      }

      const deploysReady = deploys.filter((d) => {
        const specReplicas = (d.spec as { replicas?: number })?.replicas ?? 0;
        const readyReplicas = (d.status as { readyReplicas?: number })?.readyReplicas ?? 0;
        return specReplicas === 0 || readyReplicas >= specReplicas;
      }).length;

      const parsedEvents = rawEvents
        .slice(-12)
        .reverse()
        .map((ev) => {
          const obj = ev.involvedObject as { kind?: string; name?: string } | undefined;
          return {
            type: String(ev.type ?? 'Normal'),
            reason: String(ev.reason ?? 'Event'),
            object: obj ? `${(obj.kind ?? '').toLowerCase()}/${obj.name ?? ''}` : '',
            message: String(ev.message ?? ''),
            age: String(ev.lastTimestamp ?? ev.eventTime ?? 'recent').slice(11, 19) || 'recent',
          };
        });

      const cpuPct = allocCpuMilli > 0 ? Math.min(100, Math.round((reqCpuMilli / allocCpuMilli) * 100)) : 0;
      const memPct = allocMemMiB > 0 ? Math.min(100, Math.round((reqMemMiB / allocMemMiB) * 100)) : 0;
      const podPct = allocPods > 0 ? Math.min(100, Math.round((pods.length / allocPods) * 100)) : 0;

      setLiveStats({
        nodesReady,
        nodesTotal: nodes.length,
        podsRunning,
        podsPending,
        podsTotal: pods.length,
        deploysReady,
        deploysTotal: deploys.length,
        cpuPct,
        memPct,
        podPct,
        cpuUsedLabel: `${(reqCpuMilli / 1000).toFixed(1)} / ${(allocCpuMilli / 1000).toFixed(1)} vCPU (${cpuPct}%)`,
        memUsedLabel: `${Math.round(reqMemMiB / 1024)} / ${Math.round(allocMemMiB / 1024)} GiB (${memPct}%)`,
        events: parsedEvents,
        samplePod,
      });

      if (samplePod) {
        try {
          const logRes = await fetch(
            `/api/k8s/pods/${encodeURIComponent(samplePod.namespace)}/${encodeURIComponent(samplePod.name)}/logs?cluster=${encodeURIComponent(clusterId)}&tail=15`,
          );
          if (logRes.ok) {
            const text = await logRes.text();
            setSampleLogs(text.split('\n').filter(Boolean).slice(-6));
          }
        } catch {
          setSampleLogs([]);
        }
      }
    } catch {
      // Keep prior metrics or empty state if session expired
    } finally {
      setLoadingStats(false);
    }
  }, []);

  useEffect(() => {
    if (!visible) return;
    void refreshConfigured();
  }, [visible, refreshConfigured]);

  useEffect(() => {
    if (!visible || !activeConnection) {
      setLiveStats(null);
      return;
    }
    void refreshLiveMetrics(activeConnection.id);
  }, [visible, activeConnection, refreshLiveMetrics]);

  useEffect(() => {
    const onSelectCluster = (ev: Event) => {
      const cluster = (ev as CustomEvent<ConfiguredCluster>).detail;
      setSessionState(readStoredSession());
      setSubView('workloads');
      if (cluster) {
        iframeRef.current?.contentWindow?.postMessage(
          { type: 'operquay-select-kube-cluster', cluster },
          window.location.origin,
        );
        iframeRef.current?.contentWindow?.focus();
      }
    };
    const onNavigateK8s = (ev: Event) => {
      const item = (ev as CustomEvent<Record<string, unknown>>).detail;
      if (!item) return;
      if (item.name === '__overview') {
        setSubView('overview');
      } else {
        setSubView('workloads');
      }
      iframeRef.current?.contentWindow?.postMessage(
        { type: 'operquay-k8s-navigate', resource: item },
        window.location.origin,
      );
    };
    const onFrameMessage = (event: MessageEvent) => {
      if (event.origin === window.location.origin) {
        if (event.data?.type === 'operquay:k8s-session-changed') {
          const sessionPayload = event.data?.session as
            | { connections?: StoredK8sConnection[]; activeCluster?: string | null }
            | undefined;
          const nextSession = sessionPayload
            ? {
                connections: Array.isArray(sessionPayload.connections) ? sessionPayload.connections : [],
                activeId: typeof sessionPayload.activeCluster === 'string' ? sessionPayload.activeCluster : null,
              }
            : readStoredSession();
          setSessionState(nextSession);
          if (nextSession.activeId) {
            void refreshLiveMetrics(nextSession.activeId);
          }
          window.dispatchEvent(new CustomEvent('operquay:k8s-session-changed'));
        } else if (event.data?.type === 'operquay-k8s-active-changed') {
          window.dispatchEvent(new CustomEvent('operquay:k8s-active-changed', { detail: event.data }));
        }
      }
    };
    const onOpenDiscovery = () => {
      setSubView('workloads');
      iframeRef.current?.contentWindow?.postMessage(
        { type: 'operquay-open-discovery-hub' },
        window.location.origin,
      );
      iframeRef.current?.contentWindow?.focus();
    };
    const onMfaPasted = (ev: Event) => {
      if (!visible || subView !== 'workloads') return;
      const code = (ev as CustomEvent<string>).detail;
      if (code) {
        iframeRef.current?.contentWindow?.postMessage(
          { type: 'operquay-fill-mfa', code },
          window.location.origin,
        );
        iframeRef.current?.contentWindow?.focus();
      }
    };
    const onRefocusMfa = () => {
      if (visible && subView === 'workloads') {
        iframeRef.current?.contentWindow?.postMessage(
          { type: 'operquay-refocus-mfa' },
          window.location.origin,
        );
        iframeRef.current?.contentWindow?.focus();
      }
    };
    const onWindowFocus = () => {
      if (visible && subView === 'workloads') {
        iframeRef.current?.contentWindow?.postMessage(
          { type: 'operquay-refocus-mfa' },
          window.location.origin,
        );
      }
    };
    const onGlobalPaste = (e: ClipboardEvent) => {
      if (!visible || subView !== 'workloads') return;
      const text = (e.clipboardData?.getData('text') || e.clipboardData?.getData('text/plain') || '').trim().replace(/[\s-]/g, '');
      if (/^\d{6,10}$/.test(text)) {
        e.preventDefault();
        iframeRef.current?.contentWindow?.postMessage(
          { type: 'operquay-fill-mfa', code: text },
          window.location.origin,
        );
        iframeRef.current?.contentWindow?.focus();
      }
    };
    window.addEventListener('operquay:k8s-select-cluster', onSelectCluster);
    window.addEventListener('operquay:k8s-navigate', onNavigateK8s);
    window.addEventListener('operquay:k8s-open-discovery', onOpenDiscovery);
    window.addEventListener('operquay:k8s-mfa-pasted', onMfaPasted);
    window.addEventListener('operquay:k8s-check-refocus-mfa', onRefocusMfa);
    window.addEventListener('message', onFrameMessage);
    window.addEventListener('focus', onWindowFocus);
    window.addEventListener('paste', onGlobalPaste, true);
    return () => {
      window.removeEventListener('operquay:k8s-select-cluster', onSelectCluster);
      window.removeEventListener('operquay:k8s-navigate', onNavigateK8s);
      window.removeEventListener('operquay:k8s-open-discovery', onOpenDiscovery);
      window.removeEventListener('operquay:k8s-mfa-pasted', onMfaPasted);
      window.removeEventListener('operquay:k8s-check-refocus-mfa', onRefocusMfa);
      window.removeEventListener('message', onFrameMessage);
      window.removeEventListener('focus', onWindowFocus);
      window.removeEventListener('paste', onGlobalPaste, true);
    };
  }, [iframeRef, refreshLiveMetrics, visible, subView]);

  const warningEvents = (liveStats?.events ?? []).filter((e) => e.type === 'Warning');

  return (
    <div
      style={{ display: visible ? 'flex' : 'none' }}
      className="absolute inset-0 flex-col bg-bg overflow-hidden"
    >
      {/* Persistent Kubernetes header matching blueprint media_1794663663593_a120aaec.jpg */}
      <div className="px-5 py-2.5 border-b border-border bg-surface/60 flex flex-wrap items-center justify-between gap-3 shrink-0">
        <div className="flex flex-wrap items-center gap-3 min-w-0">
          <h1 className="text-[17px] font-semibold tracking-tight text-text-pri truncate">Kubernetes Workspace</h1>
          {activeConnection ? (
            <span
              title={`${activeConnection.info?.name || activeConnection.id} connected`}
              className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-medium bg-success/15 text-success border border-success/30 whitespace-nowrap max-w-[260px] truncate"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-success shrink-0" />
              <span className="truncate">{activeConnection.info?.name || activeConnection.id} connected</span>
            </span>
          ) : (
            <Badge variant="default" size="sm">
              {configuredClusters.length} cluster{configuredClusters.length === 1 ? '' : 's'} configured
            </Badge>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <div className="inline-flex items-center gap-0.5 p-0.5 rounded-lg bg-surface border border-border">
            <button
              type="button"
              onClick={() => setSubView('overview')}
              className={`px-3 py-1 rounded-md text-[12px] font-medium transition-colors whitespace-nowrap ${
                subView === 'overview'
                  ? 'bg-[var(--accent-dim)] text-accent border border-accent/30'
                  : 'text-text-mut hover:text-text-pri'
              }`}
            >
              Cluster Overview
            </button>
            <button
              type="button"
              onClick={() => setSubView('catalog')}
              className={`px-3 py-1 rounded-md text-[12px] font-medium transition-colors whitespace-nowrap ${
                subView === 'catalog'
                  ? 'bg-[var(--accent-dim)] text-accent border border-accent/30'
                  : 'text-text-mut hover:text-text-pri'
              }`}
            >
              Cluster Catalog
            </button>
            <button
              type="button"
              onClick={() => setSubView('workloads')}
              className={`px-3 py-1 rounded-md text-[12px] font-medium transition-colors whitespace-nowrap ${
                subView === 'workloads'
                  ? 'bg-[var(--accent-dim)] text-accent border border-accent/30'
                  : 'text-text-mut hover:text-text-pri'
              }`}
            >
              Live Workloads
            </button>
          </div>
          {activeConnection && subView !== 'workloads' && (
            <Button
              size="sm"
              variant="outline"
              icon={<RefreshCw size={13} className={loadingStats ? 'animate-spin' : ''} />}
              onClick={() => void refreshLiveMetrics(activeConnection.id)}
            >
              Refresh
            </Button>
          )}
        </div>
      </div>

      {/* Live Workloads iframe stays mounted so tests and Teleport/EKS sessions never lose state */}
      <iframe
        ref={iframeRef}
        key={userId ?? 'anonymous'}
        title="Kubernetes workspace"
        src="/k8s/"
        style={{ display: visible && subView === 'workloads' ? 'block' : 'none' }}
        className="w-full flex-1 border-0"
        onLoad={(e) => {
          if (userAWS && visible) {
            e.currentTarget.contentWindow?.postMessage({ type: 'operquay-refresh-aws-roles' }, window.location.origin);
          }
          e.currentTarget.contentDocument?.addEventListener(
            'keydown',
            (event) => onFrameKeyDown?.(event),
            true,
          );
        }}
      />

      {visible && subView !== 'workloads' && (
        <div className="flex-1 overflow-y-auto p-5 sm:p-6 space-y-5">
          {subView === 'overview' ? (
            <>
              {/* 4 KPI cards matching blueprint */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                <div className="rounded-xl border border-border bg-surface p-4">
                  <div className="text-[11px] font-medium text-text-mut">Nodes Ready</div>
                  <div className="text-[22px] font-bold text-success mt-1 tabular-nums">
                    {liveStats ? `${liveStats.nodesReady} / ${liveStats.nodesTotal}` : '— / —'}
                  </div>
                  <div className="text-[11px] text-text-dim mt-0.5">
                    {liveStats
                      ? liveStats.nodesReady === liveStats.nodesTotal
                        ? 'All healthy'
                        : `${liveStats.nodesTotal - liveStats.nodesReady} not ready`
                      : 'Connect a cluster to stream node health'}
                  </div>
                </div>

                <div className="rounded-xl border border-border bg-surface p-4">
                  <div className="text-[11px] font-medium text-text-mut">Running Pods</div>
                  <div className="text-[22px] font-bold text-accent mt-1 tabular-nums">
                    {liveStats ? `${liveStats.podsRunning} / ${liveStats.podsTotal}` : '— / —'}
                  </div>
                  <div className="text-[11px] text-text-dim mt-0.5">
                    {liveStats ? `${liveStats.podsPending} pending` : 'Live pod count unavailable offline'}
                  </div>
                </div>

                <div className="rounded-xl border border-border bg-surface p-4">
                  <div className="text-[11px] font-medium text-text-mut">Deployments</div>
                  <div className="text-[22px] font-bold text-warn mt-1 tabular-nums">
                    {liveStats ? `${liveStats.deploysReady} / ${liveStats.deploysTotal}` : '— / —'}
                  </div>
                  <div className="text-[11px] text-text-dim mt-0.5">
                    {liveStats
                      ? liveStats.deploysReady === liveStats.deploysTotal
                        ? 'All desired replicas ready'
                        : `${liveStats.deploysTotal - liveStats.deploysReady} degraded`
                      : 'Awaiting cluster session'}
                  </div>
                </div>

                <div className="rounded-xl border border-border bg-surface p-4">
                  <div className="text-[11px] font-medium text-text-mut">Events (15m)</div>
                  <div className={`text-[22px] font-bold mt-1 tabular-nums ${warningEvents.length > 0 ? 'text-danger' : 'text-text-pri'}`}>
                    {liveStats ? `${warningEvents.length} Warning${warningEvents.length === 1 ? '' : 's'}` : '0 Warnings'}
                  </div>
                  <div className="text-[11px] text-text-dim mt-0.5">
                    {warningEvents[0]?.reason ?? 'Cluster event stream nominal'}
                  </div>
                </div>
              </div>

              {/* 2-Column Allocation & Events Grid matching blueprint */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <div className="rounded-xl border border-border bg-surface p-4 space-y-3.5">
                  <h2 className="text-[13px] font-semibold text-text-pri">Cluster Resource Requests vs Allocatable</h2>
                  <div className="space-y-3 text-[12px]">
                    <div>
                      <div className="flex justify-between text-[11px] mb-1">
                        <span className="text-text-mut">CPU Allocation</span>
                        <span className="font-mono text-text-pri">{liveStats ? liveStats.cpuUsedLabel : 'Connect cluster to view'}</span>
                      </div>
                      <div className="h-2 rounded-full bg-elev overflow-hidden">
                        <div className="h-full bg-accent rounded-full transition-all" style={{ width: `${liveStats?.cpuPct ?? 0}%` }} />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-[11px] mb-1">
                        <span className="text-text-mut">Memory Allocation</span>
                        <span className="font-mono text-text-pri">{liveStats ? liveStats.memUsedLabel : 'Connect cluster to view'}</span>
                      </div>
                      <div className="h-2 rounded-full bg-elev overflow-hidden">
                        <div className="h-full bg-info rounded-full transition-all" style={{ width: `${liveStats?.memPct ?? 0}%` }} />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-[11px] mb-1">
                        <span className="text-text-mut">Pod Slots Used</span>
                        <span className="font-mono text-text-pri">
                          {liveStats ? `${liveStats.podsTotal} Pods (${liveStats.podPct}%)` : 'Connect cluster to view'}
                        </span>
                      </div>
                      <div className="h-2 rounded-full bg-elev overflow-hidden">
                        <div className="h-full bg-success rounded-full transition-all" style={{ width: `${liveStats?.podPct ?? 0}%` }} />
                      </div>
                    </div>
                  </div>
                </div>

                <div className="rounded-xl border border-border bg-surface p-4 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <h2 className="text-[13px] font-semibold text-text-pri">Live Warning Events</h2>
                    <button
                      type="button"
                      onClick={() => setSubView('workloads')}
                      className="text-[11px] text-accent hover:underline"
                    >
                      View all workloads →
                    </button>
                  </div>
                  {liveStats && liveStats.events.length > 0 ? (
                    <div className="space-y-2 max-h-[190px] overflow-y-auto pr-1">
                      {liveStats.events.slice(0, 4).map((ev, idx) => (
                        <div key={idx} className="p-2.5 rounded-lg bg-elev/60 border border-border text-[12px]">
                          <div className="flex items-center gap-2">
                            <span
                              className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ${
                                ev.type === 'Warning'
                                  ? 'bg-warn/15 text-warn border border-warn/30'
                                  : 'bg-surface text-text-mut border border-border'
                              }`}
                            >
                              {ev.type}
                            </span>
                            <span className="font-mono font-medium text-text-pri truncate">{ev.reason}</span>
                            {ev.object && <span className="text-text-dim font-mono text-[11px] truncate">· {ev.object}</span>}
                          </div>
                          <p className="text-[11px] text-text-mut mt-1 line-clamp-2">{ev.message}</p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-4 rounded-lg bg-elev/40 border border-border text-center space-y-2">
                      <CheckCircle2 size={18} className="mx-auto text-success" />
                      <p className="text-[12px] text-text-mut">
                        {activeConnection
                          ? 'No recent warning events reported in this cluster.'
                          : 'Connect to any Teleport or EKS cluster in Live Workloads to stream real-time cluster events.'}
                      </p>
                      <Button size="sm" variant="primary" icon={<ArrowRight size={12} />} onClick={() => setSubView('workloads')}>
                        Open Live Cluster Console
                      </Button>
                    </div>
                  )}
                </div>
              </div>

              {/* Pod Logs Console Strip matching blueprint */}
              <div className="rounded-xl border border-border bg-surface p-4 space-y-2.5">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 text-[12px] font-mono text-text-pri">
                    <Terminal size={13} className="text-accent" />
                    <span>
                      {liveStats?.samplePod
                        ? `Pod Logs · ${liveStats.samplePod.namespace}/${liveStats.samplePod.name}`
                        : 'Pod Logs · Live Stream'}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 text-[11px] text-accent">
                    <button type="button" onClick={() => setSubView('workloads')} className="hover:underline">
                      Open Exec Shell
                    </button>
                  </div>
                </div>
                <div className="rounded-lg bg-bg border border-border p-3 font-mono text-[11.5px] leading-relaxed text-text-sec space-y-0.5 overflow-x-auto">
                  {sampleLogs.length > 0 ? (
                    sampleLogs.map((line, i) => <div key={i}>{line}</div>)
                  ) : (
                    <div className="text-text-dim">
                      {activeConnection
                        ? 'No recent stdout log lines retrieved yet. Click "Open Exec Shell" to attach an interactive log stream.'
                        : 'Select a cluster from Resources → K8s or open Cluster Catalog / Live Workloads to connect via Teleport SSO or AWS IAM.'}
                    </div>
                  )}
                </div>
              </div>
            </>
          ) : (
            /* Cluster Catalog View */
            <div className="rounded-xl border border-border bg-surface overflow-hidden">
              <div className="px-4 py-3 border-b border-border flex items-center justify-between">
                <div>
                  <h2 className="text-[13px] font-semibold text-text-pri">Configured Kubernetes Clusters</h2>
                  <p className="text-[11px] text-text-mut">
                    Click Connect / Workloads to authenticate via Teleport SSO or inspect live pods and services.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="primary"
                    onClick={() => {
                      setSubView('workloads');
                      iframeRef.current?.contentWindow?.postMessage(
                        { type: 'operquay-open-discovery-hub' },
                        window.location.origin,
                      );
                    }}
                  >
                    + Discover & Onboard Clusters
                  </Button>
                  {canManageClusters && (
                    <Button size="sm" variant="outline" onClick={() => openSettings('kube-clusters')}>
                      Manage in Settings
                    </Button>
                  )}
                </div>
              </div>
              {configuredClusters.length === 0 ? (
                <div className="p-8 text-center space-y-3">
                  <Boxes size={24} className="mx-auto text-text-dim" />
                  <div className="text-[13px] font-medium text-text-pri">No Teleport Kubernetes clusters registered</div>
                  <p className="text-[12px] text-text-mut max-w-md mx-auto">
                    Add Teleport-backed clusters or use your connected AWS IAM roles directly inside the Live Workloads console.
                  </p>
                  <div className="flex items-center justify-center gap-2 pt-1">
                    <Button size="sm" variant="primary" onClick={() => setSubView('workloads')}>
                      Open Live Workloads
                    </Button>
                    {canManageClusters && (
                      <Button size="sm" variant="outline" onClick={() => openSettings('kube-clusters')}>
                        Add Cluster
                      </Button>
                    )}
                  </div>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse text-[12px]">
                    <thead>
                      <tr className="border-b border-border bg-elev/50 text-[11px] text-text-mut">
                        <th className="py-2 px-4 font-medium">Cluster</th>
                        <th className="py-2 px-4 font-medium">Proxy / Endpoint</th>
                        <th className="py-2 px-4 font-medium">Status</th>
                        <th className="py-2 px-4 font-medium text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border/60">
                      {configuredClusters.map((c) => {
                        const displayName = c.label || c.name || c.cluster_name || 'Cluster';
                        const isConn = sessionState.connections.some(
                          (sc) =>
                            sc.id === c.id ||
                            (c.cluster_name && sc.info?.name === c.cluster_name) ||
                            (c.label && sc.info?.name === c.label) ||
                            (c.name && sc.info?.name === c.name),
                        );
                        return (
                          <tr key={c.id || displayName} className="hover:bg-surface-hover/50">
                            <td className="py-2.5 px-4 font-medium text-text-pri whitespace-nowrap max-w-[260px]" title={displayName}>
                              <div className="flex items-center gap-2 min-w-0">
                                <Server size={13} className="text-accent shrink-0" />
                                <span className="truncate">{displayName}</span>
                              </div>
                            </td>
                            <td
                              className="py-2.5 px-4 font-mono text-[11px] text-text-mut whitespace-nowrap max-w-[320px] truncate"
                              title={c.proxy || c.cluster_name || 'Teleport Proxy'}
                            >
                              {c.proxy || c.cluster_name || 'Teleport Proxy'}
                            </td>
                            <td className="py-2.5 px-4">
                              {isConn ? (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-success/15 text-success text-[11px] font-medium">
                                  Connected
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-elev text-text-mut text-[11px]">
                                  <AlertTriangle size={10} /> Ready to authenticate
                                </span>
                              )}
                            </td>
                            <td className="py-2.5 px-4 text-right">
                              <Button
                                size="xs"
                                variant="primary"
                                onClick={() => {
                                  setSubView('workloads');
                                  iframeRef.current?.contentWindow?.postMessage(
                                    { type: 'operquay-select-kube-cluster', cluster: c },
                                    window.location.origin,
                                  );
                                }}
                              >
                                Open Workloads
                              </Button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

