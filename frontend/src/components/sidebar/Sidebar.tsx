import { useEffect, useMemo, useRef, useState } from 'react';
import { Search, Loader, ChevronsDownUp, ChevronsUpDown, ChevronDown, ChevronRight, ChevronLeft, X, Plus, Database, Cloud } from 'lucide-react';
import { useInstancesStore } from '@/stores/instances';
import { getFilteredAccounts } from '@/lib/filter';
import { Menu, type MenuSection } from '@/components/primitives/Menu';
import { useLayoutStore } from '@/stores/layout';
import { useSettingsStore } from '@/stores/settings';
import { api } from '@/lib/api';
import { canSendCredentials } from '@/lib/credentialTransport';
import type { AccountNode } from '@/lib/types';
import { connectCloud } from '@/lib/connectCloud';
import { Button } from '@/components/primitives/Button';
import { FavoritesPanel } from './FavoritesPanel';
import { AccountGroup } from './AccountGroup';
import { InstanceContextMenu } from './InstanceContextMenu';
import { useAuthStore, hasPermission } from '@/stores/auth';
import { cloudKey, cloudNames, CloudMark } from './CloudMark';

interface DrawerCluster {
  id?: string;
  label?: string;
  name?: string;
  proxy?: string;
  cluster_name?: string;
  method?: string;
  connector?: string;
  auth_type?: string;
  source?: string;
}

import { DatabaseTree, ENGINE_META, type DbConnection } from '@/components/databases/DatabaseTree';
import { KubeNavTree, type KubeNavItem } from '@/components/kubernetes/KubeNavTree';

interface ConnectedK8sSession {
  id: string;
  info?: {
    name?: string;
    cluster_name?: string;
    proxy?: string;
    source?: string;
  };
}

const DB_CUSTOM_STORAGE_KEY = 'operquay.db.customConnections.v1';

function getClusterKey(c: DrawerCluster): string {
  return c.id || c.label || c.cluster_name || c.name || c.proxy || '';
}

function getClusterLabel(c: DrawerCluster): string {
  return c.label || c.name || c.cluster_name || c.proxy || 'Cluster';
}

function isClusterConnected(c: DrawerCluster, connected: ConnectedK8sSession[]): boolean {
  return connected.some((conn) => {
    if (c.id && conn.id === c.id) return true;
    const connName = conn.info?.name;
    const connClusterName = conn.info?.cluster_name;
    if (c.cluster_name && (connName === c.cluster_name || connClusterName === c.cluster_name)) return true;
    if (c.label && connName === c.label) return true;
    if (c.name && connName === c.name) return true;
    return false;
  });
}

function readDrawerDbs(): DbConnection[] {
  try {
    const raw = window.localStorage.getItem(DB_CUSTOM_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    return Array.isArray(parsed) ? (parsed as DbConnection[]) : [];
  } catch {
    return [];
  }
}

function readK8sSessionState(): { connections: ConnectedK8sSession[]; activeId: string | null } {
  try {
    const raw = window.sessionStorage.getItem('operquay:k8s:session');
    if (!raw) return { connections: [], activeId: null };
    const parsed = JSON.parse(raw) as {
      activeCluster?: string | null;
      connections?: ConnectedK8sSession[];
    } | null;
    if (!parsed) return { connections: [], activeId: null };
    return {
      connections: Array.isArray(parsed.connections) ? parsed.connections : [],
      activeId: typeof parsed.activeCluster === 'string' ? parsed.activeCluster : null,
    };
  } catch {
    return { connections: [], activeId: null };
  }
}

function EmptyState({
  filter,
  loading,
  stateFilter = 'all',
  hasAccounts = false,
}: {
  filter: string;
  loading: boolean;
  stateFilter?: 'all' | 'running' | 'favorites';
  hasAccounts?: boolean;
}) {
  const canManageCloud = useAuthStore((s) => hasPermission(s.me, 'aws_accounts:manage'));
  const userMode = useAuthStore((s) => s.config?.aws_access_mode === 'user');
  const roleCount = useInstancesStore((s) => s.userRoles.length);
  const userFetching = useInstancesStore((s) => s.userFetching.length > 0);
  if (userMode && roleCount === 0) {
    return (
      <div className="p-4 text-center space-y-3">
        <p className="text-[13px] text-text-mut">No cloud account is connected yet.</p>
        <Button size="sm" onClick={connectCloud}>Connect a cloud account</Button>
      </div>
    );
  }
  if (userMode && userFetching && !filter) return null;
  if (loading && !userMode) {
    return (
      <div className="flex flex-col items-center justify-center gap-2 py-8 text-text-dim text-[12px]">
        <Loader size={16} className="animate-spin" />
        <span>Discovering your AWS accounts…</span>
      </div>
    );
  }
  if (!filter && hasAccounts && stateFilter === 'favorites') {
    return (
      <div className="p-4 text-center text-text-dim text-[12px] space-y-1">
        <p className="text-text-sec font-medium">No favorite instances yet.</p>
        <p className="text-[11px] text-text-mut">Star any instance to quick-access it here.</p>
      </div>
    );
  }
  if (!filter && hasAccounts && stateFilter === 'running') {
    return (
      <div className="p-4 text-center text-text-dim text-[12px]">
        No running instances.
      </div>
    );
  }
  if (!filter) {
    return (
      <div className="p-4 text-center text-text-dim text-[12px] space-y-2">
        <p>No instances are available.</p>
        {canManageCloud && <Button size="sm" variant="outline" onClick={connectCloud}>Add an account</Button>}
      </div>
    );
  }
  return (
    <div className="p-4 text-center text-text-dim text-[12px]">
      No matching instances
    </div>
  );
}

const scopeKey = (a: AccountNode) => `${cloudKey(a.provider)}:${a.account_id}`;
const instanceCount = (a: AccountNode) => a.regions.reduce((n, r) => n + r.groups.reduce((m, g) => m + g.instances.length, 0), 0);

/** Narrows the list to one cloud account, subscription or project. Lives inside the filter box. */
function CloudScope({ accounts, scope, onScope }: { accounts: AccountNode[]; scope: string | null; onScope: (key: string | null) => void }) {
  const canManageCloud = useAuthStore((s) => hasPermission(s.me, 'aws_accounts:manage'));
  const userMode = useAuthStore((s) => s.config?.aws_access_mode === 'user');
  const providers = [...new Set(accounts.map((a) => cloudKey(a.provider)))];
  const current = accounts.find((a) => scopeKey(a) === scope);
  const total = accounts.reduce((n, a) => n + instanceCount(a), 0);
  const sections: MenuSection[] = accounts.length === 0 ? [{ heading: 'No accounts connected', items: [] }] : [
    { items: [{ label: 'All clouds', hint: String(total), checked: !current, onSelect: () => onScope(null) }] },
    ...providers.map((provider) => ({
      heading: cloudNames[provider] || 'Unknown cloud',
      icon: <CloudMark provider={provider} compact />,
      items: accounts.filter((a) => cloudKey(a.provider) === provider).map((a) => ({
        label: a.account_alias || a.profile || a.account_id,
        hint: String(instanceCount(a)),
        checked: scopeKey(a) === scope,
        onSelect: () => onScope(scopeKey(a)),
      })),
    })),
  ];
  const action = 'w-full flex items-center px-2.5 h-8 rounded-md text-left text-[13px] hover:bg-elev focus:bg-elev focus:outline-none';
  return (
    <Menu
      label="Cloud scope"
      align="left"
      className="flex"
      triggerClassName="h-full flex items-center gap-1.5 pl-2 pr-1.5 border-r border-border text-[12px] text-text-pri hover:bg-elev rounded-l-md max-w-[120px]"
      trigger={<>
        {current && <CloudMark provider={cloudKey(current.provider)} compact />}
        <span className="truncate">{current ? current.account_alias || current.account_id : accounts.length === 0 ? 'Accounts' : providers.length > 1 ? `All · ${providers.length}` : 'All'}</span>
        <ChevronDown size={12} aria-hidden="true" className="shrink-0 text-text-dim" />
      </>}
      sections={sections}
      footer={(userMode || canManageCloud) && <>
        <button type="button" role="menuitem" onClick={connectCloud} className={`${action} text-accent`}>{userMode ? '+ Manage connections' : '+ Connect a cloud account'}</button>
        {canManageCloud && !userMode && <button type="button" role="menuitem" onClick={() => useLayoutStore.getState().openSettings('accounts')} className={`${action} text-text-pri`}>Manage connections…</button>}
      </>}
    />
  );
}

export function Sidebar() {
  const canManageCloud = useAuthStore((s) => hasPermission(s.me, 'aws_accounts:manage'));
  const canManageK8s = useAuthStore((s) => hasPermission(s.me, 'k8s_clusters:manage'));
  const userMode = useAuthStore((s) => s.config?.aws_access_mode === 'user');
  const fetching = useInstancesStore((s) => s.loading);
  const discovering = useInstancesStore((s) => s.discovering);
  const loading = fetching || discovering;
  const filter = useInstancesStore((s) => s.filter);
  const accounts = useInstancesStore((s) => s.accounts);
  const setFilter = useInstancesStore((s) => s.setFilter);
  const collapseAll = useInstancesStore((s) => s.collapseAll);
  const expandAll = useInstancesStore((s) => s.expandAll);
  const fetchInstances = useInstancesStore((s) => s.fetchInstances);
  const [allExpanded, setAllExpanded] = useState(false);
  const [closedClouds, setClosedClouds] = useState<Record<string, boolean>>({});
  const [scope, setScope] = useState<string | null>(null);
  const [stateFilter, setStateFilter] = useState<'all' | 'running' | 'favorites'>('all');
  const filterInputRef = useRef<HTMLInputElement>(null);
  const favorites = useInstancesStore((s) => s.favorites);

  useEffect(() => {
    const onSlash = (e: KeyboardEvent) => {
      if (e.key !== '/' || e.metaKey || e.ctrlKey || e.altKey) return;
      const t = e.target as HTMLElement | null;
      if (
        !t ||
        t.tagName === 'INPUT' ||
        t.tagName === 'TEXTAREA' ||
        t.tagName === 'SELECT' ||
        t.isContentEditable ||
        t.getAttribute('role') === 'textbox' ||
        t.closest('[data-terminal-wrapper="true"]')
      ) return;
      e.preventDefault();
      filterInputRef.current?.focus();
    };
    document.addEventListener('keydown', onSlash);
    return () => document.removeEventListener('keydown', onSlash);
  }, []);
  const toggleList = useLayoutStore((s) => s.toggleSidebar);

  const watchDiscovery = useInstancesStore((s) => s.watchDiscovery);
  const userRoles = useInstancesStore((s) => s.userRoles);
  const userFetching = useInstancesStore((s) => s.userFetching);
  const fetchingRoles = userRoles.filter((r) => userFetching.includes(r.id));
  const roleProblems = userRoles.filter((r) => r.error || r.failedRegions?.length);
  useEffect(() => {
    void fetchInstances();
    return watchDiscovery();
  }, [fetchInstances, watchDiscovery]);
  useEffect(() => { if (filter.trim()) setClosedClouds({}); }, [filter]);

  const scoped = useMemo(() => (scope && accounts.some((a) => scopeKey(a) === scope) ? accounts.filter((a) => scopeKey(a) === scope) : accounts), [accounts, scope]);
  const textFiltered = useMemo(() => getFilteredAccounts(scoped, filter), [scoped, filter]);
  const filtered = useMemo(() => {
    if (stateFilter === 'all') return textFiltered;
    const favSet = new Set(favorites);
    return textFiltered
      .map((a) => ({
        ...a,
        regions: a.regions
          .map((r) => ({
            ...r,
            groups: r.groups
              .map((g) => ({
                ...g,
                instances: g.instances.filter((i) =>
                  stateFilter === 'running' ? i.state === 'running' : favSet.has(i.instance_id),
                ),
              }))
              .filter((g) => g.instances.length > 0),
          }))
          .filter((r) => r.groups.length > 0),
      }))
      .filter((a) => a.regions.length > 0);
  }, [textFiltered, stateFilter, favorites]);
  const clouds = useMemo(() => {
    const groups = new Map<string, typeof filtered>();
    for (const account of filtered) {
      const key = cloudKey(account.provider);
      groups.set(key, [...(groups.get(key) ?? []), account]);
    }
    return [...groups.entries()];
  }, [filtered]);
  const isEmpty = filtered.length === 0;

  const toggleExpandCollapse = () => {
    if (allExpanded) {
      collapseAll();
      setClosedClouds(Object.fromEntries(clouds.map(([provider]) => [provider, true])));
    } else {
      expandAll();
      setClosedClouds({});
    }
    setAllExpanded(!allExpanded);
  };

  const view = useLayoutStore((s) => s.view);
  const setView = useLayoutStore((s) => s.setView);
  const enableKubernetes = useSettingsStore((s) => s.enableKubernetes ?? true);
  const enableDatabases = useSettingsStore((s) => s.enableDatabases ?? true);

  const [resourceFilter, setResourceFilter] = useState('');
  const [kubeClusters, setKubeClusters] = useState<DrawerCluster[]>([]);
  const [kubeLoading, setKubeLoading] = useState(false);
  const [connectedK8s, setConnectedK8s] = useState<ConnectedK8sSession[]>(() => readK8sSessionState().connections);
  const [selectedK8sKey, setSelectedK8sKey] = useState<string | null>(() => {
    const sess = readK8sSessionState();
    const active = sess.connections.find((c) => c.id === sess.activeId);
    return active?.id || active?.info?.cluster_name || active?.info?.name || null;
  });
  const [activeK8sNavKey, setActiveK8sNavKey] = useState<string>('/v1/pods');
  const [dbConnections, setDbConnections] = useState<DbConnection[]>(() => readDrawerDbs());
  const [selectedDbId, setSelectedDbId] = useState<string | null>(null);
  const [activeDbTable, setActiveDbTable] = useState<{ connectionId?: string; schema?: string; name?: string } | null>(null);
  const [dbFilterMode, setDbFilterMode] = useState<string>('all');
  const [kubeExpandSignal, setKubeExpandSignal] = useState<{ expanded: boolean; version: number }>({ expanded: false, version: 0 });
  const [dbExpandSignal, setDbExpandSignal] = useState<{ expanded: boolean; version: number }>({ expanded: true, version: 0 });

  useEffect(() => {
    if (view !== 'kubernetes' || !enableKubernetes) return;
    setConnectedK8s(readK8sSessionState().connections);
    if (!canSendCredentials('/api/k8s/configured-clusters')) return;
    let active = true;
    setKubeLoading(true);
    void api.get<{ clusters?: DrawerCluster[] }>('/api/k8s/configured-clusters').then((res) => {
      if (!active) return;
      if (res.ok && res.data && Array.isArray(res.data.clusters)) {
        setKubeClusters(res.data.clusters);
      } else if (res.ok && Array.isArray(res.data)) {
        setKubeClusters(res.data as unknown as DrawerCluster[]);
      }
      setKubeLoading(false);
    }).catch(() => {
      if (active) setKubeLoading(false);
    });
    return () => { active = false; };
  }, [view, enableKubernetes]);

  useEffect(() => {
    const syncDbs = () => setDbConnections(readDrawerDbs());
    const syncK8sSession = () => {
      const sess = readK8sSessionState();
      setConnectedK8s(sess.connections);
      if (sess.activeId) {
        const active = sess.connections.find((c) => c.id === sess.activeId);
        if (active) {
          const matchedConfigured = kubeClusters.find((kc) => isClusterConnected(kc, [active]));
          setSelectedK8sKey(matchedConfigured ? getClusterKey(matchedConfigured) : (active.info?.cluster_name || active.info?.name || active.id));
        }
      }
    };
    const onSelectDb = (ev: Event) => {
      const id = (ev as CustomEvent<{ id?: string }>).detail?.id;
      if (id) setSelectedDbId(id);
    };
    const onActiveTable = (ev: Event) => {
      const detail = (ev as CustomEvent<{ connectionId?: string; schema?: string; name?: string }>).detail;
      if (detail) setActiveDbTable(detail);
    };
    const onSelectK8s = (ev: Event) => {
      const detail = (ev as CustomEvent<DrawerCluster>).detail;
      if (detail) {
        const key = getClusterKey(detail);
        if (key) setSelectedK8sKey(key);
      }
    };
    const onK8sActive = (ev: Event) => {
      const detail = (ev as CustomEvent<{ activeKey?: string }>).detail;
      if (detail?.activeKey) setActiveK8sNavKey(detail.activeKey);
    };
    const onParentMsg = (event: MessageEvent) => {
      if (event.origin === window.location.origin && event.data?.type === 'operquay-k8s-active-changed') {
        if (event.data.activeKey) setActiveK8sNavKey(event.data.activeKey);
      }
    };
    window.addEventListener('operquay:db-connections-changed', syncDbs);
    window.addEventListener('operquay:k8s-session-changed', syncK8sSession);
    window.addEventListener('storage', syncDbs);
    window.addEventListener('storage', syncK8sSession);
    window.addEventListener('operquay:db-select-connection', onSelectDb);
    window.addEventListener('operquay:db-active-table-changed', onActiveTable);
    window.addEventListener('operquay:k8s-select-cluster', onSelectK8s);
    window.addEventListener('operquay:k8s-active-changed', onK8sActive);
    window.addEventListener('message', onParentMsg);
    return () => {
      window.removeEventListener('operquay:db-connections-changed', syncDbs);
      window.removeEventListener('operquay:k8s-session-changed', syncK8sSession);
      window.removeEventListener('storage', syncDbs);
      window.removeEventListener('storage', syncK8sSession);
      window.removeEventListener('operquay:db-select-connection', onSelectDb);
      window.removeEventListener('operquay:db-active-table-changed', onActiveTable);
      window.removeEventListener('operquay:k8s-select-cluster', onSelectK8s);
      window.removeEventListener('operquay:k8s-active-changed', onK8sActive);
      window.removeEventListener('message', onParentMsg);
    };
  }, [kubeClusters]);

  const switcherItems = useMemo(() => {
    const items: Array<['session' | 'kubernetes' | 'databases', string]> = [['session', 'VMs']];
    if (enableKubernetes) items.push(['kubernetes', 'K8s']);
    if (enableDatabases) items.push(['databases', 'DB']);
    return items;
  }, [enableKubernetes, enableDatabases]);

  const effectiveView =
    view === 'kubernetes' && enableKubernetes
      ? 'kubernetes'
      : view === 'databases' && enableDatabases
        ? 'databases'
        : 'session';

  const filteredClusters = useMemo(() => {
    const q = resourceFilter.trim().toLowerCase();
    if (!q) return kubeClusters;
    return kubeClusters.filter((c) =>
      getClusterLabel(c).toLowerCase().includes(q)
      || (c.cluster_name ?? '').toLowerCase().includes(q)
      || (c.proxy ?? '').toLowerCase().includes(q),
    );
  }, [kubeClusters, resourceFilter]);

  const activeK8sCluster = useMemo(() => {
    const sess = readK8sSessionState();
    const activeConn = connectedK8s.find((c) => c.id === sess.activeId) ?? connectedK8s[0];
    if (activeConn) {
      return {
        id: activeConn.id,
        name: activeConn.info?.name,
        label: activeConn.info?.name,
        proxy: activeConn.info?.proxy,
        connected: true,
      };
    }
    const matched = kubeClusters.find((kc) => getClusterKey(kc) === selectedK8sKey) ?? kubeClusters[0];
    if (matched) {
      return {
        id: matched.id || getClusterKey(matched),
        name: matched.cluster_name,
        label: matched.label,
        proxy: matched.proxy,
        connected: false,
      };
    }
    return null;
  }, [connectedK8s, selectedK8sKey, kubeClusters]);

  const k8sClustersList = useMemo(() => {
    return filteredClusters.map((c) => {
      const isConn = isClusterConnected(c, connectedK8s);
      return {
        id: c.id || getClusterKey(c),
        label: getClusterLabel(c),
        name: c.cluster_name,
        proxy: c.proxy,
        connected: isConn,
      };
    });
  }, [filteredClusters, connectedK8s]);

  const handleK8sNavigate = (item: KubeNavItem) => {
    setActiveK8sNavKey(item.id);
    window.dispatchEvent(new CustomEvent('operquay:k8s-navigate', { detail: item }));
  };

  const vmCounts = useMemo(() => {
    const allInsts = scoped.flatMap((a) => a.regions.flatMap((r) => r.groups.flatMap((g) => g.instances)));
    const favSet = new Set(favorites);
    return {
      total: allInsts.length,
      running: allInsts.filter((i) => i.state === 'running').length,
      favorites: allInsts.filter((i) => favSet.has(i.instance_id)).length,
    };
  }, [scoped, favorites]);

  const dbEngines = useMemo(
    () => Array.from(new Set(dbConnections.map((c) => c.engine).filter(Boolean))),
    [dbConnections],
  );
  const liveDbCount = useMemo(
    () => dbConnections.filter((c) => c.status === 'connected').length,
    [dbConnections],
  );
  const filteredDbConnections = useMemo(() => {
    if (dbFilterMode === 'all') return dbConnections;
    if (dbFilterMode === 'live') return dbConnections.filter((c) => c.status === 'connected');
    return dbConnections.filter((c) => c.engine === dbFilterMode);
  }, [dbConnections, dbFilterMode]);

  return (
    <div
      className="h-full flex flex-col bg-side overflow-hidden"
      aria-label={effectiveView === 'kubernetes' ? 'Kubernetes clusters' : effectiveView === 'databases' ? 'Database connections' : 'Instances'}
      role="tree"
    >
      {/* RESOURCES header: Row 1 = label + collapse; Row 2 = full-width segmented switcher */}
      <div className="px-3 pt-3 pb-2.5 border-b border-border/70 space-y-2.5">
        <div className="flex items-center justify-between gap-2">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-text-dim">RESOURCES</span>
          <button
            type="button"
            onClick={toggleList}
            aria-label="Hide instance list"
            title="Hide instance list (⌘B)"
            className="w-5 h-5 rounded flex items-center justify-center text-text-mut hover:text-text-pri hover:bg-elev"
          >
            <ChevronLeft size={13} />
          </button>
        </div>
        {switcherItems.length > 1 && (
          <div
            className="grid gap-1 p-0.5 rounded-lg bg-bg border border-border"
            style={{ gridTemplateColumns: `repeat(${switcherItems.length}, minmax(0, 1fr))` }}
            role="group"
            aria-label="Switch resource type"
          >
            {switcherItems.map(([targetView, label]) => {
              const active = effectiveView === targetView;
              return (
                <button
                  key={targetView}
                  type="button"
                  onClick={() => setView(targetView)}
                  className={`py-1 rounded-md text-[11px] font-medium transition-colors border ${active
                    ? 'bg-elev text-accent border-border shadow-2xs'
                    : 'text-text-mut border-transparent hover:text-text-pri'
                    }`}
                >
                  {label}
                </button>
              );
            })}
          </div>
        )}
      </div>

      {effectiveView === 'kubernetes' ? (
        <>
          <div className="px-3 py-2 border-b border-border flex items-center gap-1">
            <label className="flex-1 min-w-0 h-8 flex items-center gap-2 px-2.5 rounded-md border border-border bg-bg hover:border-text-dim focus-within:border-accent">
              <Search size={13} aria-hidden="true" className="shrink-0 text-text-dim" />
              <input
                value={resourceFilter}
                onChange={(e) => {
                  const val = e.target.value;
                  const trimmed = val.trim().replace(/[\s-]/g, '');
                  if (/^\d{6,10}$/.test(trimmed)) {
                    setResourceFilter('');
                    window.dispatchEvent(new CustomEvent('operquay:k8s-mfa-pasted', { detail: trimmed }));
                    return;
                  }
                  setResourceFilter(val);
                }}
                onFocus={(e) => {
                  if (e.relatedTarget === null) {
                    window.dispatchEvent(new CustomEvent('operquay:k8s-check-refocus-mfa'));
                  }
                }}
                onPaste={(e) => {
                  const text = (e.clipboardData?.getData('text') || e.clipboardData?.getData('text/plain') || '').trim().replace(/[\s-]/g, '');
                  if (/^\d{6,10}$/.test(text)) {
                    e.preventDefault();
                    setResourceFilter('');
                    window.dispatchEvent(new CustomEvent('operquay:k8s-mfa-pasted', { detail: text }));
                  }
                }}
                placeholder="Filter kubernetes…"
                aria-label="Filter kubernetes"
                className="w-full min-w-0 bg-transparent text-[12px] text-text-pri placeholder:text-text-dim focus:outline-none"
              />
              {resourceFilter && (
                <button
                  type="button"
                  onClick={() => setResourceFilter('')}
                  aria-label="Clear filter"
                  className="text-text-dim hover:text-text-pri"
                >
                  <X size={12} />
                </button>
              )}
            </label>
            <button
              type="button"
              onClick={() =>
                setKubeExpandSignal((prev) => ({ expanded: !prev.expanded, version: prev.version + 1 }))
              }
              aria-label={kubeExpandSignal.expanded ? 'Collapse all clusters' : 'Expand all clusters'}
              title={kubeExpandSignal.expanded ? 'Collapse all clusters' : 'Expand all clusters'}
              className="w-7 h-8 shrink-0 rounded-md flex items-center justify-center text-text-mut hover:text-text-pri hover:bg-elev"
            >
              {kubeExpandSignal.expanded ? <ChevronsDownUp size={14} /> : <ChevronsUpDown size={14} />}
            </button>
          </div>
          <KubeNavTree
            cluster={activeK8sCluster}
            selectedClusterId={selectedK8sKey}
            activeKey={activeK8sNavKey}
            filterText={resourceFilter}
            clusters={k8sClustersList}
            loading={kubeLoading}
            expandSignal={kubeExpandSignal}
            onNavigate={handleK8sNavigate}
            onSelectCluster={(c) => {
              const matched = kubeClusters.find((kc) => (kc.id || getClusterKey(kc)) === c.id);
              if (matched) {
                const key = getClusterKey(matched);
                if (key) setSelectedK8sKey(key);
                window.dispatchEvent(new CustomEvent('operquay:k8s-select-cluster', { detail: matched }));
              }
            }}
            onAddCluster={() => {
              window.dispatchEvent(new CustomEvent('operquay:k8s-open-discovery'));
            }}
          />
          {canManageK8s && (
            <div className="p-2.5 border-t border-border">
              <Button
                size="sm"
                variant="outline"
                className="w-full"
                icon={<Plus size={12} />}
                onClick={() => useLayoutStore.getState().openSettings('kube-clusters')}
              >
                Manage Kube Clusters
              </Button>
            </div>
          )}
        </>
      ) : effectiveView === 'databases' ? (
        <>
          <div className="px-3 py-2 border-b border-border flex items-center gap-1">
            <label className="flex-1 min-w-0 h-8 flex items-center gap-2 px-2.5 rounded-md border border-border bg-bg hover:border-text-dim focus-within:border-accent">
              <Search size={13} aria-hidden="true" className="shrink-0 text-text-dim" />
              <input
                value={resourceFilter}
                onChange={(e) => setResourceFilter(e.target.value)}
                placeholder="Filter databases…"
                aria-label="Filter databases"
                className="w-full min-w-0 bg-transparent text-[12px] text-text-pri placeholder:text-text-dim focus:outline-none"
              />
              {resourceFilter && (
                <button
                  type="button"
                  onClick={() => setResourceFilter('')}
                  aria-label="Clear filter"
                  className="text-text-dim hover:text-text-pri"
                >
                  <X size={12} />
                </button>
              )}
            </label>
            <button
              type="button"
              onClick={() =>
                setDbExpandSignal((prev) => ({ expanded: !prev.expanded, version: prev.version + 1 }))
              }
              aria-label={dbExpandSignal.expanded ? 'Collapse all connections' : 'Expand all connections'}
              title={dbExpandSignal.expanded ? 'Collapse all connections' : 'Expand all connections'}
              className="w-7 h-8 shrink-0 rounded-md flex items-center justify-center text-text-mut hover:text-text-pri hover:bg-elev"
            >
              {dbExpandSignal.expanded ? <ChevronsDownUp size={14} /> : <ChevronsUpDown size={14} />}
            </button>
          </div>

          <div className="px-3 pt-2.5 pb-2 border-b border-border bg-bg space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-text-dim">
                <Database size={13} className="text-accent" />
                <span>DATABASE CONNECTIONS ({dbConnections.length})</span>
              </div>
              <button
                type="button"
                aria-label="Add database connection"
                onClick={() => window.dispatchEvent(new CustomEvent('operquay:db-open-add-modal'))}
                className="text-accent hover:underline text-[11px] font-medium flex items-center gap-1"
              >
                <Plus size={12} />
                <span>Add</span>
              </button>
            </div>
            {dbConnections.length > 0 && (
              <div className="flex items-center gap-1 overflow-x-auto no-scrollbar pt-0.5">
                <button
                  type="button"
                  onClick={() => setDbFilterMode('all')}
                  className={`text-[11px] px-2 py-0.5 rounded-full border transition-colors shrink-0 ${dbFilterMode === 'all'
                    ? 'bg-accent/15 border-accent/40 text-accent font-medium'
                    : 'bg-surface border-border text-text-mut hover:text-text-pri hover:border-text-dim'
                    }`}
                >
                  All ({dbConnections.length})
                </button>
                {liveDbCount > 0 && (
                  <button
                    type="button"
                    onClick={() => setDbFilterMode('live')}
                    className={`text-[11px] px-2 py-0.5 rounded-full border transition-colors flex items-center gap-1 shrink-0 ${dbFilterMode === 'live'
                      ? 'bg-success/20 border-success/40 text-success font-medium'
                      : 'bg-surface border-border text-text-mut hover:text-text-pri hover:border-text-dim'
                      }`}
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
                    Live ({liveDbCount})
                  </button>
                )}
                {dbEngines.map((eng) => {
                  const meta = ENGINE_META[eng];
                  const label = meta ? meta.label : eng;
                  return (
                    <button
                      key={eng}
                      type="button"
                      onClick={() => setDbFilterMode(eng)}
                      className={`text-[11px] px-2 py-0.5 rounded-full border transition-colors shrink-0 ${dbFilterMode === eng
                        ? 'bg-accent/15 border-accent/40 text-accent font-medium'
                        : 'bg-surface border-border text-text-mut hover:text-text-pri hover:border-text-dim'
                        }`}
                    >
                      {label}
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          <div className="flex-1 overflow-y-auto px-2 py-2 bg-bg">
            <DatabaseTree
              connections={filteredDbConnections}
              selectedConnectionId={selectedDbId}
              activeTable={activeDbTable}
              filterText={resourceFilter}
              expandSignal={dbExpandSignal}
              onSelectConnection={(conn) => {
                setSelectedDbId(conn.id);
                window.dispatchEvent(new CustomEvent('operquay:db-select-connection', { detail: { id: conn.id } }));
              }}
              onConnect={(conn) => {
                setSelectedDbId(conn.id);
                window.dispatchEvent(new CustomEvent('operquay:db-connect', { detail: { id: conn.id } }));
              }}
              onDisconnect={(conn) => {
                window.dispatchEvent(new CustomEvent('operquay:db-disconnect', { detail: { id: conn.id } }));
              }}
              onEdit={(conn) => {
                window.dispatchEvent(new CustomEvent('operquay:db-open-edit-modal', { detail: { id: conn.id } }));
              }}
              onRemove={(conn) => {
                const updated = dbConnections.filter((c) => c.id !== conn.id);
                window.localStorage.setItem(DB_CUSTOM_STORAGE_KEY, JSON.stringify(updated));
                setDbConnections(updated);
                window.dispatchEvent(new CustomEvent('operquay:db-connections-changed'));
                window.dispatchEvent(new CustomEvent('operquay:db-remove-connection', { detail: { id: conn.id } }));
              }}
              onOpenTable={(conn, tbl) => {
                setSelectedDbId(conn.id);
                setActiveDbTable({ connectionId: conn.id, schema: tbl.schema, name: tbl.name });
                window.dispatchEvent(
                  new CustomEvent('operquay:db-open-table', {
                    detail: { connectionId: conn.id, schema: tbl.schema, name: tbl.name },
                  }),
                );
              }}
              onOpenAddModal={() => {
                window.dispatchEvent(new CustomEvent('operquay:db-open-add-modal'));
              }}
            />
          </div>
          <div className="p-2.5 border-t border-border">
            <Button
              size="sm"
              variant="outline"
              className="w-full"
              icon={<Plus size={12} />}
              onClick={() => window.dispatchEvent(new CustomEvent('operquay:db-open-add-modal'))}
            >
              Add Database Connection
            </Button>
          </div>
        </>
      ) : (
        <>
          <div className="px-3 py-2 border-b border-border space-y-1.5">
            <div className="flex items-center gap-1">
              <div className="flex-1 min-w-0 h-8 flex items-stretch rounded-md border border-border bg-bg hover:border-text-dim focus-within:border-accent focus-within:ring-2 focus-within:ring-[var(--accent-dim)]">
                {(accounts.length > 0 || userMode || canManageCloud) && <CloudScope accounts={accounts} scope={scope} onScope={setScope} />}
                <label className="flex-1 min-w-0 flex items-center gap-2 pl-2 pr-1.5">
                  <Search size={13} aria-hidden="true" className="shrink-0 text-text-dim" />
                  <input
                    ref={filterInputRef}
                    placeholder="Filter instances…"
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                    className="w-full min-w-0 bg-transparent text-[12px] text-text-pri placeholder:text-text-dim focus:outline-none"
                    aria-label="Filter instances"
                  />
                  {filter && (
                    <button
                      type="button"
                      onClick={() => setFilter('')}
                      aria-label="Clear filter"
                      title="Clear filter"
                      className="w-5 h-5 rounded flex items-center justify-center text-text-dim hover:text-text-pri hover:bg-elev shrink-0"
                    >
                      <X size={12} />
                    </button>
                  )}
                </label>
              </div>
              <button
                type="button"
                onClick={toggleExpandCollapse}
                aria-label={allExpanded ? 'Collapse all' : 'Expand all'}
                title={allExpanded ? 'Collapse all' : 'Expand all'}
                className="w-7 h-8 shrink-0 rounded-md flex items-center justify-center text-text-mut hover:text-text-pri hover:bg-elev"
              >
                {allExpanded ? <ChevronsDownUp size={14} /> : <ChevronsUpDown size={14} />}
              </button>
            </div>
            {loading && accounts.length === 0 && fetchingRoles.length === 0 && <p className="px-0.5 text-[12px] text-text-dim">Fetching…</p>}
            {fetchingRoles.length > 0 && <ul role="status" aria-label="Discovering accounts" className="space-y-0.5 px-0.5">
              {fetchingRoles.map((r) => <li key={r.id} className="flex items-center gap-1.5 text-[11px] text-text-mut"><Loader size={11} className="animate-spin motion-reduce:animate-none shrink-0 text-accent" aria-hidden="true" /><span className="truncate">Fetching {r.name}…</span></li>)}
            </ul>}
            {roleProblems.map((r) => <p key={r.id} role="alert" className={`px-0.5 text-[11px] ${r.error ? 'text-danger' : 'text-warn'}`}>{r.name}: {r.error ?? `not fetched in ${r.failedRegions?.join(', ')}`}</p>)}
            {userRoles.some((r) => r.live === false) && <p className="px-0.5 text-[12px] text-text-mut">AWS sign-in expired. <button type="button" onClick={connectCloud} className="text-accent hover:underline">Sign in again</button></p>}
          </div>

          <div className="px-3 pt-2.5 pb-2 border-b border-border bg-bg space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-text-dim">
                <Cloud size={13} className="text-accent" />
                <span>COMPUTE ACCOUNTS ({scoped.length})</span>
              </div>
              {(userMode || canManageCloud) && (
                <button
                  type="button"
                  aria-label="Connect cloud account"
                  onClick={connectCloud}
                  className="text-accent hover:underline text-[11px] font-medium flex items-center gap-1"
                >
                  <Plus size={12} />
                  <span>Add</span>
                </button>
              )}
            </div>
            {accounts.length > 0 && (
              <div className="flex items-center gap-1 overflow-x-auto no-scrollbar pt-0.5" role="group" aria-label="Instance state filter">
                <button
                  type="button"
                  aria-pressed={stateFilter === 'all'}
                  onClick={() => setStateFilter('all')}
                  className={`text-[11px] px-2 py-0.5 rounded-full border transition-colors shrink-0 ${stateFilter === 'all'
                    ? 'bg-accent/15 border-accent/40 text-accent font-medium'
                    : 'bg-surface border-border text-text-mut hover:text-text-pri hover:border-text-dim'
                    }`}
                >
                  All ({vmCounts.total})
                </button>
                <button
                  type="button"
                  aria-pressed={stateFilter === 'running'}
                  onClick={() => setStateFilter('running')}
                  className={`text-[11px] px-2 py-0.5 rounded-full border transition-colors flex items-center gap-1 shrink-0 ${stateFilter === 'running'
                    ? 'bg-success/20 border-success/40 text-success font-medium'
                    : 'bg-surface border-border text-text-mut hover:text-text-pri hover:border-text-dim'
                    }`}
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-success" />
                  Running ({vmCounts.running})
                </button>
                <button
                  type="button"
                  aria-pressed={stateFilter === 'favorites'}
                  onClick={() => setStateFilter('favorites')}
                  className={`text-[11px] px-2 py-0.5 rounded-full border transition-colors shrink-0 ${stateFilter === 'favorites'
                    ? 'bg-accent/15 border-accent/40 text-accent font-medium'
                    : 'bg-surface border-border text-text-mut hover:text-text-pri hover:border-text-dim'
                    }`}
                >
                  Favorites ({vmCounts.favorites})
                </button>
              </div>
            )}
          </div>

          <div className="flex-1 overflow-y-auto px-2 py-2 space-y-3 bg-bg">
            {isEmpty ? (
              <EmptyState filter={filter} loading={loading} stateFilter={stateFilter} hasAccounts={accounts.length > 0} />
            ) : stateFilter === 'favorites' ? (
              <FavoritesPanel accounts={filtered} />
            ) : (
              <>
                {clouds.map(([provider, entries]) => {
                  const name = cloudNames[provider] || 'Unknown cloud';
                  const open = !closedClouds[provider];
                  return (
                    <div role="group" aria-label={`${name} accounts`} key={provider} className="space-y-1">
                      <button
                        type="button"
                        aria-label={`${name} accounts`}
                        aria-expanded={open}
                        onClick={() => setClosedClouds((current) => ({ ...current, [provider]: !current[provider] }))}
                        className="w-full px-1.5 py-1 flex items-center gap-1.5 text-left text-[10.5px] font-semibold text-text-dim uppercase tracking-wider hover:text-text-pri transition-colors"
                      >
                        {open ? <ChevronDown size={11} aria-hidden="true" /> : <ChevronRight size={11} aria-hidden="true" />}
                        <CloudMark provider={provider} compact />
                        <span>{name}</span>
                        <span className="text-text-mut font-normal">({entries.length})</span>
                      </button>
                      {open && (
                        <div className="space-y-1.5">
                          {entries.map((a) => (
                            <AccountGroup key={`${provider}:${a.account_id}`} account={a} />
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </>
            )}
          </div>

          <InstanceContextMenu />
        </>
      )}
    </div>
  );
}
