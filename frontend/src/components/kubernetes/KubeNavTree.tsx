import { useEffect, useMemo, useState } from 'react';
import {
  Activity,
  AppWindow,
  Box,
  Boxes,
  ChevronDown,
  ChevronRight,
  CircleDollarSign,
  Code2,
  Cpu,
  Database,
  FolderTree,
  GitBranch,
  Layers,
  LayoutDashboard,
  Loader,
  Network,
  Package,
  Plus,
  Server,
  Settings,
  ShieldCheck,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { Tooltip } from '@/components/primitives/Tooltip';

export interface KubeNavItem {
  id: string; // e.g. '/v1/pods'
  name: string;
  kind?: string;
  group?: string;
  version?: string;
  namespaced?: boolean;
  icon?: LucideIcon;
  badge?: string;
  clusterId?: string;
}

export interface KubeNavCategory {
  id: string;
  name: string;
  icon: LucideIcon;
  defaultExpanded?: boolean;
  items: KubeNavItem[];
}

export const KUBE_NAV_CATEGORIES: KubeNavCategory[] = [
  {
    id: 'workloads',
    name: 'Workloads',
    icon: Box,
    defaultExpanded: true,
    items: [
      { id: '/v1/pods', name: 'pods', kind: 'Pod', group: '', version: 'v1', namespaced: true },
      { id: 'apps/v1/deployments', name: 'deployments', kind: 'Deployment', group: 'apps', version: 'v1', namespaced: true },
      { id: 'apps/v1/daemonsets', name: 'daemonsets', kind: 'DaemonSet', group: 'apps', version: 'v1', namespaced: true },
      { id: 'apps/v1/statefulsets', name: 'statefulsets', kind: 'StatefulSet', group: 'apps', version: 'v1', namespaced: true },
      { id: 'apps/v1/replicasets', name: 'replicasets', kind: 'ReplicaSet', group: 'apps', version: 'v1', namespaced: true },
      { id: '/v1/replicationcontrollers', name: 'replicationcontrollers', kind: 'ReplicationController', group: '', version: 'v1', namespaced: true },
      { id: 'batch/v1/jobs', name: 'jobs', kind: 'Job', group: 'batch', version: 'v1', namespaced: true },
      { id: 'batch/v1/cronjobs', name: 'cronjobs', kind: 'CronJob', group: 'batch', version: 'v1', namespaced: true },
    ],
  },
  {
    id: 'config',
    name: 'Config',
    icon: Settings,
    defaultExpanded: false,
    items: [
      { id: '/v1/configmaps', name: 'configmaps', kind: 'ConfigMap', group: '', version: 'v1', namespaced: true },
      { id: '/v1/secrets', name: 'secrets', kind: 'Secret', group: '', version: 'v1', namespaced: true },
      { id: '/v1/resourcequotas', name: 'resourcequotas', kind: 'ResourceQuota', group: '', version: 'v1', namespaced: true },
      { id: '/v1/limitranges', name: 'limitranges', kind: 'LimitRange', group: '', version: 'v1', namespaced: true },
      { id: 'autoscaling/v2/horizontalpodautoscalers', name: 'horizontalpodautoscalers', kind: 'HorizontalPodAutoscaler', group: 'autoscaling', version: 'v2', namespaced: true },
      { id: 'policy/v1/poddisruptionbudgets', name: 'poddisruptionbudgets', kind: 'PodDisruptionBudget', group: 'policy', version: 'v1', namespaced: true },
      { id: 'scheduling.k8s.io/v1/priorityclasses', name: 'priorityclasses', kind: 'PriorityClass', group: 'scheduling.k8s.io', version: 'v1', namespaced: false },
    ],
  },
  {
    id: 'network',
    name: 'Network',
    icon: Network,
    defaultExpanded: false,
    items: [
      { id: '/v1/services', name: 'services', kind: 'Service', group: '', version: 'v1', namespaced: true },
      { id: '/v1/endpoints', name: 'endpoints', kind: 'Endpoints', group: '', version: 'v1', namespaced: true },
      { id: 'networking.k8s.io/v1/ingresses', name: 'ingresses', kind: 'Ingress', group: 'networking.k8s.io', version: 'v1', namespaced: true },
      { id: 'networking.k8s.io/v1/ingressclasses', name: 'ingressclasses', kind: 'IngressClass', group: 'networking.k8s.io', version: 'v1', namespaced: false },
      { id: 'networking.k8s.io/v1/networkpolicies', name: 'networkpolicies', kind: 'NetworkPolicy', group: 'networking.k8s.io', version: 'v1', namespaced: true },
    ],
  },
  {
    id: 'storage',
    name: 'Storage',
    icon: Database,
    defaultExpanded: false,
    items: [
      { id: '/v1/persistentvolumeclaims', name: 'persistentvolumeclaims', kind: 'PersistentVolumeClaim', group: '', version: 'v1', namespaced: true },
      { id: '/v1/persistentvolumes', name: 'persistentvolumes', kind: 'PersistentVolume', group: '', version: 'v1', namespaced: false },
      { id: 'storage.k8s.io/v1/storageclasses', name: 'storageclasses', kind: 'StorageClass', group: 'storage.k8s.io', version: 'v1', namespaced: false },
    ],
  },
  {
    id: 'device',
    name: 'Device Resources',
    icon: Cpu,
    defaultExpanded: false,
    items: [
      { id: 'resource.k8s.io/v1alpha3/deviceclasses', name: 'deviceclasses', kind: 'DeviceClass', group: 'resource.k8s.io', version: 'v1alpha3', namespaced: false },
      { id: 'resource.k8s.io/v1alpha3/resourceclaims', name: 'resourceclaims', kind: 'ResourceClaim', group: 'resource.k8s.io', version: 'v1alpha3', namespaced: true },
    ],
  },
  {
    id: 'helm',
    name: 'Helm',
    icon: Package,
    defaultExpanded: false,
    items: [
      { id: '/v1/__helmcharts', name: '__helmcharts', kind: 'Helm Charts', group: '', version: 'v1', namespaced: true },
      { id: '/v1/__helm', name: '__helm', kind: 'Helm Releases', group: '', version: 'v1', namespaced: true },
    ],
  },
  {
    id: 'access_control',
    name: 'Access Control',
    icon: ShieldCheck,
    defaultExpanded: false,
    items: [
      { id: '/v1/serviceaccounts', name: 'serviceaccounts', kind: 'ServiceAccount', group: '', version: 'v1', namespaced: true },
      { id: 'rbac.authorization.k8s.io/v1/clusterroles', name: 'clusterroles', kind: 'ClusterRole', group: 'rbac.authorization.k8s.io', version: 'v1', namespaced: false },
      { id: 'rbac.authorization.k8s.io/v1/roles', name: 'roles', kind: 'Role', group: 'rbac.authorization.k8s.io', version: 'v1', namespaced: true },
      { id: 'rbac.authorization.k8s.io/v1/clusterrolebindings', name: 'clusterrolebindings', kind: 'ClusterRoleBinding', group: 'rbac.authorization.k8s.io', version: 'v1', namespaced: false },
      { id: 'rbac.authorization.k8s.io/v1/rolebindings', name: 'rolebindings', kind: 'RoleBinding', group: 'rbac.authorization.k8s.io', version: 'v1', namespaced: true },
    ],
  },
  {
    id: 'custom_resources',
    name: 'Custom Resources',
    icon: Code2,
    defaultExpanded: false,
    items: [
      { id: 'apiextensions.k8s.io/v1/customresourcedefinitions', name: 'customresourcedefinitions', kind: 'CustomResourceDefinition', group: 'apiextensions.k8s.io', version: 'v1', namespaced: false },
    ],
  },
];

export const KUBE_STANDALONE_ITEMS: Array<{ section: 'top' | 'middle' | 'bottom'; item: KubeNavItem }> = [
  { section: 'top', item: { id: '/v1/__overview', name: '__overview', kind: 'Overview', group: '', version: 'v1', namespaced: false, icon: LayoutDashboard } },
  { section: 'top', item: { id: '/v1/__applications', name: '__applications', kind: 'Applications', group: '', version: 'v1', namespaced: true, icon: AppWindow } },
  { section: 'top', item: { id: 'argoproj.io/v1alpha1/applications', name: 'applications', kind: 'Argo CD Applications', group: 'argoproj.io', version: 'v1alpha1', namespaced: true, icon: GitBranch, badge: 'NEW' } },
  { section: 'top', item: { id: '/v1/nodes', name: 'nodes', kind: 'Node', group: '', version: 'v1', namespaced: false, icon: Server } },
  { section: 'middle', item: { id: '/v1/namespaces', name: 'namespaces', kind: 'Namespace', group: '', version: 'v1', namespaced: false, icon: FolderTree } },
  { section: 'middle', item: { id: '/v1/events', name: 'events', kind: 'Event', group: '', version: 'v1', namespaced: true, icon: Activity } },
  { section: 'bottom', item: { id: '/v1/__cost', name: '__cost', kind: 'Cost Monitoring', group: '', version: 'v1', namespaced: false, icon: CircleDollarSign, badge: 'NEW' } },
];

export const RESOURCE_TITLES: Record<string, string> = {
  __overview: 'Overview',
  __applications: 'Applications',
  __helm: 'Helm Releases',
  __helmcharts: 'Helm Charts',
  __cost: 'Cost Monitoring',
  pods: 'Pods',
  deployments: 'Deployments',
  daemonsets: 'Daemon Sets',
  statefulsets: 'Stateful Sets',
  replicasets: 'Replica Sets',
  replicationcontrollers: 'Replication Controllers',
  jobs: 'Jobs',
  cronjobs: 'Cron Jobs',
  configmaps: 'Config Maps',
  secrets: 'Secrets',
  services: 'Services',
  ingresses: 'Ingresses',
  networkpolicies: 'Network Policies',
  persistentvolumeclaims: 'Persistent Volume Claims',
  persistentvolumes: 'Persistent Volumes',
  storageclasses: 'Storage Classes',
  serviceaccounts: 'Service Accounts',
  roles: 'Roles',
  rolebindings: 'Role Bindings',
  clusterroles: 'Cluster Roles',
  clusterrolebindings: 'Cluster Role Bindings',
  namespaces: 'Namespaces',
  nodes: 'Nodes',
  events: 'Events',
  resourcequotas: 'Resource Quotas',
  limitranges: 'Limit Ranges',
  horizontalpodautoscalers: 'Horizontal Pod Autoscalers',
  poddisruptionbudgets: 'Pod Disruption Budgets',
  priorityclasses: 'Priority Classes',
  endpoints: 'Endpoints',
  ingressclasses: 'Ingress Classes',
  deviceclasses: 'Device Classes',
  resourceclaims: 'Resource Claims',
  customresourcedefinitions: 'Definitions',
};

export function getResourceDisplayTitle(item: KubeNavItem): string {
  if (item.kind && item.kind !== item.name) return item.kind;
  if (RESOURCE_TITLES[item.name]) return RESOURCE_TITLES[item.name];
  return item.name.replace(/(^|-)([a-z])/g, (_, s, l) => (s ? ' ' : '') + l.toUpperCase());
}

export interface KubeNavCluster {
  id: string;
  name?: string;
  label?: string;
  proxy?: string;
  cluster_name?: string;
  connected?: boolean;
  connector?: string;
  provider?: string;
}

export interface KubeNavTreeProps {
  cluster?: KubeNavCluster | null;
  selectedClusterId?: string | null;
  activeKey?: string | null;
  filterText?: string;
  loading?: boolean;
  expandSignal?: { expanded: boolean; version: number };
  onNavigate?: (item: KubeNavItem) => void;
  clusters?: KubeNavCluster[];
  onSelectCluster?: (cluster: KubeNavCluster) => void;
  onAddCluster?: () => void;
}

export function KubeNavTree({
  cluster,
  selectedClusterId,
  activeKey = '/v1/pods',
  filterText = '',
  loading = false,
  expandSignal,
  onNavigate,
  clusters = [],
  onSelectCluster,
  onAddCluster,
}: KubeNavTreeProps) {
  // Track expanded state for each cluster
  const [expandedClusters, setExpandedClusters] = useState<Record<string, boolean>>({});

  // Track expanded state for resource categories inside clusters
  const [expandedCats, setExpandedCats] = useState<Record<string, boolean>>(() => {
    const init: Record<string, boolean> = {};
    for (const cat of KUBE_NAV_CATEGORIES) {
      init[cat.id] = !!cat.defaultExpanded;
    }
    return init;
  });

  // Track provider filter: 'all' | 'live' | 'teleport' | 'eks'
  const [sourceFilter, setSourceFilter] = useState<'all' | 'live' | 'teleport' | 'eks'>('all');

  // Auto-expand the active or first live cluster on mount or change
  useEffect(() => {
    if (clusters.length === 0) return;
    setExpandedClusters((prev) => {
      const hasAnyExpanded = Object.values(prev).some(Boolean);
      if (hasAnyExpanded) return prev;

      const activeMatch = clusters.find(
        (c) => (selectedClusterId && (c.id === selectedClusterId || c.name === selectedClusterId)) || c.connected,
      ) || clusters[0];

      return activeMatch ? { ...prev, [activeMatch.id]: true } : prev;
    });
  }, [clusters, selectedClusterId]);

  // Sync expand/collapse all signal from Sidebar toolbar
  useEffect(() => {
    if (!expandSignal || expandSignal.version === 0) return;
    if (expandSignal.expanded) {
      setExpandedClusters(Object.fromEntries(clusters.map((c) => [c.id, true])));
      setExpandedCats(Object.fromEntries(KUBE_NAV_CATEGORIES.map((cat) => [cat.id, true])));
    } else {
      setExpandedClusters({});
      setExpandedCats({});
    }
  }, [expandSignal, clusters]);

  const toggleCluster = (clusterId: string, e?: React.MouseEvent) => {
    e?.stopPropagation();
    setExpandedClusters((prev) => ({ ...prev, [clusterId]: !prev[clusterId] }));
  };

  const toggleCategory = (catId: string, e?: React.MouseEvent) => {
    e?.stopPropagation();
    setExpandedCats((prev) => ({ ...prev, [catId]: !prev[catId] }));
  };

  const query = filterText.trim().toLowerCase();

  // Filter resource categories based on search input
  const filteredNav = useMemo(() => {
    if (!query) {
      return {
        top: KUBE_STANDALONE_ITEMS.filter((i) => i.section === 'top').map((i) => i.item),
        middle: KUBE_STANDALONE_ITEMS.filter((i) => i.section === 'middle').map((i) => i.item),
        bottom: KUBE_STANDALONE_ITEMS.filter((i) => i.section === 'bottom').map((i) => i.item),
        categories: KUBE_NAV_CATEGORIES,
      };
    }

    const match = (item: KubeNavItem) => {
      const title = getResourceDisplayTitle(item).toLowerCase();
      const name = item.name.toLowerCase();
      const kind = (item.kind || '').toLowerCase();
      const grp = (item.group || '').toLowerCase();
      return title.includes(query) || name.includes(query) || kind.includes(query) || grp.includes(query);
    };

    const top = KUBE_STANDALONE_ITEMS.filter((i) => i.section === 'top' && match(i.item)).map((i) => i.item);
    const middle = KUBE_STANDALONE_ITEMS.filter((i) => i.section === 'middle' && match(i.item)).map((i) => i.item);
    const bottom = KUBE_STANDALONE_ITEMS.filter((i) => i.section === 'bottom' && match(i.item)).map((i) => i.item);

    const categories = KUBE_NAV_CATEGORIES.map((cat) => {
      const catMatches = cat.name.toLowerCase().includes(query);
      const items = catMatches ? cat.items : cat.items.filter(match);
      return {
        ...cat,
        items,
      };
    }).filter((cat) => cat.items.length > 0);

    return { top, middle, bottom, categories };
  }, [query]);

  // Filter clusters based on quick source filter and query
  const filteredClusters = useMemo(() => {
    let result = clusters;

    if (sourceFilter === 'live') {
      result = result.filter((c) => c.connected);
    } else if (sourceFilter === 'teleport') {
      result = result.filter((c) => c.proxy || c.connector === 'teleport');
    } else if (sourceFilter === 'eks') {
      result = result.filter((c) => !c.proxy || c.connector === 'eks');
    }

    if (query) {
      result = result.filter((c) => {
        const label = (c.label || c.name || c.id || '').toLowerCase();
        const proxy = (c.proxy || '').toLowerCase();
        const clusterName = (c.cluster_name || '').toLowerCase();
        const matchesCluster = label.includes(query) || proxy.includes(query) || clusterName.includes(query);
        const hasMatchingResource =
          filteredNav.top.length > 0 ||
          filteredNav.middle.length > 0 ||
          filteredNav.bottom.length > 0 ||
          filteredNav.categories.length > 0;
        return matchesCluster || hasMatchingResource;
      });
    }

    return result;
  }, [clusters, sourceFilter, query, filteredNav]);

  // Group clusters by source category (Lens style: Teleport Clusters, AWS EKS, Local Kubeconfigs)
  const clusterGroups = useMemo(() => {
    const teleportList: KubeNavCluster[] = [];
    const eksList: KubeNavCluster[] = [];
    const otherList: KubeNavCluster[] = [];

    for (const c of filteredClusters) {
      if (c.proxy || c.connector === 'teleport') {
        teleportList.push(c);
      } else if (c.connector === 'eks' || (c.cluster_name && c.cluster_name.includes('eks'))) {
        eksList.push(c);
      } else {
        otherList.push(c);
      }
    }

    const groups: Array<{ id: string; title: string; count: number; items: KubeNavCluster[] }> = [];

    if (teleportList.length > 0) {
      groups.push({ id: 'teleport', title: 'Teleport Clusters', count: teleportList.length, items: teleportList });
    }
    if (eksList.length > 0) {
      groups.push({ id: 'eks', title: 'AWS EKS Clusters', count: eksList.length, items: eksList });
    }
    if (otherList.length > 0) {
      groups.push({ id: 'other', title: 'Kubeconfig Clusters', count: otherList.length, items: otherList });
    }

    if (groups.length === 0 && filteredClusters.length > 0) {
      groups.push({ id: 'all', title: 'Kubernetes Clusters', count: filteredClusters.length, items: filteredClusters });
    }

    return groups;
  }, [filteredClusters]);

  const liveCount = useMemo(() => clusters.filter((c) => c.connected).length, [clusters]);

  return (
    <div className="flex flex-col flex-1 min-h-0 select-none text-[12px] bg-bg">
      {/* Header bar with cluster count and add action */}
      <div className="px-3 pt-2.5 pb-2 border-b border-border space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wider text-text-dim">
            <Boxes size={13} className="text-accent" />
            <span>KUBERNETES CLUSTERS ({clusters.length})</span>
            {loading && <Loader size={11} className="animate-spin text-accent ml-1" />}
          </div>
          {onAddCluster && (
            <button
              type="button"
              onClick={onAddCluster}
              aria-label="Add Kube Cluster"
              className="text-[11px] text-accent hover:underline font-medium flex items-center gap-1"
            >
              <Plus size={12} />
              <span>Add</span>
            </button>
          )}
        </div>

        {/* Quick source filter chips */}
        {clusters.length > 1 && (
          <div className="flex items-center gap-1 overflow-x-auto no-scrollbar pt-0.5">
            <button
              type="button"
              onClick={() => setSourceFilter('all')}
              className={`text-[11px] px-2 py-0.5 rounded-full border transition-colors shrink-0 ${
                sourceFilter === 'all'
                  ? 'bg-accent/15 border-accent/40 text-accent font-medium'
                  : 'bg-surface border-border text-text-mut hover:text-text-pri hover:border-text-dim'
              }`}
            >
              All ({clusters.length})
            </button>
            {liveCount > 0 && (
              <button
                type="button"
                onClick={() => setSourceFilter('live')}
                className={`text-[11px] px-2 py-0.5 rounded-full border transition-colors flex items-center gap-1 shrink-0 ${
                  sourceFilter === 'live'
                    ? 'bg-success/20 border-success/40 text-success font-medium'
                    : 'bg-surface border-border text-text-mut hover:text-text-pri hover:border-text-dim'
                }`}
              >
                <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
                Live ({liveCount})
              </button>
            )}
            <button
              type="button"
              onClick={() => setSourceFilter('teleport')}
              className={`text-[11px] px-2 py-0.5 rounded-full border transition-colors shrink-0 ${
                sourceFilter === 'teleport'
                  ? 'bg-accent/15 border-accent/40 text-accent font-medium'
                  : 'bg-surface border-border text-text-mut hover:text-text-pri hover:border-text-dim'
              }`}
            >
              Teleport
            </button>
            <button
              type="button"
              onClick={() => setSourceFilter('eks')}
              className={`text-[11px] px-2 py-0.5 rounded-full border transition-colors shrink-0 ${
                sourceFilter === 'eks'
                  ? 'bg-accent/15 border-accent/40 text-accent font-medium'
                  : 'bg-surface border-border text-text-mut hover:text-text-pri hover:border-text-dim'
              }`}
            >
              EKS
            </button>
          </div>
        )}
      </div>

      {/* Cluster Tree Scroll Area */}
      <div className="flex-1 overflow-y-auto px-2 py-2 space-y-3">
        {clusters.length === 0 && !loading ? (
          <div className="rounded-xl border border-dashed border-border bg-surface/50 p-4 text-center space-y-3 mx-1 my-2">
            <div className="w-9 h-9 rounded-full bg-surface border border-border flex items-center justify-center mx-auto text-text-dim">
              <Boxes size={18} />
            </div>
            <div className="space-y-1">
              <p className="text-[12.5px] font-medium text-text-pri">No Kubernetes clusters</p>
              <p className="text-[11px] text-text-dim leading-relaxed">
                Connect your Teleport or AWS EKS clusters to navigate workloads, pods, and metrics.
              </p>
            </div>
            {onAddCluster && (
              <button
                type="button"
                onClick={onAddCluster}
                className="text-[11.5px] px-3 py-1.5 rounded-lg border border-border bg-elev text-text-pri hover:border-accent hover:text-accent font-medium transition-colors"
              >
                + Add Kube Cluster
              </button>
            )}
          </div>
        ) : filteredClusters.length === 0 ? (
          <div className="p-4 text-center text-text-dim text-[11.5px]">
            No clusters match current filter.
          </div>
        ) : (
          clusterGroups.map((group) => (
            <div key={group.id} className="space-y-1">
              {/* Group category header (Lens style: Local Kubeconfigs / Teleport Clusters) */}
              {clusterGroups.length > 1 && (
                <div className="px-1.5 py-1 flex items-center gap-1.5 text-[10.5px] font-semibold text-text-dim uppercase tracking-wider">
                  <Layers size={11} className="opacity-70" />
                  <span>{group.title}</span>
                  <span className="text-text-mut font-normal">({group.count})</span>
                </div>
              )}

              {/* Cluster Nodes */}
              <div className="space-y-1">
                {group.items.map((c) => {
                  const isSelected = selectedClusterId
                    ? c.id === selectedClusterId || c.name === selectedClusterId
                    : cluster?.id === c.id;
                  const isConnected = !!c.connected;
                  const isExpanded = query ? true : !!expandedClusters[c.id];
                  const label = c.label || c.name || c.id;
                  const isTeleport = Boolean(c.proxy || c.connector === 'teleport');

                  return (
                    <div
                      key={c.id}
                      className={`rounded-xl border transition-all duration-150 ${
                        isSelected
                          ? 'border-accent/40 bg-surface/90 shadow-sm'
                          : 'border-transparent hover:border-border/60 hover:bg-surface/50'
                      }`}
                    >
                      {/* Cluster Header Row (V2 compact: subtitle visible when expanded, full text on hover if truncated) */}
                      <Tooltip
                        onlyWhenTruncated
                        side="right"
                        sideOffset={8}
                        delay={160}
                        content={
                          <div className="flex flex-col gap-0.5">
                            <span className="text-[12px] font-semibold text-[var(--text-pri)] break-all">{label}</span>
                            <span className="text-[11px] font-mono text-[var(--accent)] break-all">
                              {c.proxy || c.cluster_name || 'Kubernetes cluster'}
                            </span>
                            <span className="text-[11px] font-mono text-[var(--text-dim)]">
                              {isConnected ? 'Live' : isTeleport ? 'Teleport' : 'EKS'}
                            </span>
                          </div>
                        }
                      >
                        <button
                          type="button"
                          onClick={() => {
                            onSelectCluster?.(c);
                            toggleCluster(c.id);
                          }}
                          className="w-full px-2 py-1 rounded-lg text-left flex items-center gap-2 group transition-colors"
                        >
                          {/* Expand/Collapse Chevron */}
                          <span
                            onClick={(e) => toggleCluster(c.id, e)}
                            className="w-4 h-4 rounded flex items-center justify-center text-text-dim hover:text-text-pri hover:bg-elev/80 shrink-0 transition-transform"
                            aria-label={isExpanded ? 'Collapse cluster' : 'Expand cluster'}
                          >
                            {isExpanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
                          </span>

                          {/* Cluster Glyph & Status Pip */}
                          <div className="relative shrink-0 flex items-center justify-center">
                            <div
                              className={`w-5 h-5 rounded-md flex items-center justify-center text-[10px] font-mono border ${
                                isConnected
                                  ? 'bg-success/15 border-success/40 text-success'
                                  : isSelected
                                    ? 'bg-accent/15 border-accent/40 text-accent'
                                    : 'bg-elev border-border text-text-mut'
                              }`}
                            >
                              <Boxes size={12} />
                            </div>
                            {isConnected && (
                              <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-success ring-2 ring-bg animate-pulse" />
                            )}
                          </div>

                          {/* Cluster Title & Subtitle */}
                          <div className="min-w-0 flex-1">
                            <div className="text-[12px] font-medium text-text-pri flex items-center gap-1.5 min-w-0">
                              <span data-truncate className="truncate">
                                {label}
                              </span>
                            </div>
                            {isExpanded && (
                              <div
                                data-truncate
                                className="text-[11px] font-mono text-text-dim truncate mt-0.5"
                              >
                                {c.proxy || c.cluster_name || 'Kubernetes cluster'}
                              </div>
                            )}
                          </div>

                          {/* Status Badge */}
                          <span
                            className={`text-[10px] font-mono px-1.5 py-0.5 rounded border shrink-0 font-medium ${
                              isConnected
                                ? 'bg-success/15 border-success/30 text-success'
                                : isSelected
                                  ? 'bg-accent/15 border-accent/30 text-accent'
                                  : 'bg-elev border-border text-text-mut'
                            }`}
                          >
                            {isConnected ? 'Live' : isSelected ? 'Selected' : isTeleport ? 'Teleport' : 'EKS'}
                          </span>
                        </button>
                      </Tooltip>

                      {/* In-Cluster Resource Tree (Unfolds inside this Cluster when expanded!) */}
                      {isExpanded && (
                        <div className="ml-4 pl-2.5 my-1 pb-1.5 border-l border-border/60 space-y-0.5 animate-in fade-in duration-150">
                          {/* Top Standalone items: Overview, Applications, Argo, Nodes */}
                          {filteredNav.top.map((item) => {
                            const Icon = item.icon || Box;
                            const isItemActive =
                              isSelected && (activeKey === item.id || activeKey?.endsWith(`/${item.name}`));
                            const title = getResourceDisplayTitle(item);

                            return (
                              <Tooltip
                                key={item.id}
                                onlyWhenTruncated
                                side="right"
                                sideOffset={8}
                                delay={160}
                                content={
                                  <div className="flex flex-col gap-0.5">
                                    <span className="text-[12px] font-semibold text-[var(--text-pri)]">{title}</span>
                                    {item.group && (
                                      <span className="text-[11px] font-mono text-[var(--text-dim)]">
                                        {item.group}/{item.version}
                                      </span>
                                    )}
                                  </div>
                                }
                              >
                                <button
                                  type="button"
                                  onClick={() => {
                                    if (!isSelected) onSelectCluster?.(c);
                                    onNavigate?.({ ...item, clusterId: c.id });
                                  }}
                                  className={`w-full flex items-center gap-2 px-2 py-0.5 rounded-md text-left transition-colors truncate text-[12px] ${
                                    isItemActive
                                      ? 'bg-accent/15 text-accent font-medium border border-accent/30'
                                      : 'text-text-mut hover:text-text-pri hover:bg-surface border border-transparent'
                                  }`}
                                >
                                  <Icon size={13} className="shrink-0 opacity-80" />
                                  <span data-truncate className="truncate flex-1">{title}</span>
                                  {item.badge && (
                                    <span className="text-[10px] font-mono px-1 py-0.2 rounded bg-accent/20 text-accent font-semibold uppercase tracking-wider shrink-0">
                                      {item.badge}
                                    </span>
                                  )}
                                </button>
                              </Tooltip>
                            );
                          })}

                          {/* Nested Categories: Workloads, Config, Network, Storage, Device, Helm, Access, CRDs */}
                          {filteredNav.categories.map((cat) => {
                            const CatIcon = cat.icon;
                            const isCatExpanded = query ? true : !!expandedCats[cat.id];
                            const hasActiveChild =
                              isSelected &&
                              cat.items.some((i) => activeKey === i.id || activeKey?.endsWith(`/${i.name}`));

                            return (
                              <div key={cat.id} className="space-y-0.5">
                                <Tooltip
                                  onlyWhenTruncated
                                  side="right"
                                  sideOffset={8}
                                  delay={160}
                                  content={`${cat.name} (${cat.items.length})`}
                                >
                                  <button
                                    type="button"
                                    onClick={(e) => toggleCategory(cat.id, e)}
                                    className={`w-full flex items-center gap-1.5 px-2 py-0.5 rounded-md text-left transition-colors text-[12px] hover:bg-surface ${
                                      hasActiveChild ? 'font-medium text-accent' : 'text-text-pri'
                                    }`}
                                  >
                                    <span className="text-text-dim shrink-0">
                                      {isCatExpanded ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
                                    </span>
                                    <CatIcon size={13} className="shrink-0 opacity-80" />
                                    <span data-truncate className="truncate flex-1">{cat.name}</span>
                                    <span className="text-[10px] text-text-dim font-mono shrink-0">
                                      {cat.items.length}
                                    </span>
                                  </button>
                                </Tooltip>

                                {isCatExpanded && (
                                  <div className="pl-4 pr-1 space-y-0.5 border-l border-border/40 ml-2.5 my-0.5">
                                    {cat.items.map((item) => {
                                      const isItemActive =
                                        isSelected &&
                                        (activeKey === item.id || activeKey?.endsWith(`/${item.name}`));
                                      const title = getResourceDisplayTitle(item);

                                      return (
                                        <Tooltip
                                          key={item.id}
                                          onlyWhenTruncated
                                          side="right"
                                          sideOffset={8}
                                          delay={160}
                                          content={
                                            <div className="flex flex-col gap-0.5">
                                              <span className="text-[12px] font-semibold text-[var(--text-pri)]">{title}</span>
                                              <span className="text-[11px] font-mono text-[var(--text-dim)]">
                                                {item.group ? `${item.group}/${item.version}` : item.version || 'v1'}
                                              </span>
                                            </div>
                                          }
                                        >
                                          <button
                                            type="button"
                                            onClick={() => {
                                              if (!isSelected) onSelectCluster?.(c);
                                              onNavigate?.({ ...item, clusterId: c.id });
                                            }}
                                            className={`w-full flex items-center gap-1.5 px-2 py-0.5 rounded text-left transition-colors text-[12px] truncate ${
                                              isItemActive
                                                ? 'bg-accent/15 text-accent font-medium border border-accent/30'
                                                : 'text-text-mut hover:text-text-pri hover:bg-surface border border-transparent'
                                            }`}
                                          >
                                            <span data-truncate className="truncate flex-1">
                                              {title}
                                            </span>
                                          </button>
                                        </Tooltip>
                                      );
                                    })}
                                  </div>
                                )}
                              </div>
                            );
                          })}

                          {/* Middle Standalone items: Namespaces, Events */}
                          {filteredNav.middle.map((item) => {
                            const Icon = item.icon || Box;
                            const isItemActive =
                              isSelected && (activeKey === item.id || activeKey?.endsWith(`/${item.name}`));
                            const title = getResourceDisplayTitle(item);

                            return (
                              <Tooltip key={item.id} onlyWhenTruncated side="right" sideOffset={8} delay={160} content={title}>
                                <button
                                  type="button"
                                  onClick={() => {
                                    if (!isSelected) onSelectCluster?.(c);
                                    onNavigate?.({ ...item, clusterId: c.id });
                                  }}
                                  className={`w-full flex items-center gap-2 px-2 py-0.5 rounded-md text-left transition-colors truncate text-[12px] ${
                                    isItemActive
                                      ? 'bg-accent/15 text-accent font-medium border border-accent/30'
                                      : 'text-text-mut hover:text-text-pri hover:bg-surface border border-transparent'
                                  }`}
                                >
                                  <Icon size={13} className="shrink-0 opacity-80" />
                                  <span data-truncate className="truncate flex-1">{title}</span>
                                </button>
                              </Tooltip>
                            );
                          })}

                          {/* Bottom Standalone items: Cost Monitoring */}
                          {filteredNav.bottom.map((item) => {
                            const Icon = item.icon || Box;
                            const isItemActive =
                              isSelected && (activeKey === item.id || activeKey?.endsWith(`/${item.name}`));
                            const title = getResourceDisplayTitle(item);

                            return (
                              <Tooltip key={item.id} onlyWhenTruncated side="right" sideOffset={8} delay={160} content={title}>
                                <button
                                  type="button"
                                  onClick={() => {
                                    if (!isSelected) onSelectCluster?.(c);
                                    onNavigate?.({ ...item, clusterId: c.id });
                                  }}
                                  className={`w-full flex items-center gap-2 px-2 py-0.5 rounded-md text-left transition-colors truncate text-[12px] ${
                                    isItemActive
                                      ? 'bg-accent/15 text-accent font-medium border border-accent/30'
                                      : 'text-text-mut hover:text-text-pri hover:bg-surface border border-transparent'
                                  }`}
                                >
                                  <Icon size={13} className="shrink-0 opacity-80" />
                                  <span data-truncate className="truncate flex-1">{title}</span>
                                  {item.badge && (
                                    <span className="text-[9px] px-1 py-0.2 rounded bg-accent/20 text-accent font-semibold uppercase tracking-wider shrink-0">
                                      {item.badge}
                                    </span>
                                  )}
                                </button>
                              </Tooltip>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
