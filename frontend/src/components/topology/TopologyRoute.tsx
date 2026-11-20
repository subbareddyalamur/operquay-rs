import { useState, Component, type ReactNode, type ErrorInfo } from 'react';
import { Loader2, AlertCircle, RefreshCw } from 'lucide-react';
import { TopologyCanvas } from './TopologyCanvas';
import { TopologySidePanel } from './TopologySidePanel';
import { useTopology, useInvalidateTopology, type UserTopologyScope } from '@/hooks/useTopology';
import type { TopoNode } from '@/lib/topology-types';
import { Button } from '@/components/primitives/Button';
import { UserDeepAnalysis } from './UserDeepAnalysis';
import { useAuthStore, hasPermission } from '@/stores/auth';
import { UserTopologyPeers } from './UserTopologyPeers';

export interface TopologyRouteProps {
  instanceId: string;
  userScope?: UserTopologyScope;
}

class TopologyErrorBoundary extends Component<
  { children: ReactNode; onReset?: () => void },
  { hasError: boolean; error: Error | null }
> {
  constructor(props: { children: ReactNode; onReset?: () => void }) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }
  override componentDidCatch(error: Error, info: ErrorInfo) {
    void info;
    void error;
  }
  override render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center h-full gap-3 text-text-dim">
          <AlertCircle size={28} className="text-danger" />
          <span className="text-sm font-semibold text-danger">Topology rendering error</span>
          <span className="text-xs text-text-dim max-w-sm text-center">
            {this.state.error?.message ?? 'Unknown error'}
          </span>
          <Button
            variant="outline"
            size="sm"
            icon={<RefreshCw size={13} />}
            onClick={() => {
              this.setState({ hasError: false, error: null });
              this.props.onReset?.();
            }}
          >
            Retry
          </Button>
        </div>
      );
    }
    return this.props.children;
  }
}

export function TopologyRoute({ instanceId, userScope }: TopologyRouteProps) {
  const [peerIDs, setPeerIDs] = useState<string[]>([]);
  return <div className="flex h-full min-h-0 flex-col">
    {userScope && <UserTopologyPeers roleID={userScope.roleID} selected={peerIDs} onChange={setPeerIDs} />}
    <div className="flex-1 min-h-0"><TopologyContent instanceId={instanceId} userScope={userScope ? { ...userScope, peerIDs } : undefined} /></div>
  </div>;
}

function TopologyContent({ instanceId, userScope }: TopologyRouteProps) {
  const canDeepTopology = useAuthStore((state) => !state.me || hasPermission(state.me, 'topology:deep'));
  const { data, isLoading, isRefetching, error } = useTopology(instanceId, userScope);
  const invalidate = useInvalidateTopology();
  const [selectedNode, setSelectedNode] = useState<TopoNode | null>(null);

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 text-text-dim">
        <Loader2 size={28} className="animate-spin text-accent" />
        <span className="text-sm">Loading topology…</span>
        <span className="text-xs text-text-dim">Fetching VPC, subnets, and security groups…</span>
      </div>
    );
  }

  if (error || !data) {
    const msg = error instanceof Error ? error.message : 'Failed to load topology';
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 text-danger">
        <AlertCircle size={28} />
        <span className="text-sm font-semibold">Topology unavailable</span>
        <span className="text-xs text-text-dim max-w-sm text-center">{msg}</span>
        <Button
          variant="outline"
          size="sm"
          icon={<RefreshCw size={13} />}
          onClick={() => invalidate(instanceId)}
        >
          Retry
        </Button>
      </div>
    );
  }

  return (
    <TopologyErrorBoundary onReset={() => invalidate(instanceId)}>
      <div className="flex h-full overflow-hidden">
        <div className="flex-1 min-w-0 flex flex-col">
          {data.warnings && data.warnings.length > 0 && <div role="status" className="px-3 py-2 text-sm text-warn bg-surface border-b border-border">
            {data.warnings.map(warning => <p key={warning}>{warning}</p>)}
          </div>}
          {userScope && canDeepTopology && <UserDeepAnalysis instanceId={instanceId} scope={userScope} />}
          <div className="flex items-center justify-between gap-2 border-b border-border bg-surface px-3 py-1 text-xs text-text-mut">
            <span>Topology · relationships show configuration, not confirmed reachability</span>
          </div>
          <div className="flex-1 min-h-0">
            <TopologyCanvas
              topology={data}
              instanceId={instanceId}
              onSelectNode={setSelectedNode}
              onRefresh={() => invalidate(instanceId)}
              isRefreshing={isRefetching}
            />
          </div>
        </div>
        {selectedNode && (
          <TopologySidePanel node={selectedNode} onClose={() => setSelectedNode(null)} />
        )}
      </div>
    </TopologyErrorBoundary>
  );
}

TopologyRoute.displayName = 'TopologyRoute';
