import { useCallback, useEffect, useRef, useState } from 'react';
import { AlertTriangle, Download, Network, Route, ShieldAlert, Sparkles } from 'lucide-react';
import { Badge, Button, Card } from '@/design-system/primitives';
import { apiJson, type VpcTopology } from '../platform/api';

export function VpcTopologyWorkspace({ initialVpcId }: { initialVpcId: string }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [vpcId, setVpcId] = useState(initialVpcId || 'vpc-main');
  const [topo, setTopo] = useState<VpcTopology | null>(null);
  const [deepSummary, setDeepSummary] = useState<{ graph_nodes: number; graph_edges: number } | null>(null);
  const [sourceId, setSourceId] = useState('');
  const [destId, setDestId] = useState('0.0.0.0');
  const [port, setPort] = useState(443);
  const [reachResult, setReachResult] = useState<{
    reachable: boolean;
    hops: Array<{ component: string; status: string; detail: string }>;
    issues: string[];
  } | null>(null);
  const [exposure, setExposure] = useState<{
    exposedInstances: Array<{ instanceId: string; publicIp: string }>;
    exposedPorts: Array<{ instanceId: string; port: number; severity: string }>;
  } | null>(null);
  const [conflicts, setConflicts] = useState<Array<{ type: string; description: string; severity: string }>>([]);
  const [err, setErr] = useState<string | null>(null);

  const loadVpc = useCallback(async (id: string) => {
    setErr(null);
    try {
      const [t, exp, conf] = await Promise.all([
        apiJson<VpcTopology>(`/topology/${encodeURIComponent(id)}`),
        apiJson<typeof exposure>(`/topology/${encodeURIComponent(id)}/exposure`),
        apiJson<typeof conflicts>(`/topology/${encodeURIComponent(id)}/conflicts`),
      ]);
      setTopo(t);
      setExposure(exp);
      setConflicts(conf);
      if (t.instances[0]) setSourceId((prev) => prev || t.instances[0].id);
    } catch (e) {
      setTopo(null);
      setErr(e instanceof Error ? e.message : 'VPC topology not seeded or scanned yet');
    }
  }, []);

  useEffect(() => {
    void loadVpc(initialVpcId || 'vpc-main');
  }, [initialVpcId, loadVpc]);

  const analyzePath = async () => {
    setErr(null);
    try {
      const res = await apiJson<NonNullable<typeof reachResult>>('/topology/reachability', {
        method: 'POST',
        body: JSON.stringify({ vpc_id: vpcId, source_id: sourceId, dest_id: destId, protocol: 'tcp', port: Number(port) }),
      });
      setReachResult(res);
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Reachability analysis failed');
    }
  };

  const runDeepAnalyze = async () => {
    setErr(null);
    try {
      const res = await apiJson<{ graph_nodes: number; graph_edges: number }>('/api/aws/topology/deep-analyze', {
        method: 'POST',
        body: JSON.stringify({ vpc_id: vpcId }),
      });
      setDeepSummary(res);
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Deep topology analysis failed');
    }
  };

  const exportTopology = (kind: 'svg' | 'json') => {
    if (!topo) return;
    const content =
      kind === 'svg' && svgRef.current
        ? svgRef.current.outerHTML
        : JSON.stringify(topo, null, 2);
    const blob = new Blob([content], { type: kind === 'svg' ? 'image/svg+xml' : 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `topology-${topo.vpc.id}.${kind}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-6xl mx-auto px-6 py-6 space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-4">
        <div>
          <h1 className="text-[20px] font-semibold text-text-pri tracking-[-0.02em]">
            VPC Network Topology Graph &amp; Reachability Analyzer
          </h1>
          <p className="mt-1 text-xs text-text-mut">
            `petgraph` directed path verification across Security Groups, Subnet NACLs, Longest-Prefix Route Tables, IGW, and VPC Peerings.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <input
            aria-label="VPC ID"
            value={vpcId}
            onChange={(e) => setVpcId(e.target.value)}
            className="h-8 w-40 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-pri font-mono"
          />
          <Button size="sm" onClick={() => void loadVpc(vpcId)} icon={<Network size={14} aria-hidden="true" />}>
            Load Topology
          </Button>
          <Button size="sm" variant="outline" onClick={() => void runDeepAnalyze()} icon={<Sparkles size={14} aria-hidden="true" />}>
            Deep Analyze
          </Button>
          {topo && (
            <>
              <Button size="sm" variant="outline" onClick={() => exportTopology('svg')} icon={<Download size={14} aria-hidden="true" />}>
                SVG
              </Button>
              <Button size="sm" variant="outline" onClick={() => exportTopology('json')} icon={<Download size={14} aria-hidden="true" />}>
                JSON
              </Button>
            </>
          )}
        </div>
      </div>

      {deepSummary && (
        <div className="px-4 py-2 rounded-[var(--radius-sm)] border border-border bg-[var(--accent-dim)] text-xs text-accent tabular-mono">
          Petgraph Deep Analysis: {deepSummary.graph_nodes} graph nodes · {deepSummary.graph_edges} evaluated policy edges
        </div>
      )}

      {err && (
        <div className="px-4 py-2.5 rounded-[var(--radius-sm)] border border-border bg-[var(--warn-dim)] text-xs text-warn">
          {err}
        </div>
      )}

      {topo && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <Card className="lg:col-span-8 p-4 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-text-pri">{topo.vpc.name || topo.vpc.id} ({topo.vpc.cidr})</span>
              <div className="flex gap-2">
                <Badge tone="neutral">{topo.subnets.length} subnets</Badge>
                <Badge tone="accent">{topo.instances.length} instances</Badge>
              </div>
            </div>
            <svg ref={svgRef} viewBox="0 0 720 260" className="w-full h-64 rounded-[var(--radius-md)] border border-border bg-elev" role="img" aria-label={`VPC Topology Diagram for ${topo.vpc.id}`}>
              <rect x="20" y="16" width="680" height="40" rx="8" fill="var(--surface)" stroke="var(--accent)" strokeWidth="1.5" />
              <text x="36" y="40" fill="var(--text-pri)" fontSize="12" fontWeight="600">
                VPC: {topo.vpc.id} · CIDR {topo.vpc.cidr} · IGW: {topo.internetGateways.length}
              </text>
              {topo.instances.slice(0, 6).map((inst, idx) => {
                const x = 32 + idx * 112;
                const y = 110;
                return (
                  <g key={inst.id}>
                    <line x1="360" y1="56" x2={x + 48} y2={y} stroke="var(--border-strong)" strokeWidth="1.5" />
                    <rect x={x} y={y} width="96" height="68" rx="8" fill="var(--surface)" stroke={inst.publicIp ? 'var(--warn)' : 'var(--accent)'} strokeWidth="1.5" />
                    <text x={x + 8} y={y + 22} fill="var(--text-pri)" fontSize="11" fontWeight="600">{inst.name.slice(0, 12)}</text>
                    <text x={x + 8} y={y + 40} fill="var(--text-mut)" fontSize="10">{inst.privateIp}</text>
                    <text x={x + 8} y={y + 56} fill="var(--text-dim)" fontSize="9">{inst.publicIp || 'private'}</text>
                  </g>
                );
              })}
            </svg>
          </Card>

          <Card className="lg:col-span-4 p-4 space-y-3 text-xs">
            <div className="flex items-center gap-2 font-semibold text-text-pri">
              <Route size={14} className="text-accent" aria-hidden="true" />
              Trace Packet Path
            </div>
            <input aria-label="Source Instance ID" value={sourceId} onChange={(e) => setSourceId(e.target.value)} placeholder="Source instance (e.g. i-a)" className="w-full h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri" />
            <input aria-label="Destination IP or Instance" value={destId} onChange={(e) => setDestId(e.target.value)} placeholder="Dest instance or IP" className="w-full h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri" />
            <div className="flex gap-2">
              <input aria-label="TCP port" type="number" value={port} onChange={(e) => setPort(Number(e.target.value))} className="w-24 h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri" />
              <Button size="xs" onClick={() => void analyzePath()}>Trace Path</Button>
            </div>
            {reachResult && (
              <div className="space-y-1.5 pt-2 border-t border-border">
                <Badge tone={reachResult.reachable ? 'success' : 'danger'}>
                  {reachResult.reachable ? 'REACHABLE' : 'BLOCKED'}
                </Badge>
                {reachResult.hops.map((h, i) => (
                  <div key={i} className="p-2 rounded-[var(--radius-sm)] bg-elev border border-border">
                    <span className="font-semibold text-text-pri">{h.component}: </span>
                    <span className="text-text-mut">{h.detail}</span>
                  </div>
                ))}
              </div>
            )}
          </Card>

          {exposure && (
            <Card className="lg:col-span-6 p-4 space-y-2 text-xs">
              <div className="flex items-center gap-2 font-semibold text-text-pri">
                <ShieldAlert size={14} className="text-warn" aria-hidden="true" />
                Internet Exposure ({exposure.exposedInstances.length} public instances)
              </div>
              {exposure.exposedPorts.map((p, idx) => (
                <div key={idx} className="py-1 flex justify-between border-b border-border">
                  <span>{p.instanceId} · port {p.port}</span>
                  <Badge tone={p.severity === 'high' ? 'danger' : 'warn'}>{p.severity}</Badge>
                </div>
              ))}
            </Card>
          )}

          <Card className="lg:col-span-6 p-4 space-y-2 text-xs">
            <div className="flex items-center gap-2 font-semibold text-text-pri">
              <AlertTriangle size={14} className="text-danger" aria-hidden="true" />
              Firewall &amp; NACL Rule Conflicts ({conflicts.length})
            </div>
            {conflicts.map((c, idx) => (
              <div key={idx} className="p-2 rounded-[var(--radius-sm)] border border-border bg-elev">
                <div className="font-medium text-text-pri">{c.type}</div>
                <div className="text-text-mut">{c.description}</div>
              </div>
            ))}
          </Card>
        </div>
      )}
    </div>
  );
}
