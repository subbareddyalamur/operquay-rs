import { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, GitBranch, RefreshCw, ShieldAlert } from 'lucide-react';
import { Badge, Button } from '@/components/primitives';
import { api } from '@/lib/api';

export interface AccessNode {
  id: string;
  label: string;
  kind: string;
  account_or_tenant: string;
  environment: string;
  is_admin_capability: boolean;
}

export interface AccessEdge {
  from: string;
  to: string;
  kind: string;
  label: string;
}

export interface AccessFinding {
  id: string;
  kind: 'shadow_admin' | 'cross_account_trust_loop' | 'unused_standing_privilege' | string;
  severity: string;
  title: string;
  description: string;
  node_ids: string[];
  remediation: string;
}

export interface PrincipalBlastRadius {
  principal_id: string;
  principal_label: string;
  principal_kind: string;
  reachable_resources: number;
  reachable_prod_resources: number;
  admin_paths: number;
  blast_score: number;
  sample_path: string[];
}

export interface AccessGraphReport {
  generated_at: number;
  summary: {
    total_nodes: number;
    total_edges: number;
    principals: number;
    shadow_admins: number;
    trust_loops: number;
    unused_standing_privileges: number;
  };
  nodes: AccessNode[];
  edges: AccessEdge[];
  findings: AccessFinding[];
  blast_radius: PrincipalBlastRadius[];
}

const COLUMN_X: Record<string, number> = {
  user: 90,
  ai_agent: 90,
  group: 270,
  role: 450,
  cloud_role: 450,
  instance: 660,
  k8s_cluster: 660,
  database: 660,
  hybrid_host: 660,
};

export function AccessGraphPanel() {
  const [report, setReport] = useState<AccessGraphReport | null>(null);
  const [selectedPrincipal, setSelectedPrincipal] = useState<PrincipalBlastRadius | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    const res = await api.get<AccessGraphReport>('/api/access-graph');
    if (res.ok) {
      setReport(res.data);
      setSelectedPrincipal((prev) =>
        prev ? res.data.blast_radius.find((b) => b.principal_id === prev.principal_id) ?? res.data.blast_radius[0] ?? null : res.data.blast_radius[0] ?? null,
      );
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const layoutNodes = useMemo(() => {
    if (!report) return [];
    const buckets: Record<number, AccessNode[]> = {};
    for (const node of report.nodes.slice(0, 32)) {
      const col = COLUMN_X[node.kind] ?? 360;
      buckets[col] = buckets[col] ?? [];
      buckets[col].push(node);
    }
    const positioned: Array<AccessNode & { x: number; y: number }> = [];
    for (const [colStr, list] of Object.entries(buckets)) {
      const x = Number(colStr);
      list.forEach((n, idx) => {
        positioned.push({ ...n, x, y: 42 + idx * 48 });
      });
    }
    return positioned;
  }, [report]);

  const nodeCoords = useMemo(() => {
    const map = new Map<string, { x: number; y: number }>();
    for (const n of layoutNodes) {
      map.set(n.id, { x: n.x, y: n.y });
    }
    return map;
  }, [layoutNodes]);

  const svgHeight = useMemo(
    () => Math.max(240, layoutNodes.reduce((acc, n) => Math.max(acc, n.y + 44), 240)),
    [layoutNodes],
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <GitBranch size={18} className="text-accent" />
          <div>
            <h3 className="text-sm font-semibold text-text-pri">Unified Identity &amp; Blast-Radius Access Graph</h3>
            <p className="text-xs text-text-mut">Graph reachability and Tarjan SCC loop analysis across users, AI agents, IAM/Entra/GCP roles, VMs, databases, and Kubernetes clusters.</p>
          </div>
        </div>
        <Button size="sm" variant="ghost" icon={<RefreshCw size={13} />} onClick={() => void load()} disabled={loading}>
          Recompute Graph
        </Button>
      </div>

      {report && (
        <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="rounded-lg border border-border bg-surface p-3">
              <p className="text-[11px] uppercase tracking-wide text-text-mut">Principals</p>
              <p className="mt-1 text-xl font-semibold text-text-pri tabular-nums">{report.summary.principals}</p>
            </div>
            <div className="rounded-lg border border-border bg-surface p-3">
              <p className="text-[11px] uppercase tracking-wide text-text-mut">Shadow Admins</p>
              <p className="mt-1 text-xl font-semibold text-warn tabular-nums">{report.summary.shadow_admins}</p>
            </div>
            <div className="rounded-lg border border-border bg-surface p-3">
              <p className="text-[11px] uppercase tracking-wide text-text-mut">Trust Loops (SCC)</p>
              <p className="mt-1 text-xl font-semibold text-danger tabular-nums">{report.summary.trust_loops}</p>
            </div>
            <div className="rounded-lg border border-border bg-surface p-3">
              <p className="text-[11px] uppercase tracking-wide text-text-mut">Unused Standing</p>
              <p className="mt-1 text-xl font-semibold text-accent tabular-nums">{report.summary.unused_standing_privileges}</p>
            </div>
          </div>

          <div className="rounded-lg border border-border bg-surface p-3 overflow-x-auto">
            <svg viewBox={`0 0 780 ${svgHeight}`} className="w-full min-w-[640px] h-auto" role="img" aria-label="Identity and resource access graph">
              {report.edges.slice(0, 80).map((edge, idx) => {
                const a = nodeCoords.get(edge.from);
                const b = nodeCoords.get(edge.to);
                if (!a || !b) return null;
                return (
                  <line
                    key={`${edge.from}-${edge.to}-${idx}`}
                    x1={a.x}
                    y1={a.y}
                    x2={b.x}
                    y2={b.y}
                    stroke="var(--border)"
                    strokeWidth={1.5}
                    strokeOpacity={0.85}
                  />
                );
              })}
              {layoutNodes.map((node) => {
                const fillVar = node.is_admin_capability
                  ? 'var(--danger)'
                  : node.kind === 'user' || node.kind === 'ai_agent'
                    ? 'var(--accent)'
                    : 'var(--bg-elev)';
                return (
                  <g key={node.id} transform={`translate(${node.x},${node.y})`}>
                    <rect
                      x={-68}
                      y={-15}
                      width={136}
                      height={30}
                      rx={6}
                      fill={fillVar}
                      fillOpacity={node.is_admin_capability ? 0.18 : 1}
                      stroke="var(--border)"
                      strokeWidth={1.2}
                    />
                    <text
                      textAnchor="middle"
                      dominantBaseline="central"
                      fill="var(--text-pri)"
                      fontSize={10}
                      fontFamily="monospace"
                    >
                      {node.label.slice(0, 18)}
                    </text>
                  </g>
                );
              })}
            </svg>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <div className="space-y-2">
              <div className="flex items-center gap-1.5">
                <AlertTriangle size={14} className="text-warn" />
                <h4 className="text-xs font-semibold uppercase tracking-wide text-text-sec">
                  Security Findings ({report.findings.length})
                </h4>
              </div>
              {report.findings.length === 0 ? (
                <p className="text-xs text-text-mut rounded-lg border border-border bg-surface p-4">
                  Zero Shadow Admin paths, circular cross-account trust loops, or stale standing privileges detected.
                </p>
              ) : (
                <div className="space-y-2">
                  {report.findings.map((f) => (
                    <div key={f.id} className="rounded-lg border border-border bg-surface p-3 space-y-1">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-semibold text-text-pri">{f.title}</span>
                        <Badge variant={f.severity === 'critical' || f.severity === 'high' ? 'danger' : 'warn'}>
                          {f.severity}
                        </Badge>
                      </div>
                      <p className="text-xs text-text-sec">{f.description}</p>
                      <p className="text-[11px] text-accent">{f.remediation}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="space-y-2">
              <div className="flex items-center gap-1.5">
                <ShieldAlert size={14} className="text-accent" />
                <h4 className="text-xs font-semibold uppercase tracking-wide text-text-sec">
                  Principal Blast Radius ({report.blast_radius.length})
                </h4>
              </div>
              <div className="rounded-lg border border-border bg-surface divide-y divide-border">
                {report.blast_radius.map((br) => {
                  const selected = selectedPrincipal?.principal_id === br.principal_id;
                  return (
                    <button
                      type="button"
                      key={br.principal_id}
                      onClick={() => setSelectedPrincipal(br)}
                      className={`w-full text-left p-3 flex items-center justify-between gap-2 hover:bg-elev transition-colors ${selected ? 'bg-[var(--accent-dim)]' : ''}`}
                    >
                      <div className="min-w-0">
                        <p className="text-xs font-semibold text-text-pri truncate">{br.principal_label}</p>
                        <p className="text-[11px] text-text-mut">
                          {br.principal_kind} · {br.reachable_resources} resources ({br.reachable_prod_resources} prod)
                        </p>
                      </div>
                      <Badge variant={br.blast_score >= 60 ? 'danger' : br.blast_score >= 25 ? 'warn' : 'success'}>
                        Score {br.blast_score}
                      </Badge>
                    </button>
                  );
                })}
              </div>
              {selectedPrincipal && selectedPrincipal.sample_path.length > 0 && (
                <div className="rounded-lg border border-border bg-elev p-3 space-y-1">
                  <p className="text-[11px] uppercase tracking-wide text-text-mut">Sample Privilege Path</p>
                  <p className="text-xs font-mono text-text-pri break-all">
                    {selectedPrincipal.sample_path.join(' -> ')}
                  </p>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
