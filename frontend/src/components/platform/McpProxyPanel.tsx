import { useCallback, useEffect, useState } from 'react';
import { Bot, Copy, Plus, RefreshCw, ShieldAlert, Trash2 } from 'lucide-react';
import { Badge, Button, Input } from '@/components/primitives';
import { api } from '@/lib/api';
import { useToastStore } from '@/stores/toast';

export interface McpAgentRow {
  id: string;
  name: string;
  sponsor_user_id: string;
  sponsor_email: string;
  allowed_tools: string[];
  require_jit_tools: string[];
  rate_limit_per_min: number;
  status: string;
  expires_at: number;
  created_at: number;
  revoked_at?: number | null;
}

export interface McpInvocationRow {
  id: string;
  agent_id: string;
  sponsor_user_id: string;
  tool_name: string;
  sanitized_args: string;
  decision: string;
  jit_request_id?: string | null;
  masked_result_preview: string;
  duration_ms: number;
  created_at: number;
}

const KNOWN_MCP_TOOLS = [
  'operquay.instances.list',
  'operquay.db.query',
  'operquay.db.mutate',
  'operquay.k8s.pods',
  'operquay.aws.topology_summary',
];

export function McpProxyPanel() {
  const pushToast = useToastStore((s) => s.push);
  const [agents, setAgents] = useState<McpAgentRow[]>([]);
  const [invocations, setInvocations] = useState<McpInvocationRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  const [name, setName] = useState('');
  const [allowedTools, setAllowedTools] = useState<string[]>([
    'operquay.instances.list',
    'operquay.db.query',
  ]);
  const [jitTools, setJitTools] = useState<string[]>(['operquay.db.mutate']);
  const [rateLimit, setRateLimit] = useState('60');
  const [ttlHours, setTtlHours] = useState('24');
  const [mintedToken, setMintedToken] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const [agRes, invRes] = await Promise.all([
      api.get<{ agents: McpAgentRow[] }>('/api/mcp/agents'),
      api.get<{ invocations: McpInvocationRow[] }>('/api/mcp/invocations'),
    ]);
    if (agRes.ok) {
      setAgents(agRes.data.agents ?? []);
    }
    if (invRes.ok) {
      setInvocations(invRes.data.invocations ?? []);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const toggleItem = (list: string[], setList: (next: string[]) => void, item: string) => {
    setList(list.includes(item) ? list.filter((t) => t !== item) : [...list, item]);
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    const res = await api.post<{ agent: McpAgentRow; token: string }>('/api/mcp/agents', {
      name: name.trim(),
      allowed_tools: allowedTools,
      require_jit_tools: jitTools,
      rate_limit_per_min: Math.max(1, Number(rateLimit) || 60),
      ttl_secs: Math.max(1, Number(ttlHours) || 24) * 3600,
    });
    setBusy(false);
    if (!res.ok) {
      pushToast({ title: res.error?.message || 'Failed creating MCP agent', variant: 'danger' });
      return;
    }
    setMintedToken(res.data.token);
    setName('');
    pushToast({ title: `Minted sponsor-bound MCP agent "${res.data.agent.name}"`, variant: 'success' });
    void load();
  };

  const handleRevoke = async (id: string, agentName: string) => {
    setBusy(true);
    const res = await api.delete(`/api/mcp/agents/${encodeURIComponent(id)}`);
    setBusy(false);
    if (!res.ok) {
      pushToast({ title: res.error?.message || 'Failed revoking agent', variant: 'danger' });
      return;
    }
    pushToast({ title: `Revoked MCP agent "${agentName}"`, variant: 'warn' });
    void load();
  };

  const copyToken = async (txt: string) => {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(txt);
      pushToast({ title: 'Copied to clipboard', variant: 'info' });
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Bot size={18} className="text-accent" />
          <div>
            <h3 className="text-sm font-semibold text-text-pri">AI Agent &amp; MCP Governance Proxy (ISO 42001)</h3>
            <p className="text-xs text-text-mut">Issue short-lived sponsor-bound oqmcp_ tokens with per-tool RBAC, JIT escalation, and automatic DB PII/secret scrubbing.</p>
          </div>
        </div>
        <Button size="sm" variant="ghost" icon={<RefreshCw size={13} />} onClick={() => void load()} disabled={loading}>
          Refresh
        </Button>
      </div>

      {mintedToken && (
        <div className="rounded-lg border border-accent/40 bg-[var(--accent-dim)] p-4 space-y-2">
          <p className="text-xs font-semibold text-text-pri">One-Time MCP Bearer Token (save now — never shown again)</p>
          <div className="flex flex-wrap items-center gap-2">
            <code className="flex-1 px-2.5 py-1.5 rounded bg-bg border border-border text-xs font-mono text-text-pri break-all">
              {mintedToken}
            </code>
            <Button size="xs" variant="secondary" icon={<Copy size={12} />} onClick={() => void copyToken(mintedToken)}>
              Copy token
            </Button>
          </div>
          <p className="text-[11px] font-mono text-text-sec break-all">
            operquay mcp --server {window.location.origin} --token {mintedToken}
          </p>
        </div>
      )}

      <form onSubmit={(e) => void handleCreate(e)} className="rounded-lg border border-border bg-surface p-4 space-y-4">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-text-sec">Mint New AI Agent Identity</h4>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <label className="block text-xs text-text-mut mb-1" htmlFor="mcp-agent-name">Agent Name</label>
            <Input
              id="mcp-agent-name"
              placeholder="e.g. claude-desktop-ops"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>
          <div>
            <label className="block text-xs text-text-mut mb-1" htmlFor="mcp-rate-limit">Rate Limit (req/min)</label>
            <Input
              id="mcp-rate-limit"
              type="number"
              min="1"
              max="600"
              value={rateLimit}
              onChange={(e) => setRateLimit(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs text-text-mut mb-1" htmlFor="mcp-ttl-hours">Token TTL (hours)</label>
            <Input
              id="mcp-ttl-hours"
              type="number"
              min="1"
              max="720"
              value={ttlHours}
              onChange={(e) => setTtlHours(e.target.value)}
            />
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <p className="text-xs font-medium text-text-sec mb-2">Allowed Tools (Auto-DLP Redacted)</p>
            <div className="space-y-1.5">
              {KNOWN_MCP_TOOLS.map((tool) => (
                <label key={`allow-${tool}`} className="flex items-center gap-2 text-xs text-text-pri cursor-pointer">
                  <input
                    type="checkbox"
                    checked={allowedTools.includes(tool)}
                    onChange={() => toggleItem(allowedTools, setAllowedTools, tool)}
                  />
                  <span className="font-mono">{tool}</span>
                </label>
              ))}
            </div>
          </div>
          <div>
            <p className="text-xs font-medium text-text-sec mb-2">Require Four-Eyes JIT Approval</p>
            <div className="space-y-1.5">
              {KNOWN_MCP_TOOLS.map((tool) => (
                <label key={`jit-${tool}`} className="flex items-center gap-2 text-xs text-text-pri cursor-pointer">
                  <input
                    type="checkbox"
                    checked={jitTools.includes(tool)}
                    onChange={() => toggleItem(jitTools, setJitTools, tool)}
                  />
                  <span className="font-mono">{tool}</span>
                </label>
              ))}
            </div>
          </div>
        </div>

        <div className="flex justify-end">
          <Button type="submit" size="sm" icon={<Plus size={14} />} loading={busy}>
            Issue MCP Token
          </Button>
        </div>
      </form>

      <div className="space-y-2">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-text-sec">
          Registered MCP Agents ({agents.length})
        </h4>
        {agents.length === 0 ? (
          <p className="text-xs text-text-mut rounded-lg border border-border bg-surface p-4">
            No MCP agents registered yet.
          </p>
        ) : (
          <div className="rounded-lg border border-border bg-surface divide-y divide-border">
            {agents.map((ag) => (
              <div key={ag.id} className="p-3.5 flex flex-wrap items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-text-pri">{ag.name}</span>
                    <Badge variant={ag.status === 'active' ? 'success' : 'danger'}>{ag.status}</Badge>
                    <span className="text-[11px] text-text-mut">Sponsor: {ag.sponsor_email}</span>
                  </div>
                  <p className="text-[11px] font-mono text-text-sec">
                    Allow: {ag.allowed_tools.join(', ') || 'none'} · JIT: {ag.require_jit_tools.join(', ') || 'none'} · {ag.rate_limit_per_min}/min
                  </p>
                </div>
                {ag.status === 'active' && (
                  <Button
                    size="xs"
                    variant="danger-ghost"
                    icon={<Trash2 size={12} />}
                    onClick={() => void handleRevoke(ag.id, ag.name)}
                    disabled={busy}
                  >
                    Revoke
                  </Button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="space-y-2">
        <div className="flex items-center gap-1.5">
          <ShieldAlert size={14} className="text-accent" />
          <h4 className="text-xs font-semibold uppercase tracking-wide text-text-sec">
            ISO 42001 Tool Invocation Audit Log ({invocations.length})
          </h4>
        </div>
        {invocations.length === 0 ? (
          <p className="text-xs text-text-mut rounded-lg border border-border bg-surface p-4">
            No MCP tool invocations recorded yet.
          </p>
        ) : (
          <div className="rounded-lg border border-border bg-surface overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-border bg-elev text-text-mut">
                <tr>
                  <th className="px-3 py-2">Tool</th>
                  <th className="px-3 py-2">Decision</th>
                  <th className="px-3 py-2">Sanitized Args</th>
                  <th className="px-3 py-2">Result Preview</th>
                  <th className="px-3 py-2">Latency</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border text-text-pri">
                {invocations.slice(0, 30).map((inv) => (
                  <tr key={inv.id}>
                    <td className="px-3 py-2 font-mono">{inv.tool_name}</td>
                    <td className="px-3 py-2">
                      <Badge variant={inv.decision === 'allowed' ? 'success' : inv.decision === 'jit_pending' ? 'warn' : 'danger'}>
                        {inv.decision}
                      </Badge>
                    </td>
                    <td className="px-3 py-2 font-mono text-[11px] text-text-sec max-w-[14rem] truncate">{inv.sanitized_args}</td>
                    <td className="px-3 py-2 font-mono text-[11px] text-text-mut max-w-[16rem] truncate">{inv.masked_result_preview}</td>
                    <td className="px-3 py-2 tabular-nums text-text-mut">{inv.duration_ms} ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
