import { useCallback, useEffect, useState } from 'react';
import { Activity, Copy, Network, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { Badge, Button, Input } from '@/components/primitives';
import { api } from '@/lib/api';
import { useToastStore } from '@/stores/toast';

export interface HybridAgentTarget {
  protocol: string;
  host: string;
  port: number;
}

export interface HybridAgentRow {
  id: string;
  name: string;
  cert_fingerprint_sha256: string;
  hostname: string;
  os: string;
  arch: string;
  targets: HybridAgentTarget[];
  status: string;
  online: boolean;
  last_heartbeat_at?: number | null;
  created_at: number;
}

export function HybridAgentsPanel() {
  const pushToast = useToastStore((s) => s.push);
  const [agents, setAgents] = useState<HybridAgentRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);

  const [name, setName] = useState('');
  const [protocol, setProtocol] = useState('ssh');
  const [targetHost, setTargetHost] = useState('127.0.0.1');
  const [targetPort, setTargetPort] = useState('22');
  const [enrolledCmd, setEnrolledCmd] = useState<{ token: string; command: string } | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    const res = await api.get<{ agents: HybridAgentRow[] }>('/api/agents');
    if (res.ok) {
      setAgents(res.data.agents ?? []);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const handleEnroll = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    const res = await api.post<{
      agent: HybridAgentRow;
      enrollment_token: string;
      run_command: string;
    }>('/api/agents/enroll', {
      name: name.trim(),
      targets: [
        {
          protocol: protocol.trim() || 'ssh',
          host: targetHost.trim() || '127.0.0.1',
          port: Math.max(1, Math.min(65535, Number(targetPort) || 22)),
        },
      ],
    });
    setBusy(false);
    if (!res.ok) {
      pushToast({ title: res.error?.message || 'Failed enrolling hybrid agent', variant: 'danger' });
      return;
    }
    setEnrolledCmd({ token: res.data.enrollment_token, command: res.data.run_command });
    setName('');
    pushToast({ title: `Enrolled hybrid agent "${res.data.agent.name}"`, variant: 'success' });
    void load();
  };

  const handleDialCheck = async (ag: HybridAgentRow) => {
    const first = ag.targets[0];
    if (!first) return;
    setBusy(true);
    const res = await api.post<{ ok: boolean; response: string }>(`/api/agents/${encodeURIComponent(ag.id)}/dial-check`, {
      target: `${first.host}:${first.port}`,
    });
    setBusy(false);
    if (!res.ok) {
      pushToast({ title: res.error?.message || 'Tunnel dial check failed', variant: 'danger' });
      return;
    }
    pushToast({ title: `Mux tunnel dial OK (${first.host}:${first.port})`, variant: 'success' });
  };

  const handleDelete = async (id: string, agentName: string) => {
    setBusy(true);
    const res = await api.delete(`/api/agents/${encodeURIComponent(id)}`);
    setBusy(false);
    if (!res.ok) {
      pushToast({ title: res.error?.message || 'Failed removing agent', variant: 'danger' });
      return;
    }
    pushToast({ title: `Removed hybrid agent "${agentName}"`, variant: 'warn' });
    void load();
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Network size={18} className="text-accent" />
          <div>
            <h3 className="text-sm font-semibold text-text-pri">Zero-Inbound Hybrid Reverse-Tunnel Agents</h3>
            <p className="text-xs text-text-mut">Bridge on-prem datacenters and private VPCs via outbound WebSocket / mTLS 1.3 tunnels without opening inbound firewall ports.</p>
          </div>
        </div>
        <Button size="sm" variant="ghost" icon={<RefreshCw size={13} />} onClick={() => void load()} disabled={loading}>
          Refresh
        </Button>
      </div>

      {enrolledCmd && (
        <div className="rounded-lg border border-accent/40 bg-[var(--accent-dim)] p-4 space-y-2">
          <p className="text-xs font-semibold text-text-pri">One-Time Enrollment Command (copy to private host)</p>
          <div className="flex flex-wrap items-center gap-2">
            <code className="flex-1 px-2.5 py-1.5 rounded bg-bg border border-border text-xs font-mono text-text-pri break-all">
              {enrolledCmd.command}
            </code>
            <Button
              size="xs"
              variant="secondary"
              icon={<Copy size={12} />}
              onClick={() => {
                void navigator.clipboard?.writeText(enrolledCmd.command);
                pushToast({ title: 'Command copied', variant: 'info' });
              }}
            >
              Copy
            </Button>
          </div>
        </div>
      )}

      <form onSubmit={(e) => void handleEnroll(e)} className="rounded-lg border border-border bg-surface p-4 space-y-3">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-text-sec">Enroll Outbound Agent</h4>
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
          <div>
            <label className="block text-xs text-text-mut mb-1" htmlFor="agent-name">Agent Name</label>
            <Input
              id="agent-name"
              placeholder="dc-01-bastion"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>
          <div>
            <label className="block text-xs text-text-mut mb-1" htmlFor="agent-proto">Target Protocol</label>
            <Input
              id="agent-proto"
              value={protocol}
              onChange={(e) => setProtocol(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs text-text-mut mb-1" htmlFor="agent-host">Target Host</label>
            <Input
              id="agent-host"
              value={targetHost}
              onChange={(e) => setTargetHost(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs text-text-mut mb-1" htmlFor="agent-port">Target Port</label>
            <Input
              id="agent-port"
              type="number"
              min="1"
              max="65535"
              value={targetPort}
              onChange={(e) => setTargetPort(e.target.value)}
            />
          </div>
        </div>
        <div className="flex justify-end">
          <Button type="submit" size="sm" icon={<Plus size={14} />} loading={busy}>
            Enroll Hybrid Agent
          </Button>
        </div>
      </form>

      <div className="space-y-2">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-text-sec">
          Enrolled Agents ({agents.length})
        </h4>
        {agents.length === 0 ? (
          <p className="text-xs text-text-mut rounded-lg border border-border bg-surface p-4">
            No hybrid tunnel agents enrolled yet.
          </p>
        ) : (
          <div className="rounded-lg border border-border bg-surface divide-y divide-border">
            {agents.map((ag) => (
              <div key={ag.id} className="p-3.5 flex flex-wrap items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-text-pri">{ag.name}</span>
                    <Badge variant={ag.online ? 'success' : 'default'}>
                      {ag.online ? 'online' : ag.status}
                    </Badge>
                    {ag.hostname && (
                      <span className="text-xs text-text-mut font-mono">
                        {ag.hostname} ({ag.os}/{ag.arch})
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] font-mono text-text-sec">
                    Targets: {ag.targets.map((t) => `${t.protocol}://${t.host}:${t.port}`).join(', ') || 'none'}
                    {ag.cert_fingerprint_sha256 ? ` · mTLS SHA-256: ${ag.cert_fingerprint_sha256.slice(0, 16)}…` : ''}
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  {ag.online && ag.targets.length > 0 && (
                    <Button
                      size="xs"
                      variant="secondary"
                      icon={<Activity size={12} />}
                      onClick={() => void handleDialCheck(ag)}
                      disabled={busy}
                    >
                      Test Dial
                    </Button>
                  )}
                  <Button
                    size="xs"
                    variant="danger-ghost"
                    icon={<Trash2 size={12} />}
                    onClick={() => void handleDelete(ag.id, ag.name)}
                    disabled={busy}
                  >
                    Delete
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
