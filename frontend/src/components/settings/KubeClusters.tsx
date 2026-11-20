import { useEffect, useState } from 'react';
import { Boxes, Plus } from 'lucide-react';
import { api } from '@/lib/api';
import { Badge, Button, ConfirmDialog, EmptyState, Input, Select } from '@/components/primitives';

export interface KubeCluster { id: string; label: string; proxy: string; cluster_name: string; method: 'local' | 'sso'; connector: string; recording_mode?: 'default' | 'off' | 'all' | 'selected' }
type ClusterForm = Omit<KubeCluster, 'id' | 'recording_mode'>;
const empty: ClusterForm = { label: '', proxy: '', cluster_name: '', method: 'local', connector: '' };

export function KubeClusters() {
  const [clusters, setClusters] = useState<KubeCluster[] | null>(null);
  const [form, setForm] = useState<ClusterForm | null>(null);
  const [editing, setEditing] = useState('');
  const [pendingRemoveCluster, setPendingRemoveCluster] = useState<KubeCluster | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const load = () => { void api.get<KubeCluster[]>('/api/k8s/configured-clusters').then(r => { if (r.ok && Array.isArray(r.data)) { setClusters(r.data); setError(''); } else setError('Could not load clusters.'); }); };
  useEffect(load, []);

  const save = async () => {
    if (!form) return;
    setBusy(true); setError('');
    const result = editing ? await api.put<KubeCluster>(`/api/k8s/configured-clusters/${encodeURIComponent(editing)}`, form) : await api.post<KubeCluster>('/api/k8s/configured-clusters', form);
    setBusy(false);
    if (!result.ok) { setError('Could not save cluster. Check the proxy, cluster name and duplicates.'); return; }
    setClusters(current => [...(current ?? []).filter(c => c.id !== result.data.id), result.data].sort((a, b) => a.label.localeCompare(b.label)));
    setForm(null); setEditing('');
  };
  const confirmRemove = async () => {
    if (!pendingRemoveCluster) return;
    const target = pendingRemoveCluster;
    setBusy(true); setError('');
    const result = await api.delete(`/api/k8s/configured-clusters/${encodeURIComponent(target.id)}`);
    setBusy(false);
    setPendingRemoveCluster(null);
    if (!result.ok) { setError('Could not remove cluster.'); return; }
    setClusters(current => current?.filter(c => c.id !== target.id) ?? []);
  };
  return (
    <div className="space-y-4 text-sm">
      <div className="rounded-lg border border-border bg-surface px-5 py-4 flex flex-wrap items-center justify-between gap-4 shadow-xs">
        <div>
          <h3 className="text-[14px] font-semibold text-text-pri">Teleport clusters</h3>
          <p className="text-[13px] font-normal text-text-mut mt-0.5">
            Register an existing Teleport-backed cluster.
          </p>
        </div>
        <Button
          type="button"
          variant="primary"
          size="sm"
          icon={<Plus size={14} />}
          disabled={busy}
          onClick={() => { setForm(empty); setEditing(''); setError(''); }}
        >
          Add cluster
        </Button>
      </div>

      {error && (
        <div role="alert" className="rounded-md border border-danger/30 bg-danger/10 px-4 py-2.5 text-[13px] text-danger flex items-center justify-between gap-3">
          <span>{error}</span>
          {!clusters && (
            <Button type="button" variant="outline" size="xs" onClick={load}>
              Retry
            </Button>
          )}
        </div>
      )}

      {form && (
        <form
          className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs"
          onSubmit={event => { event.preventDefault(); void save(); }}
        >
          <div className="px-5 py-3.5 border-b border-border bg-elev/40 flex items-center justify-between">
            <span className="text-[14px] font-semibold text-text-pri">
              {editing ? 'Edit cluster' : 'Register Kubernetes cluster'}
            </span>
          </div>
          <fieldset disabled={busy} className="px-5 py-4 space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                <span>Display label</span>
                <Input
                  value={form.label}
                  onChange={e => setForm({ ...form, label: e.target.value })}
                  required
                  maxLength={128}
                  placeholder="eks-prod-us"
                />
              </label>
              <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                <span>Teleport proxy</span>
                <Input
                  value={form.proxy}
                  onChange={e => setForm({ ...form, proxy: e.target.value })}
                  placeholder="proxy.example.com"
                  required
                  className="font-mono"
                />
              </label>
              <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                <span>Teleport cluster name</span>
                <Input
                  value={form.cluster_name}
                  onChange={e => setForm({ ...form, cluster_name: e.target.value })}
                  required
                  maxLength={253}
                  className="font-mono"
                />
              </label>
              <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                <span>Sign-in method</span>
                <Select
                  value={form.method}
                  onChange={e => setForm({ ...form, method: e.target.value as ClusterForm['method'], connector: '' })}
                >
                  <option value="local">Password + code</option>
                  <option value="sso">SSO</option>
                </Select>
              </label>
              {form.method === 'sso' && (
                <label className="block space-y-1.5 text-[12px] font-medium text-text-mut md:col-span-2">
                  <span>SSO connector <span className="text-xs font-normal text-text-dim">(optional)</span></span>
                  <Input
                    value={form.connector}
                    onChange={e => setForm({ ...form, connector: e.target.value })}
                    maxLength={128}
                  />
                </label>
              )}
            </div>
            <p className="text-xs font-normal text-text-dim">
              Users enter their own credentials when signing in. Changing the proxy or cluster changes which connections receive its recording policy.
            </p>
          </fieldset>
          <div className="px-5 py-3 bg-bg/60 border-t border-border flex items-center justify-end gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => { setForm(null); setEditing(''); setError(''); }}
            >
              Cancel
            </Button>
            <Button type="submit" variant="primary" size="sm" loading={busy} disabled={busy}>
              Save cluster
            </Button>
          </div>
        </form>
      )}

      {clusters?.length === 0 && <EmptyState size="sm" title="No clusters configured." />}

      {clusters && clusters.length > 0 && (
        <div className="rounded-lg border border-border bg-surface divide-y divide-border overflow-hidden shadow-xs">
          {clusters.map(cluster => (
            <div
              key={cluster.id}
              className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 hover:bg-surface-hover/50 transition-colors"
            >
              <div className="flex items-start gap-3 min-w-0 flex-1">
                <span className="mt-0.5 w-8 h-8 rounded-md bg-[var(--accent-dim)] text-accent border border-accent/20 flex items-center justify-center shrink-0">
                  <Boxes size={15} aria-hidden="true" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-semibold text-[14px] text-text-pri break-words">{cluster.label}</span>
                    <Badge variant={cluster.method === 'sso' ? 'accent' : 'default'} size="sm">
                      {cluster.method === 'sso' ? (cluster.connector ? `SSO · ${cluster.connector}` : 'SSO') : 'Password + code'}
                    </Badge>
                  </div>
                  <div className="text-[12px] font-mono text-text-mut break-all mt-0.5">{cluster.proxy}</div>
                  {cluster.cluster_name && cluster.cluster_name !== cluster.proxy && (
                    <div className="text-[12px] font-mono text-text-dim mt-0.5 break-all">{cluster.cluster_name}</div>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <Button
                  type="button"
                  variant="outline"
                  size="xs"
                  disabled={busy}
                  onClick={() => {
                    setEditing(cluster.id);
                    setForm({ label: cluster.label, proxy: cluster.proxy, cluster_name: cluster.cluster_name, method: cluster.method, connector: cluster.connector });
                    setError('');
                  }}
                >
                  Edit
                </Button>
                <Button
                  type="button"
                  variant="danger-ghost"
                  size="xs"
                  disabled={busy}
                  onClick={() => setPendingRemoveCluster(cluster)}
                >
                  Remove
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      <ConfirmDialog
        open={Boolean(pendingRemoveCluster)}
        onOpenChange={(open) => { if (!open) setPendingRemoveCluster(null); }}
        title={pendingRemoveCluster ? `Remove ${pendingRemoveCluster.label}?` : 'Remove cluster?'}
        description="Its recording policy is removed and the default policy applies to future connections."
        confirmLabel="Remove"
        busy={busy}
        onConfirm={confirmRemove}
      />
    </div>
  );
}
