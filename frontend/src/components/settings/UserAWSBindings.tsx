import { useEffect, useState } from 'react';
import { Cloud, KeyRound } from 'lucide-react';
import { Badge, Button, Input, Select } from '@/components/primitives';
import { api } from '@/lib/api';
import { canSendCredentials } from '@/lib/credentialTransport';

type User = { id: string; email: string; disabled?: boolean };
type Binding = { id: string; label: string; role_arn: string; principal_arn: string };
type SSOProvider = { id: string; label: string; start_url: string; region: string };

export function UserAWSBindings() {
  const [users, setUsers] = useState<User[]>([]);
  const [user, setUser] = useState('');
  const [bindings, setBindings] = useState<Binding[]>([]);
  const [label, setLabel] = useState('');
  const [principalARN, setPrincipalARN] = useState('');
  const [principalID, setPrincipalID] = useState('');
  const [roleARN, setRoleARN] = useState('');
  const [externalID, setExternalID] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [providers, setProviders] = useState<SSOProvider[]>([]);
  const [ssoLabel, setSSOLabel] = useState('');
  const [ssoURL, setSSOURL] = useState('');
  const [ssoRegion, setSSORegion] = useState('');

  useEffect(() => {
    let active = true;
    void api.get<User[]>('/api/users').then(r => {
      if (!active) return;
      if (r.ok) setUsers(r.data.filter(u => !u.disabled));
      else setError('Could not load users.');
    });
    void api.get<SSOProvider[]>('/api/aws/sso-providers').then(r => {
      if (!active) return;
      if (r.ok) setProviders(r.data);
      else setError('Could not load AWS start URLs.');
    });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    setBindings([]);
    if (user) void api.get<Binding[]>(`/api/aws/user-bindings?user_id=${encodeURIComponent(user)}`).then(r => {
      if (!active) return;
      if (r.ok) setBindings(r.data);
      else setError('Could not load AWS role bindings.');
    });
    return () => { active = false; };
  }, [user]);

  const add = async () => {
    setError('');
    if (!canSendCredentials('/api/aws/user-bindings')) { setError('HTTPS is required.'); return; }
    setBusy(true);
    const result = await api.post<Binding>('/api/aws/user-bindings', { user_id: user, label, principal_arn: principalARN, principal_id: principalID, role_arn: roleARN, external_id: externalID });
    setBusy(false);
    if (!result.ok) { setError('Could not create the binding. Check the user, IAM principal ID and role ARN.'); return; }
    setBindings(rows => [...rows, result.data]); setLabel(''); setPrincipalARN(''); setPrincipalID(''); setRoleARN(''); setExternalID('');
  };

  const remove = async (id: string) => {
    if (!window.confirm('Remove this role binding? The user’s AWS connections on this server will be disconnected.')) return;
    setBusy(true); setError('');
    const result = await api.delete(`/api/aws/user-bindings/${encodeURIComponent(id)}`);
    setBusy(false);
    if (result.ok) setBindings(rows => rows.filter(row => row.id !== id));
    else setError('Could not remove the binding.');
  };

  const addProvider = async () => {
    setError('');
    if (!canSendCredentials('/api/aws/sso-providers')) { setError('HTTPS is required.'); return; }
    setBusy(true);
    const result = await api.post<SSOProvider>('/api/aws/sso-providers', { label: ssoLabel.trim(), start_url: ssoURL.trim(), region: ssoRegion.trim() });
    setBusy(false);
    if (!result.ok) { setError('Could not add AWS start URL. Check the URL and region.'); return; }
    setProviders(rows => [...rows, result.data]); setSSOLabel(''); setSSOURL(''); setSSORegion('');
  };

  const removeProvider = async (p: SSOProvider) => {
    if (!window.confirm(`Remove ${p.label}? Existing AWS sessions remain active.`)) return;
    setBusy(true); setError('');
    const result = await api.delete(`/api/aws/sso-providers/${encodeURIComponent(p.id)}`);
    setBusy(false);
    if (result.ok) setProviders(rows => rows.filter(row => row.id !== p.id));
    else setError('Could not remove AWS start URL.');
  };

  return (
    <div className="space-y-6 text-text-pri">
      <section className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs">
        <div className="px-5 py-4 border-b border-border flex items-start gap-3">
          <span className="mt-0.5 w-8 h-8 rounded-md bg-[var(--accent-dim)] text-accent border border-accent/20 flex items-center justify-center shrink-0">
            <Cloud size={15} aria-hidden="true" />
          </span>
          <div>
            <h3 className="text-[14px] font-semibold text-text-pri">AWS Identity Center start URLs</h3>
            <p className="text-[13px] text-text-mut mt-0.5">
              Optional shortcuts for users in this tenant. Users can also enter their own AWS start URL.
            </p>
          </div>
        </div>

        <form onSubmit={e => { e.preventDefault(); void addProvider(); }}>
          <div className="px-5 py-4 grid grid-cols-1 md:grid-cols-3 gap-3">
            <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
              <span>AWS connection label</span>
              <Input
                required
                value={ssoLabel}
                onChange={e => setSSOLabel(e.target.value)}
                placeholder="Production SSO"
              />
            </label>
            <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
              <span>AWS start URL</span>
              <Input
                required
                value={ssoURL}
                onChange={e => setSSOURL(e.target.value)}
                placeholder="https://d-9a675af084.awsapps.com/start"
                className="font-mono"
              />
            </label>
            <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
              <span>Identity Center region</span>
              <Input
                required
                value={ssoRegion}
                onChange={e => setSSORegion(e.target.value)}
                placeholder="us-east-2"
                className="font-mono"
              />
            </label>
          </div>
          <div className="px-5 py-3 bg-bg/60 border-t border-border flex items-center justify-end">
            <Button type="submit" variant="primary" size="sm" loading={busy} disabled={busy}>
              Add start URL
            </Button>
          </div>
        </form>

        {providers.length > 0 && (
          <ul className="border-t border-border divide-y divide-border">
            {providers.map(p => (
              <li
                key={p.id}
                className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 text-sm hover:bg-surface-hover/50 transition-colors"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <strong className="text-[14px] font-semibold text-text-pri">{p.label}</strong>
                    <Badge variant="default" size="sm" className="font-mono">{p.region}</Badge>
                  </div>
                  <span className="block text-[12px] font-mono text-text-mut break-all mt-0.5">
                    {p.start_url} · {p.region}
                  </span>
                </div>
                <Button
                  type="button"
                  variant="danger-ghost"
                  size="xs"
                  aria-label={`Remove ${p.label}`}
                  disabled={busy}
                  onClick={() => void removeProvider(p)}
                >
                  Remove
                </Button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs">
        <div className="px-5 py-4 border-b border-border flex items-start gap-3">
          <span className="mt-0.5 w-8 h-8 rounded-md bg-[var(--accent-dim)] text-accent border border-accent/20 flex items-center justify-center shrink-0">
            <KeyRound size={15} aria-hidden="true" />
          </span>
          <div>
            <h3 className="text-[14px] font-semibold text-text-pri">User AWS role bindings</h3>
            <p className="text-[13px] text-text-mut mt-0.5">
              Approve an individual IAM user and target role. AWS verifies the principal ID when the user connects; shared assumed-role sessions are not accepted as identity proof.
            </p>
          </div>
        </div>

        <div className="px-5 py-4 grid grid-cols-1 md:grid-cols-[220px_1fr] items-center gap-3">
          <label htmlFor="aws-binding-user" className="text-[13px] font-medium text-text-pri">
            Operquay user
          </label>
          <Select
            id="aws-binding-user"
            value={user}
            disabled={busy}
            onChange={e => setUser(e.target.value)}
          >
            <option value="">Select a user</option>
            {users.map(u => (
              <option key={u.id} value={u.id}>{u.email}</option>
            ))}
          </Select>
        </div>

        {user && (
          <>
            <form className="border-t border-border" onSubmit={e => { e.preventDefault(); void add(); }}>
              <div className="px-5 py-4 grid grid-cols-1 md:grid-cols-2 gap-3">
                <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                  <span>Connection label</span>
                  <Input required value={label} onChange={e => setLabel(e.target.value)} placeholder="Production ReadOnly" />
                </label>
                <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                  <span>IAM user unique ID</span>
                  <Input required value={principalID} onChange={e => setPrincipalID(e.target.value)} placeholder="AIDA…" className="font-mono" />
                </label>
                <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                  <span>IAM user ARN</span>
                  <Input required value={principalARN} onChange={e => setPrincipalARN(e.target.value)} placeholder="arn:aws:iam::123456789012:user/…" className="font-mono" />
                </label>
                <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                  <span>Target role ARN</span>
                  <Input required value={roleARN} onChange={e => setRoleARN(e.target.value)} placeholder="arn:aws:iam::123456789012:role/…" className="font-mono" />
                </label>
                <label className="block space-y-1.5 text-[12px] font-medium text-text-mut md:col-span-2">
                  <span>External ID (if required)</span>
                  <Input value={externalID} onChange={e => setExternalID(e.target.value)} className="font-mono" />
                </label>
              </div>
              <div className="px-5 py-3 bg-bg/60 border-t border-border flex justify-end">
                <Button type="submit" variant="primary" size="sm" loading={busy} disabled={busy}>
                  Approve role
                </Button>
              </div>
            </form>

            {bindings.length > 0 && (
              <ul className="border-t border-border divide-y divide-border">
                {bindings.map(b => (
                  <li key={b.id} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 text-sm hover:bg-surface-hover/50 transition-colors">
                    <div className="min-w-0 flex-1">
                      <strong className="text-[14px] font-semibold text-text-pri">{b.label}</strong>
                      <span className="block text-[12px] font-mono text-text-mut break-all mt-0.5">
                        {b.principal_arn} → {b.role_arn}
                      </span>
                    </div>
                    <Button type="button" variant="danger-ghost" size="xs" disabled={busy} onClick={() => void remove(b.id)}>
                      Remove
                    </Button>
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </section>

      {error && (
        <p role="alert" className="rounded-md border border-danger/30 bg-danger/10 px-4 py-2.5 text-[13px] text-danger">
          {error}
        </p>
      )}
    </div>
  );
}
