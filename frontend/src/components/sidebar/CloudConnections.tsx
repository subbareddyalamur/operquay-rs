import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Check, KeyRound, Loader, LogOut, Plus, RefreshCw } from 'lucide-react';
import { api } from '@/lib/api';
import { canSendCredentials } from '@/lib/credentialTransport';
import { useSessionsStore } from '@/stores/sessions';
import { useLayoutStore } from '@/stores/layout';
import { useInstancesStore, type UserRole } from '@/stores/instances';
import { Button } from '@/components/primitives/Button';

type Binding = { id: string; label: string; role_arn: string };
type SSOStart = { id: string; verification_url: string; verification_url_complete?: string; user_code: string; interval_seconds: number; expires_at: string };
type SSOSession = { id: string; region: string; start_url: string; expires_at: string };
type SSOAccount = { id: string; name: string };
type SSORole = { account_id: string; name: string };
type SSOProvider = { id: string; label: string; start_url: string; region: string };
type AccountRow = SSOAccount & { roles: string[] | null; role: string; rolesError?: boolean };
/** One Identity Center sign-in, pending or approved. */
type Flow = { id: string; startURL: string; region: string; authorized: boolean; userCode: string; verificationURL: string; interval: number; expiresAt: string; popupBlocked: boolean };
type Source = { key: string; label: string; startURL: string; region: string; configured: boolean };
type Selection = { kind: 'sso'; key: string } | { kind: 'iam' } | { kind: 'add' } | { kind: 'azure' } | { kind: 'gcp' };

export interface MultiCloudConnector {
  id: string;
  provider: 'azure' | 'gcp' | string;
  name: string;
  account_or_project_id: string;
  tenant_or_org_id: string;
  region: string;
  auth_mode?: string;
  status: string;
}

export interface MultiCloudResource {
  id: string;
  connector_id: string;
  provider: string;
  kind: string;
  name: string;
  region: string;
  state: string;
}

const ROLE_LOOKUPS_IN_FLIGHT = 2;
const ROLE_RETRY_DELAYS_MS = [400, 1000];

async function fetchRolesForAccount(flowID: string, accountID: string): Promise<{ ok: true; names: string[] } | { ok: false }> {
  for (let attempt = 0; attempt <= ROLE_RETRY_DELAYS_MS.length; attempt++) {
    const res = await api.post<SSORole[]>('/api/aws/sso/roles', { id: flowID, account_id: accountID });
    if (res.ok && Array.isArray(res.data)) {
      return { ok: true, names: res.data.map(r => r.name) };
    }
    const delay = ROLE_RETRY_DELAYS_MS[attempt];
    if (delay !== undefined) {
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  return { ok: false };
}
const EARLIER = 'earlier';
const TINT = {
  accent: 'bg-[var(--accent-dim)] text-accent',
  success: 'bg-[color-mix(in_srgb,var(--success)_14%,transparent)] text-success',
  warn: 'bg-[color-mix(in_srgb,var(--warn)_15%,transparent)] text-warn',
  danger: 'bg-[color-mix(in_srgb,var(--danger)_12%,transparent)] text-danger',
  neutral: 'bg-elev text-text-mut',
};
const accountOfARN = (arn: string) => /^arn:aws[\w-]*:iam::(\d{12}):/.exec(arn)?.[1];

/** The form the server uses to tell start URLs apart; "" when it is not a URL. */
export function normalizeStartURL(raw: string): string {
  try { return `https://${new URL(raw.trim()).hostname.toLowerCase()}/start`; } catch { return ''; }
}
const portalName = (url: string) => { try { return new URL(url).hostname.split('.')[0] ?? url; } catch { return url; } };
const portalHost = (url: string) => { try { return new URL(url).hostname; } catch { return url; } };

function timeLeft(expiresAt: string): string {
  const ms = Date.parse(expiresAt) - Date.now();
  if (!Number.isFinite(ms) || ms <= 0) return '';
  const minutes = Math.round(ms / 60000);
  return minutes < 60 ? `${minutes}m left` : `${Math.floor(minutes / 60)}h left`;
}

function closeRoleSessions(roleID?: string) {
  const sessions = useSessionsStore.getState();
  for (const s of sessions.sessions) {
    const scope = s.userSSH ?? s.userRDP ?? s.userTopology;
    if (scope && (!roleID || scope.roleID === roleID)) sessions.closeSession(s.id);
  }
}

export function CloudConnections() {
  const [bindings, setBindings] = useState<Binding[]>([]);
  const [providers, setProviders] = useState<SSOProvider[]>([]);
  const [flows, setFlows] = useState<Record<string, Flow>>({});
  const [accounts, setAccounts] = useState<Record<string, AccountRow[]>>({});
  const [cloudConnectors, setCloudConnectors] = useState<MultiCloudConnector[]>([]);
  const [cloudResources, setCloudResources] = useState<MultiCloudResource[]>([]);
  const [selection, setSelection] = useState<Selection | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const loading = useRef(new Set<string>());
  const connected = useInstancesStore(s => s.userRoles);

  useEffect(() => {
    let active = true;
    void api.get<{ sessions?: SSOSession[] }>('/api/aws/sso/session').then((result) => {
      if (!active || !result.ok || !Array.isArray(result.data?.sessions)) return;
      const restored: Record<string, Flow> = {};
      for (const s of result.data.sessions) {
        restored[normalizeStartURL(s.start_url)] = { id: s.id, startURL: s.start_url, region: s.region, authorized: true, userCode: '', verificationURL: '', interval: 1, expiresAt: s.expires_at, popupBlocked: false };
      }
      setFlows(previous => ({ ...restored, ...previous }));
    });
    void api.get<Binding[]>('/api/aws/user-bindings').then((result) => {
      if (!active) return;
      if (result.ok) setBindings(result.data);
      else setError('Could not load approved AWS roles. Check HTTPS and try again.');
    });
    void api.get<SSOProvider[]>('/api/aws/sso-providers').then(result => {
      if (active && result.ok) setProviders(result.data);
    });
    void api.get<{ connectors?: MultiCloudConnector[] } | MultiCloudConnector[]>('/api/clouds/connectors').then(result => {
      if (!active || !result.ok) return;
      const list = Array.isArray(result.data) ? [] : result.data?.connectors ?? [];
      setCloudConnectors(list);
    });
    void api.get<{ resources?: MultiCloudResource[] } | MultiCloudResource[]>('/api/clouds/resources').then(result => {
      if (!active || !result.ok) return;
      const list = Array.isArray(result.data) ? [] : result.data?.resources ?? [];
      setCloudResources(list);
    });
    return () => { active = false; };
  }, []);

  // Every start URL the user can see: configured ones, ones signed in now, and ones accounts were connected through.
  const sources = useMemo(() => {
    const byKey = new Map<string, Source>();
    for (const p of providers) {
      const key = normalizeStartURL(p.start_url);
      if (key && !byKey.has(key)) byKey.set(key, { key, label: p.label, startURL: p.start_url, region: p.region, configured: true });
    }
    for (const [key, f] of Object.entries(flows)) {
      if (!byKey.has(key)) byKey.set(key, { key, label: portalName(f.startURL), startURL: f.startURL, region: f.region, configured: false });
    }
    for (const role of connected) {
      const key = role.startURL ? normalizeStartURL(role.startURL) : '';
      if (key && !byKey.has(key)) byKey.set(key, { key, label: portalName(key), startURL: key, region: '', configured: false });
    }
    if (connected.some(role => role.roleName && !role.startURL)) byKey.set(EARLIER, { key: EARLIER, label: 'Earlier sign-in', startURL: '', region: '', configured: false });
    return [...byKey.values()];
  }, [providers, flows, connected]);

  const rolesOf = (key: string) => connected.filter(role => key === EARLIER ? role.roleName && !role.startURL : role.startURL && normalizeStartURL(role.startURL) === key);
  const iamRoles = connected.filter(role => !role.roleName);

  const fallback: Selection = (() => {
    const signedIn = sources.find(s => flows[s.key]?.authorized) ?? sources.find(s => rolesOf(s.key).length > 0) ?? sources[0];
    if (signedIn) return { kind: 'sso', key: signedIn.key };
    return iamRoles.length ? { kind: 'iam' } : { kind: 'add' };
  })();
  const current: Selection = selection && (selection.kind !== 'sso' || sources.some(s => s.key === selection.key)) ? selection : fallback;

  // Poll AWS until the user approves each pending sign-in in the tab we opened.
  useEffect(() => {
    const timers: ReturnType<typeof setTimeout>[] = [];
    let stopped = false;
    for (const [key, f] of Object.entries(flows)) {
      if (f.authorized) continue;
      const wait = Math.max(f.interval, 1) * 1000;
      const tick = async () => {
        const status = await api.post<{ status: string }>('/api/aws/sso/poll', { id: f.id });
        if (stopped) return;
        if (!status.ok) {
          setFlows(previous => { if (previous[key]?.id !== f.id) return previous; const next = { ...previous }; delete next[key]; return next; });
          setError('AWS sign-in failed or expired. Start again.');
          return;
        }
        if (status.data.status === 'authorized') {
          setFlows(previous => previous[key]?.id === f.id ? { ...previous, [key]: { ...f, authorized: true } } : previous);
          return;
        }
        timers.push(setTimeout(() => void tick(), wait));
      };
      timers.push(setTimeout(() => void tick(), wait));
    }
    return () => { stopped = true; timers.forEach(clearTimeout); };
  }, [flows]);

  // Once a sign-in is approved and opened, list its accounts and look up their roles in the background.
  const openKey = current.kind === 'sso' ? current.key : '';
  const openFlow = flows[openKey];
  const openFlowID = openFlow?.authorized ? openFlow.id : '';
  const accountsRef = useRef(accounts);
  useEffect(() => { accountsRef.current = accounts; }, [accounts]);
  const applyRoleLookupResult = (sourceKey: string, accountID: string, res: { ok: true; names: string[] } | { ok: false }) => {
    if (res.ok) {
      const linked = useInstancesStore.getState().userRoles.find(r => r.accountID === accountID);
      const preferred = linked?.roleName && res.names.includes(linked.roleName) ? linked.roleName : res.names[0] ?? '';
      setAccounts(previous => ({ ...previous, [sourceKey]: previous[sourceKey]?.map(row => row.id === accountID ? { ...row, roles: res.names, role: preferred, rolesError: false } : row) ?? [] }));
    } else {
      setAccounts(previous => ({ ...previous, [sourceKey]: previous[sourceKey]?.map(row => row.id === accountID ? { ...row, roles: [], role: '', rolesError: true } : row) ?? [] }));
    }
  };

  useEffect(() => {
    const marker = `${openKey}:${openFlowID}`;
    const inflight = loading.current;
    if (!openFlowID || openKey in accountsRef.current || inflight.has(marker)) return;
    inflight.add(marker);
    let active = true;
    void (async () => {
      const result = await api.post<SSOAccount[]>('/api/aws/sso/accounts', { id: openFlowID });
      inflight.delete(marker);
      if (!active) return;
      if (!result.ok) { setError('Could not load AWS accounts. Sign in to this start URL again.'); return; }
      setAccounts(previous => ({ ...previous, [openKey]: result.data.map(a => ({ ...a, roles: null, role: '', rolesError: false })) }));
      const queue = [...result.data];
      const worker = async () => {
        for (let next = queue.shift(); next && active; next = queue.shift()) {
          const account = next;
          const res = await fetchRolesForAccount(openFlowID, account.id);
          if (!active) return;
          applyRoleLookupResult(openKey, account.id, res);
        }
      };
      await Promise.all(Array.from({ length: ROLE_LOOKUPS_IN_FLIGHT }, worker));
    })();
    return () => { active = false; inflight.delete(marker); };
  }, [openKey, openFlowID]);

  const retryRoles = async (sourceKey: string, accountID: string) => {
    const flowID = flows[sourceKey]?.id;
    if (!flowID) return;
    setAccounts(previous => ({ ...previous, [sourceKey]: previous[sourceKey]?.map(row => row.id === accountID ? { ...row, roles: null, rolesError: false } : row) ?? [] }));
    const res = await fetchRolesForAccount(flowID, accountID);
    applyRoleLookupResult(sourceKey, accountID, res);
  };

  const forget = (key: string) => {
    setFlows(previous => { const next = { ...previous }; delete next[key]; return next; });
    setAccounts(previous => { const next = { ...previous }; delete next[key]; return next; });
  };

  const startSSO = async (startURL: string, region: string) => {
    setError('');
    const key = normalizeStartURL(startURL);
    if (!key) { setError('Enter a start URL like https://example.awsapps.com/start.'); return; }
    if (!canSendCredentials('/api/aws/sso/start')) { setError('HTTPS is required for AWS sign-in.'); return; }
    // Open the tab inside the click so pop-up blockers allow it; it is pointed at AWS once the URL arrives.
    const tab = window.open('about:blank', '_blank');
    setBusy(`sso:${key}`);
    const result = await api.post<SSOStart>('/api/aws/sso/start', { start_url: startURL.trim(), region: region.trim() });
    setBusy(null);
    if (!result.ok) { tab?.close(); setError('Could not start AWS sign-in. Check the start URL and region.'); return; }
    const url = result.data.verification_url_complete || result.data.verification_url;
    if (tab) { tab.opener = null; tab.location.href = url; }
    setAccounts(previous => { const next = { ...previous }; delete next[key]; return next; });
    setFlows(previous => ({ ...previous, [key]: { id: result.data.id, startURL: startURL.trim(), region: region.trim(), authorized: false, userCode: result.data.user_code, verificationURL: url, interval: result.data.interval_seconds, expiresAt: '', popupBlocked: !tab } }));
    setSelection({ kind: 'sso', key });
  };

  const signOut = async (key: string) => {
    const f = flows[key];
    if (!f) return;
    setBusy(`sso:${key}`); setError('');
    const result = await api.post('/api/aws/sso/cancel', { id: f.id });
    setBusy(null);
    if (!result.ok) { setError('Could not sign out of this start URL. Try again or disconnect all.'); return; }
    forget(key);
  };

  const disconnectRole = async (role: UserRole) => {
    setBusy(role.id); setError('');
    const result = await api.post('/api/aws/role-disconnect', { binding_id: role.id });
    closeRoleSessions(role.id);
    useInstancesStore.getState().removeUserRole(role.id);
    setBusy(null);
    if (!result.ok) setError(`Could not confirm that ${role.name} was disconnected on the server. Sign out of Operquay to end the session.`);
  };

  const connectSSO = async (key: string, account: AccountRow) => {
    const f = flows[key];
    if (!f?.authorized || !account.role) return;
    setBusy(account.id); setError('');
    const result = await api.post<{ id: string; credential_revision: string }>('/api/aws/sso/connect', { id: f.id, account_id: account.id, role_name: account.role });
    setBusy(null);
    if (!result.ok || !result.data.credential_revision) { setError(`Could not connect ${account.name}. The AWS sign-in may have expired; sign in again.`); return; }
    const previous = useInstancesStore.getState().userRoles.find(r => r.accountID === account.id && r.id !== result.data.id);
    if (previous) { void api.post('/api/aws/role-disconnect', { binding_id: previous.id }); closeRoleSessions(previous.id); }
    void useInstancesStore.getState().addUserRole({ id: result.data.id, name: account.name, label: `${account.name} · ${account.role}`, accountID: account.id, roleName: account.role, startURL: normalizeStartURL(f.startURL), credentialRevision: result.data.credential_revision });
  };

  const disconnectAll = async () => {
    setBusy('all'); setError('');
    const result = await api.post('/api/aws/role-disconnect', {});
    closeRoleSessions();
    useLayoutStore.getState().closeDetails();
    useInstancesStore.getState().clearUserRoles();
    setFlows({}); setAccounts({}); setBusy(null);
    if (!result.ok) setError('Could not disconnect on the server. Sign out of Operquay to end the session.');
  };

  const source = current.kind === 'sso' ? sources.find(s => s.key === current.key) : undefined;

  return <section aria-label="Cloud connections" className="-mx-5 -my-5 grid grid-cols-1 sm:grid-cols-[17rem_1fr] h-[min(72vh,42rem)] text-text-pri">
    <nav aria-label="Connection sources" className="bg-bg border-b sm:border-b-0 sm:border-r border-border overflow-y-auto p-2 flex flex-col">
      <Group label="AWS">
        {sources.map(s => {
          const status = sourceStatus(flows[s.key], rolesOf(s.key).length);
          return <SourceItem key={s.key} selected={current.kind === 'sso' && current.key === s.key} onSelect={() => setSelection({ kind: 'sso', key: s.key })}
            badge="SSO" title={s.label} detail={s.key === EARLIER ? 'Connected before this update' : `${portalName(s.startURL)}${s.region ? ` · ${s.region}` : ''}`} status={status} />;
        })}
        <SourceItem selected={current.kind === 'iam'} onSelect={() => setSelection({ kind: 'iam' })} badge="IAM" title="IAM roles" detail="Your own credentials" status={iamRoles.length ? { label: `${iamRoles.length} connected`, tone: 'accent' } : undefined} />
        <li><button type="button" onClick={() => setSelection({ kind: 'add' })} aria-current={current.kind === 'add' ? 'true' : undefined}
          className={`w-full flex items-center gap-2 px-2 h-8 rounded-md text-[13px] text-accent hover:bg-elev focus-visible:outline-2 focus-visible:outline-accent ${current.kind === 'add' ? 'bg-[var(--accent-dim)]' : ''}`}>
          <Plus size={14} aria-hidden="true" />Add a start URL</button></li>
      </Group>
      <Group label="Azure">
        <SourceItem
          selected={current.kind === 'azure'}
          onSelect={() => setSelection({ kind: 'azure' })}
          badge="AZ"
          title="Microsoft Entra ID"
          detail={cloudConnectors.filter(c => c.provider === 'azure').length ? `${cloudConnectors.filter(c => c.provider === 'azure').length} connected` : 'ARM VMs, AKS & RBAC'}
        />
      </Group>
      <Group label="Google Cloud">
        <SourceItem
          selected={current.kind === 'gcp'}
          onSelect={() => setSelection({ kind: 'gcp' })}
          badge="GCP"
          title="Google Cloud Platform"
          detail={cloudConnectors.filter(c => c.provider === 'gcp').length ? `${cloudConnectors.filter(c => c.provider === 'gcp').length} connected` : 'GCE VMs, GKE & IAM'}
        />
      </Group>
      {connected.length > 0 && <div className="mt-auto pt-2"><Button variant="danger-ghost" size="sm" fullWidth icon={<LogOut size={13} />} disabled={!!busy} onClick={() => void disconnectAll()}>Disconnect all</Button></div>}
    </nav>

    <div className="overflow-y-auto p-5 space-y-4">
      {error && <p role="alert" className={`text-[13px] rounded-md px-3 py-2 ${TINT.danger}`}>{error}</p>}
      {current.kind === 'add' && <AddStartURL busy={!!busy} onStart={(url, region) => void startSSO(url, region)} />}
      {current.kind === 'iam' && <IAMPane bindings={bindings} roles={iamRoles} busy={busy} setBusy={setBusy} setError={setError} onDisconnect={role => void disconnectRole(role)} />}
      {current.kind === 'azure' && (
        <AzureConnectorPane
          connectors={cloudConnectors.filter(c => c.provider === 'azure')}
          resources={cloudResources.filter(r => r.provider === 'azure')}
          busy={busy}
          setBusy={setBusy}
          setError={setError}
          onReload={() => {
            void api.get<{ connectors?: MultiCloudConnector[] }>('/api/clouds/connectors').then(r => { if (r.ok) setCloudConnectors(r.data?.connectors ?? []); });
            void api.get<{ resources?: MultiCloudResource[] }>('/api/clouds/resources').then(r => { if (r.ok) setCloudResources(r.data?.resources ?? []); });
          }}
        />
      )}
      {current.kind === 'gcp' && (
        <GcpConnectorPane
          connectors={cloudConnectors.filter(c => c.provider === 'gcp')}
          resources={cloudResources.filter(r => r.provider === 'gcp')}
          busy={busy}
          setBusy={setBusy}
          setError={setError}
          onReload={() => {
            void api.get<{ connectors?: MultiCloudConnector[] }>('/api/clouds/connectors').then(r => { if (r.ok) setCloudConnectors(r.data?.connectors ?? []); });
            void api.get<{ resources?: MultiCloudResource[] }>('/api/clouds/resources').then(r => { if (r.ok) setCloudResources(r.data?.resources ?? []); });
          }}
        />
      )}
      {source && <SSOPane source={source} flow={flows[source.key]} accounts={accounts[source.key]} roles={rolesOf(source.key)} connected={connected} busy={busy}
        onSignIn={() => void startSSO(source.startURL, source.region)} onSignOut={() => void signOut(source.key)}
        onRole={(id, role) => setAccounts(previous => ({ ...previous, [source.key]: previous[source.key]?.map(row => row.id === id ? { ...row, role } : row) ?? [] }))}
        onRetryRoles={id => void retryRoles(source.key, id)}
        onConnect={account => void connectSSO(source.key, account)} onDisconnect={role => void disconnectRole(role)} />}
    </div>
  </section>;
}

type Tone = keyof typeof TINT;
type Status = { label: string; tone: Tone };

function sourceStatus(flow: Flow | undefined, connectedCount: number): Status {
  if (flow && !flow.authorized) return { label: 'Waiting for approval', tone: 'accent' };
  if (flow?.authorized) return { label: ['Signed in', timeLeft(flow.expiresAt)].filter(Boolean).join(' · '), tone: 'success' };
  if (connectedCount) return { label: `Not signed in · ${connectedCount} connected`, tone: 'warn' };
  return { label: 'Not signed in', tone: 'neutral' };
}

function Pill({ status }: { status: Status }) {
  return <span className={`inline-flex max-w-full items-center gap-1.5 rounded-full px-2 h-5 text-[11px] font-medium whitespace-nowrap overflow-hidden text-ellipsis ${TINT[status.tone]}`}><span className="size-1.5 rounded-full bg-current" aria-hidden="true" />{status.label}</span>;
}

function Group({ label, children }: { label: string; children: ReactNode }) {
  return <div className="mb-2">
    <p className="px-2 pt-2 pb-1 text-[11px] font-semibold uppercase tracking-wide text-text-dim">{label}</p>
    <ul aria-label={label} className="space-y-0.5">{children}</ul>
  </div>;
}

function SourceItem({ badge, title, detail, status, selected, disabled, onSelect }: { badge: string; title: string; detail: string; status?: Status | undefined; selected?: boolean; disabled?: boolean; onSelect?: () => void }) {
  return <li><button type="button" disabled={disabled} onClick={onSelect} aria-current={selected ? 'true' : undefined}
    className={`w-full flex items-start gap-2 px-2 py-1.5 rounded-md text-left focus-visible:outline-2 focus-visible:outline-accent disabled:opacity-55 disabled:cursor-default ${selected ? 'bg-[var(--accent-dim)]' : 'enabled:hover:bg-elev'}`}>
    <span aria-hidden="true" className="mt-0.5 shrink-0 w-7 h-5 rounded text-[9px] font-bold flex items-center justify-center bg-elev border border-border text-text-mut">{badge}</span>
    <span className="min-w-0 flex-1">
      <span className={`block truncate text-[13px] font-medium ${selected ? 'text-accent' : 'text-text-pri'}`}>{title}</span>
      <span className="block truncate text-[11px] text-text-dim">{detail}</span>
      {status && <span className="block mt-1"><Pill status={status} /></span>}
    </span>
  </button></li>;
}

function ConnectedRow({ role, busy, onDisconnect }: { role: UserRole; busy: string | null; onDisconnect: (role: UserRole) => void }) {
  const fetching = useInstancesStore(s => s.userFetching.includes(role.id));
  const count = useInstancesStore(s => s.userInventory[role.id]?.length);
  return <li className="flex flex-wrap items-center gap-3 px-3 py-2.5 text-[13px]">
    <div className="flex-1 min-w-[12rem]">
      <p className="font-medium truncate">{role.name && role.label && !role.label.includes(role.name) ? `${role.name} · ${role.label}` : role.label}</p>
      <p className={`text-[12px] ${role.error ? 'text-danger' : 'text-text-mut'}`}>
        {role.live === false ? 'AWS sign-in expired · sign in to connect'
          : fetching ? <span className="inline-flex items-center gap-1"><Loader size={11} className="animate-spin motion-reduce:animate-none" aria-hidden="true" />Fetching…</span>
          : role.error ? role.error
          : count !== undefined ? `${count} instance${count === 1 ? '' : 's'}${role.failedRegions?.length ? ` · not fetched: ${role.failedRegions.join(', ')}` : ''}` : 'Waiting to fetch'}
      </p>
    </div>
    {role.live !== false && <Button variant="ghost" size="sm" icon={<RefreshCw size={13} />} aria-label={`Refetch ${role.name}`} disabled={fetching || !!busy} onClick={() => void useInstancesStore.getState().fetchUserRole(role.id)}>Refetch</Button>}
    <Button variant="danger-ghost" size="sm" aria-label={`Disconnect ${role.name}`} loading={busy === role.id} disabled={!!busy} onClick={() => onDisconnect(role)}>Disconnect</Button>
  </li>;
}

function SSOPane({ source, flow, accounts, roles, connected, busy, onSignIn, onSignOut, onRole, onRetryRoles, onConnect, onDisconnect }: {
  source: Source; flow: Flow | undefined; accounts: AccountRow[] | undefined; roles: UserRole[]; connected: UserRole[]; busy: string | null;
  onSignIn: () => void; onSignOut: () => void; onRole: (account: string, role: string) => void; onRetryRoles: (account: string) => void; onConnect: (account: AccountRow) => void; onDisconnect: (role: UserRole) => void;
}) {
  const [filter, setFilter] = useState('');
  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase();
    return (accounts ?? []).filter(a => !q || a.name.toLowerCase().includes(q) || a.id.includes(q));
  }, [accounts, filter]);
  const earlier = source.key === EARLIER;
  const pending = !!flow && !flow.authorized;
  const signingIn = busy === `sso:${source.key}`;

  return <div className="space-y-4">
    <header className="flex flex-wrap items-start gap-3">
      <div className="flex-1 min-w-[14rem]">
        <h3 className="text-[15px] font-semibold">{source.label} <span className="font-normal text-text-dim">· IAM Identity Center</span></h3>
        {!earlier && <p className="text-[12px] text-text-dim font-mono break-all">{portalHost(source.startURL)}{source.region ? ` · ${source.region}` : ''}</p>}
      </div>
      {!earlier && (flow?.authorized
        ? <><Button variant="outline" size="sm" icon={<RefreshCw size={13} />} loading={signingIn} disabled={!!busy} onClick={onSignIn}>Sign in again</Button>
            <Button variant="danger-ghost" size="sm" disabled={!!busy} onClick={onSignOut}>Sign out</Button></>
        : !pending && <Button size="sm" icon={<KeyRound size={13} />} loading={signingIn} disabled={!!busy || !source.region} onClick={onSignIn}>Sign in</Button>)}
    </header>

    {pending && <div className={`rounded-md p-3 space-y-2 text-[13px] ${TINT.accent}`}>
      <p className="flex items-center gap-2 text-text-pri"><Loader size={14} className="animate-spin motion-reduce:animate-none text-accent" aria-hidden="true" />Waiting for approval in the AWS tab. Confirm the code <strong className="font-mono tracking-wider">{flow.userCode}</strong> there.</p>
      {flow.popupBlocked && <p className="text-text-pri">Your browser blocked the new tab. <a className="underline text-accent" href={flow.verificationURL} target="_blank" rel="noopener noreferrer">Open AWS sign-in</a></p>}
      <Button variant="ghost" size="sm" disabled={signingIn} onClick={onSignOut}>Cancel AWS sign-in</Button>
    </div>}

    {!earlier && !flow && !source.region && <p className="text-[13px] text-text-mut">This start URL's region is not known here. Use “Add a start URL” to sign in to it again.</p>}

    {roles.length > 0 && <div className="space-y-2">
      <h4 className="text-[13px] font-semibold">Connected through this start URL <span className="font-normal text-text-mut">({roles.length})</span></h4>
      <ul aria-label={`Connected accounts for ${source.label}`} className="bg-surface border border-border rounded-md divide-y divide-border">
        {roles.map(role => <ConnectedRow key={role.id} role={role} busy={busy} onDisconnect={onDisconnect} />)}
      </ul>
      {!flow?.authorized && <p className="text-[12px] text-text-mut">These accounts keep working until AWS expires their credentials. Sign in to connect more.</p>}
    </div>}

    {flow?.authorized && !accounts && <p className="flex items-center gap-2 text-[13px] text-text-mut"><Loader size={14} className="animate-spin motion-reduce:animate-none" aria-hidden="true" />Loading your AWS accounts…</p>}

    {flow?.authorized && accounts && <div className="space-y-2">
      <p className="text-[13px] text-text-mut">{accounts.length} account{accounts.length === 1 ? '' : 's'} available until this sign-in expires · {roles.length} connected</p>
      {accounts.length === 0 && <p className="text-[13px] text-text-mut">AWS returned no accounts for this sign-in.</p>}
      {accounts.length > 8 && <input className="block w-full max-w-sm h-8 px-2.5 bg-elev border border-border rounded-md text-[13px] text-text-pri" aria-label="Filter AWS accounts" placeholder="Filter accounts by name or ID" value={filter} onChange={e => setFilter(e.target.value)} />}
      {accounts.length > 0 && <ul className="bg-surface border border-border rounded-md divide-y divide-border" aria-label="AWS accounts">
        {visible.map(account => {
          const linked = connected.find(r => r.accountID === account.id && r.live !== false);
          const isLinkedRole = linked?.roleName === account.role;
          return <li key={account.id} className="flex flex-wrap items-center gap-2 px-3 py-2 text-[13px]">
            <div className="flex-1 min-w-[10rem]"><p className="font-medium">{account.name}</p><p className="text-text-mut text-[12px] tabular-nums">{account.id}</p></div>
            {account.roles === null ? <span className="text-[12px] text-text-mut">Loading roles…</span>
              : account.rolesError ? <span className="inline-flex items-center gap-2 text-[12px] text-warn">Roles failed to load <Button variant="ghost" size="sm" aria-label={`Retry roles for ${account.name}`} onClick={() => onRetryRoles(account.id)}>Retry</Button></span>
              : account.roles.length === 0 ? <span className="text-[12px] text-text-mut">No roles available</span>
              : <select aria-label={`Role for ${account.name}`} className="h-7 px-2 bg-elev border border-border rounded-md text-[12px] text-text-pri" value={account.role} disabled={!!busy} onChange={e => onRole(account.id, e.target.value)}>{account.roles.map(role => <option key={role} value={role}>{role}</option>)}</select>}
            <div className="w-28 flex justify-end">
              {isLinkedRole
                ? <span className={`inline-flex items-center gap-1 h-7 px-2.5 rounded text-[12px] font-medium ${TINT.success}`}><Check size={13} aria-hidden="true" />Connected</span>
                : <Button variant="soft" size="sm" aria-label={`${linked ? 'Switch role for' : 'Connect'} ${account.name}`} loading={busy === account.id} disabled={!!busy || !account.role} onClick={() => onConnect(account)}>{linked ? 'Switch role' : 'Connect'}</Button>}
            </div>
          </li>;
        })}
      </ul>}
    </div>}

    {!flow && roles.length === 0 && !earlier && <p className="text-[13px] text-text-mut">Sign in to list the accounts and roles AWS gives you through this start URL.</p>}
    <p className="text-[12px] text-text-dim">AWS determines the available accounts and roles. Support for this hosted device sign-in has not been verified with AWS.</p>
  </div>;
}

function AddStartURL({ busy, onStart }: { busy: boolean; onStart: (url: string, region: string) => void }) {
  const [url, setURL] = useState('');
  const [region, setRegion] = useState('');
  const field = 'block w-full mt-1 h-9 px-2.5 bg-elev border border-border rounded-md text-[13px] text-text-pri';
  return <form className="max-w-lg space-y-3" onSubmit={e => { e.preventDefault(); onStart(url, region); }}>
    <header><h3 className="text-[15px] font-semibold">Add a start URL</h3><p className="text-[13px] text-text-mut mt-1">Sign in to another AWS IAM Identity Center. Start URLs your administrator configured are already listed on the left.</p></header>
    <label className="block text-[13px] text-text-mut">AWS start URL<input className={field} value={url} onChange={e => setURL(e.target.value)} placeholder="https://example.awsapps.com/start" /></label>
    <label className="block text-[13px] text-text-mut">Identity Center region<input className={field} value={region} onChange={e => setRegion(e.target.value)} placeholder="us-east-1" /></label>
    <Button type="submit" disabled={busy || !url.trim() || !region.trim()}>Start AWS sign-in</Button>
  </form>;
}

function IAMPane({ bindings, roles, busy, setBusy, setError, onDisconnect }: { bindings: Binding[]; roles: UserRole[]; busy: string | null; setBusy: (v: string | null) => void; setError: (v: string) => void; onDisconnect: (role: UserRole) => void }) {
  const [binding, setBinding] = useState('');
  const [roleARN, setRoleARN] = useState('');
  const [externalID, setExternalID] = useState('');
  const [key, setKey] = useState('');
  const [secret, setSecret] = useState('');
  const [token, setToken] = useState('');
  const field = 'block w-full mt-1 h-9 px-2.5 bg-elev border border-border rounded-md text-[13px] text-text-pri disabled:opacity-60';

  const connectIAM = async () => {
    setError('');
    if (!canSendCredentials('/api/aws/role-login')) { setError('HTTPS is required to send AWS credentials.'); return; }
    setBusy('iam');
    const role = binding ? { binding_id: binding } : { role_arn: roleARN.trim(), external_id: externalID.trim() };
    const result = await api.post<{ id?: string; credential_revision: string }>('/api/aws/role-login', { ...role, access_key_id: key, secret_access_key: secret, session_token: token });
    setKey(''); setSecret(''); setToken(''); setBusy(null);
    const id = binding || (result.ok ? result.data.id : '');
    if (!result.ok || !id || !result.data.credential_revision) { setError('AWS sign-in failed. Check the role and credentials.'); return; }
    const approved = bindings.find(b => b.id === binding);
    const arn = approved?.role_arn ?? roleARN.trim();
    const name = approved?.label ?? arn.split('/').pop() ?? arn;
    void useInstancesStore.getState().addUserRole({ id, name, label: approved ? `${approved.label} · ${arn.split('/').pop()}` : arn, accountID: accountOfARN(arn), credentialRevision: result.data.credential_revision });
  };

  return <div className="space-y-4">
    <header><h3 className="text-[15px] font-semibold">IAM roles</h3><p className="text-[13px] text-text-mut mt-1">Assume a role with your own access keys. Credentials are kept in server memory for this session; reconnect after they expire.</p></header>
    {roles.length > 0 && <ul aria-label="Connected IAM roles" className="bg-surface border border-border rounded-md divide-y divide-border">
      {roles.map(role => <ConnectedRow key={role.id} role={role} busy={busy} onDisconnect={onDisconnect} />)}
    </ul>}
    <form className="max-w-lg space-y-3" onSubmit={e => { e.preventDefault(); void connectIAM(); }}>
      <label className="block text-[13px] text-text-mut">Approved role<select className={field} value={binding} disabled={!!busy} onChange={e => setBinding(e.target.value)}><option value="">Select a role</option>{bindings.map(b => <option key={b.id} value={b.id}>{b.label} · {b.role_arn}</option>)}</select></label>
      {!binding && <><label className="block text-[13px] text-text-mut">IAM role ARN<input className={field} value={roleARN} disabled={!!busy} onChange={e => setRoleARN(e.target.value)} placeholder="arn:aws:iam::123456789012:role/RoleName" /></label><label className="block text-[13px] text-text-mut">External ID (if required)<input className={field} value={externalID} disabled={!!busy} onChange={e => setExternalID(e.target.value)} /></label></>}
      <p className="text-[12px] text-text-mut">{binding ? 'An approved role requires its configured AWS principal.' : 'AWS must allow your supplied credentials to assume this role.'} Temporary credentials require a session token.</p>
      <label className="block text-[13px] text-text-mut">Access key ID<input className={field} autoComplete="off" value={key} disabled={!!busy} onChange={e => setKey(e.target.value)} /></label>
      <label className="block text-[13px] text-text-mut">Secret access key<input type="password" className={field} autoComplete="new-password" value={secret} disabled={!!busy} onChange={e => setSecret(e.target.value)} /></label>
      <label className="block text-[13px] text-text-mut">Session token <span className="text-text-dim">(for temporary credentials)</span><input type="password" className={field} autoComplete="off" value={token} disabled={!!busy} onChange={e => setToken(e.target.value)} /></label>
      <Button type="submit" loading={busy === 'iam'} disabled={!!busy || (!binding && !roleARN.trim()) || !key || !secret}>Connect role</Button>
    </form>
  </div>;
}

function ConnectedCloudList({
  provider,
  connectors,
  resources,
  busy,
  onSync,
  onDelete,
}: {
  provider: 'azure' | 'gcp';
  connectors: MultiCloudConnector[];
  resources: MultiCloudResource[];
  busy: string | null;
  onSync: (id: string) => void;
  onDelete: (id: string) => void;
}) {
  return (
    <>
      {connectors.length > 0 && (
        <ul aria-label={`${provider.toUpperCase()} connectors`} className="bg-surface border border-border rounded-md divide-y divide-border">
          {connectors.map(c => (
            <li key={c.id} className="flex flex-wrap items-center gap-3 px-3 py-2.5 text-[13px]">
              <div className="flex-1 min-w-[12rem]">
                <p className="font-medium truncate">{c.name}</p>
                <p className="text-[12px] text-text-mut font-mono">
                  {c.account_or_project_id} · {c.auth_mode ?? 'key'} · {c.region || 'global'} · {c.status}
                </p>
              </div>
              <Button variant="ghost" size="sm" loading={busy === c.id} disabled={!!busy} onClick={() => onSync(c.id)}>
                Sync
              </Button>
              <Button variant="danger-ghost" size="sm" disabled={!!busy} onClick={() => onDelete(c.id)}>
                Remove
              </Button>
            </li>
          ))}
        </ul>
      )}
      {resources.length > 0 && (
        <div className="space-y-1.5">
          <h4 className="text-[12px] font-semibold uppercase tracking-wide text-text-sec">
            Discovered Resources ({resources.length})
          </h4>
          <ul className="bg-surface border border-border rounded-md divide-y divide-border">
            {resources.slice(0, 12).map(r => (
              <li key={r.id} className="px-3 py-2 text-[12px] flex items-center justify-between gap-2">
                <span className="font-mono text-text-pri truncate">{r.kind}: {r.name}</span>
                <span className="text-text-mut">{r.region} · {r.state}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

type AzureAuthTab = 'sso' | 'keyless' | 'secret';
interface AzureSsoState {
  flowId: string;
  userCode: string;
  verificationUri: string;
  intervalSeconds: number;
  popupBlocked: boolean;
  authorized: boolean;
  subscriptions: Array<{ subscription_id: string; display_name: string; state: string; tenant_id: string }>;
}

function AzureConnectorPane({
  connectors,
  resources,
  busy,
  setBusy,
  setError,
  onReload,
}: {
  connectors: MultiCloudConnector[];
  resources: MultiCloudResource[];
  busy: string | null;
  setBusy: (v: string | null) => void;
  setError: (v: string) => void;
  onReload: () => void;
}) {
  const [authTab, setAuthTab] = useState<AzureAuthTab>('sso');
  const [entraTenant, setEntraTenant] = useState('organizations');
  const [ssoClientId, setSsoClientId] = useState('');
  const [ssoFlow, setSsoFlow] = useState<AzureSsoState | null>(null);

  const [keylessKind, setKeylessKind] = useState<'managed_identity' | 'workload_identity'>('managed_identity');
  const [name, setName] = useState('');
  const [subId, setSubId] = useState('');
  const [tenantId, setTenantId] = useState('');
  const [region, setRegion] = useState('eastus');
  const [clientId, setClientId] = useState('');
  const [secretOrTokenFile, setSecretOrTokenFile] = useState('');

  const field = 'block w-full mt-1 h-9 px-2.5 bg-elev border border-border rounded-md text-[13px] text-text-pri disabled:opacity-60';
  const pillCls = (active: boolean) =>
    `px-2.5 h-8 rounded-md text-[12px] font-medium transition-colors ${active ? 'bg-[var(--accent-dim)] text-accent border border-accent/40' : 'bg-elev text-text-mut hover:text-text-pri border border-border'}`;

  useEffect(() => {
    if (!ssoFlow || ssoFlow.authorized) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const waitMs = Math.max(ssoFlow.intervalSeconds, 1) * 1000;
    const tick = async () => {
      const res = await api.post<{ status: string; subscriptions?: AzureSsoState['subscriptions']; error?: string }>(
        '/api/clouds/azure/sso/poll',
        { flow_id: ssoFlow.flowId },
      );
      if (stopped) return;
      if (!res.ok) {
        setError(res.error?.message || 'Entra sign-in failed or expired. Start again.');
        setSsoFlow(null);
        return;
      }
      if (res.data.status === 'authorized') {
        setSsoFlow(prev => (prev ? { ...prev, authorized: true, subscriptions: res.data.subscriptions ?? [] } : null));
        return;
      }
      timer = setTimeout(() => { void tick(); }, waitMs);
    };
    timer = setTimeout(() => { void tick(); }, waitMs);
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
    };
  }, [ssoFlow, setError]);

  const startEntraSso = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setBusy('azure-sso');
    const tab = window.open('about:blank', '_blank');
    const res = await api.post<{
      flow_id: string;
      user_code: string;
      verification_uri: string;
      verification_uri_complete?: string;
      interval_seconds: number;
    }>('/api/clouds/azure/sso/start', {
      entra_tenant: entraTenant.trim() || 'organizations',
      client_id: ssoClientId.trim(),
    });
    setBusy(null);
    if (!res.ok) {
      if (tab && !tab.closed) tab.close();
      setError(res.error?.message || 'Could not start Microsoft Entra ID sign-in.');
      return;
    }
    const targetUrl = res.data.verification_uri_complete || res.data.verification_uri;
    const opened = !!tab && !tab.closed;
    if (tab && !tab.closed) {
      tab.opener = null;
      tab.location.href = targetUrl;
    }
    setSsoFlow({
      flowId: res.data.flow_id,
      userCode: res.data.user_code,
      verificationUri: targetUrl,
      intervalSeconds: res.data.interval_seconds || 2,
      popupBlocked: !opened,
      authorized: false,
      subscriptions: [],
    });
  };

  const connectSubscription = async (sub: AzureSsoState['subscriptions'][number]) => {
    if (!ssoFlow) return;
    setError('');
    setBusy(sub.subscription_id);
    const res = await api.post('/api/clouds/azure/sso/connect', {
      flow_id: ssoFlow.flowId,
      subscription_id: sub.subscription_id,
      name: sub.display_name,
      region,
    });
    setBusy(null);
    if (!res.ok) {
      setError(res.error?.message || `Could not connect subscription ${sub.display_name}.`);
      return;
    }
    setSsoFlow(null);
    onReload();
  };

  const handleKeylessOrSecret = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setBusy('azure');
    const isSecret = authTab === 'secret';
    const res = await api.post('/api/clouds/connectors', {
      provider: 'azure',
      name: name.trim(),
      account_or_project_id: subId.trim(),
      tenant_or_org_id: tenantId.trim(),
      region: region.trim(),
      credentials: isSecret ? { client_id: clientId.trim(), client_secret: secretOrTokenFile.trim() } : {},
      config: isSecret
        ? { auth_mode: 'service_principal' }
        : {
            auth_mode: keylessKind,
            client_id: clientId.trim(),
            federated_token_file: keylessKind === 'workload_identity' ? secretOrTokenFile.trim() : '',
          },
    });
    setBusy(null);
    if (!res.ok) {
      setError(res.error?.message || 'Could not add AZURE connector.');
      return;
    }
    setName('');
    setSubId('');
    setTenantId('');
    setClientId('');
    setSecretOrTokenFile('');
    onReload();
  };

  const handleSync = async (id: string) => {
    setError('');
    setBusy(id);
    const res = await api.post(`/api/clouds/connectors/${encodeURIComponent(id)}/sync`, {});
    setBusy(null);
    if (!res.ok) setError(res.error?.message || 'Could not sync AZURE connector.');
    else onReload();
  };

  const handleDelete = async (id: string) => {
    setBusy(id);
    await api.delete(`/api/clouds/connectors/${encodeURIComponent(id)}`);
    setBusy(null);
    onReload();
  };

  return (
    <div className="space-y-4">
      <header>
        <h3 className="text-[15px] font-semibold">Microsoft Azure (Entra ID / Compute / AKS)</h3>
        <p className="text-[13px] text-text-mut mt-1">
          Sign in interactively via Microsoft Entra ID Device Code SSO (zero secrets), attach via Managed/Workload Identity, or use a Service Principal fallback.
        </p>
      </header>

      <ConnectedCloudList
        provider="azure"
        connectors={connectors}
        resources={resources}
        busy={busy}
        onSync={id => void handleSync(id)}
        onDelete={id => void handleDelete(id)}
      />

      <div className="flex flex-wrap gap-2" role="tablist" aria-label="Azure authentication methods">
        <button type="button" role="tab" aria-selected={authTab === 'sso'} className={pillCls(authTab === 'sso')} onClick={() => setAuthTab('sso')}>
          Entra ID SSO (Recommended)
        </button>
        <button type="button" role="tab" aria-selected={authTab === 'keyless'} className={pillCls(authTab === 'keyless')} onClick={() => setAuthTab('keyless')}>
          Managed / Workload Identity
        </button>
        <button type="button" role="tab" aria-selected={authTab === 'secret'} className={pillCls(authTab === 'secret')} onClick={() => setAuthTab('secret')}>
          Service Principal Secret
        </button>
      </div>

      {authTab === 'sso' && (
        <div className="max-w-lg space-y-3">
          {!ssoFlow && (
            <form className="space-y-3" onSubmit={e => void startEntraSso(e)}>
              <label className="block text-[13px] text-text-mut">
                Entra Tenant ID or domain
                <input className={field} value={entraTenant} onChange={e => setEntraTenant(e.target.value)} placeholder="organizations or tenant GUID" />
              </label>
              <label className="block text-[13px] text-text-mut">
                App Client ID <span className="text-text-dim">(optional · defaults to Azure CLI public client)</span>
                <input className={field} value={ssoClientId} onChange={e => setSsoClientId(e.target.value)} placeholder="Leave blank for default public client" />
              </label>
              <Button type="submit" icon={<KeyRound size={14} />} loading={busy === 'azure-sso'} disabled={!!busy}>
                Sign in with Microsoft Entra ID
              </Button>
            </form>
          )}
          {ssoFlow && !ssoFlow.authorized && (
            <div className={`rounded-md p-3 space-y-2 text-[13px] ${TINT.accent}`}>
              <p className="flex items-center gap-2 text-text-pri">
                <Loader size={14} className="animate-spin motion-reduce:animate-none text-accent" aria-hidden="true" />
                Waiting for Microsoft Entra approval. Confirm code <strong className="font-mono tracking-wider">{ssoFlow.userCode}</strong> in the browser tab.
              </p>
              {ssoFlow.popupBlocked && (
                <p className="text-text-pri">
                  <a className="underline text-accent" href={ssoFlow.verificationUri} target="_blank" rel="noopener noreferrer">Open Microsoft sign-in</a>
                </p>
              )}
              <Button variant="ghost" size="sm" onClick={() => setSsoFlow(null)}>Cancel Entra sign-in</Button>
            </div>
          )}
          {ssoFlow?.authorized && (
            <div className="space-y-2">
              <p className="text-[13px] text-text-mut">Entra ID signed in · {ssoFlow.subscriptions.length} subscription(s) discovered</p>
              <ul className="bg-surface border border-border rounded-md divide-y divide-border" aria-label="Azure subscriptions">
                {ssoFlow.subscriptions.map(sub => (
                  <li key={sub.subscription_id} className="flex items-center justify-between gap-2 px-3 py-2 text-[13px]">
                    <div className="min-w-0">
                      <p className="font-medium truncate">{sub.display_name}</p>
                      <p className="text-[12px] text-text-mut font-mono">{sub.subscription_id}</p>
                    </div>
                    <Button size="sm" variant="soft" loading={busy === sub.subscription_id} disabled={!!busy} onClick={() => void connectSubscription(sub)}>
                      Connect
                    </Button>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {authTab !== 'sso' && (
        <form className="max-w-lg space-y-3" onSubmit={e => void handleKeylessOrSecret(e)}>
          {authTab === 'keyless' && (
            <label className="block text-[13px] text-text-mut">
              Keyless Identity Mode
              <select className={field} value={keylessKind} onChange={e => setKeylessKind(e.target.value as 'managed_identity' | 'workload_identity')}>
                <option value="managed_identity">Azure Managed Identity (IMDS — zero secret)</option>
                <option value="workload_identity">Entra Workload Identity (OIDC JWT file — zero secret)</option>
              </select>
            </label>
          )}
          <label className="block text-[13px] text-text-mut">
            Connector name
            <input className={field} required value={name} onChange={e => setName(e.target.value)} placeholder="Azure Production" />
          </label>
          <label className="block text-[13px] text-text-mut">
            Subscription ID
            <input className={field} required value={subId} onChange={e => setSubId(e.target.value)} placeholder="sub-00000000" />
          </label>
          {(authTab === 'secret' || keylessKind === 'workload_identity') && (
            <label className="block text-[13px] text-text-mut">
              Entra Tenant ID
              <input className={field} required value={tenantId} onChange={e => setTenantId(e.target.value)} />
            </label>
          )}
          <label className="block text-[13px] text-text-mut">
            Default region
            <input className={field} value={region} onChange={e => setRegion(e.target.value)} />
          </label>
          <label className="block text-[13px] text-text-mut">
            {authTab === 'keyless' && keylessKind === 'managed_identity' ? 'User-Assigned Managed Identity Client ID (optional)' : 'Entra Client ID'}
            <input className={field} required={authTab === 'secret' || keylessKind === 'workload_identity'} value={clientId} onChange={e => setClientId(e.target.value)} />
          </label>
          {authTab === 'keyless' && keylessKind === 'workload_identity' && (
            <label className="block text-[13px] text-text-mut">
              Federated OIDC Token File Path <span className="text-text-dim">(defaults to AZURE_FEDERATED_TOKEN_FILE)</span>
              <input className={field} value={secretOrTokenFile} onChange={e => setSecretOrTokenFile(e.target.value)} placeholder="/var/run/secrets/azure/tokens/azure-identity-token" />
            </label>
          )}
          {authTab === 'secret' && (
            <label className="block text-[13px] text-text-mut">
              Entra Client Secret
              <input type="password" className={field} required value={secretOrTokenFile} onChange={e => setSecretOrTokenFile(e.target.value)} />
            </label>
          )}
          <Button type="submit" loading={busy === 'azure'} disabled={!!busy || !name.trim() || !subId.trim()}>
            Add Azure connector
          </Button>
        </form>
      )}
    </div>
  );
}

type GcpAuthTab = 'sso' | 'keyless' | 'secret';
interface GcpSsoState {
  flowId: string;
  authUrl: string;
  popupBlocked: boolean;
  authorized: boolean;
  projects: Array<{ project_id: string; name: string; project_number: string; lifecycle_state: string }>;
}

function GcpConnectorPane({
  connectors,
  resources,
  busy,
  setBusy,
  setError,
  onReload,
}: {
  connectors: MultiCloudConnector[];
  resources: MultiCloudResource[];
  busy: string | null;
  setBusy: (v: string | null) => void;
  setError: (v: string) => void;
  onReload: () => void;
}) {
  const [authTab, setAuthTab] = useState<GcpAuthTab>('sso');
  const [oauthClientId, setOauthClientId] = useState('');
  const [oauthClientSecret, setOauthClientSecret] = useState('');
  const [ssoFlow, setSsoFlow] = useState<GcpSsoState | null>(null);

  const [keylessKind, setKeylessKind] = useState<'metadata_adc' | 'workload_identity'>('metadata_adc');
  const [name, setName] = useState('');
  const [projectId, setProjectId] = useState('');
  const [orgId, setOrgId] = useState('');
  const [region, setRegion] = useState('us-central1');
  const [impersonateSa, setImpersonateSa] = useState('');
  const [wifAudience, setWifAudience] = useState('');
  const [tokenFileOrJson, setTokenFileOrJson] = useState('');

  const field = 'block w-full mt-1 h-9 px-2.5 bg-elev border border-border rounded-md text-[13px] text-text-pri disabled:opacity-60';
  const pillCls = (active: boolean) =>
    `px-2.5 h-8 rounded-md text-[12px] font-medium transition-colors ${active ? 'bg-[var(--accent-dim)] text-accent border border-accent/40' : 'bg-elev text-text-mut hover:text-text-pri border border-border'}`;

  useEffect(() => {
    if (!ssoFlow || ssoFlow.authorized) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const pollStatus = async () => {
      const res = await api.get<{ status: string; projects?: GcpSsoState['projects']; error?: string }>(
        `/api/clouds/gcp/sso/status?flow_id=${encodeURIComponent(ssoFlow.flowId)}`,
      );
      if (stopped || !res.ok) return;
      if (res.data.status === 'authorized') {
        setSsoFlow(prev => (prev ? { ...prev, authorized: true, projects: res.data.projects ?? [] } : null));
        return;
      }
      if (res.data.status === 'error') {
        setError(res.data.error || 'Google Cloud sign-in failed.');
        setSsoFlow(null);
        return;
      }
      timer = setTimeout(() => { void pollStatus(); }, 1500);
    };
    const onMessage = (ev: MessageEvent<{ type?: string; ok?: boolean }>) => {
      if (ev.origin === window.location.origin && ev.data?.type === 'operquay:gcp-sso-complete') {
        void pollStatus();
      }
    };
    window.addEventListener('message', onMessage);
    timer = setTimeout(() => { void pollStatus(); }, 1500);
    return () => {
      stopped = true;
      window.removeEventListener('message', onMessage);
      if (timer) clearTimeout(timer);
    };
  }, [ssoFlow, setError]);

  const startGoogleSso = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setBusy('gcp-sso');
    const tab = window.open('about:blank', '_blank');
    const res = await api.post<{ flow_id: string; authorization_url: string }>('/api/clouds/gcp/sso/start', {
      client_id: oauthClientId.trim(),
      client_secret: oauthClientSecret.trim(),
    });
    setBusy(null);
    if (!res.ok) {
      if (tab && !tab.closed) tab.close();
      setError(res.error?.message || 'Could not start Google Cloud OAuth2 PKCE flow.');
      return;
    }
    const opened = !!tab && !tab.closed;
    if (tab && !tab.closed) {
      tab.location.href = res.data.authorization_url;
    }
    setSsoFlow({
      flowId: res.data.flow_id,
      authUrl: res.data.authorization_url,
      popupBlocked: !opened,
      authorized: false,
      projects: [],
    });
  };

  const connectProject = async (proj: GcpSsoState['projects'][number]) => {
    if (!ssoFlow) return;
    setError('');
    setBusy(proj.project_id);
    const res = await api.post('/api/clouds/gcp/sso/connect', {
      flow_id: ssoFlow.flowId,
      project_id: proj.project_id,
      name: proj.name,
      region,
    });
    setBusy(null);
    if (!res.ok) {
      setError(res.error?.message || `Could not connect GCP project ${proj.project_id}.`);
      return;
    }
    setSsoFlow(null);
    onReload();
  };

  const handleKeylessOrSecret = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setBusy('gcp');
    let credentials: Record<string, unknown> = {};
    let config: Record<string, unknown> = {};
    if (authTab === 'secret') {
      try {
        credentials = JSON.parse(tokenFileOrJson || '{}') as Record<string, unknown>;
      } catch {
        setError('GCP Service Account JSON must be valid JSON.');
        setBusy(null);
        return;
      }
      config = { auth_mode: 'service_account' };
    } else {
      config = {
        auth_mode: keylessKind,
        impersonate_service_account: impersonateSa.trim(),
        wif_audience: keylessKind === 'workload_identity' ? wifAudience.trim() : '',
        federated_token_file: keylessKind === 'workload_identity' ? tokenFileOrJson.trim() : '',
      };
    }
    const res = await api.post('/api/clouds/connectors', {
      provider: 'gcp',
      name: name.trim(),
      account_or_project_id: projectId.trim(),
      tenant_or_org_id: orgId.trim(),
      region: region.trim(),
      credentials,
      config,
    });
    setBusy(null);
    if (!res.ok) {
      setError(res.error?.message || 'Could not add GCP connector.');
      return;
    }
    setName('');
    setProjectId('');
    setOrgId('');
    setImpersonateSa('');
    setWifAudience('');
    setTokenFileOrJson('');
    onReload();
  };

  const handleSync = async (id: string) => {
    setError('');
    setBusy(id);
    const res = await api.post(`/api/clouds/connectors/${encodeURIComponent(id)}/sync`, {});
    setBusy(null);
    if (!res.ok) setError(res.error?.message || 'Could not sync GCP connector.');
    else onReload();
  };

  const handleDelete = async (id: string) => {
    setBusy(id);
    await api.delete(`/api/clouds/connectors/${encodeURIComponent(id)}`);
    setBusy(null);
    onReload();
  };

  return (
    <div className="space-y-4">
      <header>
        <h3 className="text-[15px] font-semibold">Google Cloud Platform (Compute Engine / GKE / IAM)</h3>
        <p className="text-[13px] text-text-mut mt-1">
          Sign in interactively with Google Cloud OAuth2 PKCE, attach via Workload Identity Federation / GCE Metadata ADC, or paste a Service Account JSON fallback.
        </p>
      </header>

      <ConnectedCloudList
        provider="gcp"
        connectors={connectors}
        resources={resources}
        busy={busy}
        onSync={id => void handleSync(id)}
        onDelete={id => void handleDelete(id)}
      />

      <div className="flex flex-wrap gap-2" role="tablist" aria-label="GCP authentication methods">
        <button type="button" role="tab" aria-selected={authTab === 'sso'} className={pillCls(authTab === 'sso')} onClick={() => setAuthTab('sso')}>
          Google Cloud SSO (Recommended)
        </button>
        <button type="button" role="tab" aria-selected={authTab === 'keyless'} className={pillCls(authTab === 'keyless')} onClick={() => setAuthTab('keyless')}>
          Workload Identity / ADC
        </button>
        <button type="button" role="tab" aria-selected={authTab === 'secret'} className={pillCls(authTab === 'secret')} onClick={() => setAuthTab('secret')}>
          Service Account JSON
        </button>
      </div>

      {authTab === 'sso' && (
        <div className="max-w-lg space-y-3">
          {!ssoFlow && (
            <form className="space-y-3" onSubmit={e => void startGoogleSso(e)}>
              <label className="block text-[13px] text-text-mut">
                Google OAuth Client ID <span className="text-text-dim">(optional if OPERQUAY_GCP_OAUTH_CLIENT_ID is configured)</span>
                <input className={field} value={oauthClientId} onChange={e => setOauthClientId(e.target.value)} placeholder="123456.apps.googleusercontent.com" />
              </label>
              <label className="block text-[13px] text-text-mut">
                OAuth Client Secret <span className="text-text-dim">(optional for PKCE-only clients)</span>
                <input type="password" className={field} value={oauthClientSecret} onChange={e => setOauthClientSecret(e.target.value)} />
              </label>
              <Button type="submit" icon={<KeyRound size={14} />} loading={busy === 'gcp-sso'} disabled={!!busy}>
                Sign in with Google Cloud
              </Button>
            </form>
          )}
          {ssoFlow && !ssoFlow.authorized && (
            <div className={`rounded-md p-3 space-y-2 text-[13px] ${TINT.accent}`}>
              <p className="flex items-center gap-2 text-text-pri">
                <Loader size={14} className="animate-spin motion-reduce:animate-none text-accent" aria-hidden="true" />
                Waiting for Google Cloud authorization in the browser tab…
              </p>
              {ssoFlow.popupBlocked && (
                <p className="text-text-pri">
                  <a className="underline text-accent" href={ssoFlow.authUrl} target="_blank" rel="noopener noreferrer">Open Google sign-in</a>
                </p>
              )}
              <Button variant="ghost" size="sm" onClick={() => setSsoFlow(null)}>Cancel Google sign-in</Button>
            </div>
          )}
          {ssoFlow?.authorized && (
            <div className="space-y-2">
              <p className="text-[13px] text-text-mut">Google Cloud signed in · {ssoFlow.projects.length} project(s) discovered</p>
              <ul className="bg-surface border border-border rounded-md divide-y divide-border" aria-label="GCP projects">
                {ssoFlow.projects.map(p => (
                  <li key={p.project_id} className="flex items-center justify-between gap-2 px-3 py-2 text-[13px]">
                    <div className="min-w-0">
                      <p className="font-medium truncate">{p.name}</p>
                      <p className="text-[12px] text-text-mut font-mono">{p.project_id}</p>
                    </div>
                    <Button size="sm" variant="soft" loading={busy === p.project_id} disabled={!!busy} onClick={() => void connectProject(p)}>
                      Connect
                    </Button>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {authTab !== 'sso' && (
        <form className="max-w-lg space-y-3" onSubmit={e => void handleKeylessOrSecret(e)}>
          {authTab === 'keyless' && (
            <label className="block text-[13px] text-text-mut">
              Keyless Identity Mode
              <select className={field} value={keylessKind} onChange={e => setKeylessKind(e.target.value as 'metadata_adc' | 'workload_identity')}>
                <option value="metadata_adc">GCE / GKE Metadata Server (ADC — zero key)</option>
                <option value="workload_identity">Workload Identity Federation (STS OIDC — zero key)</option>
              </select>
            </label>
          )}
          <label className="block text-[13px] text-text-mut">
            Connector name
            <input className={field} required value={name} onChange={e => setName(e.target.value)} placeholder="GCP Production" />
          </label>
          <label className="block text-[13px] text-text-mut">
            GCP Project ID
            <input className={field} required value={projectId} onChange={e => setProjectId(e.target.value)} placeholder="my-gcp-project" />
          </label>
          <label className="block text-[13px] text-text-mut">
            GCP Organization ID (optional)
            <input className={field} value={orgId} onChange={e => setOrgId(e.target.value)} />
          </label>
          <label className="block text-[13px] text-text-mut">
            Default region
            <input className={field} value={region} onChange={e => setRegion(e.target.value)} />
          </label>
          {authTab === 'keyless' && (
            <>
              <label className="block text-[13px] text-text-mut">
                Impersonate Service Account Email (optional)
                <input className={field} value={impersonateSa} onChange={e => setImpersonateSa(e.target.value)} placeholder="operquay-reader@proj.iam.gserviceaccount.com" />
              </label>
              {keylessKind === 'workload_identity' && (
                <>
                  <label className="block text-[13px] text-text-mut">
                    Workload Identity Pool Audience
                    <input className={field} required value={wifAudience} onChange={e => setWifAudience(e.target.value)} placeholder="//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/..." />
                  </label>
                  <label className="block text-[13px] text-text-mut">
                    Federated OIDC Token File Path <span className="text-text-dim">(defaults to GCP_FEDERATED_TOKEN_FILE)</span>
                    <input className={field} value={tokenFileOrJson} onChange={e => setTokenFileOrJson(e.target.value)} placeholder="/var/run/secrets/tokens/gcp-oidc-token" />
                  </label>
                </>
              )}
            </>
          )}
          {authTab === 'secret' && (
            <label className="block text-[13px] text-text-mut">
              Service Account JSON
              <textarea
                rows={4}
                required
                className="block w-full mt-1 p-2.5 bg-elev border border-border rounded-md text-[12px] font-mono text-text-pri"
                value={tokenFileOrJson}
                onChange={e => setTokenFileOrJson(e.target.value)}
                placeholder={'{"client_email":"...","private_key":"-----BEGIN PRIVATE KEY-----..."}'}
              />
            </label>
          )}
          <Button type="submit" loading={busy === 'gcp'} disabled={!!busy || !name.trim() || !projectId.trim()}>
            Add GCP connector
          </Button>
        </form>
      )}
    </div>
  );
}
