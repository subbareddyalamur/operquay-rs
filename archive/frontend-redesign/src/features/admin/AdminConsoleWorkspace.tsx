import { useCallback, useEffect, useState } from 'react';
import { Award, Cloud, KeyRound, Shield, Trash2, Users } from 'lucide-react';
import { Badge, Button, Card } from '@/design-system/primitives';
import {
  apiJson,
  type AwsAccountItem,
  type DetailedGroup,
  type IdpMapping,
  type LicenseStatus,
  type PermissionInfo,
  type PublicUser,
  type RoleDef,
  type ScimTokenItem,
  type SsoProviderPublic,
} from '../platform/api';
import { usePlatformStore } from '../platform/store';

type AdminTab = 'users' | 'roles' | 'groups' | 'sso' | 'scim' | 'aws' | 'policy' | 'license' | 'security';

export function AdminConsoleWorkspace() {
  const [tab, setTab] = useState<AdminTab>('users');
  const [users, setUsers] = useState<PublicUser[]>([]);
  const [roles, setRoles] = useState<RoleDef[]>([]);
  const [perms, setPerms] = useState<PermissionInfo[]>([]);
  const [groups, setGroups] = useState<DetailedGroup[]>([]);
  const [providers, setProviders] = useState<SsoProviderPublic[]>([]);
  const [mappings, setMappings] = useState<IdpMapping[]>([]);
  const [scimTokens, setScimTokens] = useState<ScimTokenItem[]>([]);
  const [awsAccounts, setAwsAccounts] = useState<AwsAccountItem[]>([]);
  const [license, setLicense] = useState<LicenseStatus | null>(null);
  const [recPolicy, setRecPolicy] = useState({
    record_ssh: true,
    record_rdp: true,
    record_k8s: true,
    fail_closed: false,
    retention_days: 90,
    auto_convert_mp4: true,
  });
  const [notice, setNotice] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserName, setNewUserName] = useState('');
  const [newUserRole, setNewUserRole] = useState('operator');
  const [newUserPassword, setNewUserPassword] = useState('');

  const [newGroupName, setNewGroupName] = useState('');
  const [newRoleName, setNewRoleName] = useState('');
  const [newAwsName, setNewAwsName] = useState('');
  const [newAwsKey, setNewAwsKey] = useState('');
  const [newAwsSecret, setNewAwsSecret] = useState('');
  const [newScimName, setNewScimName] = useState('okta-scim');
  const [createdSecret, setCreatedSecret] = useState<string | null>(null);
  const [licenseToken, setLicenseToken] = useState('');
  const [curPw, setCurPw] = useState('');
  const [nextPw, setNextPw] = useState('');
  const [aiCatalogJson, setAiCatalogJson] = useState('');

  const pushActivity = usePlatformStore((s) => s.pushActivity);

  const loadAll = useCallback(async () => {
    setErr(null);
    try {
      const [u, r, p, g, prov, map, sc, aws, lic, pol] = await Promise.all([
        apiJson<PublicUser[]>('/api/users').catch(() => []),
        apiJson<RoleDef[]>('/api/roles').catch(() => []),
        apiJson<PermissionInfo[]>('/api/permissions').catch(() => []),
        apiJson<DetailedGroup[]>('/api/groups').catch(() => []),
        apiJson<SsoProviderPublic[]>('/api/auth/providers').catch(() => []),
        apiJson<IdpMapping[]>('/api/idp-mappings').catch(() => []),
        apiJson<ScimTokenItem[]>('/api/scim/tokens').catch(() => []),
        apiJson<AwsAccountItem[]>('/aws-accounts').catch(() => []),
        apiJson<LicenseStatus>('/api/license').catch(() => null),
        apiJson<typeof recPolicy | null>('/api/recording-policy').catch(() => null),
      ]);
      setUsers(u);
      setRoles(r);
      setPerms(p);
      setGroups(g);
      setProviders(prov);
      setMappings(map);
      setScimTokens(sc);
      setAwsAccounts(aws);
      setLicense(lic);
      if (pol) setRecPolicy(pol);
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Unable to load admin state');
    }
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const createUser = async () => {
    setErr(null);
    try {
      await apiJson('/api/users', {
        method: 'POST',
        body: JSON.stringify({
          email: newUserEmail,
          name: newUserName || newUserEmail,
          role: newUserRole,
          password: newUserPassword,
        }),
      });
      setNewUserEmail('');
      setNewUserName('');
      setNewUserPassword('');
      setNotice('User provisioned.');
      await loadAll();
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'Failed creating user');
    }
  };

  const createGroup = async () => {
    if (!newGroupName.trim()) return;
    await apiJson('/api/groups', {
      method: 'POST',
      body: JSON.stringify({ name: newGroupName, description: 'Managed group' }),
    });
    setNewGroupName('');
    await loadAll();
  };

  const createRole = async () => {
    if (!newRoleName.trim()) return;
    await apiJson('/api/roles', {
      method: 'POST',
      body: JSON.stringify({
        name: newRoleName,
        description: 'Custom RBAC role',
        permissions: ['instances:read', 'session:rdp'],
      }),
    });
    setNewRoleName('');
    await loadAll();
  };

  const createScim = async () => {
    const out = await apiJson<{ secret: string }>('/api/scim/tokens', {
      method: 'POST',
      body: JSON.stringify({ name: newScimName || 'scim-token' }),
    });
    setCreatedSecret(out.secret);
    await loadAll();
  };

  const addAwsAccount = async () => {
    await apiJson('/aws-accounts', {
      method: 'POST',
      body: JSON.stringify({
        name: newAwsName,
        access_key_id: newAwsKey,
        secret_access_key: newAwsSecret,
      }),
    });
    setNewAwsName('');
    setNewAwsKey('');
    setNewAwsSecret('');
    pushActivity({ title: 'AWS Account Added', detail: newAwsName, status: 'done' });
    await loadAll();
  };

  const redeemLicense = async () => {
    setErr(null);
    try {
      const updated = await apiJson<LicenseStatus>('/api/license/redeem', {
        method: 'POST',
        body: JSON.stringify({ token: licenseToken }),
      });
      setLicense(updated);
      setLicenseToken('');
      setNotice(`Redeemed ${updated.plan.toUpperCase()} license.`);
    } catch (error) {
      setErr(error instanceof Error ? error.message : 'License redemption failed');
    }
  };

  const saveRecPolicy = async () => {
    const saved = await apiJson<typeof recPolicy>('/api/recording-policy', {
      method: 'PUT',
      body: JSON.stringify(recPolicy),
    });
    setRecPolicy(saved);
    setNotice('Global recording policy updated.');
  };

  const tabs: Array<{ id: AdminTab; label: string }> = [
    { id: 'users', label: `Users (${users.length})` },
    { id: 'roles', label: `RBAC Roles (${roles.length})` },
    { id: 'groups', label: `Groups (${groups.length})` },
    { id: 'sso', label: `SSO & IdP (${providers.length})` },
    { id: 'scim', label: `SCIM v2 (${scimTokens.length})` },
    { id: 'aws', label: `AWS Accounts (${awsAccounts.length})` },
    { id: 'policy', label: 'Recording Policy' },
    { id: 'license', label: 'License' },
    { id: 'security', label: 'Security & AI Catalog' },
  ];

  return (
    <div className="max-w-6xl mx-auto px-6 py-6 space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-4">
        <div>
          <h1 className="text-[20px] font-semibold text-text-pri tracking-[-0.02em]">
            Enterprise IAM, Multi-Tenant Governance &amp; Licensing
          </h1>
          <p className="mt-1 text-xs text-text-mut">
            Bcrypt local accounts, 26-permission scoped RBAC with deny-override, OIDC/SAML SSO, SCIM v2, AWS STS accounts, and Ed25519 entitlements.
          </p>
        </div>
        {license && (
          <Badge tone="accent">
            <Award size={12} aria-hidden="true" />
            {license.plan.toUpperCase()} · {license.max_seats} seats
          </Badge>
        )}
      </div>

      <div role="tablist" aria-label="Admin Console sections" className="flex flex-wrap gap-1.5">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            onClick={() => setTab(t.id)}
            className={[
              'h-8 px-3 rounded-[var(--radius-sm)] text-xs font-medium transition-colors',
              tab === t.id
                ? 'bg-[var(--accent-dim)] text-accent border border-[var(--accent-border)]'
                : 'bg-surface border border-border text-text-mut hover:text-text-pri',
            ].join(' ')}
          >
            {t.label}
          </button>
        ))}
      </div>

      {notice && (
        <div className="px-4 py-2.5 rounded-[var(--radius-sm)] border border-border bg-[var(--success-dim)] text-xs text-success">
          {notice}
        </div>
      )}
      {err && (
        <div
          role="alert"
          className="px-4 py-2.5 rounded-[var(--radius-sm)] border border-border bg-[var(--danger-dim)] text-xs text-danger"
        >
          {err}
        </div>
      )}

      {tab === 'users' && (
        <Card className="p-5 space-y-4">
          <div className="flex items-center gap-2">
            <Users size={16} className="text-accent" aria-hidden="true" />
            <h2 className="text-[15px] font-semibold text-text-pri">Local &amp; Provisioned Users</h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-5 gap-2">
            <div>
              <label htmlFor="admin-u-email" className="block text-[11px] text-text-dim mb-1">Email</label>
              <input
                id="admin-u-email"
                value={newUserEmail}
                onChange={(e) => setNewUserEmail(e.target.value)}
                placeholder="alice@acme.io"
                className="w-full h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-pri"
              />
            </div>
            <div>
              <label htmlFor="admin-u-name" className="block text-[11px] text-text-dim mb-1">Name</label>
              <input
                id="admin-u-name"
                value={newUserName}
                onChange={(e) => setNewUserName(e.target.value)}
                placeholder="Alice Ops"
                className="w-full h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-pri"
              />
            </div>
            <div>
              <label htmlFor="admin-u-role" className="block text-[11px] text-text-dim mb-1">Role</label>
              <select
                id="admin-u-role"
                value={newUserRole}
                onChange={(e) => setNewUserRole(e.target.value)}
                className="w-full h-8 px-2 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-pri"
              >
                <option value="admin">admin</option>
                <option value="operator">operator</option>
                <option value="viewer">viewer</option>
              </select>
            </div>
            <div>
              <label htmlFor="admin-u-pw" className="block text-[11px] text-text-dim mb-1">Password</label>
              <input
                id="admin-u-pw"
                type="password"
                value={newUserPassword}
                onChange={(e) => setNewUserPassword(e.target.value)}
                placeholder="Initial password"
                className="w-full h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-pri"
              />
            </div>
            <div className="flex items-end">
              <Button size="sm" onClick={() => void createUser()} className="w-full">Add User</Button>
            </div>
          </div>

          <div className="divide-y divide-border text-xs">
            {users.map((u) => (
              <div key={u.id} className="py-2.5 flex flex-wrap items-center justify-between gap-2">
                <div>
                  <span className="font-medium text-text-pri">{u.name}</span>{' '}
                  <span className="text-text-dim">{u.email}</span>
                </div>
                <div className="flex items-center gap-2">
                  <Badge tone="neutral">{u.role}</Badge>
                  <Badge tone={u.disabled ? 'danger' : 'success'}>
                    {u.disabled ? 'disabled' : u.provider}
                  </Badge>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {tab === 'roles' && (
        <Card className="p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-[15px] font-semibold text-text-pri">Custom RBAC Roles &amp; Permissions ({perms.length})</h2>
            <div className="flex items-center gap-2">
              <input
                aria-label="New role name"
                value={newRoleName}
                onChange={(e) => setNewRoleName(e.target.value)}
                placeholder="k8s-readonly"
                className="h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-pri"
              />
              <Button size="sm" onClick={() => void createRole()}>Create Role</Button>
            </div>
          </div>
          <div className="space-y-2 text-xs">
            {roles.map((r) => (
              <div key={r.id} className="p-3 rounded-[var(--radius-md)] border border-border bg-elev flex flex-wrap items-center justify-between gap-2">
                <div>
                  <div className="font-medium text-text-pri">{r.name} {r.is_system && <Badge tone="neutral">system</Badge>}</div>
                  <div className="text-text-dim mt-0.5">{r.description}</div>
                </div>
                <Badge tone="accent">{r.permissions.length} perms</Badge>
              </div>
            ))}
          </div>
        </Card>
      )}

      {tab === 'groups' && (
        <Card className="p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-[15px] font-semibold text-text-pri">Security Groups &amp; Scoped Bindings</h2>
            <div className="flex items-center gap-2">
              <input
                aria-label="New group name"
                value={newGroupName}
                onChange={(e) => setNewGroupName(e.target.value)}
                placeholder="sre-oncall"
                className="h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-pri"
              />
              <Button size="sm" onClick={() => void createGroup()}>Create Group</Button>
            </div>
          </div>
          <div className="space-y-2 text-xs">
            {groups.map((g) => (
              <div key={g.id} className="p-3 rounded-[var(--radius-md)] border border-border bg-elev flex items-center justify-between gap-2">
                <div>
                  <span className="font-medium text-text-pri">{g.name}</span>
                  <span className="text-text-dim ml-2">{g.members.length} members · {g.bindings.length} bindings</span>
                </div>
                <Badge tone="neutral">{g.source}</Badge>
              </div>
            ))}
          </div>
        </Card>
      )}

      {tab === 'sso' && (
        <Card className="p-5 space-y-3 text-xs">
          <div className="flex items-center gap-2">
            <KeyRound size={16} className="text-accent" aria-hidden="true" />
            <h2 className="text-[15px] font-semibold text-text-pri">OIDC / SAML 2.0 Providers &amp; IdP Group Mappings</h2>
          </div>
          <p className="text-text-mut">Configured SSO Providers: {providers.length} · Claim Mappings: {mappings.length}</p>
          {providers.map((p) => (
            <div key={p.id} className="p-3 rounded-[var(--radius-md)] border border-border bg-elev flex items-center justify-between">
              <div>
                <div className="font-medium text-text-pri">{p.label || p.id}</div>
                <div className="text-text-dim">{p.provider_type.toUpperCase()} · {p.issuer}</div>
              </div>
              <Badge tone={p.enabled ? 'success' : 'neutral'}>{p.enabled ? 'enabled' : 'disabled'}</Badge>
            </div>
          ))}
        </Card>
      )}

      {tab === 'scim' && (
        <Card className="p-5 space-y-3 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-[15px] font-semibold text-text-pri">SCIM 2.0 Provisioning Tokens (`/scim/v2/*`)</h2>
            <div className="flex items-center gap-2">
              <input
                aria-label="SCIM token name"
                value={newScimName}
                onChange={(e) => setNewScimName(e.target.value)}
                className="h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-pri"
              />
              <Button size="sm" onClick={() => void createScim()}>Generate Token</Button>
            </div>
          </div>
          {createdSecret && (
            <div className="p-3 rounded-[var(--radius-sm)] border border-[var(--accent-border)] bg-[var(--accent-dim)] font-mono text-text-pri">
              Bearer Token (copy now): {createdSecret}
            </div>
          )}
          {scimTokens.map((t) => (
            <div key={t.id} className="py-2 flex items-center justify-between border-b border-border">
              <span>{t.name} ({t.prefix}...)</span>
              <Badge tone={t.revoked_at > 0 ? 'danger' : 'success'}>{t.revoked_at > 0 ? 'revoked' : 'active'}</Badge>
            </div>
          ))}
        </Card>
      )}

      {tab === 'aws' && (
        <Card className="p-5 space-y-4 text-xs">
          <div className="flex items-center gap-2">
            <Cloud size={16} className="text-accent" aria-hidden="true" />
            <h2 className="text-[15px] font-semibold text-text-pri">AES-256-GCM Sealed AWS Hub Accounts</h2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
            <input aria-label="AWS account label" value={newAwsName} onChange={(e) => setNewAwsName(e.target.value)} placeholder="prod-aws" className="h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri" />
            <input aria-label="AWS access key ID" value={newAwsKey} onChange={(e) => setNewAwsKey(e.target.value)} placeholder="AKIA..." className="h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri" />
            <input aria-label="AWS secret access key" type="password" value={newAwsSecret} onChange={(e) => setNewAwsSecret(e.target.value)} placeholder="Secret access key" className="h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri" />
            <Button size="sm" onClick={() => void addAwsAccount()}>Add Account</Button>
          </div>
          {awsAccounts.map((a) => (
            <div key={a.id} className="py-2 flex items-center justify-between border-b border-border">
              <span>{a.name} · {a.default_region}</span>
              <div className="flex items-center gap-2">
                <Badge tone={a.verified ? 'success' : 'neutral'}>{a.verified ? 'verified' : 'unverified'}</Badge>
                <Button size="xs" variant="ghost" aria-label={`Delete ${a.name}`} onClick={async () => { await apiJson(`/aws-accounts/${a.id}`, { method: 'DELETE' }); await loadAll(); }}>
                  <Trash2 size={13} aria-hidden="true" />
                </Button>
              </div>
            </div>
          ))}
        </Card>
      )}

      {tab === 'policy' && (
        <Card className="p-5 space-y-4 text-xs">
          <div className="flex items-center gap-2">
            <Shield size={16} className="text-accent" aria-hidden="true" />
            <h2 className="text-[15px] font-semibold text-text-pri">Fail-Closed Audit Recording Policy</h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {(['record_ssh', 'record_rdp', 'record_k8s', 'fail_closed', 'auto_convert_mp4'] as const).map((k) => (
              <label key={k} className="flex items-center gap-2 p-2.5 rounded-[var(--radius-sm)] border border-border bg-elev cursor-pointer">
                <input
                  type="checkbox"
                  checked={recPolicy[k]}
                  onChange={(e) => setRecPolicy((p) => ({ ...p, [k]: e.target.checked }))}
                />
                <span className="font-medium text-text-pri">{k}</span>
              </label>
            ))}
          </div>
          <Button size="sm" onClick={() => void saveRecPolicy()}>Save Recording Policy</Button>
        </Card>
      )}

      {tab === 'license' && (
        <Card className="p-5 space-y-4 text-xs">
          <div className="flex items-center gap-2">
            <Award size={16} className="text-accent" aria-hidden="true" />
            <h2 className="text-[15px] font-semibold text-text-pri">Ed25519 Signed Entitlements (`OPQL1.`)</h2>
          </div>
          {license && (
            <div className="p-3 rounded-[var(--radius-md)] border border-border bg-elev space-y-1">
              <div className="font-semibold text-text-pri">{license.customer} — Plan: {license.plan.toUpperCase()}</div>
              <div className="text-text-mut">Capabilities: {license.capabilities.join(', ')}</div>
            </div>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <input
              aria-label="Redeem OPQL1 license token"
              value={licenseToken}
              onChange={(e) => setLicenseToken(e.target.value)}
              placeholder="OPQL1.<payload>.<sig>"
              className="flex-1 min-w-[240px] h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev font-mono text-text-pri"
            />
            <Button size="sm" onClick={() => void redeemLicense()}>Redeem License</Button>
          </div>
        </Card>
      )}

      {tab === 'security' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <Card className="p-5 space-y-3">
            <div className="flex items-center gap-2">
              <KeyRound size={15} className="text-accent" aria-hidden="true" />
              <h2 className="text-[15px] font-semibold text-text-pri">Rotate Password</h2>
            </div>
            <input
              aria-label="Current password"
              type="password"
              value={curPw}
              onChange={(e) => setCurPw(e.target.value)}
              placeholder="Current password"
              className="w-full h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri"
            />
            <input
              aria-label="New password"
              type="password"
              value={nextPw}
              onChange={(e) => setNextPw(e.target.value)}
              placeholder="New password"
              className="w-full h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri"
            />
            <Button
              size="sm"
              onClick={async () => {
                setErr(null);
                try {
                  await apiJson('/api/auth/password', {
                    method: 'POST',
                    body: JSON.stringify({ current_password: curPw, new_password: nextPw }),
                  });
                  setCurPw('');
                  setNextPw('');
                  setNotice('Password rotated cleanly.');
                } catch (e) {
                  setErr(e instanceof Error ? e.message : 'Password rotation failed');
                }
              }}
            >
              Update Own Password
            </Button>
          </Card>

          <Card className="p-5 space-y-3">
            <h2 className="text-[15px] font-semibold text-text-pri">Shared AI Model Catalog</h2>
            <div className="flex gap-2">
              <Button
                size="xs"
                variant="outline"
                onClick={async () => {
                  const res = await apiJson<{ models: unknown[] }>('/api/ai/catalog');
                  setAiCatalogJson(JSON.stringify(res.models, null, 2));
                }}
              >
                Load Catalog
              </Button>
              <Button
                size="xs"
                onClick={async () => {
                  setErr(null);
                  try {
                    const models = JSON.parse(aiCatalogJson);
                    await apiJson('/api/ai/catalog', {
                      method: 'PUT',
                      body: JSON.stringify({ models }),
                    });
                    setNotice('Shared AI model catalog saved.');
                  } catch (e) {
                    setErr(e instanceof Error ? e.message : 'Invalid catalog JSON');
                  }
                }}
              >
                Save Catalog
              </Button>
            </div>
            <textarea
              aria-label="Shared AI model catalog JSON"
              rows={5}
              value={aiCatalogJson}
              onChange={(e) => setAiCatalogJson(e.target.value)}
              placeholder='[{"id":"claude-3-7-sonnet","provider":"anthropic","label":"Claude 3.7 Sonnet"}]'
              className="w-full p-2.5 rounded-[var(--radius-sm)] border border-border bg-elev font-mono text-text-pri"
            />
          </Card>
        </div>
      )}
    </div>
  );
}
