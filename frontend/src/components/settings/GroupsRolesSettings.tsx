import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Check,
  Copy,
  KeyRound,
  Link2,
  Pencil,
  Plus,
  RefreshCw,
  Server,
  Shield,
  Trash2,
  UserPlus,
  Users,
  X,
} from 'lucide-react';
import { Badge, Button, EmptyState } from '@/components/primitives';
import { Dialog, DialogPageContext } from '@/components/primitives/Dialog';
import { api } from '@/lib/api';
import {
  useAuthStore,
  type GrantEffect,
  type GrantScopeType,
  type PolicyConditions,
  type SSOProvider,
} from '@/stores/auth';
import { useToastStore } from '@/stores/toast';

const EMPTY_PROVIDERS: SSOProvider[] = [];

export interface PermissionInfo {
  id: string;
  category: string;
  description: string;
}

export interface RoleDef {
  id: string;
  tenant_id: string;
  name: string;
  description?: string;
  base_role?: string;
  is_system: boolean;
  permissions: string[];
}

export interface GroupMemberView {
  user_id: string;
  email: string;
  name?: string;
  provider?: string;
  source: 'manual' | 'sso_sync' | 'scim';
  disabled?: boolean;
}

export interface GroupRoleBindingView {
  id: string;
  group_id: string;
  role_id: string;
  role_name: string;
  base_role?: string;
  permissions: string[];
  scope_type: GrantScopeType;
  scope_id?: string;
  effect?: GrantEffect;
  conditions?: PolicyConditions;
}

export interface SCIMTokenView {
  id: string;
  tenant_id: string;
  name: string;
  prefix: string;
  created_by?: string;
  created_at: number;
  last_used_at?: number;
  revoked_at?: number;
}

interface SCIMTokenCreatedResponse {
  token: SCIMTokenView;
  secret: string;
}

export interface GroupDetail {
  id: string;
  tenant_id: string;
  name: string;
  description?: string;
  source: string;
  is_system?: boolean;
  member_count: number;
  members?: GroupMemberView[];
  bindings?: GroupRoleBindingView[];
}

export interface IdPGroupMapping {
  id: string;
  tenant_id: string;
  provider_id: string;
  external_group: string;
  group_id: string;
}

interface UserOption {
  id: string;
  email: string;
  name?: string;
  disabled?: boolean;
}

type Section = 'groups' | 'roles' | 'mappings' | 'scim';

function formatConditionsSummary(c?: PolicyConditions): string {
  if (!c) return '';
  const parts: string[] = [];
  if (c.require_recording) parts.push('Recording required');
  if (c.allowed_cidrs?.length) parts.push(`CIDR: ${c.allowed_cidrs.join(', ')}`);
  if (c.utc_hours_start !== undefined && c.utc_hours_end !== undefined) {
    parts.push(`UTC ${c.utc_hours_start}:00–${c.utc_hours_end}:00`);
  }
  return parts.join(' · ');
}

const SCOPE_OPTIONS: { value: GrantScopeType; label: string; placeholder: string }[] = [
  { value: 'global', label: 'Global (all resources)', placeholder: '' },
  { value: 'env', label: 'Environment tag (e.g. dev, prod, nonprod)', placeholder: 'dev' },
  { value: 'aws_account', label: 'AWS account / profile ID', placeholder: '123456789012' },
  { value: 'k8s_cluster', label: 'Kubernetes cluster ID', placeholder: 'prod-eks' },
];

function formatScope(scopeType: GrantScopeType, scopeID?: string): string {
  if (!scopeType || scopeType === 'global') return 'Global';
  return scopeID ? `${scopeType}:${scopeID}` : scopeType;
}

export function GroupsRolesSettings() {
  const pushToast = useToastStore((s) => s.push);
  const ssoConfig = useAuthStore((s) => s.config?.sso);
  const ssoProviders = ssoConfig?.providers ?? EMPTY_PROVIDERS;

  const [section, setSection] = useState<Section>('groups');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');

  const [groups, setGroups] = useState<GroupDetail[]>([]);
  const [roles, setRoles] = useState<RoleDef[]>([]);
  const [permissions, setPermissions] = useState<PermissionInfo[]>([]);
  const [mappings, setMappings] = useState<IdPGroupMapping[]>([]);
  const [users, setUsers] = useState<UserOption[]>([]);
  const [scimTokens, setScimTokens] = useState<SCIMTokenView[]>([]);

  const [selectedGroupId, setSelectedGroupId] = useState<string>('');

  // Group create / edit state
  const [groupDialogOpen, setGroupDialogOpen] = useState(false);
  const [editingGroup, setEditingGroup] = useState<GroupDetail | null>(null);
  const [groupName, setGroupName] = useState('');
  const [groupDesc, setGroupDesc] = useState('');

  // Member + binding forms inside selected group
  const [addMemberUserId, setAddMemberUserId] = useState('');
  const [bindRoleId, setBindRoleId] = useState('');
  const [bindScopeType, setBindScopeType] = useState<GrantScopeType>('global');
  const [bindScopeId, setBindScopeId] = useState('');
  const [bindEffect, setBindEffect] = useState<GrantEffect>('allow');
  const [bindRequireRec, setBindRequireRec] = useState(false);
  const [bindCidrs, setBindCidrs] = useState('');
  const [bindHourStart, setBindHourStart] = useState('');
  const [bindHourEnd, setBindHourEnd] = useState('');

  // SCIM token form state
  const [scimTokenName, setScimTokenName] = useState('');
  const [createdSCIMSecret, setCreatedSCIMSecret] = useState<SCIMTokenCreatedResponse | null>(null);
  const [copiedKey, setCopiedKey] = useState('');

  // Custom role modal state
  const [roleDialogOpen, setRoleDialogOpen] = useState(false);
  const [editingRole, setEditingRole] = useState<RoleDef | null>(null);
  const [roleName, setRoleName] = useState('');
  const [roleDesc, setRoleDesc] = useState('');
  const [rolePerms, setRolePerms] = useState<string[]>([]);

  // IdP mapping create form
  const [mappingProvider, setMappingProvider] = useState('');
  const [mappingExternal, setMappingExternal] = useState('');
  const [mappingGroupId, setMappingGroupId] = useState('');

  const fetchAll = useCallback(async () => {
    setLoading(true);
    const [gRes, rRes, pRes, mRes, uRes, sRes] = await Promise.all([
      api.get<GroupDetail[]>('/api/groups'),
      api.get<RoleDef[]>('/api/roles'),
      api.get<{ permissions: PermissionInfo[] }>('/api/permissions'),
      api.get<IdPGroupMapping[]>('/api/idp-mappings'),
      api.get<UserOption[]>('/api/users'),
      api.get<SCIMTokenView[]>('/api/scim/tokens'),
    ]);
    if (gRes.ok) {
      setGroups(gRes.data);
      setSelectedGroupId((prev) =>
        prev && gRes.data.some((g) => g.id === prev) ? prev : gRes.data[0]?.id ?? ''
      );
      setMappingGroupId((prev) => prev || gRes.data[0]?.id || '');
    }
    if (rRes.ok) {
      setRoles(rRes.data);
      setBindRoleId((prev) => prev || rRes.data[0]?.id || '');
    }
    if (pRes.ok) {
      setPermissions(pRes.data.permissions ?? []);
    }
    if (mRes.ok) {
      setMappings(mRes.data);
    }
    if (uRes.ok) {
      setUsers(uRes.data);
    }
    if (sRes.ok) {
      setScimTokens(sRes.data ?? []);
    }
    if (!gRes.ok || !rRes.ok) {
      setError('Could not load group and role configuration.');
    } else {
      setError('');
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    void fetchAll();
    const onUsersChanged = () => void fetchAll();
    window.addEventListener('operquay:users-changed', onUsersChanged);
    return () => window.removeEventListener('operquay:users-changed', onUsersChanged);
  }, [fetchAll]);

  useEffect(() => {
    if (!mappingProvider && ssoProviders.length > 0) {
      setMappingProvider(ssoProviders[0].id);
    }
  }, [mappingProvider, ssoProviders]);

  const selectedGroup = useMemo(
    () => groups.find((g) => g.id === selectedGroupId) ?? null,
    [groups, selectedGroupId]
  );

  const permissionsByCategory = useMemo(() => {
    const grouped = new Map<string, PermissionInfo[]>();
    for (const p of permissions) {
      const cat = p.category || 'General';
      const arr = grouped.get(cat) ?? [];
      arr.push(p);
      grouped.set(cat, arr);
    }
    return [...grouped.entries()];
  }, [permissions]);

  const availableMembers = useMemo(() => {
    if (!selectedGroup) return users;
    const memberIds = new Set((selectedGroup.members ?? []).map((m) => m.user_id));
    return users.filter((u) => !u.disabled && !memberIds.has(u.id));
  }, [selectedGroup, users]);

  const notifyChanged = async () => {
    window.dispatchEvent(new Event('operquay:users-changed'));
    await fetchAll();
  };

  const openCreateGroup = () => {
    setEditingGroup(null);
    setGroupName('');
    setGroupDesc('');
    setGroupDialogOpen(true);
  };

  const openEditGroup = (g: GroupDetail) => {
    setEditingGroup(g);
    setGroupName(g.name);
    setGroupDesc(g.description ?? '');
    setGroupDialogOpen(true);
  };

  const saveGroup = async () => {
    setBusy('group');
    setError('');
    const payload = { name: groupName.trim(), description: groupDesc.trim() };
    const res = editingGroup
      ? await api.put<GroupDetail>(`/api/groups/${encodeURIComponent(editingGroup.id)}`, payload)
      : await api.post<GroupDetail>('/api/groups', payload);
    if (res.ok) {
      setGroupDialogOpen(false);
      if (!editingGroup) setSelectedGroupId(res.data.id);
      pushToast({ variant: 'success', title: editingGroup ? 'Group updated' : 'Group created' });
      await notifyChanged();
    } else {
      setError(res.error.message || 'Could not save group.');
    }
    setBusy('');
  };

  const deleteGroup = async (g: GroupDetail) => {
    setBusy(`del-grp-${g.id}`);
    setError('');
    const res = await api.delete(`/api/groups/${encodeURIComponent(g.id)}`);
    if (res.ok) {
      pushToast({ variant: 'success', title: `Deleted group ${g.name}` });
      await notifyChanged();
    } else {
      setError(res.error.message || 'Could not delete group.');
    }
    setBusy('');
  };

  const addMember = async () => {
    if (!selectedGroup || !addMemberUserId) return;
    setBusy('add-member');
    setError('');
    const res = await api.post(`/api/groups/${encodeURIComponent(selectedGroup.id)}/members`, {
      user_id: addMemberUserId,
    });
    if (res.ok) {
      setAddMemberUserId('');
      pushToast({ variant: 'success', title: 'Member added to group' });
      await notifyChanged();
    } else {
      setError(res.error.message || 'Could not add group member.');
    }
    setBusy('');
  };

  const removeMember = async (userId: string) => {
    if (!selectedGroup) return;
    setBusy(`rem-mem-${userId}`);
    setError('');
    const res = await api.delete(
      `/api/groups/${encodeURIComponent(selectedGroup.id)}/members/${encodeURIComponent(userId)}`
    );
    if (res.ok) {
      pushToast({ variant: 'success', title: 'Member removed from group' });
      await notifyChanged();
    } else {
      setError(res.error.message || 'Could not remove member from group.');
    }
    setBusy('');
  };

  const bindRole = async () => {
    if (!selectedGroup || !bindRoleId) return;
    setBusy('bind-role');
    setError('');
    const conditions: PolicyConditions = {};
    let hasConditions = false;
    if (bindRequireRec && bindEffect !== 'deny') {
      conditions.require_recording = true;
      hasConditions = true;
    }
    const cidrs = bindCidrs
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (cidrs.length > 0) {
      conditions.allowed_cidrs = cidrs;
      hasConditions = true;
    }
    if (bindHourStart.trim() !== '' && bindHourEnd.trim() !== '') {
      conditions.utc_hours_start = Number(bindHourStart);
      conditions.utc_hours_end = Number(bindHourEnd);
      hasConditions = true;
    }
    const payload: Record<string, unknown> = {
      role_id: bindRoleId,
      scope_type: bindScopeType,
      scope_id: bindScopeType === 'global' ? '' : bindScopeId.trim(),
    };
    if (bindEffect !== 'allow') {
      payload.effect = bindEffect;
    }
    if (hasConditions) {
      payload.conditions = conditions;
    }
    const res = await api.post(`/api/groups/${encodeURIComponent(selectedGroup.id)}/roles`, payload);
    if (res.ok) {
      setBindScopeId('');
      setBindEffect('allow');
      setBindRequireRec(false);
      setBindCidrs('');
      setBindHourStart('');
      setBindHourEnd('');
      pushToast({ variant: 'success', title: 'Role bound to group' });
      await notifyChanged();
    } else {
      setError(res.error.message || 'Could not bind role.');
    }
    setBusy('');
  };

  const unbindRole = async (bindingId: string) => {
    if (!selectedGroup) return;
    setBusy(`unbind-${bindingId}`);
    setError('');
    const res = await api.delete(
      `/api/groups/${encodeURIComponent(selectedGroup.id)}/roles/${encodeURIComponent(bindingId)}`
    );
    if (res.ok) {
      pushToast({ variant: 'success', title: 'Role binding removed' });
      await notifyChanged();
    } else {
      setError(res.error.message || 'Could not remove role binding.');
    }
    setBusy('');
  };

  const openCreateRole = () => {
    setEditingRole(null);
    setRoleName('');
    setRoleDesc('');
    setRolePerms(['instances:read', 'k8s:read']);
    setRoleDialogOpen(true);
  };

  const openEditRole = (r: RoleDef) => {
    setEditingRole(r);
    setRoleName(r.name);
    setRoleDesc(r.description ?? '');
    setRolePerms([...r.permissions]);
    setRoleDialogOpen(true);
  };

  const toggleRolePerm = (permId: string) => {
    setRolePerms((prev) =>
      prev.includes(permId) ? prev.filter((p) => p !== permId) : [...prev, permId]
    );
  };

  const saveRole = async () => {
    setBusy('role');
    setError('');
    const payload = { name: roleName.trim(), description: roleDesc.trim(), permissions: rolePerms };
    const res = editingRole
      ? await api.put<RoleDef>(`/api/roles/${encodeURIComponent(editingRole.id)}`, payload)
      : await api.post<RoleDef>('/api/roles', payload);
    if (res.ok) {
      setRoleDialogOpen(false);
      pushToast({ variant: 'success', title: editingRole ? 'Custom role updated' : 'Custom role created' });
      await notifyChanged();
    } else {
      setError(res.error.message || 'Could not save custom role.');
    }
    setBusy('');
  };

  const deleteRole = async (r: RoleDef) => {
    setBusy(`del-role-${r.id}`);
    setError('');
    const res = await api.delete(`/api/roles/${encodeURIComponent(r.id)}`);
    if (res.ok) {
      pushToast({ variant: 'success', title: `Deleted role ${r.name}` });
      await notifyChanged();
    } else {
      setError(res.error.message || 'Could not delete role.');
    }
    setBusy('');
  };

  const createMapping = async () => {
    setBusy('create-mapping');
    setError('');
    const res = await api.post('/api/idp-mappings', {
      provider_id: mappingProvider.trim(),
      external_group: mappingExternal.trim(),
      group_id: mappingGroupId,
    });
    if (res.ok) {
      setMappingExternal('');
      pushToast({ variant: 'success', title: 'IdP group mapping added' });
      await fetchAll();
    } else {
      setError(res.error.message || 'Could not add IdP group mapping.');
    }
    setBusy('');
  };

  const deleteMapping = async (id: string) => {
    setBusy(`del-map-${id}`);
    setError('');
    const res = await api.delete(`/api/idp-mappings/${encodeURIComponent(id)}`);
    if (res.ok) {
      pushToast({ variant: 'success', title: 'IdP group mapping removed' });
      await fetchAll();
    } else {
      setError(res.error.message || 'Could not remove IdP group mapping.');
    }
    setBusy('');
  };

  const createSCIMToken = async () => {
    if (!scimTokenName.trim()) return;
    setBusy('scim-create');
    setError('');
    const res = await api.post<SCIMTokenCreatedResponse>('/api/scim/tokens', {
      name: scimTokenName.trim(),
    });
    if (res.ok) {
      setScimTokenName('');
      setCreatedSCIMSecret(res.data);
      pushToast({ variant: 'success', title: 'SCIM bearer token generated' });
      await fetchAll();
    } else {
      setError(res.error.message || 'Could not create SCIM token.');
    }
    setBusy('');
  };

  const revokeSCIMToken = async (id: string, name: string) => {
    setBusy(`scim-rev-${id}`);
    setError('');
    const res = await api.delete(`/api/scim/tokens/${encodeURIComponent(id)}`);
    if (res.ok) {
      pushToast({ variant: 'success', title: `Revoked SCIM token ${name}` });
      await fetchAll();
    } else {
      setError(res.error.message || 'Could not revoke SCIM token.');
    }
    setBusy('');
  };

  const copyValue = async (key: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey((prev) => (prev === key ? '' : prev)), 2000);
    } catch {
      pushToast({ variant: 'danger', title: 'Could not copy to clipboard' });
    }
  };

  const groupNameById = useMemo(() => {
    const map = new Map<string, string>();
    for (const g of groups) map.set(g.id, g.name);
    return map;
  }, [groups]);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-border">
        <div className="inline-flex items-center gap-1 rounded-md border border-border bg-elev/50 p-1" role="tablist" aria-label="RBAC sections">
          {(
            [
              { id: 'groups', label: `Groups (${groups.length})`, icon: <Users size={13} /> },
              { id: 'roles', label: `Roles (${roles.length})`, icon: <Shield size={13} /> },
              { id: 'mappings', label: `IdP Mappings (${mappings.length})`, icon: <Link2 size={13} /> },
              { id: 'scim', label: `SCIM 2.0 (${scimTokens.length})`, icon: <Server size={13} /> },
            ] as const
          ).map((item) => {
            const active = section === item.id;
            return (
              <button
                key={item.id}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => setSection(item.id)}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-[12px] font-medium transition-colors ${
                  active
                    ? 'bg-surface text-text-pri border border-border shadow-xs'
                    : 'text-text-mut hover:text-text-pri border border-transparent'
                }`}
              >
                {item.icon}
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>

        <div className="flex items-center gap-2">
          {section === 'groups' && (
            <Button type="button" size="sm" variant="primary" icon={<Plus size={13} />} onClick={openCreateGroup}>
              New group
            </Button>
          )}
          {section === 'roles' && (
            <Button type="button" size="sm" variant="primary" icon={<Plus size={13} />} onClick={openCreateRole}>
              New custom role
            </Button>
          )}
          <Button
            type="button"
            size="sm"
            variant="outline"
            icon={<RefreshCw size={13} className={loading ? 'animate-spin' : ''} />}
            onClick={() => void fetchAll()}
            disabled={loading}
          >
            Refresh
          </Button>
        </div>
      </div>

      {error && (
        <div role="alert" className="rounded-md border border-danger/40 bg-danger/10 px-3 py-2 text-[12px] text-danger flex items-center justify-between gap-2">
          <span>{error}</span>
          <button type="button" onClick={() => setError('')} className="text-danger/80 hover:text-danger" aria-label="Dismiss error">
            <X size={14} />
          </button>
        </div>
      )}

      {section === 'groups' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <div className="lg:col-span-5 rounded-lg border border-border bg-surface overflow-hidden">
            <div className="px-3.5 py-2.5 border-b border-border bg-elev/40 text-[12px] font-semibold text-text-pri">
              User Groups
            </div>
            <div className="divide-y divide-border/70">
              {groups.map((g) => {
                const selected = g.id === selectedGroup?.id;
                return (
                  <button
                    key={g.id}
                    type="button"
                    onClick={() => setSelectedGroupId(g.id)}
                    className={`w-full text-left px-3.5 py-3 transition-colors ${
                      selected ? 'bg-[var(--accent-dim)]' : 'hover:bg-surface-hover'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="text-[13px] font-medium text-text-pri truncate">{g.name}</span>
                        {g.is_system && <Badge variant="default">System</Badge>}
                      </div>
                      <span className="text-[11px] font-mono text-text-dim shrink-0">
                        {g.member_count} {g.member_count === 1 ? 'member' : 'members'}
                      </span>
                    </div>
                    {g.description && (
                      <p className="mt-0.5 text-[11px] text-text-mut line-clamp-1">{g.description}</p>
                    )}
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {(g.bindings ?? []).map((b) => (
                        <Badge
                          key={b.id}
                          variant={b.effect === 'deny' ? 'danger' : b.scope_type === 'global' ? 'accent' : 'default'}
                        >
                          {b.effect === 'deny' ? 'Deny · ' : ''}
                          {b.role_name || b.role_id} · {formatScope(b.scope_type, b.scope_id)}
                        </Badge>
                      ))}
                    </div>
                  </button>
                );
              })}
              {!loading && groups.length === 0 && (
                <div className="p-4">
                  <EmptyState title="No groups configured" description="Create a group to assign roles and permissions." />
                </div>
              )}
            </div>
          </div>

          <div className="lg:col-span-7 space-y-4">
            {selectedGroup ? (
              <div className="rounded-lg border border-border bg-surface overflow-hidden">
                <div className="px-4 py-3 border-b border-border bg-elev/40 flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-[14px] font-semibold text-text-pri">{selectedGroup.name}</h3>
                      {selectedGroup.is_system && <Badge variant="default">System group</Badge>}
                    </div>
                    <p className="text-[12px] text-text-mut mt-0.5">
                      {selectedGroup.description || 'No description'}
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button type="button" size="xs" variant="outline" icon={<Pencil size={12} />} onClick={() => openEditGroup(selectedGroup)}>
                      Edit
                    </Button>
                    {!selectedGroup.is_system && (
                      <Button
                        type="button"
                        size="xs"
                        variant="danger"
                        icon={<Trash2 size={12} />}
                        disabled={!!busy}
                        onClick={() => void deleteGroup(selectedGroup)}
                      >
                        Delete
                      </Button>
                    )}
                  </div>
                </div>

                {/* Role bindings */}
                <div className="p-4 border-b border-border space-y-3">
                  <div className="flex items-center justify-between">
                    <h4 className="text-[12px] font-semibold uppercase tracking-wider text-text-dim">
                      Role Bindings
                    </h4>
                  </div>
                  <div className="space-y-1.5">
                    {(selectedGroup.bindings ?? []).map((b) => {
                      const condText = formatConditionsSummary(b.conditions);
                      return (
                        <div key={b.id} className="flex items-center justify-between gap-2 rounded-md border border-border bg-bg px-3 py-2 text-[12px]">
                          <div className="flex flex-wrap items-center gap-2">
                            {b.effect === 'deny' ? (
                              <Badge variant="danger">Deny</Badge>
                            ) : (
                              <Badge variant="success">Allow</Badge>
                            )}
                            <span className="font-medium text-text-pri">{b.role_name || b.role_id}</span>
                            <Badge variant={b.scope_type === 'global' ? 'accent' : 'default'}>
                              {formatScope(b.scope_type, b.scope_id)}
                            </Badge>
                            {condText && <Badge variant="warn">{condText}</Badge>}
                          </div>
                          <Button
                            type="button"
                            size="xs"
                            variant="ghost"
                            aria-label={`Remove binding ${b.role_name}`}
                            disabled={!!busy}
                            onClick={() => void unbindRole(b.id)}
                          >
                            <Trash2 size={12} className="text-text-dim hover:text-danger" />
                          </Button>
                        </div>
                      );
                    })}
                    {(selectedGroup.bindings ?? []).length === 0 && (
                      <p className="text-[12px] text-text-dim">No role bindings assigned to this group yet.</p>
                    )}
                  </div>

                  <div className="space-y-2 pt-2">
                    <div className="grid grid-cols-1 sm:grid-cols-12 gap-2">
                      <select
                        aria-label="Select binding effect"
                        value={bindEffect}
                        onChange={(e) => setBindEffect(e.target.value as GrantEffect)}
                        className="sm:col-span-2 h-8 px-2.5 rounded-md border border-border bg-bg text-[12px] text-text-pri focus:outline-none focus:border-accent"
                      >
                        <option value="allow">Allow</option>
                        <option value="deny">Deny</option>
                      </select>
                      <select
                        aria-label="Select role to bind"
                        value={bindRoleId}
                        onChange={(e) => setBindRoleId(e.target.value)}
                        className="sm:col-span-4 h-8 px-2.5 rounded-md border border-border bg-bg text-[12px] text-text-pri focus:outline-none focus:border-accent"
                      >
                        {roles.map((r) => (
                          <option key={r.id} value={r.id}>
                            {r.name} {r.is_system ? '(System)' : '(Custom)'}
                          </option>
                        ))}
                      </select>
                      <select
                        aria-label="Select scope type"
                        value={bindScopeType}
                        onChange={(e) => setBindScopeType(e.target.value as GrantScopeType)}
                        className="sm:col-span-3 h-8 px-2.5 rounded-md border border-border bg-bg text-[12px] text-text-pri focus:outline-none focus:border-accent"
                      >
                        {SCOPE_OPTIONS.map((opt) => (
                          <option key={opt.value} value={opt.value}>
                            {opt.label}
                          </option>
                        ))}
                      </select>
                      {bindScopeType !== 'global' && (
                        <input
                          aria-label="Scope target ID"
                          placeholder={SCOPE_OPTIONS.find((o) => o.value === bindScopeType)?.placeholder || 'target id'}
                          value={bindScopeId}
                          onChange={(e) => setBindScopeId(e.target.value)}
                          className="sm:col-span-3 h-8 px-2.5 rounded-md border border-border bg-bg text-[12px] text-text-pri focus:outline-none focus:border-accent"
                        />
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-3 rounded-md border border-border/70 bg-elev/30 px-3 py-2 text-[12px]">
                      {bindEffect !== 'deny' && (
                        <label className="inline-flex items-center gap-1.5 text-text-pri cursor-pointer">
                          <input
                            type="checkbox"
                            aria-label="Require session recording"
                            checked={bindRequireRec}
                            onChange={(e) => setBindRequireRec(e.target.checked)}
                            className="accent-[var(--accent)]"
                          />
                          <span>Require recording</span>
                        </label>
                      )}
                      <input
                        aria-label="Allowed CIDRs"
                        placeholder="Allowed CIDRs (comma-separated)"
                        value={bindCidrs}
                        onChange={(e) => setBindCidrs(e.target.value)}
                        className="flex-1 min-w-[180px] h-7 px-2 rounded border border-border bg-bg text-[12px] text-text-pri focus:outline-none focus:border-accent"
                      />
                      <div className="flex items-center gap-1.5 text-text-mut">
                        <span>UTC</span>
                        <input
                          type="number"
                          min={0}
                          max={23}
                          aria-label="UTC hours start"
                          placeholder="0"
                          value={bindHourStart}
                          onChange={(e) => setBindHourStart(e.target.value)}
                          className="w-14 h-7 px-2 rounded border border-border bg-bg text-[12px] text-text-pri focus:outline-none focus:border-accent"
                        />
                        <span>to</span>
                        <input
                          type="number"
                          min={1}
                          max={24}
                          aria-label="UTC hours end"
                          placeholder="24"
                          value={bindHourEnd}
                          onChange={(e) => setBindHourEnd(e.target.value)}
                          className="w-14 h-7 px-2 rounded border border-border bg-bg text-[12px] text-text-pri focus:outline-none focus:border-accent"
                        />
                      </div>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        disabled={!bindRoleId || (bindScopeType !== 'global' && !bindScopeId.trim()) || !!busy}
                        onClick={() => void bindRole()}
                      >
                        Bind role
                      </Button>
                    </div>
                  </div>
                </div>

                {/* Members */}
                <div className="p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h4 className="text-[12px] font-semibold uppercase tracking-wider text-text-dim">
                      Members ({selectedGroup.members?.length ?? 0})
                    </h4>
                    <div className="flex items-center gap-2">
                      <select
                        aria-label="Select user to add to group"
                        value={addMemberUserId}
                        onChange={(e) => setAddMemberUserId(e.target.value)}
                        className="h-8 px-2.5 rounded-md border border-border bg-bg text-[12px] text-text-pri focus:outline-none focus:border-accent max-w-[240px]"
                      >
                        <option value="">Add user...</option>
                        {availableMembers.map((u) => (
                          <option key={u.id} value={u.id}>
                            {u.email}
                          </option>
                        ))}
                      </select>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        icon={<UserPlus size={12} />}
                        disabled={!addMemberUserId || !!busy}
                        onClick={() => void addMember()}
                      >
                        Add
                      </Button>
                    </div>
                  </div>

                  <div className="divide-y divide-border/60 border border-border rounded-md overflow-hidden">
                    {(selectedGroup.members ?? []).map((m) => (
                      <div key={`${m.user_id}-${m.source}`} className="flex items-center justify-between gap-2 px-3 py-2 bg-bg text-[12px]">
                        <div className="min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-text-pri truncate">{m.email}</span>
                            <Badge variant={m.source === 'manual' ? 'default' : 'accent'}>
                              {m.source === 'scim' ? 'SCIM 2.0' : m.source === 'sso_sync' ? 'IdP Sync' : 'Manual'}
                            </Badge>
                          </div>
                          {m.name && <div className="text-[11px] text-text-dim">{m.name}</div>}
                        </div>
                        <Button
                          type="button"
                          size="xs"
                          variant="ghost"
                          aria-label={`Remove member ${m.email}`}
                          disabled={!!busy}
                          onClick={() => void removeMember(m.user_id)}
                        >
                          <Trash2 size={12} className="text-text-dim hover:text-danger" />
                        </Button>
                      </div>
                    ))}
                    {(selectedGroup.members ?? []).length === 0 && (
                      <div className="px-3 py-4 text-center text-[12px] text-text-dim bg-bg">
                        No active members in this group.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            ) : (
              <EmptyState title="Select a group" description="Pick a group on the left to manage its members and role bindings." />
            )}
          </div>
        </div>
      )}

      {section === 'roles' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {roles.map((r) => (
            <div key={r.id} className="rounded-lg border border-border bg-surface p-4 flex flex-col justify-between gap-3">
              <div>
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2 min-w-0">
                    <h4 className="text-[13px] font-semibold text-text-pri truncate">{r.name}</h4>
                    {r.is_system ? <Badge variant="default">System</Badge> : <Badge variant="accent">Custom</Badge>}
                  </div>
                  {!r.is_system && (
                    <div className="flex items-center gap-1 shrink-0">
                      <Button type="button" size="xs" variant="ghost" aria-label={`Edit role ${r.name}`} onClick={() => openEditRole(r)}>
                        <Pencil size={12} />
                      </Button>
                      <Button type="button" size="xs" variant="ghost" aria-label={`Delete role ${r.name}`} disabled={!!busy} onClick={() => void deleteRole(r)}>
                        <Trash2 size={12} className="text-danger" />
                      </Button>
                    </div>
                  )}
                </div>
                {r.description && <p className="mt-1 text-[12px] text-text-mut">{r.description}</p>}
                <div className="mt-2.5 flex flex-wrap gap-1">
                  {r.permissions.map((perm) => (
                    <span key={perm} className="px-1.5 py-0.5 rounded border border-border bg-bg font-mono text-[10px] text-text-mut">
                      {perm}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {section === 'mappings' && (
        <div className="space-y-4">
          <div className="rounded-lg border border-border bg-surface p-4 space-y-3">
            <div className="flex items-center gap-2">
              <KeyRound size={15} className="text-accent" />
              <h4 className="text-[13px] font-semibold text-text-pri">Add IdP Group Mapping</h4>
            </div>
            <p className="text-[12px] text-text-mut">
              Map external OIDC or SAML group claims to Operquay groups. Mapped memberships sync automatically at each SSO sign-in while preserving manual memberships.
            </p>
            <div className="grid grid-cols-1 sm:grid-cols-12 gap-2">
              <div className="sm:col-span-3">
                {ssoProviders.length > 0 ? (
                  <select
                    aria-label="SSO Provider"
                    value={mappingProvider}
                    onChange={(e) => setMappingProvider(e.target.value)}
                    className="w-full h-9 px-2.5 rounded-md border border-border bg-bg text-[12px] text-text-pri focus:outline-none focus:border-accent"
                  >
                    {ssoProviders.map((p) => (
                      <option key={p.id} value={p.id}>
                        {p.label} ({p.id})
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    aria-label="Provider ID"
                    placeholder="Provider ID (e.g. okta)"
                    value={mappingProvider}
                    onChange={(e) => setMappingProvider(e.target.value)}
                    className="w-full h-9 px-2.5 rounded-md border border-border bg-bg text-[12px] text-text-pri focus:outline-none focus:border-accent"
                  />
                )}
              </div>
              <input
                aria-label="External IdP group name"
                placeholder="External group claim (e.g. AWS-Prod-Admins)"
                value={mappingExternal}
                onChange={(e) => setMappingExternal(e.target.value)}
                className="sm:col-span-4 h-9 px-2.5 rounded-md border border-border bg-bg text-[12px] text-text-pri focus:outline-none focus:border-accent"
              />
              <select
                aria-label="Target Operquay group"
                value={mappingGroupId}
                onChange={(e) => setMappingGroupId(e.target.value)}
                className="sm:col-span-3 h-9 px-2.5 rounded-md border border-border bg-bg text-[12px] text-text-pri focus:outline-none focus:border-accent"
              >
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </select>
              <Button
                type="button"
                size="sm"
                variant="primary"
                className="sm:col-span-2"
                disabled={!mappingProvider.trim() || !mappingExternal.trim() || !mappingGroupId || !!busy}
                onClick={() => void createMapping()}
              >
                Add mapping
              </Button>
            </div>
          </div>

          <div className="rounded-lg border border-border bg-surface overflow-hidden">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-border bg-elev/60 text-[11px] font-medium text-text-mut">
                  <th className="px-3 py-2">Provider</th>
                  <th className="px-3 py-2">External Group Claim</th>
                  <th className="px-3 py-2">Operquay Group</th>
                  <th className="w-16 px-3 py-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60 text-[12px]">
                {mappings.map((m) => (
                  <tr key={m.id} className="hover:bg-surface-hover/50">
                    <td className="px-3 py-2 font-mono text-text-pri">{m.provider_id}</td>
                    <td className="px-3 py-2 font-mono text-text-pri">{m.external_group}</td>
                    <td className="px-3 py-2 text-text-pri">{groupNameById.get(m.group_id) || m.group_id}</td>
                    <td className="px-3 py-2 text-right">
                      <Button
                        type="button"
                        size="xs"
                        variant="ghost"
                        aria-label={`Delete mapping ${m.external_group}`}
                        disabled={!!busy}
                        onClick={() => void deleteMapping(m.id)}
                      >
                        <Trash2 size={12} className="text-danger" />
                      </Button>
                    </td>
                  </tr>
                ))}
                {mappings.length === 0 && (
                  <tr>
                    <td colSpan={4} className="px-4 py-6 text-center text-[12px] text-text-dim">
                      No IdP group mappings configured yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {section === 'scim' && (
        <div className="space-y-4">
          <div className="rounded-lg border border-border bg-surface p-4 space-y-3">
            <div className="flex items-center gap-2">
              <Server size={15} className="text-accent" />
              <h4 className="text-[13px] font-semibold text-text-pri">SCIM 2.0 Provisioning Endpoint</h4>
            </div>
            <p className="text-[12px] text-text-mut">
              Configure your identity provider (Okta, Microsoft Entra ID, Google Workspace) with this SCIM 2.0 base URL and a tenant-scoped bearer token below.
            </p>
            <div className="flex items-center gap-2 rounded-md border border-border bg-bg px-3 py-2">
              <code className="flex-1 text-[12px] font-mono text-text-pri truncate">
                {`${typeof window !== 'undefined' ? window.location.origin : ''}/scim/v2`}
              </code>
              <Button
                type="button"
                size="xs"
                variant="outline"
                icon={copiedKey === 'scim-url' ? <Check size={12} /> : <Copy size={12} />}
                onClick={() => void copyValue('scim-url', `${window.location.origin}/scim/v2`)}
              >
                {copiedKey === 'scim-url' ? 'Copied' : 'Copy URL'}
              </Button>
            </div>
          </div>

          {createdSCIMSecret && (
            <div role="status" className="rounded-lg border border-accent/40 bg-[var(--accent-dim)] p-4 space-y-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[12px] font-semibold text-text-pri">
                  Copy your new SCIM bearer token ({createdSCIMSecret.token.name}) — it will only be shown once.
                </span>
                <button
                  type="button"
                  onClick={() => setCreatedSCIMSecret(null)}
                  className="text-text-mut hover:text-text-pri"
                  aria-label="Dismiss SCIM secret"
                >
                  <X size={14} />
                </button>
              </div>
              <div className="flex items-center gap-2 rounded-md border border-border bg-bg px-3 py-2">
                <code className="flex-1 text-[12px] font-mono text-text-pri break-all">{createdSCIMSecret.secret}</code>
                <Button
                  type="button"
                  size="xs"
                  variant="primary"
                  icon={copiedKey === 'scim-secret' ? <Check size={12} /> : <Copy size={12} />}
                  onClick={() => void copyValue('scim-secret', createdSCIMSecret.secret)}
                >
                  {copiedKey === 'scim-secret' ? 'Copied' : 'Copy token'}
                </Button>
              </div>
            </div>
          )}

          <div className="rounded-lg border border-border bg-surface p-4 space-y-3">
            <h4 className="text-[13px] font-semibold text-text-pri">Generate Bearer Token</h4>
            <div className="flex flex-wrap items-center gap-2">
              <input
                aria-label="SCIM token name"
                placeholder="Token label (e.g. Okta Production SCIM)"
                value={scimTokenName}
                onChange={(e) => setScimTokenName(e.target.value)}
                className="flex-1 min-w-[220px] h-9 px-2.5 rounded-md border border-border bg-bg text-[12px] text-text-pri focus:outline-none focus:border-accent"
              />
              <Button
                type="button"
                size="sm"
                variant="primary"
                disabled={!scimTokenName.trim() || !!busy}
                onClick={() => void createSCIMToken()}
              >
                Generate token
              </Button>
            </div>
          </div>

          <div className="rounded-lg border border-border bg-surface overflow-hidden">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-border bg-elev/60 text-[11px] font-medium text-text-mut">
                  <th className="px-3 py-2">Name</th>
                  <th className="px-3 py-2">Prefix</th>
                  <th className="px-3 py-2">Status</th>
                  <th className="px-3 py-2">Last used</th>
                  <th className="w-20 px-3 py-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60 text-[12px]">
                {scimTokens.map((tok) => (
                  <tr key={tok.id} className="hover:bg-surface-hover/50">
                    <td className="px-3 py-2 font-medium text-text-pri">{tok.name}</td>
                    <td className="px-3 py-2 font-mono text-text-mut">{tok.prefix}…</td>
                    <td className="px-3 py-2">
                      {tok.revoked_at ? <Badge variant="danger">Revoked</Badge> : <Badge variant="success">Active</Badge>}
                    </td>
                    <td className="px-3 py-2 text-text-dim">
                      {tok.last_used_at ? new Date(tok.last_used_at * 1000).toLocaleDateString() : 'Never'}
                    </td>
                    <td className="px-3 py-2 text-right">
                      {!tok.revoked_at && (
                        <Button
                          type="button"
                          size="xs"
                          variant="ghost"
                          aria-label={`Revoke token ${tok.name}`}
                          disabled={!!busy}
                          onClick={() => void revokeSCIMToken(tok.id, tok.name)}
                        >
                          Revoke
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
                {scimTokens.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-6 text-center text-[12px] text-text-dim">
                      No SCIM bearer tokens issued yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Group create/edit dialog */}
      <DialogPageContext.Provider value={false}>
        <Dialog
          open={groupDialogOpen}
          onOpenChange={setGroupDialogOpen}
          title={editingGroup ? `Edit group · ${editingGroup.name}` : 'Create group'}
          size="md"
        >
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              void saveGroup();
            }}
          >
            <label className="block space-y-1 text-[12px] font-medium text-text-mut">
              <span>Group name</span>
              <input
                aria-label="Group name"
                required
                disabled={Boolean(editingGroup?.is_system)}
                value={groupName}
                onChange={(e) => setGroupName(e.target.value)}
                placeholder="e.g. Cloud-Operators"
                className="block w-full h-9 px-3 rounded-md border border-border bg-bg text-[13px] text-text-pri focus:outline-none focus:border-accent disabled:opacity-60"
              />
            </label>
            <label className="block space-y-1 text-[12px] font-medium text-text-mut">
              <span>Description</span>
              <input
                aria-label="Group description"
                value={groupDesc}
                onChange={(e) => setGroupDesc(e.target.value)}
                placeholder="Scope and purpose of this group"
                className="block w-full h-9 px-3 rounded-md border border-border bg-bg text-[13px] text-text-pri focus:outline-none focus:border-accent"
              />
            </label>
            <div className="flex justify-end gap-2 pt-2">
              <Button type="button" size="sm" variant="outline" onClick={() => setGroupDialogOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" size="sm" variant="primary" disabled={!groupName.trim() || !!busy}>
                {editingGroup ? 'Save group' : 'Create group'}
              </Button>
            </div>
          </form>
        </Dialog>

        <Dialog
          open={roleDialogOpen}
          onOpenChange={setRoleDialogOpen}
          title={editingRole ? `Edit custom role · ${editingRole.name}` : 'Create custom role'}
          size="lg"
        >
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              void saveRole();
            }}
          >
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <label className="block space-y-1 text-[12px] font-medium text-text-mut">
                <span>Role name</span>
                <input
                  aria-label="Role name"
                  required
                  value={roleName}
                  onChange={(e) => setRoleName(e.target.value)}
                  placeholder="e.g. K8s-Debug-Operator"
                  className="block w-full h-9 px-3 rounded-md border border-border bg-bg text-[13px] text-text-pri focus:outline-none focus:border-accent"
                />
              </label>
              <label className="block space-y-1 text-[12px] font-medium text-text-mut">
                <span>Description</span>
                <input
                  aria-label="Role description"
                  value={roleDesc}
                  onChange={(e) => setRoleDesc(e.target.value)}
                  placeholder="What holders of this role can do"
                  className="block w-full h-9 px-3 rounded-md border border-border bg-bg text-[13px] text-text-pri focus:outline-none focus:border-accent"
                />
              </label>
            </div>

            <div className="space-y-2.5 max-h-[45vh] overflow-y-auto pr-1">
              <div className="text-[11px] font-semibold uppercase tracking-wider text-text-dim">
                Permissions ({rolePerms.length} selected)
              </div>
              {permissionsByCategory.map(([category, items]) => (
                <div key={category} className="rounded-md border border-border bg-bg p-3 space-y-2">
                  <div className="text-[12px] font-semibold text-text-pri">{category}</div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                    {items.map((perm) => {
                      const checked = rolePerms.includes(perm.id);
                      return (
                        <label
                          key={perm.id}
                          className="flex items-start gap-2 rounded p-1.5 hover:bg-surface-hover cursor-pointer text-[12px]"
                        >
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={() => toggleRolePerm(perm.id)}
                            className="mt-0.5 rounded border-border accent-[var(--accent)]"
                          />
                          <div>
                            <div className="font-mono text-[11px] text-text-pri">{perm.id}</div>
                            <div className="text-[11px] text-text-dim leading-snug">{perm.description}</div>
                          </div>
                        </label>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-border">
              <Button type="button" size="sm" variant="outline" onClick={() => setRoleDialogOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" size="sm" variant="primary" disabled={!roleName.trim() || rolePerms.length === 0 || !!busy}>
                {editingRole ? 'Save role' : 'Create role'}
              </Button>
            </div>
          </form>
        </Dialog>
      </DialogPageContext.Provider>
    </div>
  );
}
