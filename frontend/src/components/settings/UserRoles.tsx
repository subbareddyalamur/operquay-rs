import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  KeyRound,
  MoreVertical,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  ShieldAlert,
  Trash2,
  UserCheck,
} from 'lucide-react';
import { Badge, Button, Input } from '@/components/primitives';
import { Dialog, DialogPageContext } from '@/components/primitives/Dialog';
import { api } from '@/lib/api';
import { canSendCredentials } from '@/lib/credentialTransport';
import { useAuthStore, type Role } from '@/stores/auth';

type UserGroupTag = {
  id: string;
  name: string;
  source: 'manual' | 'sso_sync';
};

type GroupOption = {
  id: string;
  name: string;
};

type User = {
  id: string;
  email: string;
  name?: string;
  role: Role;
  provider?: string;
  disabled?: boolean;
  role_override?: boolean;
  groups?: UserGroupTag[];
};

export function UserRoles({ currentUser }: { currentUser: string }) {
  const [users, setUsers] = useState<User[]>([]);
  const [availableGroups, setAvailableGroups] = useState<GroupOption[]>([]);
  const [editGroupIds, setEditGroupIds] = useState<string[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState('');
  const [loading, setLoading] = useState(true);
  const [loaded, setLoaded] = useState(false);
  const localLogin = useAuthStore((s) => s.config?.local);
  const canOptIn = useAuthStore((s) => s.config?.local_user_opt_in_allowed === true);
  const [adding, setAdding] = useState(false);
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState<Role>('readonly');
  const [localSignInEnabled, setLocalSignInEnabled] = useState(false);

  const [editing, setEditing] = useState<User | null>(null);
  const [editEmail, setEditEmail] = useState('');
  const [editName, setEditName] = useState('');
  const [resetting, setResetting] = useState<User | null>(null);
  const [replacement, setReplacement] = useState('');
  const [deleting, setDeleting] = useState<User | null>(null);

  const [search, setSearch] = useState('');
  const [roleFilter, setRoleFilter] = useState<'all' | Role>('all');
  const [emailSortAsc, setEmailSortAsc] = useState(true);
  const [menuUserId, setMenuUserId] = useState<string | null>(null);

  useEffect(() => {
    if (!menuUserId) return;
    const onDocClick = () => setMenuUserId(null);
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMenuUserId(null);
    };
    document.addEventListener('click', onDocClick);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('click', onDocClick);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [menuUserId]);

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    const [r, gRes] = await Promise.all([
      api.get<User[]>('/api/users'),
      api.get<GroupOption[]>('/api/groups').catch(() => null),
    ]);
    if (r.ok) {
      setUsers(r.data);
      setLoaded(true);
      setError('');
    } else {
      setError('Could not load users.');
    }
    if (gRes && gRes.ok && Array.isArray(gRes.data)) {
      const groupRows = gRes.data.filter(
        (g): g is GroupOption => Boolean(g && typeof g.id === 'string' && typeof g.name === 'string' && !('email' in g))
      );
      setAvailableGroups(groupRows);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    void fetchUsers();
    const onUsersChanged = () => void fetchUsers();
    window.addEventListener('operquay:users-changed', onUsersChanged);
    return () => {
      window.removeEventListener('operquay:users-changed', onUsersChanged);
    };
  }, [fetchUsers]);

  const openUserEdit = (user: User) => {
    setEditing(user);
    setEditEmail(user.email);
    setEditName(user.name || '');
    setEditGroupIds((user.groups ?? []).filter((g) => g.source !== 'sso_sync').map((g) => g.id));
    setResetting(null);
    setReplacement('');
    setDeleting(null);
    setError('');
  };

  const closeUserEdit = () => {
    setEditing(null);
    setResetting(null);
    setReplacement('');
    setDeleting(null);
    setError('');
  };

  const saveUserGroups = async (user: User) => {
    setBusy(`groups-${user.id}`);
    setError('');
    const result = await api.put(`/api/users/${encodeURIComponent(user.id)}/groups`, {
      group_ids: editGroupIds,
    });
    if (result.ok) {
      await fetchUsers();
      window.dispatchEvent(new Event('operquay:users-changed'));
    } else {
      setError(result.error.message || 'Could not update user groups.');
    }
    setBusy('');
  };

  const changeRole = async (user: User, nextRole: Role) => {
    setBusy(user.id);
    setError('');
    const result = await api.put(`/api/users/${encodeURIComponent(user.id)}/role`, { role: nextRole });
    if (result.ok) {
      setUsers((rows) => rows.map((row) => (row.id === user.id ? { ...row, role: nextRole } : row)));
      setEditing((prev) => (prev && prev.id === user.id ? { ...prev, role: nextRole } : prev));
    } else {
      setError('Could not change the role.');
    }
    setBusy('');
  };

  const createUser = async () => {
    setError('');
    if (!canSendCredentials('/api/users')) {
      setError('HTTPS is required to create a user. Open Operquay at its HTTPS address.');
      return;
    }
    setBusy('create');
    const result = await api.post<{ user: User }>('/api/users', {
      email,
      name,
      password,
      role,
      local_signin_enabled: canOptIn && localSignInEnabled,
    });
    if (result.ok) {
      setUsers((rows) => [...rows, result.data.user]);
      setAdding(false);
      setEmail('');
      setName('');
      setPassword('');
      setRole('readonly');
      setLocalSignInEnabled(false);
    } else {
      let reason = '';
      try {
        reason = (JSON.parse(result.error.message) as { error?: string }).error || '';
      } catch {
        /* response did not contain JSON */
      }
      const local = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
      const message =
        reason === 'HTTPS is required'
          ? `HTTPS is required. ${local ? 'Use your configured HTTPS address (for the local TLS setup, https://localhost:5443) and sign in again.' : 'Open this deployment using its HTTPS address and sign in again.'}`
          : reason === 'admin role required'
            ? 'An administrator account is required to create users.'
            : reason === 'cross-site request refused'
              ? 'The server refused a cross-site request. Open Operquay at its configured address and try again.'
              : result.error.status === 403
                ? 'The server refused this request. Check administrator access, HTTPS and the configured site address.'
                : result.error.status === 401
                  ? 'Your session has ended. Sign in again.'
                  : result.error.status === 409
                    ? 'A local user with this email already exists.'
                    : result.error.status === 503
                      ? 'PostgreSQL is required or unavailable.'
                      : 'Could not create the user. Check the email and password.';
      setError(message);
    }
    setBusy('');
  };

  const saveEdit = async () => {
    if (!editing || !canSendCredentials('/api/users')) {
      setError('HTTPS is required to edit users.');
      return;
    }
    setBusy(editing.id);
    setError('');
    const nextEmail = editEmail.trim().toLowerCase();
    const nextName = editName.trim();
    const result = await api.put(`/api/users/${encodeURIComponent(editing.id)}`, {
      email: editEmail.trim(),
      name: nextName,
    });
    if (result.ok) {
      setUsers((rows) => rows.map((u) => (u.id === editing.id ? { ...u, email: nextEmail, name: nextName } : u)));
      setEditing((prev) => (prev ? { ...prev, email: nextEmail, name: nextName } : null));
    } else {
      setError('Could not edit user. Check the email or try again.');
    }
    setBusy('');
  };

  const toggleUserDisabled = async (target: User) => {
    if (!canSendCredentials('/api/users')) {
      setError('HTTPS is required to change user status.');
      return;
    }
    const nextDisabled = !target.disabled;
    setBusy(target.id);
    setError('');
    const result = await api.put(`/api/users/${encodeURIComponent(target.id)}/status`, { disabled: nextDisabled });
    if (result.ok) {
      setUsers((rows) => rows.map((u) => (u.id === target.id ? { ...u, disabled: nextDisabled } : u)));
      setEditing((prev) => (prev && prev.id === target.id ? { ...prev, disabled: nextDisabled } : prev));
    } else {
      setError('Could not update user status.');
    }
    setBusy('');
  };

  const resetPassword = async () => {
    if (!resetting || !canSendCredentials('/api/users')) {
      setError('HTTPS is required to reset passwords.');
      return;
    }
    setBusy(resetting.id);
    setError('');
    const result = await api.post(`/api/users/${encodeURIComponent(resetting.id)}/password`, { new_password: replacement });
    if (result.ok) {
      setResetting(null);
      setReplacement('');
    } else {
      setError('Could not reset the password. Passwords must be 12–72 bytes.');
    }
    setBusy('');
  };

  const deleteUser = async () => {
    if (!deleting || !canSendCredentials('/api/users')) {
      setError('HTTPS is required to delete users.');
      return;
    }
    setBusy(deleting.id);
    setError('');
    const result = await api.delete(`/api/users/${encodeURIComponent(deleting.id)}`);
    if (result.ok) {
      const removedId = deleting.id;
      setUsers((rows) => rows.filter((u) => u.id !== removedId));
      setDeleting(null);
      setEditing((prev) => (prev?.id === removedId ? null : prev));
    } else {
      setError('Could not delete user.');
    }
    setBusy('');
  };

  const visibleUsers = useMemo(() => {
    const query = search.trim().toLowerCase();
    return users
      .filter((user) => {
        if (roleFilter !== 'all' && user.role !== roleFilter) return false;
        if (!query) return true;
        return `${user.name || ''} ${user.email} ${user.provider || ''}`.toLowerCase().includes(query);
      })
      .sort((a, b) => {
        const cmp = a.email.localeCompare(b.email, undefined, { sensitivity: 'base' });
        return emailSortAsc ? cmp : -cmp;
      });
  }, [users, roleFilter, search, emailSortAsc]);

  return (
    <section className="space-y-4">
      <div className="rounded-lg border border-border bg-surface px-5 py-3.5 flex flex-wrap items-center justify-between gap-4 shadow-xs">
        <div className="flex items-start gap-3 min-w-0 flex-1">
          <span className="mt-0.5 w-8 h-8 rounded-md bg-[var(--accent-dim)] text-accent border border-accent/20 flex items-center justify-center shrink-0">
            <UserCheck size={15} aria-hidden="true" />
          </span>
          <div>
            <h3 className="text-[14px] font-semibold text-text-pri">Users and roles</h3>
            <p className="text-[12px] text-text-mut mt-0.5">
              Use the 3-dots menu on any user row and select Edit to modify settings, reset credentials, disable/enable access, or delete the account.
            </p>
          </div>
        </div>
        <Button
          type="button"
          size="sm"
          variant="primary"
          icon={<Plus size={14} />}
          onClick={() => setAdding(true)}
          disabled={adding || loading || !loaded}
        >
          Add local user
        </Button>
      </div>

      {adding && (
        <form
          className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs"
          onSubmit={(e) => {
            e.preventDefault();
            void createUser();
          }}
        >
          <div className="px-5 py-3.5 border-b border-border bg-elev/40 space-y-1">
            <h4 className="text-[14px] font-semibold text-text-pri">Create local user</h4>
            <p className="text-[12px] text-text-mut">PostgreSQL and HTTPS are required. Passwords must be 12–72 bytes.</p>
            {localLogin === 'admin' && !canOptIn && (
              <p className="text-[12px] text-warn">
                The deployment restricts local sign-in to administrators. Other local users cannot sign in until the login policy changes.
              </p>
            )}
            {localLogin === 'off' && (
              <p className="text-[12px] text-warn">
                Local sign-in is disabled. Local users cannot sign in until the login policy changes.
              </p>
            )}
            {canOptIn && (
              <p className="text-[12px] text-text-mut">
                Local administrators can sign in without this opt-in. This choice is for non-admin accounts.
              </p>
            )}
            {localLogin === 'all' && (
              <p className="text-[12px] text-text-mut">
                This deployment allows local password sign-in for all local accounts.
              </p>
            )}
          </div>
          <div className="px-5 py-4 space-y-3.5">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
              <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                <span>Email</span>
                <input
                  className="block w-full h-9 px-3 bg-bg border border-border rounded-md text-[13px] text-text-pri focus:outline-none focus:border-accent focus:ring-2 focus:ring-[var(--accent-dim)]"
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                />
              </label>
              <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                <span>Name</span>
                <input
                  className="block w-full h-9 px-3 bg-bg border border-border rounded-md text-[13px] text-text-pri focus:outline-none focus:border-accent focus:ring-2 focus:ring-[var(--accent-dim)]"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </label>
              <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                <span>Password</span>
                <input
                  className="block w-full h-9 px-3 bg-bg border border-border rounded-md text-[13px] text-text-pri focus:outline-none focus:border-accent focus:ring-2 focus:ring-[var(--accent-dim)]"
                  type="password"
                  autoComplete="new-password"
                  required
                  minLength={12}
                  maxLength={72}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                />
              </label>
              <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                <span>Initial role</span>
                <select
                  className="block w-full h-9 px-2.5 bg-bg border border-border rounded-md text-[13px] text-text-pri focus:outline-none focus:border-accent"
                  value={role}
                  onChange={(e) => setRole(e.target.value as Role)}
                >
                  <option value="readonly">Read-only</option>
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </select>
              </label>
            </div>
            {canOptIn && (
              <label className="flex items-center gap-2 text-[13px] text-text-pri cursor-pointer">
                <input
                  type="checkbox"
                  className="accent-accent"
                  checked={localSignInEnabled}
                  onChange={(e) => setLocalSignInEnabled(e.target.checked)}
                />
                <span>Allow this account to sign in with a local password</span>
              </label>
            )}
          </div>
          <div className="px-5 py-3 bg-bg/60 border-t border-border flex justify-end gap-2">
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={!!busy}
              onClick={() => {
                setPassword('');
                setLocalSignInEnabled(false);
                setAdding(false);
              }}
            >
              Cancel
            </Button>
            <Button type="submit" size="sm" variant="primary" disabled={!!busy}>
              Create user
            </Button>
          </div>
        </form>
      )}

      {!editing && error && (
        <p role="alert" className="rounded-md border border-danger/30 bg-danger/10 px-4 py-2.5 text-[13px] text-danger">
          {error}
        </p>
      )}

      {users.length > 0 && (
        <div className="rounded-lg border border-border bg-surface shadow-xs">
          <div className="px-3.5 py-2.5 border-b border-border bg-bg/40 rounded-t-lg flex flex-wrap items-center justify-between gap-3">
            <div className="w-full sm:w-72">
              <Input
                aria-label="Search users"
                placeholder="Search by email or username…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                leftIcon={<Search size={13} aria-hidden="true" />}
                className="h-8 text-[12px]"
              />
            </div>
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1 rounded-md border border-border bg-bg p-0.5">
                {([
                  { id: 'all', label: `All (${users.length})` },
                  { id: 'admin', label: 'Admin' },
                  { id: 'user', label: 'User' },
                  { id: 'readonly', label: 'Read-only' },
                ] as const).map((pill) => {
                  const active = roleFilter === pill.id;
                  return (
                    <button
                      key={pill.id}
                      type="button"
                      onClick={() => setRoleFilter(pill.id)}
                      className={`px-2.5 py-1 rounded text-[11.5px] font-medium transition-colors ${
                        active
                          ? 'bg-[var(--accent-dim)] text-accent'
                          : 'text-text-mut hover:text-text-pri hover:bg-surface-hover'
                      }`}
                    >
                      {pill.label}
                    </button>
                  );
                })}
              </div>
              <Button
                type="button"
                size="sm"
                variant="outline"
                icon={<RefreshCw size={13} className={loading ? 'animate-spin' : ''} />}
                onClick={() => void fetchUsers()}
                disabled={loading}
                aria-label="Refresh users list"
                className="h-8 text-[12px]"
              >
                Refresh
              </Button>
            </div>
          </div>

          <div className="overflow-visible">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-border bg-elev/60 text-[11px] font-medium text-text-mut select-none">
                  <th className="w-10 px-2 py-2" aria-label="Row actions" />
                  <th className="px-3 py-2 whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => setEmailSortAsc((prev) => !prev)}
                      className="inline-flex items-center gap-1 font-medium hover:text-text-pri"
                    >
                      <span>Email</span>
                      <span className="text-[10px]">{emailSortAsc ? '▲' : '▼'}</span>
                    </button>
                  </th>
                  <th className="px-3 py-2 whitespace-nowrap">Status</th>
                  <th className="px-3 py-2 whitespace-nowrap">User Type</th>
                  <th className="px-3 py-2 whitespace-nowrap">Roles</th>
                  <th className="px-3 py-2 whitespace-nowrap">Groups</th>
                  <th className="px-3 py-2 whitespace-nowrap">Username</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/60">
                {visibleUsers.map((user) => {
                  const isProtected = user.id === currentUser || user.email.toLowerCase() === 'admin@local';
                  const username = user.name || user.email.split('@')[0];
                  const userType = user.provider === 'local' ? 'local' : user.provider || '-';
                  const menuOpen = menuUserId === user.id;
                  return (
                    <tr
                      key={user.id}
                      className="h-9 text-[12px] hover:bg-surface-hover/50 transition-colors whitespace-nowrap"
                    >
                      <td className="px-2 py-1 whitespace-nowrap relative">
                        <button
                          type="button"
                          aria-label={`Actions for ${user.email}`}
                          aria-haspopup="menu"
                          aria-expanded={menuOpen}
                          onClick={(e) => {
                            e.stopPropagation();
                            setMenuUserId((prev) => (prev === user.id ? null : user.id));
                          }}
                          disabled={!!busy}
                          className="inline-flex items-center justify-center w-6 h-6 rounded text-text-dim hover:text-text-pri hover:bg-elev cursor-pointer"
                        >
                          <MoreVertical size={14} aria-hidden="true" />
                        </button>
                        {menuOpen && (
                          <div
                            role="menu"
                            aria-label={`Actions menu for ${user.email}`}
                            onClick={(e) => e.stopPropagation()}
                            className="absolute left-2 top-full mt-1 z-30 min-w-[120px] rounded-md border border-border bg-surface shadow-[var(--shadow-elev)] py-1"
                          >
                            <button
                              type="button"
                              role="menuitem"
                              aria-label={`Edit ${user.email}`}
                              onClick={() => {
                                setMenuUserId(null);
                                openUserEdit(user);
                              }}
                              className="w-full px-3 py-1.5 text-left text-[12px] font-medium text-text-pri hover:bg-surface-hover flex items-center gap-2 cursor-pointer"
                            >
                              <Pencil size={12} aria-hidden="true" className="text-text-dim" />
                              <span>Edit</span>
                            </button>
                          </div>
                        )}
                      </td>
                      <td className="px-3 py-1 font-mono text-[12px] text-text-pri whitespace-nowrap">
                        {user.email}
                      </td>
                      <td className="px-3 py-1 whitespace-nowrap">
                        {user.disabled ? (
                          <span className="inline-flex items-center px-2 py-0.5 rounded border border-danger/40 bg-danger/10 text-danger text-[11px] font-medium leading-none">
                            Disabled
                          </span>
                        ) : (
                          <span className="inline-flex items-center px-2 py-0.5 rounded border border-success/40 bg-success/10 text-success text-[11px] font-medium leading-none">
                            Active
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-1 text-text-mut whitespace-nowrap">{userType}</td>
                      <td className="px-3 py-1 whitespace-nowrap">
                        <select
                          aria-label={`Role for ${user.email}`}
                          className="h-6 bg-transparent hover:bg-bg border border-transparent hover:border-border rounded px-1.5 text-[12px] text-text-pri focus:outline-none focus:border-accent disabled:opacity-60"
                          value={user.role}
                          disabled={isProtected || !!busy}
                          onChange={(e) => void changeRole(user, e.target.value as Role)}
                        >
                          <option value="admin">admin</option>
                          <option value="user">user</option>
                          <option value="readonly">readonly</option>
                        </select>
                      </td>
                      <td className="px-3 py-1">
                        <div className="flex flex-wrap gap-1 max-w-[260px]">
                          {(user.groups ?? []).length > 0 ? (
                            user.groups!.map((g) => (
                              <Badge key={`${g.id}-${g.source}`} variant={g.source === 'sso_sync' ? 'accent' : 'default'}>
                                {g.name}
                                {g.source === 'sso_sync' ? ' · SSO' : ''}
                              </Badge>
                            ))
                          ) : (
                            <span className="text-[11px] text-text-dim">—</span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-1 text-text-pri whitespace-nowrap">{username}</td>
                    </tr>
                  );
                })}
                {visibleUsers.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-6 text-center text-[13px] text-text-mut">
                      No matching users.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <DialogPageContext.Provider value={false}>
        <Dialog
          open={Boolean(editing)}
          onOpenChange={(nextOpen) => {
            if (!nextOpen) closeUserEdit();
          }}
          title={editing ? `Edit user · ${editing.email}` : 'Edit user'}
          description={
            editing
              ? `Username: ${editing.name || editing.email.split('@')[0]} · User type: ${editing.provider || 'local'}`
              : undefined
          }
          size="lg"
        >
          {editing && (() => {
            const isLocal = !editing.provider || editing.provider === 'local';
            const isProtected = editing.id === currentUser || editing.email.toLowerCase() === 'admin@local';
            return (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center gap-2">
                  {editing.disabled ? (
                    <span className="inline-flex items-center px-2 py-0.5 rounded border border-danger/40 bg-danger/10 text-danger text-[11px] font-medium leading-none">
                      Disabled
                    </span>
                  ) : (
                    <span className="inline-flex items-center px-2 py-0.5 rounded border border-success/40 bg-success/10 text-success text-[11px] font-medium leading-none">
                      Active
                    </span>
                  )}
                  {isProtected && (
                    <Badge variant="default" size="sm">
                      Protected account
                    </Badge>
                  )}
                </div>

                {error && (
                  <p role="alert" className="rounded-md border border-danger/30 bg-danger/10 px-4 py-2.5 text-[13px] text-danger">
                    {error}
                  </p>
                )}

                {/* Profile & Role Settings */}
                <form
                  className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs"
                  onSubmit={(e) => {
                    e.preventDefault();
                    void saveEdit();
                  }}
                >
                  <div className="px-4 py-2.5 border-b border-border bg-elev/40">
                    <h4 className="text-[13px] font-semibold text-text-pri">User profile &amp; permissions</h4>
                  </div>
                  <div className="px-4 py-3.5 grid grid-cols-1 md:grid-cols-3 gap-3.5">
                    <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                      <span>Edit email</span>
                      <input
                        aria-label="Edit email"
                        type="email"
                        required
                        disabled={!isLocal || isProtected}
                        value={editEmail}
                        onChange={(e) => setEditEmail(e.target.value)}
                        className="block w-full h-9 px-3 bg-bg border border-border rounded-md text-[13px] text-text-pri focus:outline-none focus:border-accent disabled:opacity-60"
                      />
                    </label>
                    <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                      <span>Edit name</span>
                      <input
                        aria-label="Edit name"
                        disabled={!isLocal || isProtected}
                        value={editName}
                        onChange={(e) => setEditName(e.target.value)}
                        className="block w-full h-9 px-3 bg-bg border border-border rounded-md text-[13px] text-text-pri focus:outline-none focus:border-accent disabled:opacity-60"
                      />
                    </label>
                    <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                      <span>Role</span>
                      <select
                        aria-label="User role"
                        value={editing.role}
                        disabled={isProtected || !!busy}
                        onChange={(e) => void changeRole(editing, e.target.value as Role)}
                        className="block w-full h-9 px-2.5 bg-bg border border-border rounded-md text-[13px] text-text-pri focus:outline-none focus:border-accent disabled:opacity-60"
                      >
                        <option value="admin">Admin</option>
                        <option value="user">User</option>
                        <option value="readonly">Read-only</option>
                      </select>
                    </label>
                  </div>
                  {isLocal && !isProtected && (
                    <div className="px-4 py-2.5 bg-bg/60 border-t border-border flex justify-end gap-2">
                      <Button type="button" size="sm" variant="outline" onClick={closeUserEdit} disabled={!!busy}>
                        Cancel
                      </Button>
                      <Button type="submit" size="sm" variant="primary" disabled={!!busy}>
                        Save user
                      </Button>
                    </div>
                  )}
                </form>

                {/* Group Memberships */}
                {availableGroups.length > 0 && (
                  <div className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs">
                    <div className="px-4 py-2.5 border-b border-border bg-elev/40 flex items-center justify-between gap-2">
                      <h4 className="text-[12px] font-semibold uppercase tracking-wider text-text-mut">
                        Group memberships
                      </h4>
                      <span className="text-[11px] text-text-dim">
                        IdP-synced memberships update automatically at SSO sign-in
                      </span>
                    </div>
                    <div className="p-4 space-y-3">
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                        {availableGroups.map((g) => {
                          const ssoSynced = (editing.groups ?? []).some(
                            (ug) => ug.id === g.id && ug.source === 'sso_sync'
                          );
                          const checked = editGroupIds.includes(g.id);
                          return (
                            <label
                              key={g.id}
                              className="flex items-center justify-between gap-2 rounded-md border border-border bg-bg px-3 py-2 text-[12px] cursor-pointer hover:bg-surface-hover"
                            >
                              <span className="flex items-center gap-2 min-w-0">
                                <input
                                  type="checkbox"
                                  disabled={isProtected || !!busy}
                                  checked={checked}
                                  onChange={() =>
                                    setEditGroupIds((prev) =>
                                      prev.includes(g.id)
                                        ? prev.filter((id) => id !== g.id)
                                        : [...prev, g.id]
                                    )
                                  }
                                  className="rounded border-border accent-[var(--accent)]"
                                />
                                <span className="text-text-pri truncate">{g.name}</span>
                              </span>
                              {ssoSynced && <Badge variant="accent">SSO</Badge>}
                            </label>
                          );
                        })}
                      </div>
                      {!isProtected && (
                        <div className="flex justify-end">
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            disabled={!!busy}
                            onClick={() => void saveUserGroups(editing)}
                          >
                            Save groups
                          </Button>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Password Reset */}
                {isLocal && !isProtected && (
                  <div className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs">
                    <div className="px-4 py-3 flex flex-wrap items-center justify-between gap-3">
                      <div className="flex items-start gap-2.5">
                        <KeyRound size={15} className="text-accent mt-0.5 shrink-0" />
                        <div>
                          <h4 className="text-[13px] font-semibold text-text-pri">Password management</h4>
                          <p className="text-[12px] text-text-mut">
                            Set a new temporary password for {editing.email}. Active sessions will be signed out.
                          </p>
                        </div>
                      </div>
                      {resetting?.id !== editing.id && (
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          aria-label={`Reset password for ${editing.email}`}
                          disabled={!!busy}
                          onClick={() => {
                            setResetting(editing);
                            setReplacement('');
                          }}
                        >
                          Reset password
                        </Button>
                      )}
                    </div>

                    {resetting?.id === editing.id && (
                      <form
                        className="px-4 py-3.5 border-t border-border bg-elev/30 space-y-3"
                        onSubmit={(e) => {
                          e.preventDefault();
                          void resetPassword();
                        }}
                      >
                        <label className="block space-y-1.5 text-[12px] font-medium text-text-mut max-w-md">
                          <span>Replacement password</span>
                          <input
                            aria-label="Replacement password"
                            type="password"
                            autoComplete="new-password"
                            required
                            minLength={12}
                            maxLength={72}
                            value={replacement}
                            onChange={(e) => setReplacement(e.target.value)}
                            className="block w-full h-9 px-3 bg-bg border border-border rounded-md text-[13px] text-text-pri focus:outline-none focus:border-accent"
                          />
                        </label>
                        <div className="flex justify-end gap-2">
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            disabled={!!busy}
                            onClick={() => {
                              setResetting(null);
                              setReplacement('');
                            }}
                          >
                            Cancel
                          </Button>
                          <Button type="submit" size="sm" variant="primary" disabled={!!busy}>
                            Reset password
                          </Button>
                        </div>
                      </form>
                    )}
                  </div>
                )}

                {/* Account Status (Enable / Disable) & Danger Zone (Delete) */}
                {!isProtected && (
                  <div className="rounded-lg border border-border bg-surface divide-y divide-border overflow-hidden shadow-xs">
                    <div className="px-4 py-3 flex flex-wrap items-center justify-between gap-3">
                      <div className="flex items-start gap-2.5">
                        <ShieldAlert size={15} className={editing.disabled ? 'text-success mt-0.5 shrink-0' : 'text-warn mt-0.5 shrink-0'} />
                        <div>
                          <h4 className="text-[13px] font-semibold text-text-pri">
                            {editing.disabled ? 'Enable account access' : 'Disable account access'}
                          </h4>
                          <p className="text-[12px] text-text-mut">
                            {editing.disabled
                              ? 'Re-enable sign-in for this user while keeping their profile and audit history intact.'
                              : 'Suspend sign-in for this account immediately without deleting recordings or audit trails.'}
                          </p>
                        </div>
                      </div>
                      <Button
                        type="button"
                        size="sm"
                        variant="outline"
                        disabled={!!busy}
                        onClick={() => void toggleUserDisabled(editing)}
                      >
                        {editing.disabled ? 'Enable user' : 'Disable user'}
                      </Button>
                    </div>

                    <div className="px-4 py-3 flex flex-wrap items-center justify-between gap-3">
                      <div className="flex items-start gap-2.5">
                        <Trash2 size={15} className="text-danger mt-0.5 shrink-0" />
                        <div>
                          <h4 className="text-[13px] font-semibold text-text-pri">Delete user</h4>
                          <p className="text-[12px] text-text-mut">
                            Permanently revoke access for {editing.email}. Audit history and recordings are retained.
                          </p>
                        </div>
                      </div>
                      <Button
                        type="button"
                        size="sm"
                        variant="danger-ghost"
                        aria-label={`Delete ${editing.email}`}
                        disabled={!!busy}
                        onClick={() => setDeleting(editing)}
                      >
                        Delete
                      </Button>
                    </div>

                    {deleting?.id === editing.id && (
                      <div className="px-4 py-3 bg-danger/5 flex flex-wrap items-center justify-between gap-3" role="alert">
                        <p className="text-[13px] text-text-pri">
                          Delete {deleting.email}? The account will be removed from active management; audit history remains.
                        </p>
                        <div className="flex items-center gap-2">
                          <Button size="sm" variant="outline" onClick={() => setDeleting(null)} disabled={!!busy}>
                            Cancel
                          </Button>
                          <Button size="sm" variant="danger" onClick={() => void deleteUser()} disabled={!!busy}>
                            Confirm delete
                          </Button>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })()}
        </Dialog>
      </DialogPageContext.Provider>
    </section>
  );
}
