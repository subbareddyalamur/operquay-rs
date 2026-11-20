import { create } from 'zustand';
import { canSendCredentials } from '@/lib/credentialTransport';

export type Role = 'admin' | 'user' | 'readonly';
export type GrantScopeType = 'global' | 'env' | 'aws_account' | 'k8s_cluster';
export type GrantEffect = 'allow' | 'deny';

export interface PolicyConditions {
  require_recording?: boolean;
  allowed_cidrs?: string[];
  utc_hours_start?: number;
  utc_hours_end?: number;
}

export interface UserGroupSummary {
  id: string;
  name: string;
  source: 'manual' | 'sso_sync' | 'scim';
}

export interface Grant {
  group_id?: string;
  group_name?: string;
  role_id: string;
  role_name?: string;
  base_role?: Role;
  permissions: string[];
  scope_type: GrantScopeType;
  scope_id?: string;
  effect?: GrantEffect;
  conditions?: PolicyConditions;
}

export interface Me {
  user_id: string;
  email: string;
  name?: string;
  username?: string;
  role: Role;
  tenant_id: string;
  method: 'password' | 'break_glass' | 'sso';
  expires_at: number;
  mfa_enabled?: boolean;
  must_change_password?: boolean;
  compliance_mode?: boolean;
  groups?: UserGroupSummary[];
  permissions?: string[];
  grants?: Grant[];
}

function grantMatchesScope(g: Grant, scope?: { type?: GrantScopeType; id?: string }): boolean {
  if (!scope || g.scope_type === 'global') return true;
  if (!scope.type || scope.type === 'global') return false;
  if (g.scope_type !== scope.type) return false;
  return Boolean(scope.id && g.scope_id && g.scope_id.toLowerCase() === scope.id.toLowerCase());
}

const USER_BASE_PERMISSIONS = new Set([
  'instances:read',
  'instances:scan',
  'instances:clone',
  'session:ssh',
  'session:rdp',
  'session:forward',
  'session:transfer',
  'topology:deep',
  'ai:use',
  'k8s:read',
  'k8s:exec',
  'k8s:logs',
  'k8s:secrets',
  'k8s:mutate',
  'k8s:scale',
  'k8s:restart',
  'k8s:port_forward',
]);

const READONLY_BASE_PERMISSIONS = new Set(['instances:read', 'k8s:read']);

export function hasPermission(
  me: Me | null | undefined,
  perm: string,
  scope?: { type?: GrantScopeType; id?: string }
): boolean {
  if (!me) return false;
  const grants = me.grants;
  if (grants && grants.length > 0) {
    let allowed = false;
    for (const g of grants) {
      const hasPerm = g.permissions.includes('*') || g.permissions.includes(perm);
      if (!hasPerm || !grantMatchesScope(g, scope)) continue;
      if (g.effect === 'deny') return false;
      allowed = true;
    }
    return allowed;
  }
  if (me.role === 'admin') return true;
  if (me.permissions) {
    return me.permissions.includes('*') || me.permissions.includes(perm);
  }
  if (me.role === 'user') return USER_BASE_PERMISSIONS.has(perm);
  if (me.role === 'readonly') return READONLY_BASE_PERMISSIONS.has(perm);
  return false;
}

export interface SSOProvider {
  id: string;
  label: string;
  type: 'saml' | 'oidc';
  domains?: string[];
}

export interface AuthConfig {
  required: boolean;
  local: 'all' | 'admin' | 'off';
  local_user_opt_in_allowed?: boolean;
  sso: { enabled: boolean; providers: SSOProvider[] };
  session_hours: number;
  idle_minutes: number;
  aws_access_mode: 'hub' | 'profiles' | 'user';
  compliance_mode?: boolean;
  version: string;
  revision: string;
}

export interface MfaChallenge {
  challengeToken: string;
  methods: string[];
  email: string;
}

interface AuthState {
  ready: boolean;
  config: AuthConfig | null;
  me: Me | null;
  /** True when the server rejected a request because the session ended. */
  expired: boolean;
  signInOpen: boolean;
  mfaChallenge: MfaChallenge | null;
  load: () => Promise<void>;
  signIn: (email: string, password: string) => Promise<string | null>;
  completeMfaLogin: (code: string, isRecovery?: boolean) => Promise<string | null>;
  clearMfaChallenge: () => void;
  signOut: () => Promise<void>;
  setSignInOpen: (open: boolean) => void;
  markExpired: () => void;
  can: (perm: string, scope?: { type?: GrantScopeType; id?: string }) => boolean;
}

export const useAuthStore = create<AuthState>()((set, get) => ({
  ready: false,
  config: null,
  me: null,
  expired: false,
  signInOpen: false,
  mfaChallenge: null,

  load: async () => {
    const [cfgRes, meRes] = await Promise.all([
      fetch('/api/auth/config').catch(() => null),
      fetch('/api/auth/me').catch(() => null),
    ]);
    const config = cfgRes?.ok ? ((await cfgRes.json()) as AuthConfig) : null;
    const me = meRes?.ok ? ((await meRes.json()) as Me) : null;
    set({ config, me, ready: true, expired: false });
  },

  signIn: async (email, password) => {
    if (!canSendCredentials('/api/auth/login')) return 'HTTPS is required for password sign-in.';
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    if (!res.ok) {
      const body = (await res.json().catch(() => null)) as { error?: string; retry_after?: number } | null;
      if (res.status === 429 && body?.retry_after) {
        return body.error ?? `Too many failed sign-in attempts. Try again in ${body.retry_after}s.`;
      }
      return body?.error ?? 'That email and password were not accepted.';
    }
    const data = (await res.json().catch(() => null)) as {
      mfa_required?: boolean;
      challenge_token?: string;
      methods?: string[];
    } | null;
    if (data?.mfa_required && data.challenge_token) {
      set({
        mfaChallenge: {
          challengeToken: data.challenge_token,
          methods: data.methods ?? ['totp'],
          email,
        },
      });
      return null;
    }
    set({ mfaChallenge: null });
    await get().load();
    set({ signInOpen: false });
    return null;
  },

  completeMfaLogin: async (code, isRecovery = false) => {
    const challenge = get().mfaChallenge;
    if (!challenge) return 'MFA verification session expired. Please sign in again.';
    const payload = isRecovery
      ? { challenge_token: challenge.challengeToken, recovery_code: code.trim() }
      : { challenge_token: challenge.challengeToken, totp_code: code.trim() };
    const res = await fetch('/api/auth/login/mfa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const body = (await res.json().catch(() => null)) as { error?: string } | null;
      return body?.error ?? 'Invalid MFA verification code.';
    }
    set({ mfaChallenge: null });
    await get().load();
    set({ signInOpen: false });
    return null;
  },

  clearMfaChallenge: () => set({ mfaChallenge: null }),

  signOut: async () => {
    // A full-page navigation lets the server continue to the IdP's own
    // logout (SAML SLO / OIDC end_session) after ending the local session.
    window.location.assign('/api/auth/logout');
  },

  setSignInOpen: (open) => set({ signInOpen: open }),

  markExpired: () => {
    if (get().config?.required) set({ me: null, expired: true, mfaChallenge: null });
  },

  can: (perm, scope) => hasPermission(get().me, perm, scope),
}));

let installed = false;

/** Any 401 from the server means the session ended; show the sign-in page. */
export function installSessionWatch() {
  if (installed) return;
  installed = true;
  const original = window.fetch.bind(window);
  window.fetch = async (input, init) => {
    const res = await original(input, init);
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (res.status === 401 && !url.includes('/api/auth/')) {
      useAuthStore.getState().markExpired();
    }
    return res;
  };
}
