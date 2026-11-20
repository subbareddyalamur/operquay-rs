import { create } from 'zustand';
import { persist, createJSONStorage, devtools } from 'zustand/middleware';
import { apiGet, apiPost } from '@/lib/api';
import type { EC2Instance, AccountNode, InstanceTree } from '@/lib/types';
import { expandAccountsWithMatches } from '@/lib/filter';
import { useAuthStore } from '@/stores/auth';

const userMode = () => useAuthStore.getState().config?.aws_access_mode === 'user';

/** Groups a user-role scan into the same account → region → tag tree that GET /instances returns. */
export function userInventoryTree(instances: EC2Instance[]): AccountNode[] {
  const accounts = new Map<string, AccountNode>();
  const sorted = [...instances].sort((a, b) => (a.name || a.instance_id).localeCompare(b.name || b.instance_id));
  for (const inst of sorted) {
    let account = accounts.get(inst.account_id);
    if (!account) {
      account = { provider: 'aws', account_id: inst.account_id, account_alias: inst.account_alias || inst.account_id, profile: '', regions: [] };
      accounts.set(inst.account_id, account);
    }
    let region = account.regions.find((r) => r.region === inst.aws_region);
    if (!region) {
      region = { region: inst.aws_region, groups: [] };
      account.regions.push(region);
    }
    let group = region.groups.find((g) => g.tag1 === (inst.tag1_value ?? '') && g.tag2 === (inst.tag2_value ?? ''));
    if (!group) {
      group = { tag1: inst.tag1_value ?? '', tag2: inst.tag2_value ?? '', instances: [] };
      region.groups.push(group);
    }
    group.instances.push(inst);
  }
  for (const account of accounts.values()) account.regions.sort((a, b) => a.region.localeCompare(b.region));
  return [...accounts.values()];
}

export type { EC2Instance as Instance, AccountNode as Account };

/** A role connected in user mode. `name` labels its account in the tree; `label` adds the role. */
export interface UserRole {
  id: string;
  name: string;
  label: string;
  accountID?: string | undefined;
  roleName?: string | undefined;
  /** Identity Center start URL this account was connected through; absent for IAM roles. */
  startURL?: string | undefined;
  roleKey?: string | undefined;
  credentialRevision?: string | undefined;
  /** False when the account is saved from the last scan and AWS has not been signed in again. */
  live?: boolean | undefined;
  error?: string | undefined;
  failedRegions?: string[] | undefined;
}

const ROLE_FETCHES_IN_FLIGHT = 3;
let inventoryEpoch = 0;
const roleEpochs = new Map<string, number>();
const bumpRole = (id: string) => roleEpochs.set(id, (roleEpochs.get(id) ?? 0) + 1);
type ConnectedRole = { id: string; account_id: string; label: string; credential_revision: string; role_name?: string; role_arn?: string; start_url?: string };
export type { InstanceState } from '@/lib/types';

interface InstancesState {
  accounts: AccountNode[];
  loading: boolean;
  discovering: boolean;
  lastDiscoveryAt: number | null;
  filter: string;
  expanded: Record<string, boolean>;
  favorites: string[];
  selectedId: string | null;
  /** User mode only: every connected role, its last successful discovery, and which roles are fetching now. */
  userRoles: UserRole[];
  userInventory: Record<string, EC2Instance[]>;
  userFetching: string[];
  instanceRoles: Record<string, string>;

  addUserRole: (role: Omit<UserRole, 'error' | 'failedRegions'>) => Promise<void>;
  restoreSavedInventory: () => Promise<void>;
  refreshUserRoles: () => Promise<void>;
  removeUserRole: (id: string) => void;
  clearUserRoles: () => void;
  fetchUserRole: (id: string) => Promise<void>;
  setFilter: (q: string) => void;
  toggleExpand: (key: string) => void;
  collapseAll: () => void;
  expandAll: () => void;
  toggleFavorite: (id: string) => void;
  setSelected: (id: string | null) => void;
  fetchInstances: () => Promise<void>;
  triggerDiscovery: () => Promise<void>;
  /** Reloads the tree whenever server-side discovery finishes, including startup discovery. */
  watchDiscovery: () => () => void;
}

export const useInstancesStore = create<InstancesState>()(
  devtools(
    persist(
      (set, get) => ({
        accounts: [],
        loading: false,
        discovering: false,
        lastDiscoveryAt: null,
        filter: '',
        expanded: {},
        favorites: [],
        selectedId: null,
        userRoles: [],
        userInventory: {},
        userFetching: [],
        instanceRoles: {},

        addUserRole: async (role) => {
          if (!role.credentialRevision) return;
          const next = { ...role, live: true };
          const replaced = get().userRoles.filter((r) => r.id === next.id || (next.accountID && r.accountID === next.accountID));
          for (const r of replaced) bumpRole(r.id);
          bumpRole(next.id);
          inventoryEpoch++;
          set((s) => {
            const inventory = { ...s.userInventory };
            for (const r of replaced) delete inventory[r.id];
            const fetching = s.userFetching.filter(id => !replaced.some(r => r.id === id));
            return { userRoles: [...s.userRoles.filter((r) => !replaced.includes(r)), next], userInventory: inventory, userFetching: fetching, discovering: fetching.length > 0 };
          });
          rebuildUserTree();
          await get().fetchUserRole(next.id);
        },

        restoreSavedInventory: async () => {
          if (!userMode() || get().userRoles.length > 0) return;
          const epoch = inventoryEpoch;
          const [saved, connected] = await Promise.all([
            apiGet<{ roles: Array<{ account_id: string; role_key: string; source: string; name: string; label: string; instances: EC2Instance[] | null; live_id?: string; credential_revision: string }> | null }>('/api/aws/saved-inventory'),
            apiGet<ConnectedRole[]>('/api/aws/connected-roles'),
          ]);
          if (inventoryEpoch !== epoch || get().userRoles.length > 0 || !saved.ok || !connected.ok) return;
          const rows = saved.ok ? saved.value.roles ?? [] : [];
          const live = connected.ok && Array.isArray(connected.value) ? connected.value : [];
          const inventory: Record<string, EC2Instance[]> = {};
          const userRoles: UserRole[] = [];
          for (const role of live) {
            if (!role.credential_revision) continue;
            const row = rows.find(item => item.live_id === role.id && item.credential_revision === role.credential_revision && item.account_id === role.account_id && (item.role_key === role.role_name || item.role_key === role.role_arn));
            if (row) inventory[role.id] = row.instances ?? [];
            bumpRole(role.id);
            userRoles.push({ id: role.id, name: row?.name || role.account_id, label: row?.label || role.label || role.role_name || role.role_arn || role.account_id, accountID: role.account_id, roleKey: row?.role_key || role.role_name || role.role_arn, credentialRevision: role.credential_revision, live: true, ...(role.role_name ? { roleName: role.role_name } : {}), ...(role.start_url ? { startURL: role.start_url } : {}) });
          }
          if (!userRoles.length) return;
          set({ userRoles, userInventory: inventory, lastDiscoveryAt: rows.length ? Date.now() : null });
          rebuildUserTree();
          const fresh = userRoles.filter((role) => !(role.id in inventory)).map((role) => role.id);
          await Promise.all(Array.from({ length: ROLE_FETCHES_IN_FLIGHT }, async () => {
            for (let id = fresh.shift(); id; id = fresh.shift()) await get().fetchUserRole(id);
          }));
        },

        refreshUserRoles: async () => {
          const observed = get().userRoles.filter(role => role.live !== false).map(role => ({ id: role.id, revision: role.credentialRevision, epoch: roleEpochs.get(role.id) }));
          if (!observed.length) return;
          let timeout: ReturnType<typeof setTimeout> | undefined;
          const result = await Promise.race([
            apiGet<ConnectedRole[]>('/api/aws/connected-roles?background=1'),
            new Promise<null>(resolve => { timeout = setTimeout(() => resolve(null), 3000); }),
          ]);
          clearTimeout(timeout);
          const active = new Map(result?.ok && Array.isArray(result.value) ? result.value.map(role => [role.id, role.credential_revision]) : []);
          const lost = observed.filter(role => roleEpochs.get(role.id) === role.epoch && (!role.revision || active.get(role.id) !== role.revision)).map(role => role.id);
          if (!lost.length) return;
          for (const id of lost) bumpRole(id);
          inventoryEpoch++;
          set(s => {
            const inventory = { ...s.userInventory };
            for (const id of lost) delete inventory[id];
            const fetching = s.userFetching.filter(id => !lost.includes(id));
            return { userRoles: s.userRoles.map(role => lost.includes(role.id) ? { ...role, live: false, error: 'AWS sign-in expired or unavailable. Reconnect to see instances.' } : role), userInventory: inventory, userFetching: fetching, discovering: fetching.length > 0, selectedId: s.selectedId && lost.includes(s.instanceRoles[s.selectedId] ?? '') ? null : s.selectedId };
          });
          rebuildUserTree();
        },

        removeUserRole: (id) => {
          bumpRole(id);
          inventoryEpoch++;
          set((s) => {
            const inventory = { ...s.userInventory };
            delete inventory[id];
            const fetching = s.userFetching.filter((x) => x !== id);
            return { userRoles: s.userRoles.filter((r) => r.id !== id), userInventory: inventory, userFetching: fetching, discovering: fetching.length > 0, selectedId: s.selectedId && s.instanceRoles[s.selectedId] === id ? null : s.selectedId };
          });
          rebuildUserTree();
        },

        clearUserRoles: () => {
          inventoryEpoch++;
          for (const role of get().userRoles) bumpRole(role.id);
          set({ userRoles: [], userInventory: {}, userFetching: [], instanceRoles: {}, accounts: [], discovering: false, selectedId: null, lastDiscoveryAt: null });
        },

        fetchUserRole: async (id) => {
          const role = get().userRoles.find((r) => r.id === id && r.live !== false);
          if (!role || get().userFetching.includes(id)) return;
          const epoch = roleEpochs.get(id);
          set((s) => ({ userFetching: [...s.userFetching, id], discovering: true }));
          const res = await apiPost<{ instances: EC2Instance[] | null; failed_regions: string[] | null; credential_revision: string }>('/api/aws/role-fetch', { binding_id: id, display_name: role.name });
          if (roleEpochs.get(id) !== epoch) return;
          set((s) => {
            const fetchingNow = s.userFetching.filter((x) => x !== id);
            return { userFetching: fetchingNow, discovering: fetchingNow.length > 0 };
          });
          if (!get().userRoles.some((r) => r.id === id)) return;
          if (res.ok && role.credentialRevision && res.value.credential_revision === role.credentialRevision) {
            set((s) => ({
              userInventory: { ...s.userInventory, [id]: res.value.instances ?? [] },
              userRoles: s.userRoles.map((r) => (r.id === id ? { ...r, error: undefined, failedRegions: res.value.failed_regions ?? [] } : r)),
              lastDiscoveryAt: Date.now(),
            }));
          } else if (res.ok || res.error.status === 401 || res.error.status === 403) {
            bumpRole(id);
            inventoryEpoch++;
            set((s) => {
              const inventory = { ...s.userInventory };
              delete inventory[id];
              return { userInventory: inventory, userRoles: s.userRoles.map((r) => (r.id === id ? { ...r, live: false, error: 'Instance discovery failed or the AWS session expired. Reconnect to see instances.' } : r)), selectedId: s.selectedId && s.instanceRoles[s.selectedId] === id ? null : s.selectedId };
            });
          } else {
            set((s) => ({ userRoles: s.userRoles.map(r => r.id === id ? { ...r, error: 'Instance discovery failed. Try again.' } : r) }));
          }
          rebuildUserTree();
        },

        setFilter: (q) => {
          set({ filter: q });
          if (q.trim()) {
            const newExpanded = expandAccountsWithMatches(get().accounts, q);
            set((s) => ({ expanded: { ...s.expanded, ...newExpanded } }));
          }
        },

        toggleExpand: (key) =>
          set((s) => ({ expanded: { ...s.expanded, [key]: !s.expanded[key] } })),

        collapseAll: () => set({ expanded: {} }),

        expandAll: () => {
          const all: Record<string, boolean> = {};
          for (const a of get().accounts) {
            all[`account:${a.account_id}`] = true;
            for (const r of a.regions) {
              all[`region:${a.account_id}:${r.region}`] = true;
              for (const g of r.groups) {
                const label = [g.tag1, g.tag2].filter(Boolean).join(' / ');
                if (label) {
                  all[`tag:${a.account_id}:${r.region}:${label}`] = true;
                }
              }
            }
          }
          set({ expanded: all });
        },

        toggleFavorite: (id) =>
          set((s) => ({
            favorites: s.favorites.includes(id)
              ? s.favorites.filter((x) => x !== id)
              : [...s.favorites, id],
          })),

        setSelected: (id) => set({ selectedId: id }),

        fetchInstances: async () => {
          if (userMode()) {
            if (get().userRoles.length === 0) await get().restoreSavedInventory();
            return;
          }
          set({ loading: true });
          const res = await apiGet<InstanceTree>('/instances');
          if (res.ok) {
            set({
              accounts: res.value.accounts ?? [],
              lastDiscoveryAt: Date.now(),
              loading: false,
            });
          } else {
            set({ loading: false });
          }
        },

        triggerDiscovery: async () => {
          if (userMode()) {
            const queue = get().userRoles.filter((r) => r.live !== false).map((r) => r.id);
            const worker = async () => {
              for (let id = queue.shift(); id; id = queue.shift()) await get().fetchUserRole(id);
            };
            await Promise.all(Array.from({ length: ROLE_FETCHES_IN_FLIGHT }, worker));
            return;
          }
          if (get().discovering) return;
          set({ discovering: true });
          await apiGet('/discover-instances?force=true');
          const poll = async () => {
            const statusRes = await apiGet<{ status: string }>('/discovery-status');
            if (statusRes.ok && statusRes.value.status === 'discovering') {
              setTimeout(() => void poll(), 1500);
            } else {
              await get().fetchInstances();
              set({ discovering: false });
            }
          };
          setTimeout(() => void poll(), 1500);
        },

        watchDiscovery: () => {
          if (userMode()) {
            let stopped = false;
            let timer: ReturnType<typeof setTimeout> | undefined;
            const tick = async () => {
              await get().refreshUserRoles();
              if (!stopped) timer = setTimeout(() => void tick(), 2000);
            };
            void tick();
            return () => { stopped = true; if (timer) clearTimeout(timer); };
          }
          let stopped = false;
          let wasDiscovering = false;
          let timer: ReturnType<typeof setTimeout> | undefined;
          const tick = async () => {
            if (stopped) return;
            const res = await apiGet<{ status: string }>('/discovery-status');
            const discoveringNow = res.ok && res.value.status === 'discovering';
            if (discoveringNow !== get().discovering) set({ discovering: discoveringNow });
            if (wasDiscovering && !discoveringNow) await get().fetchInstances();
            wasDiscovering = discoveringNow;
            if (!stopped) timer = setTimeout(() => void tick(), discoveringNow ? 2000 : 30000);
          };
          void tick();
          return () => {
            stopped = true;
            if (timer) clearTimeout(timer);
          };
        },
      }),
      {
        name: 'ct-instances',
        storage: createJSONStorage(() => localStorage),
        partialize: (s) => ({ favorites: s.favorites, expanded: s.expanded }),
        merge: (stored, current) => {
          const saved = stored as Partial<InstancesState> | undefined;
          return { ...current, favorites: saved?.favorites ?? current.favorites, expanded: saved?.expanded ?? current.expanded };
        },
      },
    ),
    { name: 'instances' },
  ),
);

useAuthStore.subscribe((next, previous) => {
  if (next.config?.aws_access_mode !== 'user' && previous.config?.aws_access_mode !== 'user') return;
  if (next.me?.user_id !== previous.me?.user_id || next.me?.tenant_id !== previous.me?.tenant_id) {
    useInstancesStore.getState().clearUserRoles();
  }
});

/** Rebuilds the tree from every connected role; a later role wins if two roles see the same instance. */
function rebuildUserTree() {
  const { userRoles, userInventory } = useInstancesStore.getState();
  const owners: Record<string, string> = {};
  const byID = new Map<string, EC2Instance>();
  for (const role of userRoles) {
    for (const inst of role.live === false ? [] : userInventory[role.id] ?? []) {
      byID.set(inst.instance_id, { ...inst, account_alias: inst.account_alias || role.name });
      owners[inst.instance_id] = role.id;
    }
  }
  const accounts = userInventoryTree([...byID.values()]);
  const opened: Record<string, boolean> = {};
  for (const a of accounts) {
    opened[`account:${a.account_id}`] = true;
    for (const r of a.regions) opened[`region:${a.account_id}:${r.region}`] = true;
  }
  useInstancesStore.setState((s) => ({ accounts, instanceRoles: owners, expanded: { ...opened, ...s.expanded } }));
}
