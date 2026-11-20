import { create } from 'zustand';
import {
  apiJson,
  type AuthConfigResponse,
  type CurrentUserMe,
  type Ec2Instance,
  type FleetStats,
} from './api';

export type WorkspaceTab =
  | 'cloud'
  | 'terminal'
  | 'desktop'
  | 'kubernetes'
  | 'databases'
  | 'topology'
  | 'settings'
  | 'audit'
  | 'admin';

export interface ActivityItem {
  id: string;
  title: string;
  detail: string;
  status: 'running' | 'done' | 'error';
  ts: string;
}

interface PlatformStoreState {
  workspace: WorkspaceTab;
  setWorkspace: (w: WorkspaceTab) => void;
  authConfig: AuthConfigResponse | null;
  me: CurrentUserMe | null;
  authLoaded: boolean;
  loadAuthState: () => Promise<void>;
  signOut: () => Promise<void>;
  instances: Ec2Instance[];
  fleetStats: FleetStats;
  favorites: string[];
  selectedInstanceId: string;
  setSelectedInstanceId: (id: string) => void;
  toggleFavorite: (id: string) => Promise<void>;
  loadFleet: () => Promise<void>;
  activities: ActivityItem[];
  pushActivity: (item: Omit<ActivityItem, 'id' | 'ts'>) => void;
}

const DEFAULT_FLEET_STATS: FleetStats = {
  total: 0,
  running: 0,
  stopped: 0,
  ssm_online: 0,
  windows: 0,
  linux: 0,
  regions: 0,
  vpcs: 0,
};

export const usePlatformStore = create<PlatformStoreState>((set, get) => ({
  workspace: 'settings',
  setWorkspace: (workspace) => set({ workspace }),
  authConfig: null,
  me: null,
  authLoaded: false,
  loadAuthState: async () => {
    try {
      const cfg = await apiJson<AuthConfigResponse>('/api/auth/config');
      let me: CurrentUserMe | null = null;
      try {
        me = await apiJson<CurrentUserMe>('/api/auth/me');
      } catch {
        me = null;
      }
      set({ authConfig: cfg, me, authLoaded: true });
    } catch {
      set({ authLoaded: true });
    }
  },
  signOut: async () => {
    await apiJson('/api/auth/logout', { method: 'POST' });
    await get().loadAuthState();
  },
  instances: [],
  fleetStats: DEFAULT_FLEET_STATS,
  favorites: [],
  selectedInstanceId: '',
  setSelectedInstanceId: (selectedInstanceId) => set({ selectedInstanceId }),
  toggleFavorite: async (id) => {
    const prev = get().favorites;
    const next = prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id];
    set({ favorites: next });
    try {
      await apiJson('/preferences', {
        method: 'POST',
        body: JSON.stringify({ favorite_instances: next }),
      });
    } catch {
      // ignore offline preference failure in unit context
    }
  },
  loadFleet: async () => {
    try {
      const [instances, stats, prefs] = await Promise.all([
        apiJson<Ec2Instance[]>('/instances'),
        apiJson<FleetStats>('/fleet-stats'),
        apiJson<{ favorite_instances?: string[] }>('/preferences').catch(() => ({ favorite_instances: [] })),
      ]);
      set({
        instances,
        fleetStats: stats,
        favorites: prefs.favorite_instances ?? [],
        selectedInstanceId: get().selectedInstanceId || instances[0]?.instance_id || '',
      });
    } catch {
      // non-fatal during cold unauthenticated state
    }
  },
  activities: [],
  pushActivity: (item) =>
    set((s) => ({
      activities: [
        {
          id: `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
          ts: new Date().toLocaleTimeString(),
          ...item,
        },
        ...s.activities.slice(0, 29),
      ],
    })),
}));

