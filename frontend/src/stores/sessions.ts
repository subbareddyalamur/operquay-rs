import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import { nanoid } from 'nanoid';
import { useLayoutStore } from './layout';

const showSessionView = () => {
  useLayoutStore.getState().setView('session');
};

export type SessionType = 'ssh' | 'rdp' | 'topology';
export type SessionStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

export interface Session {
  id: string;
  type: SessionType;
  instanceId: string;
  instanceName: string;
  env?: string;
  status: SessionStatus;
  createdAt: number;
  userRDP?: { roleID: string; region: string };
  userSSH?: { roleID: string; region: string };
  userTopology?: { roleID: string; region: string };
}

interface SessionsState {
  sessions: Session[];
  activeId: string | null;
  openSession: (s: Omit<Session, 'createdAt'>) => void;
  closeSession: (id: string) => void;
  closeOthers: (keepId: string) => void;
  closeRight: (fromId: string) => void;
  duplicate: (id: string) => void;
  reorder: (fromId: string, toId: string) => void;
  setActive: (id: string | null) => void;
  updateStatus: (id: string, status: SessionStatus) => void;
}

export const useSessionsStore = create<SessionsState>()(
  persist(
    (set, get) => ({
      sessions: [],
      activeId: null,
      openSession: (s) => {
        showSessionView();
        set((state) => {
          if (state.sessions.some((x) => x.id === s.id)) return { activeId: s.id };
          return {
            sessions: [...state.sessions, { ...s, createdAt: Date.now() }],
            activeId: s.id,
          };
        });
      },
      closeSession: (id) =>
        set((state) => {
          const sessions = state.sessions.filter((x) => x.id !== id);
          const activeId =
            state.activeId === id
              ? (sessions[sessions.length - 1]?.id ?? null)
              : state.activeId;
          return { sessions, activeId };
        }),
      closeOthers: (keepId) =>
        set((state) => ({
          sessions: state.sessions.filter((x) => x.id === keepId),
          activeId: keepId,
        })),
      closeRight: (fromId) =>
        set((state) => {
          const i = state.sessions.findIndex((x) => x.id === fromId);
          return { sessions: state.sessions.slice(0, i + 1) };
        }),
      duplicate: (id) => {
        const src = get().sessions.find((x) => x.id === id);
        if (!src) return;
        get().openSession({ ...src, id: `${src.instanceId}-${nanoid(6)}` });
      },
      reorder: (fromId, toId) =>
        set((state) => {
          const from = state.sessions.findIndex((x) => x.id === fromId);
          const to = state.sessions.findIndex((x) => x.id === toId);
          if (from === -1 || to === -1) return state;
          const next = [...state.sessions];
          const [moved] = next.splice(from, 1);
          if (moved) next.splice(to, 0, moved);
          return { sessions: next };
        }),
      setActive: (id) => {
        if (id) showSessionView();
        set({ activeId: id });
      },
      updateStatus: (id, status) =>
        set((state) => ({
          sessions: state.sessions.map((s) => (s.id === id ? { ...s, status } : s)),
        })),
    }),
    {
      name: 'ct-sessions', storage: createJSONStorage(() => sessionStorage),
      partialize: (state) => ({
        sessions: state.sessions.filter(session => !session.userRDP && !session.userSSH && !session.userTopology),
        activeId: state.sessions.some(session => session.id === state.activeId && (session.userRDP || session.userSSH || session.userTopology)) ? null : state.activeId,
      }),
      merge: (persisted, current) => {
        const state = { ...current, ...persisted as Partial<SessionsState> };
        const sessions = state.sessions.filter(session => !['fleet-map', 'diagram', 'cost'].includes(session.type) && !session.userRDP && !session.userSSH && !session.userTopology);
        const activeRemoved = state.sessions.some(session => session.id === state.activeId && !sessions.includes(session));
        return { ...state, sessions, activeId: activeRemoved ? (sessions[sessions.length - 1]?.id ?? null) : state.activeId };
      },
    },
  ),
);

const USER_SSH_TABS = 'ct-user-ssh-tabs';
const USER_RDP_TABS = 'ct-user-rdp-tabs';

function tabStorage(): Storage | null {
  try {
    return typeof localStorage === 'undefined' ? null : localStorage;
  } catch {
    return null;
  }
}

function readUserTabs(key: string, kind: 'ssh' | 'rdp'): { sessions: Session[]; activeId: string | null } {
  try {
    const raw = tabStorage()?.getItem(key);
    if (!raw) return { sessions: [], activeId: null };
    const parsed = JSON.parse(raw) as { sessions?: Session[]; activeId?: string | null };
    const region = /^[a-z]{2}(-[a-z0-9]+){1,4}-[0-9]+$/;
    const instance = /^i-[0-9a-f]{8,17}$/;
    const id = /^[A-Za-z0-9_-]{1,128}$/;
    const role = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    const sessions = (parsed.sessions ?? []).filter(session => {
      const scope = kind === 'ssh' ? session?.userSSH : session?.userRDP;
      const env = session?.env;
      return session?.type === kind && scope && id.test(session.id) && instance.test(session.instanceId) && region.test(scope.region) && role.test(scope.roleID) && session.instanceName.length > 0 && session.instanceName.length <= 256 && (env === undefined || (typeof env === 'string' && env.length <= 64 && !['\r', '\n', '\0'].some(char => env.includes(char))));
    }).slice(0, 20).map(session => ({
      id: session.id,
      type: session.type,
      instanceId: session.instanceId,
      instanceName: session.instanceName,
      ...(session.env ? { env: session.env } : {}),
      status: kind === 'rdp' ? 'disconnected' as const : 'connecting' as const,
      createdAt: session.createdAt,
      ...(kind === 'ssh' ? { userSSH: session.userSSH } : { userRDP: session.userRDP }),
    }));
    const activeId = sessions.some(session => session.id === parsed.activeId) ? parsed.activeId ?? null : null;
    return { sessions, activeId };
  } catch {
    return { sessions: [], activeId: null };
  }
}

function writeUserTabs(key: string, kind: 'ssh' | 'rdp', sessions: Session[], activeId: string | null) {
  const storage = tabStorage();
  if (!storage) return;
  const kept = sessions.filter(session => session.type === kind && (kind === 'ssh' ? session.userSSH : session.userRDP)).slice(0, 20);
  if (kept.length === 0) {
    storage.removeItem(key);
    return;
  }
  const active = kept.some(session => session.id === activeId) ? activeId : null;
  storage.setItem(key, JSON.stringify({ sessions: kept, activeId: active }));
}

let userSSHHydrated = false;
let userSSHHydrating = false;
function restoreUserSSHTabs() {
  const ssh = readUserTabs(USER_SSH_TABS, 'ssh');
  const rdp = readUserTabs(USER_RDP_TABS, 'rdp');
  userSSHHydrated = true;
  if (ssh.sessions.length === 0 && rdp.sessions.length === 0) {
    const state = useSessionsStore.getState();
    writeUserTabs(USER_SSH_TABS, 'ssh', state.sessions, state.activeId);
    writeUserTabs(USER_RDP_TABS, 'rdp', state.sessions, state.activeId);
    return;
  }
  useSessionsStore.setState(state => {
    const have = new Set(state.sessions.map(session => session.id));
    const extra = [...ssh.sessions, ...rdp.sessions].filter(session => !have.has(session.id));
    if (extra.length === 0) return state;
    const focused = [ssh.activeId, rdp.activeId].find(id => id && (extra.some(session => session.id === id) || state.sessions.some(session => session.id === id))) ?? extra.at(-1)?.id ?? null;
    return { sessions: [...state.sessions, ...extra], activeId: state.activeId ?? focused };
  });
}
if (useSessionsStore.persist.hasHydrated()) restoreUserSSHTabs();
useSessionsStore.persist.onHydrate(() => {
  userSSHHydrating = true;
});
useSessionsStore.persist.onFinishHydration(() => {
  restoreUserSSHTabs();
  userSSHHydrating = false;
});
useSessionsStore.subscribe(state => {
  if (!userSSHHydrated || userSSHHydrating) return;
  writeUserTabs(USER_SSH_TABS, 'ssh', state.sessions, state.activeId);
  writeUserTabs(USER_RDP_TABS, 'rdp', state.sessions, state.activeId);
});
