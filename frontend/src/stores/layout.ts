import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import { useAIStore } from './ai';

/** Top-level places. `session` is the Instances workspace; Settings returns to whichever was open. */
export type DeskView = 'session' | 'kubernetes' | 'databases' | 'settings';
export type SettingsTab = 'appearance' | 'general' | 'remote-desktop' | 'audit' | 'recordings' | 'governance' | 'compliance' | 'ai-mcp' | 'agents' | 'access-graph' | 'device-trust' | 'snippets' | 'accounts' | 'kube-clusters' | 'signin' | 'users' | 'groups' | 'recording' | 'ai' | 'vault';
export type DetailsScope = { roleID: string; region: string; name: string; userID: string; tenantID: string };

function clampPane(px: number, min: number, max: number): number {
  const room = typeof window === 'undefined' ? max : Math.max(min, window.innerWidth - 280);
  return Math.max(min, Math.min(max, room, Math.round(px)));
}

interface LayoutState {
  sidebarWidth: number;
  assistantWidth: number;
  detailsWidth: number;
  sidebarCollapsed: boolean;
  settingsTab: SettingsTab;
  view: DeskView;
  /** Where "Back to workspace" goes from Settings. */
  returnView: Exclude<DeskView, 'settings'>;
  /** Slot in the session tab row where the active session renders its actions. */
  sessionActionsEl: HTMLElement | null;
  /** Instance shown in the reading column. The AI assistant shares that column. */
  detailsInstanceId: string | null;
  detailsScope: DetailsScope | null;
  setSidebarWidth: (px: number) => void;
  setAssistantWidth: (px: number) => void;
  setDetailsWidth: (px: number) => void;
  toggleSidebar: () => void;
  openSettings: (tab: SettingsTab) => void;
  closeSettings: () => void;
  setView: (view: DeskView) => void;
  setSessionActionsEl: (el: HTMLElement | null) => void;
  showDetails: (instanceId: string, scope?: DetailsScope) => void;
  toggleDetails: (instanceId: string) => void;
  closeDetails: () => void;
}

export const useLayoutStore = create<LayoutState>()(
  persist(
    (set, get) => ({
      sidebarWidth: 300,
      assistantWidth: 360,
      detailsWidth: 640,
      sidebarCollapsed: false,
      settingsTab: 'appearance',
      view: 'session',
      returnView: 'session',
      sessionActionsEl: null,
      detailsInstanceId: null,
      detailsScope: null,
      setSidebarWidth: (px: number) =>
        set({ sidebarWidth: Math.max(220, Math.min(440, px)) }),
      setAssistantWidth: (px: number) => set({ assistantWidth: clampPane(px, 320, 960) }),
      setDetailsWidth: (px: number) => set({ detailsWidth: clampPane(px, 420, 1200) }),
      toggleSidebar: () =>
        set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      openSettings: (settingsTab) => set((s) => ({ view: 'settings', settingsTab, returnView: s.view === 'settings' ? s.returnView : s.view })),
      closeSettings: () => set((s) => ({ view: s.returnView })),
      setView: (view) => set({ view }),
      setSessionActionsEl: (sessionActionsEl) => set({ sessionActionsEl }),
      showDetails: (instanceId, scope) => {
        useAIStore.getState().setOpen(false);
        set({ detailsInstanceId: instanceId, detailsScope: scope ?? null });
      },
      toggleDetails: (instanceId) => {
        const next = get().detailsInstanceId === instanceId ? null : instanceId;
        if (next) useAIStore.getState().setOpen(false);
        set({ detailsInstanceId: next, detailsScope: null });
      },
      closeDetails: () => set({ detailsInstanceId: null, detailsScope: null }),
    }),
    {
      name: 'ct-layout',
      storage: createJSONStorage(() => localStorage),
      partialize: (s) => ({ sidebarWidth: s.sidebarWidth, assistantWidth: s.assistantWidth, detailsWidth: s.detailsWidth, sidebarCollapsed: s.sidebarCollapsed }),
    },
  ),
);
