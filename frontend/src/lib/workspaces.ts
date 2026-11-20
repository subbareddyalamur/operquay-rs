import type { DeskView } from '@/stores/layout';

export type WorkspaceModuleId = Exclude<DeskView, 'settings'>;

export interface WorkspaceModuleConfig {
  id: WorkspaceModuleId;
  label: string;
  hasSidebar: boolean;
  hasTabBar: boolean;
  keepAlive: boolean;
}

export const WORKSPACE_MODULES: readonly WorkspaceModuleConfig[] = [
  {
    id: 'session',
    label: 'VMs',
    hasSidebar: true,
    hasTabBar: true,
    keepAlive: true,
  },
  {
    id: 'kubernetes',
    label: 'Kubernetes',
    hasSidebar: true,
    hasTabBar: false,
    keepAlive: true,
  },
  {
    id: 'databases',
    label: 'Databases',
    hasSidebar: true,
    hasTabBar: false,
    keepAlive: true,
  },
];

export function getWorkspaceModule(view: DeskView): WorkspaceModuleConfig | null {
  return WORKSPACE_MODULES.find((m) => m.id === view) ?? null;
}

