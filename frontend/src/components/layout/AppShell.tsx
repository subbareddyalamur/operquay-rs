import type { ReactNode } from 'react';
import { useRef, useCallback } from 'react';
import { ChevronRight, Home, Server, Boxes, Database, ScrollText, Video, Settings, ShieldAlert, FileCheck2 } from 'lucide-react';
import { TopBar } from './TopBar';
import { TabBar } from './TabBar';
import { StatusBar } from './StatusBar';
import { Sidebar } from '@/components/sidebar/Sidebar';
import { ToastViewport } from '@/components/primitives/ToastViewport';
import { ActivityCenter } from '@/components/activity/ActivityCenter';
import { Tooltip } from '@/components/primitives';
import { useLayoutStore } from '@/stores/layout';
import { hasPermission, useAuthStore } from '@/stores/auth';
import { useAIStore } from '@/stores/ai';
import { useSettingsStore } from '@/stores/settings';
import { useSessionsStore } from '@/stores/sessions';
import { ReadingColumn } from './ReadingColumn';
import { getWorkspaceModule } from '@/lib/workspaces';

const COLLAPSED_WIDTH = 28;
const RAIL_WIDTH = 52;

function SidebarResizer() {
  const setSidebarWidth = useLayoutStore((s) => s.setSidebarWidth);
  const isDragging = useRef(false);

  const onPointerDown = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    isDragging.current = true;
    e.currentTarget.setPointerCapture(e.pointerId);
  }, []);

  const onPointerMove = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    if (isDragging.current) setSidebarWidth(e.clientX - RAIL_WIDTH);
  }, [setSidebarWidth]);

  const onPointerUp = useCallback(() => {
    isDragging.current = false;
  }, []);

  return (
    <div
      className="absolute -right-1 top-0 bottom-0 w-2.5 cursor-col-resize hover:bg-accent/60 transition-colors z-30"
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onDoubleClick={() => setSidebarWidth(280)}
      title="Drag to resize · Double-click to reset"
      aria-label="Resize instance list"
    />
  );
}

function GlobalIconRail() {
  const view = useLayoutStore((s) => s.view);
  const settingsTab = useLayoutStore((s) => s.settingsTab);
  const setView = useLayoutStore((s) => s.setView);
  const openSettings = useLayoutStore((s) => s.openSettings);
  const activeSessionId = useSessionsStore((s) => s.activeId);
  const setActiveSession = useSessionsStore((s) => s.setActive);
  const canAudit = useAuthStore((s) => hasPermission(s.me, 'audit:read'));
  const canRecordings = useAuthStore((s) => hasPermission(s.me, 'recordings:read'));
  const canCompliance = useAuthStore((s) => hasPermission(s.me, 'compliance:manage') || hasPermission(s.me, 'audit:read'));
  const hasMe = useAuthStore((s) => Boolean(s.me));
  const enableKubernetes = useSettingsStore((s) => s.enableKubernetes ?? true);
  const enableDatabases = useSettingsStore((s) => s.enableDatabases ?? true);

  const railBtn = (active: boolean) =>
    `relative w-9 h-9 rounded-lg flex items-center justify-center transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] ${
      active
        ? 'bg-[var(--accent-dim)] text-accent border border-accent/30'
        : 'text-text-mut border border-transparent hover:text-text-pri hover:bg-[var(--surface-hover)]'
    }`;

  const activeBar = (active: boolean) =>
    active ? <span aria-hidden="true" className="absolute -left-[8px] w-[3px] h-5 rounded-r bg-accent" /> : null;

  const isHomeActive = view === 'session' && !activeSessionId;
  const isVmsActive = view === 'session' && Boolean(activeSessionId);

  return (
    <nav
      aria-label="Resources and operations"
      style={{ gridArea: 'rail' }}
      className="w-[52px] bg-surface border-r border-border flex flex-col items-center justify-between py-2.5 select-none shrink-0"
    >
      <div className="flex flex-col items-center gap-1.5">
        <Tooltip label="Command Hub & Overview" side="right">
          <button
            type="button"
            onClick={() => {
              setActiveSession(null);
              setView('session');
            }}
            aria-label="Fleet Overview"
            aria-current={isHomeActive ? 'page' : undefined}
            className={railBtn(isHomeActive)}
          >
            {activeBar(isHomeActive)}
            <Home size={16} aria-hidden="true" />
          </button>
        </Tooltip>

        <Tooltip label="Resources · VMs" side="right">
          <button
            type="button"
            onClick={() => setView('session')}
            aria-label="VMs workspace"
            aria-current={isVmsActive ? 'page' : undefined}
            className={railBtn(isVmsActive)}
          >
            {activeBar(isVmsActive)}
            <Server size={16} aria-hidden="true" />
          </button>
        </Tooltip>

        {enableKubernetes && (
          <Tooltip label="Resources · Kubernetes" side="right">
            <button
              type="button"
              onClick={() => setView('kubernetes')}
              aria-label="Kubernetes workspace"
              aria-current={view === 'kubernetes' ? 'page' : undefined}
              className={railBtn(view === 'kubernetes')}
            >
              {activeBar(view === 'kubernetes')}
              <Boxes size={16} aria-hidden="true" />
            </button>
          </Tooltip>
        )}

        {enableDatabases && (
          <Tooltip label="Resources · Databases" side="right">
            <button
              type="button"
              onClick={() => setView('databases')}
              aria-label="Databases workspace"
              aria-current={view === 'databases' ? 'page' : undefined}
              className={railBtn(view === 'databases')}
            >
              {activeBar(view === 'databases')}
              <Database size={16} aria-hidden="true" />
            </button>
          </Tooltip>
        )}

        {(canAudit || canRecordings || hasMe) && (
          <>
            <div className="w-5 h-px bg-border my-1.5" aria-hidden="true" />
            {canAudit && (
              <Tooltip label="Operations · Audit log" side="right">
                <button
                  type="button"
                  onClick={() => openSettings('audit')}
                  aria-label="Audit log"
                  aria-current={view === 'settings' && settingsTab === 'audit' ? 'page' : undefined}
                  className={railBtn(view === 'settings' && settingsTab === 'audit')}
                >
                  {activeBar(view === 'settings' && settingsTab === 'audit')}
                  <ScrollText size={16} aria-hidden="true" />
                </button>
              </Tooltip>
            )}
            {canRecordings && (
              <Tooltip label="Operations · Recordings" side="right">
                <button
                  type="button"
                  onClick={() => openSettings('recordings')}
                  aria-label="Session recordings"
                  aria-current={view === 'settings' && settingsTab === 'recordings' ? 'page' : undefined}
                  className={railBtn(view === 'settings' && settingsTab === 'recordings')}
                >
                  {activeBar(view === 'settings' && settingsTab === 'recordings')}
                  <Video size={16} aria-hidden="true" />
                </button>
              </Tooltip>
            )}
            {hasMe && (
              <Tooltip label="Governance · Access & DLP" side="right">
                <button
                  type="button"
                  onClick={() => openSettings('governance')}
                  aria-label="Access and DLP"
                  aria-current={view === 'settings' && settingsTab === 'governance' ? 'page' : undefined}
                  className={railBtn(view === 'settings' && settingsTab === 'governance')}
                >
                  {activeBar(view === 'settings' && settingsTab === 'governance')}
                  <ShieldAlert size={16} aria-hidden="true" />
                </button>
              </Tooltip>
            )}
            {canCompliance && (
              <Tooltip label="Governance · Compliance" side="right">
                <button
                  type="button"
                  onClick={() => openSettings('compliance')}
                  aria-label="Compliance portal"
                  aria-current={view === 'settings' && settingsTab === 'compliance' ? 'page' : undefined}
                  className={railBtn(view === 'settings' && settingsTab === 'compliance')}
                >
                  {activeBar(view === 'settings' && settingsTab === 'compliance')}
                  <FileCheck2 size={16} aria-hidden="true" />
                </button>
              </Tooltip>
            )}
          </>
        )}
      </div>

      <div className="flex flex-col items-center gap-1.5">
        <Tooltip label="Workspace Settings (⌘,)" side="right">
          <button
            type="button"
            onClick={() => openSettings('appearance')}
            aria-label="Workspace settings"
            aria-current={
              view === 'settings'
                && settingsTab !== 'audit'
                && settingsTab !== 'recordings'
                && settingsTab !== 'governance'
                && settingsTab !== 'compliance'
                ? 'page'
                : undefined
            }
            className={railBtn(
              view === 'settings'
                && settingsTab !== 'audit'
                && settingsTab !== 'recordings'
                && settingsTab !== 'governance'
                && settingsTab !== 'compliance',
            )}
          >
            {activeBar(
              view === 'settings'
                && settingsTab !== 'audit'
                && settingsTab !== 'recordings'
                && settingsTab !== 'governance'
                && settingsTab !== 'compliance',
            )}
            <Settings size={16} aria-hidden="true" />
          </button>
        </Tooltip>
      </div>
    </nav>
  );
}

export interface AppShellProps {
  children: ReactNode;
}

export function AppShell({ children }: AppShellProps) {
  const sidebarWidth = useLayoutStore((s) => s.sidebarWidth);
  const sidebarCollapsed = useLayoutStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useLayoutStore((s) => s.toggleSidebar);
  const view = useLayoutStore((s) => s.view);
  const aiOpen = useAIStore((s) => s.open);

  const activeModule = getWorkspaceModule(view);
  const showSidebar = activeModule?.hasSidebar ?? false;
  const showTabBar = activeModule?.hasTabBar ?? false;
  const listWidth = sidebarCollapsed ? COLLAPSED_WIDTH : sidebarWidth;

  return (
    <div
      className="app-shell h-screen overflow-hidden grid"
      style={{
        gridTemplateAreas: showSidebar
          ? '"topbar topbar topbar" "rail sidebar tabbar" "rail sidebar main" "statusbar statusbar statusbar"'
          : '"topbar topbar topbar" "rail tabbar tabbar" "rail main main" "statusbar statusbar statusbar"',
        gridTemplateColumns: showSidebar ? `${RAIL_WIDTH}px ${listWidth}px minmax(0, 1fr)` : `${RAIL_WIDTH}px 0px minmax(0, 1fr)`,
        gridTemplateRows: showTabBar ? '48px 38px 1fr 26px' : '48px 0px 1fr 26px',
        transition: 'grid-template-columns 180ms ease',
      }}
    >
      <header style={{ gridArea: 'topbar' }}>
        <TopBar />
      </header>
      <GlobalIconRail />
      <div
        style={{ gridArea: 'tabbar' }}
        className={`relative z-20 items-stretch bg-side ${showTabBar ? 'flex' : 'hidden'}`}
      >
        <TabBar />
      </div>
      <aside
        style={{ gridArea: 'sidebar', display: showSidebar ? undefined : 'none' }}
        aria-label="Instance list"
        className="shell-sidebar bg-side border-r border-border relative overflow-hidden flex flex-col min-h-0"
      >
        {sidebarCollapsed && (
          <button
            type="button"
            onClick={toggleSidebar}
            aria-label="Show instance list"
            title="Show instance list (⌘B)"
            className="m-1 h-7 rounded-md flex items-center justify-center text-text-mut hover:text-text-pri hover:bg-elev"
          >
            <ChevronRight size={14} aria-hidden="true" />
          </button>
        )}
        {/* Stays mounted while hidden: it also loads and watches the inventory. */}
        <div className="flex-1 min-h-0" hidden={sidebarCollapsed}><Sidebar /></div>
        {!sidebarCollapsed && <SidebarResizer />}
      </aside>
      <main style={{ gridArea: 'main' }} className="overflow-hidden bg-bg flex">
        <div className="flex-1 min-w-0 relative">
          {children}
        </div>
        <div className={showSidebar || aiOpen ? 'contents' : 'hidden'}><ReadingColumn /></div>
      </main>
      <footer style={{ gridArea: 'statusbar' }}>
        <StatusBar />
      </footer>
      <ToastViewport />
      <ActivityCenter />
    </div>
  );
}
