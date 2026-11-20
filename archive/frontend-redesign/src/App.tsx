import { useEffect, useState } from 'react';
import {
  Activity,
  Cloud,
  Command,
  Container,
  Database,
  FileVideo,
  LogIn,
  Monitor,
  Network,
  PlusCircle,
  Settings,
  Shield,
  ShieldCheck,
  Terminal,
} from 'lucide-react';
import { Badge, Button, ThemeToggle, ToastBanner } from './design-system/primitives';
import { AdminConsoleWorkspace } from './features/admin/AdminConsoleWorkspace';
import { AuditRecordingsView } from './features/audit/AuditRecordingsView';
import { SignInView } from './features/auth/SignInView';
import { CloudFleetWorkspace } from './features/cloud/CloudFleetWorkspace';
import { DatabaseExplorerWorkspace } from './features/databases/DatabaseExplorerWorkspace';
import { DesktopStage } from './features/desktop/DesktopStage';
import { KubernetesWorkspace } from './features/kubernetes/KubernetesWorkspace';
import { usePlatformStore, type WorkspaceTab } from './features/platform/store';
import {
  SessionLauncherDialog,
  type ActiveLaunchedSession,
} from './features/sessions/SessionLauncherDialog';
import { RemoteDesktopSettingsView } from './features/settings/RemoteDesktopSettingsView';
import { useSettingsStore } from './features/settings/store';
import { ActivityDrawer } from './features/shell/ActivityDrawer';
import { CommandPalette } from './features/shell/CommandPalette';
import { TerminalWorkspace } from './features/terminal/TerminalWorkspace';
import { VpcTopologyWorkspace } from './features/topology/VpcTopologyWorkspace';

const NAV_ITEMS: Array<{ id: WorkspaceTab; label: string; icon: typeof Settings }> = [
  { id: 'cloud', label: 'Cloud Fleet', icon: Cloud },
  { id: 'terminal', label: 'Terminal', icon: Terminal },
  { id: 'desktop', label: 'Desktop Session', icon: Monitor },
  { id: 'kubernetes', label: 'Kubernetes', icon: Container },
  { id: 'databases', label: 'Databases', icon: Database },
  { id: 'topology', label: 'Topology', icon: Network },
  { id: 'settings', label: 'Settings', icon: Settings },
  { id: 'audit', label: 'Recordings & Audit', icon: FileVideo },
  { id: 'admin', label: 'Admin', icon: ShieldCheck },
];

export function App() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    const saved = localStorage.getItem('operquay-theme');
    return saved === 'light' ? 'light' : 'dark';
  });
  const [launcherOpen, setLauncherOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [activityOpen, setActivityOpen] = useState(false);
  const [signInModal, setSignInModal] = useState(false);
  const [termTarget, setTermTarget] = useState({ instanceId: 'i-demo-0001', region: 'us-east-1' });
  const [topoVpc, setTopoVpc] = useState('vpc-main');
  const [activeSession, setActiveSession] = useState<ActiveLaunchedSession>({
    protocol: 'rdp',
    targetHost: 'win2025-ssm.internal',
    launchMode: 'demo',
  });

  const { saved, toast, dismissToast, loadAll } = useSettingsStore();
  const { workspace, setWorkspace, authConfig, me, authLoaded, loadAuthState } = usePlatformStore();

  useEffect(() => {
    const root = document.documentElement;
    root.classList.add('theme-switching');
    root.setAttribute('data-theme', theme);
    localStorage.setItem('operquay-theme', theme);
    void root.getBoundingClientRect();
    root.classList.remove('theme-switching');
  }, [theme]);

  useEffect(() => {
    void loadAll();
    void loadAuthState();
  }, [loadAll, loadAuthState]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const toggleTheme = () => setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));

  const launchDesktop = (proto: 'rdp' | 'vnc') => {
    setActiveSession({
      protocol: proto,
      targetHost: 'win2025-ssm.internal',
      launchMode: 'demo',
    });
    setWorkspace('desktop');
  };

  const launchTicketedSession = (session: ActiveLaunchedSession) => {
    setActiveSession(session);
    setWorkspace('desktop');
  };

  if (authLoaded && authConfig?.required && !me) {
    return (
      <SignInView
        tenantId={authConfig.tenant_id || 'default'}
        providers={authConfig.providers ?? authConfig.sso?.providers ?? []}
        onSignedIn={loadAuthState}
      />
    );
  }

  if (signInModal) {
    return (
      <SignInView
        tenantId={authConfig?.tenant_id || 'default'}
        providers={authConfig?.providers ?? authConfig?.sso?.providers ?? []}
        onSignedIn={async () => {
          await loadAuthState();
          setSignInModal(false);
        }}
        onCancel={() => setSignInModal(false)}
      />
    );
  }

  return (
    <div className="min-h-screen flex flex-col bg-bg text-text-pri">
      {/* Unified Enterprise Operquay Shell Header (2-tier: zero overlap across all viewports) */}
      <header className="shrink-0 bg-side border-b border-border">
        <div className="h-11 px-4 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 font-semibold text-[14px] tracking-tight text-text-pri shrink-0">
            <span className="h-6 w-6 rounded-[var(--radius-sm)] bg-accent text-accent-fg inline-flex items-center justify-center font-bold text-xs">
              OQ
            </span>
            <span>Operquay</span>
            <Badge tone="neutral">Rust Single-Binary</Badge>
          </div>

          <div className="flex items-center gap-1.5 shrink-0">
            <Button
              variant="ghost"
              size="xs"
              aria-label="Open Command Palette"
              onClick={() => setPaletteOpen(true)}
              icon={<Command size={13} aria-hidden="true" />}
            >
              Cmd+K
            </Button>
            <Button
              variant="ghost"
              size="xs"
              aria-label="Open Activity Center"
              onClick={() => setActivityOpen((o) => !o)}
              icon={<Activity size={13} aria-hidden="true" />}
            >
              Activity
            </Button>
            <Button
              variant="outline"
              size="xs"
              onClick={() => setLauncherOpen(true)}
              icon={<PlusCircle size={13} aria-hidden="true" />}
            >
              Connect Live Target
            </Button>
            <Button
              variant="ghost"
              size="xs"
              onClick={() => setSignInModal(true)}
              icon={<LogIn size={13} aria-hidden="true" />}
            >
              {me ? me.email : 'Sign In'}
            </Button>
            <Badge tone="success" className="hidden lg:inline-flex">
              <Shield size={11} aria-hidden="true" />
              OQR2 · TLS
            </Badge>
            <ThemeToggle theme={theme} onToggle={toggleTheme} />
          </div>
        </div>

        <nav
          aria-label="Primary workspace"
          className="h-10 px-4 border-t border-border bg-bg flex items-center gap-1 overflow-x-auto"
        >
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = workspace === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setWorkspace(item.id)}
                aria-current={active ? 'page' : undefined}
                className={[
                  'h-7 px-2.5 rounded-[var(--radius-sm)] text-[12px] font-medium inline-flex items-center gap-1.5 transition-colors whitespace-nowrap shrink-0',
                  active
                    ? 'bg-[var(--accent-dim)] text-accent'
                    : 'text-text-mut hover:text-text-pri hover:bg-elev',
                ].join(' ')}
              >
                <Icon size={13} aria-hidden="true" />
                {item.label}
              </button>
            );
          })}
        </nav>
      </header>

      <main className="flex-1 min-h-0">
        {workspace === 'cloud' ? (
          <CloudFleetWorkspace
            onOpenTerminal={(inst) => {
              setTermTarget({ instanceId: inst.instance_id, region: inst.region || 'us-east-1' });
              setWorkspace('terminal');
            }}
            onOpenDesktop={(inst) => {
              setActiveSession({
                protocol: 'rdp',
                targetHost: inst.private_ip || inst.instance_id,
                launchMode: 'demo',
              });
              setWorkspace('desktop');
            }}
            onOpenTopology={(vpc) => {
              setTopoVpc(vpc);
              setWorkspace('topology');
            }}
          />
        ) : workspace === 'terminal' ? (
          <TerminalWorkspace instanceId={termTarget.instanceId} region={termTarget.region} />
        ) : workspace === 'kubernetes' ? (
          <KubernetesWorkspace />
        ) : workspace === 'databases' ? (
          <DatabaseExplorerWorkspace />
        ) : workspace === 'topology' ? (
          <VpcTopologyWorkspace initialVpcId={topoVpc} />
        ) : workspace === 'admin' ? (
          <AdminConsoleWorkspace />
        ) : workspace === 'desktop' ? (
          <DesktopStage
            protocol={activeSession.protocol}
            targetHost={activeSession.targetHost}
            wsUrl={activeSession.wsUrl}
            layout={saved.keyboard_layout}
            showHud={saved.show_live_telemetry_hud}
            onBackToSettings={() => setWorkspace('settings')}
          />
        ) : workspace === 'audit' ? (
          <AuditRecordingsView />
        ) : (
          <RemoteDesktopSettingsView onLaunchSession={launchDesktop} />
        )}
      </main>

      <SessionLauncherDialog
        open={launcherOpen}
        defaultLayout={saved.keyboard_layout}
        onClose={() => setLauncherOpen(false)}
        onLaunched={launchTicketedSession}
      />

      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onNavigate={setWorkspace}
        onToggleTheme={toggleTheme}
      />

      <ActivityDrawer open={activityOpen} onClose={() => setActivityOpen(false)} />

      <ToastBanner toast={toast} onDismiss={dismissToast} />
    </div>
  );
}
export default App;
