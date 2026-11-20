import { useState, useEffect } from 'react';
import { useAIStore } from '@/stores/ai';
import { useLayoutStore } from '@/stores/layout';
import { useSessionsStore } from '@/stores/sessions';
import { Menu } from '@/components/primitives/Menu';
import { Dialog } from '@/components/primitives/Dialog';
import { hasPermission, useAuthStore } from '@/stores/auth';
import { CloudConnections } from '@/components/sidebar/CloudConnections';
import { OperquayMark } from '@/components/brand/OperquayMark';
import { Button, Input, Kbd, Tooltip } from '@/components/primitives';
import { useThemeStore } from '@/stores/theme';
import { THEMES } from '@/lib/themes';
import { Sparkles, Search, X, ChevronRight } from 'lucide-react';
import { usePaletteStore } from '@/stores/palette';
import { assistantName, useSettingsStore } from '@/stores/settings';
import type { SettingsTab } from '@/stores/layout';
import { getWorkspaceModule } from '@/lib/workspaces';

interface License {
  plan?: string;
  status?: string;
  days_remaining?: number;
  notice?: string;
}

function useLicense(): License | null {
  const [license, setLicense] = useState<License | null>(null);
  useEffect(() => {
    let stop = false;
    const load = () => {
      void fetch('/api/license')
        .then((r) => (r.ok ? (r.json() as Promise<License>) : null))
        .then((data) => {
          if (!stop) setLicense(data && data.plan && data.plan !== 'unconfigured' ? data : null);
        })
        .catch(() => undefined);
    };
    load();
    const id = window.setInterval(load, 60_000);
    return () => {
      stop = true;
      window.clearInterval(id);
    };
  }, []);
  return license;
}

function LicenseDialog({ license, isAdmin, onClose }: { license: License; isAdmin: boolean; onClose: () => void }) {
  const [code, setCode] = useState('');
  const [result, setResult] = useState<string | null>(null);
  const redeem = async () => {
    setResult(null);
    const res = await fetch('/api/license/redeem', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: code.trim() }),
    });
    const text = await res.text();
    setResult(res.ok ? 'Coupon applied. The new terms arrive with the next heartbeat.' : text.trim() || 'The coupon was not accepted.');
  };
  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose(); }} title={`${license.plan ? license.plan[0].toUpperCase() + license.plan.slice(1) : 'License'} plan`} size="sm" footer={<Button variant="outline" size="sm" onClick={onClose}>Close</Button>}>
      <div className="space-y-3 text-[14px]">
        <p className="text-text-mut">
          {license.status === 'active' ? 'Active' : license.status}
          {typeof license.days_remaining === 'number' ? ` · ${license.days_remaining} days left` : ''}
        </p>
        {license.notice && <p className="text-[13px] text-text-mut leading-relaxed">{license.notice}</p>}
        {isAdmin && (
          <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); void redeem(); }}>
            <div className="flex-1"><Input className="font-mono" placeholder="Coupon code" value={code} onChange={(e) => setCode(e.target.value)} aria-label="Coupon code" /></div>
            <Button type="submit" variant="outline" disabled={!code.trim()}>Redeem</Button>
          </form>
        )}
        {result && <p role="status" className="text-[13px] text-text-mut">{result}</p>}
      </div>
    </Dialog>
  );
}

const METHOD_LABEL: Record<string, string> = {
  sso: 'Single sign-on',
  password: 'Password',
  break_glass: 'Break-glass password',
};

const quiet = 'h-8 px-2.5 rounded-[var(--radius)] text-[13px] text-text-mut hover:text-text-pri hover:bg-[var(--surface-hover)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] transition-colors';

const openSettings = (tab: SettingsTab) => useLayoutStore.getState().openSettings(tab);

const SETTINGS_LABELS: Partial<Record<SettingsTab, string>> = {
  appearance: 'Appearance',
  general: 'General',
  'remote-desktop': 'Remote Desktop',
  audit: 'Audit log',
  recordings: 'Recordings',
  users: 'Users',
  groups: 'Groups & Roles',
  signin: 'Single Sign On',
  accounts: 'AWS Accounts',
  'kube-clusters': 'Kube clusters',
  recording: 'Recording policy',
  ai: 'Assistant',
  vault: 'Vault',
};

function WorkspaceBreadcrumb() {
  const view = useLayoutStore((s) => s.view);
  const settingsTab = useLayoutStore((s) => s.settingsTab);
  const closeSettings = useLayoutStore((s) => s.closeSettings);
  const activeSessionId = useSessionsStore((s) => s.activeId);
  const sessions = useSessionsStore((s) => s.sessions);
  const activeSession = sessions.find((s) => s.id === activeSessionId);
  const mod = getWorkspaceModule(view);

  return (
    <div className="flex items-center gap-1.5 min-w-0 text-[12.5px]">
      <span className="text-border-strong select-none">/</span>
      {view === 'settings' ? (
        <div className="inline-flex items-center gap-1.5 min-w-0">
          <span className="text-text-mut">{settingsTab === 'audit' || settingsTab === 'recordings' ? 'Operations' : 'Settings'}</span>
          <ChevronRight size={12} aria-hidden="true" className="text-text-dim shrink-0" />
          <span className="font-medium text-text-pri truncate">{SETTINGS_LABELS[settingsTab] ?? settingsTab}</span>
          <Tooltip label="Return to workspace" side="bottom">
            <button
              type="button"
              onClick={closeSettings}
              aria-label="Close settings"
              title="Return to workspace"
              className="ml-1 w-5 h-5 rounded flex items-center justify-center text-text-dim hover:text-text-pri hover:bg-elev focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
            >
              <X size={12} aria-hidden="true" />
            </button>
          </Tooltip>
        </div>
      ) : (
        <div className="inline-flex items-center gap-1.5 min-w-0">
          <span className="text-text-mut">Resources</span>
          <ChevronRight size={12} aria-hidden="true" className="text-text-dim shrink-0" />
          <span className="font-medium text-text-pri truncate">{mod?.label ?? 'Instances'}</span>
          {view === 'session' && activeSession && (
            <>
              <ChevronRight size={12} aria-hidden="true" className="text-text-dim shrink-0 hidden sm:inline" />
              <span className="hidden sm:inline font-mono text-[12px] text-accent truncate max-w-[200px]">
                {activeSession.instanceName}
              </span>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function ThemeSwitch() {
  const theme = useThemeStore((s) => s.theme);
  const setTheme = useThemeStore((s) => s.setTheme);
  return (
    <div className="flex items-center gap-3 px-2.5 h-9 text-[13px] text-text-pri">
      <span id="theme-switch-label">Theme</span>
      <div role="radiogroup" aria-labelledby="theme-switch-label" className="ml-auto flex rounded-md border border-border overflow-hidden">
        {THEMES.map((t) => (
          <button key={t.slug} type="button" role="menuitemradio" aria-checked={theme === t.slug} onClick={() => setTheme(t.slug)}
            className={`px-2.5 h-6 text-[12px] focus:outline-none focus-visible:bg-elev ${theme === t.slug ? 'bg-[var(--accent-dim)] text-accent font-medium' : 'text-text-mut hover:text-text-pri'}`}>
            {t.label}
          </button>
        ))}
      </div>
    </div>
  );
}

export function TopBar() {
  const aiOpen = useAIStore((s) => s.open);
  const setAIOpen = useAIStore((s) => s.setOpen);
  const name = assistantName(useSettingsStore((s) => s.assistantName));
  const license = useLicense();
  const userId = useAuthStore((s) => s.me?.user_id);

  const [licenseOpen, setLicenseOpen] = useState(false);
  const [awsOpen, setAWSOpen] = useState(false);
  const me = useAuthStore((s) => s.me);
  const signOut = useAuthStore((s) => s.signOut);
  const setSignInOpen = useAuthStore((s) => s.setSignInOpen);
  const isAdmin = hasPermission(me, '*');
  const canAudit = hasPermission(me, 'audit:read');
  const canRecordings = hasPermission(me, 'recordings:read');
  const canUseAI = hasPermission(me, 'ai:use');

  useEffect(() => {
    const openAWS = () => setAWSOpen(true);
    window.addEventListener('ct:open-aws-accounts', openAWS);
    return () => window.removeEventListener('ct:open-aws-accounts', openAWS);
  }, []);

  useEffect(() => {
    const onOpen = (ev: Event) => openSettings((ev as CustomEvent<{ tab?: SettingsTab }>).detail?.tab ?? 'appearance');
    window.addEventListener('ct:open-settings', onOpen);
    return () => window.removeEventListener('ct:open-settings', onOpen);
  }, []);

  const initials = me ? (me.name || me.email).slice(0, 2).toUpperCase() : null;
  const identity = me && (
    <div className="flex items-center gap-3 px-2.5 py-2.5">
      <span className="w-9 h-9 rounded-full inline-flex items-center justify-center bg-[var(--accent-dim)] text-[12px] font-semibold text-accent shrink-0">{initials}</span>
      <div className="min-w-0">
        {me.name && <div className="text-[13px] font-semibold text-text-pri truncate">{me.name}</div>}
        <div className={`truncate ${me.name ? 'text-[12px] text-text-mut' : 'text-[13px] font-semibold text-text-pri'}`}>{me.email.toLowerCase()}</div>
        <div className="mt-1 flex items-center gap-2">
          <span className="px-2 rounded-full bg-[var(--accent-dim)] text-accent text-[11px] font-semibold capitalize">{me.role}</span>
          <span className="text-[12px] text-text-dim truncate">{METHOD_LABEL[me.method] ?? me.method}</span>
        </div>
      </div>
    </div>
  );

  return (
    <>
      <header className="h-12 flex items-center gap-2 px-3 bg-surface border-b border-border shrink-0">
        <a href="/" className="flex items-center gap-2 shrink-0 no-underline text-text-pri mr-1 rounded-[var(--radius-sm)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]" aria-label="Operquay home">
          <OperquayMark size={20} />
          <span className="text-[15px] font-semibold tracking-[-0.01em]">Operquay</span>
        </a>
        <WorkspaceBreadcrumb />

        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={() => usePaletteStore.getState().setOpen(true)}
            aria-label="Open command palette"
            title="Search instances & commands (⌘K)"
            className="hidden sm:inline-flex items-center justify-between gap-4 min-w-[196px] md:min-w-[236px] h-8 px-2.5 rounded-[var(--radius)] bg-bg/90 border border-border text-[12px] text-text-mut hover:text-text-pri hover:border-[var(--border-strong)] hover:bg-elev focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] transition-colors"
          >
            <span className="inline-flex items-center gap-2">
              <Search size={12} aria-hidden="true" className="text-text-dim" />
              <span>Search or jump to…</span>
            </span>
            <Kbd>⌘K</Kbd>
          </button>

        {license && (
          <button type="button" onClick={() => setLicenseOpen(true)} className={`${quiet} capitalize`}>
            {license.plan}
            {typeof license.days_remaining === 'number' ? ` · ${license.days_remaining}d` : ''}
          </button>
        )}
        {canUseAI && (
          <Tooltip label={`Toggle ${name} assistant`} side="bottom">
            <button
              type="button"
              onClick={() => setAIOpen(!aiOpen)}
              aria-pressed={aiOpen}
              title={`Ask ${name}`}
              className={`h-8 px-2.5 rounded-[var(--radius)] inline-flex items-center gap-1.5 text-[13px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] transition-colors ${aiOpen ? 'bg-[var(--accent-dim)] text-accent font-medium border border-[var(--accent)]/25' : 'text-text-mut hover:text-text-pri hover:bg-[var(--surface-hover)] border border-transparent'}`}
            >
              <Sparkles size={14} aria-hidden="true" />{name}
            </button>
          </Tooltip>
        )}

        <Menu
          label="Account and preferences"
          trigger={
            initials ? (
              <span className="w-8 h-8 rounded-full inline-flex items-center justify-center bg-[var(--accent-dim)] text-[11px] font-semibold text-accent">{initials}</span>
            ) : (
              <span className="text-[13px] text-text-mut hover:text-text-pri px-1">Sign in</span>
            )
          }
          triggerClassName="h-8 flex items-center rounded-full"
          header={identity}
          sections={me ? [
            { items: [{ label: 'Settings', hint: '⌘,', onSelect: () => openSettings('appearance') }] },
            ...((canAudit || canRecordings) ? [
              { heading: 'Operations', items: [
                ...(canAudit ? [{ label: 'Audit log', onSelect: () => openSettings('audit') }] : []),
                ...(canRecordings ? [{ label: 'Session recordings', hint: '⌘⇧R', onSelect: () => openSettings('recordings') }] : []),
              ] },
            ] : []),
          ] : [
            { items: [{ label: 'Sign in', onSelect: () => setSignInOpen(true) }] },
          ]}
          footer={me && <>
            <ThemeSwitch />
            <div className="border-t border-border mt-1 pt-1">
              <button type="button" role="menuitem" onClick={() => void signOut()} className="w-full flex items-center px-2.5 h-8 rounded-md text-left text-[13px] text-danger hover:bg-elev focus:bg-elev focus:outline-none">Sign out</button>
            </div>
          </>}
        />
        </div>
      </header>

      {licenseOpen && license && <LicenseDialog license={license} isAdmin={isAdmin} onClose={() => setLicenseOpen(false)} />}
      {awsOpen && <Dialog open onOpenChange={setAWSOpen} title="Cloud connections" size="xl"><CloudConnections key={userId} /></Dialog>}
    </>
  );
}
