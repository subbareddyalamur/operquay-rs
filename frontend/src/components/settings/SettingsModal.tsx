import { useState, useEffect, useCallback, useRef } from 'react';
import { Palette, Type, Monitor, Cloud, Sparkles, KeyRound, Database, ArrowLeft, ScrollText, Video, Users, ShieldCheck, ShieldAlert, FileCheck2, Boxes, Bot, Network, GitBranch, Laptop, Minus, Plus, Trash2, X, Pencil, RefreshCw, Eye, EyeOff, Lock, Copy, Check } from 'lucide-react';
import { DEFAULT_ASSISTANT_NAME, useSettingsStore } from '@/stores/settings';
import { TERMINAL_FONTS, formatTerminalFontStack, normalizeTerminalFont } from '@/lib/xterm-themes';
import { normalizeTerminalEngine } from '@/lib/terminal-engine';
import { useThemeStore } from '@/stores/theme';
import { THEMES } from '@/lib/themes';
import { Badge, Button, Input, Select } from '@/components/primitives';
import { api } from '@/lib/api';
import { canSendCredentials } from '@/lib/credentialTransport';
import { fetchAIModels } from '@/lib/aiModels';
import { SAMLDetails, SSOProviderForm, type EditableSSOProvider } from './SSOProviderForm';
import { UserRoles } from './UserRoles';
import { GroupsRolesSettings } from './GroupsRolesSettings';
import { UserAWSBindings } from './UserAWSBindings';
import { RecordingPolicy } from './RecordingPolicy';
import { KubeClusters } from './KubeClusters';
import { SharedAISettings } from './SharedAISettings';
import { OwnPasswordForm } from './OwnPasswordForm';
import { MfaSettingsCard } from './MfaSettingsCard';
import { hasPermission, useAuthStore } from '@/stores/auth';
import { DialogPageContext } from '@/components/primitives/Dialog';
import { AuditLogModal } from '@/components/modals/AuditLogModal';
import { RecordingsModal } from '@/components/recordings/RecordingsModal';
import { useLayoutStore, type SettingsTab } from '@/stores/layout';
import { useToastStore } from '@/stores/toast';
import { RemoteDesktopSettingsView } from '@/rust-engines/settings/RemoteDesktopSettingsView';
import { GovernancePanel } from '@/components/governance/GovernancePanel';
import { CompliancePortal } from '@/components/governance/CompliancePortal';
import { McpProxyPanel } from '@/components/platform/McpProxyPanel';
import { HybridAgentsPanel } from '@/components/platform/HybridAgentsPanel';
import { AccessGraphPanel } from '@/components/platform/AccessGraphPanel';
import { DeviceTrustPanel } from '@/components/platform/DeviceTrustPanel';

type Tab = SettingsTab;

const TAB_DESCRIPTIONS: Record<Tab, string> = {
  appearance: 'Customize the platform theme, terminal typography, and environment safety borders.',
  general: 'Enable workspace resource modules (Kubernetes, Databases) and configure terminal engine, scrollback, and password.',
  'remote-desktop': 'Configure OQR2 RDP/VNC display scaling, codecs, keyboard layout, clipboard normalization, and security policy.',
  audit: 'Compliance activity trail with forensic event inspection and synchronized session playback.',
  recordings: 'Encrypted SSH asciinema streams and RDP Guacamole video vault.',
  governance: 'Just-in-Time access workflows, four-eyes approvals, live session moderation, and DLP command firewall rules.',
  compliance: 'Continuous SOC 2 Type II & ISO 27001 posture monitoring, quarterly access reviews, and Ed25519 evidence bundles.',
  'ai-mcp': 'Issue sponsor-bound Model Context Protocol (MCP) AI agent tokens with per-tool RBAC, JIT escalation, and automatic PII redaction.',
  agents: 'Enroll zero-inbound hybrid reverse-tunnel agents bridging private VPCs and on-prem networks over outbound mTLS.',
  'access-graph': 'Explore identity-to-resource blast radius, Shadow Admin escalation paths, cyclic trust loops, and stale privileges.',
  'device-trust': 'Enforce workstation disk encryption, active EDR sensor, and OS patch posture before issuing remote desktop tickets.',
  snippets: 'Manage reusable terminal command snippets.',
  vault: 'Manage encrypted SSH keys and credentials for infrastructure connections.',
  users: 'Provision local operators, manage SSO user roles, and enforce access policies.',
  groups: 'Create user groups, define custom roles with scoped permissions, and map IdP group claims.',
  signin: 'Configure SAML 2.0 identity providers and automatic sign-in policies.',
  accounts: 'Manage AWS IAM Identity Center start URLs and approved IAM role bindings.',
  'kube-clusters': 'Register and manage Teleport-backed Kubernetes clusters.',
  recording: 'Define mandatory session recording rules for VMs and Kubernetes namespaces.',
  ai: 'Configure shared LLM providers and models available to all operators.',
};

interface SettingsModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  initialTab?: Tab;
  asPage?: boolean;
}

export function SettingsModal({ open, onOpenChange, initialTab, asPage = false }: SettingsModalProps) {
  const [tab, setTab] = useState<Tab>(initialTab ?? 'appearance');
  const me = useAuthStore((s) => s.me);
  const canAudit = hasPermission(me, 'audit:read');
  const canRecordings = hasPermission(me, 'recordings:read');
  const canUsers = hasPermission(me, 'users:manage');
  const canGroupsOrRoles = hasPermission(me, 'groups:manage') || hasPermission(me, 'roles:manage');
  const canSSO = hasPermission(me, 'sso:manage');
  const canAccounts = hasPermission(me, 'aws_accounts:manage');
  const canK8sClusters = hasPermission(me, 'k8s_clusters:manage');
  const canRecordingPolicy = hasPermission(me, 'recording_policy:manage');
  const canAI = hasPermission(me, 'ai_catalog:manage');
  const canCompliance = hasPermission(me, 'compliance:manage') || canAudit;
  const canMcp = hasPermission(me, 'mcp:manage') || canAudit;
  const canAgents = hasPermission(me, 'agents:manage') || canAudit;
  const canAccessGraph = canAudit || canGroupsOrRoles || canAccounts;
  const canDeviceTrust = hasPermission(me, 'device_trust:manage') || canAudit;
  const userAWS = useAuthStore((s) => s.config?.aws_access_mode === 'user');
  useEffect(() => {
    if (open && initialTab) setTab(initialTab);
  }, [open, initialTab]);
  useEffect(() => {
    const onOpen = (ev: Event) => {
      const next = (ev as CustomEvent<{ tab?: Tab }>).detail?.tab;
      if (next) setTab(next);
    };
    window.addEventListener('ct:open-settings', onOpen);
    return () => window.removeEventListener('ct:open-settings', onOpen);
  }, []);

  // Escape to close + body scroll lock
  useEffect(() => {
    if (!open || asPage) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') { e.stopPropagation(); onOpenChange(false); }
    };
    document.addEventListener('keydown', onKey, true);
    return () => {
      document.removeEventListener('keydown', onKey, true);
      document.body.style.overflow = prev;
    };
  }, [open, onOpenChange, asPage]);

  if (!open) return null;

  type Entry = { id: Tab; label: string; icon: React.ReactNode; group: string };
  const tabs: Entry[] = [
    { id: 'appearance', label: 'Appearance', icon: <Palette size={15} />, group: 'Personal' },
    { id: 'general', label: 'General', icon: <Type size={15} />, group: 'Personal' },
    { id: 'remote-desktop', label: 'Remote Desktop', icon: <Monitor size={15} />, group: 'Personal' },
    ...(asPage ? [
      ...(canAudit ? [{ id: 'audit' as const, label: 'Audit log', icon: <ScrollText size={15} />, group: 'Operations' }] : []),
      ...(canRecordings ? [{ id: 'recordings' as const, label: 'Recordings', icon: <Video size={15} />, group: 'Operations' }] : []),
    ] : []),
    ...(me ? [{ id: 'governance' as const, label: 'Access & DLP', icon: <ShieldAlert size={15} />, group: 'Governance' }] : []),
    ...(canCompliance ? [{ id: 'compliance' as const, label: 'Compliance', icon: <FileCheck2 size={15} />, group: 'Governance' }] : []),
    ...(canMcp ? [{ id: 'ai-mcp' as const, label: 'AI & MCP Proxy', icon: <Bot size={15} />, group: 'Governance' }] : []),
    ...(canAccessGraph ? [{ id: 'access-graph' as const, label: 'Access Graph', icon: <GitBranch size={15} />, group: 'Governance' }] : []),
    ...(canDeviceTrust ? [{ id: 'device-trust' as const, label: 'Device Trust', icon: <Laptop size={15} />, group: 'Governance' }] : []),
    ...(canAgents ? [{ id: 'agents' as const, label: 'Hybrid Agents', icon: <Network size={15} />, group: 'Administration' }] : []),
    ...(canUsers ? [{ id: 'users' as const, label: 'Users', icon: <Users size={15} />, group: 'Administration' }] : []),
    ...(canGroupsOrRoles ? [{ id: 'groups' as const, label: 'Groups & Roles', icon: <ShieldCheck size={15} />, group: 'Administration' }] : []),
    ...(canSSO ? [{ id: 'signin' as const, label: 'Single Sign On', icon: <KeyRound size={15} />, group: 'Administration' }] : []),
    ...(canAccounts ? [{ id: 'accounts' as const, label: 'AWS Accounts', icon: <Cloud size={15} />, group: 'Administration' }] : []),
    ...(canK8sClusters ? [{ id: 'kube-clusters' as const, label: 'Kube clusters', icon: <Boxes size={15} />, group: 'Administration' }] : []),
    ...(canRecordingPolicy ? [{ id: 'recording' as const, label: 'Recording policy', icon: <Database size={15} />, group: 'Administration' }] : []),
    ...(canAI ? [{ id: 'ai' as const, label: 'Assistant', icon: <Sparkles size={15} />, group: 'Administration' }] : []),
  ];
  const activeTab = tabs.some((t) => t.id === tab) ? tab : 'appearance';
  const groups = [...new Set(tabs.map((t) => t.group))];
  // Operations pages carry their own title, toolbar and actions.
  const embedded = activeTab === 'audit' || activeTab === 'recordings';
  const close = () => onOpenChange(false);

  const activeEntry = tabs.find((t) => t.id === activeTab);

  return (
    <div className={asPage ? 'h-full' : 'fixed inset-0 z-[200] flex items-center justify-center bg-[var(--overlay)]'} onClick={asPage ? undefined : close}>
      <div
        className={asPage ? 'settings-frame bg-bg w-full h-full flex flex-col overflow-hidden' : 'settings-frame bg-bg border border-border rounded-[var(--radius-lg)] shadow-[var(--shadow-elev)] w-[92vw] max-w-[1440px] h-[88vh] flex flex-col overflow-hidden'}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex flex-1 min-h-0">
          <nav aria-label="Settings navigation" className="w-[232px] border-r border-border bg-side p-3 shrink-0 overflow-y-auto space-y-1">
            {asPage && (
              <button
                type="button"
                onClick={close}
                className="w-full flex items-center gap-2 px-2.5 h-9 mb-2 rounded-md text-[13px] font-medium text-text-mut hover:bg-surface-hover hover:text-text-pri transition-colors"
              >
                <ArrowLeft size={15} aria-hidden="true" />Back to workspace
              </button>
            )}
            {groups.map((group) => (
              <div key={group} role="group" aria-label={group} className="pt-2 first:pt-0">
                <div className="px-2.5 pb-1.5 text-[11px] text-text-dim font-semibold uppercase tracking-wider">{group}</div>
                <div className="space-y-0.5">
                  {tabs.filter((t) => t.group === group).map((t) => {
                    const isActive = activeTab === t.id;
                    return (
                      <button
                        key={t.id}
                        type="button"
                        onClick={() => setTab(t.id)}
                        aria-current={isActive ? 'page' : undefined}
                        className={`w-full flex items-center gap-2.5 px-2.5 h-9 text-[13px] rounded-md border transition-colors ${isActive
                          ? 'bg-[var(--accent-dim)] text-accent border-accent/25 font-medium'
                          : 'text-text-mut border-transparent hover:bg-surface-hover hover:text-text-pri'
                          }`}
                      >
                        {t.icon}
                        <span>{t.label}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </nav>
          {embedded ? (
            <div className="flex-1 min-w-0 relative bg-bg">
              <DialogPageContext.Provider value>
                {activeTab === 'audit' && <AuditLogModal open onOpenChange={close} />}
                {activeTab === 'recordings' && <RecordingsModal open onOpenChange={close} />}
              </DialogPageContext.Provider>
            </div>
          ) : (
            <div className="flex-1 overflow-y-auto bg-bg px-6 sm:px-8 py-6">
              <div className="w-full space-y-6">
                <div className="flex items-start justify-between gap-4 pb-4 border-b border-border">
                  <div>
                    <div className="text-[11px] font-semibold uppercase tracking-wider text-text-dim mb-1">
                      Settings · {activeEntry?.group ?? 'General'}
                    </div>
                    <h2 className="text-[20px] font-semibold tracking-tight text-text-pri">
                      {activeEntry?.label ?? activeTab}
                    </h2>
                    <p className="mt-1 text-xs text-text-sec">
                      {TAB_DESCRIPTIONS[activeTab]}
                    </p>
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="xs"
                    onClick={close}
                    aria-label="Close settings"
                    className="h-8 w-8 px-0 text-text-mut hover:text-text-pri"
                  >
                    <X size={16} />
                  </Button>
                </div>
                {activeTab === 'appearance' && <AppearanceTab />}
                {activeTab === 'general' && <GeneralTab />}
                {activeTab === 'remote-desktop' && (
                  <RemoteDesktopSettingsView
                    onLaunchSession={() => {
                      useLayoutStore.getState().setView('session');
                    }}
                  />
                )}
                {activeTab === 'accounts' && canAccounts && (userAWS ? <UserAWSBindings /> : <AWSAccountsTab />)}
                {activeTab === 'kube-clusters' && canK8sClusters && <KubeClusters />}
                {activeTab === 'signin' && canSSO && <SignInProvidersTab />}
                {activeTab === 'users' && me && canUsers && <UserRoles currentUser={me.user_id} />}
                {activeTab === 'groups' && canGroupsOrRoles && <GroupsRolesSettings />}
                {activeTab === 'recording' && canRecordingPolicy && <RecordingPolicy />}
                {activeTab === 'ai' && canAI && <AIAgentTab />}
                {activeTab === 'vault' && <VaultTab />}
                {activeTab === 'governance' && me && <GovernancePanel />}
                {activeTab === 'compliance' && canCompliance && <CompliancePortal />}
                {activeTab === 'ai-mcp' && canMcp && <McpProxyPanel />}
                {activeTab === 'access-graph' && canAccessGraph && <AccessGraphPanel />}
                {activeTab === 'device-trust' && canDeviceTrust && <DeviceTrustPanel />}
                {activeTab === 'agents' && canAgents && <HybridAgentsPanel />}
              </div>
            </div>
          )}
        </div>
        {/* Only preference pages are saved by the footer; the others save their own changes. */}
        {(activeTab === 'appearance' || activeTab === 'general' || (activeTab === 'ai' && !userAWS)) && (
          <SettingsFooter onClose={close} asPage={asPage} />
        )}
      </div>
    </div>
  );
}

function SettingsFooter({ onClose, asPage }: { onClose: () => void; asPage: boolean }) {
  const [saving, setSaving] = useState(false);
  const [savedNotice, setSavedNotice] = useState(false);
  const [error, setError] = useState('');
  const saveToServer = useSettingsStore((s) => s.saveToServer);
  const pushToast = useToastStore((s) => s.push);

  useEffect(() => {
    if (!savedNotice) return;
    const timer = window.setTimeout(() => setSavedNotice(false), 3500);
    return () => window.clearTimeout(timer);
  }, [savedNotice]);

  const handleSave = useCallback(async () => {
    setSaving(true);
    setError('');
    setSavedNotice(false);
    const saved = await saveToServer();
    setSaving(false);
    if (!saved) {
      setError('Could not save settings to the server. Check HTTPS and the server connection, then try again.');
      return;
    }
    setSavedNotice(true);
    pushToast({
      variant: 'success',
      title: 'Settings saved',
      description: 'Your preferences have been saved.',
      duration: 3000,
    });
    if (!asPage) onClose();
  }, [saveToServer, pushToast, onClose, asPage]);

  return (
    <div className="flex items-center justify-end gap-2 px-6 py-3 border-t border-border bg-side/80 shrink-0">
      {error && <p role="alert" className="mr-auto text-sm text-danger">{error}</p>}
      {!error && savedNotice && (
        <p role="status" className="mr-auto inline-flex items-center gap-1.5 text-[13px] font-medium text-success">
          <Check size={14} aria-hidden="true" />
          <span>Settings saved</span>
        </p>
      )}
      <Button variant="outline" size="sm" onClick={onClose}>
        Cancel
      </Button>
      <Button variant="primary" size="sm" onClick={() => void handleSave()} loading={saving}>
        Save
      </Button>
    </div>
  );
}

function AppearanceTab() {
  const currentTheme = useThemeStore((s) => s.theme);
  const setTheme = useThemeStore((s) => s.setTheme);
  const fontSize = useSettingsStore((s) => s.fontSize);
  const setFontSize = useSettingsStore((s) => s.setFontSize);
  const fontFamily = useSettingsStore((s) => s.fontFamily);
  const envColors = useSettingsStore((s) => s.envColors);
  const addEnvColor = useSettingsStore((s) => s.addEnvColor);
  const removeEnvColor = useSettingsStore((s) => s.removeEnvColor);
  const enableEnvBorders = useSettingsStore((s) => s.enableEnvBorders);
  const setEnableEnvBorders = useSettingsStore((s) => s.setEnableEnvBorders);

  const [newEnv, setNewEnv] = useState('');
  const [newColor, setNewColor] = useState('var(--env-preset-danger)');

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-border bg-surface divide-y divide-border overflow-hidden shadow-xs">
        <div className="px-5 py-4 grid grid-cols-1 md:grid-cols-[minmax(200px,1fr)_minmax(280px,1.3fr)] gap-4 items-start">
          <div>
            <h3 className="text-[14px] font-semibold text-text-pri" id="theme-label">Theme</h3>
            <p className="text-[13px] text-text-mut mt-0.5">
              Applies to the whole app, the Kubernetes workspace and every terminal.
            </p>
          </div>
          <div role="radiogroup" aria-labelledby="theme-label" className="grid grid-cols-2 gap-3 lg:max-w-[440px] lg:ml-auto w-full">
            {THEMES.map((t) => {
              const selected = currentTheme === t.slug;
              return (
                <button
                  key={t.slug}
                  type="button"
                  role="radio"
                  aria-checked={selected}
                  onClick={() => setTheme(t.slug)}
                  className={`text-left rounded-lg border p-2.5 transition-all ${selected
                    ? 'border-accent bg-[var(--accent-dim)] ring-1 ring-accent/30'
                    : 'border-border bg-bg/40 hover:bg-surface-hover hover:border-text-dim'
                    }`}
                >
                  <span data-theme={t.slug} aria-hidden="true" className="block rounded-md border border-border bg-bg p-2">
                    <span className="flex gap-1.5">
                      <span className="w-6 rounded-sm bg-side" />
                      <span className="flex-1 space-y-1.5">
                        <span className="block h-2 rounded-sm bg-surface border border-border" />
                        <span className="block h-2 w-1/2 rounded-sm bg-accent" />
                        <span className="block h-5 rounded-sm" style={{ background: 'var(--term-bg)' }} />
                      </span>
                    </span>
                  </span>
                  <span className="mt-2 flex items-center justify-between text-[13px] font-medium text-text-pri">
                    <span>{t.label}</span>
                    {selected && <Badge variant="accent" size="sm">Selected</Badge>}
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="px-5 py-4 grid grid-cols-1 md:grid-cols-[minmax(200px,1fr)_minmax(280px,1.3fr)] gap-4 items-center">
          <div>
            <h3 className="text-[14px] font-semibold text-text-pri">Terminal font size</h3>
            <p className="text-[13px] text-text-mut mt-0.5">
              Base size applied across active and future terminal panes.
            </p>
          </div>
          <div className="flex md:justify-end">
            <div className="inline-flex items-center gap-1.5 rounded-md border border-border bg-bg px-2 py-1">
              <Button
                type="button"
                variant="ghost"
                size="xs"
                onClick={() => setFontSize(fontSize - 1)}
                className="w-7 h-7 px-0"
                aria-label="Decrease font size"
              >
                <Minus size={14} />
              </Button>
              <span className="text-[14px] font-mono tabular-nums font-semibold text-text-pri w-9 text-center">{fontSize}</span>
              <Button
                type="button"
                variant="ghost"
                size="xs"
                onClick={() => setFontSize(fontSize + 1)}
                className="w-7 h-7 px-0"
                aria-label="Increase font size"
              >
                <Plus size={14} />
              </Button>
              <span className="text-[12px] text-text-dim pl-1 pr-1 border-l border-border">px</span>
            </div>
          </div>
        </div>

        <div className="px-5 py-4 grid grid-cols-1 md:grid-cols-[minmax(200px,1fr)_minmax(280px,1.3fr)] gap-4 items-center">
          <div>
            <label htmlFor="terminal-font" className="block text-[14px] font-semibold text-text-pri">
              Terminal font
            </label>
            <p className="mt-0.5 text-text-mut text-[13px]">
              All bundled monospace webfonts load cleanly with crisp fallback metrics.
            </p>
          </div>
          <div className="md:max-w-xs md:ml-auto w-full">
            <Select
              id="terminal-font"
              value={normalizeTerminalFont(fontFamily)}
              onChange={(e) => useSettingsStore.setState({ fontFamily: normalizeTerminalFont(e.target.value) })}
              className="font-mono"
            >
              {TERMINAL_FONTS.map((f) => (
                <option key={f} value={f} style={{ fontFamily: formatTerminalFontStack(f) }}>
                  {f}
                </option>
              ))}
            </Select>
          </div>
        </div>

        <div className="px-5 py-4 space-y-3 bg-bg/30">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-[14px] font-semibold text-text-pri">Terminal preview</h3>
              <p className="text-[13px] text-text-mut">Terminal colors follow the selected theme.</p>
            </div>
            <Badge variant="default" size="sm" className="font-mono">{normalizeTerminalFont(fontFamily)} · {fontSize}px</Badge>
          </div>
          <div className="rounded-lg border border-border overflow-hidden shadow-xs">
            <div className="px-3 py-1.5 border-b border-border bg-side/80 flex items-center justify-between text-[11px] font-mono text-text-dim">
              <span>bash — 80×24</span>
              <span>live preview</span>
            </div>
            <div
              className="p-3.5 font-mono text-sm leading-relaxed"
              style={{
                background: 'var(--term-bg)',
                color: 'var(--term-fg)',
                fontFamily: formatTerminalFontStack(normalizeTerminalFont(fontFamily)),
              }}
              aria-label="Terminal preview"
            >
              <div><span style={{ color: 'var(--term-green)' }}>operator</span><span style={{ color: 'var(--term-blue)' }}>@server</span> <span style={{ color: 'var(--term-cyan)' }}>~</span> $ ls -la</div>
              <div><span style={{ color: 'var(--term-blue)' }}>config/</span> &nbsp; <span style={{ color: 'var(--term-green)' }}>ready</span> &nbsp; <span style={{ color: 'var(--term-yellow)' }}>warning</span> &nbsp; <span style={{ color: 'var(--term-red)' }}>error</span></div>
              <div><span style={{ color: 'var(--term-magenta)' }}>PS</span> C:\Users\Admin&gt; Get-Process</div>
            </div>
          </div>
        </div>
      </div>

      <section className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs">
        <div className="px-5 py-4 border-b border-border flex items-center justify-between gap-4">
          <div>
            <h3 className="text-[14px] font-semibold text-text-pri">Environment color borders</h3>
            <p className="text-[13px] text-text-mut mt-0.5">
              Visually distinguish production and staging terminals with colored frame accents.
            </p>
          </div>
          <label className="flex items-center gap-2 text-[13px] font-medium text-text-pri cursor-pointer shrink-0">
            <input
              type="checkbox"
              checked={enableEnvBorders}
              onChange={(e) => setEnableEnvBorders(e.target.checked)}
              className="accent-accent rounded"
            />
            <span>Enabled</span>
          </label>
        </div>

        <div className="divide-y divide-border">
          {envColors.map((ec) => (
            <div key={ec.env} className="flex items-center gap-3 px-5 py-2.5 text-[13px] hover:bg-surface-hover/50 transition-colors">
              <span className="w-3.5 h-3.5 rounded-sm shrink-0 border border-border" style={{ background: ec.color }} />
              <span className="text-text-pri font-mono font-medium min-w-[5rem]">{ec.env}</span>
              <Badge variant="default" size="sm">{ec.width}px border</Badge>
              <Button
                type="button"
                variant="danger-ghost"
                size="xs"
                className="ml-auto"
                onClick={() => removeEnvColor(ec.env)}
                aria-label={`Remove ${ec.env}`}
              >
                <Trash2 size={13} />
              </Button>
            </div>
          ))}
        </div>

        <div className="px-5 py-3 bg-bg/60 border-t border-border flex flex-wrap items-center gap-2">
          <div className="w-32">
            <Input placeholder="env name" value={newEnv} onChange={(e) => setNewEnv(e.target.value)} className="h-8 text-[13px]" />
          </div>
          <div className="w-40">
            <Select aria-label="Border color" value={newColor} onChange={(e) => setNewColor(e.target.value)} className="h-8 text-[13px]">
              <option value="var(--env-preset-danger)">Danger</option>
              <option value="var(--warn)">Warning</option>
              <option value="var(--success)">Success</option>
              <option value="var(--info)">Info</option>
              <option value="var(--accent)">Accent</option>
            </Select>
          </div>
          <Button
            variant="primary"
            size="sm"
            onClick={() => {
              if (newEnv.trim()) {
                addEnvColor({ env: newEnv.trim().toLowerCase(), color: newColor, width: 2 });
                setNewEnv('');
              }
            }}
          >
            Add
          </Button>
        </div>
      </section>
    </div>
  );
}

function GeneralTab() {
  const scrollbackLines = useSettingsStore((s) => s.scrollbackLines);
  const setScrollbackLines = useSettingsStore((s) => s.setScrollbackLines);
  const terminalEngine = useSettingsStore((s) => normalizeTerminalEngine(s.terminalEngine));
  const setTerminalEngine = useSettingsStore((s) => s.setTerminalEngine);
  const enableKubernetes = useSettingsStore((s) => s.enableKubernetes ?? true);
  const setEnableKubernetes = useSettingsStore((s) => s.setEnableKubernetes);
  const enableDatabases = useSettingsStore((s) => s.enableDatabases ?? true);
  const setEnableDatabases = useSettingsStore((s) => s.setEnableDatabases);

  const toggleKubernetes = () => {
    const next = !enableKubernetes;
    setEnableKubernetes?.(next);
    if (!next && useLayoutStore.getState().view === 'kubernetes') {
      useLayoutStore.getState().setView('session');
    }
  };

  const toggleDatabases = () => {
    const next = !enableDatabases;
    setEnableDatabases?.(next);
    if (!next && useLayoutStore.getState().view === 'databases') {
      useLayoutStore.getState().setView('session');
    }
  };

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-border bg-surface divide-y divide-border overflow-hidden shadow-xs">
        <div className="px-5 py-3.5 bg-elev/40 flex items-center justify-between">
          <div>
            <h3 className="text-[14px] font-semibold text-text-pri">Workspace Resource Modules</h3>
            <p className="text-[12px] text-text-mut mt-0.5">
              VMs is included for every workspace. Enable optional Kubernetes and Databases modules on demand.
            </p>
          </div>
          <Badge variant="default" size="sm">VMs Base Included</Badge>
        </div>

        <div className="px-5 py-3.5 flex items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[13px] font-semibold text-text-pri">VMs (Compute Instances)</span>
              <Badge variant="accent" size="sm">Base feature · Always enabled</Badge>
            </div>
            <p className="text-[12px] text-text-mut mt-0.5">
              SSH, AWS SSM, and RDP browser sessions for virtual machines and cloud instances.
            </p>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked
            aria-label="VMs module always enabled"
            disabled
            className="relative inline-flex h-5 w-9 shrink-0 cursor-not-allowed items-center rounded-full bg-accent/80 opacity-80"
          >
            <span className="inline-block h-3.5 w-3.5 translate-x-[18px] rounded-full bg-bg shadow" />
          </button>
        </div>

        <div className="px-5 py-3.5 flex items-center justify-between gap-4">
          <div>
            <span className="text-[13px] font-semibold text-text-pri">Kubernetes (K8s)</span>
            <p className="text-[12px] text-text-mut mt-0.5">
              Enable Teleport &amp; EKS cluster catalog, pod logs, and workload console.
            </p>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={enableKubernetes}
            aria-label="Enable Kubernetes module"
            onClick={toggleKubernetes}
            className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors ${enableKubernetes ? 'bg-accent border-accent' : 'bg-bg border-border'
              }`}
          >
            <span
              className={`inline-block h-3.5 w-3.5 rounded-full transition-transform ${enableKubernetes ? 'translate-x-[18px] bg-bg' : 'translate-x-1 bg-text-dim'
                }`}
            />
          </button>
        </div>

        <div className="px-5 py-3.5 flex items-center justify-between gap-4">
          <div>
            <span className="text-[13px] font-semibold text-text-pri">Databases (DB)</span>
            <p className="text-[12px] text-text-mut mt-0.5">
              Enable DBeaver-style SQL studio, schema browser, and query runner.
            </p>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={enableDatabases}
            aria-label="Enable Databases module"
            onClick={toggleDatabases}
            className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors ${enableDatabases ? 'bg-accent border-accent' : 'bg-bg border-border'
              }`}
          >
            <span
              className={`inline-block h-3.5 w-3.5 rounded-full transition-transform ${enableDatabases ? 'translate-x-[18px] bg-bg' : 'translate-x-1 bg-text-dim'
                }`}
            />
          </button>
        </div>
      </div>

      <div className="rounded-lg border border-border bg-surface divide-y divide-border overflow-hidden shadow-xs">
        <div className="px-5 py-4 grid grid-cols-1 md:grid-cols-[minmax(220px,1fr)_minmax(240px,1fr)] gap-4 items-center">
          <div>
            <label htmlFor="scrollback-lines" className="block text-[14px] font-semibold text-text-pri">
              Terminal scrollback
            </label>
            <p className="text-[13px] text-text-mut mt-0.5">
              Lines each terminal keeps for scrolling and Find. Applies to open terminals too. 1,000–100,000.
            </p>
          </div>
          <div className="flex items-center md:justify-end gap-2">
            <div className="w-32">
              <Input
                id="scrollback-lines"
                type="number"
                min={1000}
                max={100000}
                step={1000}
                value={scrollbackLines}
                onChange={(e) => setScrollbackLines(Number(e.target.value))}
                className="font-mono text-right"
              />
            </div>
            <span className="text-[13px] text-text-mut">lines</span>
          </div>
        </div>

        <div className="px-5 py-4 grid grid-cols-1 md:grid-cols-[minmax(220px,1fr)_minmax(240px,1fr)] gap-4 items-center">
          <div>
            <label htmlFor="terminal-engine" className="block text-[14px] font-semibold text-text-pri">
              Terminal engine
            </label>
            <p className="text-[13px] text-text-mut mt-0.5">
              Applies immediately to SSH, SSM, and Kubernetes pod shells without disconnecting open sessions.
            </p>
          </div>
          <div className="md:max-w-xs md:ml-auto w-full">
            <Select id="terminal-engine" value={terminalEngine} onChange={(e) => setTerminalEngine(normalizeTerminalEngine(e.target.value))}>
              <option value="xterm">xterm.js (Default)</option>
              <option value="wterm">wterm (WebAssembly DOM)</option>
            </Select>
          </div>
        </div>

        <AssistantNameField />
      </div>

      <OwnPasswordForm />
      <MfaSettingsCard />
    </div>
  );
}

interface AWSAccount {
  id: string;
  name: string;
  access_key_id?: string;
  secret_access_key?: string;
  session_token?: string;
  role_arn?: string;
  external_id?: string;
  added_at?: string;
}

function maskKey(key: string): string {
  if (!key || key.length < 8) return '****';
  return key.slice(0, 4) + '****' + key.slice(-4);
}

function AWSAccountsTab() {
  const [accounts, setAccounts] = useState<AWSAccount[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [newName, setNewName] = useState('');
  const [newAccessKeyId, setNewAccessKeyId] = useState('');
  const [newSecretAccessKey, setNewSecretAccessKey] = useState('');
  const [newSessionToken, setNewSessionToken] = useState('');
  const [newRoleArn, setNewRoleArn] = useState('');
  const [mode, setMode] = useState<'role' | 'keys'>('role');
  const [onboarding, setOnboarding] = useState<{ external_id?: string; template?: string; mode?: string; access_keys?: boolean } | null>(null);
  const [verify, setVerify] = useState<Record<string, { ok: boolean; text: string } | 'busy'>>({});
  const [addError, setAddError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    api.get<AWSAccount[]>('/aws-accounts').then((r) => {
      if (r.ok) setAccounts(r.data ?? []);
      setLoading(false);
    }).catch(() => setLoading(false));
    api.get<{ external_id?: string; template?: string; mode?: string; access_keys?: boolean }>('/api/aws/onboarding').then((r) => {
      if (r.ok && r.data) setOnboarding(r.data);
    }).catch(() => undefined);
  }, []);

  const addAccount = async () => {
    if (mode === 'role' && !newRoleArn.trim()) return;
    if (mode === 'keys' && (!newAccessKeyId.trim() || !newSecretAccessKey.trim())) return;
    setSubmitting(true);
    const result = await api.post<AWSAccount>('/aws-accounts', mode === 'role'
      ? { name: newName.trim() || undefined, role_arn: newRoleArn.trim() }
      : {
        name: newName.trim() || undefined,
        access_key_id: newAccessKeyId.trim(),
        secret_access_key: newSecretAccessKey.trim(),
        session_token: newSessionToken.trim() || undefined,
      });
    setAddError(result.ok ? null : (() => {
      try { return (JSON.parse(result.error.message) as { error?: string }).error ?? result.error.message; } catch { return result.error.message; }
    })());
    if (result.ok && result.data) {
      setAccounts((prev) => [...prev, result.data as AWSAccount]);
      setNewName('');
      setNewAccessKeyId('');
      setNewSecretAccessKey('');
      setNewSessionToken('');
      setNewRoleArn('');
      setShowAdd(false);
    }
    setSubmitting(false);
  };

  const deleteAccount = async (id: string) => {
    await api.delete(`/aws-accounts/${id}`);
    setAccounts((prev) => prev.filter((a) => a.id !== id));
  };

  const fetchAccount = async (id: string) => {
    await api.post(`/aws-accounts/fetch/${id}`, {});
  };

  const verifyAccount = async (id: string) => {
    setVerify((v) => ({ ...v, [id]: 'busy' }));
    const r = await api.post<{ ok: boolean; account_id?: string; arn?: string; error?: string }>(`/aws-accounts/verify/${id}`, {});
    const d = r.ok ? r.data : { ok: false, error: r.error.message };
    setVerify((v) => ({
      ...v,
      [id]: d.ok ? { ok: true, text: `Assumed ${d.arn} in ${d.account_id}` } : { ok: false, text: d.error ?? 'AssumeRole failed' },
    }));
  };

  const keysAllowed = onboarding?.access_keys !== false;

  if (loading) return <div className="text-[12px] text-text-dim">Loading accounts...</div>;

  return (
    <div className="space-y-5">
      <div className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs">
        <div className="px-5 py-4 flex flex-wrap items-start justify-between gap-4">
          <div className="text-[13px] text-text-mut leading-relaxed space-y-1.5 flex-1 min-w-[240px]">
            <p>
              Operquay reaches each AWS account by assuming its <span className="font-mono text-text-pri">OperquayAccess</span> role from this server's own role.
              Launch <span className="font-mono text-text-pri">{onboarding?.template ?? 'deploy/cloudformation/operquay-access.yaml'}</span> in the account, then paste the role ARN here.
            </p>
            {onboarding?.external_id && (
              <p>
                ExternalId for this deployment:{' '}
                <span className="font-mono text-text-pri bg-bg border border-border px-1.5 py-0.5 rounded select-all">{onboarding.external_id}</span>
              </p>
            )}
            <p className="text-[12px] text-text-dim">
              {onboarding?.mode === 'hub'
                ? 'Hub mode: this server never reads ~/.aws credentials.'
                : 'Profiles mode: this server also discovers ~/.aws profiles. Set AWS_ACCESS_MODE=hub to stop that.'}
            </p>
          </div>
          <Button variant={showAdd ? 'outline' : 'primary'} size="sm" onClick={() => setShowAdd(!showAdd)} className="shrink-0">
            {showAdd ? 'Cancel' : '+ Add Account'}
          </Button>
        </div>

        {showAdd && (
          <div className="px-5 py-4 border-t border-border bg-bg/40 space-y-3">
            {keysAllowed && (
              <div className="inline-flex items-center gap-1 rounded-md border border-border bg-bg p-0.5 text-[12px]">
                <button
                  type="button"
                  className={`px-2.5 py-1 rounded font-medium transition-colors ${mode === 'role' ? 'bg-[var(--accent-dim)] text-accent' : 'text-text-mut hover:text-text-pri'}`}
                  onClick={() => setMode('role')}
                >
                  Assume role
                </button>
                <button
                  type="button"
                  className={`px-2.5 py-1 rounded font-medium transition-colors ${mode === 'keys' ? 'bg-[var(--accent-dim)] text-accent' : 'text-text-mut hover:text-text-pri'}`}
                  onClick={() => setMode('keys')}
                >
                  Access keys (migration)
                </button>
              </div>
            )}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <Input
                placeholder="Account name (optional)"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
              />
              {mode === 'role' ? (
                <Input
                  placeholder="arn:aws:iam::123456789012:role/OperquayAccess"
                  value={newRoleArn}
                  onChange={(e) => setNewRoleArn(e.target.value)}
                  className="font-mono"
                />
              ) : (
                <>
                  <Input
                    placeholder="Access Key ID *"
                    value={newAccessKeyId}
                    onChange={(e) => setNewAccessKeyId(e.target.value)}
                    className="font-mono"
                  />
                  <Input
                    type="password"
                    placeholder="Secret Access Key *"
                    value={newSecretAccessKey}
                    onChange={(e) => setNewSecretAccessKey(e.target.value)}
                    className="font-mono"
                  />
                  <Input
                    placeholder="Session Token (optional)"
                    value={newSessionToken}
                    onChange={(e) => setNewSessionToken(e.target.value)}
                    className="font-mono"
                  />
                </>
              )}
            </div>
            <div className="flex items-center justify-between gap-3">
              <div>{addError && <p className="text-[12px] text-danger">{addError}</p>}</div>
              <Button
                variant="primary"
                size="sm"
                onClick={() => void addAccount()}
                disabled={submitting || (mode === 'role' ? !newRoleArn.trim() : !newAccessKeyId.trim() || !newSecretAccessKey.trim())}
              >
                {submitting ? 'Adding…' : 'Add Account'}
              </Button>
            </div>
          </div>
        )}
      </div>

      {accounts.length === 0 ? (
        <div className="rounded-lg border border-border bg-surface text-[13px] text-text-dim text-center py-8">
          No AWS accounts configured
        </div>
      ) : (
        <div className="rounded-lg border border-border bg-surface divide-y divide-border overflow-hidden shadow-xs">
          {accounts.map((a) => (
            <div key={a.id} className="flex items-start gap-3 px-5 py-3.5 hover:bg-surface-hover/50 transition-colors">
              <span className="mt-0.5 w-8 h-8 rounded-md bg-[var(--accent-dim)] text-accent border border-accent/20 flex items-center justify-center shrink-0">
                <Cloud size={15} />
              </span>
              <div className="flex-1 min-w-0">
                <div className="font-semibold text-[14px] text-text-pri truncate">{a.name || a.role_arn || a.access_key_id}</div>
                <div className="text-[12px] text-text-dim font-mono mt-0.5 break-all">
                  {a.role_arn ? a.role_arn : `${maskKey(a.access_key_id ?? '')} · secret: ${maskKey(a.secret_access_key ?? '')}`}
                </div>
                {(() => {
                  const v = verify[a.id];
                  if (!v) return null;
                  if (v === 'busy') return <div className="text-[12px] text-text-mut mt-1">Assuming role…</div>;
                  return <div className={`text-[12px] mt-1 leading-relaxed ${v.ok ? 'text-success' : 'text-danger'}`}>{v.text}</div>;
                })()}
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                {a.role_arn && (
                  <Button variant="outline" size="xs" onClick={() => void verifyAccount(a.id)} aria-label={`Verify ${a.name}`}>
                    Verify
                  </Button>
                )}
                <Button
                  variant="outline"
                  size="xs"
                  icon={<RefreshCw size={12} />}
                  onClick={() => void fetchAccount(a.id)}
                  aria-label="Fetch instances"
                >
                  Fetch
                </Button>
                <Button
                  type="button"
                  variant="danger-ghost"
                  size="xs"
                  onClick={() => void deleteAccount(a.id)}
                  aria-label="Delete account"
                >
                  <Trash2 size={13} />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

interface ProviderRow extends EditableSSOProvider {
  editable?: boolean;
  redirect_url?: string;
  saml?: { entity_id: string; acs_url: string; metadata_url: string; slo_url?: string; certificate_sha256: string };
  admin_groups?: string[];
  operator_groups?: string[];
  viewer_groups?: string[];
  default_role?: string;
}

function CopyRow({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    void navigator.clipboard?.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div className="grid grid-cols-1 sm:grid-cols-[175px_1fr] items-center gap-2 px-3 py-2 text-[12px]">
      <span className="font-medium text-text-dim">{label}</span>
      <div className="flex items-center justify-between gap-2 min-w-0">
        <button
          type="button"
          className="font-mono text-accent text-left break-all hover:underline focus-visible:outline-2 focus-visible:outline-accent"
          title="Copy"
          onClick={handleCopy}
        >
          {value}
        </button>
        <span className="shrink-0 text-text-dim" aria-hidden="true">
          {copied ? <Check size={12} className="text-success" /> : <Copy size={12} />}
        </span>
      </div>
    </div>
  );
}

function SignInProvidersTab() {
  const [rows, setRows] = useState<ProviderRow[] | null>(null);
  const [canManage, setCanManage] = useState(false);
  const [samlBaseURL, setSamlBaseURL] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<ProviderRow | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);

  const loadProviders = useCallback(() => {
    api.get<{ providers: ProviderRow[]; local: string; can_manage: boolean; saml_base_url?: string }>('/api/auth/providers').then((r) => {
      if (r.ok) {
        setRows(r.data.providers);
        setCanManage(r.data.can_manage);
        setSamlBaseURL(r.data.saml_base_url ?? '');
      } else {
        setError(r.error.status === 403 ? 'Only administrators can see sign-in settings.' : r.error.message);
      }
    }).catch(() => setError('Could not load sign-in providers.'));
  }, []);

  useEffect(() => { loadProviders(); }, [loadProviders]);

  if (error) return <div className="text-[13px] text-text-mut">{error}</div>;
  if (!rows) return <div className="text-[13px] text-text-dim">Loading…</div>;

  const deleteProvider = async (row: ProviderRow) => {
    if (!canSendCredentials(`/api/auth/providers/${encodeURIComponent(row.id)}`)) { setActionError('HTTPS is required to delete an SSO provider.'); return; }
    if (!window.confirm(`Delete ${row.label}? New sign-ins through this provider will stop; sign-ins already in progress may still finish. Existing sessions and user accounts remain.`)) return;
    setActionError(null);
    setDeleting(row.id);
    const result = await api.delete(`/api/auth/providers/${encodeURIComponent(row.id)}`);
    setDeleting(null);
    if (!result.ok) {
      try { setActionError((JSON.parse(result.error.message) as { error?: string }).error ?? result.error.message); }
      catch { setActionError(result.error.message); }
      return;
    }
    setEditing(null);
    loadProviders();
  };

  return (
    <div className="space-y-5">
      <div className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs">
        <div className="px-5 py-3.5 border-b border-border flex flex-wrap items-center justify-between gap-2">
          <div>
            <div className="text-[14px] font-semibold text-text-pri">SAML URL patterns</div>
            <p className="text-[12px] text-text-mut mt-0.5">Replace the host and provider ID with your Operquay values.</p>
          </div>
          <Badge variant="default" size="sm">Reference</Badge>
        </div>
        <div className="divide-y divide-border bg-bg/40 text-[12px]">
          <div className="grid grid-cols-1 sm:grid-cols-[175px_1fr] items-center gap-2 px-5 py-2.5">
            <span className="font-medium text-text-dim">Entity ID / Audience URI</span>
            <p className="text-text-pri">
              <span className="sr-only">Entity ID / Audience URI: </span>
              <code className="font-mono break-all text-text-pri">{'https://<host.example.com>/api/auth/saml/<provider-id>/metadata'}</code>
            </p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-[175px_1fr] items-center gap-2 px-5 py-2.5">
            <span className="font-medium text-text-dim">ACS URL</span>
            <p className="text-text-pri">
              <span className="sr-only">ACS URL: </span>
              <code className="font-mono break-all text-text-pri">{'https://<host.example.com>/api/auth/saml/<provider-id>/acs'}</code>
            </p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-[175px_1fr] items-center gap-2 px-5 py-2.5">
            <span className="font-medium text-text-dim">SLO response URL</span>
            <p className="text-text-pri">
              <span className="sr-only">SLO response URL: </span>
              <code className="font-mono break-all text-text-pri">{'https://<host.example.com>/api/auth/saml/<provider-id>/slo'}</code>
            </p>
          </div>
        </div>
      </div>

      <SSOProviderForm canManage={canManage} onAdded={loadProviders} samlBaseURL={samlBaseURL} />

      {actionError && (
        <p role="alert" className="rounded-md border border-danger/30 bg-danger/10 px-4 py-2.5 text-[13px] text-danger">
          {actionError}
        </p>
      )}

      {rows.length === 0 && (
        <div className="text-[13px] text-text-mut bg-surface border border-border rounded-lg p-5">
          No single sign-on provider is configured yet.
        </div>
      )}

      {rows.map((r) => (
        <div key={r.id} className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs">
          <div className="px-5 py-3.5 border-b border-border flex flex-wrap items-center gap-2.5">
            <span className="w-8 h-8 rounded-md bg-[var(--accent-dim)] text-accent border border-accent/20 flex items-center justify-center shrink-0">
              <KeyRound size={15} aria-hidden="true" />
            </span>
            <span className="text-[14px] font-semibold text-text-pri">{r.label}</span>
            <Badge variant="accent" size="sm" className="uppercase">{r.type}</Badge>
            <span className="text-[12px] font-mono text-text-dim">id {r.id}</span>
            {r.editable && canManage ? (
              <div className="ml-auto flex gap-1.5">
                <Button variant="outline" size="xs" disabled={!!deleting} onClick={() => setEditing(r)} aria-label={`Edit ${r.label}`}>
                  Edit
                </Button>
                <Button variant="danger-ghost" size="xs" disabled={!!deleting} onClick={() => void deleteProvider(r)} aria-label={`Delete ${r.label}`}>
                  Delete
                </Button>
              </div>
            ) : (
              <Badge variant="default" size="sm" className="ml-auto">Managed outside settings</Badge>
            )}
          </div>

          <div className="px-5 py-4 space-y-4">
            {editing?.id === r.id && (
              <SSOProviderForm
                key={r.id}
                canManage
                editing={editing}
                samlBaseURL={samlBaseURL}
                onCancel={() => setEditing(null)}
                onAdded={() => { setEditing(null); loadProviders(); }}
              />
            )}
            {r.saml && (
              <div className="space-y-2.5">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-text-dim">
                  Paste into the IdP's SAML app
                </div>
                <SAMLDetails entityID={r.saml.entity_id} acsURL={r.saml.acs_url} metadataURL={r.saml.metadata_url} sloURL={r.saml.slo_url} />
                <div className="rounded-md border border-border bg-bg/60 overflow-hidden">
                  <CopyRow label="Signing cert" value={r.saml.certificate_sha256} />
                </div>
              </div>
            )}
            {r.redirect_url && (
              <div className="space-y-2">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-text-dim">
                  Paste into the IdP's OIDC app
                </div>
                <div className="rounded-md border border-border bg-bg/60 overflow-hidden">
                  <CopyRow label="Redirect URI" value={r.redirect_url} />
                </div>
              </div>
            )}
          </div>

          <div className="px-5 py-3 bg-bg/40 border-t border-border flex flex-wrap items-center gap-x-5 gap-y-1 text-[12px] text-text-mut">
            {r.domains?.length ? <div>Allowed domains: {r.domains.join(', ')}</div> : <div>Any email domain</div>}
            <div>Allowed groups: {[...new Set([...(r.admin_groups ?? []), ...(r.operator_groups ?? []), ...(r.viewer_groups ?? [])])].join(', ') || 'none'}</div>
            <div>Other users: {r.default_role ? 'allowed by this provider' : 'refused'}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

function AIAgentTab() {
  const userAWS = useAuthStore((s) => s.config?.aws_access_mode === 'user');
  return userAWS ? <SharedAISettings /> : <LegacyAIAgentTab />;
}

function AssistantNameField() {
  const name = useSettingsStore((s) => s.assistantName);
  const setName = useSettingsStore((s) => s.setAssistantName);
  return (
    <div className="px-5 py-4 grid grid-cols-1 md:grid-cols-[minmax(220px,1fr)_minmax(240px,1fr)] gap-4 items-center">
      <div>
        <label htmlFor="assistant-name" className="block text-[14px] font-semibold text-text-pri">
          Assistant name
        </label>
        <p className="text-[13px] text-text-mut mt-0.5">
          Your name for the assistant, shown on the header button, the chat panel and the command palette. Up to 16 characters; empty uses “{DEFAULT_ASSISTANT_NAME}”.
        </p>
      </div>
      <div className="md:max-w-xs md:ml-auto w-full">
        <Input id="assistant-name" value={name} maxLength={16} placeholder={DEFAULT_ASSISTANT_NAME} onChange={(e) => setName(e.target.value)} />
      </div>
    </div>
  );
}

function LegacyAIAgentTab() {
  const userAWS = useAuthStore((s) => s.config?.aws_access_mode === 'user');
  const aiProvider = useSettingsStore((s) => s.aiProvider);
  const aiModel = useSettingsStore((s) => s.aiModel);
  const bedrockAuthMode = useSettingsStore((s) => s.bedrockAuthMode);
  const bedrockRegion = useSettingsStore((s) => s.bedrockRegion);
  const bedrockProfile = useSettingsStore((s) => s.bedrockProfile);
  const bedrockAccessKeyId = useSettingsStore((s) => s.bedrockAccessKeyId);
  const bedrockSecretKey = useSettingsStore((s) => s.bedrockSecretKey);
  const bedrockSessionToken = useSettingsStore((s) => s.bedrockSessionToken);
  const bedrockInferenceProfileArn = useSettingsStore((s) => s.bedrockInferenceProfileArn);
  const aiApiKey = useSettingsStore((s) => s.aiApiKey);
  const aiBaseUrl = useSettingsStore((s) => s.aiBaseUrl);

  const [models, setModels] = useState<Array<{ id: string; name: string }>>([]);
  const [modelsLoading, setModelsLoading] = useState(false);
  const [modelsError, setModelsError] = useState<string | null>(null);
  const [modelSearch, setModelSearch] = useState('');
  const [modelDropdownOpen, setModelDropdownOpen] = useState(false);
  const [modelActiveIdx, setModelActiveIdx] = useState(0);
  const modelDropdownRef = useRef<HTMLDivElement>(null);
  const modelRequest = useRef(0);
  useEffect(() => () => { modelRequest.current++; }, []);

  const fetchModels = useCallback((provider: string) => {
    const request = ++modelRequest.current;
    setModelsLoading(true);
    setModelsError(null);
    fetchAIModels(provider).then((r) => {
      if (request !== modelRequest.current || useSettingsStore.getState().aiProvider !== provider) return;
      if (r.ok && Array.isArray(r.data)) {
        setModels(r.data);
        if (r.warning) setModelsError(r.warning);
        if (r.data.length > 0) {
          const current = useSettingsStore.getState().aiModel;
          const hasMatch = r.data.some((m) => m.id === current);
          if (!hasMatch && (!current || useAuthStore.getState().config?.aws_access_mode !== 'user')) {
            useSettingsStore.setState({ aiModel: r.data[0].id });
          }
        }
      } else {
        let msg = ('error' in r ? r.error?.message : undefined) ?? 'Failed to load models';
        try {
          const parsed = JSON.parse(msg);
          if (parsed?.error) msg = parsed.error;
        } catch { /* not JSON, use as-is */ }
        setModelsError(msg);
        setModels([]);
      }
      setModelsLoading(false);
    }).catch((e: unknown) => {
      if (request !== modelRequest.current || useSettingsStore.getState().aiProvider !== provider) return;
      setModelsError(e instanceof Error ? e.message : 'Failed to fetch');
      setModels([]);
      setModelsLoading(false);
    });
  }, []);

  useEffect(() => {
    fetchModels(aiProvider);
  }, [aiProvider, bedrockAuthMode, fetchModels]);

  const providers = [
    { id: 'bedrock', label: 'AWS Bedrock' },
    { id: 'anthropic', label: 'Anthropic (or compatible)' },
    { id: 'openai', label: 'OpenAI (or compatible)' },
    { id: 'gemini', label: 'Google Gemini (or compatible)' },
  ];

  const isApiKeyProvider = aiProvider === 'anthropic' || aiProvider === 'openai' || aiProvider === 'gemini';

  return (
    <div className="space-y-5">
      <section className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs">
        <div className="px-5 py-4 border-b border-border flex items-start gap-3">
          <span className="mt-0.5 w-8 h-8 rounded-md bg-[var(--accent-dim)] text-accent border border-accent/20 flex items-center justify-center shrink-0">
            <Sparkles size={15} aria-hidden="true" />
          </span>
          <div>
            <h3 className="text-[14px] font-semibold text-text-pri">Provider</h3>
            <p className="text-[13px] text-text-mut mt-0.5">Choose your assistant model provider and authentication credentials.</p>
          </div>
        </div>
        <div className="px-5 py-4 space-y-5">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            {providers.map((p) => {
              const active = aiProvider === p.id;
              return (
                <label
                  key={p.id}
                  className={`flex items-center gap-2.5 rounded-lg border px-3.5 py-3 cursor-pointer transition-colors ${active
                    ? 'border-accent bg-[var(--accent-dim)] ring-1 ring-accent/25 text-text-pri font-medium'
                    : 'border-border bg-bg/50 hover:bg-surface-hover text-text-mut'
                    }`}
                >
                  <input
                    type="radio"
                    name="ai-provider"
                    value={p.id}
                    checked={active}
                    onChange={() => {
                      useSettingsStore.setState({ aiProvider: p.id, aiModel: '' });
                    }}
                    className="accent-accent shrink-0"
                  />
                  <span className="text-[13px] text-text-pri">{p.label}</span>
                </label>
              );
            })}
          </div>

          {aiProvider === 'bedrock' && (
            <div className="rounded-lg border border-border bg-bg/40 p-4 space-y-4">
              <h3 className="text-[13px] font-semibold text-text-pri">Bedrock Authentication</h3>

              {userAWS ? (
                <p className="text-[13px] text-text-mut">Bedrock uses the selected AWS role from your active scoped SSH terminal.</p>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
                  {([
                    { mode: 'profile' as const, label: 'AWS Profile & Region', desc: 'Use shared credentials file (~/.aws/credentials)' },
                    { mode: 'api_key' as const, label: 'Access Key & Secret', desc: 'Direct IAM access key authentication' },
                    { mode: 'inference_profile' as const, label: 'Application Inference Profile', desc: 'Use a pre-configured inference profile ARN' },
                  ]).map((opt) => {
                    const active = bedrockAuthMode === opt.mode;
                    return (
                      <div
                        key={opt.mode}
                        onClick={() => useSettingsStore.setState({ bedrockAuthMode: opt.mode })}
                        className={`rounded-lg border p-3 cursor-pointer transition-colors ${active ? 'border-accent bg-[var(--accent-dim)] ring-1 ring-accent/25' : 'border-border bg-surface hover:bg-surface-hover'
                          }`}
                      >
                        <label
                          className="flex items-center gap-2 cursor-pointer text-[13px] text-text-pri font-medium"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <input
                            type="radio"
                            name="bedrock-auth"
                            checked={active}
                            onChange={() => useSettingsStore.setState({ bedrockAuthMode: opt.mode })}
                            className="accent-accent"
                          />
                          <span>{opt.label}</span>
                        </label>
                        <div className="text-[11px] text-text-dim pl-6 mt-1">{opt.desc}</div>
                      </div>
                    );
                  })}
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div>
                  <label className="text-[12px] font-medium text-text-mut mb-1.5 block">Region</label>
                  <Input
                    placeholder="us-east-1"
                    value={bedrockRegion}
                    onChange={(e) => useSettingsStore.setState({ bedrockRegion: e.target.value })}
                    onBlur={() => fetchModels('bedrock')}
                    className="font-mono"
                  />
                </div>

                {!userAWS && bedrockAuthMode === 'profile' && (
                  <div>
                    <label className="text-[12px] font-medium text-text-mut mb-1.5 block">AWS Profile</label>
                    <Input
                      placeholder="default"
                      value={bedrockProfile}
                      onChange={(e) => useSettingsStore.setState({ bedrockProfile: e.target.value })}
                      onBlur={() => fetchModels('bedrock')}
                    />
                  </div>
                )}

                {!userAWS && bedrockAuthMode === 'api_key' && (
                  <>
                    <div>
                      <label className="text-[12px] font-medium text-text-mut mb-1.5 block">Access Key ID</label>
                      <Input
                        placeholder="AKIA..."
                        value={bedrockAccessKeyId}
                        onChange={(e) => useSettingsStore.setState({ bedrockAccessKeyId: e.target.value })}
                        className="font-mono"
                      />
                    </div>
                    <div>
                      <label className="text-[12px] font-medium text-text-mut mb-1.5 block">Secret Access Key</label>
                      <Input
                        type="password"
                        placeholder="Secret key"
                        value={bedrockSecretKey}
                        onChange={(e) => useSettingsStore.setState({ bedrockSecretKey: e.target.value })}
                        onBlur={() => fetchModels('bedrock')}
                        className="font-mono"
                      />
                    </div>
                    <div>
                      <label className="text-[12px] font-medium text-text-mut mb-1.5 block">Session Token <span className="text-text-dim font-normal">(optional)</span></label>
                      <Input
                        type="password"
                        placeholder="Temporary session token"
                        value={bedrockSessionToken}
                        onChange={(e) => useSettingsStore.setState({ bedrockSessionToken: e.target.value })}
                        className="font-mono"
                      />
                    </div>
                  </>
                )}

                {!userAWS && bedrockAuthMode === 'inference_profile' && (
                  <>
                    <div>
                      <label className="text-[12px] font-medium text-text-mut mb-1.5 block">Inference Profile ARN</label>
                      <Input
                        placeholder="arn:aws:bedrock:us-east-1:123456789:inference-profile/..."
                        value={bedrockInferenceProfileArn}
                        onChange={(e) => useSettingsStore.setState({ bedrockInferenceProfileArn: e.target.value })}
                        onBlur={() => fetchModels('bedrock')}
                        className="font-mono"
                      />
                      <p className="text-[11px] text-text-dim mt-1">The inference profile ARN will be used as the model ID for API calls.</p>
                    </div>
                    <div>
                      <label className="text-[12px] font-medium text-text-mut mb-1.5 block">AWS Profile <span className="text-text-dim font-normal">(for authentication)</span></label>
                      <Input
                        placeholder="default"
                        value={bedrockProfile}
                        onChange={(e) => useSettingsStore.setState({ bedrockProfile: e.target.value })}
                        onBlur={() => fetchModels('bedrock')}
                      />
                    </div>
                  </>
                )}
                {userAWS && (
                  <label className="text-[12px] font-medium text-text-mut block">
                    Inference profile ARN (optional)
                    <Input
                      placeholder="arn:aws:bedrock:..."
                      value={bedrockAuthMode === 'inference_profile' ? bedrockInferenceProfileArn : ''}
                      onChange={(e) => useSettingsStore.setState({ bedrockInferenceProfileArn: e.target.value, bedrockAuthMode: e.target.value ? 'inference_profile' : 'profile' })}
                      className="font-mono mt-1.5"
                    />
                  </label>
                )}
              </div>
            </div>
          )}

          {isApiKeyProvider && (
            <div className="rounded-lg border border-border bg-bg/40 p-4 grid grid-cols-1 md:grid-cols-2 gap-3.5">
              <div>
                <h3 className="text-[12px] font-medium text-text-mut mb-1.5">
                  Base URL <span className="font-normal text-text-dim">(optional)</span>
                </h3>
                <Input
                  type="url"
                  aria-label="Provider base URL"
                  placeholder={aiProvider === 'anthropic' ? 'https://api.anthropic.com/v1' : aiProvider === 'gemini' ? 'https://generativelanguage.googleapis.com/v1beta' : 'https://api.openai.com/v1'}
                  value={aiBaseUrl}
                  onChange={(e) => useSettingsStore.setState({ aiBaseUrl: e.target.value })}
                  onBlur={() => fetchModels(aiProvider)}
                  className="font-mono"
                />
                <p className="text-[11px] text-text-dim mt-1">Leave blank for the default endpoint, or enter an OpenAI/Anthropic/Gemini-compatible URL.</p>
              </div>
              <div>
                <h3 className="text-[12px] font-medium text-text-mut mb-1.5">API Key</h3>
                <Input
                  type="password"
                  placeholder="Enter API key"
                  value={aiApiKey}
                  onChange={(e) => useSettingsStore.setState({ aiApiKey: e.target.value })}
                />
              </div>
            </div>
          )}
        </div>
      </section>

      <section className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs">
        <div className="px-5 py-3.5 border-b border-border flex items-center justify-between gap-3">
          <h3 className="text-[14px] font-semibold text-text-pri">Model</h3>
          <Button
            variant="outline"
            size="xs"
            icon={<RefreshCw size={12} className={modelsLoading ? 'animate-spin' : ''} />}
            onClick={() => fetchModels(aiProvider)}
            disabled={modelsLoading}
          >
            {modelsLoading ? 'Loading…' : 'Refresh'}
          </Button>
        </div>
        <div className="px-5 py-4 space-y-3">
          {modelsError && (
            <p className="text-[12px] text-danger">{modelsError}</p>
          )}
          {models.length > 0 ? (() => {
            const q = modelSearch.toLowerCase();
            const filteredModels = q
              ? models.filter((m) => m.name.toLowerCase().includes(q) || m.id.toLowerCase().includes(q))
              : models;
            const clampedIdx = filteredModels.length > 0 ? Math.min(modelActiveIdx, filteredModels.length - 1) : 0;
            return (
              <div ref={modelDropdownRef} className="relative">
                <input
                  type="text"
                  role="combobox"
                  aria-expanded={modelDropdownOpen}
                  aria-label="Model"
                  placeholder="Search models…"
                  value={modelDropdownOpen ? modelSearch : models.find((m) => m.id === aiModel)?.name ? `${models.find((m) => m.id === aiModel)!.name} (${aiModel})` : aiModel}
                  onChange={(e) => { setModelSearch(e.target.value); setModelDropdownOpen(true); setModelActiveIdx(0); }}
                  onFocus={() => { setModelSearch(''); setModelDropdownOpen(true); setModelActiveIdx(0); }}
                  onKeyDown={(e) => {
                    if (e.key === 'Escape') {
                      e.stopPropagation();
                      setModelDropdownOpen(false);
                    } else if (e.key === 'ArrowDown') {
                      e.preventDefault();
                      setModelDropdownOpen(true);
                      setModelActiveIdx((prev) => filteredModels.length ? (prev + 1) % filteredModels.length : 0);
                    } else if (e.key === 'ArrowUp') {
                      e.preventDefault();
                      setModelDropdownOpen(true);
                      setModelActiveIdx((prev) => filteredModels.length ? (prev - 1 + filteredModels.length) % filteredModels.length : 0);
                    } else if (e.key === 'Home') {
                      e.preventDefault();
                      setModelActiveIdx(0);
                    } else if (e.key === 'End') {
                      e.preventDefault();
                      setModelActiveIdx(Math.max(0, filteredModels.length - 1));
                    } else if (e.key === 'Enter' && modelDropdownOpen && filteredModels[clampedIdx]) {
                      e.preventDefault();
                      useSettingsStore.setState({ aiModel: filteredModels[clampedIdx].id });
                      setModelDropdownOpen(false);
                      setModelSearch('');
                    }
                  }}
                  onBlur={(e) => {
                    if (modelDropdownRef.current?.contains(e.relatedTarget as Node)) return;
                    setTimeout(() => setModelDropdownOpen(false), 150);
                  }}
                  className="w-full bg-bg border border-border rounded-md text-text-pri text-[13px] h-9 px-3 focus:outline-none focus:border-accent focus:ring-2 focus:ring-[var(--accent-dim)]"
                />
                {modelDropdownOpen && (
                  <div role="listbox" aria-label="Models" className="absolute z-50 mt-1 w-full max-h-60 overflow-y-auto bg-surface border border-border rounded-md shadow-[var(--shadow-elev)]">
                    {filteredModels.length === 0 ? (
                      <div className="px-3 py-2 text-[12px] text-text-dim">No models match "{modelSearch}"</div>
                    ) : filteredModels.map((m, idx) => (
                      <button
                        key={m.id}
                        type="button"
                        role="option"
                        aria-selected={m.id === aiModel}
                        onMouseDown={(e) => e.preventDefault()}
                        onMouseEnter={() => setModelActiveIdx(idx)}
                        onClick={() => {
                          useSettingsStore.setState({ aiModel: m.id });
                          setModelDropdownOpen(false);
                          setModelSearch('');
                        }}
                        className={`w-full text-left px-3 py-2 text-[13px] transition-colors ${m.id === aiModel
                          ? 'bg-[var(--accent-dim)] text-accent'
                          : idx === clampedIdx
                            ? 'bg-surface-hover text-text-pri'
                            : 'text-text-pri hover:bg-surface-hover'
                          }`}
                      >
                        <span className="font-medium">{m.name}</span>
                        <span className="block text-[11px] text-text-dim font-mono">{m.id}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            );
          })() : !modelsLoading ? (
            <Input
              placeholder="Enter model ID manually"
              value={aiModel}
              onChange={(e) => useSettingsStore.setState({ aiModel: e.target.value })}
              className="font-mono"
            />
          ) : null}
          {aiModel && (
            <p className="text-[11px] text-text-dim font-mono break-all">{aiModel}</p>
          )}
        </div>
      </section>
    </div>
  );
}

interface VaultRule {
  id: string;
  type: string;
  value: string;
  label: string;
  priority: number;
}

interface VaultCredential {
  username: string;
  password?: string;
  domain?: string;
  security: string;
}

interface VaultEntry {
  rule: VaultRule;
  credential: VaultCredential;
  created_at: string;
  updated_at: string;
}

const VAULT_RULE_TYPES = [
  { type: 'instance', label: 'This instance only' },
  { type: 'substring', label: 'Name contains (substring)' },
  { type: 'pattern', label: 'Name pattern (glob)' },
  { type: 'environment', label: 'Environment' },
  { type: 'account', label: 'Account' },
  { type: 'global', label: 'All instances' },
] as const;

const VAULT_SECURITY_OPTIONS = [
  { value: 'any', label: 'Auto (any)' },
  { value: 'nla', label: 'NLA' },
  { value: 'tls', label: 'TLS' },
  { value: 'rdp', label: 'RDP' },
] as const;

function VaultTab() {
  const [entries, setEntries] = useState<VaultEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [revealedIds, setRevealedIds] = useState<Set<string>>(new Set());
  const [resolvedPasswords, setResolvedPasswords] = useState<Record<string, string>>({});

  const toggleReveal = useCallback(async (id: string) => {
    setRevealedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
    if (!resolvedPasswords[id]) {
      const res = await api.get<VaultEntry>(`/vault/credentials?resolve=${encodeURIComponent(id)}`);
      if (res.ok && res.data) {
        const pwd = (res.data.credential as unknown as Record<string, string>).password ?? '';
        setResolvedPasswords((prev) => ({ ...prev, [id]: pwd }));
      }
    }
  }, [resolvedPasswords]);

  // Form state shared between add and edit
  const [formLabel, setFormLabel] = useState('');
  const [formRuleType, setFormRuleType] = useState('substring');
  const [formRuleValue, setFormRuleValue] = useState('');
  const [formUsername, setFormUsername] = useState('');
  const [formPassword, setFormPassword] = useState('');
  const [formSecurity, setFormSecurity] = useState('any');

  const resetForm = () => {
    setFormLabel('');
    setFormRuleType('substring');
    setFormRuleValue('');
    setFormUsername('');
    setFormPassword('');
    setFormSecurity('any');
  };

  const loadEntries = useCallback(() => {
    setLoading(true);
    api.get<VaultEntry[]>('/vault/credentials').then((r) => {
      if (r.ok) setEntries(r.data ?? []);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, []);

  useEffect(() => { loadEntries(); }, [loadEntries]);

  const startAdd = () => {
    resetForm();
    setEditingId(null);
    setShowAdd(true);
  };

  const startEdit = (e: VaultEntry) => {
    setFormLabel(e.rule.label);
    setFormRuleType(e.rule.type);
    setFormRuleValue(e.rule.value);
    setFormUsername(e.credential.username);
    setFormPassword('');
    setFormSecurity(e.credential.security || 'any');
    setEditingId(e.rule.id);
    setShowAdd(true);
  };

  const cancelForm = () => {
    resetForm();
    setShowAdd(false);
    setEditingId(null);
  };

  const saveEntry = async () => {
    if (!formRuleValue.trim() || !formUsername.trim()) return;
    if (!editingId && !formPassword) return;

    let password = formPassword;
    if (editingId && !formPassword) {
      // Fetch the existing entry to preserve the stored password
      const existing = await api.get<VaultEntry>(`/vault/credentials?resolve=${encodeURIComponent(editingId)}`);
      if (existing.ok && existing.data) {
        password = (existing.data.credential as unknown as Record<string, string>).password ?? '';
      }
    }

    const payload = {
      rule: {
        id: editingId ?? undefined,
        type: formRuleType,
        value: formRuleValue.trim(),
        label: formLabel.trim() || formRuleValue.trim(),
      },
      credential: {
        username: formUsername.trim(),
        password,
        security: formSecurity,
        domain: '',
      },
    };

    const result = await api.post<{ id: string }>('/vault/credentials', payload);

    if (result.ok) {
      cancelForm();
      loadEntries();
    }
  };

  const deleteEntry = async (id: string) => {
    await api.delete(`/vault/credentials?id=${id}`);
    setEntries((prev) => prev.filter((e) => e.rule.id !== id));
  };

  if (loading) return <div className="text-[12px] text-text-dim">Loading vault...</div>;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4">
        <p className="text-xs text-text-sec">Store RDP credentials encrypted, matched by VM or account rule.</p>
        <Button variant={showAdd ? 'outline' : 'primary'} size="sm" onClick={showAdd ? cancelForm : startAdd}>
          {showAdd ? 'Cancel' : '+ Add credential'}
        </Button>
      </div>

      {showAdd && (
        <div className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs">
          <div className="px-4 py-3 border-b border-border bg-elev/40">
            <h3 className="text-[13px] font-semibold text-text-pri">
              {editingId ? 'Edit vault credential' : 'New vault credential'}
            </h3>
          </div>
          <div className="p-4 space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-[180px_1fr] gap-2.5">
              <Select
                value={formRuleType}
                onChange={(e) => setFormRuleType(e.target.value)}
                aria-label="Match rule type"
                className="text-[13px]"
              >
                {VAULT_RULE_TYPES.map((r) => <option key={r.type} value={r.type}>{r.label}</option>)}
              </Select>
              <Input
                placeholder="Value (e.g. *-prod-*, substring, instance id…)"
                value={formRuleValue}
                onChange={(e) => setFormRuleValue(e.target.value)}
                className="text-[13px]"
              />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <Input placeholder="Label (optional, e.g. Prod Windows)" value={formLabel} onChange={(e) => setFormLabel(e.target.value)} className="text-[13px]" />
              <Input placeholder="Username" value={formUsername} onChange={(e) => setFormUsername(e.target.value)} className="text-[13px]" />
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-[1fr_180px] gap-2.5">
              <Input
                type="password"
                placeholder={editingId ? 'New password (leave blank to keep current)' : 'Password'}
                value={formPassword}
                onChange={(e) => setFormPassword(e.target.value)}
                className="text-[13px]"
              />
              <Select
                value={formSecurity}
                onChange={(e) => setFormSecurity(e.target.value)}
                aria-label="RDP security protocol"
                className="text-[13px]"
              >
                {VAULT_SECURITY_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
              </Select>
            </div>
            <div className="pt-1 flex items-center justify-end gap-2">
              <Button variant="ghost" size="sm" onClick={cancelForm}>Cancel</Button>
              <Button variant="primary" size="sm" onClick={() => void saveEntry()}>
                {editingId ? 'Update credential' : 'Save credential'}
              </Button>
            </div>
          </div>
        </div>
      )}

      {entries.length === 0 ? (
        <div className="rounded-lg border border-border bg-surface px-4 py-8 text-center text-xs text-text-dim">
          No credentials stored in the vault yet.
        </div>
      ) : (
        <div className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs divide-y divide-border">
          {entries.map((e) => (
            <div key={e.rule.id} className="flex items-center gap-3 px-4 py-3 hover:bg-elev/30 transition-colors">
              <Lock size={15} className="text-accent shrink-0" aria-hidden="true" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-[13px] font-semibold text-text-pri truncate">{e.rule.label || e.rule.value}</span>
                  <Badge variant="info">{e.rule.type.toUpperCase()}</Badge>
                </div>
                <div className="text-[11px] text-text-dim font-mono mt-0.5 truncate">{e.rule.value}</div>
                <div className="text-[11px] text-text-sec mt-0.5">
                  {e.credential.username} · Security: {e.credential.security || 'any'}
                </div>
                <div className="flex items-center gap-1.5 mt-1">
                  <span className="text-[11px] font-mono text-text-dim tracking-widest">
                    {revealedIds.has(e.rule.id)
                      ? (resolvedPasswords[e.rule.id] ?? '••••••••')
                      : '••••••••'}
                  </span>
                  <button
                    type="button"
                    onClick={() => void toggleReveal(e.rule.id)}
                    className="text-text-dim hover:text-text-pri transition-colors"
                    aria-label={revealedIds.has(e.rule.id) ? 'Hide password' : 'Show password'}
                  >
                    {revealedIds.has(e.rule.id) ? <EyeOff size={11} /> : <Eye size={11} />}
                  </button>
                </div>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <Button
                  type="button"
                  variant="ghost"
                  size="xs"
                  aria-label="Edit"
                  onClick={() => startEdit(e)}
                >
                  <Pencil size={13} />
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  size="xs"
                  className="text-danger hover:bg-danger/10"
                  onClick={() => void deleteEntry(e.rule.id)}
                  aria-label="Delete"
                >
                  <Trash2 size={13} />
                </Button>
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="rounded-lg border border-border bg-surface px-4 py-3.5 text-xs text-text-sec leading-relaxed">
        <p className="flex items-center gap-1.5 font-medium text-text-pri">
          <Lock size={12} className="text-accent shrink-0" aria-hidden="true" />
          <span>Credentials are encrypted at rest using AES-256-GCM.</span>
        </p>
        <p className="mt-1.5 text-[11px] text-text-dim">
          <strong className="text-text-sec">Match Priority:</strong> Instance → Substring → Name Pattern → Environment → Account → Global
        </p>
      </div>
    </div>
  );
}
