import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Check,
  Gauge,
  Keyboard,
  Lock,
  RotateCcw,
  Search,
  SlidersHorizontal,
} from 'lucide-react';
import {
  Badge,
  Button,
  Disclosure,
  SegmentedControl,
  Slider,
  Switch,
} from '@/rust-engines/design-system/primitives';
import {
  DEFAULT_KEYBOARD_LAYOUTS,
  diffSettingsCount,
  NETWORK_PRESET_CARDS,
  type CertPolicy,
  type ClipboardNormalization,
  type ProtocolPreference,
  type RdpSecurityMode,
  type VncSecurityMode,
} from './schema';
import { useSettingsStore } from './store';

export function RemoteDesktopSettingsView({
  onLaunchSession: _onLaunchSession,
}: {
  onLaunchSession?: (protocol: 'rdp' | 'vnc') => void;
}) {
  const {
    saved,
    draft,
    keyboardLayouts,
    saving,
    updateField,
    applyPreset,
    discardDraft,
    saveDraft,
    resetServerDefaults,
  } = useSettingsStore();

  const [search, setSearch] = useState('');
  const [layoutSearch, setLayoutSearch] = useState('');
  const [advancedOpen, setAdvancedOpen] = useState(false);

  const searchInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (
        e.key === '/' &&
        !(e.target instanceof HTMLInputElement) &&
        !(e.target instanceof HTMLTextAreaElement) &&
        !(e.target instanceof HTMLSelectElement)
      ) {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const dirtyCount = useMemo(() => diffSettingsCount(saved, draft), [saved, draft]);

  const effectiveLayouts = keyboardLayouts.length > 0 ? keyboardLayouts : DEFAULT_KEYBOARD_LAYOUTS;
  const filteredLayouts = useMemo(() => {
    const q = layoutSearch.trim().toLowerCase();
    if (!q) return effectiveLayouts;
    return effectiveLayouts.filter(
      (l) =>
        l.label.toLowerCase().includes(q) ||
        l.id.toLowerCase().includes(q) ||
        l.lcid_hex.toLowerCase().includes(q),
    );
  }, [effectiveLayouts, layoutSearch]);

  const q = search.trim().toLowerCase();
  const matches = (keywords: string) => !q || keywords.toLowerCase().includes(q);
  const showPresets = matches('preset profile latency wan lan ssm auto adaptive low balanced constrained');
  const showDisplayInput = matches('keyboard layout resize fit window clipboard hud display input');
  const showSecurity = matches('security nla tls certificate rdp tofu');
  const showAdvanced = matches('fps jpeg copyrect cursor prediction unicode vnc recording drive');

  return (
    <div className="max-w-5xl mx-auto px-6 py-6 pb-28 space-y-6">
      <header className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 pb-4 border-b border-border">
        <div className="space-y-1">
          <h1 className="text-[20px] font-semibold tracking-tight text-text-pri">
            Remote Desktop Settings
          </h1>
          <p className="text-[13px] text-text-mut max-w-2xl">
            Configure performance profiles, display sizing, keyboard layout defaults, and RDP security policy.
          </p>
        </div>

        <div className="relative w-full sm:w-72">
          <Search
            size={15}
            aria-hidden="true"
            className="absolute left-3 top-1/2 -translate-y-1/2 text-text-dim pointer-events-none"
          />
          <input
            ref={searchInputRef}
            type="search"
            aria-label="Filter settings"
            placeholder="Filter settings… (press /)"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full h-9 pl-9 pr-3 rounded-[var(--radius-sm)] border border-border bg-surface text-[13px] text-text-pri placeholder:text-text-dim"
          />
        </div>
      </header>

      {!showPresets && !showDisplayInput && !showSecurity && !showAdvanced && (
        <div className="rounded-[var(--radius-lg)] border border-border bg-surface p-8 text-center space-y-2">
          <p className="text-[14px] font-medium text-text-pri">No settings match "{search}"</p>
          <Button variant="outline" size="sm" onClick={() => setSearch('')}>
            Clear Filter
          </Button>
        </div>
      )}

      {showPresets && (
        <section aria-label="Connection performance presets" className="space-y-3">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h2 className="text-[15px] font-semibold text-text-pri flex items-center gap-2">
                <Gauge size={16} aria-hidden="true" className="text-accent" />
                Performance Presets
              </h2>
              <p className="text-xs text-text-mut mt-0.5">
                Pick a connection profile matched to your network path.
              </p>
            </div>
            {draft.network_preset === 'custom' && <Badge tone="warn">Custom Override</Badge>}
          </div>

          <div role="radiogroup" aria-label="Connection profile preset" className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {NETWORK_PRESET_CARDS.map((card) => {
              const selected = draft.network_preset === card.id;
              return (
                <button
                  key={card.id}
                  type="button"
                  role="radio"
                  aria-checked={selected}
                  onClick={() => applyPreset(card.id)}
                  className={[
                    'text-left p-4 rounded-[var(--radius-lg)] border transition-colors',
                    selected
                      ? 'bg-[var(--accent-dim)] border-[var(--accent-border)]'
                      : 'bg-surface border-border hover:bg-surface-hover',
                  ].join(' ')}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[14px] font-semibold text-text-pri flex items-center gap-2">
                      {card.title}
                      {card.recommended && <Badge tone="accent">Recommended</Badge>}
                    </span>
                    {selected && <Check size={16} className="text-accent shrink-0" aria-hidden="true" />}
                  </div>
                  <p className="mt-1.5 text-xs text-text-mut leading-relaxed">{card.summary}</p>
                </button>
              );
            })}
          </div>
        </section>
      )}

      {showDisplayInput && (
        <Disclosure
          title="Display & Input"
          subtitle="Default keyboard layout (also switchable live inside any open RDP tab), window fit, and clipboard"
          badge={<Keyboard size={12} aria-hidden="true" />}
          expanded
          onToggle={() => undefined}
        >
          <div className="space-y-4">
            <div className="space-y-2">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <label htmlFor="rdp-default-kbd-layout" className="text-[13px] font-medium text-text-pri">
                  Default Keyboard Layout
                </label>
                <input
                  type="search"
                  aria-label="Search keyboard layouts"
                  placeholder="Search 25 layouts (US, UK, DE, FR, JP)..."
                  value={layoutSearch}
                  onChange={(e) => setLayoutSearch(e.target.value)}
                  className="h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-bg text-xs text-text-pri sm:w-64"
                />
              </div>
              <select
                id="rdp-default-kbd-layout"
                value={draft.keyboard_layout}
                onChange={(e) => updateField('keyboard_layout', e.target.value)}
                className="w-full h-9 px-3 rounded-[var(--radius-sm)] border border-border bg-surface text-[13px] text-text-pri"
              >
                {filteredLayouts.map((l) => (
                  <option key={l.id} value={l.id}>
                    {l.label} ({l.lcid_hex})
                  </option>
                ))}
              </select>
              <p className="text-[11px] text-text-dim">
                You can also switch keyboard layouts mid-session directly from the active RDP tab toolbar.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <SegmentedControl<ClipboardNormalization>
                label="Clipboard Line Endings"
                value={draft.clipboard_normalization}
                onChange={(v) => updateField('clipboard_normalization', v)}
                options={[
                  { value: 'preserve', label: 'Preserve' },
                  { value: 'windows_crlf', label: 'Windows CRLF' },
                  { value: 'unix_lf', label: 'Unix LF' },
                ]}
              />
            </div>

            <Switch
              label="Dynamic Window Fit"
              description="Automatically resize the Windows desktop to fill the session tab whenever the window is resized."
              checked={draft.enable_dynamic_resize}
              onChange={(v) => updateField('enable_dynamic_resize', v)}
            />

            <Switch
              label="Show Live Telemetry HUD"
              description="Display session latency and frame rate status in the desktop stage footer when running standalone."
              checked={draft.show_live_telemetry_hud}
              onChange={(v) => updateField('show_live_telemetry_hud', v)}
            />
          </div>
        </Disclosure>
      )}

      {showSecurity && (
        <Disclosure
          title="Security"
          subtitle="RDP transport negotiation and TLS certificate verification policy"
          badge={<Lock size={12} aria-hidden="true" />}
          expanded
          onToggle={() => undefined}
        >
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label htmlFor="rdp-security-mode" className="block text-[13px] font-medium text-text-pri">
                RDP Security Mode
              </label>
              <select
                id="rdp-security-mode"
                value={draft.rdp_security_mode}
                onChange={(e) => updateField('rdp_security_mode', e.target.value as RdpSecurityMode)}
                className="w-full h-9 px-3 rounded-[var(--radius-sm)] border border-border bg-surface text-[13px] text-text-pri"
              >
                <option value="any">Auto Negotiate (NLA / TLS / Classic)</option>
                <option value="nla">NLA / CredSSP</option>
                <option value="tls">TLS Only</option>
                <option value="classic_rdp">Standard RDP Security</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="rdp-cert-policy" className="block text-[13px] font-medium text-text-pri">
                TLS Certificate Policy
              </label>
              <select
                id="rdp-cert-policy"
                value={draft.cert_policy}
                onChange={(e) => updateField('cert_policy', e.target.value as CertPolicy)}
                className="w-full h-9 px-3 rounded-[var(--radius-sm)] border border-border bg-surface text-[13px] text-text-pri"
              >
                <option value="tofu_pinned">Trust On First Use (SHA-256 Pinned)</option>
                <option value="strict_ca">Strict CA Verification</option>
                <option value="ssm_loopback_ignore">SSM Loopback Skip Cert Hostname</option>
              </select>
            </div>
          </div>
        </Disclosure>
      )}

      {showAdvanced && (
        <Disclosure
          title="Advanced Tuning"
          subtitle="Frame rate cap, minimum JPEG quality, scroll acceleration, and fallback options"
          badge={<SlidersHorizontal size={12} aria-hidden="true" />}
          expanded={Boolean(q) || advancedOpen}
          onToggle={() => setAdvancedOpen((v) => !v)}
        >
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <Slider
                label="Target Frame Cadence (FPS)"
                min={10}
                max={60}
                step={5}
                value={draft.target_fps}
                unit=" fps"
                onChange={(v) => updateField('target_fps', v)}
              />
              <Slider
                label="JPEG Quality Floor"
                min={20}
                max={95}
                step={5}
                value={draft.jpeg_quality_floor}
                unit="%"
                onChange={(v) => updateField('jpeg_quality_floor', v)}
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              <SegmentedControl<ProtocolPreference>
                label="Default Desktop Protocol"
                value={draft.protocol_preference}
                onChange={(v) => updateField('protocol_preference', v)}
                options={[
                  { value: 'auto', label: 'Auto' },
                  { value: 'rdp', label: 'RDP' },
                  { value: 'vnc', label: 'VNC' },
                ]}
              />

              <div className="space-y-1.5">
                <label htmlFor="vnc-security-mode" className="block text-[13px] font-medium text-text-pri">
                  VNC Authentication Mode
                </label>
                <select
                  id="vnc-security-mode"
                  value={draft.vnc_security_mode}
                  onChange={(e) => updateField('vnc_security_mode', e.target.value as VncSecurityMode)}
                  className="w-full h-9 px-3 rounded-[var(--radius-sm)] border border-border bg-surface text-[13px] text-text-pri"
                >
                  <option value="auto">Auto</option>
                  <option value="ve_ncrypt_tls">VeNCrypt TLS</option>
                  <option value="vnc_auth">VNC DES Auth</option>
                </select>
              </div>
            </div>

            <Switch
              label="CopyRect Scroll Acceleration"
              description="Reuses unchanged desktop blocks during scrolling to lower bandwidth usage."
              checked={draft.enable_copy_rect}
              onChange={(v) => updateField('enable_copy_rect', v)}
            />

            <Switch
              label="Local Hardware Cursor"
              description="Renders the native client pointer locally for zero-lag cursor response."
              checked={draft.enable_local_cursor_prediction}
              onChange={(v) => updateField('enable_local_cursor_prediction', v)}
            />

            <Switch
              label="Unicode Keystroke Fallback"
              description="Sends non-ASCII characters as Fast-Path Unicode events when absent from the host LCID map."
              checked={draft.unicode_fallback}
              onChange={(v) => updateField('unicode_fallback', v)}
            />
          </div>
        </Disclosure>
      )}

      <footer className="flex items-center justify-end gap-4 pt-3 border-t border-border">
        <Button variant="ghost" size="xs" onClick={resetServerDefaults} icon={<RotateCcw size={13} aria-hidden="true" />}>
          Reset Server Defaults
        </Button>
      </footer>

      {dirtyCount > 0 && (
        <div
          role="region"
          aria-label="Unsaved settings changes"
          className="fixed bottom-4 left-1/2 -translate-x-1/2 z-40 w-[min(94vw,680px)] rounded-[var(--radius-lg)] border border-[var(--accent-border)] bg-surface px-4 py-3 shadow-[var(--shadow-elev)] flex items-center justify-between gap-4"
        >
          <div className="flex items-center gap-2.5 min-w-0">
            <Badge tone="accent" className="tabular-mono">
              {dirtyCount} unsaved
            </Badge>
            <span className="text-[13px] font-medium text-text-pri truncate">
              Changes will apply to subsequent RDP & VNC sessions.
            </span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Button variant="outline" size="sm" onClick={discardDraft} disabled={saving}>
              Discard
            </Button>
            <Button variant="primary" size="sm" loading={saving} onClick={saveDraft}>
              Save Profile
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
