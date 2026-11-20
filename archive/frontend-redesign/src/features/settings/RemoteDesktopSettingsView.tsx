import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  Check,
  Gauge,
  Keyboard,
  Lock,
  Monitor,
  Radio,
  RotateCcw,
  Search,
  ShieldCheck,
  SlidersHorizontal,
  Video,
} from 'lucide-react';
import {
  Badge,
  Button,
  Card,
  Disclosure,
  SegmentedControl,
  Slider,
  Switch,
} from '@/design-system/primitives';
import { filterSections, type ProtocolScope, type SettingsSectionId } from './registry';
import {
  computeLocalSimulation,
  diffSettingsCount,
  NETWORK_PRESET_CARDS,
  type CertPolicy,
  type ClipboardNormalization,
  type CodecMode,
  type ProtocolPreference,
  type RdpSecurityMode,
  type TransportMode,
  type VncSecurityMode,
} from './schema';
import { useSettingsStore } from './store';

export function RemoteDesktopSettingsView({
  onLaunchSession,
}: {
  onLaunchSession: (protocol: 'rdp' | 'vnc') => void;
}) {
  const {
    saved,
    draft,
    capabilities,
    keyboardLayouts,
    telemetrySummary,
    lastTraceId,
    saving,
    simulatedRttMs,
    updateField,
    applyPreset,
    discardDraft,
    saveDraft,
    resetServerDefaults,
    setSimulatedRtt,
  } = useSettingsStore();

  const [search, setSearch] = useState('');
  const [scope, setScope] = useState<ProtocolScope>('all');
  const [layoutSearch, setLayoutSearch] = useState('');
  const [expanded, setExpanded] = useState<Record<SettingsSectionId, boolean>>({
    profiles: true,
    display: true,
    input: false,
    security: false,
    recording: false,
    telemetry: false,
  });

  const searchInputRef = useRef<HTMLInputElement>(null);

  // Keyboard-first `/` quick search inside settings
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

  const visibleSections = useMemo(() => filterSections(search, scope), [search, scope]);
  const isSectionVisible = (id: SettingsSectionId) =>
    visibleSections.some((sec) => sec.id === id);

  const toggleSection = (id: SettingsSectionId) => {
    setExpanded((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  // When searching, auto-open matching sections cleanly
  const effectiveExpanded = (id: SettingsSectionId) => Boolean(search.trim()) || expanded[id];

  const dirtyCount = useMemo(() => diffSettingsCount(saved, draft), [saved, draft]);
  const sim = useMemo(
    () => computeLocalSimulation(draft, simulatedRttMs),
    [draft, simulatedRttMs],
  );

  const filteredLayouts = useMemo(() => {
    const q = layoutSearch.trim().toLowerCase();
    if (!q) return keyboardLayouts;
    return keyboardLayouts.filter(
      (l) =>
        l.label.toLowerCase().includes(q) ||
        l.id.toLowerCase().includes(q) ||
        l.lcid_hex.toLowerCase().includes(q),
    );
  }, [keyboardLayouts, layoutSearch]);

  return (
    <div className="max-w-6xl mx-auto px-6 py-6 pb-28 space-y-6">
      {/* Page Hero & Search Toolbar */}
      <header className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 pb-5 border-b border-border">
        <div className="space-y-1">
          <div className="flex items-center gap-2 flex-wrap">
            <Badge tone="accent">Clean-Room Pure Rust</Badge>
            <Badge tone="neutral">Zero IronRDP</Badge>
            <Badge tone="info" className="tabular-mono">
              trace:{lastTraceId.slice(0, 12)}
            </Badge>
          </div>
          <h1 className="text-[20px] font-semibold tracking-tight text-text-pri">
            Remote Desktop & Protocol Engine Settings
          </h1>
          <p className="text-[13px] text-text-mut max-w-2xl">
            Configure low-latency OQR2 binary streaming, clean-room RDP/VNC handshakes, 25 Windows LCID keyboard mappings, and OpenTelemetry SLO budgets.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <Button variant="outline" size="sm" onClick={() => onLaunchSession('vnc')}>
            Launch VNC Session
          </Button>
          <Button variant="primary" size="sm" onClick={() => onLaunchSession('rdp')}>
            Launch RDP Session
          </Button>
        </div>
      </header>

      {/* Capability Strip (Dynamically populated from Rust /api/v1/protocols) */}
      {capabilities.length > 0 && (
        <section aria-label="Registered backend engines" className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {capabilities.map((cap) => (
            <Card key={cap.protocol} className="px-4 py-3 flex items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-[13px] font-semibold text-text-pri">{cap.display_name}</span>
                  <Badge tone="success">Ready</Badge>
                </div>
                <p className="mt-1 text-xs text-text-dim truncate">
                  Codecs: {cap.codecs.join(' · ')}
                </p>
              </div>
              <span className="tabular-mono text-xs text-text-dim shrink-0">:{cap.default_port}</span>
            </Card>
          ))}
        </section>
      )}

      {/* Search & Scope Filter Toolbar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search
            size={15}
            aria-hidden="true"
            className="absolute left-3 top-1/2 -translate-y-1/2 text-text-dim pointer-events-none"
          />
          <input
            ref={searchInputRef}
            type="search"
            aria-label="Filter settings"
            placeholder="Filter settings, codecs, NLA, LCID, OTel... (press /)"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full h-9 pl-9 pr-3 rounded-[var(--radius-sm)] border border-border bg-surface text-[13px] text-text-pri placeholder:text-text-dim"
          />
        </div>

        <SegmentedControl<ProtocolScope>
          label="Protocol view"
          value={scope}
          onChange={setScope}
          options={[
            { value: 'all', label: 'All Engines' },
            { value: 'rdp', label: 'RDP Only' },
            { value: 'vnc', label: 'VNC Only' },
          ]}
        />
      </div>

      {/* Empty Search Guard */}
      {visibleSections.length === 0 && (
        <Card className="p-8 text-center space-y-2">
          <p className="text-[14px] font-medium text-text-pri">No settings match "{search}"</p>
          <p className="text-xs text-text-dim">Clear the filter or switch to All Engines.</p>
          <div>
            <Button variant="outline" size="sm" onClick={() => { setSearch(''); setScope('all'); }}>
              Clear Filters
            </Button>
          </div>
        </Card>
      )}

      {/* 1. Connection Profiles & Interactive Network Simulator */}
      {isSectionVisible('profiles') && (
        <section aria-label="Connection Profiles and Network Simulator" className="space-y-4">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h2 className="text-[16px] font-semibold text-text-pri flex items-center gap-2">
                <Gauge size={16} aria-hidden="true" className="text-accent" />
                Connection Performance Presets
              </h2>
              <p className="text-xs text-text-mut mt-0.5">
                Start with a goal-based profile; fine-tune individual protocol rules below only if needed.
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
                  <div className="mt-3 flex items-center gap-2 flex-wrap">
                    <Badge tone="neutral">{card.latencyTag}</Badge>
                    <Badge tone="neutral">{card.bandwidthTag}</Badge>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Interactive Latency Behavior Preview Strip */}
          <Card className="p-4 space-y-3" elevated>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-[14px] font-semibold text-text-pri flex items-center gap-2">
                  <Radio size={15} className="text-accent" aria-hidden="true" />
                  Live Pipeline Behavior Preview
                </h3>
                <p className="text-xs text-text-dim">
                  Inspect how your active profile adapts quality, cursor prediction, and frame pacing across links.
                </p>
              </div>
              <div className="flex items-center gap-1.5" role="group" aria-label="Simulate network condition">
                {([15, 120, 280] as const).map((rtt) => (
                  <Button
                    key={rtt}
                    variant={simulatedRttMs === rtt ? 'primary' : 'outline'}
                    size="xs"
                    onClick={() => setSimulatedRtt(rtt)}
                  >
                    {rtt === 15 ? '15 ms LAN' : rtt === 120 ? '120 ms WAN' : '280 ms SSM'}
                  </Button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 pt-1">
              <div className="rounded-[var(--radius-md)] border border-border bg-bg p-3">
                <div className="text-[11px] uppercase tracking-wider text-text-dim font-medium">JPEG Quality</div>
                <div className="mt-1 tabular-mono text-[16px] font-semibold text-text-pri">
                  {sim.effective_jpeg_quality}%
                </div>
                <div className="text-[11px] text-text-dim">Floor {draft.jpeg_quality_floor}%</div>
              </div>
              <div className="rounded-[var(--radius-md)] border border-border bg-bg p-3">
                <div className="text-[11px] uppercase tracking-wider text-text-dim font-medium">Cursor Mode</div>
                <div className="mt-1 text-[13px] font-semibold text-accent">
                  {sim.cursor_mode === 'zero_rtt_local' ? 'Zero-RTT Local' : 'Server Roundtrip'}
                </div>
                <div className="tabular-mono text-[11px] text-text-dim">
                  ~{sim.estimated_glass_latency_ms} ms perceived
                </div>
              </div>
              <div className="rounded-[var(--radius-md)] border border-border bg-bg p-3">
                <div className="text-[11px] uppercase tracking-wider text-text-dim font-medium">FPS / Sync Budget</div>
                <div className="mt-1 tabular-mono text-[16px] font-semibold text-text-pri">
                  {sim.effective_fps_cap} FPS
                </div>
                <div className="text-[11px] text-text-dim">Max {sim.max_in_flight_sync} unacked</div>
              </div>
              <div className="rounded-[var(--radius-md)] border border-border bg-bg p-3">
                <div className="text-[11px] uppercase tracking-wider text-text-dim font-medium">Congestion Policy</div>
                <div className="mt-1 text-[13px] font-semibold text-text-pri">
                  {sim.drops_stale_frames ? 'Coalesce Stale' : 'Render All'}
                </div>
                <div className="text-[11px] text-text-dim truncate" title={sim.active_codec_summary}>
                  {sim.active_codec_summary}
                </div>
              </div>
            </div>
          </Card>
        </section>
      )}

      {/* 2. Display & Adaptive Codec */}
      {isSectionVisible('display') && (
        <Disclosure
          title="Display Pipeline & Adaptive Codecs"
          subtitle="Wire framing (`OQR2` binary vs `Guacamole` compat), FPS targets, and 64x64 CopyRect scroll acceleration"
          badge={<Badge tone="info">{draft.transport_mode === 'oqr2_binary' ? 'OQR2 Binary' : 'Guacamole Compat'}</Badge>}
          expanded={effectiveExpanded('display')}
          onToggle={() => toggleSection('display')}
        >
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <SegmentedControl<TransportMode>
              label="Browser Wire Transport"
              value={draft.transport_mode}
              onChange={(v) => updateField('transport_mode', v)}
              options={[
                { value: 'oqr2_binary', label: 'OQR2 Binary (Fastest)' },
                { value: 'guacamole_compat', label: 'Guacamole Compat' },
              ]}
            />

            <SegmentedControl<CodecMode>
              label="Frame Encoder Heuristic"
              value={draft.codec_mode}
              onChange={(v) => updateField('codec_mode', v)}
              options={[
                { value: 'adaptive_hybrid', label: 'Adaptive Hybrid' },
                { value: 'lossless_crisp', label: 'Lossless Crisp' },
                { value: 'motion_priority', label: 'Motion Priority' },
              ]}
            />

            <SegmentedControl<ProtocolPreference>
              label="Default Desktop Protocol"
              value={draft.protocol_preference}
              onChange={(v) => updateField('protocol_preference', v)}
              options={[
                { value: 'auto', label: 'Auto Detect' },
                { value: 'rdp', label: 'Microsoft RDP' },
                { value: 'vnc', label: 'VNC / RFB' },
              ]}
            />

            <div className="space-y-1">
              <Slider
                label="Target Frame Cadence (FPS)"
                min={10}
                max={60}
                value={draft.target_fps}
                unit=" fps"
                onChange={(v) => updateField('target_fps', v)}
              />
              <Slider
                label="JPEG Quality Floor"
                description="Minimum JPEG quality enforced even under severe WAN congestion."
                min={20}
                max={95}
                value={draft.jpeg_quality_floor}
                unit="%"
                onChange={(v) => updateField('jpeg_quality_floor', v)}
              />
            </div>
          </div>

          <div className="border-t border-border pt-3 divide-y divide-border">
            <Switch
              label="64x64 Rolling-Hash CopyRect Scroll Acceleration"
              description="Detects moved terminal and browser blocks from previous frameBuffer hashes instead of re-encoding pixels."
              checked={draft.enable_copy_rect}
              onChange={(v) => updateField('enable_copy_rect', v)}
            />
            <Switch
              label="Dynamic Desktop Resize (MS-RDPEDISP / SetDesktopSize)"
              description="Automatically snaps viewport dimensions to [200, 8192] with even pixel widths on window resize."
              checked={draft.enable_dynamic_resize}
              onChange={(v) => updateField('enable_dynamic_resize', v)}
            />
          </div>
        </Disclosure>
      )}

      {/* 3. Input & 25-LCID Keyboard Engine */}
      {isSectionVisible('input') && (
        <Disclosure
          title="Input Prediction & 25-LCID Keyboard Engine"
          subtitle="Zero-RTT client pointer rendering and exact Windows scan-code + Unicode fallback mapping"
          badge={<Badge tone="neutral" className="tabular-mono">{draft.keyboard_layout}</Badge>}
          expanded={effectiveExpanded('input')}
          onToggle={() => toggleSection('input')}
        >
          <div className="divide-y divide-border">
            <Switch
              label="Zero-RTT Local Cursor Prediction"
              description="Updates browser cursor overlay immediately on mouse move instead of waiting for server round-trip frames."
              checked={draft.enable_local_cursor_prediction}
              onChange={(v) => updateField('enable_local_cursor_prediction', v)}
            />
            <Switch
              label="Mouse Move Event Coalescing"
              description="Collapses high-frequency pointer bursts per frame interval to avoid input buffer bloat on constrained WAN links."
              checked={draft.enable_mouse_coalescing}
              onChange={(v) => updateField('enable_mouse_coalescing', v)}
            />
            <Switch
              label="Fast-Path Unicode & Dead-Key Fallback"
              description="Forwards non-ASCII/IME characters via Fast-Path Unicode events when absent from the host LCID layout."
              checked={draft.unicode_fallback}
              onChange={(v) => updateField('unicode_fallback', v)}
            />
          </div>

          <div className="pt-2 space-y-2">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <label htmlFor="keyboard-layout-select" className="text-[13px] font-medium text-text-pri flex items-center gap-1.5">
                <Keyboard size={14} aria-hidden="true" className="text-accent" />
                Server Keyboard Layout (25 Windows LCID Maps)
              </label>
              <input
                type="search"
                aria-label="Search keyboard layouts"
                placeholder="Search LCID or country..."
                value={layoutSearch}
                onChange={(e) => setLayoutSearch(e.target.value)}
                className="h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-bg text-xs text-text-pri placeholder:text-text-dim"
              />
            </div>
            <select
              id="keyboard-layout-select"
              value={draft.keyboard_layout}
              onChange={(e) => updateField('keyboard_layout', e.target.value)}
              className="w-full h-9 px-3 rounded-[var(--radius-sm)] border border-border bg-bg text-[13px] text-text-pri"
            >
              {filteredLayouts.map((kl) => (
                <option key={kl.id} value={kl.id}>
                  {kl.label} [{kl.lcid_hex} · {kl.id}]
                </option>
              ))}
            </select>
          </div>
        </Disclosure>
      )}

      {/* 4. Authentication & Certificates */}
      {isSectionVisible('security') && (
        <Disclosure
          title="Authentication & Certificate Verification"
          subtitle="Clean-room CredSSP NLA (`HYBRID` / `HYBRID_EX`), VNC Security, and TOFU SHA-256 certificate pinning"
          badge={<Badge tone="success"><Lock size={11} aria-hidden="true" /> ZeroizeOnDrop</Badge>}
          expanded={effectiveExpanded('security')}
          onToggle={() => toggleSection('security')}
        >
          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label htmlFor="rdp-security-select" className="block text-[13px] font-medium text-text-pri">
                RDP Negotiation Mode
              </label>
              <select
                id="rdp-security-select"
                value={draft.rdp_security_mode}
                onChange={(e) => updateField('rdp_security_mode', e.target.value as RdpSecurityMode)}
                className="w-full h-9 px-3 rounded-[var(--radius-sm)] border border-border bg-bg text-[13px] text-text-pri"
              >
                <option value="any">Auto Negotiate (NLA-Ext / NLA / TLS / Classic)</option>
                <option value="nla_ext">CredSSP Extended NLA (HYBRID_EX / Entra ID)</option>
                <option value="nla">CredSSP NLA (HYBRID)</option>
                <option value="tls">TLS Only (No NLA)</option>
                <option value="classic_rdp">Classic RDP Security (xrdp legacy)</option>
                <option value="vmconnect">Hyper-V VMConnect Preconnection</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="vnc-security-select" className="block text-[13px] font-medium text-text-pri">
                VNC / RFB Security Mode
              </label>
              <select
                id="vnc-security-select"
                value={draft.vnc_security_mode}
                onChange={(e) => updateField('vnc_security_mode', e.target.value as VncSecurityMode)}
                className="w-full h-9 px-3 rounded-[var(--radius-sm)] border border-border bg-bg text-[13px] text-text-pri"
              >
                <option value="auto">Auto Negotiate (VeNCrypt TLS / DES VNCAuth)</option>
                <option value="ve_ncrypt_tls">Require VeNCrypt TLS</option>
                <option value="vnc_auth">Standard RFB VNCAuth (DES Challenge)</option>
                <option value="none">None (Encrypted Tunnel Only)</option>
              </select>
            </div>
          </div>

          <SegmentedControl<CertPolicy>
            label="TLS Certificate Verification Policy"
            value={draft.cert_policy}
            onChange={(v) => updateField('cert_policy', v)}
            options={[
              { value: 'tofu_pinned', label: 'TOFU SHA-256 Pinned' },
              { value: 'strict_ca', label: 'Strict Enterprise CA' },
              { value: 'ssm_loopback_ignore', label: 'SSM Loopback Only' },
            ]}
          />
          {draft.cert_policy === 'ssm_loopback_ignore' && (
            <div role="alert" className="rounded-[var(--radius-md)] border border-border bg-[var(--warn-dim)] px-3.5 py-2.5 text-xs text-warn flex items-center gap-2">
              <ShieldCheck size={15} className="shrink-0" aria-hidden="true" />
              Server certificate verification bypass is restricted to authenticated AWS SSM encrypted tunnels (`RULES.md` §3.2).
            </div>
          )}
        </Disclosure>
      )}

      {/* 5. Clipboard, Fail-Closed Recording & Compliance */}
      {isSectionVisible('recording') && (
        <Disclosure
          title="Clipboard, Fail-Closed Recording & Compliance"
          subtitle="Deterministic audit stream capture and host isolation policies"
          badge={
            draft.fail_closed_recording ? (
              <Badge tone="success">Fail-Closed Enforced</Badge>
            ) : (
              <Badge tone="danger">Recording Optional</Badge>
            )
          }
          expanded={effectiveExpanded('recording')}
          onToggle={() => toggleSection('recording')}
        >
          <SegmentedControl<ClipboardNormalization>
            label="Clipboard Line-Ending Normalization"
            value={draft.clipboard_normalization}
            onChange={(v) => updateField('clipboard_normalization', v)}
            options={[
              { value: 'preserve', label: 'Preserve Original' },
              { value: 'windows_crlf', label: 'Windows CRLF (\\r\\n)' },
              { value: 'unix_lf', label: 'Unix LF (\\n)' },
            ]}
          />

          <div className="divide-y divide-border pt-2">
            <Switch
              label="Fail-Closed Session Recording"
              description="Aborts session startup cleanly if audit writer fails, fixing the Go/guacd production RDP blocker."
              checked={draft.fail_closed_recording}
              onChange={(v) => updateField('fail_closed_recording', v)}
            />
            <Switch
              label="Enable RDP Drive Redirection (RDPDR)"
              description="Disabled by default; prefer audited AWS S3/SSM transfers over host filesystem shares."
              checked={draft.enable_drive_redirection}
              onChange={(v) => updateField('enable_drive_redirection', v)}
            />
          </div>
        </Disclosure>
      )}

      {/* 6. OpenTelemetry & Diagnostics */}
      {isSectionVisible('telemetry') && (
        <Disclosure
          title="OpenTelemetry & Transport Diagnostics"
          subtitle="W3C traceparent correlation, Prometheus /metrics counters, and browser telemetry overlay"
          badge={
            <Badge tone="info" className="tabular-mono">
              <Activity size={11} aria-hidden="true" />
              {telemetrySummary ? `${telemetrySummary.frames_encoded_total} frames` : 'OTel Ready'}
            </Badge>
          }
          expanded={effectiveExpanded('telemetry')}
          onToggle={() => toggleSection('telemetry')}
        >
          <Slider
            label="Distributed Trace Sample Ratio"
            min={0}
            max={100}
            step={5}
            value={Math.round(draft.otel_sample_ratio * 100)}
            unit="%"
            onChange={(pct) => updateField('otel_sample_ratio', Number((pct / 100).toFixed(2)))}
          />

          <Switch
            label="Show Live Telemetry HUD Inside Desktop Viewport"
            description="Renders real-time RTT, FPS, active codec tag, and OpenTelemetry Trace ID badge over sessions."
            checked={draft.show_live_telemetry_hud}
            onChange={(v) => updateField('show_live_telemetry_hud', v)}
          />

          {telemetrySummary && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
              <div className="rounded-[var(--radius-md)] border border-border bg-bg p-3">
                <div className="text-[11px] text-text-dim uppercase">Active Sessions</div>
                <div className="mt-1 tabular-mono text-[15px] font-semibold text-text-pri">
                  {telemetrySummary.active_sessions}
                </div>
              </div>
              <div className="rounded-[var(--radius-md)] border border-border bg-bg p-3">
                <div className="text-[11px] text-text-dim uppercase">Frames Encoded</div>
                <div className="mt-1 tabular-mono text-[15px] font-semibold text-text-pri">
                  {telemetrySummary.frames_encoded_total}
                </div>
              </div>
              <div className="rounded-[var(--radius-md)] border border-border bg-bg p-3">
                <div className="text-[11px] text-text-dim uppercase">Frames Dropped</div>
                <div className="mt-1 tabular-mono text-[15px] font-semibold text-text-pri">
                  {telemetrySummary.frames_dropped_total}
                </div>
              </div>
              <div className="rounded-[var(--radius-md)] border border-border bg-bg p-3">
                <div className="text-[11px] text-text-dim uppercase">Settings Saves</div>
                <div className="mt-1 tabular-mono text-[15px] font-semibold text-text-pri">
                  {telemetrySummary.settings_updates_total}
                </div>
              </div>
            </div>
          )}
        </Disclosure>
      )}

      {/* Footer Quick Utilities */}
      <footer className="flex items-center justify-between gap-4 pt-3 border-t border-border text-xs text-text-dim">
        <span className="flex items-center gap-1.5">
          <SlidersHorizontal size={13} aria-hidden="true" />
          OpenTelemetry Prometheus Endpoint: <a href="/metrics" target="_blank" rel="noreferrer" className="text-accent underline tabular-mono">/metrics</a>
        </span>
        <Button variant="ghost" size="xs" onClick={resetServerDefaults} icon={<RotateCcw size={13} aria-hidden="true" />}>
          Reset Server Defaults
        </Button>
      </footer>

      {/* Sticky Contextual Unsaved Changes Bar (Appears strictly when dirty!) */}
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

      {/* Visual placeholder reference anchor */}
      <span className="sr-only">
        <Monitor size={12} /> <Video size={12} />
      </span>
    </div>
  );
}

