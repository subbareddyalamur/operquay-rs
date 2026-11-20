import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { RemoteDesktopSettingsView } from './RemoteDesktopSettingsView';
import { DEFAULT_SETTINGS, computeLocalSimulation, diffSettingsCount } from './schema';
import { filterSections } from './registry';
import { useSettingsStore } from './store';
import { decodeOqr2Frame } from '../desktop/oqr2Decoder';

describe('Remote Desktop Settings & OQR2 Codec', () => {
  beforeEach(() => {
    useSettingsStore.setState({
      saved: DEFAULT_SETTINGS,
      draft: DEFAULT_SETTINGS,
      capabilities: [],
      keyboardLayouts: [
        { id: 'en-us-qwerty', label: 'English (US QWERTY)', lcid_hex: '0x0409', lcid: 0x0409 },
        { id: 'de-de-qwertz', label: 'German (Germany QWERTZ)', lcid_hex: '0x0407', lcid: 0x0407 },
      ],
      telemetrySummary: null,
      simulatedRttMs: 120,
      toast: null,
    });
  });

  it('computes Guacamole lag-adaptive quality matching Rust engine bounds', () => {
    const lan = computeLocalSimulation(DEFAULT_SETTINGS, 15);
    expect(lan.effective_jpeg_quality).toBe(90);
    expect(lan.cursor_mode).toBe('zero_rtt_local');

    const wan = computeLocalSimulation(DEFAULT_SETTINGS, 280);
    expect(wan.effective_jpeg_quality).toBe(55); // clamped by quality floor 55
    expect(wan.drops_stale_frames).toBe(true);
    expect(wan.effective_fps_cap).toBe(20);
  });

  it('filters registry sections declaratively by search keyword and protocol scope', () => {
    expect(filterSections('lcid', 'all').map((s) => s.id)).toEqual(['input']);
    expect(filterSections('', 'vnc').some((s) => s.id === 'input')).toBe(false);
    expect(filterSections('opentelemetry', 'all').map((s) => s.id)).toEqual(['telemetry']);
  });

  it('renders goal presets, updates live latency simulator, and surfaces dirty bar on edit', () => {
    const onLaunch = vi.fn();
    render(<RemoteDesktopSettingsView onLaunchSession={onLaunch} />);

    expect(screen.queryByRole('region', { name: 'Unsaved settings changes' })).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('radio', { name: /Ultra-Low Latency LAN/ }));
    expect(diffSettingsCount(DEFAULT_SETTINGS, useSettingsStore.getState().draft)).toBeGreaterThan(0);
    expect(screen.getByRole('region', { name: 'Unsaved settings changes' })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: '280 ms SSM' }));
    expect(screen.getByText('95%')).toBeInTheDocument();
  });

  it('decodes OQR2 SolidFill binary wire frames cleanly', () => {
    // magic "OQR2" + opcode 0x04 + seq=7 + layer=0 + x=10,y=20,w=100,h=50 + rgba=[63,184,175,255]
    const buf = new ArrayBuffer(25);
    const dv = new DataView(buf);
    const bytes = new Uint8Array(buf);
    bytes.set([0x4f, 0x51, 0x52, 0x32], 0);
    dv.setUint8(4, 0x04);
    dv.setUint32(5, 7, true);
    dv.setInt32(9, 0, true);
    dv.setUint16(13, 10, true);
    dv.setUint16(15, 20, true);
    dv.setUint16(17, 100, true);
    dv.setUint16(19, 50, true);
    bytes.set([63, 184, 175, 255], 21);

    const decoded = decodeOqr2Frame(buf);
    expect(decoded).toEqual({
      type: 'solid_fill',
      seq: 7,
      layer: 0,
      x: 10,
      y: 20,
      w: 100,
      h: 50,
      rgba: [63, 184, 175, 255],
    });
  });

  it('mints single-use launch tickets and wipes password from browser dialog state immediately', async () => {
    const { SessionLauncherDialog } = await import('../sessions/SessionLauncherDialog');
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        ticket: '11111111-2222-3333-4444-555555555555',
        session_id: 'sess-123',
        ws_url: '/api/v1/ws/rdp?ticket=11111111-2222-3333-4444-555555555555',
        protocol: 'rdp',
        launch_mode: 'direct_tcp',
        expires_in_secs: 60,
        trace_id: 'abcdef1234',
      }),
    });
    vi.stubGlobal('fetch', fetchMock);

    const onLaunched = vi.fn();
    const onClose = vi.fn();
    render(
      <SessionLauncherDialog
        open={true}
        defaultLayout="en-us-qwerty"
        onClose={onClose}
        onLaunched={onLaunched}
      />,
    );

    fireEvent.click(screen.getByRole('radio', { name: 'Direct TCP' }));
    const passInput = screen.getByLabelText('Password (Ephemeral Zeroize)') as HTMLInputElement;
    fireEvent.change(passInput, { target: { value: 'SecretPass!42' } });
    fireEvent.click(screen.getByRole('button', { name: /Mint Ticket & Connect/ }));

    expect(passInput.value).toBe('');
    await vi.waitFor(() => {
      expect(onLaunched).toHaveBeenCalledWith(
        expect.objectContaining({
          protocol: 'rdp',
          launchMode: 'direct_tcp',
          wsUrl: '/api/v1/ws/rdp?ticket=11111111-2222-3333-4444-555555555555',
        }),
      );
    });
    expect(onLaunched.mock.calls[0][0].wsUrl).not.toContain('SecretPass');
    vi.unstubAllGlobals();
  });

  it('renders recordings catalog with SHA-256 checksums, MP4 export link, and audit events', async () => {
    const { AuditRecordingsView } = await import('../audit/AuditRecordingsView');
    const fetchMock = vi.fn(async (url: string) => {
      if (url === '/api/v1/recordings') {
        return {
          ok: true,
          json: async () => ({
            recordings: [
              {
                id: 'rec-abc-123456',
                tenant_id: 'default',
                protocol: 'rdp',
                target_host: 'win-01.corp',
                format: 'guac',
                started_at_ms: 1700000000000,
                bytes_written: 4096,
                frame_count: 18,
                sha256_hex: 'deadbeef0123456789abcdef',
                fail_closed: true,
                status: 'completed',
              },
            ],
          }),
        };
      }
      return {
        ok: true,
        json: async () => ({
          events: [
            {
              id: 'ev-1',
              ts_ms: 1700000000100,
              tenant_id: 'default',
              trace_id: '0123456789abcdef0123456789abcdef',
              session_id: 'rec-abc-123456',
              action: 'session_closed',
              protocol: 'rdp',
              target_host: 'win-01.corp',
              detail: 'bytes=4096 frames=18',
              recording_id: 'rec-abc-123456',
            },
          ],
        }),
      };
    });
    vi.stubGlobal('fetch', fetchMock);

    render(<AuditRecordingsView />);
    await vi.waitFor(() => {
      expect(screen.getByText('win-01.corp')).toBeInTheDocument();
      expect(screen.getByText('session_closed')).toBeInTheDocument();
    });
    expect(screen.getByRole('link', { name: 'Export MP4' })).toHaveAttribute(
      'href',
      '/api/v1/recordings/rec-abc-123456/export-mp4',
    );
    vi.unstubAllGlobals();
  });
});

