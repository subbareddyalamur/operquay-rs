import { describe, expect, it, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { RemoteDesktopSettingsView } from './RemoteDesktopSettingsView';
import { DEFAULT_SETTINGS, computeLocalSimulation, diffSettingsCount } from './schema';
import { filterSections } from './registry';
import { useSettingsStore } from './store';
import { decodeOqr2Frame } from '../oqr2Decoder';

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
    expect(wan.effective_jpeg_quality).toBe(55);
    expect(wan.drops_stale_frames).toBe(true);
    expect(wan.effective_fps_cap).toBe(20);
  });

  it('filters registry sections declaratively by search keyword and protocol scope', () => {
    expect(filterSections('lcid', 'all').map((s) => s.id)).toEqual(['input']);
    expect(filterSections('', 'vnc').some((s) => s.id === 'input')).toBe(false);
    expect(filterSections('opentelemetry', 'all').map((s) => s.id)).toEqual(['telemetry']);
  });

  it('renders streamlined operator settings without debug badges and surfaces dirty bar on preset change', () => {
    render(<RemoteDesktopSettingsView />);

    expect(screen.queryByRole('region', { name: 'Unsaved settings changes' })).not.toBeInTheDocument();
    expect(screen.queryByText(/In-Process IronRDP/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Launch RDP Session/i)).not.toBeInTheDocument();
    expect(screen.queryByText('/metrics')).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole('radio', { name: /Ultra-Low Latency LAN/ }));
    expect(diffSettingsCount(DEFAULT_SETTINGS, useSettingsStore.getState().draft)).toBeGreaterThan(0);
    expect(screen.getByRole('region', { name: 'Unsaved settings changes' })).toBeInTheDocument();

    const layoutSelect = screen.getByLabelText('Default Keyboard Layout');
    fireEvent.change(layoutSelect, { target: { value: 'de-de-qwertz' } });
    expect(useSettingsStore.getState().draft.keyboard_layout).toBe('de-de-qwertz');
  });

  it('decodes OQR2 SolidFill binary wire frames cleanly', () => {
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
});
