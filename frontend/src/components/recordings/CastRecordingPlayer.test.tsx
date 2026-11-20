import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { CastRecordingPlayer, parseAsciicast } from './CastRecordingPlayer';

const writes: string[] = [];

vi.mock('@/lib/terminal-engine', () => ({
  normalizeTerminalEngine: () => 'wasm',
  createTerminalAdapter: () => ({
    engine: 'wasm',
    cols: 120,
    rows: 32,
    init: async () => undefined,
    write: (d: string) => { writes.push(d); },
    focus: () => undefined,
    fit: () => undefined,
    paste: () => undefined,
    getSelection: () => '',
    search: () => false,
    searchNext: () => false,
    searchPrevious: () => false,
    clearSearch: () => undefined,
    serialize: () => '',
    serializeAsync: async () => '',
    setAppearance: () => undefined,
    setTheme: () => undefined,
    setScrollbackLines: () => undefined,
    dispose: () => undefined,
  }),
}));

describe('CastRecordingPlayer', () => {
  beforeEach(() => {
    writes.length = 0;
    const sampleCast = [
      JSON.stringify({ version: 2, width: 120, height: 32 }),
      JSON.stringify([0.0, 'o', 'booting\r\n']),
      JSON.stringify([5.0, 'o', 'step-5s\r\n']),
      JSON.stringify([20.0, 'o', 'done-20s\r\n']),
    ].join('\n');

    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        ok: true,
        status: 200,
        text: async () => sampleCast,
      })),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('parses asciicast v2 output events and ignores headers/malformed lines', () => {
    const parsed = parseAsciicast('{"version":2}\nnot-json\n[1.25,"i","x"]\n[2.5,"o","ok"]\n');
    expect(parsed.events).toEqual([{ tsMs: 2500, data: 'ok' }]);
    expect(parsed.totalMs).toBe(2500);
  });

  it('renders play/pause, -10s/+10s, restart, 1x/2x/4x speed, and seek timeline with backward reset', async () => {
    render(<CastRecordingPlayer src="/recordings/sess.cast" />);

    await waitFor(() => {
      expect(screen.getByText('00:00 / 00:20')).toBeInTheDocument();
    });

    const slider = screen.getByLabelText('Seek terminal recording timeline') as HTMLInputElement;
    expect(slider.max).toBe('20000');

    // Forward +10s advances timeline and writes intermediate events
    fireEvent.click(screen.getByRole('button', { name: 'Forward 10 seconds' }));
    expect(screen.getByText('00:10 / 00:20')).toBeInTheDocument();
    expect(writes.join('')).toContain('step-5s');

    // Seek to end then Rewind -10s resets terminal (\x1bc\x1b[3J\x1b[H) & replays cleanly
    fireEvent.change(slider, { target: { value: '20000' } });
    expect(screen.getByText('00:20 / 00:20')).toBeInTheDocument();

    writes.length = 0;
    fireEvent.click(screen.getByRole('button', { name: 'Rewind 10 seconds' }));
    expect(screen.getByText('00:10 / 00:20')).toBeInTheDocument();
    expect(writes[0]).toBe('\x1bc\x1b[3J\x1b[H');
    expect(writes.join('')).toContain('step-5s');
    expect(writes.join('')).not.toContain('done-20s');

    // Speed toggle + Pause/Play
    fireEvent.click(screen.getByRole('button', { name: '4x' }));
    fireEvent.click(screen.getByRole('button', { name: 'Restart playback' }));
    expect(screen.getByText('00:00 / 00:20')).toBeInTheDocument();
  });
});
