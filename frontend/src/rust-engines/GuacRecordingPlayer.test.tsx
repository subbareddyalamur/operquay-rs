import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { GuacRecordingPlayer, parseGuacStream } from './GuacRecordingPlayer';

function encGuac(insts: string[][]): string {
  return insts
    .map((parts) => parts.map((p) => `${p.length}.${p}`).join(',') + ';')
    .join('');
}

describe('GuacRecordingPlayer', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        ok: true,
        text: async () =>
          encGuac([
            ['size', '0', '800', '600'],
            ['rect', '0', '10', '20', '100', '50'],
            ['cfill', '14', '0', '30', '144', '255', '255'],
            ['img', '1', '14', '0', 'image/png', '50', '60'],
            ['blob', '1', 'AAAA'],
            ['blob', '1', 'BBBB'],
            ['end', '1'],
            ['copy', '0', '10', '20', '100', '50', '14', '0', '200', '300'],
            ['sync', '1000'],
            ['sync', '6000'],
          ]),
      })),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('parses guac instructions including img/blob/end, copy indices, and sync timestamps', () => {
    const ops = parseGuacStream(
      encGuac([
        ['size', '0', '800', '600'],
        ['img', '1', '14', '0', 'image/png', '5', '6'],
        ['blob', '1', 'YWJj'],
        ['end', '1'],
        ['copy', '0', '1', '2', '3', '4', '14', '0', '40', '50'],
        ['sync', '500'],
        ['sync', '3500'],
      ]),
    );
    expect(ops).toHaveLength(7);
    expect(ops[0].opcode).toBe('size');
    expect(ops[1].opcode).toBe('img');
    expect(ops[2].args).toEqual(['1', 'YWJj']);
    expect(ops[4].args[7]).toBe('40');
    expect(ops[4].args[8]).toBe('50');
    expect(ops[5].tsMs).toBe(0);
    expect(ops[6].tsMs).toBe(3000);
  });

  it('renders duration readout, speed buttons, and seeks without crashing', async () => {
    render(<GuacRecordingPlayer recordingId="rec-123" onClose={() => undefined} />);

    await waitFor(() => {
      expect(screen.getByText(/00:05/)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: '2x' }));
    const slider = screen.getByLabelText('Seek recording timeline') as HTMLInputElement;
    fireEvent.change(slider, { target: { value: '8' } });
    expect(slider.value).toBe('8');
  });

  it('omits duplicate header and close button in embedded mode while keeping controls', async () => {
    render(<GuacRecordingPlayer recordingId="rec-123" onClose={() => undefined} embedded />);

    await waitFor(() => {
      expect(screen.getByText(/00:05/)).toBeInTheDocument();
    });

    expect(screen.queryByText('Guacamole Session Replay')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Close player' })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Seek recording timeline')).toBeInTheDocument();
  });
});
