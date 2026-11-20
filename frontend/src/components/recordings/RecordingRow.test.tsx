import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { RecordingRow } from './RecordingRow';
import { api } from '@/lib/api';

vi.mock('@/lib/api', () => ({ api: { post: vi.fn(), get: vi.fn() } }));
afterEach(() => vi.resetAllMocks());

it('waits for a conversion to finish before offering the MP4', async () => {
  vi.mocked(api.post).mockResolvedValue({ ok: true, data: { job_id: 'job' } });
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: { status: 'running' } });
  render(<table><tbody><RecordingRow recording={{ name: 'test.cast', type: 'ssh', size: 1, mod_time: '2026-01-01' }} onPlay={() => {}} onDelete={() => {}} /></tbody></table>);
  fireEvent.click(screen.getByRole('button', { name: 'Convert test.cast to MP4' }));
  await waitFor(() => expect(api.get).toHaveBeenCalledWith('/convert-status/job'));
  expect(screen.queryByRole('link', { name: 'Download MP4 for test.cast' })).toBeNull();
});

it('offers the MP4 only after the converter reports success', async () => {
  vi.mocked(api.post).mockResolvedValue({ ok: true, data: { job_id: 'job' } });
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: { status: 'done' } });
  render(<table><tbody><RecordingRow recording={{ name: 'test.cast', type: 'ssh', size: 1, mod_time: '2026-01-01' }} onPlay={() => {}} onDelete={() => {}} /></tbody></table>);
  fireEvent.click(screen.getByRole('button', { name: 'Convert test.cast to MP4' }));
  expect(await screen.findByRole('link', { name: 'Download MP4 for test.cast' })).toBeTruthy();
});

it('shows a conversion failure instead of an MP4 link', async () => {
  vi.mocked(api.post).mockResolvedValue({ ok: true, data: { job_id: 'job' } });
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: { status: 'error', error: 'conversion failed' } });
  render(<table><tbody><RecordingRow recording={{ name: 'test.cast', type: 'ssh', size: 1, mod_time: '2026-01-01' }} onPlay={() => {}} onDelete={() => {}} /></tbody></table>);
  fireEvent.click(screen.getByRole('button', { name: 'Convert test.cast to MP4' }));
  expect((await screen.findByRole('alert')).textContent).toContain('conversion failed');
  expect(screen.queryByRole('link', { name: 'Download MP4 for test.cast' })).toBeNull();
});
