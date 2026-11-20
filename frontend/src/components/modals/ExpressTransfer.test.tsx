import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { UploadModal } from './UploadModal';
import { DownloadModal } from './DownloadModal';
import { FileBrowserModal } from './FileBrowserModal';
import { api } from '@/lib/api';
import { CTX_ITEMS, getVisibleEntries, isSeparator } from '@/components/sidebar/contextMenuItems';
import type { EC2Instance } from '@/lib/types';

vi.mock('@/stores/instances', () => ({ useInstancesStore: { getState: () => ({ accounts: [] }) } }));
vi.mock('@/stores/activity', () => ({ useActivityStore: (select: (s: unknown) => unknown) => select({ add: () => 'activity', finish: vi.fn(), update: vi.fn() }) }));
vi.mock('@/hooks/useNDJSON', () => ({ streamNDJSON: async function* () { yield { done: true }; } }));
vi.mock('@/lib/api', () => ({ api: { post: vi.fn() } }));
vi.mock('@/stores/toast', () => { const push = vi.fn(); return { useToastStore: (select: (s: unknown) => unknown) => select({ push }) }; });
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it('shows express actions without a saved bucket', () => {
  const items = getVisibleEntries(CTX_ITEMS, { platform: 'linux' } as EC2Instance, {}).filter(entry => !isSeparator(entry));
  expect(items.flatMap(item => ('id' in item ? [item.id] : []))).toEqual(expect.arrayContaining(['expupload', 'expdownload']));
});

it('offers express download from the file browser without a saved bucket', async () => {
  vi.mocked(api.post).mockResolvedValue({ ok: true, data: [{ name: 'file.txt', is_dir: false, size: 1, modified: '' }] });
  const onExpressDownload = vi.fn();
  render(<FileBrowserModal open onOpenChange={vi.fn()} instanceId="i-1" onExpressDownload={onExpressDownload} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Express download file.txt' }));
  expect(onExpressDownload).toHaveBeenCalledWith('/file.txt');
});

it('requires and submits the bucket selected for an express upload', async () => {
  const fetchMock = vi.fn().mockResolvedValue({ ok: true });
  vi.stubGlobal('fetch', fetchMock);
  render(<UploadModal open onOpenChange={vi.fn()} instanceId="i-1" express />);
  fireEvent.change(screen.getByLabelText('Select file to upload'), { target: { files: [new File(['x'], 'x.txt')] } });
  expect(screen.getByRole('button', { name: 'Upload' })).toBeDisabled();
  fireEvent.change(screen.getByLabelText('S3 bucket'), { target: { value: 'not/a/bucket' } });
  expect(screen.getByRole('button', { name: 'Upload' })).toBeDisabled();
  fireEvent.change(screen.getByLabelText('S3 bucket'), { target: { value: 'transfer-bucket' } });
  fireEvent.click(screen.getByRole('button', { name: 'Upload' }));
  await waitFor(() => expect(fetchMock).toHaveBeenCalled());
  expect((fetchMock.mock.calls[0][1].body as FormData).get('s3_bucket')).toBe('transfer-bucket');
});

it('requires and submits the bucket selected for an express download', async () => {
  const fetchMock = vi.fn().mockResolvedValue({ ok: true });
  vi.stubGlobal('fetch', fetchMock);
  render(<DownloadModal open onOpenChange={vi.fn()} instanceId="i-1" initialPath="/tmp/x" express />);
  expect(screen.getByRole('button', { name: 'Download' })).toBeDisabled();
  fireEvent.change(screen.getByLabelText('S3 bucket'), { target: { value: 'other-bucket' } });
  fireEvent.click(screen.getByRole('button', { name: 'Download' }));
  await waitFor(() => expect(fetchMock).toHaveBeenCalled());
  expect(JSON.parse(fetchMock.mock.calls[0][1].body).s3_bucket).toBe('other-bucket');
});
