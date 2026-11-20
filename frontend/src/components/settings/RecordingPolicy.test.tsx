// @vitest-environment-options {"url":"https://desk.example/"}
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { RecordingPolicy } from './RecordingPolicy';
import { api } from '@/lib/api';

vi.mock('@/lib/api', () => ({ api: { get: vi.fn(), put: vi.fn() } }));
vi.mock('./KubeRecordingPolicy', () => ({ KubeRecordingPolicy: () => null }));
vi.mock('@/stores/instances', () => ({ useInstancesStore: (select: (state: unknown) => unknown) => select({ accounts: [{ account_id: 'account', account_alias: 'A', profile: 'a', regions: [{ region: 'region', groups: [{ tag1: '', tag2: '', instances: [{ instance_id: 'i-1', name: 'Server' }, { instance_id: 'i-2', name: 'Worker' }] }] }] }] }) }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

it('keeps recording guidance concise while retaining safety information', async () => {
  vi.mocked(api.get).mockImplementation(async path => path === '/api/recording-storage' ? { ok: true, data: { configured: true } } : { ok: true, data: { mode: 'off', instances: [] } });
  render(<RecordingPolicy />);
  expect(await screen.findByText('Changes apply to new sessions. Required production recording still applies.')).toHaveClass('text-xs', 'font-normal');
  expect(screen.getByText('RDP recording writes are not continuously verified.')).toBeInTheDocument();
  expect(screen.getByText('Local or mounted NAS: configured. Write access and durability are not verified.')).toBeInTheDocument();
  expect(screen.getByText('Cloud storage is not yet available.')).toBeInTheDocument();
});

it('lets the administrator save selected instances', async () => {
  vi.mocked(api.get).mockImplementation(async path => path === '/api/recording-storage' ? { ok: true, data: { configured: true } } : { ok: true, data: { mode: 'off', instances: [] } });
  vi.mocked(api.put).mockResolvedValue({ ok: true, data: { mode: 'selected', instances: ['i-1'] } });
  render(<RecordingPolicy />);
  await screen.findByLabelText('Selected instances');
  fireEvent.click(screen.getByLabelText('Selected instances'));
  fireEvent.click(screen.getByRole('button', { name: 'Choose instances' }));
  fireEvent.click(screen.getByLabelText('Server (i-1)'));
  expect(screen.getByRole('button', { name: 'Selected instances (1)' })).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Save recording policy' }));
  await waitFor(() => expect(api.put).toHaveBeenCalledWith('/api/recording-policy', { mode: 'selected', instances: ['i-1'] }));
  expect(await screen.findByText('Recording policy saved.')).toBeInTheDocument();
});

it('searches by name or ID and manages selections inside Selected instances modal', async () => {
  vi.mocked(api.get).mockImplementation(async path => path === '/api/recording-storage' ? { ok: true, data: { configured: true } } : { ok: true, data: { mode: 'selected', instances: ['i-1', 'i-missing'] } });
  render(<RecordingPolicy />);
  const selectedBtn = await screen.findByRole('button', { name: 'Selected instances (2)' });
  fireEvent.click(screen.getByRole('button', { name: 'Choose instances' }));
  const search = screen.getByRole('searchbox', { name: 'Search instances' });
  expect(search).toHaveFocus();
  fireEvent.change(search, { target: { value: 'WORK' } });
  expect(screen.getByLabelText('Worker (i-2)')).toBeInTheDocument();
  expect(screen.queryByLabelText('Server (i-1)')).not.toBeInTheDocument();
  fireEvent.click(screen.getByLabelText('Worker (i-2)'));
  expect(screen.getByRole('button', { name: 'Selected instances (3)' })).toBeInTheDocument();
  fireEvent.change(search, { target: { value: 'i-1' } });
  expect(screen.getByLabelText('Server (i-1)')).toBeChecked();
  fireEvent.change(search, { target: { value: 'nothing-matches' } });
  expect(screen.getByText('No matching instances.')).toBeInTheDocument();
  fireEvent.keyDown(search, { key: 'Escape' });
  expect(screen.queryByRole('searchbox', { name: 'Search instances' })).not.toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Choose instances' })).toHaveFocus();

  // Open Selected instances modal, inspect missing inventory note, remove items, and close via Esc & Close button
  fireEvent.click(selectedBtn);
  const dialog = screen.getByRole('dialog');
  const list = within(dialog).getByRole('list', { name: 'Selected recording instances' });
  expect(within(list).getByText('Server')).toBeInTheDocument();
  expect(within(list).getByText('Worker')).toBeInTheDocument();
  expect(within(list).getByText('i-missing')).toBeInTheDocument();
  expect(within(list).getByText('Not in current inventory')).toBeInTheDocument();
  fireEvent.click(within(list).getByRole('button', { name: 'Remove i-missing' }));
  expect(within(list).queryByText('i-missing')).not.toBeInTheDocument();
  fireEvent.click(within(list).getByRole('button', { name: 'Remove Server (i-1)' }));
  fireEvent.keyDown(dialog, { key: 'Escape' });
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

  vi.mocked(api.put).mockResolvedValue({ ok: true, data: { mode: 'selected', instances: ['i-2'] } });
  fireEvent.click(screen.getByRole('button', { name: 'Save recording policy' }));
  await waitFor(() => expect(api.put).toHaveBeenCalledWith('/api/recording-policy', { mode: 'selected', instances: ['i-2'] }));
});

it('closes on outside click and requires a selection before saving', async () => {
  vi.mocked(api.get).mockImplementation(async path => path === '/api/recording-storage' ? { ok: true, data: { configured: true } } : { ok: true, data: { mode: 'selected', instances: [] } });
  render(<RecordingPolicy />);
  const choose = await screen.findByRole('button', { name: 'Choose instances' });
  const save = screen.getByRole('button', { name: 'Save recording policy' });
  expect(save).toBeDisabled();
  fireEvent.click(choose);
  expect(choose).toHaveAttribute('aria-expanded', 'true');
  fireEvent.click(screen.getByLabelText('Server (i-1)'));
  expect(save).toBeEnabled();
  fireEvent.click(screen.getByLabelText('Server (i-1)'));
  expect(save).toBeDisabled();
  fireEvent.mouseDown(document.body);
  expect(choose).toHaveAttribute('aria-expanded', 'false');
});

it('warns when recording is enabled without configured storage', async () => {
  vi.mocked(api.get).mockImplementation(async path => path === '/api/recording-storage' ? { ok: true, data: { configured: false } } : { ok: true, data: { mode: 'off', instances: [] } });
  render(<RecordingPolicy />);
  fireEvent.click(await screen.findByLabelText('All instances'));
  expect(screen.getByRole('alert')).toHaveTextContent('No recording storage is configured');
});

it('warns for required production recording even if the tenant policy is off', async () => {
  vi.mocked(api.get).mockImplementation(async path => path === '/api/recording-storage' ? { ok: true, data: { configured: false, required_production: true } } : { ok: true, data: { mode: 'off', instances: [] } });
  render(<RecordingPolicy />);
  expect(await screen.findByRole('alert')).toHaveTextContent('No recording storage is configured');
});
