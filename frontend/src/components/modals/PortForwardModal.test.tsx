import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { PortForwardModal } from './PortForwardModal';
import { apiGet, apiPost } from '@/lib/api';

vi.mock('@/lib/api', () => ({ apiGet: vi.fn(), apiPost: vi.fn() }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

it('starts a tunnel through the active modal', async () => {
  vi.mocked(apiGet).mockResolvedValue({ ok: true, value: [] });
  vi.mocked(apiPost).mockResolvedValue({ ok: true, value: { forward_id: 'forward-one', port: 33890 } });
  const onOpenChange = vi.fn();
  render(<PortForwardModal open onOpenChange={onOpenChange} defaultInstanceId="i-1" defaultInstanceName="Test" />);
  fireEvent.change(screen.getByLabelText('Remote port'), { target: { value: '8080' } });
  fireEvent.click(screen.getByRole('button', { name: 'Start tunnel' }));
  await waitFor(() => expect(apiPost).toHaveBeenCalledWith('/start-port-forward', { instance_id: 'i-1', instance_name: 'Test', port_number: 8080 }));
  await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false));
});

it('stops the selected tunnel by its unique forward ID', async () => {
  vi.mocked(apiGet).mockResolvedValue({ ok: true, value: [{ forward_id: 'forward-one', instance_id: 'i-1', instance_name: 'Test', local_port: 33890, remote_port: 8080, aws_profile: 'test', aws_region: 'test', started_at: '' }] });
  vi.mocked(apiPost).mockResolvedValue({ ok: true, value: {} });
  render(<PortForwardModal open onOpenChange={() => {}} defaultInstanceId="i-1" />);
  fireEvent.click(await screen.findByRole('button', { name: 'Stop tunnel' }));
  await waitFor(() => expect(apiPost).toHaveBeenCalledWith('/stop-port-forward', { forward_id: 'forward-one' }));
});
