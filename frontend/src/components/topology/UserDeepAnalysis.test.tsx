import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { UserDeepAnalysis } from './UserDeepAnalysis';
import { apiPost } from '@/lib/api';

vi.mock('@/lib/api', () => ({ apiPost: vi.fn() }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it('runs analysis with the selected role and shows the result', async () => {
  vi.mocked(apiPost).mockResolvedValue({ ok: true, value: { reachable: true, hops: [{ index: 0, detail: 'Synthetic route' }] } });
  render(<UserDeepAnalysis instanceId="i-source" scope={{ roleID: 'role-a', region: 'us-east-1', cacheKey: 'tab' }} />);
  fireEvent.click(screen.getByText('Deep reachability analysis'));
  fireEvent.change(screen.getByLabelText('Destination instance or IP'), { target: { value: 'i-destination' } });
  fireEvent.change(screen.getByLabelText('Destination port'), { target: { value: '443' } });
  fireEvent.click(screen.getByRole('button', { name: 'Run deep analysis' }));
  expect(await screen.findByText('AWS reports the path is reachable.')).toBeInTheDocument();
  expect(screen.getByText('Synthetic route')).toBeInTheDocument();
  expect(apiPost).toHaveBeenCalledWith('/api/aws/topology/deep-analyze', expect.objectContaining({ binding_id: 'role-a', region: 'us-east-1', sourceInstanceId: 'i-source', destInstanceId: 'i-destination', protocol: 'tcp', port: 443 }), expect.any(AbortSignal));
});

it('cancels a running request when the topology tab closes', () => {
  vi.mocked(apiPost).mockImplementation(() => new Promise(() => {}));
  const view = render(<UserDeepAnalysis instanceId="i-source" scope={{ roleID: 'role-a', region: 'us-east-1', cacheKey: 'tab' }} />);
  fireEvent.click(screen.getByText('Deep reachability analysis'));
  fireEvent.change(screen.getByLabelText('Destination instance or IP'), { target: { value: 'i-destination' } });
  fireEvent.change(screen.getByLabelText('Destination port'), { target: { value: '443' } });
  fireEvent.click(screen.getByRole('button', { name: 'Run deep analysis' }));
  const signal = vi.mocked(apiPost).mock.calls[0][2] as AbortSignal;
  view.unmount();
  expect(signal.aborted).toBe(true);
});
