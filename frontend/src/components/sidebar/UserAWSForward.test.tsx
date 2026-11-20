import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { UserAWSForward } from './UserAWSForward';
import { api } from '@/lib/api';

vi.mock('@/lib/api', () => ({ api: { post: vi.fn() } }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it('starts with the selected role, shows the pairing code and stops the forward', async () => {
  vi.mocked(api.post).mockImplementation(async path => path.endsWith('/start') ? { ok: true, data: { forward_id: 'forward', pairing_code: 'one-time-code' } } : { ok: true, data: { status: 'stopping' } });
  render(<UserAWSForward roleID="role-a" instanceID="i-test" instanceName="Fixture" region="us-east-1" />);
  fireEvent.click(screen.getByText('Port forwarding'));
  fireEvent.change(screen.getByLabelText('Remote TCP port for i-test'), { target: { value: '5432' } });
  fireEvent.click(screen.getByRole('button', { name: 'Start forward for i-test' }));
  expect(await screen.findByText('one-time-code')).toBeInTheDocument();
  expect(screen.getByText(/\.\/operquay-forward -url/)).toBeInTheDocument();
  expect(api.post).toHaveBeenCalledWith('/api/aws/forward/start', { binding_id:'role-a', instance_id:'i-test', instance_name:'Fixture', region:'us-east-1', port:5432 });
  fireEvent.click(screen.getByRole('button', { name: 'Stop forward to port 5432' }));
  expect(await screen.findByText(/Stop requested/)).toBeInTheDocument();
  expect(api.post).toHaveBeenCalledWith('/api/aws/forward/stop', { forward_id:'forward' });
});
