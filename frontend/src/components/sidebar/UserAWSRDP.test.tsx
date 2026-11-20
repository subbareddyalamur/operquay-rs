import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { UserAWSRDP } from './UserAWSRDP';
import { useSessionsStore } from '@/stores/sessions';

const { post, get } = vi.hoisted(() => ({ post: vi.fn(), get: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { post, get } }));
vi.mock('@/lib/credentialTransport', () => ({ canSendCredentials: () => true }));
vi.mock('@/components/rdp/RdpDesktopClient', () => ({ RdpDesktopClient: (props: { token: string; userScoped: boolean }) => <div data-testid="rdp-client">{props.token} {String(props.userScoped)}</div> }));

it('uses the existing RDP credential dialog and scoped connection', async () => {
  post.mockResolvedValue({ ok:true, data:{ token:'one-time-ticket', forward_id:'forward' } });
  render(<UserAWSRDP id="rdp-1" roleID="role" instanceID="i-windows" instanceName="Windows" region="us-east-1" onClose={() => {}} />);
  fireEvent.change(screen.getByLabelText('Username'), { target:{ value:'alice' } });
  fireEvent.change(screen.getByLabelText('Password'), { target:{ value:'secret' } });
  fireEvent.change(screen.getByLabelText('Security'), { target:{ value:'tls' } });
  fireEvent.click(screen.getByRole('button', { name:/^Connect$/ }));
  expect(await screen.findByTestId('rdp-client')).toHaveTextContent('one-time-ticket true');
  expect(post).toHaveBeenCalledWith('/api/aws/rdp/start', expect.objectContaining({ aws_profile:'user:role', instance_id:'i-windows', password:'secret', security:'tls' }));
  expect(screen.queryByDisplayValue('secret')).not.toBeInTheDocument();
});

it('defaults to Auto and sends no certificate prompt or fingerprint', async () => {
  post.mockReset();
  post.mockResolvedValue({ ok:true, data:{ token:'ticket', forward_id:'forward' } });
  render(<UserAWSRDP id="rdp-auto" roleID="role" instanceID="i-windows" instanceName="Windows" region="us-east-1" onClose={() => {}} />);
  expect(screen.getByLabelText('Security')).toHaveValue('any');
  expect(screen.queryByLabelText(/fingerprint|certificate/i)).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText('Username'), { target:{ value:'alice' } });
  fireEvent.change(screen.getByLabelText('Password'), { target:{ value:'secret' } });
  fireEvent.click(screen.getByRole('button', { name:/^Connect$/ }));
  await screen.findByTestId('rdp-client');
  const request = post.mock.calls.find(([path]) => path === '/api/aws/rdp/start')?.[1];
  expect(request).toMatchObject({ security:'any', username:'alice' });
  expect(request).not.toHaveProperty('certificate_fingerprint');
});

it('shows why AWS refused the RDP tunnel', async () => {
  post.mockReset();
  post.mockResolvedValueOnce({ ok:false, error:{ status:502, message:JSON.stringify({ error:'The instance is not connected to AWS Systems Manager. Check that it is running and that its SSM agent and instance profile allow Session Manager.' }) } });
  render(<UserAWSRDP id="rdp-3" roleID="role" instanceID="i-windows" instanceName="Windows" region="us-east-1" onClose={() => {}} />);
  fireEvent.change(screen.getByLabelText('Username'), { target:{ value:'alice' } });
  fireEvent.change(screen.getByLabelText('Password'), { target:{ value:'secret' } });
  fireEvent.click(screen.getByRole('button', { name:/^Connect$/ }));
  expect(await screen.findByRole('alert')).toHaveTextContent('not connected to AWS Systems Manager');
});

it('allows retry after a connection failure', async () => {
  post.mockReset();
  post.mockResolvedValueOnce({ ok:false }).mockResolvedValueOnce({ ok:true, data:{ token:'ticket', forward_id:'forward' } });
  render(<UserAWSRDP id="rdp-2" roleID="role" instanceID="i-windows" instanceName="Windows" region="us-east-1" onClose={() => {}} />);
  fireEvent.change(screen.getByLabelText('Username'), { target:{ value:'alice' } });
  fireEvent.change(screen.getByLabelText('Password'), { target:{ value:'secret' } });
  fireEvent.click(screen.getByRole('button', { name:/^Connect$/ }));
  expect(await screen.findByRole('alert')).toHaveTextContent('RDP could not start');
  fireEvent.click(screen.getByRole('button', { name:'Retry RDP' }));
  expect(screen.getByLabelText('Password')).toHaveValue('');
  fireEvent.change(screen.getByLabelText('Password'), { target:{ value:'new-secret' } });
  fireEvent.click(screen.getByRole('button', { name:/^Connect$/ }));
  expect(await screen.findByTestId('rdp-client')).toHaveTextContent('ticket true');
});

it('shows the login form as a reconnect after the tab is restored', () => {
  useSessionsStore.setState({ sessions: [{ id: 'rdp-back', type: 'rdp', instanceId: 'i-windows', instanceName: 'Windows', status: 'disconnected', createdAt: 1, userRDP: { roleID: 'role', region: 'us-east-1' } }], activeId: 'rdp-back' });
  render(<UserAWSRDP id="rdp-back" roleID="role" instanceID="i-windows" instanceName="Windows" region="us-east-1" onClose={() => {}} />);
  expect(screen.getByRole('button', { name: 'Reconnect' })).toBeInTheDocument();
  expect(screen.getByLabelText('Password')).toHaveValue('');
});

it('keeps an inactive tab credential dialog hidden', () => {
  const { rerender } = render(<UserAWSRDP id="rdp-3" roleID="role" instanceID="i-windows" instanceName="Windows" region="us-east-1" active={false} onClose={() => {}} />);
  expect(screen.queryByLabelText('Password')).not.toBeInTheDocument();
  rerender(<UserAWSRDP id="rdp-3" roleID="role" instanceID="i-windows" instanceName="Windows" region="us-east-1" active onClose={() => {}} />);
  expect(screen.getByLabelText('Password')).toBeInTheDocument();
});

it('cleans up if a tab closes while the forward is starting', async () => {
  post.mockReset();
  let finish!: (value: unknown) => void;
  post.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; })).mockResolvedValue({ ok:true, data:{} });
  const { unmount } = render(<UserAWSRDP id="rdp-4" roleID="role" instanceID="i-windows" instanceName="Windows" region="us-east-1" onClose={() => {}} />);
  fireEvent.change(screen.getByLabelText('Username'), { target:{ value:'alice' } });
  fireEvent.change(screen.getByLabelText('Password'), { target:{ value:'secret' } });
  fireEvent.click(screen.getByRole('button', { name:/^Connect$/ }));
  unmount();
  finish({ ok:true, data:{ token:'ticket', forward_id:'late-forward' } });
  await waitFor(() => expect(post).toHaveBeenCalledWith('/api/aws/rdp/stop', { forward_id:'late-forward' }));
});

it('shows the recording indicator only when the scoped recording is present', async () => {
  post.mockReset(); get.mockReset();
  post.mockResolvedValue({ ok:true, data:{ token:'ticket', forward_id:'forward', recording_name:'session.guac' } });
  get.mockResolvedValue({ ok:true, data:[{ name:'session.guac', size:10 }] });
  useSessionsStore.setState({ sessions:[{ id:'rdp-5', type:'rdp', instanceId:'i-windows', instanceName:'Windows', status:'connected', createdAt:1 }], activeId:'rdp-5' });
  render(<UserAWSRDP id="rdp-5" roleID="role" instanceID="i-windows" instanceName="Windows" region="us-east-1" onClose={() => {}} />);
  fireEvent.change(screen.getByLabelText('Username'), { target:{ value:'alice' } });
  fireEvent.change(screen.getByLabelText('Password'), { target:{ value:'secret' } });
  fireEvent.click(screen.getByRole('button', { name:/^Connect$/ }));
  await screen.findByTestId('rdp-client');
  useSessionsStore.getState().updateStatus('rdp-5', 'connected');
  expect(await screen.findByRole('img', { name:'Recording' })).toBeInTheDocument();
});
