import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { TerminalSession } from './TerminalSession';
import { useSessionsStore } from '@/stores/sessions';

const mocks = vi.hoisted(() => ({ send: vi.fn(), getWS: vi.fn() }));
vi.mock('@/lib/ws', () => ({ getTerminalWS: mocks.getWS }));
vi.mock('./Xterm', () => ({ Xterm: (props: { instanceId: string; awsProfile: string; userScoped: boolean }) => <div data-testid="terminal">{props.instanceId} {props.awsProfile} {String(props.userScoped)}</div> }));
vi.hoisted(() => { window.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} }) as unknown as MediaQueryList; });
afterEach(() => { useSessionsStore.setState({ sessions: [], activeId: null }); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it('opens split terminals with their own scoped role and never uses a legacy profile', () => {
  mocks.getWS.mockReturnValue({ send: mocks.send });
  useSessionsStore.setState({ sessions: [
    { id:'a', type:'ssh', instanceId:'i-one', instanceName:'One', status:'connected', createdAt:1, userSSH:{ roleID:'role-one', region:'us-east-1' } },
    { id:'b', type:'ssh', instanceId:'i-two', instanceName:'Two', status:'connected', createdAt:2, userSSH:{ roleID:'role-two', region:'us-west-2' } },
    { id:'c', type:'ssh', instanceId:'i-legacy', instanceName:'Legacy', status:'connected', createdAt:3 },
  ], activeId:'a' });
  render(<TerminalSession instance={{ instance_id:'i-one', name:'One', aws_profile:'user:role-one', aws_region:'us-east-1' }} sessionId="a" userScoped />);
  expect(screen.getByTestId('terminal')).toHaveTextContent('i-one user:role-one true');
  fireEvent.click(screen.getByRole('button', { name:'More session actions' }));
  fireEvent.click(screen.getByRole('menuitem', { name:'Split with another session' }));
  expect(screen.queryByText('Legacy')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name:/Two/ }));
  expect(screen.getAllByTestId('terminal')[1]).toHaveTextContent('i-two user:role-two true');
  fireEvent.click(screen.getByRole('button', { name:'Close split pane' }));
  expect(mocks.getWS).toHaveBeenCalledWith(true);
  expect(mocks.send).toHaveBeenCalledWith(expect.objectContaining({ type:'close_session' }));
  expect(mocks.getWS).not.toHaveBeenCalledWith(false);
});

it('exports only through the scoped session endpoint', async () => {
  const fetcher = vi.spyOn(window, 'fetch').mockResolvedValue(new Response('terminal output', { status:200 }));
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL:vi.fn().mockReturnValue('blob:output'), revokeObjectURL:vi.fn() }));
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  render(<TerminalSession instance={{ instance_id:'i-one', name:'One', aws_profile:'user:role-one', aws_region:'us-east-1' }} sessionId="scoped-one" userScoped />);
  fireEvent.click(screen.getByRole('button', { name:'More session actions' }));
  fireEvent.click(screen.getByRole('menuitem', { name:'Export session log' }));
  await waitFor(() => expect(click).toHaveBeenCalled());
  expect(fetcher).toHaveBeenCalledWith('/api/aws/session-export', expect.objectContaining({ method:'POST', body:JSON.stringify({ session_id:'scoped-one' }) }));
});

it('does not download output when scoped export is denied', async () => {
  vi.spyOn(window, 'fetch').mockResolvedValue(new Response('', { status:403 }));
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  render(<TerminalSession instance={{ instance_id:'i-one', name:'One', aws_profile:'user:role-one', aws_region:'us-east-1' }} sessionId="scoped-one" userScoped />);
  fireEvent.click(screen.getByRole('button', { name:'More session actions' }));
  fireEvent.click(screen.getByRole('menuitem', { name:'Export session log' }));
  await waitFor(() => expect(window.fetch).toHaveBeenCalled());
  expect(click).not.toHaveBeenCalled();
});
