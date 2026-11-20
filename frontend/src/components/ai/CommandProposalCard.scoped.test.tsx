import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { CommandProposalCard } from './CommandProposalCard';
import { useAIStore } from '@/stores/ai';
import { useSessionsStore } from '@/stores/sessions';
import { useAuthStore } from '@/stores/auth';

afterEach(() => { cleanup(); useAIStore.getState().clear(); useAIStore.getState().setScope(null); useSessionsStore.setState({ sessions:[], activeId:null }); useAuthStore.setState({ me:null }); });

it('does not type an earlier role proposal into a different active terminal', () => {
  useAIStore.setState({ proposals:{ p:{ id:'p', command:'echo test' } } });
  useSessionsStore.setState({ sessions:[
    { id:'a', type:'ssh', instanceId:'i-a', instanceName:'A', status:'connected', createdAt:1, userSSH:{ roleID:'role-a', region:'us-east-1' } },
    { id:'b', type:'ssh', instanceId:'i-b', instanceName:'B', status:'connected', createdAt:2, userSSH:{ roleID:'role-b', region:'us-west-2' } },
  ], activeId:'b' });
  const dispatch = vi.spyOn(window, 'dispatchEvent');
  render(<CommandProposalCard proposalId="p" sessionId="a" requireActiveSession />);
  fireEvent.click(screen.getByRole('button', { name:'Type into terminal' }));
  expect(dispatch).not.toHaveBeenCalled();
  expect(useAIStore.getState().proposals.p?.approved).not.toBe(true);
  dispatch.mockRestore();
});

it('types only when the original user, role and terminal still match', () => {
  const scope = { key:'scope-a', sessionId:'a', bindingId:'role-a', region:'us-east-1', instanceId:'i-a', tenantId:'tenant', userId:'user', expiresAt:9999999999 };
  useAIStore.getState().setScope(scope.key);
  useAIStore.setState({ proposals:{ p:{ id:'p', command:'uptime' } } });
  useSessionsStore.setState({ sessions:[{ id:'a', type:'ssh', instanceId:'i-a', instanceName:'A', status:'connected', createdAt:1, userSSH:{ roleID:'role-a', region:'us-east-1' } }], activeId:'a' });
  useAuthStore.setState({ me:{ user_id:'other', tenant_id:'tenant', email:'other@example.test', role:'admin', method:'password', expires_at:9999999999 } });
  const dispatch = vi.spyOn(window, 'dispatchEvent');
  render(<CommandProposalCard proposalId="p" sessionId="a" requireActiveSession scope={scope} />);
  fireEvent.click(screen.getByRole('button', { name:'Type into terminal' }));
  expect(dispatch).not.toHaveBeenCalled();
  useAuthStore.setState({ me:{ user_id:'user', tenant_id:'tenant', email:'user@example.test', role:'admin', method:'password', expires_at:9999999999 } });
  useSessionsStore.setState({ sessions:[{ id:'a', type:'ssh', instanceId:'i-a', instanceName:'A', status:'connected', createdAt:1, userSSH:{ roleID:'role-b', region:'us-east-1' } }] });
  fireEvent.click(screen.getByRole('button', { name:'Type into terminal' }));
  expect(dispatch).not.toHaveBeenCalled();
  useSessionsStore.setState({ sessions:[{ id:'a', type:'ssh', instanceId:'i-a', instanceName:'A', status:'connected', createdAt:1, userSSH:{ roleID:'role-a', region:'us-east-1' } }] });
  fireEvent.click(screen.getByRole('button', { name:'Type into terminal' }));
  expect(dispatch).toHaveBeenCalledTimes(1);
  expect(useAIStore.getState().proposals.p?.approved).toBe(true);
  expect(screen.getByText('uptime')).toBeInTheDocument();
  expect(screen.getByText(/Typed into terminal/)).toBeInTheDocument();
  expect(screen.getByText('uptime')).toBeTruthy();
  expect(screen.getByText(/Typed into terminal/)).toBeTruthy();
  dispatch.mockRestore();
});
