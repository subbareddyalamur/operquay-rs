// @vitest-environment-options {"url":"https://desk.example/"}
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { AIChatPanel } from './AIChatPanel';
import { useAIStore } from '@/stores/ai';
import { useSessionsStore } from '@/stores/sessions';
import { useAuthStore, type AuthConfig } from '@/stores/auth';
import { useSettingsStore } from '@/stores/settings';

vi.hoisted(() => { const values = new Map<string,string>(); vi.stubGlobal('localStorage', { getItem:(key:string) => values.get(key) ?? null, setItem:(key:string, value:string) => values.set(key,value), removeItem:(key:string) => values.delete(key) }); });
vi.mock('./ProviderSelector', () => ({ ProviderSelector: () => <span>legacy provider selector</span> }));
afterEach(() => { cleanup(); useAIStore.getState().clear(); useAIStore.getState().setScope(null); useAIStore.getState().setOpen(false); useSessionsStore.setState({ sessions:[], activeId:null }); useAuthStore.setState({ config:null, me:null }); vi.restoreAllMocks(); });

it('sends and clears the conversation with the active user role', async () => {
  Element.prototype.scrollIntoView = vi.fn();
  useAuthStore.setState({ config:{ aws_access_mode:'user' } as AuthConfig, me:{ user_id:'user', tenant_id:'tenant', email:'admin@example.test', role:'admin', method:'password', expires_at:9999999999 } });
  useSessionsStore.setState({ sessions:[
    { id:'a', type:'ssh', instanceId:'i-a', instanceName:'A', status:'connected', createdAt:1, userSSH:{ roleID:'role-a', region:'us-east-1' } },
    { id:'b', type:'ssh', instanceId:'i-b', instanceName:'B', status:'connected', createdAt:2, userSSH:{ roleID:'role-b', region:'us-west-2' } },
  ], activeId:'a' });
  useAIStore.getState().setOpen(true);
  const fetch = vi.spyOn(window, 'fetch').mockImplementation(async (url) => String(url).includes('/api/ai/catalog')
    ? new Response(JSON.stringify({ configured: false, models: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    : new Response('data: {"type":"text","text":"private answer"}\n\n', { status: 200 }));
  render(<AIChatPanel />);
  fireEvent.change(screen.getByLabelText('Chat message input'), { target:{ value:'question' } });
  fireEvent.click(screen.getByRole('button', { name:'Send message' }));
  expect(await screen.findByText('private answer')).toBeInTheDocument();
  const chat = fetch.mock.calls.find((call) => call[0] === '/api/aws/ai/chat');
  expect(chat?.[0]).toBe('/api/aws/ai/chat');
  const body = JSON.parse(chat![1]!.body as string) as Record<string, unknown>;
  expect(body).toMatchObject({ session_id:'a', binding_id:'role-a', region:'us-east-1', instance_id:'i-a' });
  act(() => useSessionsStore.setState({ activeId:'b' }));
  await waitFor(() => expect(screen.queryByText('private answer')).not.toBeInTheDocument());
  expect(screen.queryByText('legacy provider selector')).not.toBeInTheDocument();
  act(() => useSessionsStore.setState({ activeId:null }));
  expect(screen.getByText(/Select an active scoped SSH terminal/)).toBeInTheDocument();
  expect(screen.getByLabelText('Chat message input')).toBeDisabled();
  expect(screen.queryByText(/Shift\+Enter for newline/)).not.toBeInTheDocument();
});

it('clears a scoped conversation when changing providers', async () => {
  Element.prototype.scrollIntoView = vi.fn();
  useSettingsStore.setState({ aiProvider:'bedrock', aiModel:'model-a' });
  useAuthStore.setState({ config:{ aws_access_mode:'user' } as AuthConfig, me:{ user_id:'user', tenant_id:'tenant', email:'admin@example.test', role:'admin', method:'password', expires_at:9999999999 } });
  useSessionsStore.setState({ sessions:[{ id:'a', type:'ssh', instanceId:'i-a', instanceName:'A', status:'connected', createdAt:1, userSSH:{ roleID:'role-a', region:'us-east-1' } }], activeId:'a' });
  useAIStore.getState().setOpen(true);
  vi.spyOn(window, 'fetch').mockImplementation(async (url) => String(url).includes('/api/ai/catalog')
    ? new Response(JSON.stringify({ configured: false, models: [] }), { status: 200, headers: { 'Content-Type': 'application/json' } })
    : new Response('data: {"type":"text","text":"private answer"}\n\n', { status: 200 }));
  render(<AIChatPanel />);
  fireEvent.change(screen.getByLabelText('Chat message input'), { target:{ value:'question' } });
  fireEvent.click(screen.getByRole('button', { name:'Send message' }));
  expect(await screen.findByText('private answer')).toBeInTheDocument();
  act(() => useSettingsStore.setState({ aiProvider:'openai', aiModel:'model-b' }));
  await waitFor(() => expect(screen.queryByText('private answer')).not.toBeInTheDocument());
});
