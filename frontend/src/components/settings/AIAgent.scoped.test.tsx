import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { SettingsModal } from './SettingsModal';
import { useAuthStore, type AuthConfig } from '@/stores/auth';
import { useInstancesStore } from '@/stores/instances';
import { useSettingsStore } from '@/stores/settings';

vi.hoisted(() => { const values = new Map<string, string>(); vi.stubGlobal('localStorage', { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => values.set(key, value), removeItem: (key: string) => values.delete(key) }); });
const models = vi.hoisted(() => ({ fetch: vi.fn().mockResolvedValue({ ok: true, data: [] }) }));
vi.mock('@/lib/aiModels', () => ({ fetchAIModels: models.fetch }));
vi.mock('@/stores/theme', () => ({ useThemeStore: vi.fn() }));
afterEach(() => { cleanup(); useAuthStore.setState({ config: null, me: null }); useInstancesStore.setState({ userRoles: [] }); });

it('does not offer shared AWS credentials for Bedrock in user-scoped mode', () => {
  useAuthStore.setState({ config: { aws_access_mode: 'user' } as AuthConfig, me: { user_id: 'admin', tenant_id: 'tenant', email: 'admin@example.test', role: 'admin', method: 'password', expires_at: 9999999999 } });
  render(<SettingsModal open initialTab="ai" onOpenChange={() => {}} />);
  expect(screen.getByLabelText('AWS account')).toBeInTheDocument();
  expect(screen.queryByText('AWS Profile & Region')).not.toBeInTheDocument();
  expect(screen.queryByPlaceholderText('AKIA...')).not.toBeInTheDocument();
});

it('saves only the models an administrator selects', async () => {
  models.fetch.mockReset().mockResolvedValue({ ok: true, data: [{ id: 'model-a', name: 'Model A' }, { id: 'model-b', name: 'Model B' }] });
  useAuthStore.setState({ config: { aws_access_mode: 'user' } as AuthConfig, me: { user_id: 'admin', tenant_id: 'tenant', email: 'admin@example.test', role: 'admin', method: 'password', expires_at: 9999999999 } });
  useInstancesStore.setState({ userRoles: [{ id: '11111111-1111-1111-1111-111111111111', name: 'DataCloud', label: 'Admin', accountID: '111111111111', live: true }] });
  render(<SettingsModal open initialTab="ai" onOpenChange={() => {}} />);
  fireEvent.change(screen.getByLabelText('AWS account'), { target: { value: '11111111-1111-1111-1111-111111111111' } });
  fireEvent.click(screen.getByRole('button', { name: 'Discover models' }));
  fireEvent.change(await screen.findByLabelText('Search models'), { target: { value: 'Model B' } });
  expect(screen.queryByLabelText('Model A')).not.toBeInTheDocument();
  expect(screen.getByLabelText('Model B')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
  fireEvent.click(await screen.findByLabelText('Model A'));
  fireEvent.change(screen.getByLabelText('Search models'), { target: { value: 'Model B' } });
  expect(screen.getByLabelText('Model A')).toBeChecked();
  expect(screen.getByText('Selected for everyone')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
  const fetch = vi.spyOn(window, 'fetch').mockResolvedValue(new Response(JSON.stringify({ configured: true, provider: 'bedrock', models: [{ id: 'model-a', name: 'Model A' }] }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
  fireEvent.click(screen.getByRole('button', { name: 'Save for everyone' }));
  await waitFor(() => expect(fetch).toHaveBeenCalled());
  const save = fetch.mock.calls.find((call) => String(call[0]).includes('/api/ai/catalog') && (call[1] as RequestInit).method === 'PUT');
  const body = JSON.parse(String((save?.[1] as RequestInit).body)) as { models: unknown; account_id: string; api_key?: string };
  expect(body.models).toEqual([{ id: 'model-a', name: 'Model A' }]);
  expect(body.account_id).toBe('111111111111');
  expect(body.api_key).toBeUndefined();
});

it('drops a model list that arrives after the provider changes', async () => {
  let finish!: (result: unknown) => void;
  models.fetch.mockReset().mockReturnValueOnce(new Promise((resolve) => { finish = resolve; }));
  useAuthStore.setState({ config: { aws_access_mode: 'user' } as AuthConfig, me: { user_id: 'admin', tenant_id: 'tenant', email: 'admin@example.test', role: 'admin', method: 'password', expires_at: 9999999999 } });
  useInstancesStore.setState({ userRoles: [{ id: '11111111-1111-1111-1111-111111111111', name: 'DataCloud', label: 'Admin', accountID: '111111111111', live: true }] });
  render(<SettingsModal open initialTab="ai" onOpenChange={() => {}} />);
  fireEvent.change(screen.getByLabelText('AWS account'), { target: { value: '11111111-1111-1111-1111-111111111111' } });
  fireEvent.click(screen.getByRole('button', { name: 'Discover models' }));
  fireEvent.click(screen.getByRole('radio', { name: /OpenAI/i }));
  finish({ ok: true, data: [{ id: 'old-bedrock', name: 'Old Bedrock' }] });
  await waitFor(() => expect(screen.queryByLabelText('Old Bedrock')).not.toBeInTheDocument());
  expect(screen.getByLabelText('Provider base URL')).toBeInTheDocument();
  expect(screen.getByLabelText('Provider API key')).toBeInTheDocument();
});

it('allows configuring a custom base URL for OpenAI/Anthropic/Gemini in legacy mode', async () => {
  models.fetch.mockReset().mockResolvedValue({ ok: true, data: [] });
  useAuthStore.setState({ config: { aws_access_mode: 'profiles' } as AuthConfig, me: { user_id: 'admin', tenant_id: 'tenant', email: 'admin@example.test', role: 'admin', method: 'password', expires_at: 9999999999 } });
  useSettingsStore.setState({ aiProvider: 'openai', aiBaseUrl: 'https://llm.example.test/v1' });
  render(<SettingsModal open initialTab="ai" onOpenChange={() => {}} />);
  expect(await screen.findByDisplayValue('https://llm.example.test/v1')).toBeInTheDocument();
  useSettingsStore.setState({ aiProvider: 'bedrock', aiBaseUrl: '' });
});
