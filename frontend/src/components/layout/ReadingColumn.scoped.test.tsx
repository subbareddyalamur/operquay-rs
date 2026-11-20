// @vitest-environment-options {"url":"https://desk.example/"}
import { act, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { ReadingColumn } from './ReadingColumn';
import { api } from '@/lib/api';
import { useAuthStore, type AuthConfig } from '@/stores/auth';
import { useLayoutStore } from '@/stores/layout';
import { useSessionsStore } from '@/stores/sessions';
import { useInstancesStore } from '@/stores/instances';

vi.hoisted(() => {
  const data = new Map<string, string>();
  const storage = { getItem: (key: string) => data.get(key) ?? null, setItem: (key: string, value: string) => { data.set(key, value); }, removeItem: (key: string) => { data.delete(key); } };
  vi.stubGlobal('localStorage', storage);
  vi.stubGlobal('sessionStorage', storage);
});
vi.mock('@/lib/api', () => ({ api: { get: vi.fn() } }));
vi.mock('@/components/ai/AIChatPanel', () => ({ AIChatPanel: () => null }));

afterEach(() => {
  useSessionsStore.setState({ sessions: [], activeId: null });
  useLayoutStore.getState().closeDetails();
  useAuthStore.setState({ config: null, me: null });
  useInstancesStore.getState().clearUserRoles();
  vi.resetAllMocks();
});

it('loads details with the active scoped role, even when another role has the same instance id', async () => {
  useAuthStore.setState({ config: { aws_access_mode: 'user' } as AuthConfig, me: { user_id: 'user', tenant_id: 'tenant', email: 'user@example.test', role: 'user', method: 'password', expires_at: 9999999999 } });
  useInstancesStore.setState({ userRoles: [{ id: 'role-a', name: 'A', label: 'A', live: true }, { id: 'role-b', name: 'B', label: 'B', live: true }] });
  useSessionsStore.setState({ sessions: [
    { id: 'a', type: 'ssh', instanceId: 'i-example', instanceName: 'A', status: 'connected', createdAt: 1, userSSH: { roleID: 'role-a', region: 'us-east-1' } },
    { id: 'b', type: 'ssh', instanceId: 'i-example', instanceName: 'B', status: 'connected', createdAt: 2, userSSH: { roleID: 'role-b', region: 'us-west-2' } },
  ], activeId: 'a' });
  vi.mocked(api.get).mockImplementation(async (path) => path.startsWith('/api/aws/instance-metrics?')
    ? { ok: true, data: { cpu_load: 0.5, cpu_count: 2, mem_used_pct: 30, disk_used_pct: 40 } }
    : { ok: true, data: { instance_id: 'i-example', name: 'Example', platform: 'linux', tags: {}, security_group_details: [{ group_id: 'sg-1', group_name: 'example' }] } });
  useLayoutStore.getState().showDetails('i-example');
  render(<ReadingColumn />);
  await waitFor(() => expect(api.get).toHaveBeenCalledWith('/api/aws/instance-details?binding_id=role-a&region=us-east-1&instance_id=i-example'));
  expect(screen.getByRole('complementary', { name: 'Instance details' })).toHaveTextContent('Example');
  expect(screen.getAllByText('None')).toHaveLength(2);
  await waitFor(() => expect(api.get).toHaveBeenCalledWith('/api/aws/instance-metrics?binding_id=role-a&region=us-east-1&instance_id=i-example'));
  expect(await screen.findByText('30%')).toBeVisible();
  act(() => useSessionsStore.setState({ activeId: 'b' }));
  await waitFor(() => expect(api.get).toHaveBeenCalledWith('/api/aws/instance-details?binding_id=role-b&region=us-west-2&instance_id=i-example'));
  expect(vi.mocked(api.get).mock.calls.every(([path]) => path.startsWith('/api/aws/instance-details?') || path.startsWith('/api/aws/instance-metrics?'))).toBe(true);
  act(() => useSessionsStore.setState({ activeId: null }));
  await waitFor(() => expect(screen.queryByRole('complementary', { name: 'Instance details' })).not.toBeInTheDocument());
  expect(vi.mocked(api.get).mock.calls.every(([path]) => path.startsWith('/api/aws/instance-details?') || path.startsWith('/api/aws/instance-metrics?'))).toBe(true);
});

it('opens inventory details for a signed-in readonly user without an active terminal', async () => {
  useAuthStore.setState({ config: { aws_access_mode: 'user' } as AuthConfig, me: { user_id: 'reader', tenant_id: 'tenant', email: 'reader@example.test', role: 'readonly', method: 'password', expires_at: 9999999999 } });
  useInstancesStore.setState({ userRoles: [{ id: 'role-a', name: 'A', label: 'A', live: true }] });
  useSessionsStore.setState({ sessions: [], activeId: null });
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: { instance_id: 'i-example', name: 'Example', platform: 'linux', tags: {} } });
  useLayoutStore.getState().showDetails('i-example', { roleID:'role-a', region:'us-east-1', name:'Example', userID:'reader', tenantID:'tenant' });
  render(<ReadingColumn />);
  await waitFor(() => expect(api.get).toHaveBeenCalledWith('/api/aws/instance-details?binding_id=role-a&region=us-east-1&instance_id=i-example'));
  expect(screen.getByText('Instance metrics are not available.')).toBeInTheDocument();
  expect(vi.mocked(api.get).mock.calls.some(([path]) => path.includes('instance-metrics'))).toBe(false);
  act(() => useAuthStore.setState({ me: { user_id:'different', tenant_id:'tenant', email:'different@example.test', role:'user', method:'password', expires_at:9999999999 } }));
  await waitFor(() => expect(screen.queryByRole('complementary', { name: 'Instance details' })).not.toBeInTheDocument());
  expect(api.get).toHaveBeenCalledTimes(1);
});

it('opens details for a sidebar instance using the connected role that scanned it', async () => {
  const { useInstancesStore } = await import('@/stores/instances');
  useAuthStore.setState({ config: { aws_access_mode: 'user' } as AuthConfig, me: { user_id: 'user', tenant_id: 'tenant', email: 'user@example.test', role: 'user', method: 'password', expires_at: 9999999999 } });
  useInstancesStore.setState({
    userRoles: [{ id: 'role-prod', name: 'Prod', label: 'Prod', live: true }],
    instanceRoles: { 'i-prod': 'role-prod' },
    accounts: [{ account_id: '333333333333', account_alias: 'Production', profile: '', regions: [{ region: 'eu-west-1', groups: [{ tag1: '', tag2: '', instances: [{ instance_id: 'i-prod', name: 'Prod', state: 'running', platform: 'linux', os: '', instance_type: 't3.micro', aws_profile: '', aws_region: 'eu-west-1', account_id: '333333333333', account_alias: '', tag1_value: '', tag2_value: '', private_ip: '10.0.0.2' }] }] }] }],
  });
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: { instance_id: 'i-prod', name: 'Prod', platform: 'linux', tags: {} } });
  useLayoutStore.getState().showDetails('i-prod');
  render(<ReadingColumn />);
  await waitFor(() => expect(api.get).toHaveBeenCalledWith('/api/aws/instance-details?binding_id=role-prod&region=eu-west-1&instance_id=i-prod'));
  useInstancesStore.setState({ instanceRoles: {}, accounts: [] });
});

it('hides details and discards a late response after a role expires', async () => {
  useAuthStore.setState({ config: { aws_access_mode: 'user' } as AuthConfig, me: { user_id: 'reader', tenant_id: 'tenant', email: 'reader@example.test', role: 'readonly', method: 'password', expires_at: 9999999999 } });
  useInstancesStore.setState({ userRoles: [{ id: 'role-a', name: 'A', label: 'A', live: true }] });
  let finish: (v: unknown) => void = () => undefined;
  vi.mocked(api.get).mockReturnValueOnce(new Promise(resolve => { finish = resolve as typeof finish; }));
  useLayoutStore.getState().showDetails('i-example', { roleID: 'role-a', region: 'us-east-1', name: 'Example', userID: 'reader', tenantID: 'tenant' });
  render(<ReadingColumn />);
  act(() => useInstancesStore.setState({ userRoles: [{ id: 'role-a', name: 'A', label: 'A', live: false }] }));
  act(() => finish({ ok: true, data: { instance_id: 'i-example', name: 'Secret instance', platform: 'linux', tags: {} } }));
  await waitFor(() => expect(screen.queryByText('Secret instance')).not.toBeInTheDocument());
  expect(screen.queryByRole('complementary', { name: 'Instance details' })).not.toBeInTheDocument();
});
