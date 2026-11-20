import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { DeskPage } from './DeskPages';
import { SettingsModal } from '@/components/settings/SettingsModal';
import { useAuthStore } from '@/stores/auth';
import { useLayoutStore } from '@/stores/layout';

const { saveToServer } = vi.hoisted(() => ({ saveToServer: vi.fn().mockResolvedValue(true) }));
vi.mock('@/stores/settings', () => ({ DEFAULT_ASSISTANT_NAME: 'Oi', useSettingsStore: (select: (s: unknown) => unknown) => select({ scrollbackLines: 1000, setScrollbackLines: vi.fn(), assistantName: 'Oi', setAssistantName: vi.fn(), saveToServer }) }));
vi.mock('@/stores/theme', () => ({ useThemeStore: vi.fn() }));
vi.mock('@/components/settings/UserRoles', () => ({ UserRoles: () => <div>Users and roles</div> }));
vi.mock('@/components/settings/OwnPasswordForm', () => ({ OwnPasswordForm: () => null }));
vi.mock('@/components/dashboard/FleetDashboard', () => ({ FleetDashboard: () => null }));
vi.mock('@/components/modals/AuditLogModal', () => ({ AuditLogModal: () => null }));
vi.mock('@/components/recordings/RecordingsModal', () => ({ RecordingsModal: () => null }));

function Desk() {
  const view = useLayoutStore((s) => s.view);
  return view === 'settings' ? <DeskPage /> : <><div>Fleet</div><button type="button" onClick={() => useLayoutStore.getState().openSettings('users')}>Admin</button></>;
}

function signInAsAdmin() {
  useAuthStore.setState({ me: { user_id: 'admin', email: 'admin@example.com', role: 'admin', tenant_id: 'local', method: 'password', expires_at: 9999999999 } });
}

afterEach(() => {
  cleanup();
  useAuthStore.setState({ me: null });
  useLayoutStore.setState({ view: 'session', returnView: 'session', settingsTab: 'appearance' });
  saveToServer.mockClear();
});

it('keeps Administration navigation available after saving', async () => {
  signInAsAdmin();
  render(<Desk />);
  fireEvent.click(screen.getByRole('button', { name: 'Admin' }));
  fireEvent.click(screen.getByRole('button', { name: 'General' }));
  fireEvent.click(screen.getByRole('button', { name: /^Save$/ }));
  await waitFor(() => expect(saveToServer).toHaveBeenCalledTimes(1));
  expect(await screen.findByRole('status')).toHaveTextContent(/settings saved/i);
  await waitFor(() => expect(screen.getByRole('button', { name: /^Save$/ })).toBeEnabled());
  expect(screen.getByRole('navigation', { name: 'Settings navigation' })).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Users' }));
  expect(screen.getByText('Users and roles')).toBeInTheDocument();
});

it.each(['Cancel', 'Close settings', 'Back to workspace'])('returns to the workspace when closing settings with %s', (button) => {
  signInAsAdmin();
  render(<Desk />);
  fireEvent.click(screen.getByRole('button', { name: 'Admin' }));
  fireEvent.click(screen.getByRole('button', { name: 'General' }));
  fireEvent.click(screen.getByRole('button', { name: button }));
  expect(screen.getByText('Fleet')).toBeInTheDocument();
  expect(useLayoutStore.getState().view).toBe('session');
});

it('returns to Kubernetes when Settings was opened from there', () => {
  signInAsAdmin();
  useLayoutStore.setState({ view: 'kubernetes' });
  useLayoutStore.getState().openSettings('audit');
  useLayoutStore.getState().closeSettings();
  expect(useLayoutStore.getState().view).toBe('kubernetes');
});

it('groups operations with administration for admins only and omits Tools', () => {
  signInAsAdmin();
  render(<Desk />);
  fireEvent.click(screen.getByRole('button', { name: 'Admin' }));
  for (const group of ['Personal', 'Operations', 'Administration']) expect(screen.getByRole('group', { name: group })).toBeInTheDocument();
  expect(screen.queryByRole('group', { name: 'Tools' })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Back to workspace' }));
  useAuthStore.setState({ me: { user_id: 'u', email: 'u@example.com', role: 'user', tenant_id: 'local', method: 'password', expires_at: 9999999999 } });
  act(() => useLayoutStore.getState().openSettings('general'));
  expect(screen.getByRole('group', { name: 'Personal' })).toBeInTheDocument();
  for (const group of ['Operations', 'Tools', 'Administration']) expect(screen.queryByRole('group', { name: group })).not.toBeInTheDocument();
});

it('still closes settings dialogs after saving', async () => {
  signInAsAdmin();
  const onOpenChange = vi.fn();
  render(<SettingsModal open initialTab="general" onOpenChange={onOpenChange} />);
  fireEvent.click(screen.getByRole('button', { name: /^Save$/ }));
  await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false));
  expect(saveToServer).toHaveBeenCalledTimes(1);
});

it('reports a failed save and allows retry without closing Administration', async () => {
  signInAsAdmin();
  saveToServer.mockResolvedValueOnce(false);
  render(<Desk />);
  fireEvent.click(screen.getByRole('button', { name: 'Admin' }));
  fireEvent.click(screen.getByRole('button', { name: 'General' }));
  fireEvent.click(screen.getByRole('button', { name: /^Save$/ }));
  expect(await screen.findByRole('alert')).toHaveTextContent(/could not save/i);
  expect(screen.getByRole('button', { name: 'Users' })).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /^Save$/ }));
  await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument());
  expect(saveToServer).toHaveBeenCalledTimes(2);
});

it('does not close settings dialogs after a failed save', async () => {
  signInAsAdmin();
  saveToServer.mockResolvedValueOnce(false);
  const onOpenChange = vi.fn();
  render(<SettingsModal open initialTab="general" onOpenChange={onOpenChange} />);
  fireEvent.click(screen.getByRole('button', { name: /^Save$/ }));
  expect(await screen.findByRole('alert')).toHaveTextContent(/could not save/i);
  expect(onOpenChange).not.toHaveBeenCalled();
});

it('shows Save only on pages whose changes it saves', () => {
  signInAsAdmin();
  render(<Desk />);
  fireEvent.click(screen.getByRole('button', { name: 'Admin' }));
  expect(screen.queryByRole('button', { name: /^Save$/ })).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'General' }));
  expect(screen.getByRole('button', { name: /^Save$/ })).toBeInTheDocument();
});
