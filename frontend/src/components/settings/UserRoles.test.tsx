// @vitest-environment-options {"url":"https://localhost/"}
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { UserRoles } from './UserRoles';
import { api } from '@/lib/api';
import { useAuthStore, type AuthConfig } from '@/stores/auth';
import type { APIError } from '@/lib/api';

vi.mock('@/lib/api', () => ({ api: { get: vi.fn(), put: vi.fn(), post: vi.fn(), delete: vi.fn() } }));
afterEach(() => { cleanup(); vi.resetAllMocks(); useAuthStore.setState({ config: null }); });

it('opens user edit only via the 3-dots menu inside a popup dialog, then edits, resets and confirms removal', async () => {
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: [{ id: 'alice', email: 'alice@example.com', name: 'Alice', provider: 'local', role: 'user' }] });
  vi.mocked(api.put).mockResolvedValue({ ok: true, data: {} });
  vi.mocked(api.post).mockResolvedValue({ ok: true, data: {} });
  vi.mocked(api.delete).mockResolvedValue({ ok: true, data: {} });
  render(<UserRoles currentUser="admin" />);

  // Clicking the row directly must not open the edit dialog
  fireEvent.click(await screen.findByText('alice@example.com'));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();

  // Open via 3-dots actions menu -> Edit
  fireEvent.click(screen.getByRole('button', { name: 'Actions for alice@example.com' }));
  fireEvent.click(screen.getByRole('menuitem', { name: 'Edit alice@example.com' }));

  const dialog = await screen.findByRole('dialog');
  expect(dialog).toBeInTheDocument();

  fireEvent.change(within(dialog).getByLabelText('Edit name'), { target: { value: 'Alicia' } });
  fireEvent.click(within(dialog).getByRole('button', { name: 'Save user' }));
  await waitFor(() => expect(api.put).toHaveBeenCalledWith('/api/users/alice', { email: 'alice@example.com', name: 'Alicia' }));

  fireEvent.click(within(dialog).getByRole('button', { name: 'Reset password for alice@example.com' }));
  fireEvent.change(within(dialog).getByLabelText('Replacement password'), { target: { value: 'new-password-123' } });
  fireEvent.click(within(dialog).getByRole('button', { name: 'Reset password' }));
  await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/users/alice/password', { new_password: 'new-password-123' }));

  fireEvent.click(within(dialog).getByRole('button', { name: 'Delete alice@example.com' }));
  expect(api.delete).not.toHaveBeenCalled();
  fireEvent.click(within(dialog).getByRole('button', { name: 'Confirm delete' }));
  await waitFor(() => expect(api.delete).toHaveBeenCalledWith('/api/users/alice'));
  expect(screen.queryByText('alice@example.com')).not.toBeInTheDocument();
});

it('shows users and lets an admin change another user role', async () => {
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: [{ id: 'admin', email: 'admin@local', role: 'admin' }, { id: 'alice', email: 'alice@example.com', role: 'readonly' }] });
  vi.mocked(api.put).mockResolvedValue({ ok: true, data: { status: 'updated' } });
  render(<UserRoles currentUser="admin" />);
  expect(await screen.findByLabelText('Role for admin@local')).toBeDisabled();
  fireEvent.change(screen.getByLabelText('Role for alice@example.com'), { target: { value: 'user' } });
  await waitFor(() => expect(api.put).toHaveBeenCalledWith('/api/users/alice/role', { role: 'user' }));
});

it.each([
  ['HTTPS is required', /HTTPS is required.*https:\/\/localhost:5443/i],
  ['admin role required', /administrator.*required/i],
  ['cross-site request refused', /cross-site/i],
])('shows the specific reason for a rejected user creation: %s', async (serverError, expected) => {
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: [] });
  vi.mocked(api.post).mockResolvedValue({ ok: false, error: { status: 403, message: JSON.stringify({ error: serverError }) } as APIError });
  render(<UserRoles currentUser="admin" />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Add local user' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Add local user' }));
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'test-password-123' } });
  fireEvent.click(screen.getByRole('button', { name: 'Create user' }));
  expect(await screen.findByRole('alert')).toHaveTextContent(expected);
});

it('sends an explicit local sign-in opt-in only when available', async () => {
  useAuthStore.setState({ config: { local: 'admin', local_user_opt_in_allowed: true } as AuthConfig });
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: [] });
  vi.mocked(api.post).mockResolvedValue({ ok: true, data: { user: { id: 'new', email: 'new@example.com', role: 'readonly' } } });
  render(<UserRoles currentUser="admin" />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Add local user' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Add local user' }));
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'test-password-123' } });
  fireEvent.click(screen.getByLabelText('Allow this account to sign in with a local password'));
  fireEvent.click(screen.getByRole('button', { name: 'Create user' }));
  await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/users', { email: 'new@example.com', name: '', password: 'test-password-123', role: 'readonly', local_signin_enabled: true }));
});

it('creates a local user with an explicit role and clears the password', async () => {
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: [] });
  vi.mocked(api.post).mockResolvedValue({ ok: true, data: { user: { id: 'new', email: 'new@example.com', name: 'New', role: 'readonly' }, local_login: 'all' } });
  render(<UserRoles currentUser="admin" />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Add local user' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Add local user' }));
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
  fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'New' } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'test-password-123' } });
  fireEvent.click(screen.getByRole('button', { name: 'Create user' }));
  await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/users', { email: 'new@example.com', name: 'New', password: 'test-password-123', role: 'readonly', local_signin_enabled: false }));
  expect(await screen.findByText('new@example.com')).toBeInTheDocument();
  expect(screen.queryByLabelText('Password')).not.toBeInTheDocument();
});

it('toggles user disable and enable status from the user edit modal', async () => {
  vi.mocked(api.get).mockResolvedValue({
    ok: true,
    data: [{ id: 'alice', email: 'alice@example.com', name: 'Alice', provider: 'local', role: 'user', disabled: false }],
  });
  vi.mocked(api.put).mockResolvedValue({ ok: true, data: { status: 'updated', disabled: true } });
  render(<UserRoles currentUser="admin" />);

  expect(await screen.findByText('Active')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Actions for alice@example.com' }));
  fireEvent.click(screen.getByRole('menuitem', { name: 'Edit alice@example.com' }));

  const dialog = await screen.findByRole('dialog');
  fireEvent.click(within(dialog).getByRole('button', { name: 'Disable user' }));
  await waitFor(() => expect(api.put).toHaveBeenCalledWith('/api/users/alice/status', { disabled: true }));
  expect(await within(dialog).findByText('Disabled')).toBeInTheDocument();

  fireEvent.click(within(dialog).getByRole('button', { name: 'Enable user' }));
  await waitFor(() => expect(api.put).toHaveBeenCalledWith('/api/users/alice/status', { disabled: false }));
  fireEvent.click(within(dialog).getByRole('button', { name: 'Close dialog' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
  expect(screen.getByText('Active')).toBeInTheDocument();
});
