// @vitest-environment-options {"url":"http://localhost/"}
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { AdminPasswordForm } from './AdminPasswordForm';
import { UserRoles } from './UserRoles';
import { api } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';

vi.mock('@/lib/api', () => ({ api: { get: vi.fn(), post: vi.fn(), put: vi.fn() } }));
afterEach(() => { cleanup(); vi.resetAllMocks(); useAuthStore.setState({ me: null, config: null }); });

it('does not send a password change over HTTP', () => {
  useAuthStore.setState({ me: { user_id: 'admin', email: 'admin@local', role: 'admin', tenant_id: 'local', method: 'password', expires_at: 1 } });
  render(<AdminPasswordForm />);
  fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'current-password' } });
  fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'new-password-456' } });
  fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: 'new-password-456' } });
  fireEvent.click(screen.getByRole('button', { name: 'Change password' }));
  expect(screen.getByRole('alert')).toHaveTextContent(/HTTPS is required/i);
  expect(api.post).not.toHaveBeenCalled();
});

it('does not send a new user password over HTTP', async () => {
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: [] });
  render(<UserRoles currentUser="admin" />);
  await waitFor(() => expect(screen.getByRole('button', { name: 'Add local user' })).toBeEnabled());
  fireEvent.click(screen.getByRole('button', { name: 'Add local user' }));
  fireEvent.change(screen.getByLabelText('Email'), { target: { value: 'new@example.com' } });
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'test-password-123' } });
  fireEvent.click(screen.getByRole('button', { name: 'Create user' }));
  expect(screen.getByRole('alert')).toHaveTextContent(/HTTPS is required/i);
  expect(api.post).not.toHaveBeenCalled();
});
