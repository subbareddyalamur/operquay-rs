// @vitest-environment-options {"url":"https://localhost/"}
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { AdminPasswordForm } from './AdminPasswordForm';
import { useAuthStore } from '@/stores/auth';
import { api } from '@/lib/api';

vi.mock('@/lib/api', () => ({ api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() } }));

afterEach(() => {
  cleanup();
  vi.resetAllMocks();
  useAuthStore.setState({ me: null });
});

it('lets the local administrator change the password and signs them out', async () => {
  const load = vi.fn().mockResolvedValue(undefined);
  useAuthStore.setState({ me: { user_id: 'admin', email: 'admin@local', role: 'admin', tenant_id: 'local', method: 'password', expires_at: 1 }, load });
  vi.mocked(api.post).mockResolvedValue({ ok: true, data: { status: 'password changed' } });
  render(<AdminPasswordForm />);
  fireEvent.change(await screen.findByLabelText('Current password'), { target: { value: 'current-password' } });
  fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'new-password-456' } });
  fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: 'new-password-456' } });
  fireEvent.click(screen.getByRole('button', { name: 'Change password' }));
  await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/auth/admin-password', { current_password: 'current-password', new_password: 'new-password-456' }));
  await waitFor(() => expect(load).toHaveBeenCalled());
});

it('does not offer local admin password changes to other accounts', () => {
  useAuthStore.setState({ me: { user_id: 'operator', email: 'operator@example.com', role: 'user', tenant_id: 'local', method: 'password', expires_at: 1 } });
  render(<AdminPasswordForm />);
  expect(screen.queryByRole('button', { name: 'Change password' })).toBeNull();
});
