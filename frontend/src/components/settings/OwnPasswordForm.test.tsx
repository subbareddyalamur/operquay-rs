import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { OwnPasswordForm } from './OwnPasswordForm';
import { api } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';

vi.mock('@/lib/api', () => ({ api: { post: vi.fn() } }));
afterEach(() => { cleanup(); vi.resetAllMocks(); useAuthStore.setState({ me: null }); });
it('allows a read-only local user to change their password', async () => {
  useAuthStore.setState({ me: { user_id: 'alice', email: 'alice@example.com', role: 'readonly', tenant_id: 'local', method: 'password', expires_at: 1 } });
  vi.mocked(api.post).mockResolvedValue({ ok: true, data: {} });
  render(<OwnPasswordForm />);
  fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'old-password-123' } });
  fireEvent.change(screen.getByLabelText('New password'), { target: { value: 'new-password-123' } });
  fireEvent.change(screen.getByLabelText('Confirm new password'), { target: { value: 'new-password-123' } });
  fireEvent.click(screen.getByRole('button', { name: 'Change password' }));
  await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/auth/password', { current_password: 'old-password-123', new_password: 'new-password-123' }));
  expect(useAuthStore.getState().expired).toBe(true);
});
it('does not offer a local password form to an SSO user', () => {
  useAuthStore.setState({ me: { user_id: 'sso', email: 'sso@example.com', role: 'user', tenant_id: 'local', method: 'sso', expires_at: 1 } });
  render(<OwnPasswordForm />);
  expect(screen.queryByRole('button', { name: 'Change password' })).not.toBeInTheDocument();
});
// @vitest-environment-options {"url":"https://desk.example/"}
