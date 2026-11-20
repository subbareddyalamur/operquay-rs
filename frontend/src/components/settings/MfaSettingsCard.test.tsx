import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { MfaSettingsCard } from './MfaSettingsCard';
import { api } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';

vi.mock('@/lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    delete: vi.fn(),
  },
}));

afterEach(() => {
  cleanup();
  vi.resetAllMocks();
  useAuthStore.setState({ me: null });
});

it('enrolls TOTP, displays recovery codes, and disables TOTP cleanly', async () => {
  const loadMock = vi.fn().mockResolvedValue(undefined);
  useAuthStore.setState({
    me: {
      user_id: 'alice',
      email: 'alice@example.com',
      role: 'admin',
      tenant_id: 'default',
      method: 'password',
      expires_at: 9999999999,
      mfa_enabled: false,
    },
    load: loadMock,
  });

  vi.mocked(api.get)
    .mockResolvedValueOnce({
      ok: true,
      data: { mfa_enabled: false, totp_enabled: false, recovery_codes_remaining: 0, passkeys: [] },
    })
    .mockResolvedValueOnce({
      ok: true,
      data: { mfa_enabled: true, totp_enabled: true, recovery_codes_remaining: 8, passkeys: [] },
    })
    .mockResolvedValueOnce({
      ok: true,
      data: { mfa_enabled: false, totp_enabled: false, recovery_codes_remaining: 0, passkeys: [] },
    });

  vi.mocked(api.post)
    .mockResolvedValueOnce({
      ok: true,
      data: {
        secret: 'JBSWY3DPEHPK3PXP',
        otpauth_url: 'otpauth://totp/Operquay:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Operquay',
      },
    })
    .mockResolvedValueOnce({
      ok: true,
      data: {
        enabled: true,
        recovery_codes: ['AAAA-1111', 'BBBB-2222', 'CCCC-3333', 'DDDD-4444', 'EEEE-5555', 'FFFF-6666', 'GGGG-7777', 'HHHH-8888'],
      },
    })
    .mockResolvedValueOnce({
      ok: true,
      data: { enabled: false },
    });

  render(<MfaSettingsCard />);

  await waitFor(() => expect(screen.getByRole('button', { name: 'Set up authenticator app' })).toBeInTheDocument());
  fireEvent.click(screen.getByRole('button', { name: 'Set up authenticator app' }));

  await waitFor(() => expect(screen.getByText('JBSWY3DPEHPK3PXP')).toBeInTheDocument());
  fireEvent.change(screen.getByLabelText('Verification code'), { target: { value: '123456' } });
  fireEvent.click(screen.getByRole('button', { name: 'Verify & enable' }));

  await waitFor(() => expect(screen.getByText('AAAA-1111')).toBeInTheDocument());
  expect(screen.getByText('HHHH-8888')).toBeInTheDocument();
  expect(loadMock).toHaveBeenCalled();

  fireEvent.click(screen.getByRole('button', { name: 'Disable authenticator' }));
  fireEvent.change(screen.getByLabelText('Current password'), { target: { value: 'AdminStrong#2026' } });
  fireEvent.change(screen.getByLabelText('Authenticator or recovery code'), { target: { value: 'AAAA-1111' } });
  fireEvent.click(screen.getByRole('button', { name: 'Confirm disable' }));

  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith('/api/auth/mfa/totp/disable', {
      current_password: 'AdminStrong#2026',
      code: 'AAAA-1111',
    }),
  );
  await waitFor(() => expect(screen.getByText('Not configured')).toBeInTheDocument());
});
