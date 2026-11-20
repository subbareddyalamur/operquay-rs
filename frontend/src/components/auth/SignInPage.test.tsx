import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import { SignInPage } from './SignInPage';
import { useAuthStore, type AuthConfig } from '@/stores/auth';

const config = {
  required: true,
  local: 'all',
  sso: { enabled: false, providers: [] },
  session_hours: 8,
  idle_minutes: 60,
  aws_access_mode: 'profiles',
  version: '0.0.1',
  revision: 'b1227ec39574-dirty',
} as AuthConfig;

afterEach(() => {
  cleanup();
  useAuthStore.setState({ config: null, expired: false, mfaChallenge: null });
});

it('shows build identity and explains unavailable SSO without the removed labels', () => {
  useAuthStore.setState({ config, expired: false });
  render(<SignInPage />);
  expect(screen.getByText('Operquay')).toBeInTheDocument();
  expect(screen.queryByText('Sessions are recorded in the audit log.')).toBeNull();
  expect(screen.queryByText(/Sessions last up to/)).toBeNull();
  expect(screen.getByRole('button', { name: 'Single sign-on (not configured)' })).toBeDisabled();
  expect(screen.getByText('v0.0.1:b1227ec')).toBeInTheDocument();
  expect(screen.getByText('dirty')).toBeInTheDocument();
});

it('does not invent a commit when build metadata is unavailable', () => {
  useAuthStore.setState({ config: { ...config, version: 'v0.0.1', revision: 'unknown' } });
  render(<SignInPage />);
  expect(screen.getByText('v0.0.1:unknown')).toBeInTheDocument();
  expect(screen.queryByText('dirty')).toBeNull();
});

it('keeps configured provider and break-glass access', () => {
  useAuthStore.setState({ config: { ...config, local: 'admin', sso: { enabled: true, providers: [{ id: 'work', label: 'Work', type: 'oidc' }] } } });
  render(<SignInPage />);
  expect(screen.getByRole('button', { name: /Continue with Work/ })).toBeEnabled();
  expect(screen.getByRole('button', { name: 'Break-glass administrator' })).toBeEnabled();
  expect(screen.queryByRole('button', { name: 'Single sign-on (not configured)' })).toBeNull();
});

it('makes opted-in local sign-in discoverable with SSO', () => {
  useAuthStore.setState({ config: { ...config, local: 'admin', local_user_opt_in_allowed: true, sso: { enabled: true, providers: [{ id: 'work', label: 'Work', type: 'oidc' }] } } });
  render(<SignInPage />);
  fireEvent.click(screen.getByRole('button', { name: 'Sign in with a local account' }));
  expect(screen.getByText(/accounts explicitly enabled/)).toBeInTheDocument();
});

it('keeps the session-expired message when needed', () => {
  useAuthStore.setState({ config, expired: true });
  render(<SignInPage />);
  expect(screen.getByText('Your session ended. Sign in again to continue.')).toBeInTheDocument();
});

it('prompts for TOTP or recovery verification when mfaChallenge is active', () => {
  useAuthStore.setState({
    config,
    mfaChallenge: { challengeToken: 'chal-1', methods: ['totp', 'recovery'], email: 'alice@example.com' },
  });
  render(<SignInPage />);
  expect(screen.getByText('Two-factor verification')).toBeInTheDocument();
  expect(screen.getByText('alice@example.com')).toBeInTheDocument();
  expect(screen.getByLabelText('Authenticator code')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Use a recovery code' }));
  expect(screen.getByLabelText('Recovery code')).toBeInTheDocument();
});
