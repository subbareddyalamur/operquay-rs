import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { SettingsModal } from './SettingsModal';
import { useAuthStore } from '@/stores/auth';

vi.mock('@/stores/settings', () => ({ DEFAULT_ASSISTANT_NAME: 'Oi', useSettingsStore: (select: (s: unknown) => unknown) => select({ compactMode: false, setCompactMode: vi.fn(), scrollbackLines: 1000, setScrollbackLines: vi.fn(), saveToServer: vi.fn() }) }));
vi.mock('@/stores/theme', () => ({ useThemeStore: vi.fn() }));
vi.mock('./OwnPasswordForm', () => ({ OwnPasswordForm: () => <span>My password</span> }));
afterEach(() => { cleanup(); useAuthStore.setState({ me: null }); });

it.each(['user', 'readonly'] as const)('hides administrator settings from %s', role => {
  useAuthStore.setState({ me: { user_id: role, email: 'user@example.com', role, tenant_id: 'local', method: 'password', expires_at: 1 } });
  render(<SettingsModal open initialTab="general" onOpenChange={() => {}} />);
  expect(screen.getByText('My password')).toBeInTheDocument();
  for (const name of ['Fleet Map', 'Diagram Board', 'AWS Accounts', 'Single Sign On', 'Groups & Roles', 'Recording', 'Database Viewer']) expect(screen.queryByText(name)).not.toBeInTheDocument();
});

it('shows administrator controls and names the SSO and Groups tabs', () => {
  useAuthStore.setState({ me: { user_id: 'admin', email: 'admin@local', role: 'admin', tenant_id: 'local', method: 'password', expires_at: 1 } });
  render(<SettingsModal open initialTab="general" onOpenChange={() => {}} />);
  expect(screen.getByText('Single Sign On')).toBeInTheDocument();
  expect(screen.getByText('Groups & Roles')).toBeInTheDocument();
  for (const name of ['Fleet Map', 'Diagram Board']) expect(screen.queryByText(name)).not.toBeInTheDocument();
  expect(screen.queryByText('S3 Bucket (Express Upload/Download)')).not.toBeInTheDocument();
});
