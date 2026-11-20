// @vitest-environment-options {"url":"https://desk.example/"}
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { SettingsModal } from './SettingsModal';
import { api } from '@/lib/api';
import { useAuthStore } from '@/stores/auth';

vi.mock('@/lib/api', () => ({ api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() } }));
vi.mock('@/stores/settings', () => ({ useSettingsStore: (select: (s: unknown) => unknown) => select({ saveToServer: vi.fn() }) }));
vi.mock('@/stores/theme', () => ({ useThemeStore: vi.fn() }));

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.resetAllMocks(); useAuthStore.setState({ me: null }); });

it('shows a SAML setup preview on the empty sign-in page', async () => {
  useAuthStore.setState({ me: { user_id: 'admin', email: 'admin@local', role: 'admin', tenant_id: 'local', method: 'password', expires_at: 1 } });
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: { providers: [], local: 'all', can_manage: true, saml_base_url: 'https://configured.example' } });
  render(<SettingsModal open initialTab="signin" onOpenChange={() => {}} />);
  expect(await screen.findByText('https://<host.example.com>/api/auth/saml/<provider-id>/acs')).toBeInTheDocument();
  expect(screen.queryByText(/Add SAML or OIDC providers here/)).not.toBeInTheDocument();
  fireEvent.click(await screen.findByRole('button', { name: 'Add SSO provider' }));
  fireEvent.change(screen.getByLabelText('Provider type'), { target: { value: 'saml' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Provider ID' }), { target: { value: 'work' } });
  expect(screen.getByRole('button', { name: 'Copy ACS (reply) URL' })).toHaveTextContent('https://configured.example/api/auth/saml/work/acs');
});

it('edits a stored provider without resending its metadata or secret and confirms deletion', async () => {
  useAuthStore.setState({ me: { user_id: 'admin', email: 'admin@local', role: 'admin', tenant_id: 'local', method: 'password', expires_at: 1 } });
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: { providers: [{ id: 'work', label: 'Work', type: 'saml', editable: true, viewer_groups: ['support'] }], local: 'all', can_manage: true, saml_base_url: 'https://configured.example' } });
  vi.mocked(api.put).mockResolvedValue({ ok: true, data: { status: 'updated' } });
  vi.mocked(api.delete).mockResolvedValue({ ok: true, data: { status: 'deleted' } });
  render(<SettingsModal open initialTab="signin" onOpenChange={() => {}} />);
  fireEvent.click(await screen.findByRole('button', { name: 'Edit Work' }));
  fireEvent.change(screen.getByLabelText(/Display name/), { target: { value: 'Work SSO' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save provider' }));
  await waitFor(() => expect(api.put).toHaveBeenCalledWith('/api/auth/providers/work', { label: 'Work SSO' }));
  const confirm = vi.spyOn(window, 'confirm').mockReturnValueOnce(false).mockReturnValueOnce(true);
  fireEvent.click(await screen.findByRole('button', { name: 'Delete Work' }));
  expect(api.delete).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: 'Delete Work' }));
  await waitFor(() => expect(api.delete).toHaveBeenCalledWith('/api/auth/providers/work'));
  expect(confirm).toHaveBeenCalledTimes(2);
});

it('does not offer edits for an externally managed provider', async () => {
  useAuthStore.setState({ me: { user_id: 'admin', email: 'admin@local', role: 'admin', tenant_id: 'local', method: 'password', expires_at: 1 } });
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: { providers: [{ id: 'env', label: 'Environment', type: 'oidc', editable: false }], local: 'all', can_manage: true } });
  render(<SettingsModal open initialTab="signin" onOpenChange={() => {}} />);
  expect(await screen.findByText('Managed outside settings')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Delete Environment' })).not.toBeInTheDocument();
});

it('shows the saved provider’s supplied SLO URL', async () => {
  useAuthStore.setState({ me: { user_id: 'admin', email: 'admin@local', role: 'admin', tenant_id: 'local', method: 'password', expires_at: 1 } });
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: { providers: [{ id: 'work', label: 'Work', type: 'saml', saml: { entity_id: 'https://configured.example/metadata', acs_url: 'https://configured.example/acs', metadata_url: 'https://configured.example/metadata', slo_url: 'https://configured.example/slo', certificate_sha256: 'ABC' } }], local: 'all', can_manage: true, saml_base_url: 'https://configured.example' } });
  render(<SettingsModal open initialTab="signin" onOpenChange={() => {}} />);
  expect(await screen.findByRole('button', { name: 'Copy SLO response URL' })).toHaveTextContent('https://configured.example/slo');
  expect(screen.getByRole('button', { name: 'Copy Entity ID / Audience URI' })).toHaveTextContent('https://configured.example/metadata');
});
