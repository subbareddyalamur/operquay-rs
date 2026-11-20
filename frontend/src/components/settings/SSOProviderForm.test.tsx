// @vitest-environment-options {"url":"https://desk.example/"}
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { SSOProviderForm } from './SSOProviderForm';
import { api } from '@/lib/api';

vi.mock('@/lib/api', () => ({ api: { post: vi.fn(), put: vi.fn() } }));
afterEach(() => { cleanup(); vi.resetAllMocks(); vi.unstubAllEnvs(); vi.unstubAllGlobals(); });

it('edits an OIDC provider without clearing its existing client secret', async () => {
  const editing = { id: 'work', label: 'Work', type: 'oidc' as const, issuer: 'https://idp.example', client_id: 'client', default_role: 'readonly' };
  vi.mocked(api.put).mockResolvedValue({ ok: true, data: { status: 'updated' } });
  render(<SSOProviderForm canManage editing={editing} onAdded={() => {}} />);
  expect(screen.getByRole('textbox', { name: 'Provider ID' })).toHaveAttribute('readonly');
  expect(screen.getByLabelText('Provider type')).toBeDisabled();
  fireEvent.change(screen.getByLabelText(/Display name/), { target: { value: 'New label' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save provider' }));
  await waitFor(() => expect(api.put).toHaveBeenCalledWith('/api/auth/providers/work', { label: 'New label' }));
});

it('does not update a provider when nothing changed', () => {
  const onCancel = vi.fn();
  render(<SSOProviderForm canManage editing={{ id: 'work', label: 'Work', type: 'saml', default_role: 'readonly' }} onAdded={() => {}} onCancel={onCancel} />);
  fireEvent.click(screen.getByRole('button', { name: 'Save provider' }));
  expect(api.put).not.toHaveBeenCalled();
  expect(onCancel).toHaveBeenCalled();
});

it('previews copyable SAML details from the configured URL before saving', async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });
  render(<SSOProviderForm canManage onAdded={() => {}} samlBaseURL="https://operquay.example:5443" />);
  fireEvent.click(screen.getByRole('button', { name: 'Add SSO provider' }));
  fireEvent.change(screen.getByLabelText('Provider type'), { target: { value: 'saml' } });
  expect(screen.getByText(/enter a provider id/i)).toBeInTheDocument();
  fireEvent.change(screen.getByRole('textbox', { name: 'Provider ID' }), { target: { value: 'work' } });
  const root = 'https://operquay.example:5443/api/auth/saml/work';
  for (const label of ['Entity ID / Audience URI', 'ACS (reply) URL', 'SP metadata URL', 'SLO response URL']) expect(screen.getByText(label)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Copy Entity ID / Audience URI' }));
  await waitFor(() => expect(writeText).toHaveBeenCalledWith(`${root}/metadata`));
  expect(screen.getByRole('button', { name: 'Copy ACS (reply) URL' })).toHaveTextContent(`${root}/acs`);
  expect(screen.getByRole('button', { name: 'Copy SLO response URL' })).toHaveTextContent(`${root}/slo`);
  expect(screen.getByText(/metadata.*available.*after.*saved/i)).toBeInTheDocument();
  expect(screen.getByText(/IdP-initiated logout.*not supported/i)).toBeInTheDocument();
  expect(screen.getByText(/POST the SAML response to the ACS URL, not the metadata URL/i)).toBeInTheDocument();
  expect(screen.getByText(/metadata from your identity provider, not Operquay/i)).toBeInTheDocument();
  expect(screen.getByText(/NameID.*unspecified.*email attribute or an email-shaped NameID/i)).toBeInTheDocument();
  expect(screen.getByText(/username is optional.*not stored/i)).toBeInTheDocument();
  fireEvent.change(screen.getByRole('textbox', { name: 'Provider ID' }), { target: { value: 'partners' } });
  expect(screen.getByRole('button', { name: 'Copy ACS (reply) URL' })).toHaveTextContent('https://operquay.example:5443/api/auth/saml/partners/acs');
  fireEvent.change(screen.getByRole('textbox', { name: 'Provider ID' }), { target: { value: 'INVALID!' } });
  expect(screen.queryByRole('button', { name: 'Copy ACS (reply) URL' })).not.toBeInTheDocument();
});

it('warns when the configured SAML URL is not HTTPS', () => {
  render(<SSOProviderForm canManage onAdded={() => {}} samlBaseURL="http://localhost:5000" />);
  fireEvent.click(screen.getByRole('button', { name: 'Add SSO provider' }));
  fireEvent.change(screen.getByLabelText('Provider type'), { target: { value: 'saml' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Provider ID' }), { target: { value: 'work' } });
  expect(screen.getByText(/HTTP weakens SAML browser binding/i)).toBeInTheDocument();
});

it('explains when the configured public URL is missing', () => {
  render(<SSOProviderForm canManage onAdded={() => {}} samlBaseURL="" />);
  fireEvent.click(screen.getByRole('button', { name: 'Add SSO provider' }));
  fireEvent.change(screen.getByLabelText('Provider type'), { target: { value: 'saml' } });
  expect(screen.getByText(/set PUBLIC_URL on the Operquay server/i)).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Copy ACS (reply) URL' })).not.toBeInTheDocument();
});

it('adds an OIDC provider with explicit admission policy', async () => {
  const onAdded = vi.fn();
  vi.mocked(api.post).mockResolvedValue({ ok: true, data: { status: 'added' } });
  render(<SSOProviderForm canManage onAdded={onAdded} />);
  fireEvent.click(screen.getByRole('button', { name: 'Add SSO provider' }));
  fireEvent.change(screen.getByRole('textbox', { name: 'Provider ID' }), { target: { value: 'work' } });
  fireEvent.change(screen.getByLabelText(/Display name/), { target: { value: 'Work' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Issuer URL' }), { target: { value: 'https://idp.example' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Client ID' }), { target: { value: 'client' } });
  fireEvent.change(screen.getByLabelText(/Client secret/), { target: { value: 'secret' } });
  fireEvent.click(screen.getByLabelText('Require verified email'));
  fireEvent.change(screen.getByLabelText('Other users'), { target: { value: 'readonly' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save provider' }));
  await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/auth/providers', expect.objectContaining({ id: 'work', type: 'oidc', client_secret: 'secret', require_email_verified: false, default_role: 'readonly' })));
  await waitFor(() => expect(onAdded).toHaveBeenCalled());
});

it('does not send credentials to an HTTP API from an HTTPS page', () => {
  vi.stubEnv('VITE_API_BASE', 'http://api.example');
  render(<SSOProviderForm canManage onAdded={() => {}} />);
  fireEvent.click(screen.getByRole('button', { name: 'Add SSO provider' }));
  fireEvent.change(screen.getByRole('textbox', { name: 'Provider ID' }), { target: { value: 'work' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Issuer URL' }), { target: { value: 'https://idp.example' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Client ID' }), { target: { value: 'client' } });
  fireEvent.change(screen.getByLabelText(/Client secret/), { target: { value: 'secret' } });
  fireEvent.change(screen.getByLabelText('Other users'), { target: { value: 'readonly' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save provider' }));
  expect(screen.getByRole('alert')).toHaveTextContent(/HTTPS is required/i);
  expect(api.post).not.toHaveBeenCalled();
});

it('explains when PostgreSQL is not configured', () => {
  render(<SSOProviderForm canManage={false} onAdded={() => {}} />);
  expect(screen.getByRole('button', { name: 'Add SSO provider' })).toBeDisabled();
  expect(screen.getByText(/PostgreSQL is required/)).toBeInTheDocument();
});

it('adds a SAML provider without sending OIDC credentials', async () => {
  const onAdded = vi.fn();
  vi.mocked(api.post).mockResolvedValue({ ok: true, data: { status: 'added' } });
  render(<SSOProviderForm canManage onAdded={onAdded} />);
  fireEvent.click(screen.getByRole('button', { name: 'Add SSO provider' }));
  fireEvent.change(screen.getByLabelText('Provider type'), { target: { value: 'saml' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Provider ID' }), { target: { value: 'company' } });
  fireEvent.change(screen.getByLabelText(/Display name/), { target: { value: 'Company' } });
  fireEvent.change(screen.getByLabelText(/Metadata URL/), { target: { value: 'https://idp.example/metadata' } });
  fireEvent.change(screen.getByLabelText(/Identity provider entity ID/), { target: { value: 'https://idp.example/entity' } });
  fireEvent.change(screen.getByLabelText(/Allowed groups/), { target: { value: 'ops, support' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save provider' }));
  await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/auth/providers', expect.objectContaining({ id: 'company', type: 'saml', metadata_url: 'https://idp.example/metadata', entity_id: 'https://idp.example/entity', viewer_groups: ['ops', 'support'] })));
  const body = vi.mocked(api.post).mock.calls[0][1] as Record<string, unknown>;
  expect(body.client_secret).toBeUndefined();
  expect(onAdded).toHaveBeenCalled();
});

it('marks only necessary OIDC fields required and permits an empty display name', async () => {
  vi.mocked(api.post).mockResolvedValue({ ok: true, data: { status: 'added' } });
  render(<SSOProviderForm canManage onAdded={() => {}} />);
  fireEvent.click(screen.getByRole('button', { name: 'Add SSO provider' }));
  for (const name of ['Provider ID', 'Issuer URL', 'Client ID']) expect(screen.getByRole('textbox', { name })).toBeRequired();
  expect(screen.getByLabelText(/Allowed groups/)).toBeRequired();
  fireEvent.change(screen.getByLabelText('Other users'), { target: { value: 'readonly' } });
  for (const name of [/Display name/, /Client secret/, /Allowed domains/, /Allowed groups/]) expect(screen.getByLabelText(name)).not.toBeRequired();
  fireEvent.change(screen.getByRole('textbox', { name: 'Provider ID' }), { target: { value: 'work' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Issuer URL' }), { target: { value: 'https://idp.example' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Client ID' }), { target: { value: 'client' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save provider' }));
  await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/auth/providers', expect.objectContaining({ label: '', default_role: 'readonly' })));
});

it('requires either SAML metadata URL or XML and enforces an admission choice', async () => {
  vi.mocked(api.post).mockResolvedValue({ ok: true, data: { status: 'added' } });
  render(<SSOProviderForm canManage onAdded={() => {}} />);
  fireEvent.click(screen.getByRole('button', { name: 'Add SSO provider' }));
  fireEvent.change(screen.getByLabelText('Provider type'), { target: { value: 'saml' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Provider ID' }), { target: { value: 'work' } });
  expect(screen.getByText(/provide either a metadata URL or metadata XML/i)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Save provider' }));
  expect(screen.getByRole('alert')).toHaveTextContent(/provide either.*metadata/i);
  expect(api.post).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText(/Metadata XML/), { target: { value: '<EntityDescriptor />' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save provider' }));
  expect(screen.getByRole('alert')).toHaveTextContent(/at least one.*group/i);
  expect(api.post).not.toHaveBeenCalled();
  fireEvent.change(screen.getByLabelText('Other users'), { target: { value: 'readonly' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save provider' }));
  await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/auth/providers', expect.objectContaining({ metadata_xml: '<EntityDescriptor />', metadata_url: '', default_role: 'readonly' })));
});

it('does not silently choose between a metadata URL and pasted XML', () => {
  render(<SSOProviderForm canManage onAdded={() => {}} />);
  fireEvent.click(screen.getByRole('button', { name: 'Add SSO provider' }));
  fireEvent.change(screen.getByLabelText('Provider type'), { target: { value: 'saml' } });
  fireEvent.change(screen.getByRole('textbox', { name: 'Provider ID' }), { target: { value: 'work' } });
  fireEvent.change(screen.getByLabelText(/Metadata URL/), { target: { value: 'https://idp.example/metadata' } });
  fireEvent.change(screen.getByLabelText(/Metadata XML/), { target: { value: '<EntityDescriptor />' } });
  fireEvent.click(screen.getByRole('button', { name: 'Save provider' }));
  expect(screen.getByRole('alert')).toHaveTextContent(/only one.*metadata/i);
  expect(api.post).not.toHaveBeenCalled();
});
