import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CloudConnections, normalizeStartURL } from './CloudConnections';
import { useSessionsStore } from '@/stores/sessions';
import { useAuthStore } from '@/stores/auth';
import { useInstancesStore } from '@/stores/instances';

const { get, post, del, closeDetails } = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), del: vi.fn(), closeDetails: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { get, post, delete: del }, apiGet: vi.fn(), apiPost: (path: string, body: unknown) => post(path, body).then((r: { ok: boolean; data?: unknown }) => (r.ok ? { ok: true, value: r.data } : r)) }));
vi.mock('@/lib/credentialTransport', () => ({ canSendCredentials: () => true }));
vi.mock('@/stores/layout', () => ({ useLayoutStore: { getState: () => ({ setNavSection: vi.fn(), setView: vi.fn(), closeDetails }) } }));

const provider = { id: 'provider', label: 'Company AWS', start_url: 'https://example.awsapps.com/start', region: 'us-east-1' };
const started = { id: 'flow', verification_url: 'https://example.awsapps.com/start/#/device', verification_url_complete: 'https://example.awsapps.com/start/#/device?user_code=ABCD', user_code: 'ABCD', interval_seconds: 1, expires_at: '2099-01-01T00:00:00Z' };
const slow = { timeout: 4000 };
const sources = () => screen.getByRole('navigation', { name: 'Connection sources' });

function backend({ polls = ['pending', 'authorized'], sessions = [] as unknown[] } = {}) {
  let connects = 0;
  get.mockImplementation(async (path: string) => ({
    ok: true, data:
      path === '/api/aws/sso-providers' ? [provider]
        : path === '/api/aws/user-bindings' ? [{ id: 'binding', label: 'Development', role_arn: 'arn:aws:iam::222222222222:role/InventoryReadOnly' }]
          : path === '/api/aws/sso/session' ? { active: sessions.length > 0, sessions }
            : []
  }));
  post.mockImplementation(async (path: string, body: { id?: string; account_id?: string }) => {
    switch (path) {
      case '/api/aws/sso/start': return { ok: true, data: started };
      case '/api/aws/sso/poll': return { ok: true, data: { status: polls.shift() ?? 'authorized' } };
      case '/api/aws/sso/accounts': return { ok: true, data: body.id === 'other-flow' ? [{ id: '333333333333', name: 'Partner' }] : [{ id: '111111111111', name: 'Production' }, { id: '222222222222', name: 'Development' }] };
      case '/api/aws/sso/roles': return { ok: true, data: body.account_id === '222222222222' ? [{ account_id: '222222222222', name: 'ReadOnly' }, { account_id: '222222222222', name: 'Admin' }] : [{ account_id: body.account_id, name: 'Viewer' }] };
      case '/api/aws/sso/connect': return { ok: true, data: { id: `sso-${body.account_id}-${++connects}`, status: 'connected', credential_revision: 'rev' } };
      case '/api/aws/role-fetch': return { ok: true, data: { instances: [], failed_regions: [], credential_revision: 'rev' } };
      default: return { ok: true, data: { status: 'connected', credential_revision: 'rev' } };
    }
  });
}

describe('cloud connections', () => {
  beforeEach(() => {
    get.mockReset(); post.mockReset(); closeDetails.mockReset();
    useSessionsStore.setState({ sessions: [], activeId: null });
    useAuthStore.setState({ config: { aws_access_mode: 'user' } as never, me: { user_id: 'user', tenant_id: 'tenant', email: 'user@example.test', role: 'user', method: 'password', expires_at: 9999999999 } });
    useInstancesStore.getState().clearUserRoles();
  });
  afterEach(() => vi.restoreAllMocks());

  it('normalizes start URLs the way the server tells them apart', () => {
    expect(normalizeStartURL(' https://Example.AWSApps.com/start/ ')).toBe('https://example.awsapps.com/start');
    expect(normalizeStartURL('not a url')).toBe('');
  });

  it('signs in to a configured start URL, lists its accounts and connects them under that source', async () => {
    const tab = { opener: {}, location: { href: '' }, close: vi.fn() };
    const open = vi.spyOn(window, 'open').mockReturnValue(tab as unknown as Window);
    backend();
    render(<CloudConnections />);
    fireEvent.click(await within(sources()).findByRole('button', { name: /Company AWS/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(open).toHaveBeenCalledWith('about:blank', '_blank');
    expect(await screen.findByText('ABCD')).toBeInTheDocument();
    expect(post).toHaveBeenCalledWith('/api/aws/sso/start', { start_url: provider.start_url, region: 'us-east-1' });
    expect(tab.location.href).toBe(started.verification_url_complete);
    expect(tab.opener).toBeNull();
    expect(within(sources()).getByText('Waiting for approval')).toBeInTheDocument();

    const list = await screen.findByRole('list', { name: 'AWS accounts' }, slow);
    expect(within(sources()).getByText(/^Signed in/)).toBeInTheDocument();
    fireEvent.change(await screen.findByLabelText('Role for Development'), { target: { value: 'Admin' } });
    fireEvent.click(screen.getByRole('button', { name: 'Connect Development' }));
    await waitFor(() => expect(useInstancesStore.getState().userRoles[0]).toMatchObject({ id: 'sso-222222222222-1', startURL: 'https://example.awsapps.com/start' }));
    expect(post).toHaveBeenCalledWith('/api/aws/sso/connect', { id: 'flow', account_id: '222222222222', role_name: 'Admin' });
    await screen.findByLabelText('Role for Production');
    fireEvent.click(screen.getByRole('button', { name: 'Connect Production' }));
    await waitFor(() => expect(useInstancesStore.getState().userRoles).toHaveLength(2));
    const connected = screen.getByRole('list', { name: 'Connected accounts for Company AWS' });
    expect(within(connected).getByText('Development · Admin')).toBeInTheDocument();
    expect(within(list).getAllByText('Connected')).toHaveLength(2);

    fireEvent.change(screen.getByLabelText('Role for Development'), { target: { value: 'ReadOnly' } });
    fireEvent.click(screen.getByRole('button', { name: 'Switch role for Development' }));
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/aws/role-disconnect', { binding_id: 'sso-222222222222-1' }));

    fireEvent.click(screen.getByRole('button', { name: 'Disconnect Production' }));
    await waitFor(() => expect(useInstancesStore.getState().userRoles.map(r => r.name)).toEqual(['Development']));

    fireEvent.click(screen.getByRole('button', { name: 'Disconnect all' }));
    await waitFor(() => expect(useInstancesStore.getState().userRoles).toHaveLength(0));
    expect(post).toHaveBeenCalledWith('/api/aws/role-disconnect', {});
  });

  it('lists every live sign-in as its own source and signs out of one without touching the other', async () => {
    backend({
      sessions: [
        { id: 'flow', region: 'us-east-1', start_url: 'https://example.awsapps.com/start', expires_at: '2099-01-01T00:00:00Z' },
        { id: 'other-flow', region: 'eu-west-1', start_url: 'https://partner.awsapps.com/start', expires_at: '2099-01-01T00:00:00Z' },
      ]
    });
    render(<CloudConnections />);
    const partner = await within(sources()).findByRole('button', { name: /partner/ });
    expect(within(sources()).getAllByText(/^Signed in/)).toHaveLength(2);
    fireEvent.click(partner);
    expect(await screen.findByText('Partner')).toBeInTheDocument();
    expect(post).toHaveBeenCalledWith('/api/aws/sso/accounts', { id: 'other-flow' });
    fireEvent.click(screen.getByRole('button', { name: 'Sign out' }));
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/aws/sso/cancel', { id: 'other-flow' }));
    await waitFor(() => expect(within(sources()).getAllByText(/^Signed in/)).toHaveLength(1));
    expect(within(sources()).queryByRole('button', { name: /partner/ })).not.toBeInTheDocument();
  });

  it('keeps accounts from a signed-out start URL listed under it', async () => {
    backend();
    await useInstancesStore.getState().addUserRole({ id: 'kept', name: 'Partner', label: 'Partner · Viewer', accountID: '333333333333', roleName: 'Viewer', startURL: 'https://partner.awsapps.com/start', credentialRevision: 'rev' });
    render(<CloudConnections />);
    expect(await within(sources()).findByText('Not signed in · 1 connected')).toBeInTheDocument();
    expect(screen.getByRole('list', { name: 'Connected accounts for partner' })).toHaveTextContent('Partner · Viewer');
  });

  it('adds a user-supplied start URL and offers a link when the browser blocks the tab', async () => {
    vi.spyOn(window, 'open').mockReturnValue(null);
    backend({ polls: ['pending', 'pending', 'pending'] });
    render(<CloudConnections />);
    fireEvent.click(within(sources()).getByRole('button', { name: 'Add a start URL' }));
    fireEvent.change(screen.getByLabelText('AWS start URL'), { target: { value: 'https://own.awsapps.com/start' } });
    fireEvent.change(screen.getByLabelText('Identity Center region'), { target: { value: 'us-west-2' } });
    fireEvent.click(screen.getByRole('button', { name: 'Start AWS sign-in' }));
    expect(await screen.findByRole('link', { name: 'Open AWS sign-in' })).toHaveAttribute('href', started.verification_url_complete);
    expect(within(sources()).getByRole('button', { name: /^own/ })).toHaveAttribute('aria-current', 'true');
    fireEvent.click(screen.getByRole('button', { name: 'Cancel AWS sign-in' }));
    await waitFor(() => expect(screen.queryByText('ABCD')).not.toBeInTheDocument());
    expect(post).toHaveBeenCalledWith('/api/aws/sso/cancel', { id: 'flow' });
  });

  it('closes the pre-opened tab when AWS sign-in cannot start', async () => {
    const tab = { opener: {}, location: { href: '' }, close: vi.fn() };
    vi.spyOn(window, 'open').mockReturnValue(tab as unknown as Window);
    backend();
    post.mockResolvedValue({ ok: false, error: 'bad' });
    render(<CloudConnections />);
    fireEvent.click(await within(sources()).findByRole('button', { name: /Company AWS/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not start AWS sign-in');
    expect(tab.close).toHaveBeenCalled();
  });

  it('connects an approved IAM role and lists it under IAM roles', async () => {
    backend();
    render(<CloudConnections />);
    fireEvent.click(within(sources()).getByRole('button', { name: /IAM roles/ }));
    await screen.findByRole('option', { name: /Development/ });
    fireEvent.change(screen.getByLabelText('Approved role'), { target: { value: 'binding' } });
    fireEvent.change(screen.getByLabelText('Access key ID'), { target: { value: 'source-key' } });
    fireEvent.change(screen.getByLabelText('Secret access key'), { target: { value: 'source-secret' } });
    fireEvent.click(screen.getByRole('button', { name: 'Connect role' }));
    await waitFor(() => expect(useInstancesStore.getState().userRoles[0]).toMatchObject({ id: 'binding', accountID: '222222222222' }));
    expect(screen.getByLabelText('Secret access key')).toHaveValue('');
    expect(post).toHaveBeenCalledWith('/api/aws/role-login', expect.objectContaining({ binding_id: 'binding', access_key_id: 'source-key' }));
    expect(await screen.findByRole('list', { name: 'Connected IAM roles' })).toHaveTextContent('Development');
  });

  it('connects a user-supplied IAM role ARN', async () => {
    backend();
    post.mockImplementation(async (path: string) => ({ ok: true, data: path === '/api/aws/role-fetch' ? { instances: [], failed_regions: [], credential_revision: 'rev' } : { id: 'direct-role', status: 'connected', credential_revision: 'rev' } }));
    render(<CloudConnections />);
    fireEvent.click(within(sources()).getByRole('button', { name: /IAM roles/ }));
    fireEvent.change(screen.getByLabelText('IAM role ARN'), { target: { value: 'arn:aws:iam::222222222222:role/ReadOnly' } });
    fireEvent.change(screen.getByLabelText('Access key ID'), { target: { value: 'source-key' } });
    fireEvent.change(screen.getByLabelText('Secret access key'), { target: { value: 'source-secret' } });
    fireEvent.click(screen.getByRole('button', { name: 'Connect role' }));
    await waitFor(() => expect(useInstancesStore.getState().userRoles[0]?.id).toBe('direct-role'));
  });

  it('supports Azure Entra Device Code SSO, Managed Identity, GCP PKCE SSO, and WIF/ADC without static secrets', async () => {
    backend();
    const baseGet = get.getMockImplementation()!;
    const basePost = post.getMockImplementation()!;
    get.mockImplementation(async (path: string) => {
      if (path.startsWith('/api/clouds/gcp/sso/status')) {
        return {
          ok: true,
          data: {
            flow_id: 'gcp-flow-1',
            status: 'authorized',
            projects: [{ project_id: 'gcp-sso-proj', name: 'GCP Prod', project_number: '123', lifecycle_state: 'ACTIVE' }],
          },
        };
      }
      if (path === '/api/clouds/connectors') return { ok: true, data: { connectors: [] } };
      if (path === '/api/clouds/resources') return { ok: true, data: { resources: [] } };
      return baseGet(path);
    });
    post.mockImplementation(async (path: string, body: unknown) => {
      if (path === '/api/clouds/azure/sso/start') {
        return {
          ok: true,
          data: {
            flow_id: 'az-flow-1',
            user_code: 'WXYZ-1234',
            verification_uri: 'https://microsoft.com/devicelogin',
            interval_seconds: 0.05,
            expires_in_seconds: 600,
          },
        };
      }
      if (path === '/api/clouds/azure/sso/poll') {
        return {
          ok: true,
          data: {
            status: 'authorized',
            subscriptions: [{ subscription_id: 'sub-az-sso', display_name: 'Azure Enterprise Sub', state: 'Enabled', tenant_id: 't-1' }],
          },
        };
      }
      if (path === '/api/clouds/azure/sso/connect') {
        return { ok: true, data: { connector: { id: 'cld-az-1' }, resources_count: 1, resources: [] } };
      }
      if (path === '/api/clouds/gcp/sso/start') {
        return {
          ok: true,
          data: {
            flow_id: 'gcp-flow-1',
            authorization_url: 'https://accounts.google.com/o/oauth2/v2/auth?state=st1',
            redirect_uri: 'https://localhost:5444/api/clouds/gcp/sso/callback',
            expires_in_seconds: 900,
          },
        };
      }
      if (path === '/api/clouds/gcp/sso/connect') {
        return { ok: true, data: { connector: { id: 'cld-gcp-1' }, resources_count: 1, resources: [] } };
      }
      return basePost(path, body as { id?: string; account_id?: string });
    });

    const tab = { opener: {}, location: { href: '' }, close: vi.fn(), closed: false };
    vi.spyOn(window, 'open').mockReturnValue(tab as unknown as Window);

    render(<CloudConnections />);

    // 1. Azure Entra ID Device Code SSO flow
    fireEvent.click(within(sources()).getByRole('button', { name: /Microsoft Entra ID/ }));
    expect(await screen.findByText(/Entra ID Device Code SSO/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Sign in with Microsoft Entra ID' }));
    expect(await screen.findByText('WXYZ-1234')).toBeInTheDocument();
    expect(await screen.findByText('Azure Enterprise Sub', {}, slow)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith('/api/clouds/azure/sso/connect', expect.objectContaining({ flow_id: 'az-flow-1', subscription_id: 'sub-az-sso' })),
    );

    // 2. Azure Managed / Workload Identity keyless connector
    fireEvent.click(screen.getByRole('tab', { name: 'Managed / Workload Identity' }));
    fireEvent.change(screen.getByLabelText('Connector name'), { target: { value: 'Azure MI Prod' } });
    fireEvent.change(screen.getByLabelText('Subscription ID'), { target: { value: 'sub-az-mi' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add Azure connector' }));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith('/api/clouds/connectors', expect.objectContaining({
        provider: 'azure',
        account_or_project_id: 'sub-az-mi',
        config: expect.objectContaining({ auth_mode: 'managed_identity' }),
      })),
    );

    // 3. Google Cloud OAuth2 PKCE SSO flow
    fireEvent.click(within(sources()).getByRole('button', { name: /Google Cloud Platform/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Sign in with Google Cloud' }));
    expect(await screen.findByText('GCP Prod', {}, slow)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Connect' }));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith('/api/clouds/gcp/sso/connect', expect.objectContaining({ flow_id: 'gcp-flow-1', project_id: 'gcp-sso-proj' })),
    );

    // 4. GCP Workload Identity / ADC keyless connector
    fireEvent.click(screen.getByRole('tab', { name: 'Workload Identity / ADC' }));
    fireEvent.change(screen.getByLabelText('Connector name'), { target: { value: 'GCP ADC Prod' } });
    fireEvent.change(screen.getByLabelText('GCP Project ID'), { target: { value: 'gcp-adc-99' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add GCP connector' }));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith('/api/clouds/connectors', expect.objectContaining({
        provider: 'gcp',
        account_or_project_id: 'gcp-adc-99',
        config: expect.objectContaining({ auth_mode: 'metadata_adc' }),
      })),
    );
  });

  it('retries transient SSO role lookup failures and offers Retry when exhausted', async () => {
    backend({
      polls: ['authorized'],
      sessions: [{ id: 'flow', start_url: provider.start_url, region: 'us-east-1', expires_at: '2099-01-01T00:00:00Z' }],
    });
    let devHits = 0;
    let prodHits = 0;
    const basePost = post.getMockImplementation()!;
    post.mockImplementation(async (path: string, body: { id?: string; account_id?: string }) => {
      if (path === '/api/aws/sso/roles' && body.account_id === '222222222222') {
        devHits += 1;
        if (devHits === 1) return { ok: false, error: { status: 502, message: 'throttled' } };
        return { ok: true, data: [{ account_id: '222222222222', name: 'Admin' }] };
      }
      if (path === '/api/aws/sso/roles' && body.account_id === '111111111111') {
        prodHits += 1;
        if (prodHits <= 3) return { ok: false, error: { status: 502, message: 'still failing' } };
        return { ok: true, data: [{ account_id: '111111111111', name: 'ReadOnly' }] };
      }
      return basePost(path, body);
    });

    render(<CloudConnections />);
    fireEvent.click(await within(sources()).findByRole('button', { name: /Company AWS/ }));

    expect(await screen.findByLabelText('Role for Development', {}, { timeout: 4000 })).toHaveValue('Admin');
    expect(await screen.findByText('Roles failed to load', {}, { timeout: 4000 })).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Retry roles for Production' }));
    expect(await screen.findByLabelText('Role for Production', {}, { timeout: 4000 })).toHaveValue('ReadOnly');
  });
});
