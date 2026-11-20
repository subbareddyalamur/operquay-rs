import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { GroupsRolesSettings } from './GroupsRolesSettings';
import { api } from '@/lib/api';
import { useAuthStore, hasPermission } from '@/stores/auth';

vi.mock('@/lib/api', () => ({ api: { get: vi.fn(), put: vi.fn(), post: vi.fn(), delete: vi.fn() } }));

afterEach(() => {
  cleanup();
  vi.resetAllMocks();
  useAuthStore.setState({ config: null, me: null });
});

function setupMockAPIs() {
  vi.mocked(api.get).mockImplementation(async (path: string) => {
    if (path === '/api/groups') {
      return {
        ok: true,
        data: [
          {
            id: 'grp-admins',
            tenant_id: 'local',
            name: 'Administrators',
            description: 'Full access',
            source: 'local',
            is_system: true,
            member_count: 1,
            members: [{ user_id: 'admin@local', email: 'admin@local', name: 'Admin', source: 'manual' }],
            bindings: [{ id: 'b-1', group_id: 'grp-admins', role_id: 'admin', role_name: 'Admin', permissions: ['*'], scope_type: 'global' }],
          },
        ],
      };
    }
    if (path === '/api/roles') {
      return {
        ok: true,
        data: [
          { id: 'admin', tenant_id: 'local', name: 'Admin', is_system: true, permissions: ['*'] },
          { id: 'user', tenant_id: 'local', name: 'Operator', is_system: true, permissions: ['instances:read', 'session:ssh'] },
        ],
      };
    }
    if (path === '/api/permissions') {
      return {
        ok: true,
        data: {
          permissions: [
            { id: 'instances:read', category: 'Instances', description: 'View fleet inventory' },
            { id: 'k8s:exec', category: 'Kubernetes', description: 'Exec into pods' },
          ],
        },
      };
    }
    if (path === '/api/idp-mappings') {
      return { ok: true, data: [] };
    }
    if (path === '/api/scim/tokens') {
      return {
        ok: true,
        data: [
          {
            id: 'scim-tok-1',
            tenant_id: 'local',
            name: 'Existing Okta',
            prefix: 'oq_scim_ab',
            created_by: 'admin@local',
            created_at: 1700000000,
          },
        ],
      };
    }
    if (path === '/api/users') {
      return {
        ok: true,
        data: [
          { id: 'admin@local', email: 'admin@local' },
          { id: 'alice', email: 'alice@example.com' },
        ],
      };
    }
    return { ok: false, error: { status: 404, message: 'not found' } } as never;
  });
}

it('renders groups, adds scoped role bindings, creates custom roles, and configures IdP mappings', async () => {
  setupMockAPIs();
  vi.mocked(api.post).mockResolvedValue({ ok: true, data: { id: 'new-1', name: 'K8s-Devs' } });

  render(<GroupsRolesSettings />);

  expect(await screen.findByRole('heading', { name: 'Administrators' })).toBeInTheDocument();

  // Add member alice to Administrators
  fireEvent.change(screen.getByLabelText('Select user to add to group'), { target: { value: 'alice' } });
  fireEvent.click(screen.getByRole('button', { name: 'Add' }));
  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith('/api/groups/grp-admins/members', { user_id: 'alice' })
  );

  // Bind a scoped role
  fireEvent.change(screen.getByLabelText('Select scope type'), { target: { value: 'k8s_cluster' } });
  fireEvent.change(screen.getByLabelText('Scope target ID'), { target: { value: 'dev-eks' } });
  fireEvent.click(screen.getByRole('button', { name: 'Bind role' }));
  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith('/api/groups/grp-admins/roles', {
      role_id: 'admin',
      scope_type: 'k8s_cluster',
      scope_id: 'dev-eks',
    })
  );

  // Switch to Roles tab and open Custom Role dialog
  fireEvent.click(screen.getByRole('tab', { name: /Roles/i }));
  fireEvent.click(screen.getByRole('button', { name: 'New custom role' }));
  fireEvent.change(screen.getByLabelText('Role name'), { target: { value: 'K8s-Exec-Only' } });
  fireEvent.click(screen.getByRole('button', { name: 'Create role' }));
  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith('/api/roles', {
      name: 'K8s-Exec-Only',
      description: '',
      permissions: ['instances:read', 'k8s:read'],
    })
  );

  // Switch to IdP Mappings tab and create mapping
  fireEvent.click(screen.getByRole('tab', { name: /IdP Mappings/i }));
  fireEvent.change(screen.getByLabelText('Provider ID'), { target: { value: 'okta' } });
  fireEvent.change(screen.getByLabelText('External IdP group name'), { target: { value: 'Okta-Admins' } });
  fireEvent.click(screen.getByRole('button', { name: 'Add mapping' }));
  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith('/api/idp-mappings', {
      provider_id: 'okta',
      external_group: 'Okta-Admins',
      group_id: 'grp-admins',
    })
  );
});

it('evaluates scoped permissions accurately in auth helper', () => {
  const me = {
    user_id: 'devop',
    email: 'devop@example.com',
    role: 'readonly' as const,
    tenant_id: 'local',
    method: 'sso' as const,
    expires_at: 9999999999,
    grants: [
      {
        role_id: 'custom-1',
        permissions: ['k8s:exec', 'instances:read'],
        scope_type: 'k8s_cluster' as const,
        scope_id: 'dev-eks',
      },
    ],
  };
  expect(hasPermission(me, 'k8s:exec')).toBe(true);
  expect(hasPermission(me, 'k8s:exec', { type: 'k8s_cluster', id: 'dev-eks' })).toBe(true);
  expect(hasPermission(me, 'k8s:exec', { type: 'k8s_cluster', id: 'prod-eks' })).toBe(false);
  expect(hasPermission(me, 'users:manage')).toBe(false);

  // Explicit deny overrides wildcard allow on the matching scope while preserving other scopes
  const deniedMe = {
    ...me,
    role: 'admin' as const,
    grants: [
      {
        role_id: 'admin',
        permissions: ['*'],
        scope_type: 'global' as const,
        effect: 'allow' as const,
      },
      {
        role_id: 'custom-deny',
        permissions: ['k8s:exec'],
        scope_type: 'k8s_cluster' as const,
        scope_id: 'prod-eks',
        effect: 'deny' as const,
      },
    ],
  };
  expect(hasPermission(deniedMe, 'k8s:exec', { type: 'k8s_cluster', id: 'dev-eks' })).toBe(true);
  expect(hasPermission(deniedMe, 'k8s:exec', { type: 'k8s_cluster', id: 'prod-eks' })).toBe(false);
  expect(hasPermission(deniedMe, 'users:manage')).toBe(true);
});

it('submits explicit deny and ABAC conditional bindings', async () => {
  setupMockAPIs();
  vi.mocked(api.post).mockResolvedValue({ ok: true, data: { id: 'b-new' } });

  render(<GroupsRolesSettings />);
  expect(await screen.findByRole('heading', { name: 'Administrators' })).toBeInTheDocument();

  // Bind allow with recording obligation, CIDR allowlist, and UTC window
  fireEvent.click(screen.getByLabelText('Require session recording'));
  fireEvent.change(screen.getByLabelText('Allowed CIDRs'), { target: { value: '10.0.0.0/8, 192.168.1.0/24' } });
  fireEvent.change(screen.getByLabelText('UTC hours start'), { target: { value: '8' } });
  fireEvent.change(screen.getByLabelText('UTC hours end'), { target: { value: '18' } });
  fireEvent.click(screen.getByRole('button', { name: 'Bind role' }));

  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith('/api/groups/grp-admins/roles', {
      role_id: 'admin',
      scope_type: 'global',
      scope_id: '',
      conditions: {
        require_recording: true,
        allowed_cidrs: ['10.0.0.0/8', '192.168.1.0/24'],
        utc_hours_start: 8,
        utc_hours_end: 18,
      },
    })
  );

  // Wait for first request to settle and form to reset before second binding
  await waitFor(() => expect(screen.getByLabelText('Select binding effect')).toHaveValue('allow'));

  // Switch effect to deny and bind on prod cluster
  fireEvent.change(screen.getByLabelText('Select binding effect'), { target: { value: 'deny' } });
  fireEvent.change(screen.getByLabelText('Select scope type'), { target: { value: 'k8s_cluster' } });
  fireEvent.change(screen.getByLabelText('Scope target ID'), { target: { value: 'prod-eks' } });
  fireEvent.click(screen.getByRole('button', { name: 'Bind role' }));

  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith('/api/groups/grp-admins/roles', {
      role_id: 'admin',
      scope_type: 'k8s_cluster',
      scope_id: 'prod-eks',
      effect: 'deny',
    })
  );
});

it('manages SCIM 2.0 tokens and displays one-time bearer secrets', async () => {
  setupMockAPIs();
  vi.mocked(api.post).mockResolvedValue({
    ok: true,
    data: {
      token: {
        id: 'scim-tok-new',
        tenant_id: 'local',
        name: 'Okta Production',
        prefix: 'oq_scim_xy',
        created_by: 'admin@local',
        created_at: 1700000100,
      },
      secret: 'oq_scim_secret_once_only_value',
    },
  });
  vi.mocked(api.delete).mockResolvedValue({ ok: true, data: { deleted: true } });

  render(<GroupsRolesSettings />);
  expect(await screen.findByRole('heading', { name: 'Administrators' })).toBeInTheDocument();

  fireEvent.click(screen.getByRole('tab', { name: /SCIM 2\.0/i }));
  expect(await screen.findByText(/\/scim\/v2/)).toBeInTheDocument();
  expect(screen.getByText('Existing Okta')).toBeInTheDocument();

  fireEvent.change(screen.getByLabelText('SCIM token name'), { target: { value: 'Okta Production' } });
  fireEvent.click(screen.getByRole('button', { name: 'Generate token' }));

  await waitFor(() =>
    expect(api.post).toHaveBeenCalledWith('/api/scim/tokens', { name: 'Okta Production' })
  );
  expect(await screen.findByText('oq_scim_secret_once_only_value')).toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: 'Revoke token Existing Okta' }));
  await waitFor(() =>
    expect(api.delete).toHaveBeenCalledWith('/api/scim/tokens/scim-tok-1')
  );
});


