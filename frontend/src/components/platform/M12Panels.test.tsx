import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { McpProxyPanel } from './McpProxyPanel';
import { HybridAgentsPanel } from './HybridAgentsPanel';
import { AccessGraphPanel } from './AccessGraphPanel';
import { DeviceTrustPanel } from './DeviceTrustPanel';

const { get, post, put, del } = vi.hoisted(() => ({
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  del: vi.fn(),
}));

vi.mock('@/lib/api', () => ({
  api: { get, post, put, delete: del },
}));

describe('M12 governance & platform panels', () => {
  beforeEach(() => {
    get.mockReset();
    post.mockReset();
    put.mockReset();
    del.mockReset();
  });

  it('McpProxyPanel issues sponsor-bound oqmcp_ tokens and displays invocation audit log', async () => {
    get.mockImplementation(async (path: string) => {
      if (path === '/api/mcp/agents') {
        return {
          ok: true,
          data: {
            agents: [
              {
                id: 'mcp-1',
                name: 'existing-bot',
                sponsor_user_id: 'u-1',
                sponsor_email: 'admin@local',
                allowed_tools: ['operquay.db.query'],
                require_jit_tools: ['operquay.db.mutate'],
                rate_limit_per_min: 30,
                status: 'active',
                expires_at: 2000000000,
                created_at: 1700000000,
              },
            ],
          },
        };
      }
      if (path === '/api/mcp/invocations') {
        return {
          ok: true,
          data: {
            invocations: [
              {
                id: 'inv-1',
                agent_id: 'mcp-1',
                sponsor_user_id: 'u-1',
                tool_name: 'operquay.db.query',
                sanitized_args: '{"sql":"SELECT 1"}',
                decision: 'allowed',
                masked_result_preview: '{"rows":1}',
                duration_ms: 4,
                created_at: 1700000000,
              },
            ],
          },
        };
      }
      return { ok: true, data: {} };
    });

    post.mockResolvedValue({
      ok: true,
      data: {
        agent: {
          id: 'mcp-2',
          name: 'claude-ops',
          sponsor_user_id: 'u-1',
          sponsor_email: 'admin@local',
          allowed_tools: ['operquay.instances.list'],
          require_jit_tools: [],
          rate_limit_per_min: 60,
          status: 'active',
          expires_at: 2000000000,
          created_at: 1700000000,
        },
        token: 'oqmcp_one_time_secret',
      },
    });

    render(<McpProxyPanel />);
    expect(await screen.findByText('existing-bot')).toBeInTheDocument();
    expect(screen.getAllByText('operquay.db.query').length).toBeGreaterThan(0);

    fireEvent.change(screen.getByLabelText('Agent Name'), { target: { value: 'claude-ops' } });
    fireEvent.click(screen.getByRole('button', { name: /Issue MCP Token/i }));

    expect(await screen.findByText('oqmcp_one_time_secret')).toBeInTheDocument();
  });

  it('HybridAgentsPanel enrolls outbound reverse-tunnel agents and prints run command', async () => {
    get.mockResolvedValue({
      ok: true,
      data: {
        agents: [
          {
            id: 'agt-1',
            name: 'dc-west',
            cert_fingerprint_sha256: 'abc123def456',
            hostname: 'dc01.internal',
            os: 'linux',
            arch: 'x86_64',
            targets: [{ protocol: 'ssh', host: '10.0.1.5', port: 22 }],
            status: 'online',
            online: true,
            created_at: 1700000000,
          },
        ],
      },
    });
    post.mockResolvedValue({
      ok: true,
      data: {
        agent: { id: 'agt-2', name: 'onprem-db', targets: [], status: 'enrolled', online: false, created_at: 1700000001 },
        enrollment_token: 'oqag_demo_secret',
        run_command: 'operquay-agent --server wss://localhost:5444/api/agents/tunnel --name "onprem-db" --token oqag_demo_secret',
      },
    });

    render(<HybridAgentsPanel />);
    expect(await screen.findByText('dc-west')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Agent Name'), { target: { value: 'onprem-db' } });
    fireEvent.click(screen.getByRole('button', { name: /Enroll Hybrid Agent/i }));

    expect(await screen.findByText(/oqag_demo_secret/)).toBeInTheDocument();
  });

  it('AccessGraphPanel displays shadow admin findings and principal blast radius scores', async () => {
    get.mockResolvedValue({
      ok: true,
      data: {
        generated_at: 1700000000,
        summary: {
          total_nodes: 3,
          total_edges: 2,
          principals: 1,
          shadow_admins: 1,
          trust_loops: 1,
          unused_standing_privileges: 0,
        },
        nodes: [
          { id: 'user:1', label: 'bob@corp.test', kind: 'user', account_or_tenant: 'default', environment: 'identity', is_admin_capability: false },
          { id: 'role:admin', label: 'ProdAdmin', kind: 'role', account_or_tenant: 'default', environment: 'rbac', is_admin_capability: true },
          { id: 'inst:1', label: 'prod-api-01', kind: 'instance', account_or_tenant: '111122223333', environment: 'prod', is_admin_capability: false },
        ],
        edges: [
          { from: 'user:1', to: 'role:admin', kind: 'assigned_role', label: 'assigned' },
          { from: 'role:admin', to: 'inst:1', kind: 'can_access', label: 'ssh' },
        ],
        findings: [
          {
            id: 'f-1',
            kind: 'shadow_admin',
            severity: 'high',
            title: 'Shadow Admin Path: bob@corp.test',
            description: 'Non-admin user reaches ProdAdmin',
            node_ids: ['user:1'],
            remediation: 'Require JIT approval',
          },
        ],
        blast_radius: [
          {
            principal_id: 'user:1',
            principal_label: 'bob@corp.test',
            principal_kind: 'user',
            reachable_resources: 1,
            reachable_prod_resources: 1,
            admin_paths: 1,
            blast_score: 45,
            sample_path: ['bob@corp.test', 'ProdAdmin', 'prod-api-01'],
          },
        ],
      },
    });

    render(<AccessGraphPanel />);
    expect(await screen.findByText('Shadow Admin Path: bob@corp.test')).toBeInTheDocument();
    expect(screen.getByText('Score 45')).toBeInTheDocument();
    expect(screen.getByText('bob@corp.test -> ProdAdmin -> prod-api-01')).toBeInTheDocument();
  });

  it('DeviceTrustPanel saves MDM/EDR policy and submits compliant device posture attestations', async () => {
    get.mockImplementation(async (path: string) => {
      if (path === '/api/device-trust/policy') {
        return {
          ok: true,
          data: {
            enabled: true,
            enforce_on_desktop_launch: true,
            require_disk_encryption: true,
            require_edr_running: true,
            max_os_patch_age_days: 30,
            allowed_providers: ['jamf', 'crowdstrike'],
            attestation_ttl_secs: 86400,
          },
        };
      }
      return {
        ok: true,
        data: {
          devices: [
            {
              id: 'dev-1',
              user_id: 'u-1',
              device_id: 'mbp-01',
              provider: 'jamf',
              hostname: 'mbp-alice',
              os_version: 'macOS 15.3',
              disk_encrypted: true,
              edr_running: true,
              edr_agent: 'CrowdStrike Falcon',
              os_patch_age_days: 3,
              compliant: true,
              reasons: [],
              attested_at: 1700000000,
            },
          ],
        },
      };
    });
    put.mockResolvedValue({
      ok: true,
      data: {
        enabled: true,
        enforce_on_desktop_launch: true,
        require_disk_encryption: true,
        require_edr_running: true,
        max_os_patch_age_days: 30,
        allowed_providers: ['jamf', 'crowdstrike'],
        attestation_ttl_secs: 86400,
      },
    });
    post.mockResolvedValue({
      ok: true,
      data: {
        attestation: {
          id: 'dev-2',
          device_id: 'ws-macbook-pro-1',
          provider: 'jamf',
          hostname: 'eng-workstation',
          os_version: 'macOS 15.3',
          disk_encrypted: true,
          edr_running: true,
          edr_agent: 'CrowdStrike Falcon',
          os_patch_age_days: 4,
          compliant: true,
          reasons: [],
          attested_at: 1700000005,
        },
      },
    });

    render(<DeviceTrustPanel />);
    expect(await screen.findByText('mbp-alice')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /Save Policy/i }));
    await waitFor(() => expect(put).toHaveBeenCalledWith('/api/device-trust/policy', expect.objectContaining({ enabled: true })));

    fireEvent.click(screen.getByRole('button', { name: /Attest This Device/i }));
    await waitFor(() => expect(post).toHaveBeenCalledWith('/api/device-trust/attest', expect.objectContaining({ device_id: 'ws-macbook-pro-1' })));
  });
});
