import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { GovernancePanel } from './GovernancePanel';
import { useAuthStore } from '@/stores/auth';
import { api } from '@/lib/api';

vi.mock('@/lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}));

describe('GovernancePanel', () => {
  beforeEach(() => {
    useAuthStore.setState({
      me: {
        user_id: 'admin-1',
        email: 'admin@local',
        role: 'admin',
        tenant_id: 'default',
        method: 'password',
        expires_at: 9999999999,
      },
    });
  });

  afterEach(() => {
    cleanup();
    vi.clearAllMocks();
    useAuthStore.setState({ me: null });
  });

  it('submits and approves JIT access requests and evaluates DLP firewall dry-runs', async () => {
    const getMock = vi.mocked(api.get);
    const postMock = vi.mocked(api.post);

    getMock.mockImplementation(async (path: string) => {
      if (path === '/api/access-requests') {
        return {
          ok: true,
          data: {
            can_approve: true,
            items: [
              {
                id: 'jit-1',
                tenant_id: 'default',
                requester_user_id: 'u-bob',
                requester_email: 'bob@local',
                target_type: 'aws_role',
                target_id: 'arn:aws:iam::123:role/Prod',
                requested_role: 'ProdAdmin',
                duration_secs: 1800,
                reason: 'Incident INC-9',
                ticket_id: 'INC-9',
                ticket_provider: 'jira',
                status: 'pending',
                decision_note: '',
                created_at: 1000,
              },
            ],
          },
        };
      }
      if (path === '/api/governance/dlp-policy') {
        return {
          ok: true,
          data: {
            db_dlp: {
              enabled: true,
              mask_emails: true,
              mask_ssn: true,
              mask_credit_cards: true,
              mask_phones: true,
              mask_secrets: true,
              sensitive_column_patterns: ['password', 'ssn'],
              unmasked_roles: [],
            },
            command_firewall_enabled: true,
            require_jit_for_db_write: false,
            require_jit_for_prod_shell: false,
            rules: [
              {
                id: 'block-rm',
                name: 'Block rm -rf',
                pattern: 'rm\\s+-rf',
                protocols: ['ssh'],
                action: 'block',
                message: 'Destructive command blocked',
                enabled: true,
              },
            ],
          },
        };
      }
      if (path === '/api/governance/webhooks') {
        return {
          ok: true,
          data: {
            webhooks: [],
            stats: { enqueued: 1, delivered: 1, dropped: 0, failed: 0 },
          },
        };
      }
      return { ok: true, data: {} };
    });

    postMock.mockImplementation(async (path: string) => {
      if (path.includes('/approve')) {
        return { ok: true, data: { status: 'approved' } };
      }
      if (path === '/api/access-requests') {
        return { ok: true, data: { id: 'jit-2', status: 'pending' } };
      }
      if (path === '/api/governance/dlp-policy/test') {
        return {
          ok: true,
          data: {
            verdict: {
              action: 'block',
              rule_id: 'block-rm',
              rule_name: 'Block rm -rf',
              message: 'Destructive command blocked',
              sanitized_command: 'rm -rf /',
            },
            dlp_summary: { masked_cells: 3, masked_columns: ['email', 'ssn', 'secret_token'] },
          },
        };
      }
      return { ok: true, data: {} };
    });

    render(<GovernancePanel />);

    expect(await screen.findByText(/arn:aws:iam::123:role\/Prod/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }));
    await waitFor(() => {
      expect(postMock).toHaveBeenCalledWith('/api/access-requests/jit-1/approve', expect.any(Object));
    });

    fireEvent.change(screen.getByLabelText('Target resource ID'), { target: { value: 'i-0abc123' } });
    fireEvent.change(screen.getByLabelText('Justification'), { target: { value: 'Deploy hotfix' } });
    fireEvent.click(screen.getByRole('button', { name: 'Submit Request' }));
    await waitFor(() => {
      expect(postMock).toHaveBeenCalledWith('/api/access-requests', expect.objectContaining({ target_id: 'i-0abc123' }));
    });

    fireEvent.click(screen.getByRole('button', { name: 'DLP & Firewall' }));
    expect(await screen.findByText('Block rm -rf')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Simulate Policy' }));
    expect(await screen.findByText('Destructive command blocked')).toBeInTheDocument();
    expect(screen.getByText(/Sample DB DLP redacted 3 cells/)).toBeInTheDocument();
  });
});
