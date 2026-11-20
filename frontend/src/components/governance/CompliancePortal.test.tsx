import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CompliancePortal } from './CompliancePortal';
import { useAuthStore } from '@/stores/auth';
import { api } from '@/lib/api';

vi.mock('@/lib/api', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
  },
}));

describe('CompliancePortal', () => {
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

  it('renders SOC 2 posture controls, certifies access review items, and exports signed evidence', async () => {
    const getMock = vi.mocked(api.get);
    const postMock = vi.mocked(api.post);

    getMock.mockImplementation(async (path: string) => {
      if (path === '/api/compliance/posture') {
        return {
          ok: true,
          data: {
            tenant_id: 'default',
            generated_at: 1000,
            compliance_mode: true,
            audit_chain_valid: true,
            audit_source: 'postgres',
            audit_checked_events: 42,
            total_recordings: 4,
            encrypted_recordings: 4,
            legal_hold_recordings: 1,
            jit_pending_requests: 0,
            jit_active_grants: 1,
            dlp_firewall_enabled: true,
            webhooks_configured: 1,
            controls: [
              {
                control_id: 'CC6.3',
                framework: 'SOC 2 Type II',
                title: 'Quarterly Access Reviews & Least-Privilege Recertification',
                status: 'passing',
                evidence: '1 access review campaign(s) recorded',
              },
            ],
          },
        };
      }
      if (path === '/api/compliance/access-reviews') {
        return {
          ok: true,
          data: {
            campaigns: [
              {
                id: 'arc-1',
                title: 'Q4 Review',
                quarter: '2026-Q4',
                status: 'active',
                created_by: 'admin@local',
                created_at: 1000,
                items: [
                  {
                    item_id: 'ari-1',
                    principal_id: 'u-1',
                    principal_email: 'alice@local',
                    role: 'operator',
                    target_summary: 'provider=local disabled=false',
                    mfa_enabled: true,
                    decision: 'pending',
                    note: '',
                  },
                ],
              },
            ],
          },
        };
      }
      return { ok: true, data: {} };
    });

    postMock.mockImplementation(async (path: string) => {
      if (path.includes('/items/')) {
        return { ok: true, data: { id: 'arc-1' } };
      }
      if (path === '/api/compliance/evidence-bundle') {
        return {
          ok: true,
          data: {
            bundle: { tenant_id: 'default' },
            integrity: {
              algorithm: 'Ed25519-SHA256',
              public_key_b64: 'pk',
              payload_sha256: 'abc123def',
              signature_b64: 'sig',
              signed_at: 1000,
            },
          },
        };
      }
      if (path === '/api/compliance/evidence-bundle/verify') {
        return {
          ok: true,
          data: { valid: true, algorithm: 'Ed25519-SHA256', payload_sha256: 'abc123def' },
        };
      }
      return { ok: true, data: {} };
    });

    render(<CompliancePortal />);

    expect(await screen.findByText('CC6.3')).toBeInTheDocument();
    expect(screen.getByText('alice@local')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Certify' }));
    await waitFor(() => {
      expect(postMock).toHaveBeenCalledWith(
        '/api/compliance/access-reviews/arc-1/items/ari-1',
        expect.objectContaining({ decision: 'certified' }),
      );
    });

    fireEvent.click(screen.getByRole('button', { name: 'Export Signed Evidence' }));
    expect(await screen.findByText(/SHA-256: abc123def/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Verify Signature' }));
    expect(await screen.findByText('Ed25519 signature verified cleanly')).toBeInTheDocument();
  });
});
