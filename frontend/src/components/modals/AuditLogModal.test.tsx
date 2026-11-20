import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { AuditLogModal } from './AuditLogModal';
import { DialogPageContext } from '@/components/primitives/Dialog';
import { api } from '@/lib/api';

vi.mock('@/lib/api', () => ({ api: { get: vi.fn() } }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

const showAudit = () => render(<DialogPageContext.Provider value><AuditLogModal open onOpenChange={() => {}} /></DialogPageContext.Provider>);

it('shows an access error instead of an empty audit log', async () => {
  vi.mocked(api.get).mockResolvedValue({ ok: false, error: { status: 403, message: 'Forbidden' } as never });
  showAudit();
  expect(await screen.findByRole('alert')).toHaveTextContent(/administrator/i);
  expect(screen.queryByText('No entries')).not.toBeInTheDocument();
});

it('pages audit entries and shows their available context', async () => {
  const event = { timestamp: '2026-01-01T01:02:03Z', action: 'request', outcome: 'error', user_email: 'a@example.com', user_id: 'user-1', tenant_id: 'local', ip: '192.0.2.1', user_agent: 'browser', profile: 'dev', region: 'us-east-1', method: 'POST', status_code: 502 };
  vi.mocked(api.get).mockResolvedValueOnce({ ok: true, data: Array(100).fill(event) }).mockResolvedValueOnce({ ok: true, data: [{ ...event, action: 'older' }] });
  showAudit();
  const details = await screen.findAllByRole('button', { name: /details for request/i });
  fireEvent.click(details[0]);
  expect(screen.getByText('user-1')).toBeInTheDocument();
  expect(screen.getByText('502')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: 'Older events' }));
  await waitFor(() => expect(api.get).toHaveBeenLastCalledWith('/audit-log?limit=100&offset=100'));
  expect(await screen.findByRole('button', { name: 'Details for older' })).toBeInTheDocument();
});

it('offers a recording from the audit row and shows the browser that opened the app', async () => {
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: [
    { timestamp: '2026-01-01T01:02:03Z', action: 'aws_terminal_start', outcome: 'success', user_email: 'admin@local', instance_id: 'i-1', region: 'ap-south-1', profile: 'AdministratorAccess', method: 'GET', status_code: 101, ip: '127.0.0.1', client: 'Chrome 156 on macOS', user_agent: 'Mozilla/5.0 Chrome/156.0.0.0 Safari/537.36', recording: 'admin-host.cast' },
  ] });
  showAudit();
  fireEvent.click(await screen.findByRole('button', { name: 'Details for aws_terminal_start' }));
  expect(screen.getByText('Chrome 156 on macOS')).toBeInTheDocument();
  expect(screen.getAllByText('i-1').length).toBeGreaterThan(0);
  expect(screen.getByText('ap-south-1')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Watch admin-host.cast' })).toBeInTheDocument();
});

it('shows Kubernetes interactions in the audit log', async () => {
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: [
    { timestamp: '2026-01-01T01:02:03Z', action: 'kubernetes_exec_attempt', outcome: 'attempt', user_email: 'operator@example.com', details: 'namespace=prod pod=web' },
    { timestamp: '2026-01-01T01:02:04Z', action: 'kubernetes_edit', outcome: 'success', user_email: 'operator@example.com', details: 'namespace=prod name=web' },
    { timestamp: '2026-01-01T01:02:05Z', action: 'kubernetes_restart', outcome: 'success', user_email: 'operator@example.com', details: 'namespace=prod name=web' },
  ] });
  showAudit();
  expect(await screen.findByRole('button', { name: 'Details for kubernetes_exec_attempt' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Details for kubernetes_edit' })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Details for kubernetes_restart' })).toBeInTheDocument();
});
