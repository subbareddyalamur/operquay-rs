// @vitest-environment-options {"url":"https://desk.example/"}
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { TerminalSession } from './TerminalSession';
import { api } from '@/lib/api';
import type * as ApiModule from '@/lib/api';
import { useSessionsStore } from '@/stores/sessions';
import type { Instance } from '@/stores/instances';

vi.mock('@/components/rdp/RdpDesktopClient', () => ({ RdpDesktopClient: () => <div>RDP</div> }));
vi.mock('./Xterm', () => ({ Xterm: () => null }));
vi.hoisted(() => { window.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} }) as unknown as MediaQueryList; });
vi.mock('@/lib/api', async importOriginal => ({ ...(await importOriginal<typeof ApiModule>()), api: { get: vi.fn(), post: vi.fn() } }));
afterEach(() => { cleanup(); vi.resetAllMocks(); useSessionsStore.setState({ sessions: [], activeId: null }); });

it('shows RDP recording only after the requested file exists and contains data', async () => {
  useSessionsStore.setState({ sessions: [{ id: 's', instanceId: 'i-1', instanceName: 'Windows', type: 'rdp', status: 'connected', createdAt: 1 }], activeId: 's' });
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: [{ name: 'user-Windows-date.guac', size: 128 }] });
  const instance = { instance_id: 'i-1', name: 'Windows' } as Instance;
  const view = render(<TerminalSession instance={instance} sessionId="s" sessionType="rdp" rdpToken="ticket" />);
  expect(screen.queryByLabelText('Recording')).not.toBeInTheDocument();
  view.rerender(<TerminalSession instance={instance} sessionId="s" sessionType="rdp" rdpToken="ticket" rdpRecordingName="user-Windows-date.guac" />);
  await waitFor(() => expect(screen.getByLabelText('Recording')).toBeInTheDocument());
  act(() => useSessionsStore.getState().updateStatus('s', 'disconnected'));
  await waitFor(() => expect(screen.queryByLabelText('Recording')).not.toBeInTheDocument());
});

it.each([
  { ok: true, data: [] },
  { ok: true, data: [{ name: 'expected.guac', size: 0 }] },
  { ok: false, error: { status: 500, message: 'unavailable' } },
])('does not show a recording indicator when the file is unconfirmed', async result => {
  useSessionsStore.setState({ sessions: [{ id: 's', instanceId: 'i-1', instanceName: 'Windows', type: 'rdp', status: 'connected', createdAt: 1 }], activeId: 's' });
  vi.mocked(api.get).mockResolvedValue(result as never);
  render(<TerminalSession instance={{ instance_id: 'i-1', name: 'Windows' } as Instance} sessionId="s" sessionType="rdp" rdpToken="ticket" rdpRecordingName="expected.guac" />);
  await waitFor(() => expect(api.get).toHaveBeenCalled());
  expect(screen.queryByLabelText('Recording')).not.toBeInTheDocument();
});
