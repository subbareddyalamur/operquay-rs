import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { apiGet } from '@/lib/api';
import { UserTopologyPeers } from './UserTopologyPeers';

vi.mock('@/lib/api', () => ({ apiGet: vi.fn() }));
afterEach(() => { cleanup(); vi.clearAllMocks(); });

it('allows explicit connected peer role selection without selecting another role from the source account', async () => {
  vi.mocked(apiGet).mockResolvedValue({ ok: true, value: [
    { id: 'source', label: 'Source', account_id: '111111111111' },
    { id: 'same', label: 'Same account', account_id: '111111111111' },
    { id: 'peer', label: 'Peer role', account_id: '222222222222' },
  ] });
  const change = vi.fn();
  render(<UserTopologyPeers roleID="source" selected={[]} onChange={change} />);
  expect(await screen.findByLabelText('Peer role · 222222222222')).toBeEnabled();
  expect(screen.getByLabelText('Same account · 111111111111')).toBeDisabled();
  fireEvent.click(screen.getByLabelText('Peer role · 222222222222'));
  expect(change).toHaveBeenCalledWith(['peer']);
});
