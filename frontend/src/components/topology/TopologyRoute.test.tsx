import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { TopologyRoute } from './TopologyRoute';

vi.mock('@/hooks/useTopology', () => ({
  useTopology: () => ({ data: { vpc: { id: 'vpc-1' }, warnings: ['Some topology details are unavailable.'] }, isLoading: false, isRefetching: false }),
  useInvalidateTopology: () => vi.fn(),
}));
vi.mock('./TopologyCanvas', () => ({ TopologyCanvas: ({ instanceId }: { instanceId: string }) => <div>Topology canvas for {instanceId}</div> }));
afterEach(cleanup);

it('shows discovery limitations alongside the topology', () => {
  render(<TopologyRoute instanceId="i-1" />);
  expect(screen.getByRole('status')).toHaveTextContent('Some topology details are unavailable.');
  expect(screen.getByText('Topology canvas for i-1')).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: /architecture view|legacy tools/i })).not.toBeInTheDocument();
});
