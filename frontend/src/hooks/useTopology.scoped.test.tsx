import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useTopology } from './useTopology';
import { apiGet } from '@/lib/api';

vi.mock('@/lib/api', () => ({ apiGet: vi.fn() }));

it('keeps topology requests and cached results scoped to the selected role and tab', async () => {
  vi.mocked(apiGet).mockImplementation(async path => ({ ok:true, value:{ vpc:{ id:path.includes('role-b') ? 'vpc-b' : 'vpc-a' } } }));
  function View({ role, tab }: { role:string; tab:string }) {
    const { data } = useTopology('i-example', { roleID:role, region:'us-east-1', cacheKey:tab });
    return <div>{data?.vpc.id}</div>;
  }
  const client = new QueryClient({ defaultOptions:{ queries:{ retry:false } } });
  const ui = render(<QueryClientProvider client={client}><View role="role-a" tab="one" /></QueryClientProvider>);
  expect(await screen.findByText('vpc-a')).toBeInTheDocument();
  ui.rerender(<QueryClientProvider client={client}><View role="role-b" tab="two" /></QueryClientProvider>);
  await waitFor(() => expect(apiGet).toHaveBeenCalledWith('/api/aws/topology?binding_id=role-b&region=us-east-1&instance_id=i-example'));
  expect(await screen.findByText('vpc-b')).toBeInTheDocument();
  expect(screen.queryByText('vpc-a')).not.toBeInTheDocument();
  expect(vi.mocked(apiGet).mock.calls.every(([path]) => path.startsWith('/api/aws/topology?'))).toBe(true);
});

it('includes only explicitly selected peer roles in the request and cache key', async () => {
  vi.mocked(apiGet).mockImplementation(async path => ({ ok: true, value: { vpc: { id: path.includes('peer_binding_id') ? 'vpc-peers' : 'vpc-source' } } }));
  function View({ peers }: { peers: string[] }) {
    const { data } = useTopology('i-example', { roleID: 'role-a', region: 'us-east-1', cacheKey: 'tab', peerIDs: peers });
    return <div>{data?.vpc.id}</div>;
  }
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const ui = render(<QueryClientProvider client={client}><View peers={[]} /></QueryClientProvider>);
  expect(await screen.findByText('vpc-source')).toBeInTheDocument();
  ui.rerender(<QueryClientProvider client={client}><View peers={['peer-a']} /></QueryClientProvider>);
  expect(await screen.findByText('vpc-peers')).toBeInTheDocument();
  expect(apiGet).toHaveBeenCalledWith('/api/aws/topology?binding_id=role-a&region=us-east-1&instance_id=i-example&peer_binding_id=peer-a');
});
