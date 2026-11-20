import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { KubeRecordingPolicy } from './KubeRecordingPolicy';
import { api } from '@/lib/api';

vi.mock('@/lib/api', () => ({ api: { get: vi.fn(), put: vi.fn() } }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

it('edits a cluster policy without changing the default policy', async () => {
  vi.mocked(api.get).mockImplementation(async path => path === '/api/k8s/configured-clusters' ? { ok:true, data:[{ id:'1', label:'Production', proxy:'proxy.example.com', cluster_name:'prod', method:'local', connector:'' }] } : { ok:true, data:{ mode:'all', namespaces:[], inherited:true } });
  vi.mocked(api.put).mockResolvedValue({ ok:true, data:{ mode:'selected', namespaces:['payments'] } });
  render(<KubeRecordingPolicy />);
  fireEvent.click(await screen.findByRole('button', { name:/Production/ }));
  expect(await screen.findByText('Uses the default policy until saved.')).toBeInTheDocument();
  fireEvent.click(screen.getByLabelText('Selected namespaces'));
  fireEvent.change(screen.getByLabelText('Namespace'), { target:{ value:'payments' } });
  fireEvent.click(screen.getByRole('button', { name:'Add namespace' }));
  fireEvent.click(screen.getByRole('button', { name:'Save Kubernetes policy' }));
  await waitFor(() => expect(api.put).toHaveBeenCalledWith('/api/k8s/configured-clusters/1/recording', { mode:'selected', namespaces:['payments'] }));
});
