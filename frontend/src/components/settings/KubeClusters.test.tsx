import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { KubeClusters } from './KubeClusters';
import { api } from '@/lib/api';

vi.mock('@/lib/api', () => ({ api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), delete: vi.fn() } }));
afterEach(() => { cleanup(); vi.resetAllMocks(); });

it('adds a cluster without storing user credentials', async () => {
  vi.mocked(api.get).mockResolvedValue({ ok: true, data: [] });
  vi.mocked(api.post).mockResolvedValue({ ok: true, data: { id:'1', label:'Prod', proxy:'proxy.example.com', cluster_name:'prod', method:'local', connector:'' } });
  render(<KubeClusters />);
  fireEvent.click(await screen.findByRole('button', { name:'Add cluster' }));
  fireEvent.change(screen.getByLabelText('Display label'), { target:{ value:'Prod' } });
  fireEvent.change(screen.getByLabelText('Teleport proxy'), { target:{ value:'proxy.example.com' } });
  fireEvent.change(screen.getByLabelText('Teleport cluster name'), { target:{ value:'prod' } });
  fireEvent.click(screen.getByRole('button', { name:'Save cluster' }));
  await waitFor(() => expect(api.post).toHaveBeenCalledWith('/api/k8s/configured-clusters', { label:'Prod', proxy:'proxy.example.com', cluster_name:'prod', method:'local', connector:'' }));
  expect(await screen.findByText('proxy.example.com')).toBeInTheDocument();
});

it('keeps the form open on failure', async () => {
  vi.mocked(api.get).mockResolvedValue({ ok:true, data:[] });
  vi.mocked(api.post).mockResolvedValue({ ok:false, error:{ status:500, message:'failure', name:'APIError', body:null } });
  render(<KubeClusters />);
  fireEvent.click(await screen.findByRole('button', { name:'Add cluster' }));
  fireEvent.change(screen.getByLabelText('Display label'), { target:{ value:'Prod' } });
  fireEvent.change(screen.getByLabelText('Teleport proxy'), { target:{ value:'proxy.example.com' } });
  fireEvent.change(screen.getByLabelText('Teleport cluster name'), { target:{ value:'prod' } });
  fireEvent.click(screen.getByRole('button', { name:'Save cluster' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Could not save cluster');
  expect(screen.getByLabelText('Display label')).toHaveValue('Prod');
});
