import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { UserAWSClone } from './UserAWSClone';
import { api } from '@/lib/api';

vi.mock('@/lib/api', () => ({ api: { get: vi.fn(), post: vi.fn() } }));
afterEach(() => { cleanup(); vi.clearAllMocks(); vi.restoreAllMocks(); });

it('creates, checks and launches a session-scoped clone with reviewed settings', async () => {
  vi.spyOn(window, 'confirm').mockReturnValue(true);
  vi.spyOn(crypto, 'randomUUID').mockReturnValue('11111111-1111-4111-8111-111111111111');
  const id = '11111111-1111-4111-8111-111111111111';
  vi.mocked(api.get).mockImplementation(async path => {
    if (path.includes('/settings')) return { ok:true, data:{ ami_id:'ami-clone', instance_type:'t3.small', subnet_id:'subnet-test', security_group_ids:['sg-test'], key_name:'', iam_profile:'', tags:{ Name:'copy' } } };
    if (path.includes(id)) return { ok:true, data:{ id, source_instance_id:'i-source', clone_name:'copy', region:'us-east-1', phase:'image_ready', image_id:'ami-clone' } };
    return { ok:true, data:[] };
  });
  vi.mocked(api.post).mockImplementation(async path => ({ ok:true, data: path.endsWith('/start')
    ? { id, source_instance_id:'i-source', clone_name:'copy', region:'us-east-1', phase:'image_pending', image_id:'ami-clone' }
    : { id, source_instance_id:'i-source', clone_name:'copy', region:'us-east-1', phase:'launch_unknown', image_id:'ami-clone' } }));
  render(<UserAWSClone roleID="role-a" region="us-east-1" instanceID="i-source" instanceName="source" />);
  fireEvent.click(screen.getByText('Clone instance'));
  fireEvent.change(screen.getByLabelText('Clone name for i-source'), { target:{ value:'copy' } });
  fireEvent.click(screen.getByRole('button', { name:'Create clone image for i-source' }));
  expect(await screen.findByText(/AMI creation is pending/)).toBeInTheDocument();
  expect(api.post).toHaveBeenCalledWith('/api/aws/clones/start', { request_id:id, binding_id:'role-a', region:'us-east-1', instance_id:'i-source', clone_name:'copy' });
  fireEvent.click(screen.getByRole('button', { name:`Check clone ${id}` }));
  expect(await screen.findByText(/AMI is ready/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name:`Configure clone ${id}` }));
  expect(await screen.findByLabelText('Clone instance type')).toHaveValue('t3.small');
  fireEvent.click(screen.getByRole('button', { name:'Launch clone' }));
  await waitFor(() => expect(api.post).toHaveBeenCalledWith(`/api/aws/clones/${id}/launch`, expect.objectContaining({ binding_id:'role-a', settings: expect.objectContaining({ ami_id:'ami-clone', subnet_id:'subnet-test' }) })));
  expect(await screen.findByText(/Launch outcome is unknown/)).toBeInTheDocument();
});

it('only transfers a verified older operation after explicit confirmation', async () => {
  const confirm = vi.spyOn(window, 'confirm').mockReturnValueOnce(false).mockReturnValueOnce(true);
  const id = '11111111-1111-4111-8111-111111111111';
  const clone = { id, source_instance_id:'i-source', clone_name:'old-copy', region:'us-east-1', phase:'launch_unknown', image_id:'ami-clone', image_name:`operquay-clone-${id}` };
  vi.mocked(api.get).mockImplementation(async path => path.includes('/recoverable?') ? { ok:true, data:{ operations:[clone], incomplete:true } } : { ok:true, data:[] });
  vi.mocked(api.post).mockResolvedValue({ ok:true, data:clone });
  render(<UserAWSClone roleID="new-role" region="us-east-1" instanceID="i-source" instanceName="source" />);
  fireEvent.click(screen.getByText('Clone instance'));
  fireEvent.click(screen.getByRole('button', { name:'Find earlier clones for i-source' }));
  expect(await screen.findByRole('button', { name:`Recover clone ${id}` })).toBeInTheDocument();
  expect(screen.getByText(/Some earlier operations may be missing/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name:`Recover clone ${id}` }));
  expect(api.post).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name:`Recover clone ${id}` }));
  await waitFor(() => expect(api.post).toHaveBeenCalledWith(`/api/aws/clones/${id}/recover`, { binding_id:'new-role' }));
  expect(await screen.findByText(/Launch outcome is unknown/)).toBeInTheDocument();
  expect(confirm).toHaveBeenCalledTimes(2);
});
