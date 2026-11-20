import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { UserAWSTransfer } from './UserAWSTransfer';

vi.mock('@/lib/credentialTransport', () => ({ canSendCredentials: () => true }));
afterEach(() => vi.restoreAllMocks());

it('uploads through the selected user role after confirmation', async () => {
  const fetcher = vi.spyOn(window, 'fetch').mockResolvedValue(new Response(JSON.stringify({ status: 'complete' }), { status: 200 }));
  vi.spyOn(window, 'confirm').mockReturnValue(true);
  render(<UserAWSTransfer mode="upload" roleID="role" instanceID="i-example" region="us-east-1" platform="linux" onClose={() => {}} />);
  fireEvent.change(screen.getByLabelText('Remote path'), { target: { value: '/tmp/test' } });
  fireEvent.change(screen.getByLabelText('File'), { target: { files: [new File(['hello'], 'test.txt')] } });
  fireEvent.click(screen.getByRole('button', { name: 'Upload file' }));
  await screen.findByText('Upload complete.');
  const [path, options] = fetcher.mock.calls[0];
  expect(path).toBe('/api/aws/transfer/upload');
  const body = options?.body as FormData;
  expect(body.get('binding_id')).toBe('role');
  expect(body.get('instance_id')).toBe('i-example');
  expect(body.get('remote_path')).toBe('/tmp/test');
});

it('rejects an oversized file before sending it', async () => {
  const fetcher = vi.spyOn(window, 'fetch');
  const file = new File(['x'], 'large');
  Object.defineProperty(file, 'size', { value: 32 * 1024 * 1024 + 1 });
  render(<UserAWSTransfer mode="upload" roleID="role" instanceID="i-example" region="us-east-1" platform="linux" onClose={() => {}} />);
  fireEvent.change(screen.getByLabelText('Remote path'), { target: { value: '/tmp/test' } });
  fireEvent.change(screen.getByLabelText('File'), { target: { files: [file] } });
  fireEvent.click(screen.getByRole('button', { name: 'Upload file' }));
  await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('32 MiB'));
  expect(fetcher).not.toHaveBeenCalled();
});

it('downloads only after the role-scoped server returns the file', async () => {
  const fetcher = vi.spyOn(window, 'fetch').mockResolvedValue(new Response(JSON.stringify({ data: btoa('hello'), filename: 'file.txt' }), { status: 200 }));
  const createURL = vi.fn().mockReturnValue('blob:test');
  vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: createURL, revokeObjectURL: vi.fn() }));
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  render(<UserAWSTransfer mode="download" roleID="role" instanceID="i-example" region="us-east-1" platform="linux" onClose={() => {}} />);
  fireEvent.change(screen.getByLabelText('Remote path'), { target: { value: '/tmp/file.txt' } });
  fireEvent.click(screen.getByRole('button', { name: 'Download file' }));
  await screen.findByText('Download complete.');
  expect(fetcher).toHaveBeenCalledWith('/api/aws/transfer/download', expect.objectContaining({ method: 'POST', body: expect.stringContaining('"binding_id":"role"') }));
  expect(createURL).toHaveBeenCalledOnce();
  expect(click).toHaveBeenCalledOnce();
  vi.unstubAllGlobals();
});

it('browses with the selected role and fills the chosen file path', async () => {
  const fetcher = vi.spyOn(window, 'fetch').mockResolvedValue(new Response(JSON.stringify([{ name: 'file.txt', is_dir: false, size: 5, modified: '' }]), { status: 200 }));
  render(<UserAWSTransfer mode="download" roleID="role" instanceID="i-example" region="us-east-1" platform="linux" onClose={() => {}} />);
  fireEvent.click(screen.getByRole('button', { name: 'Browse files' }));
  await screen.findByRole('button', { name: 'file.txt' });
  expect(fetcher).toHaveBeenCalledWith('/api/aws/transfer/browse', expect.objectContaining({ method:'POST', body:JSON.stringify({ binding_id:'role', instance_id:'i-example', region:'us-east-1', remote_path:'/', platform:'linux' }) }));
  fireEvent.click(screen.getByRole('button', { name: 'file.txt' }));
  expect(screen.getByLabelText('Remote path')).toHaveValue('/file.txt');
});

it('requests express transfer with the selected bucket and warns about access and cleanup', async () => {
  const fetcher = vi.spyOn(window, 'fetch').mockResolvedValue(new Response(JSON.stringify({ status:'complete' }), { status:200 }));
  vi.spyOn(window, 'confirm').mockReturnValue(true);
  render(<UserAWSTransfer mode="upload" roleID="role" instanceID="i-example" region="us-east-1" platform="linux" onClose={() => {}} />);
  fireEvent.change(screen.getByLabelText('Remote path'), { target:{ value:'/tmp/file' } });
  fireEvent.change(screen.getByLabelText('File'), { target:{ files:[new File(['hello'], 'file')] } });
  fireEvent.click(screen.getByLabelText('Express via S3'));
  fireEvent.change(screen.getByLabelText('S3 bucket'), { target:{ value:'test-bucket' } });
  expect(screen.getByText(/Bucket permissions determine/)).toBeInTheDocument();
  expect(screen.getByText(/lifecycle rule/)).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name:'Upload file' }));
  await screen.findByText('Upload complete.');
  expect((fetcher.mock.calls[0]![1]!.body as FormData).get('express_bucket')).toBe('test-bucket');
});
