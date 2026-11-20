import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import { UserAWSBindings } from './UserAWSBindings';

const { get, post, del } = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), del: vi.fn() }));
vi.mock('@/lib/api', () => ({ api: { get, post, delete: del } }));
vi.mock('@/lib/credentialTransport', () => ({ canSendCredentials: () => true }));

beforeEach(() => { get.mockReset(); post.mockReset(); del.mockReset(); });

it('lets an administrator add and remove an optional AWS start URL', async () => {
  get.mockResolvedValue({ ok: true, data: [] });
  post.mockResolvedValue({ ok: true, data: { id: 'provider', label: 'Company', start_url: 'https://company.awsapps.com/start', region: 'us-east-1' } });
  del.mockResolvedValue({ ok: true, data: {} });
  vi.spyOn(window, 'confirm').mockReturnValue(true);
  render(<UserAWSBindings />);
  fireEvent.change(screen.getByLabelText('AWS connection label'), { target: { value: 'Company' } });
  fireEvent.change(screen.getByLabelText('AWS start URL'), { target: { value: 'https://company.awsapps.com/start' } });
  fireEvent.change(screen.getByLabelText('Identity Center region'), { target: { value: 'us-east-1' } });
  fireEvent.click(screen.getByRole('button', { name: 'Add start URL' }));
  expect(await screen.findByText('Company', { exact: true })).toBeInTheDocument();
  expect(post).toHaveBeenCalledWith('/api/aws/sso-providers', { label: 'Company', start_url: 'https://company.awsapps.com/start', region: 'us-east-1' });
  fireEvent.click(screen.getByRole('button', { name: 'Remove Company' }));
  await waitFor(() => expect(del).toHaveBeenCalledWith('/api/aws/sso-providers/provider'));
  expect(screen.queryByText('Company', { exact: true })).not.toBeInTheDocument();
  vi.restoreAllMocks();
});
