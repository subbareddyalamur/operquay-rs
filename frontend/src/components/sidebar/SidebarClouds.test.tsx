import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { useInstancesStore } from '@/stores/instances';
import { Sidebar } from './Sidebar';

vi.mock('zustand/middleware', async importOriginal => ({ ...(await importOriginal<object>()), persist: (fn: unknown) => fn, createJSONStorage: () => undefined }));
vi.mock('./FavoritesPanel', () => ({ FavoritesPanel: () => null }));
vi.mock('./InstanceContextMenu', () => ({ InstanceContextMenu: () => null }));
vi.mock('./AccountGroup', () => ({ AccountGroup: ({ account }: { account: { account_alias: string } }) => <div>{account.account_alias}</div> }));

afterEach(() => { cleanup(); useInstancesStore.setState({ accounts: [], filter: '' }); });

it('groups accounts by cloud with an unknown group and keeps older AWS responses working', () => {
  useInstancesStore.setState({
    accounts: [
      { account_id: '1', account_alias: 'AWS team', profile: 'p', provider: 'aws', regions: [] },
      { account_id: '2', account_alias: 'Older AWS', profile: 'p', regions: [] },
      { account_id: '3', account_alias: 'Azure team', profile: 'p', provider: 'azure', regions: [] },
      { account_id: '4', account_alias: 'Other team', profile: 'p', provider: 'other', regions: [] },
    ],
    fetchInstances: async () => { }, watchDiscovery: () => () => { },
  });
  render(<Sidebar />);
  expect(screen.getByRole('group', { name: 'AWS accounts' })).toHaveTextContent('AWS team');
  expect(screen.getByRole('group', { name: 'AWS accounts' })).toHaveTextContent('Older AWS');
  expect(screen.getByRole('group', { name: 'Azure accounts' })).toHaveTextContent('Azure team');
  expect(screen.getByRole('group', { name: 'Unknown cloud accounts' })).toHaveTextContent('Other team');
  fireEvent.click(screen.getByRole('button', { name: /AWS accounts/ }));
  expect(screen.queryByText('AWS team')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button', { name: /AWS accounts/ }));
  expect(screen.getByText('AWS team')).toBeInTheDocument();
});

it('scopes the list to one account from provider-grouped choices', () => {
  useInstancesStore.setState({
    accounts: [
      { account_id: '1', account_alias: 'AWS team', profile: 'p', provider: 'aws', regions: [] },
      { account_id: '3', account_alias: 'Azure team', profile: 'p', provider: 'azure', regions: [] },
    ],
    fetchInstances: async () => { }, watchDiscovery: () => () => { },
  });
  render(<Sidebar />);
  fireEvent.click(screen.getByRole('button', { name: 'Cloud scope' }));
  const menu = screen.getByRole('menu', { name: 'Cloud scope' });
  expect(menu).toHaveTextContent('AWS');
  expect(menu).toHaveTextContent('Azure');
  expect(screen.getByRole('menuitemradio', { name: /All clouds/ })).toHaveAttribute('aria-checked', 'true');
  fireEvent.click(screen.getByRole('menuitemradio', { name: /Azure team/ }));
  expect(screen.queryByRole('group', { name: 'AWS accounts' })).not.toBeInTheDocument();
  expect(screen.getByRole('group', { name: 'Azure accounts' })).toHaveTextContent('Azure team');
  fireEvent.click(screen.getByRole('button', { name: 'Cloud scope' }));
  fireEvent.click(screen.getByRole('menuitemradio', { name: /All clouds/ }));
  expect(screen.getByRole('group', { name: 'AWS accounts' })).toBeInTheDocument();
});

it('offers a way to connect a cloud account when none is connected', async () => {
  const { useAuthStore } = await import('@/stores/auth');
  useAuthStore.setState({ config: { aws_access_mode: 'user' } as never, me: { user_id: 'u', email: 'u@example.com', role: 'user', tenant_id: 't', method: 'sso', expires_at: 1 } });
  useInstancesStore.setState({ accounts: [], userRoles: [], fetchInstances: async () => { }, watchDiscovery: () => () => { } });
  const opened = vi.fn();
  window.addEventListener('ct:open-aws-accounts', opened);
  render(<Sidebar />);
  fireEvent.click(screen.getByRole('button', { name: 'Connect a cloud account' }));
  expect(opened).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button', { name: 'Cloud scope' }));
  fireEvent.click(screen.getByRole('menuitem', { name: /Manage connections/ }));
  expect(opened).toHaveBeenCalledTimes(2);
  window.removeEventListener('ct:open-aws-accounts', opened);
  useAuthStore.setState({ config: null, me: null });
});
