import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import type { AccountNode, EC2Instance } from '@/lib/types';
import { useInstancesStore } from '@/stores/instances';
import { Sidebar } from './Sidebar';

vi.mock('zustand/middleware', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  persist: (fn: unknown) => fn,
  createJSONStorage: () => undefined,
}));
vi.mock('./InstanceContextMenu', () => ({ InstanceContextMenu: () => null }));
vi.mock('./AccountGroup', () => ({
  AccountGroup: ({ account }: { account: { account_alias: string } }) => <div>{account.account_alias}</div>,
}));

function makeInstance(overrides: Partial<EC2Instance> = {}): EC2Instance {
  return {
    instance_id: 'i-001',
    name: 'alpha-web',
    state: 'running',
    platform: 'linux',
    os: 'ubuntu',
    instance_type: 't3.micro',
    aws_profile: 'dev',
    aws_region: 'us-east-1',
    account_id: '111122223333',
    account_alias: 'Sycamore Informatics',
    tag1_value: 'web',
    tag2_value: 'DEV',
    private_ip: '10.0.0.10',
    ...overrides,
  };
}

function makeAccounts(instances: EC2Instance[]): AccountNode[] {
  return [
    {
      account_id: '111122223333',
      account_alias: 'Sycamore Informatics',
      profile: 'dev',
      provider: 'aws',
      regions: [
        {
          region: 'us-east-1',
          groups: [{ tag1: 'web', tag2: 'DEV', instances }],
        },
      ],
    },
  ];
}

afterEach(() => {
  cleanup();
  useInstancesStore.setState({ accounts: [], favorites: [], filter: '' });
});

it('renders FavoritesPanel only in the Favorites filter tab and avoids duplicate trees', () => {
  const favRunning = makeInstance({ instance_id: 'i-fav-1', name: 'fav-perf-node', state: 'running' });
  const favStopped = makeInstance({ instance_id: 'i-fav-2', name: 'fav-dev-win', state: 'stopped', platform: 'windows' });
  const other = makeInstance({ instance_id: 'i-other', name: 'other-node', state: 'running' });

  useInstancesStore.setState({
    accounts: makeAccounts([favRunning, favStopped, other]),
    favorites: ['i-fav-1', 'i-fav-2'],
    filter: '',
    fetchInstances: async () => {},
    watchDiscovery: () => () => {},
  });

  render(<Sidebar />);

  // 1. Default All view hides FavoritesPanel while showing cloud/account groups
  expect(screen.queryByRole('region', { name: 'Favorites' })).not.toBeInTheDocument();
  expect(screen.getByRole('group', { name: 'AWS accounts' })).toHaveTextContent('Sycamore Informatics');

  // 2. Running view hides FavoritesPanel while showing cloud/account groups
  fireEvent.click(screen.getByRole('button', { name: /Running \(2\)/ }));
  expect(screen.queryByRole('region', { name: 'Favorites' })).not.toBeInTheDocument();
  expect(screen.getByRole('group', { name: 'AWS accounts' })).toBeInTheDocument();

  // 3. Favorites view renders FavoritesPanel only, with no duplicate AWS accounts group underneath
  fireEvent.click(screen.getByRole('button', { name: /Favorites \(2\)/ }));
  const favSection = screen.getByRole('region', { name: 'Favorites' });
  expect(favSection).toHaveTextContent('fav-perf-node');
  expect(favSection).toHaveTextContent('fav-dev-win');
  expect(screen.queryByRole('group', { name: 'AWS accounts' })).not.toBeInTheDocument();

  // 4. Typing into filter narrows instances rendered inside FavoritesPanel
  fireEvent.change(screen.getByRole('textbox', { name: 'Filter instances' }), {
    target: { value: 'fav-dev-win' },
  });
  const narrowed = screen.getByRole('region', { name: 'Favorites' });
  expect(narrowed).not.toHaveTextContent('fav-perf-node');
  expect(narrowed).toHaveTextContent('fav-dev-win');
});

it('shows dedicated empty message when Favorites filter has zero starred instances', () => {
  useInstancesStore.setState({
    accounts: makeAccounts([makeInstance()]),
    favorites: [],
    filter: '',
    fetchInstances: async () => {},
    watchDiscovery: () => () => {},
  });

  render(<Sidebar />);

  fireEvent.click(screen.getByRole('button', { name: /Favorites \(0\)/ }));
  expect(screen.getByText('No favorite instances yet.')).toBeInTheDocument();
  expect(screen.queryByText('No instances are available.')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Add an account' })).not.toBeInTheDocument();
});
