import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '@/lib/api';
import { useInstancesStore } from '@/stores/instances';
import { useLayoutStore } from '@/stores/layout';
import { useSettingsStore } from '@/stores/settings';
import { Sidebar } from './Sidebar';

vi.mock('zustand/middleware', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  persist: (fn: unknown) => fn,
  createJSONStorage: () => undefined,
}));
vi.mock('@/lib/credentialTransport', () => ({ canSendCredentials: () => true }));
vi.mock('./FavoritesPanel', () => ({ FavoritesPanel: () => null }));
vi.mock('./InstanceContextMenu', () => ({ InstanceContextMenu: () => null }));
vi.mock('./AccountGroup', () => ({
  AccountGroup: ({ account }: { account: { account_alias: string } }) => <div>{account.account_alias}</div>,
}));

describe('Sidebar Kubernetes view', () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
    useSettingsStore.setState({ enableKubernetes: true, enableDatabases: true });
    useLayoutStore.setState({ view: 'kubernetes' });
    useInstancesStore.setState({ accounts: [], filter: '', fetchInstances: async () => {}, watchDiscovery: () => () => {} });
  });

  afterEach(() => {
    cleanup();
    vi.restoreAllMocks();
  });

  it('removes the Unified badge and selects/highlights only one cluster at a time', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/api/k8s/configured-clusters') {
        return {
          ok: true,
          data: [
            {
              id: 'c1',
              label: 'syca-plat-euc1-higher-1',
              proxy: 'higher-1.teleport.example.com',
              cluster_name: 'eks-higher-1',
              method: 'password',
              connector: 'teleport',
            },
            {
              id: 'c2',
              label: 'syca-plat-euc1-lower-1',
              proxy: 'lower-1.teleport.example.com',
              cluster_name: 'eks-lower-1',
              method: 'password',
              connector: 'teleport',
            },
            {
              id: 'c3',
              label: 'syca-plat-use2-staging',
              proxy: 'staging.teleport.example.com',
              cluster_name: 'eks-staging',
              method: 'password',
              connector: 'teleport',
            },
          ],
        } as never;
      }
      return { ok: true, data: [] } as never;
    });

    render(<Sidebar />);

    expect(screen.queryByText('Unified')).not.toBeInTheDocument();

    await waitFor(() => {
      expect(screen.getByText('syca-plat-euc1-higher-1')).toBeInTheDocument();
      expect(screen.getByText('syca-plat-euc1-lower-1')).toBeInTheDocument();
      expect(screen.getByText('syca-plat-use2-staging')).toBeInTheDocument();
    });

    expect(screen.queryByText('Live')).not.toBeInTheDocument();

    const firstCard = screen.getByText('syca-plat-euc1-higher-1').closest('button')!;
    const secondCard = screen.getByText('syca-plat-euc1-lower-1').closest('button')!;
    fireEvent.click(firstCard);

    expect(screen.getAllByText('Selected')).toHaveLength(1);
    expect(firstCard).toHaveTextContent('Selected');
    expect(secondCard).not.toHaveTextContent('Selected');
    expect(secondCard).toHaveTextContent('Teleport');

    window.sessionStorage.setItem(
      'operquay:k8s:session',
      JSON.stringify({
        activeCluster: 'conn-2',
        connections: [{ id: 'conn-2', info: { name: 'eks-lower-1', cluster_name: 'eks-lower-1' } }],
      }),
    );
    fireEvent(window, new CustomEvent('operquay:k8s-session-changed'));

    await waitFor(() => {
      expect(screen.getAllByText('Live')).toHaveLength(1);
    });
    expect(secondCard).toHaveTextContent('Live');
    expect(firstCard).not.toHaveTextContent('Live');
  });

  it('shows full cluster text on hover when truncated and skips when not truncated', async () => {
    vi.spyOn(api, 'get').mockImplementation(async (path: string) => {
      if (path === '/api/k8s/configured-clusters') {
        return {
          ok: true,
          data: [
            {
              id: 'c1',
              label: 'eks-eu-higher-very-long-cluster-name-that-wraps',
              proxy: 'higher-1.teleport.example.com',
              cluster_name: 'eks-higher-1',
              method: 'password',
              connector: 'teleport',
            },
            {
              id: 'c2',
              label: 'eks-short',
              proxy: 'short.teleport.example.com',
              cluster_name: 'eks-short',
              method: 'password',
              connector: 'eks',
            },
          ],
        } as never;
      }
      return { ok: true, data: [] } as never;
    });

    render(<Sidebar />);

    const longNode = await screen.findByText('eks-eu-higher-very-long-cluster-name-that-wraps');
    const shortNode = screen.getByText('eks-short');

    Object.defineProperty(longNode, 'scrollWidth', { value: 280, configurable: true });
    Object.defineProperty(longNode, 'clientWidth', { value: 110, configurable: true });
    Object.defineProperty(shortNode, 'scrollWidth', { value: 60, configurable: true });
    Object.defineProperty(shortNode, 'clientWidth', { value: 140, configurable: true });

    const shortCard = shortNode.closest('button')!;
    fireEvent.pointerEnter(shortCard);
    fireEvent.mouseEnter(shortCard);
    await new Promise((r) => setTimeout(r, 450));
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();
    fireEvent.pointerLeave(shortCard);
    fireEvent.mouseLeave(shortCard);

    const longCard = longNode.closest('button')!;
    fireEvent.pointerEnter(longCard);
    fireEvent.mouseEnter(longCard);

    await waitFor(
      () => {
        const tooltip = screen.getByRole('tooltip');
        expect(tooltip).toHaveTextContent('eks-eu-higher-very-long-cluster-name-that-wraps');
      },
      { timeout: 1500 },
    );
  });
});
