import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, render, screen, waitFor } from '@testing-library/react';
import { App } from './App';
import { AuthGate } from '@/components/auth/SignInPage';
import type { AccountNode } from '@/lib/types';
import { useAuthStore, type AuthConfig, type Me } from '@/stores/auth';
import { useInstancesStore } from '@/stores/instances';
import { useLayoutStore } from '@/stores/layout';
import { usePaletteStore } from '@/stores/palette';
import { useSessionsStore } from '@/stores/sessions';

vi.hoisted(() => {
  const values = new Map<string, string>();
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
    removeItem: (key: string) => values.delete(key),
  });
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });
});

const AUTH_CONFIG: AuthConfig = {
  required: true,
  local: 'all',
  sso: { enabled: false, providers: [] },
  session_hours: 12,
  idle_minutes: 30,
  aws_access_mode: 'hub',
  version: 'test',
  revision: 'test',
};

const ADMIN_ME: Me = {
  user_id: 'u1',
  email: 'admin@example.com',
  username: 'admin',
  role: 'admin',
  tenant_id: 'local',
  method: 'password',
  expires_at: 9999999999,
};

const SAMPLE_ACCOUNTS: AccountNode[] = [
  {
    provider: 'aws',
    account_id: '123456789012',
    account_alias: 'prod',
    profile: 'prod',
    regions: [
      {
        region: 'us-east-1',
        groups: [
          {
            tag1: 'web',
            tag2: 'prod',
            instances: [
              {
                instance_id: 'i-01',
                name: 'web-01',
                state: 'running',
                platform: 'linux',
                os: 'ubuntu',
                instance_type: 't3.micro',
                aws_profile: 'prod',
                aws_region: 'us-east-1',
                account_id: '123456789012',
                account_alias: 'prod',
                tag1_value: 'web',
                tag2_value: 'prod',
                private_ip: '10.0.1.10',
              },
              {
                instance_id: 'i-02',
                name: 'web-02',
                state: 'stopped',
                platform: 'linux',
                os: 'ubuntu',
                instance_type: 't3.micro',
                aws_profile: 'prod',
                aws_region: 'us-east-1',
                account_id: '123456789012',
                account_alias: 'prod',
                tag1_value: 'web',
                tag2_value: 'prod',
                private_ip: '10.0.1.11',
              },
            ],
          },
        ],
      },
    ],
  },
];

function stubPostLoginFetch(accounts: AccountNode[] = []) {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input.toString();
    if (url.includes('/api/auth/config')) {
      return new Response(JSON.stringify(AUTH_CONFIG), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    if (url.includes('/api/auth/me')) {
      return new Response(JSON.stringify(ADMIN_ME), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    if (url.endsWith('/instances') || url.includes('/instances?')) {
      return new Response(JSON.stringify({ accounts }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return new Response(JSON.stringify({}), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

afterEach(() => {
  cleanup();
  useAuthStore.setState({ ready: false, config: null, me: null, expired: false, signInOpen: false });
  useInstancesStore.setState({ accounts: [], favorites: [], userRoles: [], loading: false, discovering: false });
  useSessionsStore.setState({ sessions: [], activeId: null });
  usePaletteStore.setState({ open: false, query: '' });
  useLayoutStore.setState({ view: 'session', returnView: 'session', settingsTab: 'appearance' });
  vi.restoreAllMocks();
});

describe('Post-login App workspace rendering', () => {
  it('renders App workspace cleanly after sign-in without crashing or showing closed dialogs', async () => {
    stubPostLoginFetch([]);

    render(
      <AuthGate>
        <App />
      </AuthGate>,
    );

    await waitFor(() => {
      expect(screen.getByRole('link', { name: 'Operquay home' })).toBeInTheDocument();
    });

    expect(screen.getByRole('button', { name: 'Open command palette' })).toBeInTheDocument();
    expect(screen.getByText('0 instances')).toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: /sign in/i })).not.toBeInTheDocument();
  });

  it('renders StatusBar instance and running counts stably when inventory has instances', async () => {
    stubPostLoginFetch(SAMPLE_ACCOUNTS);

    render(
      <AuthGate>
        <App />
      </AuthGate>,
    );

    await waitFor(() => {
      expect(screen.getByRole('link', { name: 'Operquay home' })).toBeInTheDocument();
    });

    act(() => {
      useInstancesStore.setState({ accounts: SAMPLE_ACCOUNTS });
    });

    await waitFor(() => {
      expect(screen.getByText('2 instances')).toBeInTheDocument();
    });
    expect(screen.getByText('(1 running)')).toBeInTheDocument();
  });
});
