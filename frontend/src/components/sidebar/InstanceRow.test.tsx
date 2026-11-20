import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import { InstanceRow } from './InstanceRow';
import { useAuthStore } from '@/stores/auth';
import type { EC2Instance } from '@/lib/types';

vi.mock('zustand/middleware', async (importOriginal) => {
  const mod = await importOriginal() as Record<string, unknown>;
  return { ...mod, persist: (fn: unknown) => fn, createJSONStorage: () => undefined };
});

const instance: EC2Instance = { instance_id: 'i-123', name: 'server', state: 'running', platform: 'linux', os: 'ubuntu', instance_type: 't3.small', aws_profile: 'dev', aws_region: 'us-east-1', account_id: '1', account_alias: 'dev', tag1_value: '', tag2_value: '', private_ip: '10.0.0.1' };
afterEach(() => { cleanup(); useAuthStore.setState({ me: null }); });

it('opens details, not SSH, for a read-only user', () => {
  useAuthStore.setState({ me: { user_id: 'u', email: 'u@example.com', role: 'readonly', tenant_id: 'local', method: 'password', expires_at: 1 } });
  const details = vi.fn();
  const ssh = vi.fn();
  window.addEventListener('ct:show-details', details);
  window.addEventListener('ct:open-ssh', ssh);
  render(<InstanceRow instance={instance} />);
  expect(useAuthStore.getState().me?.role).toBe('readonly');
  fireEvent.click(screen.getByRole('option'));
  expect(details).toHaveBeenCalledOnce();
  expect(ssh).not.toHaveBeenCalled();
  window.removeEventListener('ct:show-details', details);
  window.removeEventListener('ct:open-ssh', ssh);
});

it('displays full instance name and instance id on hover', async () => {
  const longInstance: EC2Instance = {
    ...instance,
    instance_id: 'i-0987654321abcdef0',
    name: 'prod-sycamore-analytics-worker-very-long-hostname-01',
    private_ip: '10.24.8.15',
  };
  render(<InstanceRow instance={longInstance} />);

  const option = screen.getByRole('option');
  expect(screen.queryByRole('tooltip')).not.toBeInTheDocument();

  fireEvent.pointerEnter(option);
  fireEvent.mouseEnter(option);

  await waitFor(
    () => {
      const tooltip = screen.getByRole('tooltip');
      expect(tooltip).toHaveTextContent('prod-sycamore-analytics-worker-very-long-hostname-01');
      expect(tooltip).toHaveTextContent('i-0987654321abcdef0');
    },
    { timeout: 1500 },
  );
});
