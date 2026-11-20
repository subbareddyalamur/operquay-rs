import { beforeEach, describe, expect, it, vi } from 'vitest';

const { apiGet, apiPost } = vi.hoisted(() => ({ apiGet: vi.fn(), apiPost: vi.fn() }));
vi.mock('@/lib/api', () => ({ apiGet, apiPost }));
vi.mock('zustand/middleware', async (importOriginal) => ({ ...(await importOriginal() as Record<string, unknown>), persist: (fn: unknown) => fn, createJSONStorage: () => undefined }));

import { useInstancesStore } from './instances';
import { useAuthStore } from './auth';
import { userScopedInstance } from '@/lib/userScope';
import { getAllInstances } from '@/lib/filter';
import { getVisibleEntries, CTX_ITEMS, isSeparator } from '@/components/sidebar/contextMenuItems';
import type { EC2Instance } from '@/lib/types';

const inst = (id: string, region: string, name: string, account = '222222222222'): EC2Instance => ({ instance_id: id, name, state: 'running', platform: 'linux', os: '', instance_type: 't3.micro', aws_profile: 'user:unwired', aws_region: region, account_id: account, account_alias: '', tag1_value: '', tag2_value: '', private_ip: '10.0.0.1' });
const scanResult = (instances: EC2Instance[], failed: string[] = []) => ({ ok: true, value: { instances, failed_regions: failed, credential_revision: 'rev' } });
const ids = () => getAllInstances(useInstancesStore.getState().accounts).map((i) => i.instance_id).sort();

describe('user-mode inventory', () => {
  beforeEach(() => {
    apiGet.mockReset(); apiPost.mockReset();
    useAuthStore.setState({ config: { aws_access_mode: 'user' } as never });
    useInstancesStore.getState().clearUserRoles();
    useInstancesStore.setState({ expanded: {} });
  });

  it('fetches a connected role into the normal account tree without the shared-profile routes', async () => {
    apiPost.mockResolvedValue(scanResult([inst('i-b', 'us-east-1', 'web'), inst('i-a', 'ap-south-1', 'app')], ['eu-west-1']));
    await useInstancesStore.getState().addUserRole({ id: 'role-1', name: 'Development', label: 'Development · Admin', accountID: '222222222222', credentialRevision: 'rev' });
    expect(apiPost).toHaveBeenCalledWith('/api/aws/role-fetch', { binding_id: 'role-1', display_name: 'Development' });
    expect(apiGet).not.toHaveBeenCalled();
    const account = useInstancesStore.getState().accounts[0]!;
    expect(account).toMatchObject({ account_id: '222222222222', account_alias: 'Development' });
    expect(account.regions.map((r) => r.region)).toEqual(['ap-south-1', 'us-east-1']);
    expect(useInstancesStore.getState().expanded['account:222222222222']).toBe(true);
    expect(useInstancesStore.getState().userRoles[0]?.failedRegions).toEqual(['eu-west-1']);
    expect(userScopedInstance('i-a')).toMatchObject({ roleID: 'role-1', instance: { aws_region: 'ap-south-1' } });
  });

  it('keeps every connected account listed while another one fetches or fails', async () => {
    apiPost.mockResolvedValueOnce(scanResult([inst('i-dev', 'us-east-1', 'dev')]));
    await useInstancesStore.getState().addUserRole({ id: 'dev', name: 'Development', label: 'Development · Admin', accountID: '222222222222', credentialRevision: 'rev' });
    let finishProd: (v: unknown) => void = () => undefined;
    apiPost.mockReturnValueOnce(new Promise((resolve) => { finishProd = resolve; }));
    const prod = useInstancesStore.getState().addUserRole({ id: 'prod', name: 'Production', label: 'Production · ReadOnly', accountID: '333333333333', credentialRevision: 'rev' });
    expect(useInstancesStore.getState().userFetching).toEqual(['prod']);
    expect(ids()).toEqual(['i-dev']);
    finishProd(scanResult([inst('i-prod', 'us-east-1', 'prod', '333333333333')]));
    await prod;
    expect(ids()).toEqual(['i-dev', 'i-prod']);
    expect(userScopedInstance('i-prod')?.roleID).toBe('prod');

    apiPost.mockResolvedValueOnce({ ok: false, error: { status: 403 } }).mockResolvedValueOnce(scanResult([inst('i-prod', 'us-east-1', 'prod', '333333333333')]));
    await useInstancesStore.getState().triggerDiscovery();
    expect(apiPost).toHaveBeenCalledTimes(4);
    expect(ids()).toEqual(['i-prod']);
    expect(useInstancesStore.getState().userRoles.find(r => r.id === 'dev')?.live).toBe(false);
  });

  it('retains a valid role on a temporary discovery error', async () => {
    apiPost.mockResolvedValueOnce(scanResult([inst('i-dev', 'us-east-1', 'dev')]));
    await useInstancesStore.getState().addUserRole({ id: 'dev', name: 'Dev', label: 'Dev', credentialRevision: 'rev' });
    apiPost.mockResolvedValueOnce({ ok: false, error: { status: 502 } });
    await useInstancesStore.getState().fetchUserRole('dev');
    expect(ids()).toEqual(['i-dev']);
    expect(useInstancesStore.getState().userRoles[0]?.live).toBe(true);
  });

  it('switching role on the same account replaces it, and removing one keeps the others', async () => {
    apiPost.mockResolvedValueOnce(scanResult([inst('i-dev', 'us-east-1', 'dev')]));
    await useInstancesStore.getState().addUserRole({ id: 'dev-ro', name: 'Development', label: 'Development · ReadOnly', accountID: '222222222222', credentialRevision: 'rev' });
    apiPost.mockResolvedValueOnce(scanResult([inst('i-dev', 'us-east-1', 'dev')]));
    await useInstancesStore.getState().addUserRole({ id: 'dev-admin', name: 'Development', label: 'Development · Admin', accountID: '222222222222', credentialRevision: 'rev' });
    expect(useInstancesStore.getState().userRoles.map((r) => r.id)).toEqual(['dev-admin']);
    apiPost.mockResolvedValueOnce(scanResult([inst('i-prod', 'us-east-1', 'prod', '333333333333')]));
    await useInstancesStore.getState().addUserRole({ id: 'prod', name: 'Production', label: 'Production · ReadOnly', accountID: '333333333333', credentialRevision: 'rev' });
    useInstancesStore.getState().removeUserRole('dev-admin');
    expect(ids()).toEqual(['i-prod']);
    useInstancesStore.getState().clearUserRoles();
    expect(useInstancesStore.getState().accounts).toEqual([]);
  });

  it('does nothing before a role is connected', async () => {
    apiGet.mockResolvedValue({ ok: true, value: { roles: [] } });
    await useInstancesStore.getState().fetchInstances();
    await useInstancesStore.getState().triggerDiscovery();
    expect(apiGet).toHaveBeenCalledWith('/api/aws/saved-inventory');
    expect(apiPost).not.toHaveBeenCalled();
    expect(userScopedInstance('i-a')).toBeNull();
  });

  it('never restores a disconnected saved inventory snapshot', async () => {
    apiGet.mockImplementation(async (path: string) => path === '/api/aws/saved-inventory'
      ? { ok: true, value: { roles: [{ account_id: '222222222222', role_key: 'Admin', source: 'sso', name: 'Development', label: 'Development · Admin', instances: [inst('i-saved', 'ap-south-1', 'saved')] }] } }
      : { ok: true, value: path === '/api/aws/connected-roles' ? [] : {} });
    await useInstancesStore.getState().fetchInstances();
    expect(apiPost).not.toHaveBeenCalled();
    expect(ids()).toEqual([]);
    expect(useInstancesStore.getState().userInventory).toEqual({});
  });

  it('keeps a still-valid AWS role connected after reload and does not fetch again', async () => {
    apiGet.mockImplementation(async (path: string) => {
      if (path === '/api/aws/saved-inventory') return { ok: true, value: { roles: [{ account_id: '222222222222', role_key: 'Admin', source: 'sso', name: 'Development', label: 'Admin', live_id: 'role-live', credential_revision: 'rev', instances: [inst('i-saved', 'ap-south-1', 'saved')] }] } };
      if (path === '/api/aws/connected-roles') return { ok: true, value: [{ id: 'role-live', account_id: '222222222222', role_name: 'Admin', credential_revision: 'rev' }] };
      return { ok: true, value: {} };
    });
    await useInstancesStore.getState().fetchInstances();
    expect(apiPost).not.toHaveBeenCalled();
    expect(useInstancesStore.getState().userRoles[0]).toMatchObject({ id: 'role-live', live: true });
    expect(ids()).toEqual(['i-saved']);
  });

  it('refetches when a snapshot belongs to another credential revision', async () => {
    apiGet.mockImplementation(async (path: string) => path === '/api/aws/saved-inventory'
      ? { ok: true, value: { roles: [{ account_id: '222222222222', role_key: 'Admin', source: 'sso', name: 'Development', label: 'Admin', live_id: 'role-live', credential_revision: 'old', instances: [inst('i-old', 'us-east-1', 'old')] }] } }
      : { ok: true, value: [{ id: 'role-live', account_id: '222222222222', role_name: 'Admin', credential_revision: 'rev' }] });
    apiPost.mockResolvedValueOnce(scanResult([inst('i-new', 'us-east-1', 'new')]));
    await useInstancesStore.getState().fetchInstances();
    expect(ids()).toEqual(['i-new']);
    expect(apiPost).toHaveBeenCalledWith('/api/aws/role-fetch', expect.objectContaining({ binding_id: 'role-live' }));
  });

  it('clears only the expired role and ignores an older in-flight fetch', async () => {
    apiPost.mockResolvedValueOnce(scanResult([inst('i-dev', 'us-east-1', 'dev')]));
    await useInstancesStore.getState().addUserRole({ id: 'dev', name: 'Dev', label: 'Dev', accountID: '222222222222', credentialRevision: 'rev' });
    apiPost.mockResolvedValueOnce(scanResult([inst('i-prod', 'us-east-1', 'prod', '333333333333')]));
    await useInstancesStore.getState().addUserRole({ id: 'prod', name: 'Prod', label: 'Prod', accountID: '333333333333', credentialRevision: 'rev' });
    let finish: (v: unknown) => void = () => undefined;
    apiPost.mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
    const fetchJob = useInstancesStore.getState().fetchUserRole('dev');
    apiGet.mockResolvedValue({ ok: true, value: [{ id: 'prod', account_id: '333333333333', label: 'Prod', credential_revision: 'rev' }] });
    await useInstancesStore.getState().refreshUserRoles();
    expect(ids()).toEqual(['i-prod']);
    finish(scanResult([inst('i-late', 'us-east-1', 'late')]));
    await fetchJob;
    expect(ids()).toEqual(['i-prod']);
  });

  it('does not restore an old request after the user clears inventory', async () => {
    let finish: (v: unknown) => void = () => undefined;
    apiGet.mockImplementation((path: string) => path === '/api/aws/saved-inventory'
      ? new Promise(resolve => { finish = resolve; })
      : Promise.resolve({ ok: true, value: [{ id: 'role-live', account_id: '222222222222', role_name: 'Admin' }] }));
    const pending = useInstancesStore.getState().fetchInstances();
    useInstancesStore.getState().clearUserRoles();
    finish({ ok: true, value: { roles: [{ account_id: '222222222222', role_key: 'Admin', source: 'sso', name: 'Dev', label: 'Admin', live_id: 'role-live', instances: [inst('i-old', 'us-east-1', 'old')] }] } });
    await pending;
    expect(ids()).toEqual([]);
  });

  it('discards a stale scan when the same role is reconnected', async () => {
    let finish: (v: unknown) => void = () => undefined;
    apiPost.mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
    const old = useInstancesStore.getState().addUserRole({ id: 'same', name: 'Old', label: 'Old', credentialRevision: 'rev' });
    apiPost.mockResolvedValueOnce(scanResult([inst('i-new', 'us-east-1', 'new')]));
    await useInstancesStore.getState().addUserRole({ id: 'same', name: 'New', label: 'New', credentialRevision: 'rev' });
    finish(scanResult([inst('i-old', 'us-east-1', 'old')]));
    await old;
    expect(ids()).toEqual(['i-new']);
  });

  it('fails closed when the status request fails', async () => {
    apiPost.mockResolvedValueOnce(scanResult([inst('i-dev', 'us-east-1', 'dev')]));
    await useInstancesStore.getState().addUserRole({ id: 'dev', name: 'Dev', label: 'Dev', credentialRevision: 'rev' });
    apiGet.mockResolvedValueOnce({ ok: false, error: { status: 503 } });
    await useInstancesStore.getState().refreshUserRoles();
    expect(ids()).toEqual([]);
  });

  it('fails closed on a stalled status request', async () => {
    apiPost.mockResolvedValueOnce(scanResult([inst('i-dev', 'us-east-1', 'dev')]));
    await useInstancesStore.getState().addUserRole({ id: 'dev', name: 'Dev', label: 'Dev', credentialRevision: 'rev' });
    vi.useFakeTimers();
    try {
      apiGet.mockReturnValueOnce(new Promise(() => undefined));
      const refresh = useInstancesStore.getState().refreshUserRoles();
      await vi.advanceTimersByTimeAsync(3000);
      await refresh;
      expect(ids()).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });

  it('does not let an old status response remove a reconnected role', async () => {
    apiPost.mockResolvedValueOnce(scanResult([inst('i-old', 'us-east-1', 'old')]));
    await useInstancesStore.getState().addUserRole({ id: 'dev', name: 'Dev', label: 'Dev', credentialRevision: 'rev' });
    let finish: (v: unknown) => void = () => undefined;
    apiGet.mockReturnValueOnce(new Promise(resolve => { finish = resolve; }));
    const refresh = useInstancesStore.getState().refreshUserRoles();
    apiPost.mockResolvedValueOnce(scanResult([inst('i-new', 'us-east-1', 'new')]));
    await useInstancesStore.getState().addUserRole({ id: 'dev', name: 'Dev', label: 'Dev', credentialRevision: 'rev' });
    finish({ ok: true, value: [] });
    await refresh;
    expect(ids()).toEqual(['i-new']);
  });

  it('hides inventory when another replica replaces credentials under the same role id', async () => {
    apiPost.mockResolvedValueOnce({ ...scanResult([inst('i-old', 'us-east-1', 'old')]), value: { ...scanResult([]).value, instances: [inst('i-old', 'us-east-1', 'old')], credential_revision: 'old-revision' } });
    await useInstancesStore.getState().addUserRole({ id: 'dev', name: 'Dev', label: 'Dev', credentialRevision: 'old-revision' });
    apiGet.mockResolvedValueOnce({ ok: true, value: [{ id: 'dev', account_id: '222222222222', label: 'Dev', credential_revision: 'new-revision' }] });
    await useInstancesStore.getState().refreshUserRoles();
    expect(ids()).toEqual([]);
  });

  it('rejects a scan response signed by a different credential revision', async () => {
    apiPost.mockResolvedValueOnce(scanResult([inst('i-wrong', 'us-east-1', 'wrong')]));
    await useInstancesStore.getState().addUserRole({ id: 'dev', name: 'Dev', label: 'Dev', credentialRevision: 'old-revision' });
    expect(ids()).toEqual([]);
    expect(useInstancesStore.getState().userRoles[0]?.live).toBe(false);
  });

  it('clears inventory when the signed-in identity changes', async () => {
    useAuthStore.setState({ me: { user_id: 'alice', tenant_id: 'tenant' } as never });
    apiPost.mockResolvedValueOnce(scanResult([inst('i-dev', 'us-east-1', 'dev')]));
    await useInstancesStore.getState().addUserRole({ id: 'dev', name: 'Dev', label: 'Dev', credentialRevision: 'rev' });
    useAuthStore.setState({ me: { user_id: 'bob', tenant_id: 'tenant' } as never });
    expect(ids()).toEqual([]);
    expect(useInstancesStore.getState().userRoles).toEqual([]);
  });

  it('hides context actions that user mode does not support', () => {
    const shown = getVisibleEntries(CTX_ITEMS, inst('i-a', 'us-east-1', 'app'), {}).filter((e) => !isSeparator(e)).map((e) => (e as { id: string }).id);
    expect(shown).toEqual(expect.arrayContaining(['ssh', 'details', 'port-forward', 'topology', 'clone', 'upload', 'download']));
    expect(shown).not.toContain('browse');
    expect(shown.some((id) => id.startsWith('exp'))).toBe(false);
  });
});
