// @vitest-environment-options {"url":"https://desk.example/"}
import { afterEach, expect, it, vi } from 'vitest';

afterEach(() => { vi.unstubAllGlobals(); vi.resetModules(); });

it('does not rehydrate old cached instance data, but keeps preferences', async () => {
  const values = new Map<string, string>();
  vi.stubGlobal('localStorage', { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => values.set(key, value), removeItem: (key: string) => values.delete(key) });
  localStorage.setItem('ct-instances', JSON.stringify({ state: { favorites: ['i-fav'], expanded: { account: true }, accounts: [{ account_id: 'leaked' }], userInventory: { old: [{ instance_id: 'i-old' }] }, userRoles: [{ id: 'old' }] }, version: 0 }));
  const { useInstancesStore } = await import('./instances');
  await useInstancesStore.persist.rehydrate();
  expect(useInstancesStore.getState().accounts).toEqual([]);
  expect(useInstancesStore.getState().userInventory).toEqual({});
  expect(useInstancesStore.getState().userRoles).toEqual([]);
  expect(useInstancesStore.getState().favorites).toEqual(['i-fav']);
  expect(useInstancesStore.getState().expanded).toEqual({ account: true });
});
