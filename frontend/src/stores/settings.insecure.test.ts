// @vitest-environment-options {"url":"http://localhost/"}
import { expect, it, vi } from 'vitest';

it('does not send or fetch stored preferences over HTTP', async () => {
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  const { useSettingsStore } = await import('./settings');
  await useSettingsStore.getState().loadFromServer();
  expect(await useSettingsStore.getState().saveToServer()).toBe(false);
  expect(fetch).not.toHaveBeenCalled();
  vi.unstubAllGlobals();
});
