// @vitest-environment-options {"url":"https://desk.example/"}
import { expect, it, vi } from 'vitest';
import { useToastStore } from './toast';

vi.mock('zustand/middleware', async (importOriginal) => ({
  ...(await importOriginal() as Record<string, unknown>),
  persist: (fn: unknown) => fn,
  createJSONStorage: () => undefined,
}));

it('reports successful, rejected and failed server saves', async () => {
  const fetch = vi.fn().mockResolvedValue({ ok: false });
  vi.stubGlobal('fetch', fetch);
  const { useSettingsStore } = await import('./settings');
  fetch.mockClear();
  fetch.mockResolvedValueOnce({ ok: true });
  expect(await useSettingsStore.getState().saveToServer()).toBe(true);
  expect(fetch).toHaveBeenCalledWith('/preferences', expect.objectContaining({ method: 'PATCH', body:expect.not.stringContaining('"snippets"') }));
  fetch.mockResolvedValueOnce({ ok: false, status: 500 });
  expect(await useSettingsStore.getState().saveToServer()).toBe(false);
  fetch.mockRejectedValueOnce(new Error('offline'));
  expect(await useSettingsStore.getState().saveToServer()).toBe(false);
  vi.unstubAllGlobals();
});

it('reports a failed automatic save', async () => {
  vi.useFakeTimers();
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false }));
  useToastStore.getState().clear();
  const { useSettingsStore } = await import('./settings');
  useSettingsStore.getState().setFontSize(15);
  await vi.advanceTimersByTimeAsync(2000);
  expect(useToastStore.getState().toasts).toEqual(expect.arrayContaining([
    expect.objectContaining({ variant: 'danger', title: 'Could not save settings' }),
  ]));
  useToastStore.getState().clear();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

it('persists and loads terminalEngine preference', async () => {
  const fetch = vi.fn()
    .mockResolvedValueOnce({ ok: true, json: async () => ({ terminalEngine: 'wterm' }) })
    .mockResolvedValueOnce({ ok: true });
  vi.stubGlobal('fetch', fetch);

  const { useSettingsStore } = await import('./settings');
  await useSettingsStore.getState().loadFromServer();
  expect(useSettingsStore.getState().terminalEngine).toBe('wterm');

  useSettingsStore.getState().setTerminalEngine('xterm');
  expect(await useSettingsStore.getState().saveToServer()).toBe(true);
  expect(fetch).toHaveBeenLastCalledWith('/preferences', expect.objectContaining({
    method: 'PATCH',
    body: expect.stringContaining('"terminalEngine":"xterm"'),
  }));
  vi.unstubAllGlobals();
});
