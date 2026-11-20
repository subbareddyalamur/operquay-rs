// @vitest-environment-options {"url":"http://localhost/"}
import { expect, it, vi } from 'vitest';

const mock = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), settings: { aiApiKey: 'test-secret', aiBaseUrl: '', bedrockAccessKeyId: '', bedrockSecretKey: '', bedrockSessionToken: '', bedrockRegion: 'us-east-1', bedrockAuthMode: 'profile', bedrockProfile: 'default' } }));
vi.mock('@/lib/api', () => ({ api: { get: mock.get, post: mock.post }, APIError: class extends Error { status = 0; } }));
vi.mock('@/stores/settings', () => ({ useSettingsStore: { getState: () => mock.settings } }));
import { fetchAIModels } from './aiModels';

it('does not send model lookup credentials over HTTP', async () => {
  const result = await fetchAIModels('openai');
  expect(result.ok).toBe(false);
  expect(mock.get).not.toHaveBeenCalled();
  expect(mock.post).not.toHaveBeenCalled();
});
