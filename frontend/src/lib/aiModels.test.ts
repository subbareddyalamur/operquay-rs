// @vitest-environment-options {"url":"https://desk.example/"}
import { beforeEach, expect, it, vi } from 'vitest';

const mock = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), mode: 'profiles', sessions:{ activeId:'a', sessions:[{ id:'a', type:'ssh', status:'connected', userSSH:{ roleID:'role-a', region:'us-east-1' } }] }, actor:{ user_id:'user', tenant_id:'tenant', expires_at:12345 }, settings: { aiApiKey: 'test-api-key', aiBaseUrl: '', bedrockAccessKeyId: 'test-access-id', bedrockSecretKey: 'test-secret-key', bedrockSessionToken: 'test-token', bedrockRegion: 'us-east-1', bedrockAuthMode: 'api_key', bedrockProfile: 'default' } }));
vi.mock('@/lib/api', () => ({ api: { get: mock.get, post: mock.post }, APIError: class extends Error { status = 0; } }));
vi.mock('@/stores/settings', () => ({ useSettingsStore: { getState: () => mock.settings } }));
vi.mock('@/stores/auth', () => ({ useAuthStore: { getState: () => ({ config:{aws_access_mode:mock.mode}, me:mock.actor }) } }));
vi.mock('@/stores/sessions', () => ({ useSessionsStore: { getState: () => mock.sessions } }));
import { fetchAIModels } from './aiModels';

beforeEach(() => { mock.get.mockReset(); mock.post.mockReset(); mock.mode = 'profiles'; mock.sessions.activeId = 'a'; });

it('sends API credentials in a POST body rather than a URL', () => {
  fetchAIModels('openai');
  expect(mock.get).not.toHaveBeenCalled();
  expect(mock.post).toHaveBeenCalledWith('/ai-agent/models', { provider: 'openai', api_key: 'test-api-key' });
});

it('uses the selected role for scoped Bedrock discovery without sending shared credentials', async () => {
  mock.mode = 'user';
  mock.post.mockResolvedValue({ ok:true, data:{ models:[{ id:'model', name:'Model' }], incomplete:true } });
  const result = await fetchAIModels('bedrock');
  expect(mock.post).toHaveBeenCalledWith('/api/aws/ai/models', { provider:'bedrock', binding_id:'role-a', region:'us-east-1' });
  expect(result).toMatchObject({ ok:true, data:[{ id:'model' }], warning:expect.any(String) });
});

it('discards scoped discovery results after switching terminals', async () => {
  mock.mode = 'user';
  let finish!: (value:unknown) => void;
  mock.post.mockReturnValue(new Promise(resolve => { finish = resolve; }));
  const pending = fetchAIModels('bedrock');
  mock.sessions.activeId = 'other';
  finish({ ok:true, data:{ models:[{ id:'private', name:'Private' }], incomplete:false } });
  expect((await pending).ok).toBe(false);
});

it('sends all Bedrock credentials in a POST body', () => {
  fetchAIModels('bedrock');
  expect(mock.get).not.toHaveBeenCalled();
  expect(mock.post).toHaveBeenCalledWith('/ai-agent/models', { provider: 'bedrock', region: 'us-east-1', auth_mode: 'api_key', access_key_id: 'test-access-id', secret_key: 'test-secret-key', session_token: 'test-token' });
});

it('keeps non-secret profile lookups as GET requests', () => {
  mock.settings.bedrockAuthMode = 'profile';
  fetchAIModels('bedrock');
  expect(mock.post).not.toHaveBeenCalled();
  expect(mock.get).toHaveBeenCalledWith('/ai-agent/models?provider=bedrock&region=us-east-1&auth_mode=profile&profile=default');
  mock.settings.bedrockAuthMode = 'api_key';
});

it('sends a custom base_url when configured for generic providers', () => {
  mock.settings.aiBaseUrl = 'https://llm.example.test/v1';
  fetchAIModels('openai');
  expect(mock.get).not.toHaveBeenCalled();
  expect(mock.post).toHaveBeenCalledWith('/ai-agent/models', { provider: 'openai', api_key: 'test-api-key', base_url: 'https://llm.example.test/v1' });
  mock.settings.aiBaseUrl = '';
});

it('sends a custom base_url for scoped provider discovery when configured', async () => {
  mock.mode = 'user';
  mock.settings.aiBaseUrl = 'https://llm.example.test/v1';
  mock.post.mockResolvedValue({ ok:true, data:{ models:[], incomplete:false } });
  await fetchAIModels('anthropic');
  expect(mock.post).toHaveBeenCalledWith('/api/aws/ai/models', { provider:'anthropic', binding_id:'role-a', region:'us-east-1', api_key:'test-api-key', base_url:'https://llm.example.test/v1' });
  mock.settings.aiBaseUrl = '';
});
