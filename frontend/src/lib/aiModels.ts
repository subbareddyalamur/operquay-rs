import { api, APIError, type Result } from '@/lib/api';
import { canSendCredentials } from '@/lib/credentialTransport';
import { useSettingsStore } from '@/stores/settings';
import { useAuthStore } from '@/stores/auth';
import { useSessionsStore } from '@/stores/sessions';

export function fetchAIModels(provider: string, scope?: { bindingId?: string; region?: string; apiKey?: string; baseUrl?: string }): Promise<Result<Array<{ id: string; name: string }>> & { warning?: string }> {
  const st = useSettingsStore.getState();
  const isHTTPProvider = ['anthropic', 'openai', 'gemini'].includes(provider);
  if (useAuthStore.getState().config?.aws_access_mode === 'user' && scope) {
    if (!canSendCredentials('/api/aws/ai/models')) return Promise.resolve({ ok: false, error: new APIError(0, 'HTTPS is required for model discovery.') });
    if (provider === 'bedrock' && !scope.bindingId) return Promise.resolve({ ok: false, error: new APIError(0, 'Connect an AWS account before discovering models.') });
    const body: Record<string, string> = { provider, binding_id: scope.bindingId ?? '', region: scope.region || 'us-east-1' };
    if (scope.apiKey) body.api_key = scope.apiKey;
    if (isHTTPProvider && scope.baseUrl?.trim()) body.base_url = scope.baseUrl.trim();
    return api.post<{ models: Array<{ id: string; name: string }>; incomplete: boolean }>('/api/aws/ai/models', body).then((result) => {
      if (!result.ok) return result;
      return { ok: true as const, data: result.data.models, ...(result.data.incomplete ? { warning: 'Some models could not be listed.' } : {}) };
    });
  }
  if (useAuthStore.getState().config?.aws_access_mode === 'user') {
    const auth = useAuthStore.getState().me;
    const sessions = useSessionsStore.getState();
    const selected = sessions.sessions.find(session => session.id === sessions.activeId);
    if (!auth || !selected?.userSSH || selected.status !== 'connected') return Promise.resolve({ ok:false, error:new APIError(0, 'Select an active scoped SSH terminal before discovering models.') });
    if (!canSendCredentials('/api/aws/ai/models')) return Promise.resolve({ ok:false, error:new APIError(0, 'HTTPS is required for model discovery.') });
    const body: Record<string, string> = { provider, binding_id:selected.userSSH.roleID, region:provider === 'bedrock' ? (st.bedrockRegion || selected.userSSH.region) : selected.userSSH.region };
    if (isHTTPProvider && st.aiApiKey) body.api_key = st.aiApiKey;
    if (isHTTPProvider && st.aiBaseUrl?.trim()) body.base_url = st.aiBaseUrl.trim();
    return api.post<{ models:Array<{id:string;name:string}>; incomplete:boolean }>('/api/aws/ai/models', body).then(result => {
      const current = useSessionsStore.getState();
      const active = current.sessions.find(session => session.id === current.activeId);
      const actor = useAuthStore.getState().me;
      if (current.activeId !== selected.id || active?.userSSH?.roleID !== selected.userSSH?.roleID || active?.status !== 'connected' || actor?.user_id !== auth.user_id || actor.tenant_id !== auth.tenant_id || actor.expires_at !== auth.expires_at) return { ok:false, error:new APIError(0, 'AWS session changed during model discovery.') };
      if (!result.ok) return result;
      return { ok:true, data:result.data.models, ...(result.data.incomplete ? { warning:'Some models could not be listed with this AWS role.' } : {}) };
    });
  }
  const data: Record<string, string> = { provider };
  if (provider === 'bedrock') {
    data.region = st.bedrockRegion;
    data.auth_mode = st.bedrockAuthMode;
    if (st.bedrockAuthMode === 'api_key') {
      if (st.bedrockAccessKeyId) data.access_key_id = st.bedrockAccessKeyId;
      if (st.bedrockSecretKey) data.secret_key = st.bedrockSecretKey;
      if (st.bedrockSessionToken) data.session_token = st.bedrockSessionToken;
    } else {
      data.profile = st.bedrockProfile;
    }
  }
  if (st.aiApiKey && isHTTPProvider) data.api_key = st.aiApiKey;
  if (st.aiBaseUrl?.trim() && isHTTPProvider) data.base_url = st.aiBaseUrl.trim();
  if (data.api_key || data.access_key_id || data.secret_key || data.session_token) {
    if (!canSendCredentials('/ai-agent/models')) return Promise.resolve({ ok: false, error: new APIError(0, 'HTTPS is required for model lookup with credentials.') });
    return api.post('/ai-agent/models', data);
  }
  return api.get(`/ai-agent/models?${new URLSearchParams(data).toString()}`);
}
