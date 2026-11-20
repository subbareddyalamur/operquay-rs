import { useCallback, useEffect, useRef, useState } from 'react';
import { RefreshCw, Search, Sparkles } from 'lucide-react';
import { Badge, Button, Input, Select } from '@/components/primitives';
import { api } from '@/lib/api';
import { fetchAIModels } from '@/lib/aiModels';
import { useInstancesStore } from '@/stores/instances';

const PROVIDERS = [
  { id: 'bedrock', label: 'AWS Bedrock' },
  { id: 'anthropic', label: 'Anthropic (or compatible)' },
  { id: 'openai', label: 'OpenAI (or compatible)' },
  { id: 'gemini', label: 'Google Gemini (or compatible)' },
];

type Model = { id: string; name: string };

type Catalog = {
  configured?: boolean;
  provider?: string;
  region?: string;
  account_id?: string;
  account_label?: string;
  binding_id?: string;
  base_url?: string;
  models?: Model[];
  key_configured?: boolean;
};

function formatCatalogError(raw: string | undefined, fallback: string): string {
  const message = (raw ?? '').trim();
  if (!message) return fallback;
  try {
    const parsed = JSON.parse(message) as { error?: unknown; message?: unknown };
    if (typeof parsed.error === 'string' && parsed.error.trim()) return parsed.error.trim();
    if (typeof parsed.message === 'string' && parsed.message.trim()) return parsed.message.trim();
  } catch {
    /* already plain text */
  }
  return message;
}

export function SharedAISettings() {
  const roles = useInstancesStore((s) => s.userRoles);
  const [provider, setProvider] = useState('bedrock');
  const [region, setRegion] = useState('us-east-1');
  const [bindingId, setBindingId] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [keyConfigured, setKeyConfigured] = useState(false);
  const [savedLabel, setSavedLabel] = useState('');
  const [savedAccount, setSavedAccount] = useState('');
  const [discovered, setDiscovered] = useState<Model[]>([]);
  const [modelQuery, setModelQuery] = useState('');
  const [selected, setSelected] = useState<Record<string, string>>({});
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const request = useRef(0);
  const savedCatalogRef = useRef<Catalog | null>(null);

  useEffect(() => {
    let cancel = false;
    void api.get<Catalog>('/api/ai/catalog').then((result) => {
      if (cancel || !result.ok) return;
      const data = result.data;
      if (!data.configured && !data.key_configured && !data.provider) return;
      savedCatalogRef.current = data;
      setProvider(data.provider || 'bedrock');
      if (data.region) setRegion(data.region);
      if (data.binding_id) setBindingId(data.binding_id);
      setBaseUrl(data.base_url || '');
      setSavedLabel(data.account_label || data.account_id || '');
      setSavedAccount(data.account_id || '');
      setKeyConfigured(Boolean(data.key_configured));
      const next: Record<string, string> = {};
      for (const model of data.models ?? []) next[model.id] = model.name || model.id;
      setSelected(next);
      setDiscovered(data.models ?? []);
    });
    return () => { cancel = true; };
  }, []);

  const liveRoles = roles.filter((role) => role.live !== false && role.accountID);
  const chosen = liveRoles.find((role) => role.id === bindingId);
  const modelSearch = modelQuery.trim().toLowerCase();
  const selectedModels = Object.entries(selected)
    .map(([id, name]) => {
      const known = discovered.find((model) => model.id === id);
      return { id, name: known?.name || name || id };
    })
    .sort((a, b) => a.name.localeCompare(b.name));
  const availableModels = (modelSearch
    ? discovered.filter((model) => `${model.name} ${model.id}`.toLowerCase().includes(modelSearch))
    : discovered
  ).filter((model) => !selected[model.id]);

  const discover = useCallback(async () => {
    const current = ++request.current;
    setBusy(true);
    setError('');
    setNotice('');
    const result = provider === 'bedrock'
      ? await fetchAIModels(provider, { bindingId, region })
      : await fetchAIModels(provider, { apiKey: apiKey.trim(), baseUrl });
    if (current !== request.current) return;
    setBusy(false);
    if (!result.ok || !Array.isArray(result.data)) {
      setError(result.ok ? 'No models were returned.' : formatCatalogError(result.error.message, 'Model discovery unavailable.'));
      return;
    }
    setDiscovered(result.data);
    if (result.data.length === 1) {
      const single = result.data[0]!;
      setSelected((curr) => Object.keys(curr).length === 0 ? { [single.id]: single.name || single.id } : curr);
    }
    if (result.warning) setError(result.warning);
  }, [provider, bindingId, region, apiKey, baseUrl]);

  const save = useCallback(async () => {
    const accountID = chosen?.accountID || savedAccount;
    if (provider === 'bedrock' && (!bindingId || !accountID || !region.trim())) {
      setError('Select a connected AWS account and region.');
      return;
    }
    const trimmedKey = apiKey.trim();
    let models = Object.entries(selected).map(([id, name]) => ({ id, name }));
    if (models.length === 0 && (provider === 'bedrock' || (!trimmedKey && !keyConfigured))) {
      setError('Select at least one model.');
      return;
    }
    setBusy(true);
    setError('');
    setNotice('');
    if (models.length === 0 && provider !== 'bedrock' && (trimmedKey !== '' || keyConfigured)) {
      if (discovered.length === 0) {
        const disc = await fetchAIModels(provider, { apiKey: trimmedKey, baseUrl });
        if (disc.ok && Array.isArray(disc.data)) {
          setDiscovered(disc.data);
          if (disc.data.length === 1) {
            const single = disc.data[0]!;
            const picked = { id: single.id, name: single.name || single.id };
            setSelected({ [picked.id]: picked.name });
            models = [picked];
          }
        }
      }
      if (models.length === 0 && trimmedKey === '') {
        setBusy(false);
        setError('Select at least one model.');
        return;
      }
    }
    const body: Record<string, unknown> = {
      provider,
      region: provider === 'bedrock' ? region : '',
      account_id: provider === 'bedrock' ? accountID : '',
      account_label: provider === 'bedrock' ? (chosen?.name || savedLabel) : '',
      binding_id: provider === 'bedrock' ? bindingId : '',
      base_url: provider === 'bedrock' ? '' : baseUrl.trim(),
      models,
    };
    if (trimmedKey) body.api_key = trimmedKey;
    const result = await api.put<Catalog>('/api/ai/catalog', body);
    setBusy(false);
    if (!result.ok) {
      setError(formatCatalogError(result.error.message, 'Could not save the assistant.'));
      return;
    }
    savedCatalogRef.current = result.data;
    setApiKey('');
    setKeyConfigured(Boolean(result.data.key_configured));
    if (result.data.models && result.data.models.length > 0) {
      const next: Record<string, string> = {};
      for (const model of result.data.models) next[model.id] = model.name || model.id;
      setSelected(next);
      setDiscovered((prev) => prev.length > 0 ? prev : (result.data.models ?? []));
      setNotice('Saved. Everyone uses these models.');
    } else {
      setNotice('API key saved. Select models below and save to enable for everyone.');
    }
    window.dispatchEvent(new CustomEvent('operquay:ai-catalog-updated'));
  }, [selected, discovered.length, keyConfigured, provider, region, chosen, savedLabel, savedAccount, bindingId, apiKey, baseUrl]);

  const toggle = (model: Model) => {
    setSelected((current) => {
      const next = { ...current };
      if (next[model.id]) delete next[model.id];
      else next[model.id] = model.name || model.id;
      return next;
    });
  };

  return (
    <div className="space-y-5">
      <div className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs">
        <div className="px-5 py-4 border-b border-border flex items-start gap-3">
          <span className="mt-0.5 w-8 h-8 rounded-md bg-[var(--accent-dim)] text-accent border border-accent/20 flex items-center justify-center shrink-0">
            <Sparkles size={15} aria-hidden="true" />
          </span>
          <div>
            <h3 className="text-[14px] font-semibold text-text-pri">Provider</h3>
            <p className="text-[13px] text-text-mut mt-0.5">
              These settings apply to every user. Users can switch among the models you select.
            </p>
          </div>
        </div>

        <div className="px-5 py-4 space-y-5">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
            {PROVIDERS.map((item) => {
              const active = provider === item.id;
              return (
                <label
                  key={item.id}
                  className={`flex items-center gap-2.5 rounded-lg border px-3.5 py-3 cursor-pointer transition-colors ${
                    active
                      ? 'border-accent bg-[var(--accent-dim)] ring-1 ring-accent/25 text-text-pri font-medium'
                      : 'border-border bg-bg/50 hover:bg-surface-hover text-text-mut'
                  }`}
                >
                  <input
                    type="radio"
                    name="ai-provider"
                    className="accent-accent shrink-0"
                    checked={active}
                    onChange={() => {
                      request.current += 1;
                      setBusy(false);
                      setProvider(item.id);
                      const saved = savedCatalogRef.current;
                      if (saved?.provider === item.id) {
                        setBaseUrl(saved.base_url || '');
                        setKeyConfigured(Boolean(saved.key_configured));
                        const next: Record<string, string> = {};
                        for (const model of saved.models ?? []) next[model.id] = model.name || model.id;
                        setSelected(next);
                        setDiscovered(saved.models ?? []);
                        if (saved.region) setRegion(saved.region);
                        if (saved.binding_id) setBindingId(saved.binding_id);
                      } else {
                        setBaseUrl('');
                        setKeyConfigured(false);
                        setDiscovered([]);
                        setSelected({});
                      }
                      setModelQuery('');
                      setError('');
                      setNotice('');
                    }}
                  />
                  <span className="text-[13px] text-text-pri">{item.label}</span>
                </label>
              );
            })}
          </div>

          {provider === 'bedrock' && (
            <div className="rounded-lg border border-border bg-bg/40 p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h4 className="text-[13px] font-semibold text-text-pri">AWS account</h4>
                <span className="text-[12px] text-text-dim">Bedrock calls use this account while someone is signed in to it.</span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                  <span>Connected account</span>
                  <Select
                    aria-label="AWS account"
                    value={bindingId}
                    onChange={(e) => setBindingId(e.target.value)}
                  >
                    <option value="">Select an account</option>
                    {liveRoles.map((role) => (
                      <option key={role.id} value={role.id}>
                        {role.name}{role.label && role.label !== role.name ? ` · ${role.label}` : ''} · {role.accountID}
                      </option>
                    ))}
                  </Select>
                </label>
                <label className="block space-y-1.5 text-[12px] font-medium text-text-mut">
                  <span>Region</span>
                  <Input
                    aria-label="Bedrock region"
                    value={region}
                    onChange={(e) => setRegion(e.target.value)}
                    className="font-mono"
                  />
                </label>
              </div>
              {savedLabel && !chosen && (
                <p className="text-[12px] text-text-mut">Saved account: {savedLabel}. Connect it again to discover models.</p>
              )}
            </div>
          )}

          {(provider === 'anthropic' || provider === 'openai' || provider === 'gemini') && (
            <div className="rounded-lg border border-border bg-bg/40 p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <h3 className="text-[12px] font-medium text-text-mut">
                  Base URL <span className="font-normal text-text-dim">(optional)</span>
                </h3>
                <Input
                  type="url"
                  aria-label="Provider base URL"
                  placeholder={provider === 'anthropic' ? 'https://api.anthropic.com/v1' : provider === 'gemini' ? 'https://generativelanguage.googleapis.com/v1beta' : 'https://api.openai.com/v1'}
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  className="font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <h3 className="text-[12px] font-medium text-text-mut">API key</h3>
                <Input
                  type="password"
                  aria-label="Provider API key"
                  placeholder={keyConfigured ? 'A key is saved. Enter a new key to replace it.' : 'Enter API key'}
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                />
              </div>
            </div>
          )}
        </div>

        <div className="px-5 py-3 bg-bg/60 border-t border-border flex flex-wrap items-center justify-between gap-3">
          <div className="min-h-[1.25rem]">
            {error && <p className="text-[12px] font-medium text-danger" role="alert">{error}</p>}
            {!error && notice && <p className="text-[12px] font-medium text-success">{notice}</p>}
          </div>
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              icon={<RefreshCw size={13} className={busy ? 'animate-spin' : ''} />}
              disabled={busy}
              onClick={() => void discover()}
            >
              {busy ? 'Working…' : 'Discover models'}
            </Button>
            <Button type="button" variant="primary" size="sm" loading={busy} disabled={busy} onClick={() => void save()}>
              Save for everyone
            </Button>
          </div>
        </div>
      </div>

      <section className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs">
        <div className="px-5 py-4 border-b border-border flex items-center justify-between gap-3">
          <h3 className="text-[14px] font-semibold text-text-pri">Models</h3>
          {selectedModels.length > 0 && (
            <Badge variant="accent" size="sm">{selectedModels.length} selected</Badge>
          )}
        </div>
        <div className="px-5 py-4 space-y-4">
          {discovered.length === 0 && selectedModels.length === 0 ? (
            <p className="text-[13px] text-text-mut">Discover models, then select the ones users may use.</p>
          ) : (
            <>
              {discovered.length > 0 && (
                <div className="flex items-center gap-2">
                  <div className="flex-1">
                    <Input
                      aria-label="Search models"
                      placeholder="Search name or model ID"
                      value={modelQuery}
                      onChange={(e) => setModelQuery(e.target.value)}
                      leftIcon={<Search size={13} aria-hidden="true" />}
                    />
                  </div>
                  {modelQuery && (
                    <Button type="button" variant="ghost" size="sm" onClick={() => setModelQuery('')}>
                      Clear
                    </Button>
                  )}
                </div>
              )}

              {selectedModels.length > 0 && (
                <div className="space-y-1.5">
                  <p className="text-[12px] font-medium text-text-mut">Selected for everyone</p>
                  <ul className="rounded-md border border-accent/30 bg-[var(--accent-dim)]/50 divide-y divide-border overflow-hidden">
                    {selectedModels.map((model) => (
                      <li key={model.id}>
                        <label className="flex items-center gap-2.5 px-3.5 py-2 text-[13px] text-text-pri cursor-pointer hover:bg-[var(--accent-dim)] transition-colors">
                          <input
                            type="checkbox"
                            className="accent-accent shrink-0"
                            checked
                            onChange={() => toggle(model)}
                            aria-label={model.name || model.id}
                          />
                          <span className="font-medium truncate">{model.name || model.id}</span>
                          <span className="ml-auto text-[12px] text-text-dim font-mono truncate">{model.id}</span>
                        </label>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {availableModels.length > 0 && (
                <ul className="max-h-72 overflow-y-auto rounded-md border border-border bg-bg/40 divide-y divide-border">
                  {availableModels.map((model) => (
                    <li key={model.id}>
                      <label className="flex items-center gap-2.5 px-3.5 py-2 text-[13px] text-text-pri cursor-pointer hover:bg-surface-hover transition-colors">
                        <input
                          type="checkbox"
                          className="accent-accent shrink-0"
                          checked={false}
                          onChange={() => toggle(model)}
                          aria-label={model.name || model.id}
                        />
                        <span className="truncate">{model.name || model.id}</span>
                        <span className="ml-auto text-[12px] text-text-dim font-mono truncate">{model.id}</span>
                      </label>
                    </li>
                  ))}
                </ul>
              )}

              {modelSearch && availableModels.length === 0 && (
                <p className="text-[13px] text-text-mut">No other models match “{modelQuery.trim()}”.</p>
              )}
            </>
          )}
        </div>
      </section>
    </div>
  );
}
