import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Bookmark,
  Bot,
  Columns2,
  Download,
  Plus,
  Search,
  Send,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
} from 'lucide-react';
import { Badge, Button, Card } from '@/design-system/primitives';
import { apiJson } from '../platform/api';
import { WsTerminalPane } from './WsTerminalPane';

export interface TerminalWorkspaceProps {
  instanceId: string;
  region: string;
}

interface SafetyVerdict {
  command: string;
  blocked: boolean;
  reason: string;
}

interface Snippet {
  id: string;
  name: string;
  command: string;
  category: string;
}

const DEFAULT_SNIPPETS: Snippet[] = [
  { id: '1', name: 'Disk usage', command: 'df -h', category: 'System' },
  { id: '2', name: 'Memory usage', command: 'free -h', category: 'System' },
  { id: '3', name: 'Listening sockets', command: 'ss -tlnp', category: 'Network' },
  { id: '4', name: 'K8s unhealthy pods', command: 'kubectl get pods -A --field-selector status.phase!=Running', category: 'Kubernetes' },
  { id: '5', name: 'Systemd failures', command: 'systemctl --failed', category: 'Services' },
];

export function TerminalWorkspace({ instanceId, region }: TerminalWorkspaceProps) {
  const controlsRef = useRef<{
    sendCommand: (cmd: string) => void;
    search: (q: string) => number;
    serialize: () => string;
  } | null>(null);
  const [splitPane, setSplitPane] = useState(false);
  const [showSnippets, setShowSnippets] = useState(false);
  const [snippets, setSnippets] = useState<Snippet[]>(DEFAULT_SNIPPETS);
  const [snippetFilter, setSnippetFilter] = useState('');
  const [newSnipName, setNewSnipName] = useState('');
  const [newSnipCmd, setNewSnipCmd] = useState('');

  const [prefix, setPrefix] = useState('kubectl');
  const [suggestions, setSuggestions] = useState<Array<{ text: string; score: number; source: string }>>([]);
  const [searchText, setSearchText] = useState('');
  const [searchMatches, setSearchMatches] = useState<number>(0);

  const [models, setModels] = useState<Array<{ id: string; provider: string; label: string }>>([]);
  const [selectedModel, setSelectedModel] = useState('');
  const [aiPrompt, setAiPrompt] = useState('Check disk space and avoid destructive cleanup');
  const [aiReply, setAiReply] = useState('');
  const [proposedCmd, setProposedCmd] = useState('df -h');
  const [safetyResult, setSafetyResult] = useState<SafetyVerdict | null>(null);
  const [exportMsg, setExportMsg] = useState<string | null>(null);

  const wsUrl = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws?instance_id=${encodeURIComponent(instanceId)}&region=${encodeURIComponent(region)}`;

  useEffect(() => {
    void apiJson<{ suggestions: Array<{ text: string; score: number; source: string }> }>('/api/suggest', {
      method: 'POST',
      body: JSON.stringify({ prefix, limit: 5 }),
    })
      .then((res) => setSuggestions(res.suggestions ?? []))
      .catch(() => setSuggestions([]));
  }, [prefix]);

  useEffect(() => {
    void apiJson<{ models?: Array<{ id: string; provider: string; label: string }> }>('/api/ai/catalog')
      .then((res) => {
        const list = res.models ?? [];
        setModels(list);
        if (list[0] && !selectedModel) setSelectedModel(list[0].id);
      })
      .catch(() => {});
  }, [selectedModel]);

  const checkSafety = async (cmd: string) => {
    const res = await apiJson<{ blocked: boolean; reason: string }>('/api/ai/check-safety', {
      method: 'POST',
      body: JSON.stringify({ command: cmd }),
    });
    setSafetyResult({ command: cmd, ...res });
  };

  const askAi = async () => {
    setAiReply('');
    try {
      const m = models.find((x) => x.id === selectedModel);
      const res = await apiJson<{ reply?: string; suggested_command?: string; error?: string }>('/ai-agent/chat', {
        method: 'POST',
        body: JSON.stringify({
          provider: m?.provider ?? 'ollama',
          model: selectedModel || 'llama3.2',
          prompt: aiPrompt,
          instance_id: instanceId,
        }),
      });
      setAiReply(res.reply ?? 'No response returned.');
      if (res.suggested_command) {
        setProposedCmd(res.suggested_command);
        await checkSafety(res.suggested_command);
      }
    } catch (e) {
      setAiReply(e instanceof Error ? e.message : 'Configure an LLM API key in AI settings or run safety check directly.');
    }
  };

  const addSnippet = async () => {
    if (!newSnipName.trim() || !newSnipCmd.trim()) return;
    const next = [
      ...snippets,
      { id: String(Date.now()), name: newSnipName.trim(), command: newSnipCmd.trim(), category: 'Custom' },
    ];
    setSnippets(next);
    setNewSnipName('');
    setNewSnipCmd('');
    await apiJson('/preferences', {
      method: 'POST',
      body: JSON.stringify({ theme: 'dark', keyboard_layout: 'en-us-qwerty', snippets: next }),
    }).catch(() => {});
  };

  const handleReady = useCallback(
    (ctrls: { sendCommand: (cmd: string) => void; search: (q: string) => number; serialize: () => string }) => {
      controlsRef.current = ctrls;
    },
    [],
  );

  const runSearch = () => {
    if (!controlsRef.current || !searchText.trim()) {
      setSearchMatches(0);
      return;
    }
    setSearchMatches(controlsRef.current.search(searchText.trim()));
  };

  const exportCast = async () => {
    const vt = controlsRef.current?.serialize() || 'operquay session transcript';
    const out = await apiJson<{ id: string; filename: string; download_url: string }>('/export-session', {
      method: 'POST',
      body: JSON.stringify({ instance_id: instanceId, format: 'cast', transcript: vt }),
    });
    setExportMsg(`Exported ${out.filename} (${out.download_url})`);
  };

  return (
    <div className="max-w-7xl mx-auto px-5 py-5 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-3">
        <div className="flex items-center gap-2.5">
          <Terminal size={16} className="text-accent" aria-hidden="true" />
          <h1 className="text-[18px] font-semibold text-text-pri">
            Pure-Rust WASM Terminal Workspace
          </h1>
          <Badge tone="accent">{instanceId} · {region}</Badge>
          <Badge tone="success">operquay_term.wasm</Badge>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1">
            <input
              aria-label="Search terminal scrollback"
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              placeholder="Search scrollback..."
              className="h-8 w-44 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-pri"
            />
            <Button size="xs" variant="outline" onClick={runSearch} icon={<Search size={12} aria-hidden="true" />}>
              {searchMatches > 0 ? `${searchMatches} hits` : 'Find'}
            </Button>
          </div>
          <Button size="xs" variant="outline" onClick={() => setShowSnippets((s) => !s)} icon={<Bookmark size={12} aria-hidden="true" />}>
            Snippets
          </Button>
          <Button size="xs" variant="outline" onClick={() => setSplitPane((s) => !s)} icon={<Columns2 size={12} aria-hidden="true" />}>
            {splitPane ? 'Single Pane' : 'Split Pane'}
          </Button>
          <Button size="xs" variant="outline" onClick={() => void exportCast()} icon={<Download size={12} aria-hidden="true" />}>
            Export .cast
          </Button>
        </div>
      </div>

      {exportMsg && (
        <div className="px-3.5 py-2 rounded-[var(--radius-sm)] border border-border bg-[var(--success-dim)] text-xs text-success">
          {exportMsg}
        </div>
      )}

      {showSnippets && (
        <Card className="p-4 space-y-3 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-semibold text-text-pri">Command Snippets Library</span>
            <input
              aria-label="Filter command snippets"
              value={snippetFilter}
              onChange={(e) => setSnippetFilter(e.target.value)}
              placeholder="Filter snippets..."
              className="h-7 w-48 px-2 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri"
            />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
            {snippets
              .filter(
                (s) =>
                  !snippetFilter.trim() ||
                  s.name.toLowerCase().includes(snippetFilter.toLowerCase()) ||
                  s.command.toLowerCase().includes(snippetFilter.toLowerCase()),
              )
              .map((s) => (
                <div key={s.id} className="p-2.5 rounded-[var(--radius-sm)] border border-border bg-elev flex items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="font-medium text-text-pri truncate">{s.name}</div>
                    <div className="font-mono text-[11px] text-text-dim truncate">{s.command}</div>
                  </div>
                  <Button size="xs" variant="outline" onClick={() => controlsRef.current?.sendCommand(`${s.command}\r`)}>
                    Run
                  </Button>
                </div>
              ))}
          </div>
          <div className="flex flex-wrap gap-2 pt-2 border-t border-border">
            <input aria-label="Snippet name" value={newSnipName} onChange={(e) => setNewSnipName(e.target.value)} placeholder="Snippet label" className="h-7 px-2 rounded-[var(--radius-sm)] border border-border bg-elev text-text-pri" />
            <input aria-label="Snippet command" value={newSnipCmd} onChange={(e) => setNewSnipCmd(e.target.value)} placeholder="Shell command" className="h-7 flex-1 px-2 rounded-[var(--radius-sm)] border border-border bg-elev font-mono text-text-pri" />
            <Button size="xs" onClick={() => void addSnippet()} icon={<Plus size={12} aria-hidden="true" />}>Save Snippet</Button>
          </div>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-8 space-y-3">
          <div className={splitPane ? 'grid grid-cols-1 md:grid-cols-2 gap-3' : ''}>
            <WsTerminalPane wsUrl={wsUrl} title={`SSM · ${instanceId}`} cols={96} rows={24} onReady={handleReady} />
            {splitPane && (
              <WsTerminalPane wsUrl={wsUrl} title={`Split · ${instanceId}`} cols={96} rows={24} />
            )}
          </div>

          <Card className="p-3.5 space-y-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 text-xs font-medium text-text-pri">
                <Sparkles size={13} className="text-accent" aria-hidden="true" />
                Trie + Frecency + MLP Suggest
              </div>
              <input
                aria-label="Test suggest command prefix"
                value={prefix}
                onChange={(e) => setPrefix(e.target.value)}
                className="h-7 w-48 px-2 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-pri"
              />
            </div>
            <div className="flex flex-wrap gap-1.5">
              {suggestions.map((s) => (
                <button
                  key={s.text}
                  type="button"
                  onClick={() => controlsRef.current?.sendCommand(`${s.text}\r`)}
                  className="px-2.5 py-1 rounded-[var(--radius-sm)] border border-border bg-elev hover:border-[var(--accent-border)] text-xs font-mono text-text-pri"
                >
                  {s.text}
                </button>
              ))}
            </div>
          </Card>
        </div>

        <Card className="lg:col-span-4 p-4 space-y-3 flex flex-col">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm font-semibold text-text-pri">
              <Bot size={15} className="text-accent" aria-hidden="true" />
              AI Ops Guardrails
            </div>
            <Badge tone="neutral">Safety Gate</Badge>
          </div>
          {models.length > 0 && (
            <select
              aria-label="Select AI model"
              value={selectedModel}
              onChange={(e) => setSelectedModel(e.target.value)}
              className="h-8 px-2 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-pri"
            >
              {models.map((m) => (
                <option key={m.id} value={m.id}>{m.label} ({m.provider})</option>
              ))}
            </select>
          )}
          <label htmlFor="ai-prompt-box" className="text-xs text-text-mut">
            Operations Question or Proposal
          </label>
          <textarea
            id="ai-prompt-box"
            rows={2}
            value={aiPrompt}
            onChange={(e) => setAiPrompt(e.target.value)}
            className="w-full p-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-pri"
          />
          <Button size="xs" variant="outline" onClick={() => void askAi()} icon={<Send size={12} aria-hidden="true" />}>
            Ask AI Assistant
          </Button>
          {aiReply && (
            <div className="p-2.5 rounded-[var(--radius-sm)] border border-border bg-elev text-xs text-text-mut whitespace-pre-wrap">
              {aiReply}
            </div>
          )}
          <label htmlFor="ai-cmd-check" className="text-xs text-text-mut">
            Proposed Shell Command (Pre-Execution Check)
          </label>
          <input
            id="ai-cmd-check"
            value={proposedCmd}
            onChange={(e) => setProposedCmd(e.target.value)}
            className="w-full h-8 px-2.5 rounded-[var(--radius-sm)] border border-border bg-elev font-mono text-xs text-text-pri"
          />
          <div className="flex gap-2">
            <Button size="xs" onClick={() => void checkSafety(proposedCmd)}>Verify Safety</Button>
            <Button
              size="xs"
              variant="outline"
              onClick={() => void checkSafety('sudo rm -rf /var/lib')}
            >
              Test Block (`rm -rf`)
            </Button>
          </div>

          {safetyResult && (
            <div
              role="status"
              className={[
                'p-3 rounded-[var(--radius-md)] border text-xs space-y-1',
                safetyResult.blocked
                  ? 'border-border bg-[var(--danger-dim)] text-danger'
                  : 'border-border bg-[var(--success-dim)] text-success',
              ].join(' ')}
            >
              <div className="font-semibold flex items-center gap-1.5">
                {safetyResult.blocked ? <ShieldAlert size={14} aria-hidden="true" /> : <ShieldCheck size={14} aria-hidden="true" />}
                {safetyResult.blocked ? 'Destructive Command Blocked' : 'Command Safe to Run'}
              </div>
              <div className="font-mono text-[11px]">{safetyResult.command}</div>
              {safetyResult.reason && <div>{safetyResult.reason}</div>}
              {!safetyResult.blocked && (
                <Button size="xs" onClick={() => controlsRef.current?.sendCommand(`${safetyResult.command}\r`)}>
                  Send to WASM Terminal
                </Button>
              )}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
