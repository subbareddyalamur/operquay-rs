import { useRef, useEffect, useState, useCallback, useMemo, type ReactNode } from 'react';
import { X, Send, Square, ShieldAlert, Bot, Plus, ChevronDown, AlertTriangle, Copy, Check } from 'lucide-react';
import { createInputHistory } from '@ui-sdk/core';
import { useAIStore, type Message } from '@/stores/ai';
import { useSessionsStore } from '@/stores/sessions';
import { useAuthStore, hasPermission } from '@/stores/auth';
import { assistantName, useSettingsStore } from '@/stores/settings';
import { ProviderSelector } from './ProviderSelector';
import { CommandProposalCard } from './CommandProposalCard';
import { ToolCallCard } from './ToolCallCard';

function parseInline(text: string): ReactNode[] {
  const nodes: ReactNode[] = [];
  const regex = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      nodes.push(text.slice(lastIndex, match.index));
    }
    const token = match[0];
    if (token.startsWith('**') && token.endsWith('**')) {
      nodes.push(
        <strong key={match.index} className="font-bold text-text-pri">
          {token.slice(2, -2)}
        </strong>,
      );
    } else if (token.startsWith('`') && token.endsWith('`')) {
      nodes.push(
        <code
          key={match.index}
          className="bg-[var(--bg)] text-accent px-1.5 py-0.5 rounded text-[12px] font-mono"
        >
          {token.slice(1, -1)}
        </code>,
      );
    } else {
      nodes.push(token);
    }
    lastIndex = regex.lastIndex;
  }

  if (lastIndex < text.length) {
    nodes.push(text.slice(lastIndex));
  }

  return nodes;
}

function CodeBlock({ lang, code }: { lang: string; code: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="rounded-[var(--radius)] border border-[var(--border)] bg-[var(--bg)] overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1 border-b border-[var(--border)] bg-[var(--surface)]/60">
        <span className="font-mono text-[10px] uppercase tracking-wider text-text-dim">
          {lang || 'shell'}
        </span>
        <button
          type="button"
          onClick={() => {
            void navigator.clipboard?.writeText(code);
            setCopied(true);
            window.setTimeout(() => setCopied(false), 1400);
          }}
          className="inline-flex items-center gap-1 text-[11px] text-text-mut hover:text-text-pri rounded px-1.5 py-0.5 hover:bg-[var(--surface-hover)] focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[var(--accent)]"
          aria-label="Copy code block"
        >
          {copied ? <Check size={11} className="text-success" aria-hidden="true" /> : <Copy size={11} aria-hidden="true" />}
          <span>{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>
      <pre className="p-3 text-[12px] font-mono overflow-x-auto scrollbar-none leading-[1.55] text-text-pri">
        <code>{code}</code>
      </pre>
    </div>
  );
}

function MessageContent({ content }: { content: string }) {
  const blocks = content.split(/(```[\s\S]*?```)/g);

  return (
    <div className="text-[13px] leading-[1.65] space-y-2.5">
      {blocks.map((block, i) => {
        if (block.startsWith('```')) {
          const newline = block.indexOf('\n');
          const lang = newline > 3 ? block.slice(3, newline).trim() : '';
          const code = newline > 0 ? block.slice(newline + 1, -3) : block.slice(3, -3);
          return <CodeBlock key={i} lang={lang} code={code} />;
        }

        const lines = block.split('\n');
        const elements: ReactNode[] = [];
        let listItems: string[] = [];

        const flushList = () => {
          if (listItems.length > 0) {
            elements.push(
              <ul key={`list-${elements.length}`} className="space-y-1 ml-1">
                {listItems.map((item, li) => (
                  <li key={li} className="flex items-start gap-2.5 text-[13px]">
                    <span className="text-accent mt-[8px] text-[5px] shrink-0">●</span>
                    <span className="text-text-pri/90">{parseInline(item)}</span>
                  </li>
                ))}
              </ul>,
            );
            listItems = [];
          }
        };

        for (const [li, rawLine] of lines.entries()) {
          const line = rawLine ?? '';
          const listMatch = line.match(/^\s*[-•*]\s+(.*)/);
          const numberedMatch = line.match(/^\s*\d+\.\s+(.*)/);

          if (listMatch?.[1]) {
            listItems.push(listMatch[1]);
          } else if (numberedMatch?.[1]) {
            listItems.push(numberedMatch[1]);
          } else {
            flushList();
            if (line.trim() === '') {
              if (li > 0 && li < lines.length - 1) {
                elements.push(<div key={`br-${li}`} className="h-1.5" />);
              }
            } else if (line.trim().startsWith('⚠')) {
              elements.push(
                <ErrorBlock key={`w-${li}`} text={line.trim().replace(/^⚠️?\s*/, '')} />,
              );
            } else {
              elements.push(
                <p key={`p-${li}`} className="text-text-pri/90">
                  {parseInline(line)}
                </p>,
              );
            }
          }
        }
        flushList();

        return <div key={i}>{elements}</div>;
      })}
    </div>
  );
}

function ErrorBlock({ text }: { text: string }) {
  const LIMIT = 200;
  const [expanded, setExpanded] = useState(false);
  const truncated = text.length > LIMIT && !expanded;
  return (
    <div className="flex flex-col gap-1.5 text-[12px] text-warn bg-warn/10 border border-warn/20 rounded-lg px-3 py-2.5">
      <div className="flex items-start gap-2">
        <AlertTriangle size={14} className="shrink-0 mt-0.5 text-warn" aria-hidden="true" />
        <span className="leading-snug break-words">
          {truncated ? text.slice(0, LIMIT) + '…' : text}
        </span>
      </div>
      {text.length > LIMIT && (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="flex items-center gap-1 text-[10px] text-warn/70 hover:text-warn transition-colors self-start ml-5"
        >
          <ChevronDown size={10} className={`transition-transform ${expanded ? 'rotate-180' : ''}`} />
          {expanded ? 'Show less' : 'Show full error'}
        </button>
      )}
    </div>
  );
}

function MessageBubble({ msg }: { msg: Message }) {
  const isUser = msg.role === 'user';
  const toolCalls = useAIStore((s) => s.toolCalls);
  const activeSessionId = useSessionsStore((s) => s.activeId);

  if (isUser) {
    return (
      <div className="flex justify-end mb-4">
        <div className="bg-[var(--elev)] border border-[var(--border)] rounded-2xl rounded-tr-md px-4 py-2.5 max-w-[85%]">
          <p className="text-[13px] text-text-pri">{msg.content}</p>
        </div>
      </div>
    );
  }

  const hasText = msg.content.trim() !== '';

  return (
    <div className="mb-5">
      {msg.toolCallIds && msg.toolCallIds.length > 0 && (
        <div className="space-y-2 mb-3">
          {msg.toolCallIds.map((tcId) => {
            const tc = toolCalls[tcId];
            return tc ? <ToolCallCard key={tcId} toolCall={tc} /> : null;
          })}
        </div>
      )}

      {(msg.streaming || hasText) && (
      <div className="bg-[var(--elev)] border border-[var(--border)] rounded-2xl rounded-tl-md px-4 py-3 max-w-[92%]">
        {msg.streaming && !hasText ? (
          <div className="flex items-center gap-1.5 py-1" aria-label="AI is thinking">
            <span className="w-1.5 h-1.5 rounded-full bg-text-dim animate-bounce [animation-delay:0ms]" />
            <span className="w-1.5 h-1.5 rounded-full bg-text-dim animate-bounce [animation-delay:150ms]" />
            <span className="w-1.5 h-1.5 rounded-full bg-text-dim animate-bounce [animation-delay:300ms]" />
          </div>
        ) : (
          <MessageContent content={msg.content} />
        )}

        {msg.streaming && hasText && (
          <span className="inline-block w-0.5 h-4 bg-accent rounded-full animate-pulse ml-0.5 align-middle" aria-hidden="true" />
        )}
      </div>
      )}

      {msg.proposals && msg.proposals.length > 0 && (
        <div className="space-y-2 mt-3">
          {msg.proposals.map((pid) => (
            <CommandProposalCard
              key={pid}
              proposalId={pid}
              sessionId={msg.scope?.sessionId ?? activeSessionId ?? undefined}
              requireActiveSession={Boolean(msg.scope)}
              scope={msg.scope}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export function AIChatPanel() {
  const open = useAIStore((s) => s.open);
  const setOpen = useAIStore((s) => s.setOpen);
  const messages = useAIStore((s) => s.messages);
  const currentScope = useAIStore((s) => s.scope);
  const setScope = useAIStore((s) => s.setScope);
  const streaming = useAIStore((s) => s.streaming);
  const sendMessage = useAIStore((s) => s.sendMessage);
  const stopStreaming = useAIStore((s) => s.stopStreaming);
  const clear = useAIStore((s) => s.clear);
  const activeSessionId = useSessionsStore((s) => s.activeId);
  const active = useSessionsStore((s) => s.sessions.find(session => session.id === s.activeId));
  const configuredUserMode = useAuthStore((s) => s.config?.aws_access_mode === 'user');
  const actor = useAuthStore((s) => s.me);
  const name = assistantName(useSettingsStore((s) => s.assistantName));
  const provider = useSettingsStore((s) => s.aiProvider);
  const model = useSettingsStore((s) => s.aiModel);
  const apiKey = useSettingsStore((s) => s.aiApiKey);
  const endpoint = useSettingsStore((s) => s.aiBaseUrl);
  const modelRegion = useSettingsStore((s) => s.bedrockRegion);
  const inferenceProfile = useSettingsStore((s) => s.bedrockInferenceProfileArn);
  const providerRevision = useRef({ key:apiKey, endpoint, revision:0 });
  if (providerRevision.current.key !== apiKey || providerRevision.current.endpoint !== endpoint) providerRevision.current = { key:apiKey, endpoint, revision:providerRevision.current.revision + 1 };
  const userMode = configuredUserMode || Boolean(active?.userSSH || active?.userRDP || active?.userTopology);
  const [catalog, setCatalog] = useState<{ provider: string; models: Array<{ id: string; name: string }> } | null>(null);
  const [pickedModel, setPickedModel] = useState(() => {
    try { return localStorage.getItem('ct-ai-model') ?? ''; } catch { return ''; }
  });
  useEffect(() => {
    if (!userMode) return;
    let cancel = false;
    const loadCatalog = () => {
      fetch('/api/ai/catalog')
        .then(async (res) => (res.ok ? res.json() as Promise<{ configured?: boolean; provider?: string; models?: Array<{ id: string; name: string }> }> : null))
        .then((data) => {
          if (cancel || !data) return;
          if (!data.configured || !data.models?.length) {
            setCatalog(null);
            return;
          }
          setCatalog({ provider: data.provider || '', models: data.models });
          setPickedModel((current) => data.models?.some((item) => item.id === current) ? current : data.models?.[0]?.id ?? '');
        })
        .catch(() => {});
    };
    loadCatalog();
    window.addEventListener('operquay:ai-catalog-updated', loadCatalog);
    return () => {
      cancel = true;
      window.removeEventListener('operquay:ai-catalog-updated', loadCatalog);
    };
  }, [userMode, actor?.tenant_id, actor?.user_id]);
  const activeInstanceId = useSessionsStore((s) => {
    if (!s.activeId) return undefined;
    const session = s.sessions.find((x) => x.id === s.activeId);
    return session?.instanceId;
  });

  const [input, setInput] = useState('');
  const inputRef = useRef(input);
  inputRef.current = input;
  const promptHistoryRef = useRef<string[]>([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const inputHistory = useMemo(
    () =>
      createInputHistory<string>({
        entries: () => promptHistoryRef.current,
        read: () => inputRef.current,
        write: (value) => {
          setInput(value);
        },
      }),
    [],
  );
  const scopeKey = userMode ? JSON.stringify([actor?.tenant_id, actor?.user_id, actor?.expires_at, active?.id, active?.userSSH?.roleID, active?.userSSH?.region, active?.instanceId, catalog ? catalog.provider : provider, catalog ? pickedModel : model, modelRegion, inferenceProfile, providerRevision.current.revision]) : null;
  const scope = useMemo(() => userMode && scopeKey && actor && hasPermission(actor, 'ai:use') && active?.type === 'ssh' && active.userSSH && active.status === 'connected'
    ? { key:scopeKey, sessionId:active.id, bindingId:active.userSSH.roleID, region:active.userSSH.region, instanceId:active.instanceId, tenantId:actor.tenant_id, userId:actor.user_id, expiresAt:actor.expires_at }
    : undefined, [userMode, scopeKey, actor, active]);
  const visibleMessages = userMode && currentScope !== scopeKey ? [] : messages;
  const visibleStreaming = !userMode || currentScope === scopeKey ? streaming : false;
  const scopedReady = Boolean(scope && currentScope === scopeKey);

  useEffect(() => { setScope(scopeKey); setInput(''); }, [scopeKey, setScope]);

  useEffect(() => {
    if (open) {
      messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, open]);

  useEffect(() => {
    if (open) {
      setTimeout(() => textareaRef.current?.focus(), 150);
    }
  }, [open]);

  const handleSend = useCallback(() => {
    const content = input.trim();
    if (!content || visibleStreaming || (userMode && !scopedReady && !catalog)) return;
    const prev = promptHistoryRef.current;
    if (prev[prev.length - 1] !== content) {
      promptHistoryRef.current = [...prev.slice(-49), content];
    }
    inputHistory.reset();
    setInput('');
    void sendMessage(content, activeInstanceId, scope, catalog ? (pickedModel || catalog.models[0]?.id || undefined) : undefined);
  }, [input, visibleStreaming, userMode, scopedReady, catalog, pickedModel, scope, sendMessage, activeInstanceId, inputHistory]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        handleSend();
        return;
      }
      inputHistory.keydown(e.nativeEvent);
    },
    [handleSend, inputHistory],
  );

  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, 120)}px`;
  }, [input]);

  const isEmpty = visibleMessages.length === 0;

  if (!open) return null;

  return (
    <div
      className="flex h-full min-h-0 w-full flex-col bg-[var(--surface)] border-l border-[var(--border)] overflow-hidden"
      aria-label="AI assistant"
      role="complementary"
    >
      {/* Header */}
      <div className="border-b border-[var(--border)] shrink-0">
        <div className="flex items-center justify-between px-3 h-10">
          <div className="flex items-center gap-2">
            <Bot size={14} className="text-accent shrink-0" aria-hidden="true" />
            <span className="text-[13px] font-semibold text-text-pri">{name}</span>
          </div>
          <div className="flex items-center gap-0.5 shrink-0">
            {visibleMessages.length > 0 && (
              <button
                type="button"
                onClick={clear}
                className="w-7 h-7 rounded-md flex items-center justify-center text-text-dim hover:text-text-pri hover:bg-[var(--elev)] transition-colors"
                aria-label="New conversation"
                title="New conversation"
              >
                <Plus size={14} />
              </button>
            )}
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="w-7 h-7 rounded-md flex items-center justify-center text-text-dim hover:text-text-pri hover:bg-[var(--elev)] transition-colors"
              aria-label="Close AI chat"
              title="Close"
            >
              <X size={14} />
            </button>
          </div>
        </div>
        <div className="px-3 pb-2 space-y-1.5">
          {catalog ? (
            <label className="flex items-center gap-2 min-w-0 text-[11px] text-text-mut">
              Model
              <select aria-label="Assistant model" value={pickedModel} onChange={(e) => { setPickedModel(e.target.value); try { localStorage.setItem('ct-ai-model', e.target.value); } catch { /* the browser can refuse storage */ } }} className="min-w-0 flex-1 bg-transparent text-text-pri focus:outline-none">
                {catalog.models.map((item) => <option key={item.id} value={item.id}>{item.name || item.id}</option>)}
              </select>
            </label>
          ) : userMode ? <span className="text-[11px] text-text-mut">Uses saved AI settings; AWS tools use the selected role and instance.</span> : <ProviderSelector />}
          {active && (!userMode || scopedReady) && (
            <div className="inline-flex items-center gap-1.5 max-w-full px-2 py-0.5 rounded-full bg-bg border border-border text-[11px] text-text-mut">
              <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${active.status === 'connected' ? 'bg-success' : 'bg-text-dim'}`} aria-hidden="true" />
              <span className="truncate">
                Attached · {active.instanceName || active.instanceId}{active.userSSH?.region ? ` (${active.userSSH.region})` : ''}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Messages area */}
      <div
        className="flex-1 overflow-y-auto px-4 py-4"
        style={{ scrollbarWidth: 'thin', scrollbarColor: 'var(--border) transparent' }}
        aria-live="polite"
      >
        {isEmpty ? (
          <div className="h-full flex flex-col items-center justify-center text-center gap-4 p-6">
            <div className="w-12 h-12 rounded-2xl bg-accent/10 flex items-center justify-center">
              <Bot size={22} className="text-accent" aria-hidden="true" />
            </div>
            <div className="space-y-1.5">
              <p className="text-[14px] font-semibold text-text-pri">{name}</p>
              <p className="text-[12px] text-text-mut leading-relaxed max-w-[280px]">
                Ask about your fleet, get command suggestions, debug errors, and analyze infrastructure.
              </p>
            </div>
            <div className="flex flex-wrap gap-1.5 justify-center mt-1">
              {(activeSessionId
                ? ['Check disk & memory usage', 'Inspect recent system logs', 'List listening ports']
                : ['Show running instances', 'Check fleet platform mix', 'How do I forward a port?']
              ).map((q) => (
                <button
                  key={q}
                  type="button"
                  onClick={() => {
                    setInput(q);
                    setTimeout(() => textareaRef.current?.focus(), 50);
                  }}
                  className="text-[11px] text-text-mut hover:text-accent px-2.5 py-1.5 rounded-lg border border-[var(--border)] hover:border-accent/30 hover:bg-accent/5 transition-all"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        ) : (
          <>
            {visibleMessages.map((msg) => (
              <MessageBubble key={msg.id} msg={msg} />
            ))}
            <div ref={messagesEndRef} />
          </>
        )}
      </div>

      {/* Footer: warning + input */}
      <div className="shrink-0 border-t border-[var(--border)]">
        {/* Input area */}
        <div className="px-3 py-2.5">
          <div className="flex items-end gap-2 bg-[var(--elev)] rounded-xl border border-[var(--border)] overflow-hidden focus-within:border-accent/40 transition-colors">
            <textarea
              ref={textareaRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={
                activeSessionId
                  ? 'Ask about your instance…'
                  : 'Ask me anything about your fleet…'
              }
              rows={1}
              className="flex-1 bg-transparent resize-none text-[13px] text-text-pri placeholder:text-text-dim px-3.5 py-2.5 focus:outline-none leading-snug"
              style={{ maxHeight: 120, overflowY: 'auto' }}
              aria-label="Chat message input"
              disabled={!open || (userMode && !scopedReady && !catalog)}
            />
            <div className="flex items-center gap-1 p-1.5 shrink-0">
              {visibleStreaming ? (
                <button
                  type="button"
                  onClick={stopStreaming}
                  className="w-8 h-8 rounded-lg flex items-center justify-center text-danger hover:bg-danger/10 transition-colors"
                  aria-label="Stop generation"
                >
                  <Square size={14} fill="currentColor" />
                </button>
              ) : (
                <button
                  type="button"
                  onClick={handleSend}
                  disabled={!input.trim() || (userMode && !scopedReady && !catalog)}
                  className="w-8 h-8 rounded-lg flex items-center justify-center bg-accent text-accent-fg disabled:opacity-30 disabled:pointer-events-none hover:opacity-90 transition-all"
                  aria-label="Send message"
                >
                  <Send size={14} />
                </button>
              )}
            </div>
          </div>
          {userMode && !scope && !catalog && <p className="text-xs text-warn mt-1.5">Select an active scoped SSH terminal to use the assistant.</p>}
          {userMode && !scope && catalog && <p className="text-[11px] text-text-dim text-center">AWS tools use an open SSH session.</p>}
        </div>

        {/* Safety notice at the very bottom */}
        <div className="flex items-center justify-center gap-1.5 px-3 py-1.5 border-t border-[var(--border)] bg-[var(--bg)]">
          <ShieldAlert size={11} className="text-text-dim shrink-0" aria-hidden="true" />
          <p className="text-[10px] text-text-dim">
            AI never executes commands. You approve every action.
          </p>
        </div>
      </div>
    </div>
  );
}

AIChatPanel.displayName = 'AIChatPanel';
