import { useState, useCallback, useEffect, useMemo } from 'react';
import { Plus, Pencil, Trash2, Copy, Terminal, Search } from 'lucide-react';
import { Dialog, DialogPageContext } from '@/components/primitives/Dialog';
import { Button } from '@/components/primitives/Button';
import { EmptyState } from '@/components/primitives/EmptyState';
import { Input } from '@/components/primitives/Input';
import { SkeletonRow } from '@/components/primitives/Skeleton';
import { Tooltip } from '@/components/primitives/Tooltip';
import { api } from '@/lib/api';
import { canSendCredentials } from '@/lib/credentialTransport';
import { useToastStore } from '@/stores/toast';

export interface SnippetsModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onInsert?: (command: string) => void;
}

interface Snippet {
  id: string;
  name: string;
  command: string;
  category: string;
}

interface PreferencesPayload {
  snippets?: Snippet[];
}

const DEFAULT_SNIPPETS: Snippet[] = [
  { id: '1', name: 'Disk usage', command: 'df -h', category: 'System' },
  { id: '2', name: 'Memory usage', command: 'free -h', category: 'System' },
  { id: '3', name: 'CPU / processes', command: 'top -b -n 1 | head -20', category: 'System' },
  { id: '4', name: 'Uptime', command: 'uptime', category: 'System' },
  { id: '5', name: 'Listening ports', command: 'ss -tlnp', category: 'Network' },
  { id: '6', name: 'Systemd services', command: 'systemctl list-units --state=running', category: 'Services' },
];

function nanoid() {
  return Math.random().toString(36).slice(2, 10);
}

function readSnippets(value: unknown): Snippet[] | null {
  if (!Array.isArray(value)) return null;
  const ids = new Set<string>();
  const result: Snippet[] = [];
  for (const [index, item] of value.entries()) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return null;
    const row = item as Record<string, unknown>;
    if (typeof row.name !== 'string' || typeof row.command !== 'string' || (row.id !== undefined && typeof row.id !== 'string') || (row.category !== undefined && typeof row.category !== 'string')) return null;
    const id = (row.id as string | undefined) || `legacy-${index}`;
    if (ids.has(id)) return null;
    ids.add(id);
    result.push({ ...row, id, name:row.name, command:row.command, category:(row.category as string | undefined) || 'General' });
  }
  return result;
}

export function SnippetsModal({ open, onOpenChange, onInsert }: SnippetsModalProps) {
  const [snippets, setSnippets] = useState<Snippet[]>(DEFAULT_SNIPPETS);
  const [editing, setEditing] = useState<Snippet | null>(null);
  const [isNew, setIsNew] = useState(false);
  const [filterText, setFilterText] = useState('');
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(() => open && canSendCredentials('/preferences'));
  const [loadError, setLoadError] = useState(false);
  const [loadAttempt, setLoadAttempt] = useState(0);
  const pushToast = useToastStore((s) => s.push);

  useEffect(() => {
    if (!open || !canSendCredentials('/preferences')) return;
    let active = true;
    setLoading(true);
    setLoadError(false);
    void api.get<PreferencesPayload>('/preferences').then((res) => {
      if (!active) return;
      if (!res.ok || !res.data || typeof res.data !== 'object' || Array.isArray(res.data)) setLoadError(true);
      else if (res.data.snippets === undefined) setSnippets(DEFAULT_SNIPPETS);
      else {
        const loaded = readSnippets(res.data.snippets);
        if (loaded) setSnippets(loaded);
        else setLoadError(true);
      }
      setLoading(false);
    });
    return () => { active = false; };
  }, [open, loadAttempt]);

  const persist = useCallback(
    async (updated: Snippet[]) => {
      if (!canSendCredentials('/preferences')) {
        pushToast({ variant: 'danger', title: 'Save failed', description: 'HTTPS is required to save snippets' });
        return false;
      }
      setSaving(true);
      const pref = await api.get<PreferencesPayload>('/preferences');
      if (!pref.ok) {
        setSaving(false);
        pushToast({ variant: 'danger', title: 'Save failed', description: 'Could not read preferences' });
        return false;
      }
      const result = await api.patch('/preferences', { snippets: updated });
      setSaving(false);
      if (!result.ok) {
        pushToast({ variant: 'danger', title: 'Save failed', description: 'Could not save snippets' });
      }
      return result.ok;
    },
    [pushToast],
  );

  const handleSaveEdit = useCallback(
    async (s: Snippet) => {
      const updated = isNew
        ? [...snippets, s]
        : snippets.map((x) => (x.id === s.id ? s : x));
      if (await persist(updated)) {
        setSnippets(updated);
        setEditing(null);
        setIsNew(false);
      }
    },
    [snippets, isNew, persist],
  );

  const handleDelete = useCallback(
    async (id: string) => {
      const updated = snippets.filter((s) => s.id !== id);
      if (await persist(updated)) setSnippets(updated);
    },
    [snippets, persist],
  );

  const handleInsert = useCallback(
    (command: string) => {
      if (onInsert) {
        onInsert(command);
      } else {
        void navigator.clipboard.writeText(command).then(() => {
          pushToast({ variant: 'success', title: 'Copied', description: 'Command copied to clipboard' });
        });
      }
    },
    [onInsert, pushToast],
  );

  const filtered = useMemo(() => {
    if (!filterText.trim()) return snippets;
    const q = filterText.toLowerCase();
    return snippets.filter(
      (s) =>
        s.name.toLowerCase().includes(q) ||
        s.command.toLowerCase().includes(q) ||
        s.category.toLowerCase().includes(q),
    );
  }, [snippets, filterText]);

  const categories = useMemo(
    () => [...new Set(filtered.map((s) => s.category))].sort(),
    [filtered],
  );

  if (editing) {
    return (
      <DialogPageContext.Provider value={false}>
        <SnippetEditor
          snippet={editing}
          isNew={isNew}
          saving={saving}
          onSave={(s) => void handleSaveEdit(s)}
          onCancel={() => { setEditing(null); setIsNew(false); }}
        />
      </DialogPageContext.Provider>
    );
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Snippets"
      size="lg"
      footer={
        <Button
          variant="primary"
          size="sm"
          icon={<Plus size={13} />}
          disabled={saving || loading || loadError}
          onClick={() => {
            setEditing({ id: nanoid(), name: '', command: '', category: 'General' });
            setIsNew(true);
          }}
        >
          New snippet
        </Button>
      }
    >
      <div className="space-y-3">
        <Input
          icon={<Search size={12} />}
          placeholder="Filter snippets…"
          aria-label="Filter snippets"
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          className="text-[12px]"
        />

        {loadError && (
          <div role="alert" className="py-4 flex items-center justify-center gap-2 text-danger text-[12px]">
            <span>Snippets are unavailable.</span>
            <Button size="sm" variant="secondary" onClick={() => setLoadAttempt((n) => n + 1)}>
              Retry
            </Button>
          </div>
        )}
        {loading && !loadError && (
          <div className="border border-border rounded divide-y divide-border" aria-busy="true" aria-label="Loading snippets">
            <SkeletonRow />
            <SkeletonRow />
            <SkeletonRow />
          </div>
        )}
        {!loading && !loadError && categories.length === 0 && (
          <EmptyState
            size="sm"
            icon={<Terminal size={18} />}
            title="No snippets found"
            description={filterText.trim() ? 'No snippets match your search query.' : 'Create reusable shell commands for quick insertion.'}
            action={
              filterText.trim() ? (
                <Button size="sm" variant="secondary" onClick={() => setFilterText('')}>
                  Clear filter
                </Button>
              ) : undefined
            }
          />
        )}

        {!loading && !loadError && categories.map((cat) => (
          <div key={cat}>
            <h3 className="text-[10px] font-semibold uppercase tracking-wider text-text-dim mb-1.5 px-0.5">
              {cat}
            </h3>
            <div className="border border-border rounded divide-y divide-border">
              {filtered
                .filter((s) => s.category === cat)
                .map((snippet) => (
                  <div
                    key={snippet.id}
                    className="flex items-center gap-2 px-3 py-2 hover:bg-surface-hover transition-colors group"
                  >
                    <Terminal size={13} className="text-text-dim shrink-0" />
                    <div className="flex-1 min-w-0">
                      <p className="text-[13px] text-text-pri">{snippet.name}</p>
                      <p className="text-[11px] text-text-dim font-mono truncate">{snippet.command}</p>
                    </div>
                    <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 transition-opacity">
                      <Tooltip content={onInsert ? 'Insert into active terminal' : 'Copy command'} side="top">
                        <button
                          type="button"
                          aria-label={`Insert ${snippet.name}`}
                          className="text-text-dim hover:text-accent transition-colors p-1 rounded hover:bg-elev cursor-pointer"
                          onClick={() => handleInsert(snippet.command)}
                        >
                          {onInsert ? <Terminal size={13} /> : <Copy size={13} />}
                        </button>
                      </Tooltip>
                      {onInsert && (
                        <Tooltip content="Copy command" side="top">
                          <button
                            type="button"
                            aria-label={`Copy ${snippet.name}`}
                            className="text-text-dim hover:text-accent transition-colors p-1 rounded hover:bg-elev cursor-pointer"
                            onClick={() => {
                              void navigator.clipboard.writeText(snippet.command).then(() => {
                                pushToast({ variant: 'success', title: 'Copied', description: 'Command copied to clipboard' });
                              });
                            }}
                          >
                            <Copy size={13} />
                          </button>
                        </Tooltip>
                      )}
                      <Tooltip content="Edit snippet" side="top">
                        <button
                          type="button"
                          aria-label={`Edit ${snippet.name}`}
                          disabled={saving}
                          className="text-text-dim hover:text-text-pri transition-colors p-1 rounded hover:bg-elev cursor-pointer"
                          onClick={() => setEditing(snippet)}
                        >
                          <Pencil size={13} />
                        </button>
                      </Tooltip>
                      <Tooltip content="Delete snippet" side="top">
                        <button
                          type="button"
                          aria-label={`Delete ${snippet.name}`}
                          disabled={saving}
                          className="text-text-dim hover:text-danger transition-colors p-1 rounded hover:bg-danger/10 cursor-pointer"
                          onClick={() => void handleDelete(snippet.id)}
                        >
                          <Trash2 size={13} />
                        </button>
                      </Tooltip>
                    </div>
                  </div>
                ))}
            </div>
          </div>
        ))}
      </div>
    </Dialog>
  );
}

interface SnippetEditorProps {
  snippet: Snippet;
  isNew: boolean;
  saving: boolean;
  onSave: (s: Snippet) => void;
  onCancel: () => void;
}

function SnippetEditor({ snippet, isNew, saving, onSave, onCancel }: SnippetEditorProps) {
  const [name, setName] = useState(snippet.name);
  const [command, setCommand] = useState(snippet.command);
  const [category, setCategory] = useState(snippet.category);
  const [error, setError] = useState('');

  const handleSave = () => {
    if (!name.trim()) { setError('Name is required'); return; }
    if (!command.trim()) { setError('Command is required'); return; }
    onSave({ ...snippet, name: name.trim(), command: command.trim(), category: category.trim() || 'General' });
  };

  return (
    <Dialog
      open
      onOpenChange={onCancel}
      title={isNew ? 'New Snippet' : 'Edit Snippet'}
      size="sm"
      footer={
        <>
          <Button variant="outline" size="sm" onClick={onCancel}>Cancel</Button>
          <Button variant="primary" size="sm" loading={saving} onClick={handleSave}>Save</Button>
        </>
      }
    >
      <div className="space-y-3">
        <div>
          <label htmlFor="snip-name" className="text-[11px] font-medium text-text-mut block mb-1">Name</label>
          <Input id="snip-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Disk usage" />
        </div>
        <div>
          <label htmlFor="snip-cmd" className="text-[11px] font-medium text-text-mut block mb-1">Command</label>
          <Input id="snip-cmd" value={command} onChange={(e) => setCommand(e.target.value)} placeholder="df -h" className="font-mono" />
        </div>
        <div>
          <label htmlFor="snip-cat" className="text-[11px] font-medium text-text-mut block mb-1">Category</label>
          <Input id="snip-cat" value={category} onChange={(e) => setCategory(e.target.value)} placeholder="System" />
        </div>
        {error && <p className="text-[11px] text-danger">{error}</p>}
      </div>
    </Dialog>
  );
}

SnippetsModal.displayName = 'SnippetsModal';
