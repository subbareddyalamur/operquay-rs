import { useEffect, useId, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { ListFilter, X } from 'lucide-react';
import { api } from '@/lib/api';
import { Badge, Button, ConfirmDialog, Input } from '@/components/primitives';
import type { KubeCluster } from './KubeClusters';

type KubePolicy = { mode: 'off' | 'all' | 'selected'; namespaces: string[]; inherited?: boolean };

export function KubeRecordingPolicy({ storage = true }: { storage?: boolean | null }) {
  const [clusters, setClusters] = useState<KubeCluster[] | null>(null);
  const [selected, setSelected] = useState('default');
  const [pendingSelectId, setPendingSelectId] = useState<string | null>(null);
  const [policy, setPolicy] = useState<KubePolicy | null>(null);
  const [draft, setDraft] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [nsModalOpen, setNsModalOpen] = useState(false);
  const nsBtnRef = useRef<HTMLButtonElement>(null);
  const modalTitleId = useId();
  const path = selected === 'default' ? '/api/k8s/recording-policy' : `/api/k8s/configured-clusters/${encodeURIComponent(selected)}/recording`;

  useEffect(() => {
    if (!nsModalOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        setNsModalOpen(false);
        nsBtnRef.current?.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown, true);
    return () => document.removeEventListener('keydown', onKeyDown, true);
  }, [nsModalOpen]);

  useEffect(() => { let live = true; void api.get<KubeCluster[]>('/api/k8s/configured-clusters').then(r => { if (live) { if (r.ok && Array.isArray(r.data)) setClusters(r.data); else setError('Could not load configured clusters.'); } }); return () => { live = false; }; }, []);
  useEffect(() => {
    let live = true; setPolicy(null); setNotice(''); setDraft(''); setDirty(false);
    void api.get<KubePolicy>(path).then(r => { if (live) { if (r.ok) setPolicy(r.data); else setError('Could not load Kubernetes recording policy.'); } });
    return () => { live = false; };
  }, [path]);
  const save = async () => {
    if (!policy) return;
    setSaving(true); setError(''); setNotice('');
    const result = await api.put<KubePolicy>(path, { mode:policy.mode, namespaces:policy.mode === 'selected' ? policy.namespaces : [] });
    setSaving(false);
    if (result.ok) { setPolicy(result.data); if (selected !== 'default') setClusters(current => current?.map(c => c.id === selected ? { ...c, recording_mode:result.data.mode } : c) ?? null); setDirty(false); setNotice('Kubernetes recording policy saved.'); }
    else setError('Could not save Kubernetes recording policy.');
  };
  const add = () => {
    if (!policy) return;
    const value = draft.trim();
    if (value.length > 63 || !/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/.test(value) || policy.namespaces.includes(value)) { setError('Enter a valid, unique namespace name.'); return; }
    setPolicy({ ...policy, namespaces:[...policy.namespaces, value] }); setDirty(true); setDraft(''); setError('');
  };
  const select = (id: string) => {
    if (id === selected) return;
    if (dirty) {
      setPendingSelectId(id);
      return;
    }
    setError(''); setSelected(id);
  };
  const activeCluster = clusters?.find(c => c.id === selected);
  return (
    <section className="rounded-lg border border-border bg-surface overflow-hidden shadow-xs">
      <div className="px-5 py-4 border-b border-border">
        <h3 className="text-[14px] font-semibold text-text-pri">Kubernetes shells</h3>
        <p className="text-xs font-normal text-text-mut mt-0.5">
          Changes apply to new shells. Unmatched connections use the default policy.
        </p>
      </div>
      {error && (
        <div className="px-5 py-2.5 bg-danger/10 border-b border-danger/20">
          <p role="alert" className="text-[12px] text-danger">{error}</p>
        </div>
      )}
      <div className="grid grid-cols-1 md:grid-cols-[240px_1fr]">
        <div
          className="border-b md:border-b-0 md:border-r border-border bg-side/60 p-2 space-y-1"
          aria-label="Recording clusters"
        >
          <button
            type="button"
            disabled={saving}
            aria-pressed={selected === 'default'}
            className={`w-full text-left rounded-md px-3 py-2 text-[13px] font-medium transition-colors flex items-center justify-between gap-2 ${
              selected === 'default'
                ? 'bg-[var(--accent-dim)] text-accent border border-accent/25'
                : 'text-text-pri border border-transparent hover:bg-surface-hover'
            }`}
            onClick={() => select('default')}
          >
            <span>Default policy</span>
            <Badge variant={selected === 'default' ? 'accent' : 'default'} size="sm">Global</Badge>
          </button>
          {clusters?.map(cluster => {
            const isSel = selected === cluster.id;
            const modeLabel = ({ default: 'Default', off: 'None', all: 'All', selected: 'Selected' } as const)[
              cluster.recording_mode ?? 'default'
            ];
            return (
              <button
                key={cluster.id}
                type="button"
                disabled={saving}
                aria-pressed={isSel}
                className={`w-full text-left rounded-md px-3 py-2 transition-colors border ${
                  isSel
                    ? 'bg-[var(--accent-dim)] border-accent/25 text-accent'
                    : 'border-transparent hover:bg-surface-hover text-text-pri'
                }`}
                onClick={() => select(cluster.id)}
              >
                <span className="flex items-center justify-between gap-2">
                  <span className="text-[13px] font-medium break-words">{cluster.label}</span>
                  <Badge variant={isSel ? 'accent' : 'default'} size="sm">{modeLabel}</Badge>
                </span>
                <span className="block text-[11px] font-mono text-text-dim break-all mt-0.5 truncate">
                  {cluster.proxy}
                </span>
              </button>
            );
          })}
          {clusters?.length === 0 && (
            <p className="p-2.5 text-xs text-text-mut">No clusters configured.</p>
          )}
        </div>

        <div className="p-5 flex flex-col justify-between gap-4">
          <div className="space-y-4">
            <div className="pb-3 border-b border-border">
              <h4 className="text-[14px] font-semibold text-text-pri">
                {selected === 'default' ? 'Default policy' : activeCluster?.label}
              </h4>
              <p className="text-xs font-normal text-text-mut mt-0.5 break-all">
                {selected === 'default' ? 'Applies when a cluster has no specific policy.' : activeCluster?.proxy}
              </p>
            </div>

            {policy ? (
              <>
                <p className="text-xs font-normal text-text-mut">
                  {policy.inherited ? 'Uses the default policy until saved.' : 'Choose which namespaces to record.'}
                </p>
                {policy.mode !== 'off' && storage !== true && (
                  <p role="alert" className="text-[12px] text-warn font-medium bg-warn/10 border border-warn/25 rounded-md px-3 py-2">
                    Recording storage is {storage === false ? 'not configured' : 'unavailable'}. Shells requiring recording may fail.
                  </p>
                )}
                <fieldset disabled={saving} className="space-y-2">
                  <legend className="sr-only">Kubernetes recording mode</legend>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                    {([
                      { value: 'off', label: 'None' },
                      { value: 'all', label: 'All namespaces' },
                      { value: 'selected', label: 'Selected namespaces' },
                    ] as const).map(option => {
                      const active = policy.mode === option.value;
                      return (
                        <label
                          key={option.value}
                          className={`flex items-center gap-2 rounded-md border px-3 py-2.5 text-[13px] cursor-pointer transition-colors ${
                            active
                              ? 'border-accent bg-[var(--accent-dim)] text-text-pri font-medium'
                              : 'border-border bg-bg/50 text-text-mut hover:bg-surface-hover'
                          }`}
                        >
                          <input
                            type="radio"
                            name="kube-recording-mode"
                            className="accent-accent"
                            checked={active}
                            onChange={() => { setPolicy({ ...policy, mode: option.value }); setDirty(true); setNotice(''); }}
                          />
                          <span>{option.label}</span>
                        </label>
                      );
                    })}
                  </div>
                </fieldset>

                {policy.mode === 'selected' && (
                  <div className="space-y-2.5 pt-1">
                    <div className="flex items-end gap-2">
                      <label className="flex-1 block space-y-1 text-[12px] font-medium text-text-mut">
                        <span>Namespace</span>
                        <Input
                          disabled={saving}
                          aria-label="Namespace"
                          value={draft}
                          onChange={e => setDraft(e.target.value)}
                          onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); add(); } }}
                          placeholder="production"
                          className="font-mono"
                        />
                      </label>
                      <Button type="button" variant="outline" size="sm" disabled={saving} onClick={add}>
                        Add namespace
                      </Button>
                    </div>
                    {policy.namespaces.length > 0 && (
                      <div>
                        <Button
                          ref={nsBtnRef}
                          type="button"
                          variant="outline"
                          size="sm"
                          disabled={saving}
                          icon={<ListFilter size={14} aria-hidden="true" />}
                          onClick={() => setNsModalOpen(true)}
                        >
                          Selected namespaces ({policy.namespaces.length})
                        </Button>
                      </div>
                    )}
                    {nsModalOpen && createPortal(
                      <div
                        className="fixed inset-0 z-[9700] flex items-center justify-center bg-[var(--overlay)] backdrop-blur-xs p-4"
                        onClick={e => {
                          if (e.target === e.currentTarget) {
                            setNsModalOpen(false);
                            nsBtnRef.current?.focus();
                          }
                        }}
                      >
                        <div
                          role="dialog"
                          aria-modal="true"
                          aria-labelledby={modalTitleId}
                          className="w-full max-w-md rounded-xl border border-[var(--border-strong)] bg-surface shadow-[var(--shadow-elev)] flex flex-col overflow-hidden"
                        >
                          <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-border bg-elev">
                            <h4 id={modalTitleId} className="text-[14px] font-semibold text-text-pri">
                              Selected namespaces ({policy.namespaces.length})
                            </h4>
                            <button
                              type="button"
                              aria-label="Close modal"
                              onClick={() => {
                                setNsModalOpen(false);
                                nsBtnRef.current?.focus();
                              }}
                              className="rounded p-1 text-text-dim hover:text-text-pri hover:bg-surface-hover transition-colors"
                            >
                              <X size={15} aria-hidden="true" />
                            </button>
                          </div>
                          <div className="max-h-[55vh] overflow-y-auto p-3">
                            {policy.namespaces.length === 0 ? (
                              <p className="py-6 text-center text-[13px] text-text-mut">No namespaces selected.</p>
                            ) : (
                              <ul aria-label="Selected recording namespaces" className="rounded-md border border-border bg-bg/50 divide-y divide-border overflow-hidden">
                                {policy.namespaces.map(name => (
                                  <li key={name} className="flex items-center justify-between gap-2 px-3 py-2.5 text-[13px]">
                                    <span className="font-mono text-text-pri">{name}</span>
                                    <button
                                      type="button"
                                      disabled={saving}
                                      aria-label={`Remove ${name}`}
                                      onClick={() => {
                                        setPolicy({ ...policy, namespaces: policy.namespaces.filter(n => n !== name) });
                                        setDirty(true);
                                      }}
                                      className="rounded p-1 text-text-dim hover:text-danger hover:bg-danger/10 focus-visible:outline-2 focus-visible:outline-accent transition-colors"
                                    >
                                      <X size={15} aria-hidden="true" />
                                    </button>
                                  </li>
                                ))}
                              </ul>
                            )}
                          </div>
                          <div className="flex items-center justify-between gap-2 px-4 py-3 border-t border-border bg-bg/60">
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              disabled={saving || policy.namespaces.length === 0}
                              onClick={() => {
                                setPolicy({ ...policy, namespaces: [] });
                                setDirty(true);
                              }}
                            >
                              Clear all
                            </Button>
                            <Button
                              type="button"
                              variant="primary"
                              size="sm"
                              onClick={() => {
                                setNsModalOpen(false);
                                nsBtnRef.current?.focus();
                              }}
                            >
                              Close
                            </Button>
                          </div>
                        </div>
                      </div>,
                      document.body,
                    )}
                  </div>
                )}
              </>
            ) : (
              <p className="text-xs text-text-mut py-4">Loading policy…</p>
            )}
          </div>

          {policy && (
            <div className="pt-3 border-t border-border flex flex-wrap items-center justify-between gap-3">
              <div className="min-h-[1.25rem]">
                {notice && <p role="status" className="text-[12px] font-medium text-success">{notice}</p>}
              </div>
              <Button
                type="button"
                variant="primary"
                size="sm"
                loading={saving}
                disabled={saving || (policy.mode === 'selected' && policy.namespaces.length === 0)}
                onClick={() => void save()}
              >
                Save Kubernetes policy
              </Button>
            </div>
          )}
        </div>
      </div>

      <ConfirmDialog
        open={Boolean(pendingSelectId)}
        onOpenChange={(open) => { if (!open) setPendingSelectId(null); }}
        title="Discard unsaved Kubernetes recording changes?"
        description="Switching clusters will discard the unsaved recording policy edits for the current cluster."
        confirmLabel="Discard"
        onConfirm={() => {
          if (pendingSelectId) {
            setError('');
            setSelected(pendingSelectId);
          }
          setPendingSelectId(null);
        }}
      />
    </section>
  );
}
