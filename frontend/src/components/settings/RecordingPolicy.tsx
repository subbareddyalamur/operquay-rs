import { useEffect, useId, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { ChevronDown, HardDrive, ListFilter, Search, ShieldCheck, X } from 'lucide-react';
import { Badge, Button } from '@/components/primitives';
import { api } from '@/lib/api';
import { useInstancesStore } from '@/stores/instances';
import { KubeRecordingPolicy } from './KubeRecordingPolicy';

type Mode = 'off' | 'all' | 'selected';
interface Policy { mode: Mode; instances: string[] }

interface DropdownPos {
  left: number;
  width: number;
  top?: number;
  bottom?: number;
  maxHeight: number;
}

export function RecordingPolicy() {
  const accounts = useInstancesStore(s => s.accounts);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [storage, setStorage] = useState<boolean | null>(null);
  const [requiredProduction, setRequiredProduction] = useState(false);
  const [message, setMessage] = useState('');
  const [saving, setSaving] = useState(false);
  const [open, setOpen] = useState(false);
  const [selectedModalOpen, setSelectedModalOpen] = useState(false);
  const [search, setSearch] = useState('');
  const [dropdownPos, setDropdownPos] = useState<DropdownPos | null>(null);
  const selectorRef = useRef<HTMLDivElement>(null);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const selectedBtnRef = useRef<HTMLButtonElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const optionsId = useId();
  const modalTitleId = useId();
  const instances = Array.from(new Map(accounts.flatMap(a => a.regions).flatMap(r => r.groups).flatMap(g => g.instances).map(instance => [instance.instance_id, instance])).values());
  const byId = new Map(instances.map(instance => [instance.instance_id, instance]));
  const query = search.trim().toLowerCase();
  const filtered = instances.filter(instance => `${instance.name} ${instance.instance_id}`.toLowerCase().includes(query));
  useEffect(() => {
    let live = true;
    void api.get<Policy>('/api/recording-policy').then(result => {
      if (!live) return;
      if (result.ok) setPolicy(result.data);
      else setMessage('Could not load recording policy.');
    });
    void api.get<{ configured: boolean; required_production: boolean }>('/api/recording-storage').then(result => {
      if (live && result.ok) { setStorage(result.data.configured); setRequiredProduction(result.data.required_production); }
    });
    return () => { live = false; };
  }, []);

  const updateDropdownPosition = () => {
    const trigger = triggerRef.current;
    if (!trigger) return;
    const rect = trigger.getBoundingClientRect();
    const spaceBelow = window.innerHeight - rect.bottom - 12;
    const spaceAbove = rect.top - 12;
    const width = Math.max(260, rect.width || 420);
    const left = Math.max(8, Math.min(window.innerWidth - width - 8, rect.left));
    if (spaceBelow < 220 && spaceAbove > spaceBelow) {
      setDropdownPos({
        left,
        width,
        bottom: Math.max(8, window.innerHeight - rect.top + 4),
        maxHeight: Math.max(140, Math.min(300, spaceAbove - 48)),
      });
    } else {
      setDropdownPos({
        left,
        width,
        top: rect.bottom + 4,
        maxHeight: Math.max(140, Math.min(300, spaceBelow - 48)),
      });
    }
  };

  useLayoutEffect(() => {
    if (!open) return;
    updateDropdownPosition();
  }, [open, filtered.length]);

  useEffect(() => {
    if (!open) return;
    searchRef.current?.focus();
    const onMouseDown = (event: MouseEvent) => {
      const target = event.target as Node;
      if (!selectorRef.current?.contains(target) && !dropdownRef.current?.contains(target)) {
        setOpen(false);
      }
    };
    const onReposition = () => updateDropdownPosition();
    document.addEventListener('mousedown', onMouseDown);
    window.addEventListener('resize', onReposition);
    window.addEventListener('scroll', onReposition, true);
    return () => {
      document.removeEventListener('mousedown', onMouseDown);
      window.removeEventListener('resize', onReposition);
      window.removeEventListener('scroll', onReposition, true);
    };
  }, [open]);

  useEffect(() => {
    if (!selectedModalOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        event.stopPropagation();
        setSelectedModalOpen(false);
        selectedBtnRef.current?.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown, true);
    return () => document.removeEventListener('keydown', onKeyDown, true);
  }, [selectedModalOpen]);
  if (!policy) return <p role={message ? 'alert' : 'status'}>{message || 'Loading recording policy…'}</p>;
  const save = async () => {
    setSaving(true); setMessage('');
    const result = await api.put<Policy>('/api/recording-policy', { mode: policy.mode, instances: policy.mode === 'selected' ? policy.instances : [] });
    setSaving(false);
    if (result.ok) { setPolicy(result.data); setMessage('Recording policy saved.'); }
    else setMessage('Could not save recording policy.');
  };
  return (
    <div className="space-y-5 text-sm">
      <div className="rounded-lg border border-border bg-surface shadow-xs">
        <div className="px-5 py-4 border-b border-border flex flex-wrap items-start justify-between gap-3">
          <div className="flex items-start gap-3">
            <span className="mt-0.5 w-8 h-8 rounded-md bg-[var(--accent-dim)] text-accent border border-accent/20 flex items-center justify-center shrink-0">
              <HardDrive size={15} aria-hidden="true" />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-[14px] font-semibold text-text-pri">Recording storage</h3>
                <Badge variant={storage === true ? 'success' : storage === false ? 'warn' : 'default'} size="sm">
                  {storage === true ? 'Configured' : storage === false ? 'Not configured' : 'Unknown'}
                </Badge>
              </div>
              <p className="text-xs font-normal text-text-mut mt-1">Changes apply to new sessions. Required production recording still applies.</p>
            </div>
          </div>
          <Badge variant="default" size="sm" className="shrink-0">
            <ShieldCheck size={12} className="mr-1" aria-hidden="true" />
            Audit compliance
          </Badge>
        </div>
        <div className="px-5 py-3.5 bg-bg/40 grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="rounded-md border border-border bg-surface px-3.5 py-2.5 space-y-1">
            <div className="text-[12px] font-medium text-text-pri">Local &amp; NAS destination</div>
            <p className="text-xs font-normal text-text-mut">
              Local or mounted NAS: {storage === true ? 'configured' : storage === false ? 'not configured' : 'configuration unavailable'}. Write access and durability are not verified.
            </p>
            <p className="text-xs font-normal text-text-dim">RDP recording writes are not continuously verified.</p>
          </div>
          <div className="rounded-md border border-border bg-surface px-3.5 py-2.5 space-y-1">
            <div className="text-[12px] font-medium text-text-pri">Object storage</div>
            <p className="text-xs font-normal text-text-mut">Cloud storage is not yet available.</p>
          </div>
        </div>
        {(policy.mode !== 'off' || requiredProduction) && storage !== true && (
          <div className="px-5 py-2.5 border-t border-border bg-warn/10">
            <p role="alert" className="text-[12px] text-warn font-medium">
              {storage === false ? 'No recording storage is configured.' : 'Recording storage configuration could not be verified.'} Sessions requiring recording may fail.
            </p>
          </div>
        )}
      </div>

      <div className="rounded-lg border border-border bg-surface shadow-xs">
        <div className="px-5 py-4 space-y-4">
          <fieldset className="space-y-3">
            <legend className="text-[14px] font-semibold text-text-pri">Record SSH and RDP sessions</legend>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              {([
                { value: 'off', label: 'No instances', desc: 'Unless required by production tag' },
                { value: 'all', label: 'All instances', desc: 'Capture every SSH & RDP session' },
                { value: 'selected', label: 'Selected instances', desc: 'Choose specific instances below' },
              ] as const).map(option => {
                const active = policy.mode === option.value;
                return (
                  <div
                    key={option.value}
                    onClick={() => { setPolicy({ ...policy, mode: option.value }); setMessage(''); setOpen(false); }}
                    className={`flex flex-col gap-1 rounded-lg border px-3.5 py-3 cursor-pointer transition-colors ${
                      active
                        ? 'border-accent bg-[var(--accent-dim)] ring-1 ring-accent/25'
                        : 'border-border bg-bg/50 hover:bg-surface-hover'
                    }`}
                  >
                    <label
                      className="flex items-center gap-2 cursor-pointer text-[13px] font-medium text-text-pri"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <input
                        type="radio"
                        name="recording-mode"
                        checked={active}
                        onChange={() => { setPolicy({ ...policy, mode: option.value }); setMessage(''); setOpen(false); }}
                        className="accent-accent shrink-0"
                      />
                      <span>{option.label}</span>
                    </label>
                    <p className="text-[11px] text-text-dim pl-6">{option.desc}</p>
                  </div>
                );
              })}
            </div>
          </fieldset>

          {policy.mode === 'selected' && (
            <div className="space-y-3 pt-1 max-w-2xl">
              <div className="flex flex-wrap items-center gap-2.5">
                <div
                  ref={selectorRef}
                  className="relative flex-1 min-w-[240px]"
                  onKeyDown={event => {
                    if (!open) return;
                    if (event.key === 'Escape') {
                      event.stopPropagation();
                      setOpen(false);
                      triggerRef.current?.focus();
                      return;
                    }
                    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
                      const items = Array.from(
                        dropdownRef.current?.querySelectorAll<HTMLElement>('input[type="search"], input[type="checkbox"]') ?? [],
                      );
                      if (items.length === 0) return;
                      event.preventDefault();
                      const cur = items.indexOf(document.activeElement as HTMLElement);
                      const next = event.key === 'ArrowDown'
                        ? (cur < 0 ? 0 : (cur + 1) % items.length)
                        : (cur <= 0 ? items.length - 1 : cur - 1);
                      items[next]?.focus();
                    }
                  }}
                >
                  <button
                    ref={triggerRef}
                    type="button"
                    aria-label="Choose instances"
                    aria-expanded={open}
                    aria-controls={optionsId}
                    onClick={() => setOpen(value => !value)}
                    className="w-full h-9 flex items-center justify-between gap-3 rounded-md border border-border bg-bg px-3 text-left text-[13px] text-text-pri hover:border-text-dim focus-visible:outline-2 focus-visible:outline-accent transition-colors"
                  >
                    <span>
                      {policy.instances.length
                        ? `${policy.instances.length} instance${policy.instances.length === 1 ? '' : 's'} selected`
                        : 'Choose instances…'}
                    </span>
                    <ChevronDown size={15} aria-hidden="true" className="shrink-0 text-text-mut" />
                  </button>
                  {open && createPortal(
                    <div
                      ref={dropdownRef}
                      id={optionsId}
                      style={{
                        position: 'fixed',
                        left: dropdownPos?.left ?? 16,
                        width: dropdownPos?.width ?? 360,
                        top: dropdownPos?.top,
                        bottom: dropdownPos?.bottom,
                        zIndex: 9600,
                      }}
                      onKeyDown={event => {
                        if (event.key === 'Escape') {
                          event.preventDefault();
                          event.stopPropagation();
                          setOpen(false);
                          triggerRef.current?.focus();
                          return;
                        }
                        if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
                          const items = Array.from(
                            dropdownRef.current?.querySelectorAll<HTMLElement>('input[type="search"], input[type="checkbox"]') ?? [],
                          );
                          if (items.length === 0) return;
                          event.preventDefault();
                          const cur = items.indexOf(document.activeElement as HTMLElement);
                          const next = event.key === 'ArrowDown'
                            ? (cur < 0 ? 0 : (cur + 1) % items.length)
                            : (cur <= 0 ? items.length - 1 : cur - 1);
                          items[next]?.focus();
                        }
                      }}
                      className="rounded-lg border border-border bg-surface shadow-[var(--shadow-elev)] overflow-hidden"
                    >
                      <div className="flex items-center gap-2 border-b border-border px-3 py-2 bg-bg/60">
                        <Search size={14} aria-hidden="true" className="shrink-0 text-text-dim" />
                        <input
                          ref={searchRef}
                          type="search"
                          aria-label="Search instances"
                          placeholder="Search by name or instance ID…"
                          value={search}
                          onChange={event => setSearch(event.target.value)}
                          className="w-full bg-transparent text-[13px] text-text-pri outline-none placeholder:text-text-dim"
                        />
                      </div>
                      <div
                        role="group"
                        aria-label="Available instances"
                        style={{ maxHeight: dropdownPos?.maxHeight ?? 260 }}
                        className="overflow-y-auto p-1"
                      >
                        {filtered.length === 0 && (
                          <p className="px-3 py-3 text-[12px] text-text-mut">
                            {instances.length ? 'No matching instances.' : 'No instances found in the current inventory.'}
                          </p>
                        )}
                        {filtered.map(instance => (
                          <label
                            key={instance.instance_id}
                            className="flex cursor-pointer items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] text-text-pri hover:bg-surface-hover transition-colors"
                          >
                            <input
                              type="checkbox"
                              className="accent-accent"
                              checked={policy.instances.includes(instance.instance_id)}
                              onChange={event => {
                                setPolicy({
                                  ...policy,
                                  instances: event.target.checked
                                    ? [...policy.instances, instance.instance_id]
                                    : policy.instances.filter(id => id !== instance.instance_id),
                                });
                                setMessage('');
                              }}
                            />
                            <span className="min-w-0 break-words">
                              {instance.name} ({instance.instance_id})
                            </span>
                          </label>
                        ))}
                      </div>
                    </div>,
                    document.body,
                  )}
                </div>

                {policy.instances.length > 0 && (
                  <Button
                    ref={selectedBtnRef}
                    type="button"
                    variant="outline"
                    size="sm"
                    icon={<ListFilter size={14} aria-hidden="true" />}
                    onClick={() => {
                      setOpen(false);
                      setSelectedModalOpen(true);
                    }}
                  >
                    Selected instances ({policy.instances.length})
                  </Button>
                )}
              </div>

              {selectedModalOpen && createPortal(
                <div
                  className="fixed inset-0 z-[9700] flex items-center justify-center bg-[var(--overlay)] backdrop-blur-xs p-4"
                  onClick={event => {
                    if (event.target === event.currentTarget) {
                      setSelectedModalOpen(false);
                      selectedBtnRef.current?.focus();
                    }
                  }}
                >
                  <div
                    role="dialog"
                    aria-modal="true"
                    aria-labelledby={modalTitleId}
                    className="w-full max-w-lg rounded-xl border border-[var(--border-strong)] bg-surface shadow-[var(--shadow-elev)] flex flex-col overflow-hidden"
                  >
                    <div className="flex items-center justify-between gap-3 px-4 py-3 border-b border-border bg-elev">
                      <h4 id={modalTitleId} className="text-[14px] font-semibold text-text-pri">
                        Selected instances ({policy.instances.length})
                      </h4>
                      <button
                        type="button"
                        aria-label="Close modal"
                        onClick={() => {
                          setSelectedModalOpen(false);
                          selectedBtnRef.current?.focus();
                        }}
                        className="rounded p-1 text-text-dim hover:text-text-pri hover:bg-surface-hover transition-colors"
                      >
                        <X size={15} aria-hidden="true" />
                      </button>
                    </div>
                    <div className="max-h-[60vh] overflow-y-auto p-3">
                      {policy.instances.length === 0 ? (
                        <p className="py-6 text-center text-[13px] text-text-mut">No instances selected.</p>
                      ) : (
                        <ul aria-label="Selected recording instances" className="rounded-md border border-border bg-bg/50 divide-y divide-border overflow-hidden">
                          {policy.instances.map(id => {
                            const instance = byId.get(id);
                            const label = instance?.name ? `${instance.name} (${id})` : id;
                            return (
                              <li key={id} className="flex items-center justify-between gap-3 px-3.5 py-2.5 text-[13px]">
                                <span className="min-w-0 break-words">
                                  {instance?.name ? (
                                    <>
                                      <span className="font-medium text-text-pri">{instance.name}</span>{' '}
                                      <span className="font-mono text-[12px] text-text-mut">({id})</span>
                                    </>
                                  ) : (
                                    <>
                                      <span className="font-mono text-[12px] text-text-pri">{id}</span>
                                      <span className="ml-2 text-[12px] text-text-dim">Not in current inventory</span>
                                    </>
                                  )}
                                </span>
                                <button
                                  type="button"
                                  aria-label={`Remove ${label}`}
                                  onClick={() => { setPolicy({ ...policy, instances: policy.instances.filter(value => value !== id) }); setMessage(''); }}
                                  className="shrink-0 rounded p-1 text-text-dim hover:text-danger hover:bg-danger/10 focus-visible:outline-2 focus-visible:outline-accent transition-colors"
                                >
                                  <X size={15} aria-hidden="true" />
                                </button>
                              </li>
                            );
                          })}
                        </ul>
                      )}
                    </div>
                    <div className="flex items-center justify-between gap-2 px-4 py-3 border-t border-border bg-bg/60">
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        disabled={policy.instances.length === 0}
                        onClick={() => {
                          setPolicy({ ...policy, instances: [] });
                          setMessage('');
                        }}
                      >
                        Clear all
                      </Button>
                      <Button
                        type="button"
                        variant="primary"
                        size="sm"
                        onClick={() => {
                          setSelectedModalOpen(false);
                          selectedBtnRef.current?.focus();
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
        </div>

        <div className="px-5 py-3 bg-bg/60 border-t border-border flex flex-wrap items-center justify-between gap-3">
          <div className="min-h-[1.25rem]">
            {message && (
              <p
                role={message.includes('Could not') ? 'alert' : 'status'}
                className={`text-[12px] font-medium ${message.includes('Could not') ? 'text-danger' : 'text-success'}`}
              >
                {message}
              </p>
            )}
          </div>
          <Button
            type="button"
            variant="primary"
            size="sm"
            loading={saving}
            disabled={saving || (policy.mode === 'selected' && policy.instances.length === 0)}
            onClick={() => void save()}
          >
            Save recording policy
          </Button>
        </div>
      </div>

      <KubeRecordingPolicy storage={storage} />
    </div>
  );
}
