import { useState, useCallback, useEffect, useMemo, useRef } from 'react';
import { createPortal } from 'react-dom';
import { Download, Film, Maximize2, Minimize2, RefreshCw, Search, ShieldAlert, X } from 'lucide-react';
import { Dialog } from '@/components/primitives/Dialog';
import { Button, Input, Select, SkeletonRow, Tooltip } from '@/components/primitives';
import { Badge } from '@/components/primitives/Badge';
import { CastRecordingPlayer } from '@/components/recordings/CastRecordingPlayer';
import { GuacPlayer } from '@/components/recordings/GuacPlayer';
import { api } from '@/lib/api';

export interface AuditLogModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface AuditEntry {
  timestamp: string;
  action: string;
  instance_id?: string;
  instance_name?: string;
  session_id?: string;
  details?: string;
  user_id?: string;
  user_email?: string;
  role?: string;
  ip?: string;
  outcome?: string;
  tenant_id?: string;
  user_agent?: string;
  profile?: string;
  region?: string;
  method?: string;
  status_code?: number;
  recording?: string;
  client?: string;
}

type CategoryFilter = 'all' | 'sessions' | 'kubernetes' | 'auth' | 'network';

const PAGE_SIZE = 100;

const CATEGORY_TABS: Array<{ id: CategoryFilter; label: string }> = [
  { id: 'all', label: 'All events' },
  { id: 'sessions', label: 'SSH & RDP' },
  { id: 'kubernetes', label: 'Kubernetes' },
  { id: 'auth', label: 'Identity & Auth' },
  { id: 'network', label: 'Files & Network' },
];

function entryCategory(action: string): CategoryFilter {
  const a = action.toLowerCase();
  if (a.includes('kubernetes') || a.includes('k8s') || a.includes('kube')) return 'kubernetes';
  if (a.includes('login') || a.includes('logout') || a.includes('access_denied') || a.includes('auth') || a.includes('sso')) return 'auth';
  if (a.includes('upload') || a.includes('download') || a.includes('port_forward') || a.includes('broadcast')) return 'network';
  if (a.includes('ssh') || a.includes('rdp') || a.includes('terminal') || a.includes('session')) return 'sessions';
  return 'all';
}

const ACTION_VARIANTS: Record<string, 'success' | 'danger' | 'warn' | 'info' | 'default'> = {
  ssh_start: 'success',
  ssh_stop: 'default',
  rdp_start: 'info',
  rdp_stop: 'default',
  upload: 'info',
  download: 'info',
  broadcast: 'warn',
  port_forward_start: 'info',
  port_forward_stop: 'default',
  clone: 'warn',
  login_sso: 'success',
  login_password: 'success',
  login_break_glass: 'warn',
  logout: 'default',
  access_denied: 'danger',
  license_redeem: 'info',
  request: 'default',
};

function actionVariant(action: string, outcome?: string): 'success' | 'danger' | 'warn' | 'info' | 'default' {
  if (outcome === 'denied' || outcome === 'error') return 'danger';
  return ACTION_VARIANTS[action.toLowerCase()] ?? 'default';
}

function formatTimestamp(ts: string): string {
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short',
  });
}

function fieldsOf(entry: AuditEntry): Array<[string, string | number | undefined]> {
  return Object.entries({
    Timestamp: entry.timestamp,
    Outcome: entry.outcome,
    'User ID': entry.user_id,
    'User email': entry.user_email,
    Role: entry.role,
    Tenant: entry.tenant_id,
    'Source IP': entry.ip,
    'User agent': entry.client || entry.user_agent,
    'Browser string': entry.client && entry.user_agent && entry.client !== entry.user_agent ? entry.user_agent : undefined,
    Instance: entry.instance_id,
    'Instance name': entry.instance_name,
    Profile: entry.profile,
    Region: entry.region,
    'Session ID': entry.session_id,
    Method: entry.method,
    'HTTP status': entry.status_code,
    Recording: entry.recording,
    Details: entry.details,
  });
}

export function AuditLogModal({ open, onOpenChange }: AuditLogModalProps) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [offset, setOffset] = useState(0);
  const generation = useRef(0);
  const [search, setSearch] = useState('');
  const [actionFilter, setActionFilter] = useState('');
  const [outcomeFilter, setOutcomeFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>('all');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [watching, setWatching] = useState<{ name: string; owner: string } | null>(null);

  const fetchLog = useCallback(async () => {
    const current = ++generation.current;
    setLoading(true);
    setError('');
    const res = await api.get<AuditEntry[]>(`/audit-log?limit=${PAGE_SIZE}&offset=${offset}`);
    if (current !== generation.current) return;
    if (res.ok) {
      setEntries(res.data ?? []);
    } else {
      setEntries([]);
      setError(res.error.status === 403 || res.error.status === 401 ? 'Administrator sign-in is required to view the audit log.' : 'Audit log could not be loaded. Check server logs and audit storage.');
    }
    setLoading(false);
  }, [offset]);

  useEffect(() => {
    const pending = generation;
    if (open) void fetchLog();
    return () => { pending.current++; };
  }, [open, fetchLog]);

  const uniqueActions = useMemo(
    () => [...new Set(entries.map((e) => e.action))].sort(),
    [entries],
  );

  const metrics = useMemo(() => {
    const total = entries.length;
    let succeeded = 0;
    let denied = 0;
    let recorded = 0;
    for (const e of entries) {
      if (e.outcome === 'denied' || e.outcome === 'error') denied++;
      else succeeded++;
      if (e.recording) recorded++;
    }
    return { total, succeeded, denied, recorded };
  }, [entries]);

  const filtered = useMemo(() => {
    let list = entries;
    if (categoryFilter !== 'all') list = list.filter((e) => entryCategory(e.action) === categoryFilter);
    if (actionFilter) list = list.filter((e) => e.action === actionFilter);
    if (outcomeFilter === 'success') list = list.filter((e) => !e.outcome || e.outcome === 'success');
    else if (outcomeFilter === 'failure') list = list.filter((e) => e.outcome === 'denied' || e.outcome === 'error');
    if (search.trim()) {
      const q = search.toLowerCase();
      list = list.filter((e) =>
        [e.instance_name, e.instance_id, e.action, e.details, e.session_id, e.user_id, e.user_email, e.ip, e.outcome, e.role, e.tenant_id, e.profile, e.region, e.method, e.user_agent, e.client, e.recording, String(e.status_code ?? '')]
          .some((v) => (v ?? '').toLowerCase().includes(q)),
      );
    }
    return list;
  }, [entries, categoryFilter, actionFilter, outcomeFilter, search]);

  const selectedEntry = useMemo(() => {
    if (!expanded) return null;
    const matchIndex = filtered.findIndex((e, idx) => `${e.timestamp}-${idx}` === expanded);
    return matchIndex >= 0 ? filtered[matchIndex] : null;
  }, [expanded, filtered]);

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title="Audit Log"
      description="Compliance activity trail with forensic event inspection and synchronized session playback."
      size="2xl"
    >
      <div className="space-y-4">
        {!error && !loading && (
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="rounded-[var(--radius-lg)] border border-border bg-surface px-4 py-3">
              <div className="text-[11px] font-medium uppercase tracking-wider text-text-dim">Loaded Events</div>
              <div className="mt-1 flex items-baseline justify-between">
                <span className="text-[22px] font-mono font-semibold tabular-nums text-text-pri">{metrics.total}</span>
                <span className="text-[11px] text-text-dim">Page {Math.floor(offset / PAGE_SIZE) + 1}</span>
              </div>
            </div>
            <div className="rounded-[var(--radius-lg)] border border-border bg-surface px-4 py-3">
              <div className="text-[11px] font-medium uppercase tracking-wider text-text-dim">Succeeded</div>
              <div className="mt-1 flex items-baseline justify-between">
                <span className="text-[22px] font-mono font-semibold tabular-nums text-success">{metrics.succeeded}</span>
                <span className="text-[11px] text-text-dim">Authorized</span>
              </div>
            </div>
            <div className="rounded-[var(--radius-lg)] border border-border bg-surface px-4 py-3">
              <div className="text-[11px] font-medium uppercase tracking-wider text-text-dim">Denied / Error</div>
              <div className="mt-1 flex items-baseline justify-between">
                <span className={`text-[22px] font-mono font-semibold tabular-nums ${metrics.denied > 0 ? 'text-danger' : 'text-text-pri'}`}>{metrics.denied}</span>
                <span className="text-[11px] text-text-dim">Policy hits</span>
              </div>
            </div>
            <div className="rounded-[var(--radius-lg)] border border-border bg-surface px-4 py-3">
              <div className="text-[11px] font-medium uppercase tracking-wider text-text-dim">Recorded Sessions</div>
              <div className="mt-1 flex items-baseline justify-between">
                <span className="text-[22px] font-mono font-semibold tabular-nums text-accent">{metrics.recorded}</span>
                <span className="text-[11px] text-text-dim">Replayable</span>
              </div>
            </div>
          </div>
        )}

        <div className="rounded-[var(--radius-lg)] border border-border bg-surface p-3 space-y-2.5">
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex flex-wrap gap-1" role="group" aria-label="Event category">
              {CATEGORY_TABS.map((cat) => (
                <button
                  key={cat.id}
                  type="button"
                  aria-pressed={categoryFilter === cat.id}
                  onClick={() => setCategoryFilter(cat.id)}
                  className={`px-2.5 py-1 rounded-[var(--radius-sm)] text-[12px] font-medium transition-colors cursor-pointer ${categoryFilter === cat.id
                    ? 'bg-[var(--accent-soft)] text-accent border border-[var(--accent-border)]'
                    : 'text-text-sec hover:text-text-pri hover:bg-elev border border-transparent'
                    }`}
                >
                  {cat.label}
                </button>
              ))}
            </div>
            <a
              href="/api/audit/export"
              className="ml-auto inline-flex items-center gap-1.5 text-[12px] text-accent hover:underline font-medium"
            >
              <Download size={12} aria-hidden="true" />
              Export recent events (up to 10,000)
            </a>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="flex-1 min-w-[200px]">
              <Input
                leftIcon={<Search size={12} />}
                placeholder="Search actor, instance, IP, action, or details…"
                aria-label="Search this page"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="text-sm"
              />
            </div>
            <Select
              className="w-auto min-w-[145px]"
              value={actionFilter}
              onChange={(e) => setActionFilter(e.target.value)}
              aria-label="Filter this page by action"
            >
              <option value="">All actions</option>
              {uniqueActions.map((a) => (
                <option key={a} value={a}>{a}</option>
              ))}
            </Select>
            <Select
              className="w-auto min-w-[135px]"
              value={outcomeFilter}
              onChange={(e) => setOutcomeFilter(e.target.value)}
              aria-label="Filter this page by outcome"
            >
              <option value="">All outcomes</option>
              <option value="success">Success</option>
              <option value="failure">Denied / Error</option>
            </Select>
            <Tooltip label="Refresh audit log">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => void fetchLog()}
                aria-label="Refresh audit log"
                disabled={loading}
                icon={<RefreshCw size={13} className={loading ? 'animate-spin motion-reduce:animate-none' : ''} />}
              />
            </Tooltip>
          </div>
          <p className="text-text-dim text-[11px]">
            Filters search this page only. Records without an attributable tenant are excluded. New events can shift pages.
          </p>
        </div>

        {error && (
          <div role="alert" className="flex items-center gap-2 rounded-[var(--radius)] border border-danger/30 bg-danger/10 px-4 py-3 text-danger text-sm">
            <ShieldAlert size={15} className="shrink-0" aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}

        {loading ? (
          <div className="border border-border rounded-[var(--radius-lg)] overflow-hidden" role="status" aria-label="Loading audit log">
            <SkeletonRow />
            <SkeletonRow />
            <SkeletonRow />
            <SkeletonRow />
            <SkeletonRow />
          </div>
        ) : !error && (
          <div className={`grid gap-4 items-start ${selectedEntry ? 'grid-cols-1 xl:grid-cols-[minmax(0,1fr)_360px]' : 'grid-cols-1'}`}>
            <div className="border border-border rounded-[var(--radius-lg)] bg-surface overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-elev text-[11px] uppercase tracking-wider text-text-dim">
                    <th className="text-left px-3 py-2.5 font-medium w-40">Time</th>
                    <th className="text-left px-3 py-2.5 font-medium w-32">Action</th>
                    <th className="text-left px-3 py-2.5 font-medium">Actor</th>
                    <th className="text-left px-3 py-2.5 font-medium">Resource</th>
                    <th className="text-left px-3 py-2.5 font-medium hidden md:table-cell">Details</th>
                    <th className="text-left px-3 py-2.5 font-medium w-24">Replay</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/70">
                  {filtered.length === 0 && (
                    <tr>
                      <td colSpan={6} className="text-center py-8 text-text-dim">
                        {entries.length ? 'No matching entries on this page' : 'No entries on this page'}
                      </td>
                    </tr>
                  )}
                  {filtered.map((entry, i) => {
                    const key = `${entry.timestamp}-${i}`;
                    const isExpanded = expanded === key;
                    return (
                      <tr
                        key={key}
                        className={`transition-colors hover:bg-elev/70 ${isExpanded ? 'bg-[var(--accent-soft)]/50' : ''}`}
                      >
                        <td className="px-3 py-2.5 text-text-dim font-mono text-[12px] whitespace-nowrap">
                          {formatTimestamp(entry.timestamp)}
                        </td>
                        <td className="px-3 py-2.5">
                          <button
                            type="button"
                            className="focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent rounded text-left cursor-pointer"
                            onClick={() => setExpanded(isExpanded ? null : key)}
                            aria-expanded={isExpanded}
                            aria-label={`Details for ${entry.action}`}
                          >
                            <Badge variant={actionVariant(entry.action, entry.outcome)} className="text-[12px]">
                              {entry.action.replace(/_/g, ' ')}
                            </Badge>
                          </button>
                          {entry.outcome && entry.outcome !== 'success' && (
                            <div className={`text-[11px] mt-0.5 ${entry.outcome === 'error' || entry.outcome === 'denied' ? 'text-danger' : 'text-text-mut'}`}>
                              {entry.outcome}
                            </div>
                          )}
                        </td>
                        <td className="px-3 py-2.5 max-w-[200px]">
                          <div className="truncate text-text-pri font-medium text-[13px]">{entry.user_email || entry.user_id || '—'}</div>
                          <div className="text-[11px] font-mono text-text-dim truncate">
                            {[entry.role, entry.ip].filter(Boolean).join(' · ')}
                          </div>
                        </td>
                        <td className="px-3 py-2.5 text-text-pri max-w-[220px]">
                          <div className="truncate text-[13px]">{entry.instance_name || entry.instance_id || '—'}</div>
                          {entry.instance_name && entry.instance_id && (
                            <div className="font-mono text-[11px] text-text-dim truncate">{entry.instance_id}</div>
                          )}
                        </td>
                        <td className="px-3 py-2.5 text-text-sec hidden md:table-cell max-w-[260px]">
                          <span className="truncate block text-[12px]">{entry.details || '—'}</span>
                        </td>
                        <td className="px-3 py-2.5 whitespace-nowrap">
                          {entry.recording ? (
                            <button
                              type="button"
                              className="inline-flex items-center gap-1 rounded-[var(--radius-sm)] border border-border bg-elev px-2 py-0.5 text-[11px] font-medium text-accent hover:border-[var(--accent-border)] cursor-pointer"
                              onClick={() => setWatching({ name: entry.recording ?? '', owner: `${entry.tenant_id || 'local'}/${entry.user_id || ''}` })}
                              aria-label={`Watch ${entry.recording}`}
                            >
                              <Film size={11} aria-hidden="true" />
                              Watch
                            </button>
                          ) : (
                            <span className="text-text-dim">—</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {selectedEntry && (
              <aside
                aria-label="Forensic event inspector"
                className="rounded-[var(--radius-lg)] border border-border bg-surface overflow-hidden sticky top-0"
              >
                <div className="flex items-center justify-between border-b border-border bg-elev px-4 py-3">
                  <div className="min-w-0">
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-text-dim">Forensic Inspector</div>
                    <div className="mt-1">
                      <Badge variant={actionVariant(selectedEntry.action, selectedEntry.outcome)}>
                        {selectedEntry.action.replace(/_/g, ' ')}
                      </Badge>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setExpanded(null)}
                    aria-label="Close inspector"
                    className="h-7 w-7 inline-flex items-center justify-center rounded text-text-dim hover:text-text-pri hover:bg-surface"
                  >
                    <X size={14} />
                  </button>
                </div>
                <div className="p-4 max-h-[58vh] overflow-y-auto space-y-3">
                  <dl className="grid grid-cols-1 gap-2.5 text-[12px] break-words">
                    {fieldsOf(selectedEntry).map(([label, value]) => (
                      <div key={label} className="rounded-[var(--radius-sm)] border border-border/70 bg-elev/40 px-2.5 py-2">
                        <dt className="text-[10px] font-semibold uppercase tracking-wider text-text-mut">{label}</dt>
                        <dd className="mt-0.5 font-mono text-[12px] text-text-pri">{value ?? '—'}</dd>
                      </div>
                    ))}
                  </dl>
                </div>
              </aside>
            )}
          </div>
        )}

        {watching && <AuditRecordingPlayer name={watching.name} owner={watching.owner} onClose={() => setWatching(null)} />}
        {!error && !loading && (
          <div className="flex flex-wrap items-center gap-3 pt-1 text-sm text-text-mut">
            <span>Showing {filtered.length} of {entries.length} entries on this page.</span>
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={offset === 0}
              onClick={() => { setExpanded(null); setActionFilter(''); setCategoryFilter('all'); setOffset(Math.max(0, offset - PAGE_SIZE)); }}
            >
              Newer events
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={entries.length < PAGE_SIZE}
              onClick={() => { setExpanded(null); setActionFilter(''); setCategoryFilter('all'); setOffset(offset + PAGE_SIZE); }}
            >
              Older events
            </Button>
          </div>
        )}
      </div>
    </Dialog>
  );
}

function AuditRecordingPlayer({ name, owner, onClose }: { name: string; owner: string; onClose: () => void }) {
  const [maximized, setMaximized] = useState(false);
  const isGuac = name.endsWith('.guac');
  const src = `/recordings/${encodeURIComponent(name)}${owner.endsWith('/') ? '' : `?owner=${encodeURIComponent(owner)}`}`;
  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onClose();
      } else if (
        (e.key === 'f' || e.key === 'F') &&
        !e.metaKey &&
        !e.ctrlKey &&
        !e.altKey &&
        (e.target as HTMLElement | null)?.tagName !== 'INPUT'
      ) {
        e.preventDefault();
        setMaximized((m) => !m);
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [onClose]);
  return createPortal(
    <div
      className={`fixed inset-0 z-[9500] flex items-center justify-center bg-[var(--overlay)] backdrop-blur-xs ${maximized ? 'p-0' : 'p-4'}`}
      role="dialog"
      aria-modal="true"
      aria-label={`Recording ${name}`}
      onClick={event => { if (event.target === event.currentTarget) onClose(); }}
    >
      <div className={`flex flex-col overflow-hidden border border-[var(--border-strong)] bg-surface shadow-[var(--shadow-elev)] ${maximized ? 'h-screen w-screen rounded-none' : 'h-[88vh] w-[92vw] rounded-[var(--radius-lg)]'}`}>
        <div className="flex items-center justify-between border-b border-border px-4 py-3 bg-elev shrink-0">
          <span className="truncate font-mono text-[12px] text-text-pri mr-4">{name}</span>
          <div className="flex items-center gap-1.5 shrink-0">
            <button
              type="button"
              onClick={() => setMaximized((m) => !m)}
              className="text-text-dim hover:text-text-pri rounded p-1 hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
              aria-label={maximized ? 'Restore player' : 'Maximize player'}
              title={maximized ? 'Restore window (F)' : 'Maximize window (F)'}
            >
              {maximized ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
            </button>
            <button
              type="button"
              className="text-text-dim hover:text-text-pri rounded p-1 hover:bg-surface-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)]"
              aria-label="Close player"
              onClick={onClose}
            >
              <X size={14} />
            </button>
          </div>
        </div>
        <div className="min-h-0 flex-1 overflow-hidden">
          {isGuac ? (
            <GuacPlayer filename={name} owner={owner.endsWith('/') ? undefined : owner} embedded />
          ) : (
            <CastRecordingPlayer src={src} />
          )}
        </div>
      </div>
    </div>,
    document.body,
  );
}

AuditLogModal.displayName = 'AuditLogModal';
