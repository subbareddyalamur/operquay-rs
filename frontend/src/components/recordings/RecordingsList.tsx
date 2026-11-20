import { useEffect, useState, useCallback, useMemo } from 'react';
import { Video, ChevronUp, ChevronDown, Search, Play, Download, RefreshCw, Film } from 'lucide-react';
import { Badge, Button, EmptyState, Input, SkeletonRow, Tooltip } from '@/components/primitives';
import { RecordingRow } from './RecordingRow';
import type { Recording } from './RecordingRow';
import { api } from '@/lib/api';

type FilterType = 'all' | 'ssh' | 'k8s' | 'rdp';
type SortKey = 'name' | 'size' | 'mod_time';
type SortDir = 'asc' | 'desc';

interface RecordingsListProps {
  onPlay: (r: Recording) => void;
}

const FILTER_LABELS: Array<{ value: FilterType; label: string }> = [
  { value: 'all', label: 'All' },
  { value: 'ssh', label: 'SSH' },
  { value: 'k8s', label: 'K8s' },
  { value: 'rdp', label: 'RDP' },
];

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function SortIcon({ col, sortKey, sortDir }: { col: SortKey; sortKey: SortKey; sortDir: SortDir }) {
  if (col !== sortKey) return <span className="opacity-30"><ChevronDown size={10} /></span>;
  return sortDir === 'asc' ? <ChevronUp size={10} className="text-accent" /> : <ChevronDown size={10} className="text-accent" />;
}

export function RecordingsList({ onPlay }: RecordingsListProps) {
  const [recordings, setRecordings] = useState<Recording[]>([]);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [deleteError, setDeleteError] = useState('');
  const [filter, setFilter] = useState<FilterType>('all');
  const [search, setSearch] = useState('');
  const [sortKey, setSortKey] = useState<SortKey>('mod_time');
  const [sortDir, setSortDir] = useState<SortDir>('desc');
  const [selectedName, setSelectedName] = useState<string | null>(null);

  const fetchRecordings = useCallback(async () => {
    setLoading(true);
    setUnavailable(false);
    const result = await api.get<Recording[]>('/recordings');
    if (result.ok) setRecordings(result.data ?? []);
    else setUnavailable(true);
    setLoading(false);
  }, []);

  useEffect(() => {
    void fetchRecordings();
  }, [fetchRecordings]);

  const handleDelete = useCallback(async (name: string) => {
    setDeleteError('');
    const result = await api.delete<void>(`/recordings/${encodeURIComponent(name)}`);
    if (result.ok) {
      await fetchRecordings();
    } else setDeleteError('Could not delete recording. Please try again.');
  }, [fetchRecordings]);

  const handleSort = (col: SortKey) => {
    if (col === sortKey) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortKey(col);
      setSortDir('desc');
    }
  };

  const stats = useMemo(() => {
    let ssh = 0;
    let rdp = 0;
    let bytes = 0;
    for (const r of recordings) {
      if (r.type === 'rdp') rdp++;
      else ssh++;
      bytes += r.size || 0;
    }
    return { total: recordings.length, ssh, rdp, bytes };
  }, [recordings]);

  const query = search.trim().toLowerCase();
  const filtered = recordings
    .filter((r) => filter === 'all' || r.type === filter)
    .filter((r) => !query || r.name.toLowerCase().includes(query) || r.type.toLowerCase().includes(query))
    .sort((a, b) => {
      const cmp =
        sortKey === 'name'
          ? a.name.localeCompare(b.name)
          : sortKey === 'size'
            ? a.size - b.size
            : new Date(a.mod_time).getTime() - new Date(b.mod_time).getTime();
      return sortDir === 'asc' ? cmp : -cmp;
    });

  const selectedRecording = filtered.find((r) => r.name === selectedName) ?? filtered[0] ?? null;

  return (
    <div className="space-y-4">
      {!loading && !unavailable && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="rounded-[var(--radius-lg)] border border-border bg-surface px-4 py-3">
            <div className="text-[11px] font-medium uppercase tracking-wider text-text-dim">Total Recordings</div>
            <div className="mt-1 flex items-baseline justify-between">
              <span className="text-[22px] font-mono font-semibold tabular-nums text-text-pri">{stats.total}</span>
              <span className="text-[11px] text-text-dim">Vault index</span>
            </div>
          </div>
          <div className="rounded-[var(--radius-lg)] border border-border bg-surface px-4 py-3">
            <div className="text-[11px] font-medium uppercase tracking-wider text-text-dim">SSH Streams</div>
            <div className="mt-1 flex items-baseline justify-between">
              <span className="text-[22px] font-mono font-semibold tabular-nums text-success">{stats.ssh}</span>
              <span className="text-[11px] text-text-dim">.cast</span>
            </div>
          </div>
          <div className="rounded-[var(--radius-lg)] border border-border bg-surface px-4 py-3">
            <div className="text-[11px] font-medium uppercase tracking-wider text-text-dim">RDP Captures</div>
            <div className="mt-1 flex items-baseline justify-between">
              <span className="text-[22px] font-mono font-semibold tabular-nums text-info">{stats.rdp}</span>
              <span className="text-[11px] text-text-dim">.guac / MP4</span>
            </div>
          </div>
          <div className="rounded-[var(--radius-lg)] border border-border bg-surface px-4 py-3">
            <div className="text-[11px] font-medium uppercase tracking-wider text-text-dim">Vault Size</div>
            <div className="mt-1 flex items-baseline justify-between">
              <span className="text-[22px] font-mono font-semibold tabular-nums text-accent">{formatBytes(stats.bytes)}</span>
              <span className="text-[11px] text-text-dim">Stored media</span>
            </div>
          </div>
        </div>
      )}

      <div className="rounded-[var(--radius-lg)] border border-border bg-surface p-3 flex flex-wrap items-center gap-2">
        <div className="text-xs text-text-sec">
          Showing <span className="font-mono font-semibold text-text-pri">{filtered.length}</span> of{' '}
          <span className="font-mono font-semibold text-text-pri">{recordings.length}</span> recordings
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <div className="w-56">
            <Input
              icon={<Search size={12} />}
              placeholder="Filter recordings…"
              aria-label="Filter recordings"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="text-[12px]"
            />
          </div>
          <div className="flex gap-1" role="group" aria-label="Protocol filter">
            {FILTER_LABELS.map((f) => (
              <button
                key={f.value}
                type="button"
                aria-pressed={filter === f.value}
                onClick={() => setFilter(f.value)}
                className={`px-2.5 py-1 text-[11px] rounded-[var(--radius-sm)] font-medium transition-colors cursor-pointer ${
                  filter === f.value
                    ? 'bg-[var(--accent-soft)] text-accent border border-[var(--accent-border)]'
                    : 'bg-elev text-text-dim hover:text-text-pri border border-transparent'
                }`}
              >
                {f.label}
              </button>
            ))}
          </div>
          <Tooltip label="Refresh recordings">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => void fetchRecordings()}
              aria-label="Refresh recordings"
              disabled={loading}
              icon={<RefreshCw size={12} className={loading ? 'animate-spin motion-reduce:animate-none' : ''} />}
            />
          </Tooltip>
        </div>
      </div>

      {deleteError && <p role="alert" className="text-danger text-[12px]">{deleteError}</p>}
      {loading ? (
        <div className="rounded-[var(--radius-lg)] border border-border divide-y divide-border" aria-busy="true" aria-label="Loading recordings">
          <SkeletonRow />
          <SkeletonRow />
          <SkeletonRow />
        </div>
      ) : unavailable ? (
        <div role="alert" className="py-8 flex flex-col items-center gap-2 text-danger text-[12px]">
          <span>Recordings are unavailable.</span>
          <Button size="sm" variant="secondary" onClick={() => void fetchRecordings()}>
            Retry
          </Button>
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState
          size="sm"
          icon={<Video size={18} />}
          title={
            recordings.length === 0
              ? 'No recordings yet'
              : query
                ? `No recordings matching "${search.trim()}"`
                : `No ${filter} recordings`
          }
          action={
            query || filter !== 'all' ? (
              <Button
                size="sm"
                variant="secondary"
                onClick={() => {
                  setSearch('');
                  setFilter('all');
                }}
              >
                Clear filters
              </Button>
            ) : undefined
          }
        />
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_320px] gap-4 items-start">
          <div className="overflow-x-auto rounded-[var(--radius-lg)] border border-border bg-surface">
            <table className="w-full text-[12px]">
              <thead className="bg-elev/60">
                <tr className="border-b border-border text-[10px] uppercase tracking-wider text-text-dim">
                  <th className="px-4 py-2.5 text-left font-medium">Protocol</th>
                  <th className="px-4 py-2.5 text-left font-medium">
                    <button type="button" className="flex items-center gap-1 hover:text-text-pri cursor-pointer" onClick={() => handleSort('name')}>
                      Filename <SortIcon col="name" sortKey={sortKey} sortDir={sortDir} />
                    </button>
                  </th>
                  <th className="px-4 py-2.5 text-left font-medium">
                    <button type="button" className="flex items-center gap-1 hover:text-text-pri cursor-pointer" onClick={() => handleSort('size')}>
                      Size <SortIcon col="size" sortKey={sortKey} sortDir={sortDir} />
                    </button>
                  </th>
                  <th className="px-4 py-2.5 text-left font-medium">
                    <button type="button" className="flex items-center gap-1 hover:text-text-pri cursor-pointer" onClick={() => handleSort('mod_time')}>
                      Date <SortIcon col="mod_time" sortKey={sortKey} sortDir={sortDir} />
                    </button>
                  </th>
                  <th className="px-4 py-2.5 text-left font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r) => (
                  <RecordingRow
                    key={r.name}
                    recording={r}
                    selected={selectedRecording?.name === r.name}
                    onSelect={(item) => setSelectedName(item.name)}
                    onPlay={(item) => {
                      setSelectedName(item.name);
                      onPlay(item);
                    }}
                    onDelete={(name) => void handleDelete(name)}
                  />
                ))}
              </tbody>
            </table>
          </div>

          {selectedRecording && (
            <aside
              aria-label="Recording vault inspector"
              className="rounded-[var(--radius-lg)] border border-border bg-surface overflow-hidden sticky top-0"
            >
              <div className="flex items-center justify-between border-b border-border bg-elev px-4 py-3">
                <div className="flex items-center gap-2">
                  <Film size={14} className="text-accent" aria-hidden="true" />
                  <span className="text-[12px] font-semibold text-text-pri">Recording Preview</span>
                </div>
                <Badge variant={selectedRecording.type === 'rdp' ? 'info' : 'success'}>
                  {(selectedRecording.type ?? 'ssh').toUpperCase()}
                </Badge>
              </div>
              <div className="p-4 space-y-3 text-[12px]">
                <div className="rounded-[var(--radius-md)] border border-border/80 bg-[var(--canvas,var(--bg))] p-3 flex flex-col items-center justify-center text-center gap-2 min-h-[116px]">
                  <div className="h-9 w-9 rounded-full bg-[var(--accent-soft)] border border-[var(--accent-border)] flex items-center justify-center text-accent">
                    <Play size={15} aria-hidden="true" />
                  </div>
                  <div className="text-[11px] text-text-sec">
                    {selectedRecording.type === 'ssh' || selectedRecording.type === 'k8s' || selectedRecording.name.endsWith('.cast')
                      ? 'Interactive asciinema terminal playback'
                      : selectedRecording.has_mp4
                        ? 'Converted MP4 desktop stream ready'
                        : 'Guacamole graphical session stream'}
                  </div>
                  <Button
                    type="button"
                    size="sm"
                    variant="primary"
                    icon={<Play size={12} />}
                    aria-label="Open selected recording player"
                    onClick={() => onPlay(selectedRecording)}
                  >
                    Open Session Player
                  </Button>
                </div>

                <dl className="space-y-2">
                  <div className="rounded-[var(--radius-sm)] border border-border/70 bg-elev/40 px-2.5 py-2">
                    <dt className="text-[10px] font-semibold uppercase tracking-wider text-text-dim">Filename</dt>
                    <dd className="mt-0.5 font-mono text-[11px] text-text-pri break-all">{selectedRecording.name}</dd>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="rounded-[var(--radius-sm)] border border-border/70 bg-elev/40 px-2.5 py-2">
                      <dt className="text-[10px] font-semibold uppercase tracking-wider text-text-dim">Size</dt>
                      <dd className="mt-0.5 font-mono text-[12px] text-text-pri">{formatBytes(selectedRecording.size)}</dd>
                    </div>
                    <div className="rounded-[var(--radius-sm)] border border-border/70 bg-elev/40 px-2.5 py-2">
                      <dt className="text-[10px] font-semibold uppercase tracking-wider text-text-dim">MP4 Export</dt>
                      <dd className="mt-0.5 text-[12px] text-text-pri">{selectedRecording.has_mp4 ? 'Available' : 'Raw only'}</dd>
                    </div>
                  </div>
                  <div className="rounded-[var(--radius-sm)] border border-border/70 bg-elev/40 px-2.5 py-2">
                    <dt className="text-[10px] font-semibold uppercase tracking-wider text-text-dim">Recorded At</dt>
                    <dd className="mt-0.5 text-[12px] text-text-pri">
                      {Number.isNaN(new Date(selectedRecording.mod_time).getTime())
                        ? '—'
                        : new Date(selectedRecording.mod_time).toLocaleString()}
                    </dd>
                  </div>
                </dl>

                <a
                  href={`/recordings/${encodeURIComponent(selectedRecording.name)}`}
                  download
                  className="w-full inline-flex items-center justify-center gap-1.5 h-8 rounded-[var(--radius)] border border-border bg-elev px-3 text-[12px] font-medium text-text-pri hover:border-[var(--accent-border)] transition-colors"
                >
                  <Download size={12} aria-hidden="true" />
                  Download Raw Stream
                </a>
              </div>
            </aside>
          )}
        </div>
      )}
    </div>
  );
}
