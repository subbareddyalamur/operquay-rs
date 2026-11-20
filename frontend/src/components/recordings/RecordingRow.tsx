import { useEffect, useState } from 'react';
import { Play, Film, Download, Trash2, Loader2 } from 'lucide-react';
import { Button, Badge } from '@/components/primitives';
import { api } from '@/lib/api';

export interface Recording {
  name: string;
  type: 'ssh' | 'rdp' | 'k8s';
  size: number;
  mod_time: string;
  has_mp4?: boolean;
}

interface RecordingRowProps {
  recording: Recording;
  onPlay: (r: Recording) => void;
  onDelete: (name: string) => void;
  selected?: boolean;
  onSelect?: (r: Recording) => void;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export function RecordingRow({ recording: r, onPlay, onDelete, selected = false, onSelect }: RecordingRowProps) {
  const [converting, setConverting] = useState(false);
  const [converted, setConverted] = useState(!!r.has_mp4);
  const [jobId, setJobId] = useState<string | null>(null);
  const [conversionError, setConversionError] = useState('');
  const [confirmingDelete, setConfirmingDelete] = useState(false);

  const rawName = r.name ?? 'recording';
  const base = rawName.replace(/\.[^.]+$/, '');

  const handleConvert = async () => {
    setConverting(true);
    setConversionError('');
    const result = await api.post<{ job_id: string }>('/convert-recording', { filename: rawName });
    if (result.ok) {
      setJobId(result.data.job_id);
    } else {
      setConversionError(result.error.message);
      setConverting(false);
    }
  };

  useEffect(() => {
    if (!jobId) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      const result = await api.get<{ status: string; error?: string }>(`/convert-status/${encodeURIComponent(jobId)}`);
      if (!active) return;
      if (!result.ok || result.data.status === 'error') {
        setConversionError(result.ok ? result.data.error || 'Conversion failed' : result.error.message);
        setConverting(false);
        setJobId(null);
      } else if (result.data.status === 'done') {
        setConverted(true);
        setConverting(false);
        setJobId(null);
      } else {
        timer = setTimeout(() => void poll(), 2000);
      }
    };
    void poll();
    return () => { active = false; clearTimeout(timer); };
  }, [jobId]);

  const modified = new Date(r.mod_time);
  const dateDisplay = Number.isNaN(modified.getTime()) ? '—' : modified.toLocaleDateString([], {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });

  return (
    <tr
      onClick={() => onSelect?.(r)}
      className={`border-b border-border transition-colors text-[12px] ${onSelect ? 'cursor-pointer' : ''} ${
        selected ? 'bg-[var(--accent-soft)]/50' : 'hover:bg-elev/50'
      }`}
    >
      <td className="px-4 py-2.5">
        <Badge variant={r.type === 'rdp' ? 'info' : 'success'}>{(r.type ?? 'ssh').toUpperCase()}</Badge>
      </td>
      <td className="px-4 py-2.5 font-mono text-text-pri truncate max-w-[240px]">{r.name}</td>
      <td className="px-4 py-2.5 text-text-dim">{formatSize(r.size)}</td>
      <td className="px-4 py-2.5 text-text-dim">{dateDisplay}</td>
      <td className="px-4 py-2.5">
        <div className="flex items-center gap-1 whitespace-nowrap">
          {conversionError && (
            <span
              role="alert"
              title={conversionError}
              className="max-w-[220px] truncate px-2 py-0.5 rounded bg-danger/10 border border-danger/30 text-[11px] text-danger shrink-0"
            >
              {conversionError}
            </span>
          )}
          <Button
            variant="ghost"
            size="xs"
            icon={<Play size={11} />}
            onClick={() => onPlay({ ...r, has_mp4: converted })}
            aria-label={`Play ${r.name}`}
          />

          {!converted ? (
            <Button
              variant="ghost"
              size="xs"
              icon={converting ? <Loader2 size={11} className="animate-spin" /> : <Film size={11} />}
              onClick={() => void handleConvert()}
              disabled={converting}
              aria-label={`Convert ${r.name} to MP4`}
            >
              {converting ? 'Converting…' : 'MP4'}
            </Button>
          ) : (
            <a
              href={`/recordings/${encodeURIComponent(base + '.mp4')}`}
              download
              className="inline-flex items-center gap-1 h-6 px-2 text-[11px] rounded font-medium text-success hover:bg-success/10 transition-colors"
              aria-label={`Download MP4 for ${r.name}`}
            >
              <Download size={11} />
              MP4
            </a>
          )}

          <a
            href={`/recordings/${encodeURIComponent(r.name)}`}
            download
            className="inline-flex items-center h-6 px-1.5 rounded text-text-dim hover:text-text-pri hover:bg-elev transition-colors"
            aria-label={`Download ${r.name}`}
          >
            <Download size={11} />
          </a>

          {confirmingDelete ? (
            <span className="flex items-center gap-1 text-[11px]">
              <span className="text-text-dim">Delete?</span>
              <button
                type="button"
                className="px-1.5 py-0.5 rounded bg-danger/20 text-danger text-[10px] font-medium hover:bg-danger/30 transition-colors"
                onClick={() => {
                  setConfirmingDelete(false);
                  onDelete(r.name);
                }}
              >
                Yes
              </button>
              <button
                type="button"
                className="px-1.5 py-0.5 rounded bg-elev text-text-dim text-[10px] font-medium hover:text-text-pri transition-colors"
                onClick={() => setConfirmingDelete(false)}
              >
                No
              </button>
            </span>
          ) : (
            <Button
              variant="ghost"
              size="xs"
              icon={<Trash2 size={11} />}
              onClick={() => setConfirmingDelete(true)}
              className="text-danger hover:bg-danger/10"
              aria-label={`Delete ${r.name}`}
            />
          )}
        </div>
      </td>
    </tr>
  );
}
