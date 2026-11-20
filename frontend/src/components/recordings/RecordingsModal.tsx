import { useState, useEffect, useCallback } from 'react';
import { createPortal } from 'react-dom';
import { X, Maximize2, Minimize2, Sparkles, ShieldAlert } from 'lucide-react';
import { Badge, Button, Dialog } from '@/components/primitives';
import { api } from '@/lib/api';
import { RecordingsList } from './RecordingsList';
import { GuacPlayer } from './GuacPlayer';
import { CastRecordingPlayer } from './CastRecordingPlayer';
import type { Recording } from './RecordingRow';

interface RecordingRiskBookmark {
  id: string;
  offset_secs: number;
  severity: string;
  category: string;
  title: string;
  detail: string;
  source: string;
}

type PlayerSize = 'normal' | 'max';

interface RecordingsModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function RecordingsModal({ open, onOpenChange }: RecordingsModalProps) {
  const [playing, setPlaying] = useState<Recording | null>(null);
  const [playerSize, setPlayerSize] = useState<PlayerSize>('normal');
  const [bookmarksOpen, setBookmarksOpen] = useState(false);
  const [bookmarks, setBookmarks] = useState<RecordingRiskBookmark[]>([]);
  const [riskSummary, setRiskSummary] = useState<string>('');
  const [riskScore, setRiskScore] = useState<number | null>(null);
  const [analyzing, setAnalyzing] = useState(false);

  const recLookupId = playing ? playing.name.replace(/\.(cast|guac|mp4)$/, '') : '';

  const loadBookmarks = useCallback(async (id: string) => {
    if (!id) return;
    const res = await api.get<{ bookmarks: RecordingRiskBookmark[] }>(`/api/recordings/${encodeURIComponent(id)}/bookmarks`);
    if (res.ok) setBookmarks(res.data.bookmarks);
  }, []);

  useEffect(() => {
    if (!playing || !recLookupId) return;
    void loadBookmarks(recLookupId);
  }, [playing, recLookupId, loadBookmarks]);

  const handleAnalyzeRisk = async () => {
    if (!recLookupId) return;
    setAnalyzing(true);
    setBookmarksOpen(true);
    const res = await api.post<{ risk_score: number; summary: string; bookmarks: RecordingRiskBookmark[] }>(
      `/api/recordings/${encodeURIComponent(recLookupId)}/analyze`,
      {},
    );
    setAnalyzing(false);
    if (res.ok) {
      setRiskScore(res.data.risk_score);
      setRiskSummary(res.data.summary);
      setBookmarks(res.data.bookmarks);
    }
  };

  const closePlayer = () => {
    setPlaying(null);
    setPlayerSize('normal');
    setBookmarksOpen(false);
    setBookmarks([]);
    setRiskSummary('');
    setRiskScore(null);
  };

  useEffect(() => {
    if (!playing) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        closePlayer();
      } else if (
        (e.key === 'f' || e.key === 'F') &&
        !e.metaKey &&
        !e.ctrlKey &&
        !e.altKey &&
        (e.target as HTMLElement | null)?.tagName !== 'INPUT'
      ) {
        e.preventDefault();
        setPlayerSize((s) => (s === 'max' ? 'normal' : 'max'));
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [playing]);

  const toggleMaximize = () => {
    setPlayerSize((s) => (s === 'max' ? 'normal' : 'max'));
  };

  const handleOpenChange = (o: boolean) => {
    if (!o) closePlayer();
    onOpenChange(o);
  };

  // Derive player content type
  const isGuac = playing?.type === 'rdp' && !playing?.has_mp4 && playing?.name.endsWith('.guac');
  const isMp4 = playing?.has_mp4;
  const isAsc = (playing?.type === 'ssh' || playing?.type === 'k8s') && !playing?.has_mp4;

  const playerTitle = playing
    ? playing.name.length > 60
      ? '…' + playing.name.slice(-57)
      : playing.name
    : '';

  return (
    <>
      <Dialog
        open={open}
        onOpenChange={handleOpenChange}
        title="Recordings"
        description="Encrypted SSH asciinema streams and RDP Guacamole video vault."
        size="2xl"
      >
        <RecordingsList onPlay={(r) => setPlaying(r)} />
      </Dialog>

      {/* Portal the player to document.body so it escapes Dialog stacking context */}
      {playing && createPortal(
        <div
          className={`fixed inset-0 z-[9500] flex items-center justify-center bg-[var(--overlay)] ${
            playerSize === 'max' ? 'p-0' : 'p-4'
          }`}
          onClick={(e) => { if (e.target === e.currentTarget) closePlayer(); }}
          role="dialog"
          aria-modal="true"
          aria-label="Recording Player"
        >
          <div
            className={`bg-surface border border-border shadow-2xl flex flex-col overflow-hidden ${
              playerSize === 'max'
                ? 'w-screen h-screen max-w-none rounded-none'
                : 'rounded-xl'
            }`}
            style={
              playerSize === 'max'
                ? undefined
                : { width: '92vw', height: '88vh', maxWidth: 'none' }
            }
          >
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-elev shrink-0">
              <span className="text-[12px] font-mono text-text-pri truncate flex-1 mr-4">{playerTitle}</span>
              <div className="flex items-center gap-2 shrink-0">
                {isAsc && (
                  <>
                    <Button
                      size="xs"
                      variant={bookmarksOpen ? 'primary' : 'secondary'}
                      icon={<ShieldAlert size={12} />}
                      onClick={() => setBookmarksOpen((o) => !o)}
                    >
                      Risk Bookmarks ({bookmarks.length})
                    </Button>
                    <Button
                      size="xs"
                      variant="secondary"
                      loading={analyzing}
                      icon={<Sparkles size={12} />}
                      onClick={() => void handleAnalyzeRisk()}
                    >
                      Analyze Risk
                    </Button>
                  </>
                )}
                <button
                  type="button"
                  onClick={toggleMaximize}
                  className="text-text-dim hover:text-text-pri transition-colors p-1 rounded hover:bg-surface-hover"
                  aria-label={playerSize === 'max' ? 'Restore player' : 'Maximize player'}
                  title={playerSize === 'max' ? 'Restore window (F)' : 'Maximize window (F)'}
                >
                  {playerSize === 'max' ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
                </button>
                <button
                  type="button"
                  onClick={closePlayer}
                  className="text-text-dim hover:text-text-pri transition-colors p-1 rounded hover:bg-surface-hover"
                  aria-label="Close player"
                >
                  <X size={14} />
                </button>
              </div>
            </div>

            {/* Player body — fills remaining space */}
            <div className="flex-1 overflow-hidden min-h-0 flex">
              <div className="flex-1 min-w-0 h-full overflow-hidden">
                {isMp4 ? (
                  <video
                    controls
                    autoPlay
                    className="w-full h-full bg-black object-contain"
                    src={`/recordings/${encodeURIComponent(playing.name.replace(/\.[^.]+$/, '.mp4'))}`}
                  />
                ) : isGuac ? (
                  <GuacPlayer filename={playing.name} embedded />
                ) : isAsc ? (
                  <CastRecordingPlayer src={`/recordings/${encodeURIComponent(playing.name)}`} />
                ) : (
                  <div className="p-6 text-center text-[12px] text-text-dim">
                    No player available. Convert to MP4 first.
                  </div>
                )}
              </div>
              {isAsc && bookmarksOpen && (
                <aside className="w-80 shrink-0 border-l border-border bg-surface overflow-y-auto p-3 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-text-pri">AI Risk Bookmarks</span>
                    {riskScore !== null && (
                      <Badge variant={riskScore >= 70 ? 'danger' : riskScore >= 40 ? 'warn' : 'info'}>
                        Score {riskScore}
                      </Badge>
                    )}
                  </div>
                  {riskSummary && <p className="text-[11px] text-text-sec">{riskSummary}</p>}
                  {bookmarks.length === 0 ? (
                    <p className="text-[11px] text-text-dim">No risk findings yet. Click Analyze Risk to scan (PII-sanitized).</p>
                  ) : (
                    <div className="space-y-2">
                      {bookmarks.map((bm) => (
                        <div key={bm.id} className="p-2.5 rounded border border-border bg-bg space-y-1">
                          <div className="flex items-center justify-between gap-2 text-[11px]">
                            <Badge variant={bm.severity === 'critical' || bm.severity === 'high' ? 'danger' : 'warn'}>
                              {bm.severity.toUpperCase()}
                            </Badge>
                            <span className="font-mono text-text-dim">{bm.offset_secs.toFixed(1)}s</span>
                          </div>
                          <div className="text-xs font-medium text-text-pri">{bm.title}</div>
                          <div className="text-[11px] text-text-dim break-words">{bm.detail}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </aside>
              )}
            </div>
          </div>
        </div>,
        document.body,
      )}
    </>
  );
}
