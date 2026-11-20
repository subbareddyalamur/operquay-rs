import { useCallback, useEffect, useRef, useState } from 'react';
import { FastForward, Pause, Play, Rewind, RotateCcw } from 'lucide-react';
import { Button } from '@/rust-engines/design-system/primitives';
import { createTerminalAdapter, type TerminalAdapter } from '@/lib/terminal-engine';
import { useSettingsStore } from '@/stores/settings';

export interface CastEvent {
  tsMs: number;
  data: string;
}

export function parseAsciicast(raw: string): { events: CastEvent[]; totalMs: number } {
  const lines = raw.split('\n');
  const events: CastEvent[] = [];
  let lastMs = 0;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const parsed = JSON.parse(trimmed) as unknown;
      if (!Array.isArray(parsed) || parsed.length < 3) continue;
      const [sec, kind, data] = parsed;
      if (kind !== 'o' || typeof sec !== 'number' || typeof data !== 'string') continue;
      const tsMs = Math.max(lastMs, Math.round(sec * 1000));
      lastMs = tsMs;
      events.push({ tsMs, data });
    } catch {
      // Ignore header or malformed JSON lines cleanly
    }
  }

  return { events, totalMs: lastMs };
}

function formatDurationMs(ms: number): string {
  const totalSec = Math.max(0, Math.floor(ms / 1000));
  const mins = Math.floor(totalSec / 60);
  const secs = totalSec % 60;
  return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

export function CastRecordingPlayer({ src }: { src: string }) {
  const termHostRef = useRef<HTMLDivElement>(null);
  const adapterRef = useRef<TerminalAdapter | null>(null);
  const readyRef = useRef(false);
  const cursorIdxRef = useRef(0);
  const appliedMsRef = useRef(0);

  const fontFamily = useSettingsStore((s) => s.fontFamily);
  const fontSize = useSettingsStore((s) => s.fontSize);

  const [events, setEvents] = useState<CastEvent[]>([]);
  const [totalMs, setTotalMs] = useState(0);
  const [currentMs, setCurrentMs] = useState(0);
  const [playing, setPlaying] = useState(true);
  const [speed, setSpeed] = useState<1 | 2 | 4>(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const seekToMs = useCallback(
    (targetMs: number, sourceEvents: CastEvent[] = events) => {
      const clamped = Math.max(0, Math.min(targetMs, totalMs));
      const adapter = adapterRef.current;

      // Compute last event index <= clamped
      let targetIdx = 0;
      while (targetIdx < sourceEvents.length && sourceEvents[targetIdx].tsMs <= clamped) {
        targetIdx += 1;
      }

      if (adapter && readyRef.current) {
        if (targetIdx < cursorIdxRef.current) {
          // Backward seek: full RIS + scrollback clear + cursor home, then batch-write up to targetIdx
          adapter.write('\x1bc\x1b[3J\x1b[H');
          const chunks: string[] = [];
          for (let i = 0; i < targetIdx; i++) {
            chunks.push(sourceEvents[i].data);
          }
          if (chunks.length > 0) {
            adapter.write(chunks.join(''));
          }
        } else if (targetIdx > cursorIdxRef.current) {
          const chunks: string[] = [];
          for (let i = cursorIdxRef.current; i < targetIdx; i++) {
            chunks.push(sourceEvents[i].data);
          }
          if (chunks.length > 0) {
            adapter.write(chunks.join(''));
          }
        }
        cursorIdxRef.current = targetIdx;
      }

      appliedMsRef.current = clamped;
      setCurrentMs(clamped);
    },
    [events, totalMs],
  );

  // Mount terminal engine once per src
  useEffect(() => {
    const host = termHostRef.current;
    if (!host) return;
    let disposed = false;
    readyRef.current = false;
    cursorIdxRef.current = 0;
    appliedMsRef.current = 0;

    const adapter = createTerminalAdapter({
      engine: 'wasm',
      container: host,
      fontFamily: fontFamily || 'JetBrains Mono',
      fontSize: fontSize || 13,
      scrollbackLines: 10000,
      onData: () => undefined,
      onResize: () => undefined,
    });
    adapterRef.current = adapter;

    void adapter.init().then(() => {
      if (disposed) {
        adapter.dispose();
        return;
      }
      readyRef.current = true;
    });

    return () => {
      disposed = true;
      readyRef.current = false;
      adapterRef.current = null;
      adapter.dispose();
    };
  }, [src, fontFamily, fontSize]);

  // Fetch & parse asciicast stream
  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setEvents([]);
    setTotalMs(0);
    setCurrentMs(0);
    setPlaying(true);
    cursorIdxRef.current = 0;
    appliedMsRef.current = 0;

    void fetch(src, { credentials: 'include' })
      .then(async (res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return res.text();
      })
      .then((text) => {
        if (cancelled) return;
        const parsed = parseAsciicast(text);
        setEvents(parsed.events);
        setTotalMs(parsed.totalMs);
        setLoading(false);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'Failed to load recording');
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [src]);

  // Flush events once both terminal driver and events are ready
  useEffect(() => {
    if (loading || !readyRef.current || events.length === 0) return;
    if (cursorIdxRef.current === 0 && appliedMsRef.current === 0) {
      // Emit tsMs === 0 banner/initial frames right away
      seekToMs(0, events);
    }
  }, [loading, events, seekToMs]);

  // Playback timer loop supporting 1x / 2x / 4x speed and smooth seeking
  useEffect(() => {
    if (!playing || loading || events.length === 0) return;
    if (currentMs >= totalMs) {
      seekToMs(totalMs, events);
      setPlaying(false);
      return;
    }

    const nextEvt = events[cursorIdxRef.current];
    if (!nextEvt) {
      setCurrentMs(totalMs);
      setPlaying(false);
      return;
    }

    const rawDelta = Math.max(0, nextEvt.tsMs - currentMs);
    // Compress extreme idle pauses (>1.5s) only for wait duration? Keep exact timeline progress or tick every 100ms!
    // Ticking by min(50ms, remaining) keeps slider smooth while advancing real timeline at speed!
    const stepRealMs = Math.max(16, Math.min(50, rawDelta || 16));
    const timer = window.setTimeout(() => {
      const target = Math.min(totalMs, appliedMsRef.current + stepRealMs * speed);
      seekToMs(target, events);
      if (target >= totalMs) {
        setPlaying(false);
      }
    }, Math.max(8, Math.round(stepRealMs)));

    return () => window.clearTimeout(timer);
  }, [playing, loading, events, currentMs, totalMs, speed, seekToMs]);

  const togglePlay = () => {
    if (events.length === 0) return;
    if (!playing && currentMs >= totalMs) {
      seekToMs(0, events);
      setPlaying(true);
      return;
    }
    setPlaying((p) => !p);
  };

  return (
    <div
      className="h-full w-full flex flex-col bg-surface text-xs min-h-0"
      onKeyDown={(e) => {
        const tag = (e.target as HTMLElement | null)?.tagName;
        if (e.key === ' ' && tag !== 'BUTTON' && tag !== 'INPUT') {
          e.preventDefault();
          togglePlay();
        } else if (e.key === 'ArrowLeft') {
          e.preventDefault();
          seekToMs(appliedMsRef.current - 10_000);
        } else if (e.key === 'ArrowRight') {
          e.preventDefault();
          seekToMs(appliedMsRef.current + 10_000);
        }
      }}
    >
      {error ? (
        <div role="alert" className="p-4 text-danger flex-1">
          Unable to load terminal recording: {error}
        </div>
      ) : (
        <div className="relative flex-1 min-h-0 bg-[var(--term-bg,#0a0e17)]">
          <div ref={termHostRef} className="w-full h-full" />
          {loading && (
            <div className="absolute inset-0 flex items-center justify-center bg-bg/70 text-text-mut">
              Loading terminal recording…
            </div>
          )}
        </div>
      )}

      <div className="flex flex-wrap items-center gap-2 px-4 py-2.5 border-t border-border bg-elev shrink-0">
        <Button
          size="xs"
          variant="outline"
          disabled={loading || Boolean(error)}
          onClick={togglePlay}
          icon={playing ? <Pause size={12} aria-hidden="true" /> : <Play size={12} aria-hidden="true" />}
        >
          {playing ? 'Pause' : 'Play'}
        </Button>
        <Button
          size="xs"
          variant="outline"
          disabled={loading || Boolean(error)}
          aria-label="Rewind 10 seconds"
          onClick={() => seekToMs(appliedMsRef.current - 10_000)}
          icon={<Rewind size={12} aria-hidden="true" />}
        >
          -10s
        </Button>
        <Button
          size="xs"
          variant="outline"
          disabled={loading || Boolean(error)}
          aria-label="Forward 10 seconds"
          onClick={() => seekToMs(appliedMsRef.current + 10_000)}
          icon={<FastForward size={12} aria-hidden="true" />}
        >
          +10s
        </Button>
        <Button
          size="xs"
          variant="outline"
          disabled={loading || Boolean(error)}
          aria-label="Restart playback"
          onClick={() => {
            seekToMs(0);
            setPlaying(true);
          }}
          icon={<RotateCcw size={12} aria-hidden="true" />}
        >
          Restart
        </Button>

        <div className="flex items-center gap-1" role="group" aria-label="Playback speed">
          {([1, 2, 4] as const).map((s) => (
            <Button
              key={s}
              size="xs"
              variant={speed === s ? 'primary' : 'outline'}
              onClick={() => setSpeed(s)}
            >
              {s}x
            </Button>
          ))}
        </div>

        <input
          aria-label="Seek terminal recording timeline"
          type="range"
          min={0}
          max={Math.max(1, totalMs)}
          value={Math.min(currentMs, Math.max(1, totalMs))}
          disabled={loading || Boolean(error)}
          onChange={(e) => {
            setPlaying(false);
            seekToMs(Number(e.target.value));
          }}
          className="flex-1 min-w-[120px]"
        />

        <span className="text-text-dim tabular-mono shrink-0">
          {formatDurationMs(currentMs)} / {formatDurationMs(totalMs)}
        </span>
      </div>
    </div>
  );
}
