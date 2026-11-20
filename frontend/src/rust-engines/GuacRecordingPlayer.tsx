import { useEffect, useMemo, useRef, useState } from 'react';
import { Pause, Play, RotateCcw, X } from 'lucide-react';
import { Badge, Button, Card } from '@/rust-engines/design-system/primitives';

export interface GuacOp {
  opcode: string;
  args: string[];
  tsMs: number;
}

export interface DecodedGuacImage {
  mime: string;
  x: number;
  y: number;
  dataUrl: string;
}

export function parseGuacStream(raw: string): GuacOp[] {
  const ops: GuacOp[] = [];
  let i = 0;
  let ts = 0;
  let firstTs: number | null = null;
  let args: string[] = [];

  while (i < raw.length) {
    while (i < raw.length && (raw[i] === '\n' || raw[i] === '\r' || raw[i] === ' ')) {
      i++;
    }
    if (i >= raw.length) break;
    const dot = raw.indexOf('.', i);
    if (dot < 0) break;
    const len = Number(raw.slice(i, dot));
    if (!Number.isFinite(len) || len < 0) break;
    const start = dot + 1;
    const val = raw.slice(start, start + len);
    i = start + len;
    const delim = raw[i];
    args.push(val);
    i += 1;
    if (delim === ';') {
      const opcode = args[0] ?? '';
      const rawArgs = args.slice(1);
      if (opcode === 'sync' && rawArgs[0]) {
        const parsedTs = Number(rawArgs[0]);
        if (Number.isFinite(parsedTs)) {
          if (firstTs === null) firstTs = parsedTs;
          ts = Math.max(0, parsedTs - firstTs);
        }
      }
      ops.push({ opcode, args: rawArgs, tsMs: ts });
      args = [];
    }
  }
  return ops;
}

function buildDecodedImagesMap(ops: GuacOp[]): Map<number, DecodedGuacImage> {
  const streams = new Map<string, { mime: string; x: number; y: number; chunks: string[] }>();
  const resolved = new Map<number, DecodedGuacImage>();
  for (let idx = 0; idx < ops.length; idx++) {
    const op = ops[idx];
    if (op.opcode === 'img') {
      // Guac img: stream, mask, layer, mimetype, x, y
      const streamId = op.args[0] ?? '0';
      const mime = op.args[3] || 'image/png';
      const x = Number(op.args[4]) || 0;
      const y = Number(op.args[5]) || 0;
      streams.set(streamId, { mime, x, y, chunks: [] });
    } else if (op.opcode === 'blob') {
      const streamId = op.args[0] ?? '0';
      const st = streams.get(streamId);
      if (st && op.args[1]) {
        st.chunks.push(op.args[1]);
      }
    } else if (op.opcode === 'end') {
      const streamId = op.args[0] ?? '0';
      const st = streams.get(streamId);
      if (st) {
        streams.delete(streamId);
        if (st.chunks.length > 0) {
          resolved.set(idx, {
            mime: st.mime,
            x: st.x,
            y: st.y,
            dataUrl: `data:${st.mime};base64,${st.chunks.join('')}`,
          });
        }
      }
    }
  }
  return resolved;
}

function formatDurationMs(ms: number): string {
  const totalSec = Math.max(0, Math.floor(ms / 1000));
  const mins = Math.floor(totalSec / 60);
  const secs = totalSec % 60;
  return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

export function GuacRecordingPlayer({
  recordingId,
  onClose,
  embedded = false,
}: {
  recordingId: string;
  onClose: () => void;
  embedded?: boolean;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const offscreenRef = useRef<HTMLCanvasElement | null>(null);
  const imageCacheRef = useRef<Map<number, HTMLImageElement>>(new Map());
  const [ops, setOps] = useState<GuacOp[]>([]);
  const [cursorIdx, setCursorIdx] = useState(0);
  const [playing, setPlaying] = useState(true);
  const [speed, setSpeed] = useState<1 | 2 | 4>(1);
  const [error, setError] = useState<string | null>(null);
  const [imageTick, setImageTick] = useState(0);

  const decodedImages = useMemo(() => buildDecodedImagesMap(ops), [ops]);
  const totalMs = ops.length > 0 ? ops[ops.length - 1].tsMs : 0;
  const currentMs = cursorIdx > 0 && ops[cursorIdx - 1] ? ops[cursorIdx - 1].tsMs : 0;

  useEffect(() => {
    let cancelled = false;
    setError(null);
    imageCacheRef.current.clear();
    void fetch(`/api/v1/recordings/${encodeURIComponent(recordingId)}/guac`)
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.text();
      })
      .then((txt) => {
        if (cancelled) return;
        const parsed = parseGuacStream(txt);
        setOps(parsed);
        setCursorIdx(0);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : 'Unable to fetch recording');
      });
    return () => {
      cancelled = true;
    };
  }, [recordingId]);

  useEffect(() => {
    if (decodedImages.size === 0 || typeof Image === 'undefined') return;
    let cancelled = false;
    for (const [idx, info] of decodedImages.entries()) {
      if (imageCacheRef.current.has(idx)) continue;
      const img = new Image();
      img.onload = () => {
        if (!cancelled) setImageTick((t) => t + 1);
      };
      img.src = info.dataUrl;
      imageCacheRef.current.set(idx, img);
    }
    return () => {
      cancelled = true;
    };
  }, [decodedImages]);

  useEffect(() => {
    if (!playing || ops.length === 0 || cursorIdx >= ops.length) {
      if (ops.length > 0 && cursorIdx >= ops.length) setPlaying(false);
      return;
    }
    const baseMs = ops[cursorIdx]?.tsMs ?? 0;
    const nextTs = ops.find((op, idx) => idx > cursorIdx && op.tsMs > baseMs)?.tsMs ?? baseMs + 33;
    const delta = Math.max(16, Math.min(250, Math.round((nextTs - baseMs) / speed)));
    const timer = window.setTimeout(() => {
      setCursorIdx((idx) => {
        let next = idx + 1;
        while (next < ops.length && ops[next].opcode !== 'sync' && next - idx < 24) {
          next++;
        }
        return Math.min(ops.length, next);
      });
    }, delta);
    return () => window.clearTimeout(timer);
  }, [playing, ops, cursorIdx, speed]);

  useEffect(() => {
    const visible = canvasRef.current;
    if (!visible) return;
    const offscreen =
      offscreenRef.current ??
      (() => {
        const c = document.createElement('canvas');
        c.width = visible.width;
        c.height = visible.height;
        offscreenRef.current = c;
        return c;
      })();
    const ctx = offscreen.getContext('2d');
    const vctx = visible.getContext('2d');
    if (!ctx || !vctx) return;

    ctx.fillStyle = '#090d14';
    ctx.fillRect(0, 0, offscreen.width, offscreen.height);

    let pendingRect: { x: number; y: number; w: number; h: number } | null = null;
    const limit = Math.min(cursorIdx, ops.length);

    for (let idx = 0; idx < limit; idx++) {
      const op = ops[idx];
      if (op.opcode === 'size') {
        const w = Math.max(64, Math.min(4096, Number(op.args[1]) || 960));
        const h = Math.max(64, Math.min(4096, Number(op.args[2]) || 600));
        if (offscreen.width !== w || offscreen.height !== h) {
          offscreen.width = w;
          offscreen.height = h;
          ctx.fillStyle = '#090d14';
          ctx.fillRect(0, 0, w, h);
        }
      } else if (op.opcode === 'rect') {
        pendingRect = {
          x: Number(op.args[1]) || 0,
          y: Number(op.args[2]) || 0,
          w: Number(op.args[3]) || 0,
          h: Number(op.args[4]) || 0,
        };
      } else if (op.opcode === 'cfill' && pendingRect) {
        const r = Number(op.args[2]) || 0;
        const g = Number(op.args[3]) || 0;
        const b = Number(op.args[4]) || 0;
        const a = (op.args[5] !== undefined ? Number(op.args[5]) : 255) / 255;
        ctx.fillStyle = `rgba(${r},${g},${b},${a})`;
        ctx.fillRect(pendingRect.x, pendingRect.y, pendingRect.w, pendingRect.h);
        pendingRect = null;
      } else if (op.opcode === 'copy') {
        const sx = Number(op.args[1]) || 0;
        const sy = Number(op.args[2]) || 0;
        const w = Number(op.args[3]) || 0;
        const h = Number(op.args[4]) || 0;
        const dx = Number(op.args[7]) || 0;
        const dy = Number(op.args[8]) || 0;
        if (w > 0 && h > 0) {
          ctx.drawImage(offscreen, sx, sy, w, h, dx, dy, w, h);
        }
      } else if (op.opcode === 'end') {
        const meta = decodedImages.get(idx);
        const img = imageCacheRef.current.get(idx);
        if (meta && img && img.complete) {
          ctx.drawImage(img, meta.x, meta.y);
        }
      }
    }

    if (visible.width !== offscreen.width || visible.height !== offscreen.height) {
      visible.width = offscreen.width;
      visible.height = offscreen.height;
    }
    vctx.clearRect(0, 0, visible.width, visible.height);
    vctx.drawImage(offscreen, 0, 0);
  }, [ops, cursorIdx, decodedImages, imageTick]);

  const controls = (
    <div className={embedded ? 'flex flex-wrap items-center gap-2.5 px-4 py-2.5 border-t border-border bg-elev shrink-0' : 'flex items-center gap-2.5'}>
      <Button
        size="xs"
        variant="outline"
        onClick={() => {
          if (cursorIdx >= ops.length) setCursorIdx(0);
          setPlaying((p) => !p);
        }}
        icon={playing ? <Pause size={12} aria-hidden="true" /> : <Play size={12} aria-hidden="true" />}
      >
        {playing ? 'Pause' : 'Play'}
      </Button>
      <Button
        size="xs"
        variant="outline"
        onClick={() => {
          setCursorIdx(0);
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
        aria-label="Seek recording timeline"
        type="range"
        min={0}
        max={Math.max(1, ops.length)}
        value={cursorIdx}
        onChange={(e) => {
          setPlaying(false);
          setCursorIdx(Number(e.target.value));
        }}
        className="flex-1 min-w-[120px]"
      />
      {embedded && (
        <span className="text-text-dim tabular-mono shrink-0">
          {formatDurationMs(currentMs)} / {formatDurationMs(totalMs)}
        </span>
      )}
    </div>
  );

  if (embedded) {
    return (
      <div className="h-full w-full flex flex-col bg-surface text-xs min-h-0">
        {error ? (
          <div role="alert" className="p-4 text-danger">{error}</div>
        ) : (
          <>
            <div className="flex-1 min-h-0 bg-[var(--canvas-bg)] p-2 flex items-center justify-center overflow-hidden">
              <canvas ref={canvasRef} width={960} height={600} className="max-w-full max-h-full w-auto h-auto object-contain rounded-[var(--radius-sm)]" />
            </div>
            {controls}
          </>
        )}
      </div>
    );
  }

  return (
    <Card className="p-4 space-y-3 text-xs">
      <div className="flex items-center justify-between border-b border-border pb-2">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-text-pri">Guacamole Session Replay</span>
          <Badge tone="accent">{recordingId.slice(0, 8)}...</Badge>
          <span className="text-text-dim tabular-mono">
            {formatDurationMs(currentMs)} / {formatDurationMs(totalMs)} ({cursorIdx} / {ops.length} ops)
          </span>
        </div>
        <Button size="xs" variant="ghost" aria-label="Close player" onClick={onClose}>
          <X size={14} aria-hidden="true" />
        </Button>
      </div>

      {error ? (
        <div role="alert" className="text-danger">{error}</div>
      ) : (
        <>
          <div className="rounded-[var(--radius-md)] border border-border bg-[var(--canvas-bg)] p-2 flex justify-center overflow-hidden">
            <canvas ref={canvasRef} width={960} height={600} className="max-w-full max-h-[520px] rounded-[var(--radius-sm)]" />
          </div>
          {controls}
        </>
      )}
    </Card>
  );
}
