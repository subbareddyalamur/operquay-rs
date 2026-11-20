import { useEffect, useRef, useState } from 'react';
import { Pause, Play, RotateCcw, X } from 'lucide-react';
import { Badge, Button, Card } from '@/design-system/primitives';

interface GuacOp {
  opcode: string;
  args: string[];
  tsMs: number;
}

function parseGuacStream(raw: string): GuacOp[] {
  const ops: GuacOp[] = [];
  let i = 0;
  let ts = 0;
  let args: string[] = [];

  while (i < raw.length) {
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
      if (opcode === 'sync' && args[1]) {
        ts = Number(args[1]) || ts;
      }
      ops.push({ opcode, args: args.slice(1), tsMs: ts });
      args = [];
    }
  }
  return ops;
}

export function GuacRecordingPlayer({
  recordingId,
  onClose,
}: {
  recordingId: string;
  onClose: () => void;
}) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [ops, setOps] = useState<GuacOp[]>([]);
  const [cursorIdx, setCursorIdx] = useState(0);
  const [playing, setPlaying] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setError(null);
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
    if (!playing || ops.length === 0 || cursorIdx >= ops.length) return;
    const timer = window.setInterval(() => {
      setCursorIdx((idx) => Math.min(ops.length, idx + 4));
    }, 33);
    return () => window.clearInterval(timer);
  }, [playing, ops.length, cursorIdx]);

  useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext('2d');
    if (!canvas || !ctx || ops.length === 0) return;

    const styles = getComputedStyle(document.documentElement);
    ctx.fillStyle = styles.getPropertyValue('--canvas-bg').trim() || 'Canvas';
    ctx.fillRect(0, 0, canvas.width, canvas.height);

    const upto = ops.slice(0, cursorIdx);
    for (const op of upto) {
      if (op.opcode === 'size') {
        const w = Math.max(64, Math.min(2560, Number(op.args[1]) || 960));
        const h = Math.max(64, Math.min(1600, Number(op.args[2]) || 600));
        if (canvas.width !== w || canvas.height !== h) {
          canvas.width = w;
          canvas.height = h;
        }
      } else if (op.opcode === 'rect' || op.opcode === 'cfill') {
        if (op.opcode === 'rect') {
          ctx.beginPath();
          ctx.rect(Number(op.args[1]) || 0, Number(op.args[2]) || 0, Number(op.args[3]) || 0, Number(op.args[4]) || 0);
        } else {
          const r = Number(op.args[2]) || 0;
          const g = Number(op.args[3]) || 0;
          const b = Number(op.args[4]) || 0;
          const a = (op.args[5] !== undefined ? Number(op.args[5]) : 255) / 255;
          ctx.fillStyle = ['rgba(', r, ',', g, ',', b, ',', a, ')'].join('');
          ctx.fill();
        }
      } else if (op.opcode === 'copy') {
        const sx = Number(op.args[1]) || 0;
        const sy = Number(op.args[2]) || 0;
        const w = Number(op.args[3]) || 0;
        const h = Number(op.args[4]) || 0;
        const dx = Number(op.args[6]) || 0;
        const dy = Number(op.args[7]) || 0;
        if (w > 0 && h > 0) {
          ctx.drawImage(canvas, sx, sy, w, h, dx, dy, w, h);
        }
      }
    }
  }, [ops, cursorIdx]);

  return (
    <Card className="p-4 space-y-3 text-xs">
      <div className="flex items-center justify-between border-b border-border pb-2">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-text-pri">Guacamole Session Replay</span>
          <Badge tone="accent">{recordingId.slice(0, 8)}...</Badge>
          <span className="text-text-dim tabular-mono">{cursorIdx} / {ops.length} instructions</span>
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
            <canvas ref={canvasRef} width={960} height={600} className="max-w-full max-h-[420px] rounded-[var(--radius-sm)]" />
          </div>
          <div className="flex items-center gap-3">
            <Button size="xs" variant="outline" onClick={() => setPlaying((p) => !p)} icon={playing ? <Pause size={12} aria-hidden="true" /> : <Play size={12} aria-hidden="true" />}>
              {playing ? 'Pause' : 'Play'}
            </Button>
            <Button size="xs" variant="outline" onClick={() => { setCursorIdx(0); setPlaying(true); }} icon={<RotateCcw size={12} aria-hidden="true" />}>
              Restart
            </Button>
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
              className="flex-1"
            />
          </div>
        </>
      )}
    </Card>
  );
}
