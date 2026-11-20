import { useEffect, useRef, useState } from 'react';
import { Activity, ArrowLeft, Maximize2, ShieldAlert } from 'lucide-react';
import { Badge, Button, Card } from '@/design-system/primitives';
import { decodeOqr2Frame } from './oqr2Decoder';

export interface DesktopStats {
  connected: boolean;
  width: number;
  height: number;
  fps: number;
  lagMs: number;
  jpegQuality: number;
  droppedFrames: number;
  codecTag: string;
  traceId: string;
  cursorPrediction: boolean;
  frameCount: number;
}

export function DesktopStage({
  protocol,
  targetHost = 'win2025-ssm.internal',
  wsUrl,
  layout = 'en-us-qwerty',
  showHud = true,
  onBackToSettings,
}: {
  protocol: 'rdp' | 'vnc';
  targetHost?: string;
  wsUrl?: string;
  layout?: string;
  showHud?: boolean;
  onBackToSettings: () => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const [cursorStyle, setCursorStyle] = useState<string>('default');
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [remoteClipboard, setRemoteClipboard] = useState<string>('');
  const [stats, setStats] = useState<DesktopStats>({
    connected: false,
    width: 960,
    height: 600,
    fps: 30,
    lagMs: 0,
    jpegQuality: 90,
    droppedFrames: 0,
    codecTag: `${protocol}:connecting`,
    traceId: 'pending',
    cursorPrediction: true,
    frameCount: 0,
  });

  useEffect(() => {
    let closed = false;
    setSessionError(null);
    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const width = Math.max(200, Math.min(1600, (containerRef.current?.clientWidth || 960) & ~1));
    const height = Math.max(200, Math.min(1000, containerRef.current?.clientHeight || 600));

    let fullWsUrl: string;
    if (wsUrl) {
      fullWsUrl = `${wsProto}//${window.location.host}${wsUrl}`;
    } else {
      const params = new URLSearchParams({
        protocol,
        mode: 'oqr2',
        width: String(width),
        height: String(height),
        target: targetHost,
        layout,
      });
      fullWsUrl = `${wsProto}//${window.location.host}/api/v1/ws/rdp?${params.toString()}`;
    }
    const ws = new WebSocket(fullWsUrl);
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;

    ws.onmessage = async (ev) => {
      if (closed) return;
      if (typeof ev.data === 'string') {
        try {
          const parsed = JSON.parse(ev.data) as { type?: string; error?: string };
          if (parsed.type === 'error' || parsed.error) {
            setSessionError(parsed.error ?? 'Session terminated by server policy');
            setStats((prev) => ({ ...prev, connected: false }));
          }
        } catch {
          // Ignore non-JSON control text
        }
        return;
      }
      if (!(ev.data instanceof ArrayBuffer)) return;
      const msg = decodeOqr2Frame(ev.data);
      const canvas = canvasRef.current;
      const ctx = canvas?.getContext('2d');

      switch (msg.type) {
        case 'hello_ack':
          if (canvas) {
            canvas.width = msg.width;
            canvas.height = msg.height;
          }
          setStats((prev) => ({
            ...prev,
            connected: true,
            width: msg.width,
            height: msg.height,
            traceId: msg.traceId,
            cursorPrediction: msg.cursorPrediction,
          }));
          break;

        case 'resize_surface':
          if (canvas) {
            canvas.width = msg.w;
            canvas.height = msg.h;
          }
          setStats((prev) => ({ ...prev, width: msg.w, height: msg.h }));
          break;

        case 'solid_fill':
          if (ctx) {
            const [r, g, b, a] = msg.rgba;
            ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${a / 255})`;
            ctx.fillRect(msg.x, msg.y, msg.w, msg.h);
          }
          break;

        case 'copy_rect':
          if (ctx) {
            const imgData = ctx.getImageData(msg.sx, msg.sy, msg.w, msg.h);
            ctx.putImageData(imgData, msg.dx, msg.dy);
          }
          break;

        case 'tile_png':
        case 'tile_jpeg':
          if (ctx) {
            const mime = msg.type === 'tile_png' ? 'image/png' : 'image/jpeg';
            const blobBytes = new Uint8Array(msg.bytes);
            const blob = new Blob([blobBytes], { type: mime });
            if (typeof createImageBitmap === 'function') {
              const bmp = await createImageBitmap(blob);
              ctx.drawImage(bmp, msg.x, msg.y);
              bmp.close();
            }
          }
          break;

        case 'cursor_shape': {
          // Render remote cursor sprite into a crisp CSS custom cursor for zero-RTT pointer feel
          const tmp = document.createElement('canvas');
          tmp.width = msg.w;
          tmp.height = msg.h;
          const tctx = tmp.getContext('2d');
          if (tctx) {
            const clamped = new Uint8ClampedArray(msg.rgba);
            tctx.putImageData(new ImageData(clamped, msg.w, msg.h), 0, 0);
            setCursorStyle(`url(${tmp.toDataURL()}) ${msg.hotX} ${msg.hotY}, default`);
          }
          break;
        }

        case 'stats_sync':
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'sync_ack', server_ts_ms: msg.serverTsMs }));
          }
          setStats((prev) => ({
            ...prev,
            lagMs: msg.lagMs,
            fps: msg.fps,
            jpegQuality: msg.jpegQuality,
            droppedFrames: msg.droppedFrames,
            codecTag: msg.codecTag,
            frameCount: prev.frameCount + 1,
          }));
          break;

        case 'h264_frame': {
          // Hardware WebCodecs VideoDecoder pass-through when browser supports AVC Annex-B
          const VDec = (window as unknown as {
            VideoDecoder?: new (init: {
              output: (frame: { close: () => void } & CanvasImageSource) => void;
              error: (err: unknown) => void;
            }) => {
              configure: (cfg: { codec: string; hardwareAcceleration?: string }) => void;
              decode: (chunk: unknown) => void;
              flush: () => Promise<void>;
              close: () => void;
            };
            EncodedVideoChunk?: new (init: { type: 'key' | 'delta'; timestamp: number; data: Uint8Array }) => unknown;
          }).VideoDecoder;
          const VChunk = (window as unknown as {
            EncodedVideoChunk?: new (init: { type: 'key' | 'delta'; timestamp: number; data: Uint8Array }) => unknown;
          }).EncodedVideoChunk;
          if (ctx && VDec && VChunk && msg.annexB.length > 4) {
            try {
              const dec = new VDec({
                output: (frame) => {
                  ctx.drawImage(frame, msg.x, msg.y, msg.w, msg.h);
                  frame.close();
                },
                error: () => {
                  // Hardware codec rejected non-standard NALU; ignored safely
                },
              });
              dec.configure({ codec: 'avc1.42E01F', hardwareAcceleration: 'prefer-hardware' });
              const isIdr = msg.annexB.some((b, i) => i >= 4 && msg.annexB[i - 1] === 1 && (b & 0x1f) === 5);
              dec.decode(
                new VChunk({
                  type: isIdr ? 'key' : 'delta',
                  timestamp: performance.now() * 1000,
                  data: msg.annexB,
                }),
              );
              void dec.flush().finally(() => dec.close());
            } catch {
              // WebCodecs unsupported in software CI environment
            }
          }
          break;
        }

        case 'clipboard_text':
          setRemoteClipboard(msg.text);
          if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
            void navigator.clipboard.writeText(msg.text).catch(() => {});
          }
          break;
      }
    };

    ws.onclose = () => {
      if (!closed) {
        setStats((prev) => ({ ...prev, connected: false }));
      }
    };

    return () => {
      closed = true;
      ws.close();
      wsRef.current = null;
    };
  }, [protocol, targetHost, wsUrl, layout]);

  // Debounced dynamic resize (MS-RDPEDISP)
  const triggerManualResize = (w: number, h: number) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'resize', width: w, height: h }));
    }
  };

  const sendCtrlAltDel = () => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'sas' }));
    }
  };

  const sendClipboard = (text: string) => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN && text) {
      ws.send(JSON.stringify({ type: 'clipboard', text }));
    }
  };

  const forwardMouse = (e: React.MouseEvent<HTMLCanvasElement>, buttonMask: number) => {
    const canvas = canvasRef.current;
    const ws = wsRef.current;
    if (!canvas || !ws || ws.readyState !== WebSocket.OPEN) return;
    const rect = canvas.getBoundingClientRect();
    const x = Math.max(0, Math.round(((e.clientX - rect.left) * canvas.width) / Math.max(1, rect.width)));
    const y = Math.max(0, Math.round(((e.clientY - rect.top) * canvas.height) / Math.max(1, rect.height)));
    ws.send(JSON.stringify({ type: 'pointer', x, y, button_mask: buttonMask }));
  };

  const domButtonsToMask = (buttons: number): number => {
    let m = 0;
    if (buttons & 1) m |= 1; // Left
    if (buttons & 4) m |= 2; // Middle
    if (buttons & 2) m |= 4; // Right
    return m;
  };

  const forwardKey = (e: React.KeyboardEvent<HTMLCanvasElement>, pressed: boolean) => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    const specialMap: Record<string, number> = {
      Backspace: 0xff08,
      Tab: 0xff09,
      Enter: 0xff0d,
      Escape: 0xff1b,
      Delete: 0xffff,
      Home: 0xff50,
      ArrowLeft: 0xff51,
      ArrowUp: 0xff52,
      ArrowRight: 0xff53,
      ArrowDown: 0xff54,
      PageUp: 0xff55,
      PageDown: 0xff56,
      End: 0xff57,
      Insert: 0xff63,
      Shift: 0xffe1,
      Control: 0xffe3,
      Alt: 0xffe9,
      Meta: 0xffeb,
      F1: 0xffbe,
      F2: 0xffbf,
      F3: 0xffc0,
      F4: 0xffc1,
      F5: 0xffc2,
      F6: 0xffc3,
      F7: 0xffc4,
      F8: 0xffc5,
      F9: 0xffc6,
      F10: 0xffc7,
      F11: 0xffc8,
      F12: 0xffc9,
    };
    const keysym = specialMap[e.key] ?? (e.key.length === 1 ? e.key.codePointAt(0) ?? 0 : 0);
    if (keysym > 0) {
      e.preventDefault();
      ws.send(JSON.stringify({ type: 'key', keysym, pressed }));
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-6 py-5 space-y-4">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-border">
        <div className="flex items-center gap-3">
          <Button variant="outline" size="sm" onClick={onBackToSettings} icon={<ArrowLeft size={14} aria-hidden="true" />}>
            Back to Settings
          </Button>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-[16px] font-semibold text-text-pri uppercase tracking-wide">
                {protocol} Session · {targetHost}
              </h1>
              <Badge tone={stats.connected ? 'success' : 'warn'}>
                {stats.connected ? 'Connected (OQR2)' : 'Connecting...'}
              </Badge>
            </div>
            <p className="text-xs text-text-dim tabular-mono">
              {stats.width}x{stats.height} · Layout {layout}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => triggerManualResize(1281, 720)}
            icon={<Maximize2 size={14} aria-hidden="true" />}
          >
            Test Resize (1281-&gt;1280)
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={sendCtrlAltDel}
            icon={<ShieldAlert size={14} aria-hidden="true" />}
          >
            Ctrl+Alt+Del
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              const txt = remoteClipboard || 'operquay-clipboard-sync';
              sendClipboard(txt);
            }}
          >
            Sync Clipboard
          </Button>
        </div>
      </div>

      {/* Session Policy / Protocol Error Alert */}
      {sessionError && (
        <Card className="px-4 py-3 border-border bg-[var(--danger-dim)] text-xs text-danger" role="alert">
          {sessionError}
        </Card>
      )}

      {/* Live Telemetry HUD Strip */}
      {showHud && (
        <Card className="px-4 py-2.5 flex flex-wrap items-center justify-between gap-3" aria-label="Live telemetry HUD">
          <div className="flex items-center gap-4 flex-wrap text-xs">
            <span className="flex items-center gap-1.5 text-text-pri font-medium">
              <Activity size={13} className="text-accent" aria-hidden="true" />
              Telemetry HUD
            </span>
            <span className="tabular-mono text-text-mut">
              RTT: <strong className="text-text-pri">{stats.lagMs} ms</strong>
            </span>
            <span className="tabular-mono text-text-mut">
              FPS: <strong className="text-text-pri">{stats.fps}</strong>
            </span>
            <span className="tabular-mono text-text-mut">
              Quality: <strong className="text-text-pri">{stats.jpegQuality}%</strong>
            </span>
            <span className="tabular-mono text-text-mut">
              Frames: <strong className="text-text-pri">{stats.frameCount}</strong>
            </span>
            <Badge tone="info" className="tabular-mono">
              {stats.codecTag}
            </Badge>
          </div>
          <span className="tabular-mono text-[11px] text-text-dim">
            trace:{stats.traceId.slice(0, 16)}
          </span>
        </Card>
      )}

      {/* Interactive Desktop Viewport */}
      <div
        ref={containerRef}
        className="rounded-[var(--radius-lg)] border border-border-strong bg-[var(--canvas-bg)] p-2 flex items-center justify-center overflow-hidden min-h-[460px]"
      >
        <canvas
          ref={canvasRef}
          width={960}
          height={600}
          tabIndex={0}
          aria-label={`Interactive ${protocol.toUpperCase()} desktop canvas`}
          style={{ cursor: cursorStyle }}
          onMouseMove={(e) => forwardMouse(e, domButtonsToMask(e.buttons))}
          onMouseDown={(e) => {
            e.currentTarget.focus();
            forwardMouse(e, domButtonsToMask(e.buttons));
          }}
          onMouseUp={(e) => forwardMouse(e, domButtonsToMask(e.buttons))}
          onContextMenu={(e) => e.preventDefault()}
          onPaste={(e) => {
            const txt = e.clipboardData.getData('text');
            if (txt) sendClipboard(txt);
          }}
          onKeyDown={(e) => forwardKey(e, true)}
          onKeyUp={(e) => forwardKey(e, false)}
          className="max-w-full max-h-[70vh] rounded-[var(--radius-sm)] shadow-md outline-none"
        />
      </div>
    </div>
  );
}
