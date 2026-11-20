import { useCallback, useEffect, useRef, useState, type CSSProperties } from 'react';
import { Activity, ArrowLeft, Maximize2, ShieldAlert } from 'lucide-react';
import { Badge, Button, Card } from '@/rust-engines/design-system/primitives';
import { useSessionsStore } from '@/stores/sessions';
import { PersistentAvc420Decoder } from './avc420';
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

interface ProgressState {
  stage: string;
  label: string;
  percent: number;
}

const MAC_CMD_TO_CTRL_CODES = new Set([
  'KeyA',
  'KeyC',
  'KeyX',
  'KeyV',
  'KeyZ',
  'KeyY',
  'KeyS',
  'KeyF',
  'KeyW',
  'KeyR',
  'KeyT',
  'KeyL',
  'KeyP',
  'KeyN',
  'KeyO',
]);

const MODIFIER_KEYSYMS = new Set([0xffe1, 0xffe2, 0xffe3, 0xffe4, 0xffe9, 0xffea, 0xffeb, 0xffec]);

const SPECIAL_KEY_MAP: Record<string, number> = {
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
  CapsLock: 0xffe5,
  Alt: 0xffe9,
  Meta: 0xffeb,
  NumLock: 0xff7f,
  ScrollLock: 0xff14,
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

function physicalCodeToAsciiKeysym(code: string): number {
  if (code === 'Tab') return 0xff09;
  const letter = /^Key([A-Z])$/.exec(code);
  if (letter) {
    return letter[1].toLowerCase().codePointAt(0) ?? 0;
  }
  const digit = /^Digit([0-9])$/.exec(code);
  if (digit) {
    return digit[1].codePointAt(0) ?? 0;
  }
  return 0;
}

export function DesktopStage({
  protocol,
  targetHost = 'win2025-ssm.internal',
  wsUrl,
  layout = 'en-us-qwerty',
  initialKeyboardLayout,
  showHud = true,
  sessionId,
  embedded = false,
  onSessionEnded,
  onBackToSettings,
}: {
  protocol: 'rdp' | 'vnc';
  targetHost?: string;
  wsUrl?: string;
  layout?: string;
  initialKeyboardLayout?: string;
  showHud?: boolean;
  sessionId?: string;
  embedded?: boolean;
  onSessionEnded?: (reason: string) => void;
  onBackToSettings: () => void;
}) {
  const effectiveInitialLayout = initialKeyboardLayout ?? layout;
  const initialLayoutRef = useRef<string>(effectiveInitialLayout);
  const onSessionEndedRef = useRef(onSessionEnded);
  onSessionEndedRef.current = onSessionEnded;

  const containerRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const lastResizeRef = useRef<{ w: number; h: number }>({ w: 0, h: 0 });
  const remoteSizeRef = useRef<{ w: number; h: number }>({ w: 960, h: 600 });
  const heldButtonsRef = useRef<number>(0);
  const heldModifiersRef = useRef<Set<number>>(new Set());
  const altTabTimersRef = useRef<number[]>([]);
  const lastPosRef = useRef<{ x: number; y: number }>({ x: 0, y: 0 });
  const pendingMoveRef = useRef<{ clientX: number; clientY: number; mask: number } | null>(null);
  const moveRafRef = useRef<number | null>(null);
  const firstFrameRef = useRef<boolean>(false);
  const avcDecoderRef = useRef<PersistentAvc420Decoder | null>(null);

  const [activeLayout, setActiveLayout] = useState<string>(effectiveInitialLayout);
  const [cursorStyle, setCursorStyle] = useState<string>('default');
  const [sessionError, setSessionError] = useState<string | null>(null);
  const [hasFirstFrame, setHasFirstFrame] = useState<boolean>(false);
  const [progress, setProgress] = useState<ProgressState>({
    stage: 'init',
    label: 'Initializing remote desktop session…',
    percent: 10,
  });
  const [remoteClipboard, setRemoteClipboard] = useState<string>('');
  const [containerSize, setContainerSize] = useState<{ w: number; h: number }>({ w: 0, h: 0 });
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

  const isMac =
    typeof navigator !== 'undefined' && /Mac|iPhone|iPad|iPod/i.test(navigator.platform || navigator.userAgent);

  useEffect(() => {
    setActiveLayout(effectiveInitialLayout);
    initialLayoutRef.current = effectiveInitialLayout;
  }, [effectiveInitialLayout]);

  useEffect(() => {
    let closed = false;
    let errored = false;
    let endedCleanly = false;
    let receivedHello = false;
    let postActivationTimer: ReturnType<typeof setTimeout> | null = null;
    let paintQueue: Promise<void> = Promise.resolve();

    firstFrameRef.current = false;
    setHasFirstFrame(false);
    setSessionError(null);
    setProgress({
      stage: 'init',
      label: 'Connecting to remote desktop gateway…',
      percent: 12,
    });

    const wsProto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const rawW = containerRef.current?.clientWidth || window.innerWidth || 1280;
    const rawH = containerRef.current?.clientHeight || window.innerHeight || 720;
    const width = Math.max(200, Math.min(4096, Math.floor(rawW))) & ~1;
    const height = Math.max(200, Math.min(4096, Math.floor(rawH)));

    let fullWsUrl: string;
    if (wsUrl) {
      fullWsUrl = /^wss?:\/\//i.test(wsUrl)
        ? wsUrl
        : `${wsProto}//${window.location.host}${wsUrl.startsWith('/') ? '' : '/'}${wsUrl}`;
    } else {
      const params = new URLSearchParams({
        protocol,
        mode: 'oqr2',
        width: String(width),
        height: String(height),
        target: targetHost,
        layout: initialLayoutRef.current,
      });
      fullWsUrl = `${wsProto}//${window.location.host}/api/v1/ws/rdp?${params.toString()}`;
    }
    const parsedUrl = new URL(fullWsUrl);
    if (!parsedUrl.searchParams.has('width')) parsedUrl.searchParams.set('width', String(width));
    if (!parsedUrl.searchParams.has('height')) parsedUrl.searchParams.set('height', String(height));
    fullWsUrl = parsedUrl.toString();

    const ws = new WebSocket(fullWsUrl);
    ws.binaryType = 'arraybuffer';
    wsRef.current = ws;

    const scheduleFitCheck = (delayMs: number) => {
      if (postActivationTimer) clearTimeout(postActivationTimer);
      postActivationTimer = setTimeout(() => {
        if (closed || ws.readyState !== WebSocket.OPEN) return;
        const el = containerRef.current;
        if (!el || el.clientWidth < 200 || el.clientHeight < 200) return;
        const cw = Math.max(200, Math.min(4096, Math.floor(el.clientWidth))) & ~1;
        const ch = Math.max(200, Math.min(4096, Math.floor(el.clientHeight)));
        if (Math.abs(cw - remoteSizeRef.current.w) >= 8 || Math.abs(ch - remoteSizeRef.current.h) >= 8) {
          lastResizeRef.current = { w: cw, h: ch };
          ws.send(JSON.stringify({ type: 'resize', width: cw, height: ch }));
        }
      }, delayMs);
    };

    const markFirstFrame = () => {
      if (!firstFrameRef.current) {
        firstFrameRef.current = true;
        setHasFirstFrame(true);
        setProgress({ stage: 'active', label: 'Session connected', percent: 100 });
        setStats((prev) => ({ ...prev, connected: true }));
        if (sessionId) {
          useSessionsStore.getState().updateStatus(sessionId, 'connected');
        }
        canvasRef.current?.focus();
        scheduleFitCheck(150);
      }
    };

    const enqueuePaint = (fn: () => Promise<void> | void) => {
      paintQueue = paintQueue
        .then(async () => {
          if (closed) return;
          await fn();
        })
        .catch(() => {});
    };

    ws.onopen = () => {
      if (closed) return;
      setProgress({
        stage: 'tunnel',
        label: 'Secure tunnel opened, starting protocol handshake…',
        percent: 25,
      });
      if (sessionId) {
        useSessionsStore.getState().updateStatus(sessionId, 'connecting');
      }
    };

    ws.onmessage = (ev) => {
      if (closed) return;
      if (typeof ev.data === 'string') {
        try {
          const parsed = JSON.parse(ev.data) as {
            type?: string;
            error?: string;
            stage?: string;
            label?: string;
            percent?: number;
            reason?: string;
          };
          if (parsed.type === 'progress') {
            setProgress({
              stage: parsed.stage ?? 'connecting',
              label: parsed.label ?? 'Connecting…',
              percent: Math.max(5, Math.min(99, parsed.percent ?? 50)),
            });
            return;
          }
          if (parsed.type === 'session_ended') {
            endedCleanly = true;
            setStats((prev) => ({ ...prev, connected: false }));
            if (sessionId) {
              useSessionsStore.getState().updateStatus(sessionId, 'disconnected');
            }
            onSessionEndedRef.current?.(parsed.reason ?? 'remote_logout');
            return;
          }
          if (parsed.type === 'error' || parsed.error) {
            errored = true;
            setSessionError(parsed.error ?? 'Session terminated by server policy');
            setStats((prev) => ({ ...prev, connected: false }));
            if (sessionId) {
              useSessionsStore.getState().updateStatus(sessionId, 'error');
            }
          }
        } catch {
          // Ignore non-JSON control text
        }
        return;
      }
      if (!(ev.data instanceof ArrayBuffer)) return;
      const msg = decodeOqr2Frame(ev.data);

      switch (msg.type) {
        case 'hello_ack': {
          receivedHello = true;
          remoteSizeRef.current = { w: msg.width, h: msg.height };
          enqueuePaint(() => {
            const canvas = canvasRef.current;
            if (canvas) {
              canvas.width = msg.width;
              canvas.height = msg.height;
            }
          });
          setStats((prev) => ({
            ...prev,
            width: msg.width,
            height: msg.height,
            traceId: msg.traceId,
            cursorPrediction: msg.cursorPrediction,
          }));
          setProgress((prev) => ({
            stage: prev.stage === 'init' ? 'handshake' : prev.stage,
            label: prev.stage === 'init' ? 'Negotiating Windows RDP display session…' : prev.label,
            percent: Math.max(prev.percent, 35),
          }));
          if (sessionId && !firstFrameRef.current) {
            useSessionsStore.getState().updateStatus(sessionId, 'connecting');
          }
          break;
        }

        case 'resize_surface':
          remoteSizeRef.current = { w: msg.w, h: msg.h };
          enqueuePaint(() => {
            const canvas = canvasRef.current;
            if (canvas) {
              canvas.width = msg.w;
              canvas.height = msg.h;
            }
          });
          setStats((prev) => ({ ...prev, width: msg.w, height: msg.h }));
          break;

        case 'solid_fill':
          markFirstFrame();
          enqueuePaint(() => {
            const ctx = canvasRef.current?.getContext('2d');
            if (ctx) {
              const [r, g, b, a] = msg.rgba;
              ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${a / 255})`;
              ctx.fillRect(msg.x, msg.y, msg.w, msg.h);
            }
          });
          break;

        case 'copy_rect':
          markFirstFrame();
          enqueuePaint(() => {
            const ctx = canvasRef.current?.getContext('2d');
            if (ctx) {
              const imgData = ctx.getImageData(msg.sx, msg.sy, msg.w, msg.h);
              ctx.putImageData(imgData, msg.dx, msg.dy);
            }
          });
          break;

        case 'tile_png':
        case 'tile_jpeg': {
          markFirstFrame();
          const mime = msg.type === 'tile_png' ? 'image/png' : 'image/jpeg';
          const blob = new Blob([new Uint8Array(msg.bytes)], { type: mime });
          const bmpPromise =
            typeof createImageBitmap === 'function' ? createImageBitmap(blob) : null;
          if (!bmpPromise) break;
          enqueuePaint(async () => {
            const ctx = canvasRef.current?.getContext('2d');
            const bmp = await bmpPromise;
            try {
              if (ctx && !closed) ctx.drawImage(bmp, msg.x, msg.y);
            } finally {
              bmp.close();
            }
          });
          break;
        }

        case 'cursor_shape': {
          if (msg.w === 0 || msg.h === 0) {
            setCursorStyle('default');
            break;
          }
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
          markFirstFrame();
          const ctx = canvasRef.current?.getContext('2d');
          if (ctx) {
            if (!avcDecoderRef.current) {
              avcDecoderRef.current = new PersistentAvc420Decoder((frame, rect) => {
                ctx.drawImage(frame, rect.x, rect.y, rect.w, rect.h);
              });
            }
            avcDecoderRef.current.decodeFrame(msg.annexB, {
              x: msg.x,
              y: msg.y,
              w: msg.w,
              h: msg.h,
            });
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

    ws.onerror = () => {
      if (!closed && !errored && !endedCleanly && !receivedHello) {
        errored = true;
        setSessionError('Remote desktop WebSocket closed before handshake completed. Check HTTPS certificate trust or reconnect the session.');
        setStats((prev) => ({ ...prev, connected: false }));
        if (sessionId) {
          useSessionsStore.getState().updateStatus(sessionId, 'error');
        }
      }
    };

    ws.onclose = () => {
      if (!closed) {
        setStats((prev) => ({ ...prev, connected: false }));
        if (endedCleanly) return;
        if (!errored && !receivedHello) {
          errored = true;
          setSessionError('Remote desktop WebSocket closed before handshake completed. Check HTTPS certificate trust or reconnect the session.');
          if (sessionId) {
            useSessionsStore.getState().updateStatus(sessionId, 'error');
          }
        } else if (sessionId && !errored) {
          useSessionsStore.getState().updateStatus(sessionId, 'disconnected');
        }
      }
    };

    return () => {
      closed = true;
      if (postActivationTimer) clearTimeout(postActivationTimer);
      avcDecoderRef.current?.close();
      avcDecoderRef.current = null;
      ws.close();
      wsRef.current = null;
    };
  }, [protocol, targetHost, wsUrl, sessionId]);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const measureAndSchedule = (entries?: ResizeObserverEntry[]) => {
      const contentW = entries?.[0]?.contentRect?.width ?? 0;
      const contentH = entries?.[0]?.contentRect?.height ?? 0;
      const rectW = Math.floor(el.clientWidth || contentW);
      const rectH = Math.floor(el.clientHeight || contentH);
      if (rectW <= 0 || rectH <= 0) return;
      setContainerSize((prev) => (prev.w === rectW && prev.h === rectH ? prev : { w: rectW, h: rectH }));
      if (rectW < 200 || rectH < 200) return;
      const targetW = Math.max(200, Math.min(4096, rectW)) & ~1;
      const targetH = Math.max(200, Math.min(4096, rectH));
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => {
        const ws = wsRef.current;
        if (!ws || ws.readyState !== WebSocket.OPEN) return;
        const dw = Math.abs(targetW - remoteSizeRef.current.w);
        const dh = Math.abs(targetH - remoteSizeRef.current.h);
        if ((dw >= 8 || dh >= 8) &&
            (lastResizeRef.current.w !== targetW || lastResizeRef.current.h !== targetH)) {
          lastResizeRef.current = { w: targetW, h: targetH };
          ws.send(JSON.stringify({ type: 'resize', width: targetW, height: targetH }));
        }
      }, 250);
    };
    measureAndSchedule();
    let ro: ResizeObserver | null = null;
    if (typeof ResizeObserver !== 'undefined') {
      ro = new ResizeObserver((entries) => measureAndSchedule(entries));
      ro.observe(el);
    }
    const onWinResize = () => measureAndSchedule();
    window.addEventListener('resize', onWinResize);
    return () => {
      if (timer) clearTimeout(timer);
      ro?.disconnect();
      window.removeEventListener('resize', onWinResize);
    };
  }, []);

  const releaseAllModifiers = useCallback(() => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      heldModifiersRef.current.clear();
      return;
    }
    for (const sym of heldModifiersRef.current) {
      ws.send(JSON.stringify({ type: 'key', keysym: sym, pressed: false }));
    }
    heldModifiersRef.current.clear();
  }, []);

  useEffect(() => {
    const onWindowMouseUp = () => {
      if (heldButtonsRef.current !== 0) {
        heldButtonsRef.current = 0;
        const ws = wsRef.current;
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({
            type: 'pointer',
            x: lastPosRef.current.x,
            y: lastPosRef.current.y,
            button_mask: 0,
          }));
        }
      }
    };
    const onWindowBlur = () => {
      releaseAllModifiers();
      onWindowMouseUp();
    };
    window.addEventListener('mouseup', onWindowMouseUp);
    window.addEventListener('blur', onWindowBlur);
    return () => {
      if (moveRafRef.current !== null && typeof cancelAnimationFrame === 'function') {
        cancelAnimationFrame(moveRafRef.current);
      }
      window.removeEventListener('mouseup', onWindowMouseUp);
      window.removeEventListener('blur', onWindowBlur);
    };
  }, [releaseAllModifiers]);

  useEffect(() => {
    const matchesSession = (ev: Event) => {
      const detail = (ev as CustomEvent<{ sessionId?: string }>).detail;
      return !sessionId || !detail?.sessionId || detail.sessionId === sessionId;
    };
    const onCtrlAltDel = (ev: Event) => {
      if (!matchesSession(ev)) return;
      const ws = wsRef.current;
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'sas' }));
      }
    };
    const onKeyboardLayout = (ev: Event) => {
      if (!matchesSession(ev)) return;
      const nextLayout = (ev as CustomEvent<{ layout?: string }>).detail?.layout;
      if (!nextLayout) return;
      setActiveLayout(nextLayout);
      const ws = wsRef.current;
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'keyboard_layout', layout: nextLayout }));
      }
    };
    const onAltTab = (ev: Event) => {
      if (!matchesSession(ev)) return;
      const ws = wsRef.current;
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      canvasRef.current?.focus();
      for (const id of altTabTimersRef.current) window.clearTimeout(id);
      altTabTimersRef.current = [];
      const sendAt = (ms: number, keysym: number, pressed: boolean) => {
        if (ms === 0) {
          ws.send(JSON.stringify({ type: 'key', keysym, pressed }));
          return;
        }
        const id = window.setTimeout(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'key', keysym, pressed }));
          }
        }, ms);
        altTabTimersRef.current.push(id);
      };
      // Staged Ctrl+Alt+Tab opens the persistent Windows Task Switcher so user can click or arrow to a window
      sendAt(0, 0xffe3, true);
      sendAt(35, 0xffe9, true);
      sendAt(75, 0xff09, true);
      sendAt(135, 0xff09, false);
      sendAt(175, 0xffe9, false);
      sendAt(210, 0xffe3, false);
    };
    const onFitWindow = (ev: Event) => {
      if (!matchesSession(ev)) return;
      const el = containerRef.current;
      const ws = wsRef.current;
      if (!el || !ws || ws.readyState !== WebSocket.OPEN) return;
      const cw = Math.max(200, Math.min(4096, Math.floor(el.clientWidth))) & ~1;
      const ch = Math.max(200, Math.min(4096, Math.floor(el.clientHeight)));
      lastResizeRef.current = { w: cw, h: ch };
      ws.send(JSON.stringify({ type: 'resize', width: cw, height: ch }));
    };
    const onCaptureAltTab = (e: KeyboardEvent) => {
      const canvas = canvasRef.current;
      if (!canvas || canvas.offsetParent === null) return;
      const active = document.activeElement as HTMLElement | null;
      if (
        active &&
        (active.tagName === 'INPUT' ||
          active.tagName === 'TEXTAREA' ||
          active.tagName === 'SELECT' ||
          active.isContentEditable ||
          active.getAttribute('role') === 'textbox' ||
          Boolean(active.closest('[data-terminal-wrapper="true"]')))
      ) {
        return;
      }
      if (e.altKey && (e.code === 'Tab' || e.key === 'Tab')) {
        const ws = wsRef.current;
        if (!ws || ws.readyState !== WebSocket.OPEN) return;
        e.preventDefault();
        e.stopPropagation();
        canvas.focus();
        if (!heldModifiersRef.current.has(0xffe9)) {
          heldModifiersRef.current.add(0xffe9);
          ws.send(JSON.stringify({ type: 'key', keysym: 0xffe9, pressed: true }));
        }
        ws.send(JSON.stringify({ type: 'key', keysym: 0xff09, pressed: true }));
        ws.send(JSON.stringify({ type: 'key', keysym: 0xff09, pressed: false }));
      }
    };
    const onFullscreenChange = () => {
      const navKbd = (
        navigator as Navigator & {
          keyboard?: { lock?: (codes?: string[]) => Promise<void>; unlock?: () => void };
        }
      ).keyboard;
      if (!navKbd) return;
      if (document.fullscreenElement && canvasRef.current?.offsetParent !== null) {
        void navKbd.lock?.(['AltLeft', 'AltRight', 'Tab']).catch(() => {});
      } else {
        try {
          navKbd.unlock?.();
        } catch {
          void 0;
        }
      }
    };
    window.addEventListener('ct:rdp-ctrl-alt-del', onCtrlAltDel);
    window.addEventListener('ct:rdp-keyboard-layout', onKeyboardLayout);
    window.addEventListener('ct:rdp-alt-tab', onAltTab);
    window.addEventListener('ct:rdp-fit-window', onFitWindow);
    window.addEventListener('keydown', onCaptureAltTab, true);
    document.addEventListener('fullscreenchange', onFullscreenChange);
    return () => {
      for (const id of altTabTimersRef.current) window.clearTimeout(id);
      altTabTimersRef.current = [];
      window.removeEventListener('ct:rdp-ctrl-alt-del', onCtrlAltDel);
      window.removeEventListener('ct:rdp-keyboard-layout', onKeyboardLayout);
      window.removeEventListener('ct:rdp-alt-tab', onAltTab);
      window.removeEventListener('ct:rdp-fit-window', onFitWindow);
      window.removeEventListener('keydown', onCaptureAltTab, true);
      document.removeEventListener('fullscreenchange', onFullscreenChange);
    };
  }, [sessionId]);

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

  const forwardMouse = (clientX: number, clientY: number, buttonMask: number) => {
    const canvas = canvasRef.current;
    const ws = wsRef.current;
    if (!canvas || !ws || ws.readyState !== WebSocket.OPEN) return;
    const rect = canvas.getBoundingClientRect();
    const x = rect.width > 0
      ? Math.max(0, Math.min(Math.max(0, canvas.width - 1), Math.round(((clientX - rect.left) * canvas.width) / rect.width)))
      : 0;
    const y = rect.height > 0
      ? Math.max(0, Math.min(Math.max(0, canvas.height - 1), Math.round(((clientY - rect.top) * canvas.height) / rect.height)))
      : 0;
    lastPosRef.current = { x, y };
    ws.send(JSON.stringify({ type: 'pointer', x, y, button_mask: buttonMask }));
  };

  const flushPendingMove = () => {
    if (moveRafRef.current !== null && typeof cancelAnimationFrame === 'function') {
      cancelAnimationFrame(moveRafRef.current);
      moveRafRef.current = null;
    }
    const pending = pendingMoveRef.current;
    if (pending) {
      pendingMoveRef.current = null;
      forwardMouse(pending.clientX, pending.clientY, pending.mask);
    }
  };

  const scheduleMouseMove = (clientX: number, clientY: number, mask: number) => {
    pendingMoveRef.current = { clientX, clientY, mask };
    if (typeof requestAnimationFrame !== 'function') {
      flushPendingMove();
      return;
    }
    if (moveRafRef.current === null) {
      moveRafRef.current = requestAnimationFrame(() => {
        moveRafRef.current = null;
        flushPendingMove();
      });
    }
  };

  const domButtonsToMask = (buttons: number): number => {
    let m = 0;
    if (buttons & 1) m |= 1; // Left
    if (buttons & 4) m |= 2; // Middle
    if (buttons & 2) m |= 4; // Right
    return m;
  };

  const buttonBitForEventButton = (button: number): number => {
    if (button === 0) return 1;
    if (button === 1) return 2;
    if (button === 2) return 4;
    return 0;
  };

  const sendKeyEvent = (keysym: number, pressed: boolean) => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;
    if (MODIFIER_KEYSYMS.has(keysym)) {
      if (pressed) heldModifiersRef.current.add(keysym);
      else heldModifiersRef.current.delete(keysym);
    }
    ws.send(JSON.stringify({ type: 'key', keysym, pressed }));
  };

  const sendCtrlCombo = (letterKeysym: number) => {
    sendKeyEvent(0xffe3, true);
    sendKeyEvent(letterKeysym, true);
    sendKeyEvent(letterKeysym, false);
    sendKeyEvent(0xffe3, false);
  };

  const forwardKey = (e: React.KeyboardEvent<HTMLCanvasElement>, pressed: boolean) => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;

    if (
      pressed &&
      e.repeat &&
      (e.key === 'Shift' ||
        e.key === 'Control' ||
        e.key === 'Alt' ||
        e.key === 'Meta' ||
        e.key === 'AltGraph')
    ) {
      e.preventDefault();
      return;
    }

    if (e.key === 'AltGraph' || e.code === 'AltRight') {
      e.preventDefault();
      sendKeyEvent(0xffe9, pressed);
      return;
    }

    // On macOS, map Cmd+C/X/V and standard editor/browser shortcuts -> Windows Ctrl+<key>
    if (isMac && e.metaKey && !e.ctrlKey && !e.altKey) {
      if (e.key === 'Meta') {
        e.preventDefault();
        return;
      }
      if (MAC_CMD_TO_CTRL_CODES.has(e.code)) {
        e.preventDefault();
        e.stopPropagation();
        if (!pressed) return;
        const sym = physicalCodeToAsciiKeysym(e.code);
        if (sym <= 0) return;
        if (e.code === 'KeyV' && navigator.clipboard && typeof navigator.clipboard.readText === 'function') {
          void navigator.clipboard
            .readText()
            .then((txt) => {
              if (txt) sendClipboard(txt);
            })
            .catch(() => {})
            .finally(() => {
              setTimeout(() => sendCtrlCombo(sym), 60);
            });
        } else {
          sendCtrlCombo(sym);
        }
        return;
      }
    }

    if (isMac && e.key === 'Meta') {
      e.preventDefault();
      return;
    }

    // Intercept Alt+Tab / Alt+<letter> using physical e.code so Option dead-keys / OS switcher don't break Windows shortcuts
    if (e.altKey && e.code && (e.code === 'Tab' || /^Key[A-Z]$/.test(e.code) || /^Digit[0-9]$/.test(e.code))) {
      e.preventDefault();
      e.stopPropagation();
      const sym = physicalCodeToAsciiKeysym(e.code);
      if (sym > 0) {
        if (pressed && !heldModifiersRef.current.has(0xffe9)) {
          sendKeyEvent(0xffe9, true);
        }
        sendKeyEvent(sym, pressed);
      }
      return;
    }

    const keysym =
      SPECIAL_KEY_MAP[e.key] ??
      (e.key.length === 1 ? e.key.codePointAt(0) ?? 0 : physicalCodeToAsciiKeysym(e.code));
    if (keysym > 0) {
      e.preventDefault();
      sendKeyEvent(keysym, pressed);
    }
  };

  const canvasDisplayStyle: CSSProperties =
    embedded && containerSize.w > 0 && containerSize.h > 0 && stats.width > 0 && stats.height > 0
      ? (() => {
          const scale = Math.min(containerSize.w / stats.width, containerSize.h / stats.height);
          return {
            width: `${Math.max(1, Math.floor(stats.width * scale))}px`,
            height: `${Math.max(1, Math.floor(stats.height * scale))}px`,
            cursor: cursorStyle,
            touchAction: 'none',
          };
        })()
      : { cursor: cursorStyle, touchAction: 'none' };

  const desktopCanvas = (className: string) => (
    <canvas
      ref={canvasRef}
      width={960}
      height={600}
      tabIndex={0}
      aria-label={`Interactive ${protocol.toUpperCase()} desktop canvas`}
      style={canvasDisplayStyle}
      onMouseMove={(e) => scheduleMouseMove(e.clientX, e.clientY, domButtonsToMask(e.buttons))}
      onMouseDown={(e) => {
        e.currentTarget.focus();
        flushPendingMove();
        const mask = domButtonsToMask(e.buttons) || buttonBitForEventButton(e.button);
        heldButtonsRef.current = mask;
        forwardMouse(e.clientX, e.clientY, mask);
      }}
      onMouseUp={(e) => {
        flushPendingMove();
        const releasedBit = buttonBitForEventButton(e.button);
        const mask = e.buttons !== 0 ? (domButtonsToMask(e.buttons) & ~releasedBit) : 0;
        heldButtonsRef.current = mask;
        forwardMouse(e.clientX, e.clientY, mask);
      }}
      onWheel={(e) => {
        e.preventDefault();
        flushPendingMove();
        const wheelBit = e.deltaY < 0 ? 0x08 : e.deltaY > 0 ? 0x10 : 0;
        if (wheelBit !== 0) {
          forwardMouse(e.clientX, e.clientY, heldButtonsRef.current | wheelBit);
        }
      }}
      onBlur={releaseAllModifiers}
      onContextMenu={(e) => e.preventDefault()}
      onPaste={(e) => {
        const txt = e.clipboardData.getData('text');
        if (txt) sendClipboard(txt);
      }}
      onKeyDown={(e) => forwardKey(e, true)}
      onKeyUp={(e) => forwardKey(e, false)}
      className={className}
    />
  );

  if (embedded) {
    return (
      <div
        ref={containerRef}
        className="relative w-full h-full bg-black flex items-center justify-center overflow-hidden"
      >
        {desktopCanvas('block outline-none')}
        {(!hasFirstFrame || sessionError) && (
          <div className="absolute inset-0 flex flex-col items-center justify-center bg-[#090d14]/92 text-text-pri gap-3 z-10 px-6">
            {sessionError ? (
              <>
                <span className="text-sm font-semibold text-danger">Connection failed</span>
                <span role="alert" className="text-xs text-text-dim max-w-sm text-center">
                  {sessionError}
                </span>
              </>
            ) : (
              <div className="w-full max-w-sm space-y-2.5 text-center">
                <div className="text-sm font-medium text-text-pri">
                  Connecting to {protocol.toUpperCase()} desktop…
                </div>
                <div
                  role="progressbar"
                  aria-label="Remote desktop connection progress"
                  aria-valuemin={0}
                  aria-valuemax={100}
                  aria-valuenow={progress.percent}
                  className="w-full h-2 rounded-full bg-elev overflow-hidden border border-border"
                >
                  <div
                    className="h-full bg-accent transition-all duration-300"
                    style={{ width: `${progress.percent}%` }}
                  />
                </div>
                <div className="text-[11px] text-text-mut text-center truncate">
                  {progress.label}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto px-6 py-5 space-y-4">
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
              {stats.width}x{stats.height} · Layout {activeLayout}
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

      {sessionError && (
        <Card className="px-4 py-3 border-border bg-[var(--danger-dim)] text-xs text-danger" role="alert">
          {sessionError}
        </Card>
      )}

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

      <div
        ref={containerRef}
        className="rounded-[var(--radius-lg)] border border-border-strong bg-[var(--canvas-bg)] p-2 flex items-center justify-center overflow-hidden min-h-[460px]"
      >
        {desktopCanvas('max-w-full max-h-[70vh] rounded-[var(--radius-sm)] shadow-md outline-none')}
      </div>
    </div>
  );
}
