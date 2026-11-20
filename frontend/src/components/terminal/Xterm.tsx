import {
  forwardRef,
  useEffect,
  useRef,
  useImperativeHandle,
} from 'react';
import {
  createTerminalAdapter,
  normalizeTerminalEngine,
  type TerminalAdapter,
  type TerminalEngineKind,
} from '@/lib/terminal-engine';
import { watchTheme } from '@/lib/xterm-themes';
import { useSettingsStore } from '@/stores/settings';
import { useSessionsStore } from '@/stores/sessions';
import { getTerminalWS } from '@/lib/ws';
import type { IncomingWSMessage } from '@/lib/ws-messages';
import { nanoid } from 'nanoid';
import { useToastStore } from '@/stores/toast';

export interface XtermRef {
  focus: () => void;
  write: (data: string) => void;
  fit: () => void;
  paste: (data: string) => void;
  copySelection: () => string;
  getSessionId: () => string;
  search: (query: string) => boolean;
  searchNext: () => boolean;
  searchPrevious: () => boolean;
  clearSearch: () => void;
  serialize: () => string;
  dispose: () => void;
}

export interface XtermProps {
  instanceId: string;
  instanceName: string;
  sessionId?: string;
  awsProfile?: string;
  awsRegion?: string;
  environment?: string;
  userScoped?: boolean;
  onReady?: () => void;
  onRecordingChange?: (recording: boolean) => void;
  onSearchResults?: (resultIndex: number, resultCount: number) => void;
  className?: string;
}

export const Xterm = forwardRef<XtermRef, XtermProps>(function Xterm(
  { instanceId, instanceName, sessionId: sessionIdProp, awsProfile, awsRegion, environment, userScoped = false, onReady, onRecordingChange, onSearchResults, className = '' },
  ref,
) {
  const containerRef = useRef<HTMLDivElement>(null);
  const adapterRef = useRef<TerminalAdapter | null>(null);
  const activeEngineRef = useRef<TerminalEngineKind | null>(null);
  const swapGenRef = useRef(0);
  const sessionId = useRef(sessionIdProp ?? nanoid());
  const sessionStartedRef = useRef(false);

  const fontSize = useSettingsStore((s) => s.fontSize);
  const fontFamily = useSettingsStore((s) => s.fontFamily);
  const scrollbackLines = useSettingsStore((s) => s.scrollbackLines);
  const terminalEngine = useSettingsStore((s) => normalizeTerminalEngine(s.terminalEngine));

  const callbacksRef = useRef({ onReady, onRecordingChange, onSearchResults });
  callbacksRef.current = { onReady, onRecordingChange, onSearchResults };

  const wsRef = useRef(getTerminalWS(userScoped));
  wsRef.current = getTerminalWS(userScoped);

  const buildAdapter = (engine: TerminalEngineKind, container: HTMLElement): TerminalAdapter => {
    const state = useSettingsStore.getState();
    const ws = wsRef.current;
    return createTerminalAdapter({
      engine,
      container,
      fontFamily: state.fontFamily,
      fontSize: state.fontSize,
      scrollbackLines: state.scrollbackLines,
      onData: (input) => {
        if (!sessionStartedRef.current) return;
        ws.send({ type: 'terminal_input', payload: { session_id: sessionId.current, input } });
      },
      onResize: (cols, rows) => {
        if (cols < 1 || rows < 1) return;
        ws.send({
          type: 'terminal_resize',
          payload: { session_id: sessionId.current, cols, rows },
        });
      },
      onSearchResults: (resultIndex, resultCount) => {
        callbacksRef.current.onSearchResults?.(resultIndex, resultCount);
      },
      onFallback: () => {
        useToastStore.getState().push({
          variant: 'warn',
          title: 'Terminal fell back to xterm.js',
          description: 'wterm could not initialize in this browser; session continues with xterm.js.',
          duration: 5000,
        });
      },
    });
  };

  // Mount initial engine synchronously on mount and hot-swap on engine change without closing the WS session.
  useEffect(() => {
    const containerEl = containerRef.current;
    if (!containerEl) return;

    if (!adapterRef.current) {
      const adapter = buildAdapter(terminalEngine, containerEl);
      adapterRef.current = adapter;
      activeEngineRef.current = terminalEngine;
      void adapter.init();
      return;
    }

    if (activeEngineRef.current === terminalEngine) return;

    let cancelled = false;
    const gen = ++swapGenRef.current;
    const prev = adapterRef.current;

    void (async () => {
      const prevCols = prev.cols;
      const prevRows = prev.rows;
      const snapshot = await prev.serializeAsync();
      if (cancelled || swapGenRef.current !== gen || !containerRef.current) return;

      prev.dispose();
      if (adapterRef.current === prev) adapterRef.current = null;
      containerRef.current.replaceChildren();

      const next = buildAdapter(terminalEngine, containerRef.current);
      adapterRef.current = next;
      activeEngineRef.current = terminalEngine;
      await next.init();

      if (cancelled || swapGenRef.current !== gen) {
        next.dispose();
        if (adapterRef.current === next) adapterRef.current = null;
        return;
      }

      if (snapshot) next.write(snapshot);
      if (next.cols > 0 && next.rows > 0 && (next.cols !== prevCols || next.rows !== prevRows)) {
        wsRef.current.send({
          type: 'terminal_resize',
          payload: { session_id: sessionId.current, cols: next.cols, rows: next.rows },
        });
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [terminalEngine]);

  // Persistent session + DOM listeners independent of active terminal engine.
  useEffect(() => {
    const containerEl = containerRef.current;
    if (!containerEl) return;
    const mySessionId = sessionId.current;
    const ws = wsRef.current;

    const unsub = ws.subscribe((msg: IncomingWSMessage) => {
      const payload = msg.payload as Record<string, unknown> | undefined;
      if (payload && typeof payload === 'object' && 'session_id' in payload && payload.session_id !== mySessionId) return;

      if (msg.type === 'session_started' && payload?.session_id === mySessionId) {
        sessionStartedRef.current = true;
        useSessionsStore.getState().updateStatus(mySessionId, 'connected');
        callbacksRef.current.onRecordingChange?.(payload.recording === true);
        const adp = adapterRef.current;
        if (adp) {
          adp.fit();
          if (adp.cols > 0 && adp.rows > 0) {
            ws.send({
              type: 'terminal_resize',
              payload: { session_id: mySessionId, cols: adp.cols, rows: adp.rows },
            });
          }
          if (containerEl.offsetParent !== null) {
            adp.focus();
          }
        }
      }
      if ((msg.type === 'session_error' || msg.type === 'session_closed') && payload?.session_id === mySessionId) {
        callbacksRef.current.onRecordingChange?.(false);
      }
      if (msg.type === 'session_closed' && payload?.session_id === mySessionId) {
        useSessionsStore.getState().updateStatus(mySessionId, 'disconnected');
      }

      if (msg.type === 'terminal_output' && adapterRef.current) {
        adapterRef.current.write((payload as { output: string }).output);
        if (!sessionStartedRef.current) useSessionsStore.getState().updateStatus(mySessionId, 'connected');
        sessionStartedRef.current = true;
        callbacksRef.current.onReady?.();
      }

      if (msg.type === 'session_error' && payload && payload.session_id === mySessionId) {
        const reason = String((payload as { error?: string }).error ?? 'The session could not start.');
        adapterRef.current?.write(`\r\n\x1b[31mOperquay: ${reason}\x1b[0m\r\n`);
        useSessionsStore.getState().updateStatus(mySessionId, 'error');
      }

      if (msg.type === 'ws_error' && !sessionStartedRef.current) {
        const reason = String((payload as { error?: string } | undefined)?.error ?? 'Terminal WebSocket disconnected, reconnecting…');
        adapterRef.current?.write(`\r\n\x1b[33mOperquay: ${reason}\x1b[0m\r\n`);
      }

      if (msg.type === 'log_insight') {
        const p = msg.payload as { error_summary: string; suggested_fix: string };
        useToastStore.getState().push({
          variant: 'warn',
          title: p.error_summary,
          description: p.suggested_fix,
          duration: 6000,
        });
      }
    });

    const initialAdapter = adapterRef.current;
    ws.send({
      type: 'start_session',
      payload: {
        instance_id: instanceId,
        instance_name: instanceName,
        session_id: mySessionId,
        aws_profile: awsProfile ?? '',
        aws_region: awsRegion ?? '',
        environment: environment ?? '',
        cols: initialAdapter?.cols ?? 80,
        rows: initialAdapter?.rows ?? 24,
      },
    });

    const ro = new ResizeObserver(() => {
      if (containerRef.current && containerRef.current.offsetHeight > 0) {
        adapterRef.current?.fit();
      }
    });
    ro.observe(containerEl);

    const typeHandler = (e: Event) => {
      const { sessionId: sid, data } = (e as CustomEvent<{ sessionId: string; data: string }>).detail;
      if (sid === sessionId.current) adapterRef.current?.paste(data);
    };
    window.addEventListener('ct:terminal-type', typeHandler);

    // Intercept clipboard paste to avoid chunked/garbled long pastes.
    const pasteHandler = (e: ClipboardEvent) => {
      const text = e.clipboardData?.getData('text/plain') ?? '';
      if (!text) return;
      e.preventDefault();
      e.stopPropagation();
      adapterRef.current?.paste(text);
    };
    containerEl.addEventListener('paste', pasteHandler, true);

    return () => {
      sessionStartedRef.current = false;
      swapGenRef.current += 1;
      try {
        // A user shell stays open across refresh. The tab close button sends close_session itself.
        if (!userScoped) ws.send({ type: 'close_session', payload: { session_id: mySessionId } });
        unsub();
        ro.disconnect();
        window.removeEventListener('ct:terminal-type', typeHandler);
        containerEl.removeEventListener('paste', pasteHandler, true);
        adapterRef.current?.dispose();
      } catch {
        void 0;
      }
      adapterRef.current = null;
      activeEngineRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    adapterRef.current?.setScrollbackLines(scrollbackLines);
  }, [scrollbackLines]);

  useEffect(() => watchTheme(() => {
    adapterRef.current?.setTheme();
  }), []);

  useEffect(() => {
    adapterRef.current?.setAppearance(fontFamily, fontSize);
  }, [fontSize, fontFamily]);

  useImperativeHandle(
    ref,
    () => ({
      focus: () => adapterRef.current?.focus(),
      write: (d) => adapterRef.current?.write(d),
      fit: () => adapterRef.current?.fit(),
      paste: (d) => adapterRef.current?.paste(d),
      copySelection: () => adapterRef.current?.getSelection() ?? '',
      getSessionId: () => sessionId.current,
      search: (q: string) => adapterRef.current?.search(q) ?? false,
      searchNext: () => adapterRef.current?.searchNext() ?? false,
      searchPrevious: () => adapterRef.current?.searchPrevious() ?? false,
      clearSearch: () => adapterRef.current?.clearSearch(),
      serialize: () => adapterRef.current?.serialize() ?? '',
      dispose: () => adapterRef.current?.dispose(),
    }),
    [],
  );

  return (
    <div
      className={`relative h-full w-full overflow-hidden ${className}`}
      style={{ backgroundColor: 'var(--term-bg)' }}
      onKeyDown={(e) => {
        // Prevent Tab from moving browser focus out of the terminal
        if (e.key === 'Tab') {
          e.preventDefault();
          adapterRef.current?.focus();
        }
      }}
    >
      <div ref={containerRef} className="h-full w-full" style={{ paddingLeft: 6, paddingTop: 4 }} />
    </div>
  );
});

Xterm.displayName = 'Xterm';
