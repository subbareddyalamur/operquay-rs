import { useEffect, useRef, useState } from 'react';
import { Badge } from '@/design-system/primitives';
import { OperquayTerminal, type OperquayTerminalRef } from './OperquayTerminal';

export interface WsTerminalPaneProps {
  wsUrl: string;
  title: string;
  cols?: number;
  rows?: number;
  onReady?: (controls: {
    sendCommand: (cmd: string) => void;
    search: (q: string) => number;
    serialize: () => string;
  }) => void;
}

export function WsTerminalPane({
  wsUrl,
  title,
  cols = 96,
  rows = 24,
  onReady,
}: WsTerminalPaneProps) {
  const termRef = useRef<OperquayTerminalRef | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const [status, setStatus] = useState<'connecting' | 'connected' | 'closed'>('connecting');

  useEffect(() => {
    setStatus('connecting');
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus('connected');
    };

    ws.onmessage = (ev) => {
      if (typeof ev.data === 'string') {
        termRef.current?.write(ev.data);
      } else if (ev.data instanceof Blob) {
        void ev.data.arrayBuffer().then((buf) => {
          termRef.current?.write(new Uint8Array(buf));
        });
      }
    };

    ws.onclose = () => setStatus('closed');
    ws.onerror = () => setStatus('closed');

    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [wsUrl]);

  useEffect(() => {
    onReady?.({
      sendCommand: (cmd: string) => {
        if (wsRef.current?.readyState === WebSocket.OPEN) {
          wsRef.current.send(JSON.stringify({ type: 'input', data: cmd }));
        }
      },
      search: (q: string) => termRef.current?.search(q) ?? 0,
      serialize: () => termRef.current?.serialize() ?? '',
    });
  }, [onReady]);

  return (
    <div className="rounded-[var(--radius-lg)] border border-border bg-surface overflow-hidden">
      <div className="px-3 py-2 border-b border-border bg-elev flex items-center justify-between text-xs">
        <span className="font-medium text-text-pri">{title}</span>
        <Badge tone={status === 'connected' ? 'success' : status === 'connecting' ? 'info' : 'neutral'}>
          {status}
        </Badge>
      </div>
      <OperquayTerminal
        ref={termRef}
        cols={cols}
        rows={rows}
        ariaLabel={title}
        onData={(chunk) => {
          if (wsRef.current?.readyState === WebSocket.OPEN) {
            wsRef.current.send(JSON.stringify({ type: 'input', data: chunk }));
          }
        }}
        onResize={(c, r) => {
          if (wsRef.current?.readyState === WebSocket.OPEN) {
            wsRef.current.send(JSON.stringify({ type: 'resize', cols: c, rows: r }));
          }
        }}
      />
    </div>
  );
}

