import { IncomingWSMsg, type IncomingWSMessage } from './ws-messages';

type MessageHandler = (msg: IncomingWSMessage) => void;

interface StartSessionPayload {
  instance_id: string;
  instance_name: string;
  session_id: string;
  aws_profile: string;
  aws_region: string;
}

class WSClient {
  private ws: WebSocket | null = null;
  private handlers = new Set<MessageHandler>();
  private queue: string[] = [];
  private reconnectDelay = 500;
  private readonly maxDelay = 16000;
  private active = true;
  private connectFailures = 0;
  private openedOnce = false;
  // Track active sessions so they can be re-started after WS reconnection.
  private activeSessions = new Map<string, StartSessionPayload>();

  constructor(private readonly path: string) {
    this.connect();
  }

  private notifyWsError(error: string) {
    for (const sid of this.activeSessions.keys()) {
      const msg: IncomingWSMessage = { type: 'ws_error', payload: { session_id: sid, error } };
      for (const h of this.handlers) {
        try { h(msg); } catch { void 0; }
      }
    }
  }

  private connect() {
    if (!this.active) return;
    let openedThisAttempt = false;
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    this.ws = new WebSocket(`${proto}//${window.location.host}${this.path}`);

    this.ws.onopen = () => {
      openedThisAttempt = true;
      this.openedOnce = true;
      this.connectFailures = 0;
      this.reconnectDelay = 500;
      // Re-register all active sessions on the new connection.
      for (const payload of this.activeSessions.values()) {
        this.ws?.send(JSON.stringify({ type: 'start_session', payload }));
      }
      // Drain queued messages after session re-registration.
      const pending = [...this.queue];
      this.queue = [];
      for (const msg of pending) this.ws?.send(msg);
    };

    this.ws.onmessage = ({ data }) => {
      try {
        const raw = JSON.parse(data as string);
        const parsed = IncomingWSMsg.safeParse(raw);
        const msg = parsed.success ? parsed.data : (raw as IncomingWSMessage);
        if ((msg.type === 'session_closed' || msg.type === 'session_error') && msg.payload?.session_id) this.activeSessions.delete(msg.payload.session_id);
        for (const h of this.handlers) {
          try { h(msg); } catch { void 0; }
        }
      } catch {
        void 0;
      }
    };

    this.ws.onerror = () => {
      this.connectFailures += 1;
      if (!openedThisAttempt && this.connectFailures === 1) {
        this.notifyWsError('Terminal WebSocket connection failed (check HTTPS certificate trust or sign-in). Retrying…');
      }
    };

    this.ws.onclose = () => {
      if (!this.active) return;
      if (!openedThisAttempt && this.connectFailures === 0) {
        this.connectFailures += 1;
        this.notifyWsError('Terminal WebSocket connection closed before opening. Retrying…');
      } else if (this.openedOnce && openedThisAttempt) {
        this.notifyWsError('Terminal WebSocket disconnected, reconnecting…');
      }
      setTimeout(() => this.connect(), this.reconnectDelay);
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxDelay);
    };
  }

  send(obj: Record<string, unknown>) {
    if (obj.type === 'start_session') {
      const p = obj.payload as StartSessionPayload;
      this.activeSessions.set(p.session_id, p);
      // Send directly if open; otherwise it will be replayed on onopen.
      // Never queue start_session — onopen always replays activeSessions,
      // so queuing it too would result in a duplicate start.
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify(obj));
      }
      return;
    }
    if (obj.type === 'close_session') {
      const p = obj.payload as { session_id: string };
      this.activeSessions.delete(p.session_id);
    }

    const data = JSON.stringify(obj);
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(data);
    } else {
      this.queue.push(data);
    }
  }

  subscribe(handler: MessageHandler): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }

  get connected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  destroy() {
    this.active = false;
    this.ws?.close();
  }
}

let terminalWS: WSClient | null = null;
let userTerminalWS: WSClient | null = null;

export function getTerminalWS(userScoped = false): WSClient {
	if (userScoped) {
		if (!userTerminalWS) userTerminalWS = new WSClient('/api/aws/session-ws');
		return userTerminalWS;
	}
  if (!terminalWS) terminalWS = new WSClient('/ws');
  return terminalWS;
}
