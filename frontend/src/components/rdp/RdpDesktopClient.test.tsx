// @vitest-environment-options {"url":"https://desk.example/"}
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { RdpDesktopClient } from './RdpDesktopClient';
import { DesktopStage } from '@/rust-engines/DesktopStage';
import { useSessionsStore } from '@/stores/sessions';
import { useLayoutStore } from '@/stores/layout';

class MockWebSocket {
  static OPEN = 1;
  static instances: MockWebSocket[] = [];

  readonly url: string;
  binaryType = 'blob';
  readyState = MockWebSocket.OPEN;
  sent: string[] = [];
  closed = false;
  onmessage: ((ev: MessageEvent) => void) | null = null;
  onclose: (() => void) | null = null;

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
  }

  send(data: string) {
    this.sent.push(data);
  }

  close() {
    this.closed = true;
    this.readyState = 3;
    this.onclose?.();
  }
}

beforeEach(() => {
  MockWebSocket.instances = [];
  vi.stubGlobal('WebSocket', MockWebSocket as unknown as typeof WebSocket);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  useSessionsStore.setState({ sessions: [], activeId: null });
});

function buildOqr2HelloAckFrame(width = 1280, height = 720): ArrayBuffer {
  const traceBytes = new TextEncoder().encode('trace-1');
  const protoBytes = new TextEncoder().encode('rdp');
  const buf = new ArrayBuffer(4 + 1 + 4 + 2 + 2 + 1 + 2 + traceBytes.length + 2 + protoBytes.length);
  const view = new DataView(buf);
  const bytes = new Uint8Array(buf);
  bytes.set([0x4f, 0x51, 0x52, 0x32], 0); // "OQR2"
  let off = 4;
  view.setUint8(off++, 0x01); // HelloAck
  view.setUint32(off, 1, true);
  off += 4;
  view.setUint16(off, width, true);
  off += 2;
  view.setUint16(off, height, true);
  off += 2;
  view.setUint8(off++, 1);
  view.setUint16(off, traceBytes.length, true);
  off += 2;
  bytes.set(traceBytes, off);
  off += traceBytes.length;
  view.setUint16(off, protoBytes.length, true);
  off += 2;
  bytes.set(protoBytes, off);
  return buf;
}

function buildOqr2SolidFillFrame(): ArrayBuffer {
  const buf = new ArrayBuffer(4 + 1 + 4 + 4 + 2 + 2 + 2 + 2 + 4);
  const view = new DataView(buf);
  const bytes = new Uint8Array(buf);
  bytes.set([0x4f, 0x51, 0x52, 0x32], 0); // "OQR2"
  let off = 4;
  view.setUint8(off++, 0x04); // SolidFill
  view.setUint32(off, 2, true);
  off += 4;
  view.setInt32(off, 0, true);
  off += 4;
  view.setUint16(off, 0, true);
  off += 2;
  view.setUint16(off, 0, true);
  off += 2;
  view.setUint16(off, 64, true);
  off += 2;
  view.setUint16(off, 64, true);
  off += 2;
  view.setUint8(off++, 12);
  view.setUint8(off++, 34);
  view.setUint8(off++, 56);
  view.setUint8(off++, 255);
  return buf;
}

it('connects once with a single /api/v1/ws/rdp prefix, stays connecting until first frame, and marks connected on SolidFill', () => {
  useSessionsStore.setState({
    sessions: [
      { id: 'rdp-1', type: 'rdp', instanceId: 'i-1', instanceName: 'Windows', status: 'connecting', createdAt: 0 },
    ],
  });

  const onEnded = vi.fn();
  const { unmount } = render(
    <RdpDesktopClient sessionId="rdp-1" token="opaque-ticket" targetHost="win2025.internal" onSessionEnded={onEnded} />,
  );

  expect(MockWebSocket.instances).toHaveLength(1);
  const ws = MockWebSocket.instances[0];
  const parsed = new URL(ws.url);
  expect(parsed.origin + parsed.pathname).toBe('https://desk.example/api/v1/ws/rdp'.replace('https:', 'wss:'));
  expect(parsed.searchParams.get('ticket')).toBe('opaque-ticket');
  expect(parsed.searchParams.get('transport')).toBe('oqr2');
  expect(Number(parsed.searchParams.get('width'))).toBeGreaterThanOrEqual(200);
  expect(Number(parsed.searchParams.get('height'))).toBeGreaterThanOrEqual(200);
  expect(ws.url.match(/\/api\/v1\/ws\/rdp/g)).toHaveLength(1);
  expect(ws.binaryType).toBe('arraybuffer');
  expect(useSessionsStore.getState().sessions[0]?.status).toBe('connecting');

  act(() => {
    ws.onmessage?.(new MessageEvent('message', { data: buildOqr2HelloAckFrame(1280, 720) }));
  });
  expect(useSessionsStore.getState().sessions[0]?.status).toBe('connecting');

  act(() => {
    ws.onmessage?.(new MessageEvent('message', { data: buildOqr2SolidFillFrame() }));
  });
  expect(useSessionsStore.getState().sessions[0]?.status).toBe('connected');
  expect(screen.getByText(/rdp Session · win2025\.internal/i)).toBeInTheDocument();
  expect(screen.getByLabelText('Live telemetry HUD')).toBeInTheDocument();

  act(() => {
    ws.onmessage?.(
      new MessageEvent('message', { data: JSON.stringify({ type: 'session_ended', reason: 'remote_logout' }) }),
    );
  });
  expect(onEnded).toHaveBeenCalledWith('remote_logout');

  unmount();
  expect(ws.closed).toBe(true);
});

it('shows progress bar overlay in embedded mode and hides it on first rendered frame', () => {
  render(<RdpDesktopClient sessionId="rdp-emb" token="t-emb" userScoped />);
  const ws = MockWebSocket.instances[0];
  expect(screen.getByRole('progressbar', { name: /Remote desktop connection progress/i })).toBeInTheDocument();

  act(() => {
    ws.onmessage?.(
      new MessageEvent('message', {
        data: JSON.stringify({ type: 'progress', stage: 'rdp', label: 'Authenticating Windows session', percent: 65 }),
      }),
    );
  });
  expect(screen.getByText('Authenticating Windows session')).toBeInTheDocument();

  act(() => {
    ws.onmessage?.(new MessageEvent('message', { data: buildOqr2SolidFillFrame() }));
  });
  expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
});

it('displays server error frames and avoids double-prefixing full wss:// DesktopStage URLs', () => {
  const onBack = vi.fn();
  render(
    <DesktopStage
      protocol="rdp"
      targetHost="edge.internal"
      wsUrl="wss://edge.desk.example/api/v1/ws/rdp?ticket=t-1&transport=oqr2"
      onBackToSettings={onBack}
    />,
  );

  expect(MockWebSocket.instances).toHaveLength(1);
  const ws = MockWebSocket.instances[0];
  const parsed = new URL(ws.url);
  expect(parsed.origin + parsed.pathname).toBe('wss://edge.desk.example/api/v1/ws/rdp');
  expect(parsed.searchParams.get('ticket')).toBe('t-1');
  expect(parsed.searchParams.get('transport')).toBe('oqr2');
  expect(Number(parsed.searchParams.get('width'))).toBeGreaterThanOrEqual(200);
  expect(Number(parsed.searchParams.get('height'))).toBeGreaterThanOrEqual(200);

  act(() => {
    ws.onmessage?.(
      new MessageEvent('message', {
        data: JSON.stringify({ type: 'error', error: 'TLS verification failed' }),
      }),
    );
  });

  expect(screen.getByRole('alert')).toHaveTextContent('TLS verification failed');
});

it('forwards keyboard, mouse click, and wheel events on the canvas and opens settings on Back', () => {
  const openSettingsSpy = vi.spyOn(useLayoutStore.getState(), 'openSettings');
  render(<RdpDesktopClient sessionId="rdp-2" token="ticket-2" targetHost="10.0.1.25" />);

  const ws = MockWebSocket.instances[0];
  const canvas = screen.getByLabelText('Interactive RDP desktop canvas');
  fireEvent.keyDown(canvas, { key: 'a' });
  expect(ws.sent).toContain(JSON.stringify({ type: 'key', keysym: 97, pressed: true }));

  fireEvent.mouseDown(canvas, { button: 0, buttons: 1 });
  fireEvent.mouseUp(canvas, { button: 0, buttons: 0 });
  fireEvent.wheel(canvas, { deltaY: -120 });
  fireEvent.wheel(canvas, { deltaY: 120 });

  const pointerMsgs = ws.sent
    .map((s) => JSON.parse(s) as { type: string; button_mask?: number })
    .filter((m) => m.type === 'pointer');
  expect(pointerMsgs.map((m) => m.button_mask)).toEqual([1, 0, 8, 16]);

  fireEvent.click(screen.getByRole('button', { name: /Back to Settings/i }));
  expect(openSettingsSpy).toHaveBeenCalledWith('remote-desktop');
  openSettingsSpy.mockRestore();
});

it('surfaces an error alert when the WebSocket closes before handshake completes', () => {
  render(<RdpDesktopClient sessionId="rdp-3" token="ticket-3" targetHost="10.0.1.26" />);
  const ws = MockWebSocket.instances[0];

  act(() => {
    ws.onclose?.();
  });

  expect(screen.getByRole('alert')).toHaveTextContent('closed before handshake completed');
});

it('debounces ResizeObserver container changes into dynamic resize WebSocket frames', () => {
  vi.useFakeTimers();
  let roCallback: ((entries: Array<{ contentRect: { width: number; height: number } }>) => void) | null = null;
  class FakeResizeObserver {
    constructor(cb: (entries: Array<{ contentRect: { width: number; height: number } }>) => void) {
      roCallback = cb;
    }
    observe() {}
    disconnect() {}
  }
  vi.stubGlobal('ResizeObserver', FakeResizeObserver);

  render(<RdpDesktopClient sessionId="rdp-4" token="ticket-4" userScoped />);
  const ws = MockWebSocket.instances[0];

  act(() => {
    roCallback?.([{ contentRect: { width: 1441, height: 900 } }]);
    vi.advanceTimersByTime(300);
  });

  expect(ws.sent).toContain(JSON.stringify({ type: 'resize', width: 1440, height: 900 }));
  vi.useRealTimers();
});
