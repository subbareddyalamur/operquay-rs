import { act, cleanup, render } from '@testing-library/react';
import { afterEach, expect, it, vi } from 'vitest';
import type { TerminalAdapterOptions, TerminalEngineKind } from '@/lib/terminal-engine';

interface MockAdapterInstance {
  readonly engine: TerminalEngineKind;
  cols: number;
  rows: number;
  options: TerminalAdapterOptions;
  queuedWrites: string[];
  flushedWrites: string[];
  initialized: boolean;
  init: ReturnType<typeof vi.fn>;
  write: ReturnType<typeof vi.fn>;
  focus: ReturnType<typeof vi.fn>;
  fit: ReturnType<typeof vi.fn>;
  paste: ReturnType<typeof vi.fn>;
  getSelection: ReturnType<typeof vi.fn>;
  search: ReturnType<typeof vi.fn>;
  searchNext: ReturnType<typeof vi.fn>;
  searchPrevious: ReturnType<typeof vi.fn>;
  clearSearch: ReturnType<typeof vi.fn>;
  serialize: ReturnType<typeof vi.fn>;
  serializeAsync: ReturnType<typeof vi.fn>;
  setAppearance: ReturnType<typeof vi.fn>;
  setTheme: ReturnType<typeof vi.fn>;
  setScrollbackLines: ReturnType<typeof vi.fn>;
  dispose: ReturnType<typeof vi.fn>;
}

const mocks = vi.hoisted(() => ({
  adapters: [] as MockAdapterInstance[],
  initBehavior: 'resolve' as 'resolve' | 'defer' | 'fallback',
  pendingInits: [] as Array<{ resolve: () => void }>,
  send: vi.fn(),
  subscriber: null as ((message: unknown) => void) | null,
}));

vi.hoisted(() => {
  window.matchMedia = () =>
    ({ matches: false, addEventListener() {}, removeEventListener() {} }) as unknown as MediaQueryList;
});

vi.mock('@/lib/terminal-engine', () => ({
  normalizeTerminalEngine: (value: unknown): TerminalEngineKind => {
    if (value === 'wterm') return 'wterm';
    if (value === 'wasm') return 'wasm';
    return 'xterm';
  },
  createTerminalAdapter: (options: TerminalAdapterOptions): MockAdapterInstance => {
    const adapter: MockAdapterInstance = {
      engine: options.engine,
      cols: 80,
      rows: 24,
      options,
      queuedWrites: [],
      flushedWrites: [],
      initialized: false,
      init: vi.fn(async () => {
        if (mocks.initBehavior === 'fallback') {
          options.onFallback?.(new Error('wasm blocked'));
          return;
        }
        if (mocks.initBehavior === 'defer') {
          await new Promise<void>((resolve) => {
            mocks.pendingInits.push({
              resolve: () => {
                adapter.initialized = true;
                for (const chunk of adapter.queuedWrites) {
                  adapter.flushedWrites.push(chunk);
                }
                adapter.queuedWrites.length = 0;
                resolve();
              },
            });
          });
          return;
        }
        adapter.initialized = true;
        for (const chunk of adapter.queuedWrites) {
          adapter.flushedWrites.push(chunk);
        }
        adapter.queuedWrites.length = 0;
      }),
      write: vi.fn((data: string) => {
        if (!adapter.initialized) {
          adapter.queuedWrites.push(data);
        } else {
          adapter.flushedWrites.push(data);
        }
      }),
      focus: vi.fn(),
      fit: vi.fn(),
      paste: vi.fn(),
      getSelection: vi.fn(() => ''),
      search: vi.fn(() => false),
      searchNext: vi.fn(() => false),
      searchPrevious: vi.fn(() => false),
      clearSearch: vi.fn(),
      serialize: vi.fn(() => `${options.engine}-buffer-snapshot`),
      serializeAsync: vi.fn(async () => `${options.engine}-buffer-snapshot`),
      setAppearance: vi.fn(),
      setTheme: vi.fn(),
      setScrollbackLines: vi.fn(),
      dispose: vi.fn(),
    };
    mocks.adapters.push(adapter);
    return adapter;
  },
}));

vi.mock('@/lib/ws', () => ({
  getTerminalWS: () => ({
    send: mocks.send,
    subscribe: (fn: (message: unknown) => void) => {
      mocks.subscriber = fn;
      return () => {};
    },
  }),
}));

vi.stubGlobal('ResizeObserver', class { observe() {} disconnect() {} });

import { Xterm } from './Xterm';
import { useSettingsStore } from '@/stores/settings';
import { useToastStore } from '@/stores/toast';

async function flushMicrotasks(rounds = 8) {
  for (let i = 0; i < rounds; i++) {
    await Promise.resolve();
  }
}

afterEach(() => {
  cleanup();
  useSettingsStore.setState({
    fontFamily: 'JetBrains Mono',
    fontSize: 13,
    scrollbackLines: 10000,
    terminalEngine: 'xterm',
  });
  useToastStore.getState().clear();
  document.documentElement.removeAttribute('style');
  document.documentElement.removeAttribute('data-theme');
  mocks.adapters.length = 0;
  mocks.pendingInits.length = 0;
  mocks.initBehavior = 'resolve';
  mocks.send.mockClear();
  mocks.subscriber = null;
});

it('updates appearance without reconnecting and passes terminal control sequences through unchanged', async () => {
  render(<Xterm instanceId="i-test" instanceName="Test" sessionId="session" userScoped />);
  await act(async () => {
    await flushMicrotasks();
  });

  const adapter = mocks.adapters[0];
  expect(mocks.send).toHaveBeenCalledTimes(1);

  act(() => useSettingsStore.setState({ fontFamily: 'Consolas', fontSize: 16 }));
  expect(adapter.setAppearance).toHaveBeenCalledWith('Consolas', 16);

  await act(async () => {
    document.documentElement.dataset.theme = 'light';
    await flushMicrotasks();
  });
  expect(adapter.setTheme).toHaveBeenCalled();

  expect(mocks.adapters).toHaveLength(1);
  expect(mocks.send).toHaveBeenCalledTimes(1);

  const raw = '\u001b[?1049h\u001b[31mhello\u001b[0m';
  act(() => {
    mocks.subscriber?.({ type: 'terminal_output', payload: { session_id: 'session', output: raw } });
  });
  expect(adapter.write).toHaveBeenCalledWith(raw);
  expect(adapter.dispose).not.toHaveBeenCalled();
});

it('applies the scrollback preference to new and open terminals', async () => {
  useSettingsStore.setState({ scrollbackLines: 5000 });
  render(<Xterm instanceId="i-test" instanceName="Test" sessionId="scroll" userScoped />);
  await act(async () => {
    await flushMicrotasks();
  });

  const adapter = mocks.adapters[0];
  expect(adapter.options.scrollbackLines).toBe(5000);

  act(() => useSettingsStore.setState({ scrollbackLines: 20000 }));
  expect(adapter.setScrollbackLines).toHaveBeenCalledWith(20000);
  expect(mocks.send).toHaveBeenCalledTimes(1);
});

it('hot-swaps terminal engines in-place without closing or restarting the WS session', async () => {
  render(<Xterm instanceId="i-test" instanceName="Test" sessionId="swap" userScoped />);
  await act(async () => {
    await flushMicrotasks();
  });
  const initialAdapter = mocks.adapters[0];
  expect(mocks.send).toHaveBeenCalledTimes(1);

  await act(async () => {
    useSettingsStore.setState({ terminalEngine: 'wterm' });
    await flushMicrotasks();
  });

  expect(initialAdapter.dispose).toHaveBeenCalledTimes(1);
  expect(mocks.adapters).toHaveLength(2);
  expect(mocks.adapters[1].engine).toBe('wterm');
  expect(mocks.adapters[1].write).toHaveBeenCalledWith('xterm-buffer-snapshot');
  expect(mocks.send).toHaveBeenCalledTimes(1);

  await act(async () => {
    useSettingsStore.setState({ terminalEngine: 'wasm' });
    await flushMicrotasks();
  });

  expect(mocks.adapters[1].dispose).toHaveBeenCalledTimes(1);
  expect(mocks.adapters).toHaveLength(3);
  expect(mocks.adapters[2].engine).toBe('wasm');
  expect(mocks.adapters[2].write).toHaveBeenCalledWith('wterm-buffer-snapshot');
  expect(mocks.send).toHaveBeenCalledTimes(1);
});

it('buffers terminal output until WASM adapter finishes initializing', async () => {
  mocks.initBehavior = 'defer';
  useSettingsStore.setState({ terminalEngine: 'wterm' });
  render(<Xterm instanceId="i-test" instanceName="Test" sessionId="queue" userScoped />);

  await act(async () => {
    await flushMicrotasks();
  });
  expect(mocks.adapters).toHaveLength(1);
  const adapter = mocks.adapters[0];

  act(() => {
    mocks.subscriber?.({ type: 'terminal_output', payload: { session_id: 'queue', output: 'chunk-1 ' } });
    mocks.subscriber?.({ type: 'terminal_output', payload: { session_id: 'queue', output: 'chunk-2' } });
  });
  expect(adapter.flushedWrites).toEqual([]);

  await act(async () => {
    mocks.pendingInits[0]?.resolve();
    await flushMicrotasks();
  });

  expect(adapter.flushedWrites).toEqual(['chunk-1 ', 'chunk-2']);
});

it('surfaces a fallback warning toast when adapter triggers onFallback', async () => {
  mocks.initBehavior = 'fallback';
  useSettingsStore.setState({ terminalEngine: 'wterm' });
  render(<Xterm instanceId="i-test" instanceName="Test" sessionId="fallback" userScoped />);

  await act(async () => {
    await flushMicrotasks();
  });

  expect(useToastStore.getState().toasts).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ variant: 'warn', title: 'Terminal fell back to xterm.js' }),
    ]),
  );
});
