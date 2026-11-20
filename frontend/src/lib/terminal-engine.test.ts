import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createTerminalAdapter, normalizeTerminalEngine } from './terminal-engine';

describe('normalizeTerminalEngine', () => {
  it('recognizes wterm, wasm, and defaults unrecognized engines to xterm', () => {
    expect(normalizeTerminalEngine('wterm')).toBe('wterm');
    expect(normalizeTerminalEngine('wasm')).toBe('wasm');
    expect(normalizeTerminalEngine('xterm')).toBe('xterm');
    expect(normalizeTerminalEngine('unknown')).toBe('xterm');
    expect(normalizeTerminalEngine(undefined)).toBe('xterm');
  });
});

describe('createTerminalAdapter', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'ResizeObserver',
      class {
        observe() { }
        disconnect() { }
      },
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('does not invoke onResize synchronously during construction before caller assignment completes', async () => {
    const container = document.createElement('div');
    Object.defineProperty(container, 'clientWidth', { value: 960, configurable: true });
    Object.defineProperty(container, 'clientHeight', { value: 480, configurable: true });
    const resizeCalls: Array<[number, number]> = [];
    const dataCalls: string[] = [];

    const next = createTerminalAdapter({
      engine: 'wasm',
      container,
      fontFamily: 'JetBrains Mono',
      fontSize: 13,
      scrollbackLines: 1000,
      onData: (data) => {
        void next;
        dataCalls.push(data);
      },
      onResize: (cols, rows) => {
        expect(next).toBeDefined();
        resizeCalls.push([cols, rows]);
      },
    });

    expect(resizeCalls).toEqual([]);
    expect(next.engine).toBe('wasm');
    next.write('early-before-init ');

    await next.init();
    next.write('after-init');
    expect(next.cols).toBeGreaterThanOrEqual(20);
    expect(next.rows).toBeGreaterThanOrEqual(5);
    expect(next.serialize()).toContain('early-before-init after-init');

    Object.defineProperty(container, 'clientWidth', { value: 1280, configurable: true });
    next.fit();
    expect(resizeCalls.length).toBeGreaterThanOrEqual(1);

    next.paste('ls -la');
    expect(dataCalls).toEqual(['ls -la']);

    next.setAppearance('Consolas', 16);
    next.dispose();
  });
});
