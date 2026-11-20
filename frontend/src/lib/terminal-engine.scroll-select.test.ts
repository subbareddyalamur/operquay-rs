import fs from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { WasmTerminalDriver } from '@/rust-engines/wasmTerminal';
import { createTerminalAdapter } from './terminal-engine';

const wasmPath = path.resolve(__dirname, '../../public/operquay_term.wasm');
const wasmBytes = fs.readFileSync(wasmPath);

function createMockCtx() {
  const filledRects: Array<{ fillStyle: string; x: number; y: number; w: number; h: number }> = [];
  const drawnText: Array<{ text: string; x: number; y: number }> = [];
  const ctx: Record<string, unknown> = {
    fillStyle: '#000000',
    font: '13px monospace',
    textBaseline: 'top',
    globalAlpha: 1,
    save: vi.fn(),
    restore: vi.fn(),
    scale: vi.fn(),
    measureText: vi.fn(() => ({ width: 84 })),
    fillRect: vi.fn((x: number, y: number, w: number, h: number) => {
      filledRects.push({ fillStyle: String(ctx.fillStyle), x, y, w, h });
    }),
    fillText: vi.fn((text: string, x: number, y: number) => {
      drawnText.push({ text, x, y });
    }),
  };
  return { ctx, filledRects, drawnText };
}

describe('SSH/K8s terminal keyboard encoding, IRM rendering, scrollback, and copy/paste', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'ResizeObserver',
      class {
        observe() {}
        disconnect() {}
      },
    );
    vi.stubGlobal('requestAnimationFrame', (cb: FrameRequestCallback) => {
      cb(0);
      return 1;
    });
    vi.stubGlobal('cancelAnimationFrame', vi.fn());
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => ({
        ok: true,
        status: 200,
        arrayBuffer: async () => wasmBytes.buffer.slice(wasmBytes.byteOffset, wasmBytes.byteOffset + wasmBytes.byteLength),
      })),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('encodes Shift+S, Shift+Tab, Ctrl+Arrow, Ctrl+[, F5, AltGraph, and macOS Option meta keys cleanly', async () => {
    const driver = await WasmTerminalDriver.create(40, 10, 200, wasmBytes);

    expect(driver.encodeKey('S', false, false, true, 'KeyS', false)).toBe('S');
    expect(driver.encodeKey('Tab', false, false, true, 'Tab', false)).toBe('\x1b[Z');
    expect(driver.encodeKey('ArrowRight', true, false, false, 'ArrowRight', false)).toBe('\x1b[1;5C');
    expect(driver.encodeKey('[', true, false, false, 'BracketLeft', false)).toBe('\x1b');
    expect(driver.encodeKey('F5', false, false, false, 'F5', false)).toBe('\x1b[15~');
    expect(driver.encodeKey('F5', false, false, true, 'F5', false)).toBe('\x1b[15;2~');
    expect(driver.encodeKey('Dead', false, false, false, 'KeyE', false)).toBe('');
    expect(driver.encodeKey('@', false, true, false, 'KeyQ', true)).toBe('@');

    const origNav = globalThis.navigator;
    Object.defineProperty(globalThis, 'navigator', {
      value: { platform: 'MacIntel', userAgent: 'Mozilla/5.0 (Macintosh)' },
      configurable: true,
    });
    try {
      expect(driver.encodeKey('∫', false, true, false, 'KeyB', false)).toBe('\x1bb');
      expect(driver.encodeKey('£', false, true, false, 'Digit3', false)).toBe('£');
    } finally {
      Object.defineProperty(globalThis, 'navigator', { value: origNav, configurable: true });
    }

    // Verify real Rust WASM IRM insert mode preserves text instead of deleting/overwriting
    driver.feed('hello world\x1b[5D\x1b[4hS\x1b[4l');
    expect(driver.plainText()).toContain('hello Sworld');
    driver.dispose();
  });

  it('supports wheel scrollback, Shift+PageUp/End, jump-to-bottom pill, drag/word/line selection, and copy/paste', async () => {
    const mock2d = createMockCtx();
    vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockReturnValue(mock2d.ctx as unknown as CanvasRenderingContext2D);

    const writeClipboard = vi.fn(async () => {});
    const readClipboard = vi.fn(async () => 'from-clipboard');
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText: writeClipboard, readText: readClipboard },
      configurable: true,
    });

    const container = document.createElement('div');
    document.body.appendChild(container);
    Object.defineProperty(container, 'clientWidth', { value: 420, configurable: true });
    Object.defineProperty(container, 'clientHeight', { value: 140, configurable: true });

    const sentData: string[] = [];
    const resizes: Array<[number, number]> = [];
    const adapter = createTerminalAdapter({
      engine: 'wasm',
      container,
      fontFamily: 'JetBrains Mono',
      fontSize: 13,
      scrollbackLines: 500,
      onData: (d) => sentData.push(d),
      onResize: (c, r) => resizes.push([c, r]),
    });

    await adapter.init();
    expect(resizes.length).toBeGreaterThanOrEqual(1);

    // Populate >15 lines so scrollback accumulates
    for (let i = 1; i <= 20; i++) {
      adapter.write(`row-${String(i).padStart(2, '0')} alpha_token beta\r\n`);
    }

    const wrapper = container.querySelector('[data-terminal-wrapper="true"]') as HTMLDivElement;
    const canvas = container.querySelector('canvas') as HTMLCanvasElement;
    expect(wrapper).toBeTruthy();
    vi.spyOn(canvas, 'getBoundingClientRect').mockReturnValue({
      left: 0,
      top: 0,
      right: 400,
      bottom: 130,
      width: 400,
      height: 130,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    });

    // Shift+S forwards uppercase 'S' without mangling
    wrapper.dispatchEvent(new KeyboardEvent('keydown', { key: 'S', code: 'KeyS', shiftKey: true, bubbles: true }));
    expect(sentData).toContain('S');

    // Wheel up scrolls back into history & reveals bottom jump button
    wrapper.dispatchEvent(new WheelEvent('wheel', { deltaY: -60, deltaMode: 0, bubbles: true, cancelable: true }));
    const jumpBtn = container.querySelector('button[aria-label="Jump to bottom of terminal output"]') as HTMLButtonElement;
    expect(jumpBtn.style.display).toBe('block');

    // Clicking bottom button snaps back to live viewport
    jumpBtn.click();
    expect(jumpBtn.style.display).toBe('none');

    // Shift+PageUp then Shift+End scrolls up & down
    wrapper.dispatchEvent(new KeyboardEvent('keydown', { key: 'PageUp', shiftKey: true, bubbles: true }));
    expect(jumpBtn.style.display).toBe('block');
    wrapper.dispatchEvent(new KeyboardEvent('keydown', { key: 'End', shiftKey: true, bubbles: true }));
    expect(jumpBtn.style.display).toBe('none');

    // Drag selection across col 0..5 on row 0 selects characters cleanly & Cmd+C copies
    wrapper.dispatchEvent(new MouseEvent('mousedown', { button: 0, clientX: 2, clientY: 2, detail: 1, bubbles: true }));
    window.dispatchEvent(new MouseEvent('mousemove', { clientX: 52, clientY: 2, bubbles: true }));
    window.dispatchEvent(new MouseEvent('mouseup', { button: 0, clientX: 52, clientY: 2, detail: 1, bubbles: true }));
    expect(adapter.getSelection().length).toBeGreaterThanOrEqual(4);

    wrapper.dispatchEvent(new KeyboardEvent('keydown', { key: 'c', metaKey: true, bubbles: true }));
    expect(writeClipboard).toHaveBeenCalledWith(adapter.getSelection());

    // Double-click word selection selects word token ("row-xx" or "alpha_token")
    adapter.write('\x1b[2J\x1b[Hselect alpha_token end');
    wrapper.dispatchEvent(new MouseEvent('mousedown', { button: 0, clientX: 70, clientY: 2, detail: 2, bubbles: true }));
    expect(adapter.getSelection()).toBe('alpha_token');

    // Triple-click line selection selects the entire line
    wrapper.dispatchEvent(new MouseEvent('mousedown', { button: 0, clientX: 10, clientY: 2, detail: 3, bubbles: true }));
    expect(adapter.getSelection()).toBe('select alpha_token end');

    // Ctrl+Shift+V pastes once via clipboard API
    wrapper.dispatchEvent(new KeyboardEvent('keydown', { key: 'V', ctrlKey: true, shiftKey: true, bubbles: true }));
    await Promise.resolve();
    expect(sentData).toContain('from-clipboard');

    // Identical rapid paste within dedupe window is ignored
    const countBefore = sentData.length;
    adapter.paste('dup-payload');
    adapter.paste('dup-payload');
    expect(sentData.length).toBe(countBefore + 1);

    adapter.dispose();
    container.remove();
  });
});
