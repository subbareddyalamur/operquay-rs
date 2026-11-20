import {
  WasmTerminalDriver,
  type TermSearchMatch,
  type TermSnapshot,
  unpackTermColor,
} from '@/rust-engines/wasmTerminal';
import { formatTerminalFontStack, terminalSearchColors, terminalTheme } from './xterm-themes';

export type TerminalEngineKind = 'xterm' | 'wterm' | 'wasm';

/** Normalize persisted or arbitrary settings values to a supported terminal engine. */
export function normalizeTerminalEngine(value: unknown): TerminalEngineKind {
  if (value === 'wterm') return 'wterm';
  if (value === 'wasm') return 'wasm';
  return 'xterm';
}

export interface TerminalAdapterOptions {
  engine: TerminalEngineKind;
  container: HTMLElement;
  fontFamily: string;
  fontSize: number;
  scrollbackLines: number;
  onData: (data: string) => void;
  onResize: (cols: number, rows: number) => void;
  onSearchResults?: (resultIndex: number, resultCount: number) => void;
  onFallback?: (error: unknown) => void;
}

export interface TerminalAdapter {
  readonly engine: TerminalEngineKind;
  readonly cols: number;
  readonly rows: number;
  init: () => Promise<void>;
  write: (data: string) => void;
  focus: () => void;
  fit: () => void;
  paste: (data: string) => void;
  getSelection: () => string;
  scrollLines?: (deltaLines: number) => void;
  scrollToBottom?: () => void;
  search: (query: string) => boolean;
  searchNext: () => boolean;
  searchPrevious: () => boolean;
  clearSearch: () => void;
  serialize: () => string;
  serializeAsync: () => Promise<string>;
  setAppearance: (fontFamily: string, fontSize: number) => void;
  setTheme: () => void;
  setScrollbackLines: (lines: number) => void;
  dispose: () => void;
}

const UTF8_DEC = new TextDecoder();

function resolveCssColor(color: string, fallback: string): string {
  if (!color) return fallback;
  if (!color.startsWith('var(')) return color;
  const match = /^var\((--[^,)]+)/.exec(color);
  if (!match) return fallback;
  const resolved = getComputedStyle(document.documentElement).getPropertyValue(match[1]).trim();
  return resolved || fallback;
}

class WasmTerminalAdapter implements TerminalAdapter {
  readonly engine: TerminalEngineKind;
  private readonly container: HTMLElement;
  private readonly onData: (data: string) => void;
  private readonly onResize: (cols: number, rows: number) => void;
  private readonly onSearchResults?: (resultIndex: number, resultCount: number) => void;
  private readonly onFallback?: (error: unknown) => void;
  private fontFamily: string;
  private fontSize: number;
  private scrollbackLines: number;

  private driver: WasmTerminalDriver | null = null;
  private wrapper: HTMLDivElement | null = null;
  private canvas: HTMLCanvasElement | null = null;
  private scrollbarTrack: HTMLDivElement | null = null;
  private scrollbarThumb: HTMLDivElement | null = null;
  private jumpBottomBtn: HTMLButtonElement | null = null;
  private contextMenu: HTMLDivElement | null = null;
  private resizeObserver: ResizeObserver | null = null;
  private pendingWrites: string[] = [];
  private rafId = 0;
  private disposed = false;

  private _cols = 80;
  private _rows = 24;
  private cellW = 8.4;
  private cellH = 18;

  private lastQuery = '';
  private matches: TermSearchMatch[] = [];
  private activeMatchIdx = -1;
  private selectedText = '';
  private lastSnap: TermSnapshot | null = null;
  private wheelAccumPx = 0;

  private selAnchor: { absRow: number; col: number } | null = null;
  private selFocus: { absRow: number; col: number } | null = null;
  private dragPending = false;
  private dragActive = false;
  private dragOriginX = 0;
  private dragOriginY = 0;
  private dragAutoScrollTimer = 0;
  private dragLastClientY = 0;
  private dragLastClientX = 0;

  private scrollbarDragging = false;
  private scrollbarDragStartY = 0;
  private scrollbarDragStartScroll = 0;
  private lastPasteAt = 0;
  private lastPasteText = '';

  constructor(options: TerminalAdapterOptions) {
    this.engine = options.engine;
    this.container = options.container;
    this.fontFamily = formatTerminalFontStack(options.fontFamily || 'JetBrains Mono');
    this.fontSize = Math.max(10, Math.min(28, options.fontSize || 13));
    this.scrollbackLines = Math.max(100, options.scrollbackLines || 5000);
    this.onData = options.onData;
    this.onResize = options.onResize;
    this.onSearchResults = options.onSearchResults;
    this.onFallback = options.onFallback;
  }

  get cols(): number {
    return this._cols;
  }

  get rows(): number {
    return this._rows;
  }

  private measureCell(): void {
    const fallbackW = Math.max(6, this.fontSize * 0.6);
    try {
      const c = document.createElement('canvas');
      const ctx = c.getContext('2d');
      if (ctx) {
        ctx.font = `${this.fontSize}px ${this.fontFamily}`;
        const m = ctx.measureText('MMMMMMMMMM');
        this.cellW = Math.max(5, m.width / 10);
      } else {
        this.cellW = fallbackW;
      }
    } catch {
      this.cellW = fallbackW;
    }
    this.cellH = Math.max(12, Math.ceil(this.fontSize * 1.45));
  }

  private computeGrid(): { cols: number; rows: number } {
    const cw = this.canvas?.clientWidth || Math.max(1, (this.container.clientWidth || 800) - 18);
    const ch = this.canvas?.clientHeight || Math.max(1, (this.container.clientHeight || 420) - 8);
    const cols = Math.max(20, Math.floor(cw / this.cellW));
    const rows = Math.max(5, Math.floor(ch / this.cellH));
    return { cols, rows };
  }

  async init(): Promise<void> {
    if (this.disposed) return;

    if (typeof document !== 'undefined' && 'fonts' in document && typeof document.fonts?.load === 'function') {
      await document.fonts.load(`${this.fontSize}px ${this.fontFamily}`).catch(() => []);
    }
    if (this.disposed) return;

    this.measureCell();
    const { cols, rows } = this.computeGrid();
    this._cols = cols;
    this._rows = rows;

    const wrapper = document.createElement('div');
    wrapper.tabIndex = 0;
    wrapper.dataset.terminalWrapper = 'true';
    wrapper.className = 'w-full h-full relative overflow-hidden outline-none select-none';
    wrapper.style.padding = '4px 12px 4px 6px';
    wrapper.style.background = 'var(--term-bg, var(--bg))';
    wrapper.style.cursor = 'text';
    wrapper.setAttribute('role', 'textbox');
    wrapper.setAttribute('aria-label', 'Terminal');

    const canvas = document.createElement('canvas');
    canvas.className = 'block w-full h-full';
    wrapper.appendChild(canvas);

    const scrollbarTrack = document.createElement('div');
    scrollbarTrack.setAttribute('data-terminal-scrollbar', 'true');
    scrollbarTrack.style.cssText =
      'position:absolute;top:4px;right:2px;bottom:4px;width:8px;border-radius:9999px;background:rgba(148,163,184,0.08);cursor:default;display:none;z-index:10;';
    const scrollbarThumb = document.createElement('div');
    scrollbarThumb.setAttribute('data-terminal-thumb', 'true');
    scrollbarThumb.style.cssText =
      'position:absolute;left:1px;right:1px;min-height:24px;border-radius:9999px;background:rgba(148,163,184,0.45);transition:background 0.15s;cursor:pointer;';
    scrollbarTrack.appendChild(scrollbarThumb);
    wrapper.appendChild(scrollbarTrack);

    const jumpBottomBtn = document.createElement('button');
    jumpBottomBtn.type = 'button';
    jumpBottomBtn.textContent = '↓ Bottom';
    jumpBottomBtn.setAttribute('aria-label', 'Jump to bottom of terminal output');
    jumpBottomBtn.style.cssText =
      'position:absolute;right:18px;bottom:10px;padding:3px 10px;font-size:11px;line-height:1.4;font-weight:500;color:#e2e8f0;background:rgba(15,23,42,0.92);border:1px solid rgba(56,189,248,0.45);border-radius:9999px;box-shadow:0 4px 12px rgba(0,0,0,0.4);cursor:pointer;display:none;z-index:15;';
    jumpBottomBtn.addEventListener('click', (ev) => {
      ev.stopPropagation();
      this.scrollToBottom();
      this.focus();
    });
    wrapper.appendChild(jumpBottomBtn);

    this.container.replaceChildren(wrapper);
    this.wrapper = wrapper;
    this.canvas = canvas;
    this.scrollbarTrack = scrollbarTrack;
    this.scrollbarThumb = scrollbarThumb;
    this.jumpBottomBtn = jumpBottomBtn;

    wrapper.addEventListener('keydown', this.handleKeyDown);
    wrapper.addEventListener('paste', this.handlePaste);
    wrapper.addEventListener('copy', this.handleCopy);
    wrapper.addEventListener('wheel', this.handleWheel, { passive: false });
    wrapper.addEventListener('mousedown', this.handleMouseDown);
    wrapper.addEventListener('contextmenu', this.handleContextMenu);
    scrollbarTrack.addEventListener('mousedown', this.handleScrollbarMouseDown);
    window.addEventListener('mousemove', this.handleWindowMouseMove);
    window.addEventListener('mouseup', this.handleWindowMouseUp);
    window.addEventListener('mousedown', this.handleGlobalDismissMenu);

    if (typeof ResizeObserver !== 'undefined') {
      this.resizeObserver = new ResizeObserver(() => this.fit());
      this.resizeObserver.observe(this.container);
    }

    try {
      this.driver = await WasmTerminalDriver.create(cols, rows, this.scrollbackLines);
    } catch (err) {
      this.onFallback?.(err);
      return;
    }
    if (this.disposed) {
      this.driver.dispose();
      this.driver = null;
      return;
    }

    if (this.pendingWrites.length > 0) {
      for (const chunk of this.pendingWrites) {
        this.feedDriver(chunk);
      }
      this.pendingWrites = [];
    }

    this.fit();
    this.onResize(this._cols, this._rows);
    this.scheduleRender();
  }

  private feedDriver(data: string): void {
    if (!this.driver) return;
    const reply = this.driver.feed(data);
    if (reply.length > 0) {
      this.onData(UTF8_DEC.decode(reply));
    }
  }

  private emitPaste(text: string): void {
    if (!text || !this.driver || this.disposed) return;
    const now = Date.now();
    if (now - this.lastPasteAt < 80 && text === this.lastPasteText) return;
    this.lastPasteAt = now;
    this.lastPasteText = text;
    this.scrollToBottom();
    this.onData(this.driver.encodePaste(text));
  }

  private handleKeyDown = (e: KeyboardEvent): void => {
    if (!this.driver || this.disposed) return;
    if (e.isComposing || e.keyCode === 229 || e.key === 'Dead' || e.key === 'Process') {
      return;
    }
    const lowerKey = e.key.toLowerCase();

    // Copy selected text: Cmd+C (macOS) or Ctrl+Shift+C (Linux/Windows)
    if (
      ((e.metaKey && !e.ctrlKey && !e.altKey) || (e.ctrlKey && e.shiftKey && !e.altKey)) &&
      lowerKey === 'c'
    ) {
      const sel = this.getNormalizedSelectionText();
      if (sel) {
        e.preventDefault();
        e.stopPropagation();
        void this.copyTextToClipboard(sel);
        return;
      }
      if (e.metaKey) return;
    }

    // Paste: Ctrl+Shift+V uses Clipboard API directly; Cmd+V prefers native paste event with 50ms fallback
    if (e.ctrlKey && e.shiftKey && !e.altKey && !e.metaKey && lowerKey === 'v') {
      if (typeof navigator !== 'undefined' && typeof navigator.clipboard?.readText === 'function') {
        e.preventDefault();
        e.stopPropagation();
        void navigator.clipboard
          .readText()
          .then((text) => {
            if (text) this.emitPaste(text);
          })
          .catch(() => {});
        return;
      }
      return;
    }
    if (e.metaKey && !e.ctrlKey && !e.altKey && lowerKey === 'v') {
      const triggerAt = Date.now();
      window.setTimeout(() => {
        if (
          !this.disposed &&
          this.lastPasteAt < triggerAt &&
          typeof navigator !== 'undefined' &&
          typeof navigator.clipboard?.readText === 'function'
        ) {
          void navigator.clipboard
            .readText()
            .then((text) => {
              if (text && this.lastPasteAt < triggerAt) {
                this.emitPaste(text);
              }
            })
            .catch(() => {});
        }
      }, 50);
      return;
    }

    // Select All in terminal buffer: Cmd+A or Ctrl+Shift+A
    if (
      ((e.metaKey && !e.ctrlKey && !e.altKey) || (e.ctrlKey && e.shiftKey && !e.altKey)) &&
      lowerKey === 'a'
    ) {
      e.preventDefault();
      e.stopPropagation();
      this.selectAll();
      return;
    }

    // Keyboard scrollback shortcuts: Shift+PageUp / Shift+PageDown / Shift+Home / Shift+End
    if (e.shiftKey && !e.ctrlKey && !e.altKey && !e.metaKey) {
      if (e.key === 'PageUp') {
        e.preventDefault();
        e.stopPropagation();
        this.scrollLines(Math.max(1, this._rows - 1));
        return;
      }
      if (e.key === 'PageDown') {
        e.preventDefault();
        e.stopPropagation();
        this.scrollLines(-Math.max(1, this._rows - 1));
        return;
      }
      if (e.key === 'Home') {
        e.preventDefault();
        e.stopPropagation();
        const sb = this.lastSnap?.scrollbackLen ?? 0;
        this.driver.setViewportScroll(sb);
        this.scheduleRender();
        return;
      }
      if (e.key === 'End') {
        e.preventDefault();
        e.stopPropagation();
        this.scrollToBottom();
        return;
      }
    }

    if (e.metaKey && !e.ctrlKey && !e.altKey) {
      return;
    }
    if (e.key === 'Shift' || e.key === 'Control' || e.key === 'Alt' || e.key === 'Meta' || e.key === 'CapsLock') {
      return;
    }
    const altGraph = typeof e.getModifierState === 'function' ? e.getModifierState('AltGraph') : false;
    const seq = this.driver.encodeKey(e.key, e.ctrlKey, e.altKey, e.shiftKey, e.code, altGraph);
    if (seq) {
      e.preventDefault();
      e.stopPropagation();
      this.clearSelection();
      if ((this.lastSnap?.viewportScroll ?? 0) > 0) {
        this.driver.setViewportScroll(0);
        this.scheduleRender();
      }
      this.onData(seq);
    }
  };

  private handlePaste = (e: ClipboardEvent): void => {
    if (!this.driver || this.disposed) return;
    const text = e.clipboardData?.getData('text/plain');
    if (text) {
      e.preventDefault();
      this.emitPaste(text);
    }
  };

  private handleCopy = (e: ClipboardEvent): void => {
    const sel = this.getNormalizedSelectionText();
    if (!sel) return;
    if (e.clipboardData) {
      e.preventDefault();
      e.clipboardData.setData('text/plain', sel);
    }
  };

  private handleWheel = (e: WheelEvent): void => {
    if (!this.driver || this.disposed) return;
    e.preventDefault();
    e.stopPropagation();
    this.closeContextMenu();

    let deltaLines = 0;
    if (e.deltaMode === 1) {
      deltaLines = Math.trunc(-e.deltaY);
      if (deltaLines === 0 && e.deltaY !== 0) {
        deltaLines = e.deltaY < 0 ? 1 : -1;
      }
    } else if (e.deltaMode === 2) {
      deltaLines = Math.trunc(-e.deltaY * this._rows);
    } else {
      const incoming = -e.deltaY;
      if (this.wheelAccumPx !== 0 && Math.sign(incoming) !== Math.sign(this.wheelAccumPx)) {
        this.wheelAccumPx = 0;
      }
      this.wheelAccumPx += incoming;
      const linePx = Math.max(10, this.cellH);
      deltaLines = Math.trunc(this.wheelAccumPx / linePx);
      this.wheelAccumPx -= deltaLines * linePx;
    }
    if (deltaLines === 0) return;

    if (this.lastSnap?.altScreen) {
      const steps = Math.min(8, Math.abs(deltaLines));
      const key = deltaLines > 0 ? 'ArrowUp' : 'ArrowDown';
      const seq = this.driver.encodeKey(key, false, false);
      if (seq) {
        this.onData(seq.repeat(steps));
      }
      return;
    }

    this.driver.scrollViewport(deltaLines);
    this.scheduleRender();
  };

  private eventToCell(clientX: number, clientY: number): { absRow: number; col: number } {
    const rect = this.canvas?.getBoundingClientRect() ?? this.wrapper?.getBoundingClientRect();
    const x = rect ? clientX - rect.left : 0;
    const y = rect ? clientY - rect.top : 0;
    const col = Math.max(0, Math.min(this._cols - 1, Math.floor(x / this.cellW)));
    const viewRow = Math.max(0, Math.min(this._rows - 1, Math.floor(y / this.cellH)));
    const sbLen = this.lastSnap?.scrollbackLen ?? 0;
    const vpScroll = this.lastSnap?.viewportScroll ?? 0;
    const visibleStart = Math.max(0, sbLen - vpScroll);
    return { absRow: visibleStart + viewRow, col };
  }

  private snapForWordAt(absRow: number, col: number): { startCol: number; endCol: number } {
    const snap = this.lastSnap;
    if (!snap) return { startCol: col, endCol: col };
    const visibleStart = Math.max(0, snap.scrollbackLen - snap.viewportScroll);
    const viewRow = absRow - visibleStart;
    if (viewRow < 0 || viewRow >= snap.rows) {
      return { startCol: col, endCol: col };
    }
    const isWordChar = (ch: string) => ch !== ' ' && !/[\s"'`()[\]{}<>,;|]/.test(ch);
    const getCh = (c: number) => snap.cells[viewRow * snap.cols + c]?.ch ?? ' ';
    if (!isWordChar(getCh(col))) {
      return { startCol: col, endCol: col };
    }
    let startCol = col;
    while (startCol > 0 && isWordChar(getCh(startCol - 1))) {
      startCol--;
    }
    let endCol = col;
    while (endCol < snap.cols - 1 && isWordChar(getCh(endCol + 1))) {
      endCol++;
    }
    return { startCol, endCol };
  }

  private handleMouseDown = (e: MouseEvent): void => {
    if (this.disposed) return;
    if (
      e.target instanceof Node &&
      (this.scrollbarTrack?.contains(e.target) ||
        this.jumpBottomBtn?.contains(e.target) ||
        this.contextMenu?.contains(e.target))
    ) {
      return;
    }
    this.closeContextMenu();
    this.wrapper?.focus();
    if (e.button !== 0 || !this.driver) return;

    const pos = this.eventToCell(e.clientX, e.clientY);
    if (e.detail === 2) {
      e.preventDefault();
      const { startCol, endCol } = this.snapForWordAt(pos.absRow, pos.col);
      this.selAnchor = { absRow: pos.absRow, col: startCol };
      this.selFocus = { absRow: pos.absRow, col: endCol };
      this.dragPending = false;
      this.dragActive = false;
      this.syncSelectedText();
      this.scheduleRender();
      return;
    }
    if (e.detail >= 3) {
      e.preventDefault();
      this.selAnchor = { absRow: pos.absRow, col: 0 };
      this.selFocus = { absRow: pos.absRow, col: Math.max(0, this._cols - 1) };
      this.dragPending = false;
      this.dragActive = false;
      this.syncSelectedText();
      this.scheduleRender();
      return;
    }

    if (e.shiftKey && this.selAnchor) {
      e.preventDefault();
      this.selFocus = pos;
      this.syncSelectedText();
      this.scheduleRender();
      return;
    }

    this.selAnchor = pos;
    this.selFocus = pos;
    this.dragPending = true;
    this.dragActive = false;
    this.dragOriginX = e.clientX;
    this.dragOriginY = e.clientY;
    this.dragLastClientX = e.clientX;
    this.dragLastClientY = e.clientY;
  };

  private handleScrollbarMouseDown = (e: MouseEvent): void => {
    if (e.button !== 0 || !this.driver || !this.scrollbarTrack) return;
    e.preventDefault();
    e.stopPropagation();
    this.closeContextMenu();
    const sbLen = this.lastSnap?.scrollbackLen ?? 0;
    if (sbLen === 0) return;

    const thumb = this.scrollbarThumb;
    if (thumb && e.target === thumb) {
      this.scrollbarDragging = true;
      this.scrollbarDragStartY = e.clientY;
      this.scrollbarDragStartScroll = this.lastSnap?.viewportScroll ?? 0;
      return;
    }

    const trackRect = this.scrollbarTrack.getBoundingClientRect();
    const rel = Math.max(0, Math.min(1, (e.clientY - trackRect.top) / Math.max(1, trackRect.height)));
    const targetScroll = Math.round((1 - rel) * sbLen);
    this.driver.setViewportScroll(targetScroll);
    this.scheduleRender();
  };

  private handleWindowMouseMove = (e: MouseEvent): void => {
    if (this.disposed || !this.driver) return;

    if (this.scrollbarDragging && this.scrollbarTrack && this.scrollbarThumb) {
      const sbLen = this.lastSnap?.scrollbackLen ?? 0;
      if (sbLen === 0) return;
      const trackH = Math.max(1, this.scrollbarTrack.clientHeight);
      const thumbH = Math.max(24, this.scrollbarThumb.clientHeight);
      const maxTravel = Math.max(1, trackH - thumbH);
      const dy = e.clientY - this.scrollbarDragStartY;
      const deltaScroll = -Math.round((dy / maxTravel) * sbLen);
      this.driver.setViewportScroll(this.scrollbarDragStartScroll + deltaScroll);
      this.scheduleRender();
      return;
    }

    if (!this.dragPending && !this.dragActive) return;
    this.dragLastClientX = e.clientX;
    this.dragLastClientY = e.clientY;

    const movedEnough =
      Math.hypot(e.clientX - this.dragOriginX, e.clientY - this.dragOriginY) >= 3;
    const pos = this.eventToCell(e.clientX, e.clientY);
    const cellMoved =
      this.selAnchor !== null &&
      (pos.absRow !== this.selAnchor.absRow || pos.col !== this.selAnchor.col);

    if (this.dragPending && !this.dragActive && (movedEnough || cellMoved)) {
      this.dragActive = true;
    }
    if (this.dragActive) {
      this.selFocus = pos;
      this.syncSelectedText();
      this.scheduleRender();
      this.updateDragAutoScroll(e.clientY);
    }
  };

  private updateDragAutoScroll(clientY: number): void {
    const rect = this.canvas?.getBoundingClientRect();
    if (!rect || !this.driver) return;
    const outsideTop = clientY < rect.top;
    const outsideBottom = clientY > rect.bottom;
    if (!outsideTop && !outsideBottom) {
      if (this.dragAutoScrollTimer) {
        window.clearInterval(this.dragAutoScrollTimer);
        this.dragAutoScrollTimer = 0;
      }
      return;
    }
    if (!this.dragAutoScrollTimer) {
      this.dragAutoScrollTimer = window.setInterval(() => {
        if (!this.dragActive || !this.driver || !this.canvas) {
          window.clearInterval(this.dragAutoScrollTimer);
          this.dragAutoScrollTimer = 0;
          return;
        }
        const r = this.canvas.getBoundingClientRect();
        const dir = this.dragLastClientY < r.top ? 1 : this.dragLastClientY > r.bottom ? -1 : 0;
        if (dir !== 0) {
          this.driver.scrollViewport(dir);
          this.selFocus = this.eventToCell(this.dragLastClientX, this.dragLastClientY);
          this.syncSelectedText();
          this.scheduleRender();
        }
      }, 65);
    }
  }

  private handleWindowMouseUp = (e: MouseEvent): void => {
    if (this.scrollbarDragging) {
      this.scrollbarDragging = false;
    }
    if (this.dragAutoScrollTimer) {
      window.clearInterval(this.dragAutoScrollTimer);
      this.dragAutoScrollTimer = 0;
    }
    if (!this.dragPending && !this.dragActive) return;

    if (!this.dragActive && e.detail <= 1 && !e.shiftKey) {
      this.clearSelection();
    } else if (this.dragActive) {
      this.selFocus = this.eventToCell(e.clientX, e.clientY);
      this.syncSelectedText();
      this.scheduleRender();
    }
    this.dragPending = false;
    this.dragActive = false;
  };

  private handleGlobalDismissMenu = (e: MouseEvent): void => {
    if (this.contextMenu && e.target instanceof Node && !this.contextMenu.contains(e.target)) {
      this.closeContextMenu();
    }
  };

  private handleContextMenu = (e: MouseEvent): void => {
    if (this.disposed || !this.wrapper) return;
    e.preventDefault();
    e.stopPropagation();
    this.closeContextMenu();

    const menu = document.createElement('div');
    menu.setAttribute('role', 'menu');
    menu.style.cssText =
      'position:absolute;min-width:150px;padding:4px;border-radius:8px;background:#0f172a;border:1px solid #334155;box-shadow:0 10px 25px rgba(0,0,0,0.45);z-index:30;font-size:12px;color:#e2e8f0;';

    const rect = this.wrapper.getBoundingClientRect();
    const left = Math.max(4, Math.min(rect.width - 160, e.clientX - rect.left));
    const top = Math.max(4, Math.min(rect.height - 130, e.clientY - rect.top));
    menu.style.left = `${left}px`;
    menu.style.top = `${top}px`;

    const sel = this.getNormalizedSelectionText();
    const addItem = (label: string, enabled: boolean, action: () => void) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.textContent = label;
      btn.disabled = !enabled;
      btn.style.cssText = `display:block;width:100%;text-align:left;padding:5px 10px;border-radius:5px;border:none;background:transparent;color:${
        enabled ? '#e2e8f0' : '#64748b'
      };cursor:${enabled ? 'pointer' : 'default'};`;
      if (enabled) {
        btn.addEventListener('mouseenter', () => {
          btn.style.background = '#1e293b';
        });
        btn.addEventListener('mouseleave', () => {
          btn.style.background = 'transparent';
        });
        btn.addEventListener('click', (ev) => {
          ev.stopPropagation();
          this.closeContextMenu();
          action();
          this.focus();
        });
      }
      menu.appendChild(btn);
    };

    addItem('Copy', Boolean(sel), () => {
      void this.copyTextToClipboard(sel);
    });
    addItem('Paste', typeof navigator !== 'undefined' && Boolean(navigator.clipboard?.readText), () => {
      void navigator.clipboard
        ?.readText?.()
        .then((text) => {
          if (text && this.driver && !this.disposed) {
            this.scrollToBottom();
            this.onData(this.driver.encodePaste(text));
          }
        })
        .catch(() => {});
    });
    addItem('Select All', true, () => {
      this.selectAll();
    });
    addItem('Clear Selection', Boolean(this.selAnchor), () => {
      this.clearSelection();
    });

    this.wrapper.appendChild(menu);
    this.contextMenu = menu;
  };

  private closeContextMenu(): void {
    if (this.contextMenu) {
      this.contextMenu.remove();
      this.contextMenu = null;
    }
  }

  private getNormalizedSelection(): {
    startRow: number;
    startCol: number;
    endRow: number;
    endCol: number;
  } | null {
    if (!this.selAnchor || !this.selFocus) return null;
    const a = this.selAnchor;
    const b = this.selFocus;
    if (a.absRow < b.absRow || (a.absRow === b.absRow && a.col <= b.col)) {
      return { startRow: a.absRow, startCol: a.col, endRow: b.absRow, endCol: b.col };
    }
    return { startRow: b.absRow, startCol: b.col, endRow: a.absRow, endCol: a.col };
  }

  private isCellSelected(absRow: number, col: number): boolean {
    const sel = this.getNormalizedSelection();
    if (!sel) return false;
    if (absRow < sel.startRow || absRow > sel.endRow) return false;
    if (sel.startRow === sel.endRow) {
      return col >= sel.startCol && col <= sel.endCol;
    }
    if (absRow === sel.startRow) return col >= sel.startCol;
    if (absRow === sel.endRow) return col <= sel.endCol;
    return true;
  }

  private syncSelectedText(): void {
    const sel = this.getNormalizedSelection();
    if (!sel || !this.driver) {
      this.selectedText = '';
      return;
    }
    this.selectedText = this.driver.extractRange(
      sel.startRow,
      sel.startCol,
      sel.endRow,
      sel.endCol,
    );
  }

  private getNormalizedSelectionText(): string {
    if (this.selAnchor && this.selFocus) {
      this.syncSelectedText();
    }
    return this.selectedText;
  }

  private async copyTextToClipboard(text: string): Promise<void> {
    if (!text) return;
    if (typeof navigator !== 'undefined' && typeof navigator.clipboard?.writeText === 'function') {
      await navigator.clipboard.writeText(text).catch(() => {});
    }
  }

  selectAll(): void {
    if (!this.driver) return;
    const sb = this.lastSnap?.scrollbackLen ?? this.driver.snapshot().scrollbackLen;
    const totalRows = sb + this._rows;
    this.selAnchor = { absRow: 0, col: 0 };
    this.selFocus = {
      absRow: Math.max(0, totalRows - 1),
      col: Math.max(0, this._cols - 1),
    };
    this.syncSelectedText();
    this.scheduleRender();
  }

  clearSelection(): void {
    if (!this.selAnchor && !this.selFocus && !this.selectedText) return;
    this.selAnchor = null;
    this.selFocus = null;
    this.selectedText = '';
    this.scheduleRender();
  }

  scrollLines(deltaLines: number): void {
    if (!this.driver || this.disposed) return;
    this.driver.scrollViewport(deltaLines);
    this.scheduleRender();
  }

  scrollToBottom(): void {
    if (!this.driver || this.disposed) return;
    this.driver.setViewportScroll(0);
    this.scheduleRender();
  }

  write(data: string): void {
    if (this.disposed || !data) return;
    if (!this.driver) {
      this.pendingWrites.push(data);
      return;
    }
    this.feedDriver(data);
    this.scheduleRender();
  }

  focus(): void {
    this.wrapper?.focus();
  }

  fit(): void {
    if (this.disposed) return;
    this.measureCell();
    const { cols, rows } = this.computeGrid();
    const changed = cols !== this._cols || rows !== this._rows;
    this._cols = cols;
    this._rows = rows;
    if (this.driver && changed) {
      this.driver.resize(cols, rows);
      this.onResize(cols, rows);
    }
    this.scheduleRender();
  }

  paste(data: string): void {
    if (this.disposed || !data) return;
    if (this.driver) {
      this.emitPaste(data);
    } else {
      this.onData(data);
    }
  }

  getSelection(): string {
    const domSel = window.getSelection()?.toString();
    if (domSel) return domSel;
    if (this.selectedText) return this.selectedText;
    return this.driver ? this.driver.plainText() : '';
  }

  search(query: string): boolean {
    this.lastQuery = query;
    if (!this.driver || !query) {
      this.matches = [];
      this.activeMatchIdx = -1;
      this.onSearchResults?.(0, 0);
      this.scheduleRender();
      return false;
    }
    this.matches = this.driver.search(query);
    this.activeMatchIdx = this.matches.length > 0 ? 0 : -1;
    this.scrollToActiveMatch();
    this.onSearchResults?.(this.activeMatchIdx >= 0 ? this.activeMatchIdx : 0, this.matches.length);
    this.scheduleRender();
    return this.matches.length > 0;
  }

  searchNext(): boolean {
    if (!this.lastQuery) return false;
    if (this.matches.length === 0) return this.search(this.lastQuery);
    this.activeMatchIdx = (this.activeMatchIdx + 1) % this.matches.length;
    this.scrollToActiveMatch();
    this.onSearchResults?.(this.activeMatchIdx, this.matches.length);
    this.scheduleRender();
    return true;
  }

  searchPrevious(): boolean {
    if (!this.lastQuery) return false;
    if (this.matches.length === 0) return this.search(this.lastQuery);
    this.activeMatchIdx = (this.activeMatchIdx - 1 + this.matches.length) % this.matches.length;
    this.scrollToActiveMatch();
    this.onSearchResults?.(this.activeMatchIdx, this.matches.length);
    this.scheduleRender();
    return true;
  }

  private scrollToActiveMatch(): void {
    if (!this.driver || this.activeMatchIdx < 0) return;
    const match = this.matches[this.activeMatchIdx];
    if (!match) return;
    const snap = this.driver.snapshot();
    this.lastSnap = snap;
    const visibleStart = Math.max(0, snap.scrollbackLen - snap.viewportScroll);
    const visibleEnd = visibleStart + snap.rows;
    if (match.absRow < visibleStart || match.absRow >= visibleEnd) {
      const targetStart = Math.max(0, match.absRow - Math.floor(snap.rows / 2));
      this.driver.setViewportScroll(Math.max(0, snap.scrollbackLen - targetStart));
    }
  }

  clearSearch(): void {
    this.lastQuery = '';
    this.matches = [];
    this.activeMatchIdx = -1;
    this.onSearchResults?.(0, 0);
    this.scheduleRender();
  }

  serialize(): string {
    return this.driver ? this.driver.serializeVt() : '';
  }

  async serializeAsync(): Promise<string> {
    return this.serialize();
  }

  setAppearance(fontFamily: string, fontSize: number): void {
    this.fontFamily = formatTerminalFontStack(fontFamily || 'JetBrains Mono');
    this.fontSize = Math.max(10, Math.min(28, fontSize || 13));
    if (typeof document !== 'undefined' && 'fonts' in document && typeof document.fonts?.load === 'function') {
      void document.fonts
        .load(`${this.fontSize}px ${this.fontFamily}`)
        .then(() => {
          if (!this.disposed) this.fit();
        })
        .catch(() => {});
    }
    this.fit();
  }

  setTheme(): void {
    this.scheduleRender();
  }

  setScrollbackLines(lines: number): void {
    this.scrollbackLines = Math.max(100, lines || 5000);
    this.driver?.setScrollbackLimit(this.scrollbackLines);
    this.scheduleRender();
  }

  private scheduleRender(): void {
    if (this.disposed || this.rafId) return;
    let ranSync = false;
    const id = requestAnimationFrame(() => {
      ranSync = true;
      this.rafId = 0;
      this.renderNow();
    });
    if (!ranSync && !this.disposed) {
      this.rafId = id;
    }
  }

  private renderNow(): void {
    if (this.disposed || !this.driver || !this.canvas || !this.container) return;
    const snap: TermSnapshot = this.driver.snapshot();
    this.lastSnap = snap;
    this.updateScrollUi(snap);
    const dpr = window.devicePixelRatio || 1;
    const cssW = Math.max(1, this.canvas.clientWidth || (this.container.clientWidth - 18));
    const cssH = Math.max(1, this.canvas.clientHeight || (this.container.clientHeight - 8));
    const targetW = Math.floor(cssW * dpr);
    const targetH = Math.floor(cssH * dpr);
    if (this.canvas.width !== targetW || this.canvas.height !== targetH) {
      this.canvas.width = targetW;
      this.canvas.height = targetH;
    }

    let ctx: CanvasRenderingContext2D | null = null;
    try {
      ctx = this.canvas.getContext('2d');
    } catch {
      return;
    }
    if (!ctx) return;

    const theme = terminalTheme();
    const searchCols = terminalSearchColors();
    const bgDefault = theme.background || '#0a0e17';
    const fgDefault = theme.foreground || '#e2e8f0';
    const cursorColor = theme.cursor || '#38bdf8';
    const selectionBg = theme.selectionBackground || 'rgba(56, 189, 248, 0.34)';

    ctx.save();
    ctx.scale(dpr, dpr);
    ctx.fillStyle = bgDefault;
    ctx.fillRect(0, 0, cssW, cssH);

    ctx.textBaseline = 'top';
    const baseFont = `${this.fontSize}px ${this.fontFamily}`;
    const boldFont = `bold ${this.fontSize}px ${this.fontFamily}`;
    const italicFont = `italic ${this.fontSize}px ${this.fontFamily}`;
    const boldItalicFont = `italic bold ${this.fontSize}px ${this.fontFamily}`;

    const visibleStartRow = Math.max(0, snap.scrollbackLen - snap.viewportScroll);
    for (let r = 0; r < snap.rows; r++) {
      const y = r * this.cellH;
      for (let c = 0; c < snap.cols; c++) {
        const cell = snap.cells[r * snap.cols + c];
        if (!cell) continue;
        const x = c * this.cellW;

        const isBold = (cell.attrs & 1) !== 0;
        const isDim = (cell.attrs & 2) !== 0;
        const isItalic = (cell.attrs & 4) !== 0;
        const isUnderline = (cell.attrs & 8) !== 0;
        const isInverse = (cell.attrs & 32) !== 0;
        const isHidden = (cell.attrs & 64) !== 0;
        const isStrike = (cell.attrs & 128) !== 0;
        const isWideCont = (cell.attrs & 256) !== 0;

        let fg = resolveCssColor(unpackTermColor(cell.fgPacked, fgDefault), fgDefault);
        let bg = resolveCssColor(unpackTermColor(cell.bgPacked, bgDefault), bgDefault);
        if (isInverse) {
          const tmp = fg;
          fg = bg;
          bg = tmp;
        }

        if (bg !== bgDefault) {
          ctx.fillStyle = bg;
          ctx.fillRect(x, y, Math.ceil(this.cellW), Math.ceil(this.cellH));
        }

        const absRow = visibleStartRow + r;
        if (this.isCellSelected(absRow, c)) {
          ctx.fillStyle = selectionBg;
          ctx.fillRect(x, y, Math.ceil(this.cellW), Math.ceil(this.cellH));
        }

        // Search highlight
        for (let mIdx = 0; mIdx < this.matches.length; mIdx++) {
          const m = this.matches[mIdx];
          if (m.absRow === absRow && c >= m.colStart && c < m.colEnd) {
            ctx.fillStyle = mIdx === this.activeMatchIdx
              ? (searchCols.activeMatchBackground || '#f59e0b')
              : (searchCols.matchBackground || '#334155');
            ctx.fillRect(x, y, Math.ceil(this.cellW), Math.ceil(this.cellH));
            break;
          }
        }

        // Cursor (hidden while inspecting scrollback history)
        if (
          snap.cursorVisible &&
          snap.viewportScroll === 0 &&
          r === snap.cursorRow &&
          c === snap.cursorCol
        ) {
          ctx.fillStyle = cursorColor;
          if (snap.cursorStyle === 1) {
            ctx.fillRect(x, y + this.cellH - 2, Math.ceil(this.cellW), 2);
          } else if (snap.cursorStyle === 2) {
            ctx.fillRect(x, y, 2, Math.ceil(this.cellH));
          } else {
            ctx.fillRect(x, y, Math.ceil(this.cellW), Math.ceil(this.cellH));
            fg = bgDefault;
          }
        }

        if (!isWideCont && !isHidden && cell.ch && cell.ch !== ' ') {
          ctx.font = isBold && isItalic
            ? boldItalicFont
            : isBold
              ? boldFont
              : isItalic
                ? italicFont
                : baseFont;
          ctx.fillStyle = fg;
          ctx.globalAlpha = isDim ? 0.65 : 1;
          ctx.fillText(cell.ch, x, y + 2);
          ctx.globalAlpha = 1;
        }

        if (isUnderline) {
          ctx.fillStyle = fg;
          ctx.fillRect(x, y + this.cellH - 2, Math.ceil(this.cellW), 1);
        }
        if (isStrike) {
          ctx.fillStyle = fg;
          ctx.fillRect(x, y + Math.floor(this.cellH / 2), Math.ceil(this.cellW), 1);
        }
      }
    }
    ctx.restore();
  }

  private updateScrollUi(snap: TermSnapshot): void {
    const hasScrollback = !snap.altScreen && snap.scrollbackLen > 0;
    if (this.scrollbarTrack && this.scrollbarThumb) {
      if (!hasScrollback) {
        this.scrollbarTrack.style.display = 'none';
      } else {
        this.scrollbarTrack.style.display = 'block';
        const trackH = Math.max(40, this.scrollbarTrack.clientHeight || this._rows * this.cellH);
        const total = snap.scrollbackLen + snap.rows;
        const thumbH = Math.max(24, Math.round((snap.rows / total) * trackH));
        const maxTravel = Math.max(0, trackH - thumbH);
        const ratio = (snap.scrollbackLen - snap.viewportScroll) / snap.scrollbackLen;
        const top = Math.max(0, Math.min(maxTravel, Math.round(ratio * maxTravel)));
        this.scrollbarThumb.style.height = `${thumbH}px`;
        this.scrollbarThumb.style.top = `${top}px`;
      }
    }
    if (this.jumpBottomBtn) {
      this.jumpBottomBtn.style.display = !snap.altScreen && snap.viewportScroll > 0 ? 'block' : 'none';
    }
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    if (this.rafId) {
      cancelAnimationFrame(this.rafId);
      this.rafId = 0;
    }
    if (this.dragAutoScrollTimer) {
      window.clearInterval(this.dragAutoScrollTimer);
      this.dragAutoScrollTimer = 0;
    }
    this.resizeObserver?.disconnect();
    this.resizeObserver = null;
    this.closeContextMenu();
    window.removeEventListener('mousemove', this.handleWindowMouseMove);
    window.removeEventListener('mouseup', this.handleWindowMouseUp);
    window.removeEventListener('mousedown', this.handleGlobalDismissMenu);
    if (this.scrollbarTrack) {
      this.scrollbarTrack.removeEventListener('mousedown', this.handleScrollbarMouseDown);
      this.scrollbarTrack = null;
      this.scrollbarThumb = null;
    }
    this.jumpBottomBtn = null;
    if (this.wrapper) {
      this.wrapper.removeEventListener('keydown', this.handleKeyDown);
      this.wrapper.removeEventListener('paste', this.handlePaste);
      this.wrapper.removeEventListener('copy', this.handleCopy);
      this.wrapper.removeEventListener('wheel', this.handleWheel);
      this.wrapper.removeEventListener('mousedown', this.handleMouseDown);
      this.wrapper.removeEventListener('contextmenu', this.handleContextMenu);
      this.wrapper.remove();
      this.wrapper = null;
    }
    this.canvas = null;
    this.driver?.dispose();
    this.driver = null;
  }
}

export function createTerminalAdapter(options: TerminalAdapterOptions): TerminalAdapter {
  return new WasmTerminalAdapter(options);
}
