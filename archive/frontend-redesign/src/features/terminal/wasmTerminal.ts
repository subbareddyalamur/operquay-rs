export interface TermSearchMatch {
  absRow: number;
  colStart: number;
  colEnd: number;
}

export interface TermCell {
  ch: string;
  fgPacked: number;
  bgPacked: number;
  attrs: number;
}

export interface TermSnapshot {
  cols: number;
  rows: number;
  cursorCol: number;
  cursorRow: number;
  cursorVisible: boolean;
  bracketedPaste: boolean;
  appCursor: boolean;
  altScreen: boolean;
  cursorStyle: number;
  scrollbackLen: number;
  cells: TermCell[];
}

interface WasmExports {
  memory: WebAssembly.Memory;
  oqr_term_new: (cols: number, rows: number, scrollback: number) => number;
  oqr_term_free: (handle: number) => void;
  oqr_term_feed16: (
    handle: number,
    w0: number,
    w1: number,
    w2: number,
    w3: number,
    len: number,
  ) => void;
  oqr_term_resize: (handle: number, cols: number, rows: number) => void;
  oqr_term_render_snapshot: (handle: number) => number;
  oqr_term_serialize_vt: (handle: number) => number;
  oqr_term_plain_text: (handle: number) => number;
  oqr_term_search16: (
    handle: number,
    w0: number,
    w1: number,
    w2: number,
    w3: number,
    len: number,
    caseSensitive: number,
  ) => number;
  oqr_term_take_replies: (handle: number) => number;
  oqr_term_out_ptr: (handle: number) => number;
  oqr_term_out_len: (handle: number) => number;
  oqr_term_bracketed_paste: (handle: number) => number;
  oqr_term_app_cursor: (handle: number) => number;
}

const UTF8_ENC = new TextEncoder();
const UTF8_DEC = new TextDecoder();

let cachedModule: Promise<WebAssembly.Module> | null = null;

async function loadWasmModule(wasmBytes?: BufferSource): Promise<WebAssembly.Module> {
  if (wasmBytes) {
    return WebAssembly.compile(wasmBytes);
  }
  if (!cachedModule) {
    cachedModule = (async () => {
      const res = await fetch('/operquay_term.wasm');
      if (!res.ok) {
        throw new Error(`Failed to fetch /operquay_term.wasm (HTTP ${res.status})`);
      }
      const bytes = await res.arrayBuffer();
      return WebAssembly.compile(bytes);
    })();
  }
  return cachedModule;
}

function pack16Bytes(slice: Uint8Array): [number, number, number, number] {
  const b = new Uint8Array(16);
  b.set(slice.subarray(0, 16));
  const dv = new DataView(b.buffer);
  return [
    dv.getUint32(0, true),
    dv.getUint32(4, true),
    dv.getUint32(8, true),
    dv.getUint32(12, true),
  ];
}

function srgbCss(r: number, g: number, b: number): string {
  return `color(srgb ${(r / 255).toFixed(4)} ${(g / 255).toFixed(4)} ${(b / 255).toFixed(4)})`;
}

export function unpackTermColor(packed: number, defaultCss: string): string {
  const kind = (packed >>> 24) & 0xff;
  if (kind === 0) return defaultCss;
  if (kind === 2) {
    const r = (packed >>> 16) & 0xff;
    const g = (packed >>> 8) & 0xff;
    const b = packed & 0xff;
    return srgbCss(r, g, b);
  }
  const idx = packed & 0xff;
  const ansiThemeMap: readonly string[] = [
    'var(--bg)',
    'var(--danger)',
    'var(--success)',
    'var(--warn)',
    'var(--info)',
    'var(--info)',
    'var(--accent)',
    'var(--text-pri)',
    'var(--text-dim)',
    'var(--danger)',
    'var(--success)',
    'var(--warn)',
    'var(--info)',
    'var(--info)',
    'var(--accent)',
    'var(--text-pri)',
  ];
  if (idx < 16) {
    return ansiThemeMap[idx];
  }
  if (idx < 232) {
    const c = idx - 16;
    const step = (v: number) => (v === 0 ? 0 : 55 + v * 40);
    return srgbCss(
      step(Math.floor(c / 36)),
      step(Math.floor((c % 36) / 6)),
      step(c % 6),
    );
  }
  const g = 8 + (idx - 232) * 10;
  return srgbCss(g, g, g);
}

/** Zero-JS-dependency WebAssembly terminal driver powered by Rust `operquay-term`. */
export class WasmTerminalDriver {
  private readonly exports: WasmExports;
  private readonly handle: number;
  private disposed = false;

  private constructor(exports: WasmExports, handle: number) {
    this.exports = exports;
    this.handle = handle;
  }

  static async create(
    cols = 80,
    rows = 24,
    scrollback = 5000,
    wasmBytes?: BufferSource,
  ): Promise<WasmTerminalDriver> {
    const mod = await loadWasmModule(wasmBytes);
    const instance = await WebAssembly.instantiate(mod, {});
    const exports = instance.exports as unknown as WasmExports;
    const handle = exports.oqr_term_new(cols, rows, scrollback);
    return new WasmTerminalDriver(exports, handle);
  }

  private readOutBytes(): Uint8Array {
    const ptr = this.exports.oqr_term_out_ptr(this.handle);
    const len = this.exports.oqr_term_out_len(this.handle);
    return new Uint8Array(this.exports.memory.buffer, ptr, len).slice();
  }

  feed(data: string | Uint8Array): Uint8Array {
    if (this.disposed) return new Uint8Array(0);
    const bytes = typeof data === 'string' ? UTF8_ENC.encode(data) : data;
    for (let i = 0; i < bytes.length; i += 16) {
      const slice = bytes.subarray(i, i + 16);
      const [w0, w1, w2, w3] = pack16Bytes(slice);
      this.exports.oqr_term_feed16(this.handle, w0, w1, w2, w3, slice.length);
    }
    const replyLen = this.exports.oqr_term_take_replies(this.handle);
    return replyLen > 0 ? this.readOutBytes() : new Uint8Array(0);
  }

  resize(cols: number, rows: number): void {
    if (!this.disposed) {
      this.exports.oqr_term_resize(this.handle, Math.max(2, cols), Math.max(1, rows));
    }
  }

  snapshot(): TermSnapshot {
    this.exports.oqr_term_render_snapshot(this.handle);
    const raw = this.readOutBytes();
    const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    const cols = dv.getUint16(4, true);
    const rows = dv.getUint16(6, true);
    const cursorCol = dv.getUint16(8, true);
    const cursorRow = dv.getUint16(10, true);
    const flags = dv.getUint8(12);
    const cursorStyle = dv.getUint8(13);
    const scrollbackLen = dv.getUint32(16, true);

    const cells: TermCell[] = [];
    for (let i = 0; i < cols * rows; i++) {
      const off = 24 + i * 14;
      const cp = dv.getUint32(off, true);
      const fgPacked = dv.getUint32(off + 4, true);
      const bgPacked = dv.getUint32(off + 8, true);
      const attrs = dv.getUint16(off + 12, true);
      cells.push({
        ch: String.fromCodePoint(cp || 32),
        fgPacked,
        bgPacked,
        attrs,
      });
    }

    return {
      cols,
      rows,
      cursorCol,
      cursorRow,
      cursorVisible: (flags & 1) !== 0,
      bracketedPaste: (flags & 2) !== 0,
      appCursor: (flags & 4) !== 0,
      altScreen: (flags & 8) !== 0,
      cursorStyle,
      scrollbackLen,
      cells,
    };
  }

  search(query: string, caseSensitive = false): TermSearchMatch[] {
    if (this.disposed || !query) return [];
    const bytes = UTF8_ENC.encode(query).subarray(0, 16);
    const [w0, w1, w2, w3] = pack16Bytes(bytes);
    this.exports.oqr_term_search16(
      this.handle,
      w0,
      w1,
      w2,
      w3,
      bytes.length,
      caseSensitive ? 1 : 0,
    );
    const raw = this.readOutBytes();
    const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    const count = dv.getUint32(0, true);
    const matches: TermSearchMatch[] = [];
    for (let i = 0; i < count; i++) {
      const off = 4 + i * 8;
      matches.push({
        absRow: dv.getUint32(off, true),
        colStart: dv.getUint16(off + 4, true),
        colEnd: dv.getUint16(off + 6, true),
      });
    }
    return matches;
  }

  serializeVt(): string {
    if (this.disposed) return '';
    this.exports.oqr_term_serialize_vt(this.handle);
    return UTF8_DEC.decode(this.readOutBytes());
  }

  plainText(): string {
    if (this.disposed) return '';
    this.exports.oqr_term_plain_text(this.handle);
    return UTF8_DEC.decode(this.readOutBytes());
  }

  encodeKey(key: string, ctrl: boolean, alt: boolean): string {
    const app = this.exports.oqr_term_app_cursor(this.handle) !== 0;
    const pfx = app ? '\x1bO' : '\x1b[';
    const fixed: Record<string, string> = {
      Enter: '\r',
      Backspace: '\x7f',
      Tab: '\t',
      Escape: '\x1b',
      ArrowUp: `${pfx}A`,
      ArrowDown: `${pfx}B`,
      ArrowRight: `${pfx}C`,
      ArrowLeft: `${pfx}D`,
      Home: app ? '\x1bOH' : '\x1b[H',
      End: app ? '\x1bOF' : '\x1b[F',
      Delete: '\x1b[3~',
      PageUp: '\x1b[5~',
      PageDown: '\x1b[6~',
    };
    if (key in fixed) return fixed[key];
    if (key.length === 1) {
      if (ctrl) {
        const lower = key.toLowerCase();
        if (lower >= 'a' && lower <= 'z') {
          const code = lower.charCodeAt(0) - 96;
          return `${alt ? '\x1b' : ''}${String.fromCharCode(code)}`;
        }
      }
      return `${alt ? '\x1b' : ''}${key}`;
    }
    return '';
  }

  encodePaste(text: string): string {
    const bp = this.exports.oqr_term_bracketed_paste(this.handle) !== 0;
    if (!bp) return text;
    return `\x1b[200~${text.split('\x1b').join('')}\x1b[201~`;
  }

  dispose(): void {
    if (!this.disposed) {
      this.disposed = true;
      this.exports.oqr_term_free(this.handle);
    }
  }
}
