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
  viewportScroll: number;
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
  oqr_term_scroll_viewport?: (handle: number, deltaLines: number) => number;
  oqr_term_set_scroll?: (handle: number, offset: number) => number;
  oqr_term_set_scrollback_limit?: (handle: number, limit: number) => void;
  oqr_term_extract_range?: (
    handle: number,
    startRow: number,
    startCol: number,
    endRow: number,
    endCol: number,
  ) => number;
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
  try {
    return await cachedModule;
  } catch (err) {
    cachedModule = null;
    throw err;
  }
}

function createJsFallbackWasmExports(): WasmExports {
  const memory = new WebAssembly.Memory({ initial: 4 });
  const ensureMem = (endOffset: number) => {
    if (endOffset > memory.buffer.byteLength) {
      const extraPages = Math.ceil((endOffset - memory.buffer.byteLength) / 65536);
      memory.grow(extraPages);
    }
  };

  interface TermState {
    cols: number;
    rows: number;
    scrollback: number;
    viewportScroll: number;
    rawBytes: number[];
    outPtr: number;
    outLen: number;
  }

  let nextHandle = 1;
  const instances = new Map<number, TermState>();
  const unpack16 = (w0: number, w1: number, w2: number, w3: number, len: number): Uint8Array => {
    const buf = new Uint8Array(16);
    const dv = new DataView(buf.buffer);
    dv.setUint32(0, w0 >>> 0, true);
    dv.setUint32(4, w1 >>> 0, true);
    dv.setUint32(8, w2 >>> 0, true);
    dv.setUint32(12, w3 >>> 0, true);
    return buf.subarray(0, Math.max(0, Math.min(16, len)));
  };

  const stripAnsiCsi = (input: string): string => {
    let out = '';
    for (let i = 0; i < input.length; i++) {
      if (input.charCodeAt(i) === 0x1b && input[i + 1] === '[') {
        let j = i + 2;
        while (j < input.length && !/[A-Za-z]/.test(input[j])) {
          j++;
        }
        i = j;
        continue;
      }
      out += input[i];
    }
    return out;
  };

  const writeOutBytes = (st: TermState, bytes: Uint8Array): number => {
    ensureMem(st.outPtr + bytes.length);
    new Uint8Array(memory.buffer, st.outPtr, bytes.length).set(bytes);
    st.outLen = bytes.length;
    return bytes.length;
  };

  const splitFallbackLines = (st: TermState): string[] => {
    const plain = stripAnsiCsi(UTF8_DEC.decode(new Uint8Array(st.rawBytes)));
    const lines = plain.replace(/\r/g, '').split('\n');
    while (lines.length < st.rows) lines.push('');
    const maxLines = st.rows + st.scrollback;
    return lines.length > maxLines ? lines.slice(lines.length - maxLines) : lines;
  };

  return {
    memory,
    oqr_term_new: (cols, rows, scrollback) => {
      const handle = nextHandle++;
      instances.set(handle, {
        cols: Math.max(2, cols),
        rows: Math.max(1, rows),
        scrollback: Math.max(0, scrollback),
        viewportScroll: 0,
        rawBytes: [],
        outPtr: 1024,
        outLen: 0,
      });
      return handle;
    },
    oqr_term_free: (handle) => {
      instances.delete(handle);
    },
    oqr_term_feed16: (handle, w0, w1, w2, w3, len) => {
      const st = instances.get(handle);
      if (!st || len <= 0) return;
      const chunk = unpack16(w0, w1, w2, w3, len);
      for (const b of chunk) {
        st.rawBytes.push(b);
      }
    },
    oqr_term_resize: (handle, cols, rows) => {
      const st = instances.get(handle);
      if (!st) return;
      st.cols = Math.max(2, cols);
      st.rows = Math.max(1, rows);
    },
    oqr_term_render_snapshot: (handle) => {
      const st = instances.get(handle);
      if (!st) return 0;
      const lines = splitFallbackLines(st);
      const sbLen = Math.max(0, lines.length - st.rows);
      st.viewportScroll = Math.max(0, Math.min(sbLen, st.viewportScroll));
      const startRow = sbLen - st.viewportScroll;
      const cellCount = st.cols * st.rows;
      const total = 24 + cellCount * 14;
      ensureMem(st.outPtr + total);
      const dv = new DataView(memory.buffer, st.outPtr, total);
      dv.setUint32(0, 0, true);
      dv.setUint16(4, st.cols, true);
      dv.setUint16(6, st.rows, true);
      dv.setUint16(8, 0, true);
      dv.setUint16(10, 0, true);
      dv.setUint8(12, 1);
      dv.setUint8(13, 0);
      dv.setUint32(16, sbLen, true);
      dv.setUint32(20, st.viewportScroll, true);
      for (let r = 0; r < st.rows; r++) {
        const chars = Array.from(lines[startRow + r] ?? '');
        for (let c = 0; c < st.cols; c++) {
          const i = r * st.cols + c;
          const off = 24 + i * 14;
          const cp = c < chars.length ? (chars[c]?.codePointAt(0) ?? 32) : 32;
          dv.setUint32(off, cp, true);
          dv.setUint32(off + 4, 0, true);
          dv.setUint32(off + 8, 0, true);
          dv.setUint16(off + 12, 0, true);
        }
      }
      st.outLen = total;
      return total;
    },
    oqr_term_serialize_vt: (handle) => {
      const st = instances.get(handle);
      if (!st) return 0;
      return writeOutBytes(st, new Uint8Array(st.rawBytes));
    },
    oqr_term_plain_text: (handle) => {
      const st = instances.get(handle);
      if (!st) return 0;
      const plain = stripAnsiCsi(UTF8_DEC.decode(new Uint8Array(st.rawBytes)));
      return writeOutBytes(st, UTF8_ENC.encode(plain));
    },
    oqr_term_search16: (handle, w0, w1, w2, w3, len, caseSensitive) => {
      const st = instances.get(handle);
      if (!st) return 0;
      const qRaw = UTF8_DEC.decode(unpack16(w0, w1, w2, w3, len));
      const text = UTF8_DEC.decode(new Uint8Array(st.rawBytes));
      const needle = caseSensitive ? qRaw : qRaw.toLowerCase();
      const lines = text.split(/\r?\n/);
      const hits: Array<[number, number, number]> = [];
      if (needle.length > 0) {
        for (let r = 0; r < lines.length; r++) {
          const line = caseSensitive ? lines[r] : lines[r].toLowerCase();
          let from = 0;
          while (from <= line.length) {
            const idx = line.indexOf(needle, from);
            if (idx < 0) break;
            hits.push([r, idx, idx + needle.length]);
            from = idx + needle.length;
          }
        }
      }
      const needed = 4 + hits.length * 8;
      ensureMem(st.outPtr + needed);
      const dv = new DataView(memory.buffer, st.outPtr, needed);
      dv.setUint32(0, hits.length, true);
      hits.forEach(([absRow, colStart, colEnd], idx) => {
        const off = 4 + idx * 8;
        dv.setUint32(off, absRow, true);
        dv.setUint16(off + 4, colStart, true);
        dv.setUint16(off + 6, colEnd, true);
      });
      st.outLen = needed;
      return hits.length;
    },
    oqr_term_take_replies: (handle) => {
      const st = instances.get(handle);
      if (st) st.outLen = 0;
      return 0;
    },
    oqr_term_out_ptr: (handle) => instances.get(handle)?.outPtr ?? 1024,
    oqr_term_out_len: (handle) => instances.get(handle)?.outLen ?? 0,
    oqr_term_bracketed_paste: () => 0,
    oqr_term_app_cursor: () => 0,
    oqr_term_scroll_viewport: (handle, deltaLines) => {
      const st = instances.get(handle);
      if (!st) return 0;
      const sbLen = Math.max(0, splitFallbackLines(st).length - st.rows);
      st.viewportScroll = Math.max(0, Math.min(sbLen, st.viewportScroll + deltaLines));
      return st.viewportScroll;
    },
    oqr_term_set_scroll: (handle, offset) => {
      const st = instances.get(handle);
      if (!st) return 0;
      const sbLen = Math.max(0, splitFallbackLines(st).length - st.rows);
      st.viewportScroll = Math.max(0, Math.min(sbLen, offset));
      return st.viewportScroll;
    },
    oqr_term_set_scrollback_limit: (handle, limit) => {
      const st = instances.get(handle);
      if (st) {
        st.scrollback = Math.max(0, Math.min(50_000, limit));
        const sbLen = Math.max(0, splitFallbackLines(st).length - st.rows);
        st.viewportScroll = Math.min(st.viewportScroll, sbLen);
      }
    },
    oqr_term_extract_range: (handle, startRow, startCol, endRow, endCol) => {
      const st = instances.get(handle);
      if (!st) return 0;
      const lines = splitFallbackLines(st);
      if (lines.length === 0) return writeOutBytes(st, new Uint8Array(0));
      let sr = startRow;
      let sc = startCol;
      let er = endRow;
      let ec = endCol;
      if (sr > er || (sr === er && sc > ec)) {
        [sr, sc, er, ec] = [er, ec, sr, sc];
      }
      er = Math.min(lines.length - 1, er);
      const extracted: string[] = [];
      for (let r = sr; r <= er; r++) {
        const line = lines[r] ?? '';
        const cStart = r === sr ? sc : 0;
        const cEnd = r === er ? ec + 1 : line.length;
        extracted.push(line.slice(cStart, cEnd).replace(/ +$/g, ''));
      }
      return writeOutBytes(st, UTF8_ENC.encode(extracted.join('\n')));
    },
  };
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
  if (idx < 16) {
    return `var(--term-color-${idx})`;
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
    let exports: WasmExports;
    try {
      const mod = await loadWasmModule(wasmBytes);
      const instance = await WebAssembly.instantiate(mod, {});
      exports = instance.exports as unknown as WasmExports;
    } catch (err) {
      if (wasmBytes) {
        throw err;
      }
      exports = createJsFallbackWasmExports();
    }
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
    const viewportScroll = dv.getUint32(20, true);

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
      viewportScroll,
      cells,
    };
  }

  scrollViewport(deltaLines: number): number {
    if (this.disposed) return 0;
    return this.exports.oqr_term_scroll_viewport?.(this.handle, Math.trunc(deltaLines)) ?? 0;
  }

  setViewportScroll(offset: number): number {
    if (this.disposed) return 0;
    return this.exports.oqr_term_set_scroll?.(this.handle, Math.max(0, Math.trunc(offset))) ?? 0;
  }

  setScrollbackLimit(limit: number): void {
    if (!this.disposed) {
      this.exports.oqr_term_set_scrollback_limit?.(this.handle, Math.max(0, Math.trunc(limit)));
    }
  }

  extractRange(
    startAbsRow: number,
    startCol: number,
    endAbsRow: number,
    endCol: number,
  ): string {
    if (this.disposed || !this.exports.oqr_term_extract_range) return '';
    const len = this.exports.oqr_term_extract_range(
      this.handle,
      Math.max(0, Math.trunc(startAbsRow)),
      Math.max(0, Math.trunc(startCol)),
      Math.max(0, Math.trunc(endAbsRow)),
      Math.max(0, Math.trunc(endCol)),
    );
    return len > 0 ? UTF8_DEC.decode(this.readOutBytes()) : '';
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

  encodeKey(
    key: string,
    ctrl: boolean,
    alt: boolean,
    shift = false,
    code = '',
    altGraph = false,
  ): string {
    if (
      !key ||
      key === 'Dead' ||
      key === 'Process' ||
      key === 'Shift' ||
      key === 'Control' ||
      key === 'Alt' ||
      key === 'Meta' ||
      key === 'CapsLock' ||
      key === 'NumLock' ||
      key === 'ScrollLock' ||
      key === 'AltGraph' ||
      key === 'Unidentified'
    ) {
      return '';
    }
    if (altGraph && key.length === 1) {
      return key;
    }

    const app = this.exports.oqr_term_app_cursor(this.handle) !== 0;
    const mod = (shift ? 1 : 0) + (alt ? 2 : 0) + (ctrl ? 4 : 0);
    const param = 1 + mod;

    switch (key) {
      case 'Enter':
        return alt ? '\x1b\r' : '\r';
      case 'Backspace':
        return ctrl ? '\x08' : alt ? '\x1b\x7f' : '\x7f';
      case 'Tab':
        return shift ? '\x1b[Z' : '\t';
      case 'Escape':
        return alt ? '\x1b\x1b' : '\x1b';
      case 'ArrowUp':
        return mod > 0 ? `\x1b[1;${param}A` : `${app ? '\x1bO' : '\x1b['}A`;
      case 'ArrowDown':
        return mod > 0 ? `\x1b[1;${param}B` : `${app ? '\x1bO' : '\x1b['}B`;
      case 'ArrowRight':
        return mod > 0 ? `\x1b[1;${param}C` : `${app ? '\x1bO' : '\x1b['}C`;
      case 'ArrowLeft':
        return mod > 0 ? `\x1b[1;${param}D` : `${app ? '\x1bO' : '\x1b['}D`;
      case 'Home':
        return mod > 0 ? `\x1b[1;${param}H` : `${app ? '\x1bO' : '\x1b['}H`;
      case 'End':
        return mod > 0 ? `\x1b[1;${param}F` : `${app ? '\x1bO' : '\x1b['}F`;
      case 'Insert':
        return mod > 0 ? `\x1b[2;${param}~` : '\x1b[2~';
      case 'Delete':
        return mod > 0 ? `\x1b[3;${param}~` : '\x1b[3~';
      case 'PageUp':
        return mod > 0 ? `\x1b[5;${param}~` : '\x1b[5~';
      case 'PageDown':
        return mod > 0 ? `\x1b[6;${param}~` : '\x1b[6~';
      case 'F1':
        return mod > 0 ? `\x1b[1;${param}P` : '\x1bOP';
      case 'F2':
        return mod > 0 ? `\x1b[1;${param}Q` : '\x1bOQ';
      case 'F3':
        return mod > 0 ? `\x1b[1;${param}R` : '\x1bOR';
      case 'F4':
        return mod > 0 ? `\x1b[1;${param}S` : '\x1bOS';
      case 'F5':
        return mod > 0 ? `\x1b[15;${param}~` : '\x1b[15~';
      case 'F6':
        return mod > 0 ? `\x1b[17;${param}~` : '\x1b[17~';
      case 'F7':
        return mod > 0 ? `\x1b[18;${param}~` : '\x1b[18~';
      case 'F8':
        return mod > 0 ? `\x1b[19;${param}~` : '\x1b[19~';
      case 'F9':
        return mod > 0 ? `\x1b[20;${param}~` : '\x1b[20~';
      case 'F10':
        return mod > 0 ? `\x1b[21;${param}~` : '\x1b[21~';
      case 'F11':
        return mod > 0 ? `\x1b[23;${param}~` : '\x1b[23~';
      case 'F12':
        return mod > 0 ? `\x1b[24;${param}~` : '\x1b[24~';
      default:
        break;
    }

    if (key.length === 1) {
      if (ctrl) {
        const lower = key.toLowerCase();
        let ctrlCh = '';
        if (lower >= 'a' && lower <= 'z') {
          ctrlCh = String.fromCharCode(lower.charCodeAt(0) - 96);
        } else if (key === ' ' || key === '@' || code === 'Digit2') {
          ctrlCh = '\x00';
        } else if (key === '[' || code === 'BracketLeft') {
          ctrlCh = '\x1b';
        } else if (key === '\\' || code === 'Backslash') {
          ctrlCh = '\x1c';
        } else if (key === ']' || code === 'BracketRight') {
          ctrlCh = '\x1d';
        } else if (key === '^' || code === 'Digit6') {
          ctrlCh = '\x1e';
        } else if (key === '_' || key === '/' || code === 'Minus' || code === 'Slash') {
          ctrlCh = '\x1f';
        } else if (key === '?') {
          ctrlCh = '\x7f';
        }
        if (ctrlCh) {
          return `${alt ? '\x1b' : ''}${ctrlCh}`;
        }
      }

      if (alt && !ctrl) {
        const isMac =
          typeof navigator !== 'undefined' &&
          /Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || '');
        if (isMac) {
          if (/^Key[A-Z]$/.test(code)) {
            const ch = shift ? code[3] : code[3].toLowerCase();
            return `\x1b${ch}`;
          }
          if (key.charCodeAt(0) > 127) {
            return key;
          }
        }
        return `\x1b${key}`;
      }

      return key;
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
