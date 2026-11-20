import {
  forwardRef,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
  type ClipboardEvent,
  type KeyboardEvent,
} from 'react';
import { unpackTermColor, WasmTerminalDriver, type TermSnapshot } from './wasmTerminal';

export interface OperquayTerminalRef {
  write: (data: string | Uint8Array) => void;
  focus: () => void;
  search: (query: string) => number;
  clearSearch: () => void;
  serialize: () => string;
  plainText: () => string;
}

export interface OperquayTerminalProps {
  cols?: number;
  rows?: number;
  fontSize?: number;
  onData?: (chunk: string) => void;
  onResize?: (cols: number, rows: number) => void;
  wasmBytes?: BufferSource;
  ariaLabel?: string;
}

const ATTR_BOLD = 1 << 0;
const ATTR_ITALIC = 1 << 2;
const ATTR_UNDERLINE = 1 << 3;
const ATTR_INVERSE = 1 << 5;
const ATTR_WIDE_CONT = 1 << 8;

export const OperquayTerminal = forwardRef<OperquayTerminalRef, OperquayTerminalProps>(
  function OperquayTerminal(
    {
      cols = 96,
      rows = 28,
      fontSize = 13,
      onData,
      onResize,
      wasmBytes,
      ariaLabel = 'Operquay pure-Rust WebAssembly terminal',
    },
    ref,
  ) {
    const containerRef = useRef<HTMLDivElement>(null);
    const driverRef = useRef<WasmTerminalDriver | null>(null);
    const pendingRef = useRef<(string | Uint8Array)[]>([]);
    const onDataRef = useRef(onData);
    onDataRef.current = onData;
    const onResizeRef = useRef(onResize);
    onResizeRef.current = onResize;

    const [snapshot, setSnapshot] = useState<TermSnapshot | null>(null);
    const [searchQuery, setSearchQuery] = useState('');
    const [wasmError, setWasmError] = useState<string | null>(null);

    const refreshView = () => {
      if (driverRef.current) {
        setSnapshot(driverRef.current.snapshot());
      }
    };

    useEffect(() => {
      let cancelled = false;
      void (async () => {
        try {
          const drv = await WasmTerminalDriver.create(cols, rows, 5000, wasmBytes);
          if (cancelled) {
            drv.dispose();
            return;
          }
          driverRef.current = drv;
          if (pendingRef.current.length > 0) {
            for (const chunk of pendingRef.current) {
              const replies = drv.feed(chunk);
              if (replies.length > 0) {
                onDataRef.current?.(new TextDecoder().decode(replies));
              }
            }
            pendingRef.current.length = 0;
          }
          setSnapshot(drv.snapshot());
        } catch (err) {
          if (!cancelled) {
            setWasmError(err instanceof Error ? err.message : 'Unable to initialize WASM terminal');
          }
        }
      })();

      return () => {
        cancelled = true;
        driverRef.current?.dispose();
        driverRef.current = null;
      };
    }, [cols, rows, wasmBytes]);

    useEffect(() => {
      const el = containerRef.current;
      if (!el || typeof ResizeObserver !== 'function') return;
      const ro = new ResizeObserver((entries) => {
        const drv = driverRef.current;
        if (!drv) return;
        const rect = entries[0]?.contentRect;
        if (!rect || rect.width < 40 || rect.height < 40) return;
        const nextCols = Math.max(20, Math.floor((rect.width - 16) / (fontSize * 0.62)));
        const nextRows = Math.max(6, Math.floor((rect.height - 16) / (fontSize * 1.35)));
        drv.resize(nextCols, nextRows);
        onResizeRef.current?.(nextCols, nextRows);
        setSnapshot(drv.snapshot());
      });
      ro.observe(el);
      return () => ro.disconnect();
    }, [fontSize]);

    useImperativeHandle(ref, () => ({
      write(data) {
        const drv = driverRef.current;
        if (!drv) {
          pendingRef.current.push(data);
          return;
        }
        const replies = drv.feed(data);
        if (replies.length > 0) {
          onDataRef.current?.(new TextDecoder().decode(replies));
        }
        refreshView();
      },
      focus() {
        containerRef.current?.focus();
      },
      search(query) {
        setSearchQuery(query);
        return driverRef.current ? driverRef.current.search(query, false).length : 0;
      },
      clearSearch() {
        setSearchQuery('');
      },
      serialize() {
        return driverRef.current ? driverRef.current.serializeVt() : '';
      },
      plainText() {
        return driverRef.current ? driverRef.current.plainText() : '';
      },
    }));

    const handleKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
      if (e.metaKey || (!e.ctrlKey && !e.altKey && e.key.length > 1 && e.key === 'Tab')) {
        // Keep Shift+Tab / Meta shortcuts working cleanly unless targeting terminal
      }
      const drv = driverRef.current;
      if (!drv) return;
      const encoded = drv.encodeKey(e.key, e.ctrlKey, e.altKey);
      if (encoded) {
        e.preventDefault();
        onDataRef.current?.(encoded);
      }
    };

    const handlePaste = (e: ClipboardEvent<HTMLDivElement>) => {
      const drv = driverRef.current;
      if (!drv) return;
      const text = e.clipboardData.getData('text');
      if (text) {
        e.preventDefault();
        onDataRef.current?.(drv.encodePaste(text));
      }
    };

    const searchMatches = useMemo(() => {
      if (!searchQuery || !driverRef.current || !snapshot) return new Set<string>();
      const hits = driverRef.current.search(searchQuery, false);
      const viewportStart = snapshot.altScreen ? 0 : snapshot.scrollbackLen;
      const set = new Set<string>();
      for (const h of hits) {
        const relRow = h.absRow - viewportStart;
        if (relRow >= 0 && relRow < snapshot.rows) {
          for (let c = h.colStart; c < h.colEnd; c++) {
            set.add(`${relRow}:${c}`);
          }
        }
      }
      return set;
    }, [searchQuery, snapshot]);

    return (
      <div
        ref={containerRef}
        tabIndex={0}
        role="textbox"
        aria-multiline="true"
        aria-label={ariaLabel}
        onKeyDown={handleKeyDown}
        onPaste={handlePaste}
        className="w-full h-full min-h-[260px] rounded-[var(--radius-md)] border border-border bg-[var(--canvas-bg)] text-text-pri p-2 overflow-auto outline-none focus-visible:ring-2 focus-visible:ring-accent select-text tabular-mono"
        style={{ fontSize: `${fontSize}px`, lineHeight: 1.35 }}
      >
        {wasmError ? (
          <div role="alert" className="text-xs text-danger p-2">
            {wasmError}
          </div>
        ) : !snapshot ? (
          <div className="text-xs text-text-dim p-2">Initializing pure-Rust WASM terminal...</div>
        ) : (
          <div className="inline-block min-w-full">
            {Array.from({ length: snapshot.rows }, (_, r) => (
              <div key={r} className="whitespace-pre leading-[1.35]">
                {Array.from({ length: snapshot.cols }, (__, c) => {
                  const cell = snapshot.cells[r * snapshot.cols + c];
                  if (!cell || (cell.attrs & ATTR_WIDE_CONT) !== 0) return null;
                  const isCursor =
                    snapshot.cursorVisible && snapshot.cursorCol === c && snapshot.cursorRow === r;
                  const isMatch = searchMatches.has(`${r}:${c}`);
                  const inverse = (cell.attrs & ATTR_INVERSE) !== 0 || isCursor;
                  const baseFg = unpackTermColor(cell.fgPacked, 'var(--text-pri)');
                  const baseBg = unpackTermColor(cell.bgPacked, 'transparent');
                  return (
                    <span
                      key={c}
                      style={{
                        color: inverse ? 'var(--bg)' : baseFg,
                        backgroundColor: isMatch
                          ? 'var(--warn-dim)'
                          : inverse
                            ? 'var(--accent)'
                            : baseBg,
                        fontWeight: (cell.attrs & ATTR_BOLD) !== 0 ? 700 : undefined,
                        fontStyle: (cell.attrs & ATTR_ITALIC) !== 0 ? 'italic' : undefined,
                        textDecoration:
                          (cell.attrs & ATTR_UNDERLINE) !== 0 ? 'underline' : undefined,
                      }}
                    >
                      {cell.ch}
                    </span>
                  );
                })}
              </div>
            ))}
          </div>
        )}
      </div>
    );
  },
);
