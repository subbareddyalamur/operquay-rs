import { createTerminalAdapter } from './terminal-engine';

export interface CastPlayerHandle {
  dispose: () => void;
}

/** Plays an asciicast v2 (.cast) recording using the Rust WASM terminal engine. */
export function playAsciicast(src: string, container: HTMLElement): CastPlayerHandle {
  let disposed = false;
  const timers: number[] = [];

  const adapter = createTerminalAdapter({
    engine: 'wasm',
    container,
    fontFamily: 'JetBrains Mono, monospace',
    fontSize: 13,
    scrollbackLines: 5000,
    onData: () => undefined,
    onResize: () => undefined,
  });

  void (async () => {
    await adapter.init();
    if (disposed) {
      adapter.dispose();
      return;
    }
    try {
      const res = await fetch(src, { credentials: 'include' });
      if (!res.ok || disposed) return;
      const text = await res.text();
      if (disposed) return;
      const lines = text.split('\n').filter((l) => l.trim().length > 0);
      let startIdx = 0;
      if (lines.length > 0 && lines[0].trim().startsWith('{')) {
        startIdx = 1;
      }
      let prevMs = 0;
      let accMs = 0;
      for (let i = startIdx; i < lines.length; i++) {
        try {
          const entry = JSON.parse(lines[i]) as [number, string, string];
          if (!Array.isArray(entry) || entry.length < 3) continue;
          const [sec, kind, data] = entry;
          if (kind !== 'o') continue;
          const ms = Math.max(0, sec * 1000);
          accMs += Math.min(400, Math.max(0, ms - prevMs));
          prevMs = ms;
          const delay = accMs;
          const id = window.setTimeout(() => {
            if (!disposed) adapter.write(data);
          }, delay);
          timers.push(id);
        } catch {
          // ignore malformed event line
        }
      }
    } catch {
      // ignore fetch error
    }
  })();

  return {
    dispose: () => {
      disposed = true;
      for (const id of timers) clearTimeout(id);
      adapter.dispose();
    },
  };
}
