export interface TerminalTheme {
  background: string;
  foreground: string;
  cursor: string;
  cursorAccent: string;
  selectionBackground: string;
  selectionForeground: string;
  black: string;
  red: string;
  green: string;
  yellow: string;
  blue: string;
  magenta: string;
  cyan: string;
  white: string;
  brightBlack: string;
  brightRed: string;
  brightGreen: string;
  brightYellow: string;
  brightBlue: string;
  brightMagenta: string;
  brightCyan: string;
  brightWhite: string;
}

const ANSI = ['black', 'red', 'green', 'yellow', 'blue', 'magenta', 'cyan', 'white'] as const;
const cap = (s: string) => s[0].toUpperCase() + s.slice(1);

function read(root: HTMLElement) {
  const style = getComputedStyle(root);
  return (name: string) => style.getPropertyValue(`--term-${name}`).trim();
}

/** Builds the terminal theme from the --term-* variables of the active theme in themes.css. */
export function terminalTheme(root: HTMLElement = document.documentElement): TerminalTheme {
  const v = read(root);
  const theme: Record<string, string> = {
    background: v('bg'),
    foreground: v('fg'),
    cursor: v('cursor'),
    cursorAccent: v('bg'),
    selectionBackground: v('selection'),
    selectionForeground: v('fg'),
  };
  for (const name of ANSI) {
    theme[name] = v(name);
    theme[`bright${cap(name)}`] = v(`bright-${name}`);
  }
  return theme as unknown as TerminalTheme;
}

export function terminalSearchColors(root: HTMLElement = document.documentElement) {
  const v = read(root);
  const match = v('match');
  const active = v('match-active');
  return {
    matchBackground: match,
    matchBorder: match,
    matchOverviewRuler: match,
    activeMatchBackground: active,
    activeMatchBorder: active,
    activeMatchColorOverviewRuler: active,
  };
}

/** Calls onChange whenever the document's theme changes. Returns a stop function. */
export function watchTheme(onChange: () => void, root: HTMLElement = document.documentElement): () => void {
  const observer = new MutationObserver(onChange);
  observer.observe(root, { attributes: true, attributeFilter: ['data-theme'] });
  return () => observer.disconnect();
}

export const TERMINAL_FONTS = [
  'JetBrains Mono',
  'Fira Code',
  'IBM Plex Mono',
  'Geist Mono',
  'Menlo',
] as const;

export type TerminalFont = (typeof TERMINAL_FONTS)[number];

const MONOSPACE_FALLBACK_STACK =
  "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace";

export function normalizeTerminalFont(value: unknown): TerminalFont {
  if (typeof value === 'string') {
    const trimmed = value.trim().replace(/^['"]|['"]$/g, '');
    const exact = TERMINAL_FONTS.find((f) => f === trimmed);
    if (exact) return exact;
  }
  return 'JetBrains Mono';
}

export function formatTerminalFontStack(font: string): string {
  const clean = (font || 'JetBrains Mono').trim().replace(/^['"]|['"]$/g, '');
  if (!clean) return `"JetBrains Mono", ${MONOSPACE_FALLBACK_STACK}`;
  if (clean.includes(',') || clean === 'monospace') return clean;
  const primary = /\s/.test(clean) ? `"${clean}"` : clean;
  return `${primary}, ${MONOSPACE_FALLBACK_STACK}`;
}
