// Polyfill Web Animations / CSS.supports checks used by @ui-sdk/core when
// components run in jsdom 25 test environments; real browsers provide both natively.
if (typeof Element !== 'undefined' && typeof Element.prototype.getAnimations !== 'function') {
  Element.prototype.getAnimations = () => [];
}

if (typeof globalThis !== 'undefined') {
  const g = globalThis as typeof globalThis & {
    CSS?: { supports?: (prop: string, val?: string) => boolean };
  };
  if (!g.CSS) {
    (g as Record<string, unknown>).CSS = { supports: () => false };
  } else if (typeof g.CSS.supports !== 'function') {
    g.CSS.supports = () => false;
  }
}

