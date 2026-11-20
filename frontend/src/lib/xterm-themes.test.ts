import { afterEach, describe, expect, it } from 'vitest';
import { terminalTheme, watchTheme } from './xterm-themes';

const root = document.documentElement;
afterEach(() => { root.removeAttribute('style'); delete root.dataset.theme; });

describe('terminal theme', () => {
  it('reads every color from the active theme variables', () => {
    root.style.setProperty('--term-bg', ' #0b0e13');
    root.style.setProperty('--term-fg', '#d8dee6');
    root.style.setProperty('--term-red', '#f07f7f');
    root.style.setProperty('--term-bright-red', '#ff9c9c');
    const theme = terminalTheme();
    expect(theme.background).toBe('#0b0e13');
    expect(theme.cursorAccent).toBe('#0b0e13');
    expect(theme.foreground).toBe('#d8dee6');
    expect(theme.red).toBe('#f07f7f');
    expect(theme.brightRed).toBe('#ff9c9c');
  });

  it('notifies when the theme attribute changes', async () => {
    let calls = 0;
    const stop = watchTheme(() => { calls++; });
    root.dataset.theme = 'light';
    await Promise.resolve();
    expect(calls).toBe(1);
    stop();
    root.dataset.theme = 'dark';
    await Promise.resolve();
    expect(calls).toBe(1);
  });
});
