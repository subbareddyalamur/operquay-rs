import { describe, expect, it } from 'vitest';
import { normalizeTheme, THEME_SLUGS } from './themes';

describe('appearance modes', () => {
  it('offers only dark and light', () => {
    expect(THEME_SLUGS).toEqual(['dark', 'light']);
  });

  it('maps saved retired choices to the matching mode', () => {
    expect(normalizeTheme('glossy', false)).toBe('dark');
    expect(normalizeTheme('obsidian', false)).toBe('dark');
    expect(normalizeTheme('night', false)).toBe('dark');
    expect(normalizeTheme('paper', true)).toBe('light');
    expect(normalizeTheme('catppuccin-latte', true)).toBe('light');
    expect(normalizeTheme('light', true)).toBe('light');
  });

  it('follows the system for new users and the old automatic choice', () => {
    expect(normalizeTheme(undefined, false)).toBe('light');
    expect(normalizeTheme('auto', true)).toBe('dark');
  });
});
