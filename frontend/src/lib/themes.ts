/** The theme registry. Each entry needs a matching block in src/styles/themes.css. */
export const THEMES = [
  { slug: 'dark', label: 'Dark', mode: 'dark' },
  { slug: 'light', label: 'Light', mode: 'light' },
] as const;

export type ThemeSlug = (typeof THEMES)[number]['slug'];
export const THEME_SLUGS: readonly ThemeSlug[] = THEMES.map((t) => t.slug);

const LEGACY_LIGHT = ['paper', 'github-light', 'solarized-light', 'one-light', 'tokyo-night-day', 'catppuccin-latte', 'rose-pine-dawn'];

export function isValidTheme(slug: string): slug is ThemeSlug {
  return (THEME_SLUGS as readonly string[]).includes(slug);
}

/** Maps any saved choice, including retired themes, to a registered theme. */
export function normalizeTheme(theme: string | undefined | null, systemIsDark: boolean): ThemeSlug {
  if (theme && isValidTheme(theme)) return theme;
  if (!theme || theme === 'auto') return systemIsDark ? 'dark' : 'light';
  return LEGACY_LIGHT.includes(theme) ? 'light' : 'dark';
}

/** Reads the saved choice the way the main app stores it; usable from the Kubernetes frame too. */
export function savedTheme(): ThemeSlug {
  let stored: string | undefined;
  try { stored = JSON.parse(localStorage.getItem('ct-theme') || '{}')?.state?.theme; } catch { /* use the system preference */ }
  return normalizeTheme(stored, window.matchMedia('(prefers-color-scheme: dark)').matches);
}
