import { create } from 'zustand';
import { persist, createJSONStorage, subscribeWithSelector } from 'zustand/middleware';
import { isValidTheme, normalizeTheme, type ThemeSlug, THEME_SLUGS } from '@/lib/themes';

interface ThemeState {
  theme: ThemeSlug;
  setTheme: (slug: ThemeSlug) => void;
  cycleTheme: () => void;
}

const systemIsDark = () => typeof window === 'undefined' || window.matchMedia('(prefers-color-scheme: dark)').matches;
// The attribute changes before React re-renders so terminals reading CSS variables see the new theme.
const apply = (slug: ThemeSlug) => { if (typeof document !== 'undefined') document.documentElement.dataset.theme = slug; };

export const useThemeStore = create<ThemeState>()(
  subscribeWithSelector(
    persist(
      (set, get) => ({
        theme: normalizeTheme(undefined, systemIsDark()),
        setTheme: (slug: ThemeSlug) => {
          if (!isValidTheme(slug)) return;
          apply(slug);
          set({ theme: slug });
        },
        cycleTheme: () => {
          const idx = THEME_SLUGS.indexOf(get().theme);
          get().setTheme(THEME_SLUGS[(idx + 1) % THEME_SLUGS.length] ?? 'dark');
        },
      }),
      {
        name: 'ct-theme',
        version: 3,
        migrate: (persisted) => ({ theme: normalizeTheme((persisted as { theme?: string } | undefined)?.theme, systemIsDark()) }) as ThemeState,
        storage: createJSONStorage(() => localStorage),
        partialize: (s) => ({ theme: s.theme }),
        onRehydrateStorage: () => (state) => { if (state) apply(state.theme); },
      },
    ),
  ),
);

apply(useThemeStore.getState().theme);
