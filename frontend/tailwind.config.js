// Every color is a variable from src/styles/themes.css; mixing keeps opacity modifiers (bg-success/15) working.
const themed = (name, fallback) => `color-mix(in srgb, var(--${name}${fallback ? `, var(--${fallback})` : ''}) calc(<alpha-value> * 100%), transparent)`;

export default {
  content: ['./index.html', './src/**/*.{ts,tsx,js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['var(--font-sans, Inter)', 'system-ui', 'sans-serif'],
        mono: ['var(--font-mono, "JetBrains Mono")', 'ui-monospace', 'monospace'],
      },
      transitionDuration: {
        '180': '180ms',
      },
      colors: {
        bg: themed('bg'),
        surface: themed('surface'),
        side: themed('side', 'surface'),
        'warn-ink': themed('warn-ink'),
        elev: themed('elev'),
        border: themed('border'),
        'border-2': themed('border-2'),
        'text-pri': themed('text-pri'),
        'text-mut': themed('text-mut'),
        'text-dim': themed('text-dim'),
        accent: themed('accent'),
        'accent-fg': themed('accent-fg'),
        'accent-2': themed('accent-2'),
        success: themed('success'),
        danger: themed('danger'),
        'danger-fg': themed('danger-fg'),
        warn: themed('warn'),
        info: themed('info'),
      },
      borderRadius: {
        DEFAULT: 'var(--radius, 6px)',
        sm: 'var(--radius-sm, 4px)',
        lg: 'var(--radius-lg, 10px)',
      },
    },
  },
  plugins: [],
};
