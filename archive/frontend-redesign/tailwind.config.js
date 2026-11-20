/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      colors: {
        bg: 'var(--bg)',
        side: 'var(--side)',
        surface: 'var(--surface)',
        elev: 'var(--elev)',
        border: 'var(--border)',
        'border-strong': 'var(--border-strong)',
        'text-pri': 'var(--text-pri)',
        'text-mut': 'var(--text-mut)',
        'text-dim': 'var(--text-dim)',
        accent: 'var(--accent)',
        'accent-fg': 'var(--accent-fg)',
        success: 'var(--success)',
        warn: 'var(--warn)',
        danger: 'var(--danger)',
        'danger-fg': 'var(--danger-fg)',
        info: 'var(--info)',
      },
    },
  },
  plugins: [],
};

