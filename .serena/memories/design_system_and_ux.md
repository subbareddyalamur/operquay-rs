# Design System & Settings UX Memory

Follows `RULES.md` §5 and `ADR-0007`:
- **Themes**: Dark (`--bg: #0e1116`, `--surface: #161b22`, `--accent: #3fb8af`) and Light (`--bg: #f5f6f8`, `--surface: #ffffff`, `--accent: #0f766e`).
- **Fonts**: `'Inter'` UI (`13-15px` body, `16-20px` titles) and `'JetBrains Mono'` telemetry/keys/hex LCIDs.
- **Zero Inline Hex**: All colors live strictly in `frontend/src/styles/tokens.css`.
- **Settings UX Architecture**:
  - `SETTINGS_SECTIONS` registry in `frontend/src/features/settings/registry.ts` drives left nav + search filter (`/` shortcut).
  - Goal-based Connection Profile cards (`auto_adaptive`, `ultra_low_latency`, `balanced_wan`, `constrained_wan`) at top.
  - Interactive Network Latency Simulator (`15 ms LAN`, `120 ms WAN`, `280 ms Lossy SSM`) displays live quality, codec path, and cursor mode calculations matching backend formulas.
  - Progressive disclosure sections (*Display & Codecs*, *Input & Keyboards*, *Security & Certificates*, *Clipboard & Recording*, *OpenTelemetry & Diagnostics*).
  - Sticky contextual Dirty Action Bar (appears only on diff, displays changed count, Reset, and Save).
- **Accessibility**: WCAG 2.2 AA, `:focus-visible` `2px solid var(--accent)`, `prefers-reduced-motion`, zero `@axe-core/playwright` violations across Dark & Light.

