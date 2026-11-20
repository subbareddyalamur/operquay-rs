import type { ReactNode } from 'react';

export interface StatTileProps {
  label: string;
  value: string;
  delta?: string;
  accent: 'success' | 'danger' | 'warn' | 'info' | 'accent';
  icon?: ReactNode;
  sparkline?: string;
}

const accentVar: Record<StatTileProps['accent'], string> = {
  success: 'var(--success)',
  danger: 'var(--danger)',
  warn: 'var(--warn)',
  info: 'var(--info)',
  accent: 'var(--accent)',
};

export function StatTile({ label, value, delta, accent, icon, sparkline }: StatTileProps) {
  const color = accentVar[accent];
  return (
    <div
      className="p-4 bg-surface rounded-[var(--radius-lg)] border border-border hover:border-[var(--border-strong)] relative overflow-hidden transition-colors"
      style={{ borderTopColor: color, borderTopWidth: 2 }}
    >
      <div className="flex items-center justify-between">
        <div className="text-[11px] text-text-mut uppercase tracking-wider font-semibold">{label}</div>
        {icon && <div style={{ color }}>{icon}</div>}
      </div>
      <div className="mt-1.5 flex items-end justify-between gap-2">
        <div className="text-[32px] font-bold font-mono leading-none tracking-tight tabular-nums text-text-pri">{value}</div>
        {sparkline && (
          <svg width="68" height="22" viewBox="0 0 68 22" fill="none" aria-hidden="true" className="shrink-0 opacity-85">
            <path d={sparkline} stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        )}
      </div>
      {delta && (
        <div className="text-[11px] mt-1.5 font-medium" style={{ color }}>
          {delta}
        </div>
      )}
    </div>
  );
}
