import type { ReactNode } from 'react';

export interface EmptyStateProps {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
  size?: 'sm' | 'md';
  className?: string;
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  size = 'md',
  className = '',
}: EmptyStateProps) {
  const pad = size === 'sm' ? 'py-6 px-4' : 'py-10 px-6';
  return (
    <div
      className={`flex flex-col items-center justify-center text-center border border-dashed border-[var(--border)] rounded-[var(--radius-lg)] bg-[var(--surface)]/40 ${pad} ${className}`}
    >
      {icon && (
        <div className="mb-2.5 flex h-9 w-9 items-center justify-center rounded-full bg-[var(--elev)] border border-[var(--border)] text-[var(--text-sec)]">
          {icon}
        </div>
      )}
      <div className="text-sm font-medium text-[var(--text-pri)]">{title}</div>
      {description && (
        <p className="mt-1 max-w-sm text-xs leading-relaxed text-[var(--text-dim)]">
          {description}
        </p>
      )}
      {action && <div className="mt-3.5 flex items-center gap-2">{action}</div>}
    </div>
  );
}

