import { forwardRef, useId, type ButtonHTMLAttributes, type HTMLAttributes, type ReactNode } from 'react';
import { ChevronDown, Loader2, Moon, Sun } from 'lucide-react';

export type ButtonVariant = 'primary' | 'outline' | 'ghost' | 'danger';
export type ButtonSize = 'xs' | 'sm' | 'md';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  icon?: ReactNode;
}

const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary: 'bg-accent text-accent-fg shadow-sm hover:opacity-90 active:opacity-80',
  outline: 'bg-surface text-text-pri border border-border hover:bg-surface-hover',
  ghost: 'bg-transparent text-text-mut hover:text-text-pri hover:bg-elev',
  danger: 'bg-danger text-danger-fg shadow-sm hover:opacity-90',
};

const BUTTON_SIZES: Record<ButtonSize, string> = {
  xs: 'h-7 px-2.5 text-xs gap-1.5',
  sm: 'h-8 px-3 text-[13px] gap-1.5',
  md: 'h-9 px-3.5 text-[13px] gap-2',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'primary', size = 'md', loading = false, icon, className = '', disabled, children, ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={rest.type ?? 'button'}
      disabled={disabled || loading}
      className={[
        'inline-flex items-center justify-center rounded-[var(--radius-sm)] font-medium whitespace-nowrap',
        'transition-[background,color,opacity,border-color] duration-150',
        'disabled:opacity-50 disabled:pointer-events-none',
        BUTTON_VARIANTS[variant],
        BUTTON_SIZES[size],
        className,
      ].join(' ')}
      {...rest}
    >
      {loading ? <Loader2 className="animate-spin" size={14} aria-hidden="true" /> : icon}
      {children}
    </button>
  );
});

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  children: ReactNode;
  className?: string;
  elevated?: boolean;
}

export function Card({
  children,
  className = '',
  elevated = false,
  ...rest
}: CardProps) {
  return (
    <div
      className={[
        'rounded-[var(--radius-lg)] border border-border bg-surface',
        elevated ? 'shadow-[var(--shadow-sm)]' : '',
        className,
      ].join(' ')}
      {...rest}
    >
      {children}
    </div>
  );
}

export type BadgeTone = 'neutral' | 'accent' | 'success' | 'warn' | 'danger' | 'info';

const BADGE_TONES: Record<BadgeTone, string> = {
  neutral: 'bg-elev text-text-mut border-border',
  accent: 'bg-[var(--accent-dim)] text-accent border-[var(--accent-border)]',
  success: 'bg-[var(--success-dim)] text-success border-border',
  warn: 'bg-[var(--warn-dim)] text-warn border-border',
  danger: 'bg-[var(--danger-dim)] text-danger border-border',
  info: 'bg-[var(--info-dim)] text-info border-border',
};

export function Badge({
  children,
  tone = 'neutral',
  className = '',
}: {
  children: ReactNode;
  tone?: BadgeTone;
  className?: string;
}) {
  return (
    <span
      className={[
        'inline-flex items-center gap-1 px-2 py-0.5 rounded-[var(--radius-sm)] border text-[11px] font-medium leading-4',
        BADGE_TONES[tone],
        className,
      ].join(' ')}
    >
      {children}
    </span>
  );
}

export function Switch({
  checked,
  onChange,
  label,
  description,
  id,
  disabled = false,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: string;
  description?: string;
  id?: string;
  disabled?: boolean;
}) {
  const autoId = useId();
  const controlId = id ?? autoId;
  const descId = description ? `${controlId}-desc` : undefined;

  return (
    <div className="flex items-start justify-between gap-4 py-2">
      <div className="min-w-0 flex-1">
        <label htmlFor={controlId} className="block text-[13px] font-medium text-text-pri cursor-pointer">
          {label}
        </label>
        {description && (
          <p id={descId} className="mt-0.5 text-xs text-text-dim leading-relaxed">
            {description}
          </p>
        )}
      </div>
      <button
        id={controlId}
        type="button"
        role="switch"
        aria-checked={checked}
        aria-describedby={descId}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={[
          'relative inline-flex h-6 w-11 shrink-0 cursor-pointer items-center rounded-full border transition-colors duration-150',
          checked ? 'bg-accent border-[var(--accent-border)]' : 'bg-elev border-border-strong',
          disabled ? 'opacity-50 pointer-events-none' : '',
        ].join(' ')}
      >
        <span
          className={[
            'pointer-events-none inline-block h-4 w-4 rounded-full bg-surface shadow-sm transition-transform duration-150',
            checked ? 'translate-x-[22px]' : 'translate-x-[3px]',
          ].join(' ')}
        />
      </button>
    </div>
  );
}

export interface SegmentedOption<T extends string> {
  value: T;
  label: string;
}

export function SegmentedControl<T extends string>({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: T;
  options: readonly SegmentedOption<T>[];
  onChange: (next: T) => void;
}) {
  const groupId = useId();
  return (
    <div className="space-y-1.5">
      <div id={groupId} className="text-[13px] font-medium text-text-pri">
        {label}
      </div>
      <div
        role="radiogroup"
        aria-labelledby={groupId}
        className="inline-flex flex-wrap gap-1 rounded-[var(--radius-md)] border border-border bg-bg p-1"
      >
        {options.map((opt) => {
          const active = opt.value === value;
          return (
            <button
              key={opt.value}
              type="button"
              role="radio"
              aria-checked={active}
              onClick={() => onChange(opt.value)}
              className={[
                'px-3 py-1.5 rounded-[var(--radius-sm)] text-xs font-medium transition-colors',
                active
                  ? 'bg-surface text-accent border border-[var(--accent-border)] shadow-sm'
                  : 'text-text-mut hover:text-text-pri hover:bg-surface-hover border border-transparent',
              ].join(' ')}
            >
              {opt.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}

export function Slider({
  id,
  label,
  description,
  min,
  max,
  step = 1,
  value,
  unit = '',
  onChange,
}: {
  id?: string;
  label: string;
  description?: string;
  min: number;
  max: number;
  step?: number;
  value: number;
  unit?: string;
  onChange: (next: number) => void;
}) {
  const autoId = useId();
  const controlId = id ?? autoId;
  return (
    <div className="space-y-1.5 py-1.5">
      <div className="flex items-center justify-between gap-2">
        <label htmlFor={controlId} className="text-[13px] font-medium text-text-pri">
          {label}
        </label>
        <span className="tabular-mono text-xs px-2 py-0.5 rounded-[var(--radius-sm)] bg-elev border border-border text-text-pri">
          {value}
          {unit}
        </span>
      </div>
      {description && <p className="text-xs text-text-dim">{description}</p>}
      <input
        id={controlId}
        type="range"
        min={min}
        max={max}
        step={step}
        value={value}
        aria-valuetext={`${value}${unit}`}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full accent-[var(--accent)] cursor-pointer"
      />
    </div>
  );
}

export function Disclosure({
  title,
  subtitle,
  badge,
  expanded,
  onToggle,
  children,
}: {
  title: string;
  subtitle: string;
  badge?: ReactNode;
  expanded: boolean;
  onToggle: () => void;
  children: ReactNode;
}) {
  const panelId = useId();
  return (
    <Card>
      <button
        type="button"
        aria-expanded={expanded}
        aria-controls={panelId}
        onClick={onToggle}
        className="w-full flex items-center justify-between gap-4 px-5 py-4 text-left hover:bg-surface-hover/50 transition-colors rounded-[var(--radius-lg)]"
      >
        <div className="min-w-0">
          <div className="flex items-center gap-2.5 flex-wrap">
            <h3 className="text-[15px] font-semibold text-text-pri tracking-[-0.01em]">{title}</h3>
            {badge}
          </div>
          <p className="mt-0.5 text-xs text-text-mut">{subtitle}</p>
        </div>
        <ChevronDown
          size={16}
          aria-hidden="true"
          className={[
            'shrink-0 text-text-dim transition-transform duration-150',
            expanded ? 'rotate-180' : '',
          ].join(' ')}
        />
      </button>
      {expanded && (
        <div id={panelId} className="px-5 pb-5 pt-2 border-t border-border space-y-4">
          {children}
        </div>
      )}
    </Card>
  );
}

export function ThemeToggle({
  theme,
  onToggle,
}: {
  theme: 'dark' | 'light';
  onToggle: () => void;
}) {
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={onToggle}
      aria-label={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} theme`}
      icon={theme === 'dark' ? <Sun size={14} aria-hidden="true" /> : <Moon size={14} aria-hidden="true" />}
    >
      {theme === 'dark' ? 'Light' : 'Dark'}
    </Button>
  );
}

export function ToastBanner({
  toast,
  onDismiss,
}: {
  toast: { id: string; tone: 'success' | 'danger' | 'info'; message: string } | null;
  onDismiss: () => void;
}) {
  if (!toast) return null;
  return (
    <div
      role="status"
      aria-live="polite"
      className="fixed top-14 right-5 z-50 max-w-sm rounded-[var(--radius-md)] border border-border-strong bg-surface px-4 py-3 shadow-[var(--shadow-elev)] flex items-center gap-3"
    >
      <Badge tone={toast.tone}>{toast.tone.toUpperCase()}</Badge>
      <span className="text-[13px] text-text-pri flex-1">{toast.message}</span>
      <Button variant="ghost" size="xs" onClick={onDismiss} aria-label="Dismiss notification">
        Close
      </Button>
    </div>
  );
}
