import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from 'react';
import { Loader2 } from 'lucide-react';

export type ButtonVariant = 'primary' | 'secondary' | 'accent' | 'ghost' | 'outline' | 'danger' | 'subtle' | 'soft' | 'danger-ghost';
export type ButtonSize = 'xs' | 'sm' | 'md' | 'lg';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: ReactNode;
  iconPosition?: 'left' | 'right';
  loading?: boolean;
  fullWidth?: boolean;
}

const variantClasses: Record<ButtonVariant, string> = {
  primary: 'bg-accent text-accent-fg shadow-sm hover:opacity-90 active:opacity-80',
  secondary: 'bg-elev text-text-pri border border-border hover:bg-surface-hover active:bg-surface',
  accent: 'bg-accent text-accent-fg shadow-sm hover:opacity-90 active:opacity-80',
  ghost: 'bg-transparent text-text-pri hover:bg-elev',
  outline: 'bg-surface text-text-pri border border-border hover:bg-elev hover:border-text-dim',
  danger: 'bg-danger text-danger-fg shadow-sm hover:opacity-90 active:opacity-80',
  subtle: 'bg-elev text-text-pri hover:bg-border-2',
  soft: 'bg-[var(--accent-dim)] text-accent hover:bg-accent hover:text-accent-fg',
  'danger-ghost': 'bg-transparent text-danger hover:bg-[color-mix(in_srgb,var(--danger)_12%,transparent)]',
};

const sizeClasses: Record<ButtonSize, string> = {
  xs: 'h-7 px-2.5 text-[12px] gap-1',
  sm: 'h-8 px-3 text-[13px] gap-1.5',
  md: 'h-9 px-3.5 text-[14px] gap-2',
  lg: 'h-10 px-4 text-[14px] gap-2',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = 'primary',
    size = 'md',
    icon,
    iconPosition = 'left',
    loading = false,
    fullWidth = false,
    className = '',
    disabled,
    children,
    ...rest
  },
  ref,
) {
  const classes = [
    'inline-flex items-center justify-center rounded-md font-medium whitespace-nowrap',
    'transition-[background,color,opacity] duration-120',
    'focus-visible:outline-2 focus-visible:outline-accent focus-visible:outline-offset-2',
    'disabled:opacity-50 disabled:pointer-events-none',
    variantClasses[variant],
    sizeClasses[size],
    fullWidth ? 'w-full' : '',
    className,
  ]
    .filter(Boolean)
    .join(' ');

  const leftContent = loading ? (
    <Loader2 className="animate-spin" size={14} />
  ) : iconPosition === 'left' ? (
    icon
  ) : null;

  const rightContent = !loading && iconPosition === 'right' ? icon : null;

  return (
    <button ref={ref} className={classes} disabled={disabled ?? loading} {...rest}>
      {leftContent}
      {children}
      {rightContent}
    </button>
  );
});

Button.displayName = 'Button';
