import { forwardRef, type InputHTMLAttributes, type ReactNode } from 'react';

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  leftIcon?: ReactNode;
  icon?: ReactNode;
  rightIcon?: ReactNode;
  error?: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(function Input(
  { leftIcon, icon, rightIcon, error, className = '', ...rest },
  ref,
) {
  const resolvedLeftIcon = leftIcon ?? icon;
  return (
    <div className="relative flex flex-col gap-1">
      <div className="relative flex items-center">
        {resolvedLeftIcon && (
          <span className="absolute left-2 text-text-dim pointer-events-none flex items-center">
            {resolvedLeftIcon}
          </span>
        )}
        <input
          ref={ref}
          className={[
            'w-full bg-bg border border-border rounded-md text-text-pri',
            'text-[14px] leading-tight',
            'placeholder:text-text-dim hover:border-text-dim',
            'focus:outline-none focus:border-accent focus:ring-2 focus:ring-[var(--accent-dim)]',
            'transition-colors duration-120',
            'h-9',
            resolvedLeftIcon ? 'pl-8' : 'pl-3',
            rightIcon ? 'pr-8' : 'pr-3',
            error ? 'border-danger' : '',
            className,
          ]
            .filter(Boolean)
            .join(' ')}
          {...rest}
        />
        {rightIcon && (
          <span className="absolute right-2 text-text-dim pointer-events-none flex items-center">
            {rightIcon}
          </span>
        )}
      </div>
      {error && <span className="text-[11px] text-danger">{error}</span>}
    </div>
  );
});

Input.displayName = 'Input';
