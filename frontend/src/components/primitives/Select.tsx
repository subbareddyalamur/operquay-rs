import { forwardRef, type SelectHTMLAttributes } from 'react';
import { ChevronDown } from 'lucide-react';

export interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  error?: string;
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(function Select(
  { error, className = '', children, ...rest },
  ref,
) {
  return (
    <div className="relative">
      <select
        ref={ref}
        className={[
          'w-full appearance-none bg-bg border border-border rounded-md',
          'text-text-pri text-[14px] leading-tight',
          'h-9 pl-3 pr-8',
          'focus:outline-none focus:border-accent focus:ring-2 focus:ring-[var(--accent-dim)]',
          'transition-colors duration-120',
          'cursor-pointer hover:border-text-dim',
          error ? 'border-danger' : '',
          className,
        ]
          .filter(Boolean)
          .join(' ')}
        {...rest}
      >
        {children}
      </select>
      <ChevronDown
        size={12}
        className="absolute right-2.5 top-1/2 -translate-y-1/2 text-text-dim pointer-events-none"
      />
      {error && <span className="text-[11px] text-danger mt-1 block">{error}</span>}
    </div>
  );
});

Select.displayName = 'Select';
