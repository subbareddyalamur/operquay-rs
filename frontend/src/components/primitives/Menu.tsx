import { useCallback, useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { Check } from 'lucide-react';
import { createTypeahead, isTypeaheadKey, labelOf } from '@ui-sdk/core';

export interface MenuItem {
  label: string;
  hint?: string;
  onSelect: () => void;
  disabled?: boolean;
  danger?: boolean;
  checked?: boolean;
  icon?: ReactNode;
}

export interface MenuSection {
  heading?: string;
  icon?: ReactNode;
  items: MenuItem[];
}

export interface MenuProps {
  label: string;
  trigger: ReactNode;
  sections: MenuSection[];
  align?: 'left' | 'right';
  triggerClassName?: string;
  className?: string;
  header?: ReactNode;
  footer?: ReactNode;
}

const ITEM_SELECTOR = '[role="menuitem"]:not([disabled]), [role="menuitemradio"]:not([disabled])';

/** Click-to-open menu with WAI-ARIA keyboard navigation, typeahead, and focus recovery. */
export function Menu({
  label,
  trigger,
  sections,
  align = 'right',
  triggerClassName = '',
  className = '',
  header,
  footer,
}: MenuProps) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const pendingFocusRef = useRef<'first' | 'last' | null>(null);
  const menuId = useId();
  const typeahead = useMemo(() => createTypeahead(500), []);

  const closeMenu = useCallback((restoreFocus = false) => {
    setOpen(false);
    typeahead.reset();
    if (restoreFocus) {
      queueMicrotask(() => triggerRef.current?.focus());
    }
  }, [typeahead]);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (e: PointerEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) closeMenu(false);
    };
    const onEscape = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        closeMenu(true);
      }
    };
    document.addEventListener('pointerdown', onPointerDown);
    document.addEventListener('keydown', onEscape);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
      document.removeEventListener('keydown', onEscape);
    };
  }, [open, closeMenu]);

  useEffect(() => {
    if (!open) return;
    const focusMode = pendingFocusRef.current ?? 'first';
    pendingFocusRef.current = null;
    const raf = requestAnimationFrame(() => {
      const items = Array.from(menuRef.current?.querySelectorAll<HTMLElement>(ITEM_SELECTOR) ?? []);
      if (items.length === 0) return;
      const target = focusMode === 'last' ? items[items.length - 1] : items[0];
      target?.focus();
    });
    return () => cancelAnimationFrame(raf);
  }, [open]);

  const onTriggerKeyDown = (e: KeyboardEvent<HTMLButtonElement>) => {
    if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
      if (!open && e.key === 'ArrowDown') {
        e.preventDefault();
        pendingFocusRef.current = 'first';
        setOpen(true);
      }
    } else if (e.key === 'ArrowUp' && !open) {
      e.preventDefault();
      pendingFocusRef.current = 'last';
      setOpen(true);
    }
  };

  const onMenuKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const items = Array.from(menuRef.current?.querySelectorAll<HTMLElement>(ITEM_SELECTOR) ?? []);
    if (items.length === 0) return;
    const idx = items.indexOf(document.activeElement as HTMLElement);

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      items[(idx + 1) % items.length]?.focus();
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      items[(idx - 1 + items.length) % items.length]?.focus();
      return;
    }
    if (e.key === 'Home') {
      e.preventDefault();
      items[0]?.focus();
      return;
    }
    if (e.key === 'End') {
      e.preventDefault();
      items[items.length - 1]?.focus();
      return;
    }
    if (e.key === 'Tab') {
      closeMenu(false);
      return;
    }
    if (isTypeaheadKey(e.nativeEvent)) {
      const labels = items.map((el) => labelOf(el));
      const match = typeahead(e.key, labels, idx);
      if (match >= 0) {
        e.preventDefault();
        items[match]?.focus();
      }
    }
  };

  return (
    <div ref={rootRef} className="relative inline-block">
      <button
        ref={triggerRef}
        type="button"
        aria-label={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => setOpen((was) => !was)}
        onKeyDown={onTriggerKeyDown}
        className={triggerClassName}
      >
        {trigger}
      </button>

      {open && (
        <div
          id={menuId}
          ref={menuRef}
          role="menu"
          aria-label={label}
          onKeyDown={onMenuKeyDown}
          className={`absolute top-full mt-1.5 z-50 min-w-[228px] rounded-[var(--radius-lg)] border border-[var(--border-strong)] bg-[var(--glass-bg)] backdrop-blur-md shadow-[var(--shadow-elev)] p-1.5 ${align === 'right' ? 'right-0' : 'left-0'} ${className}`}
        >
          {header && <div className="px-2.5 py-2 border-b border-[var(--border)] mb-1">{header}</div>}

          {sections.map((section, s) => (
            <div key={s} className={s > 0 ? 'border-t border-[var(--border)] mt-1 pt-1' : ''}>
              {section.heading && (
                <div className="px-2.5 py-1 flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-[0.06em] text-[var(--text-dim)]">
                  {section.icon && <span className="shrink-0">{section.icon}</span>}
                  <span>{section.heading}</span>
                </div>
              )}
              {section.items.map((item) => {
                const isRadio = item.checked !== undefined;
                return (
                  <button
                    key={item.label}
                    type="button"
                    role={isRadio ? 'menuitemradio' : 'menuitem'}
                    aria-checked={isRadio ? item.checked : undefined}
                    disabled={item.disabled}
                    onClick={() => {
                      closeMenu(false);
                      item.onSelect();
                    }}
                    className={`w-full flex items-center justify-between gap-3 px-2.5 h-8 rounded-[var(--radius)] text-left text-[13px] transition-colors ${
                      item.disabled
                        ? 'opacity-40 cursor-not-allowed text-[var(--text-dim)]'
                        : item.danger
                        ? 'text-[var(--danger)] hover:bg-[var(--surface-hover)] focus:bg-[var(--surface-hover)] focus:outline-none'
                        : 'text-[var(--text-pri)] hover:bg-[var(--surface-hover)] focus:bg-[var(--surface-hover)] focus:outline-none'
                    }`}
                  >
                    <span className="flex items-center gap-2 min-w-0 truncate">
                      {isRadio ? (
                        <span className="w-3.5 shrink-0 inline-flex items-center justify-center text-[var(--accent)]">
                          {item.checked ? <Check size={13} aria-hidden="true" /> : null}
                        </span>
                      ) : item.icon ? (
                        <span className="text-[var(--text-dim)] shrink-0">{item.icon}</span>
                      ) : null}
                      <span className="truncate">{item.label}</span>
                    </span>
                    {item.hint && (
                      <span className="text-[11px] font-mono text-[var(--text-dim)] shrink-0">
                        {item.hint}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          ))}

          {footer && <div className="border-t border-[var(--border)] mt-1 pt-1">{footer}</div>}
        </div>
      )}
    </div>
  );
}
