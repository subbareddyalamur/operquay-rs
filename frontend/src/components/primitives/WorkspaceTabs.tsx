import type { CSSProperties, KeyboardEvent, MouseEvent, ReactNode } from 'react';

function CloseIcon() {
  return (
    <svg
      width="12"
      height="12"
      viewBox="0 0 12 12"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      aria-hidden="true"
    >
      <path d="M3 3l6 6M9 3l-6 6" />
    </svg>
  );
}

export interface WorkspaceTabBarProps {
  ariaLabel?: string;
  role?: 'tablist' | 'none';
  className?: string;
  listClassName?: string;
  emptyText?: ReactNode;
  actionsRef?: (el: HTMLDivElement | null) => void;
  children?: ReactNode;
}

export function WorkspaceTabBar({
  ariaLabel,
  role = 'tablist',
  className = '',
  listClassName = '',
  emptyText,
  actionsRef,
  children,
}: WorkspaceTabBarProps) {
  return (
    <div className={`oq-tabbar ${className}`.trim()}>
      {emptyText ? (
        <div className="flex items-center h-full px-3 text-[13px] text-text-dim">{emptyText}</div>
      ) : (
        <div
          role={role === 'none' ? undefined : 'tablist'}
          aria-label={role === 'none' ? undefined : ariaLabel}
          className={`oq-tab-list ${listClassName}`.trim()}
        >
          {children}
        </div>
      )}
      {actionsRef && <div ref={actionsRef} className="ml-auto flex items-stretch min-w-0 shrink-0" />}
    </div>
  );
}

export interface WorkspaceTabProps {
  active?: boolean;
  icon?: ReactNode;
  label: ReactNode;
  title?: string;
  accentColor?: string;
  statusIndicator?: ReactNode;
  onSelect: () => void;
  onClose?: () => void;
  closeLabel?: string;
  confirmClose?: boolean;
  confirmLabel?: string;
  confirmAriaLabel?: string;
  onConfirmClose?: () => void;
  onContextMenu?: (e: MouseEvent<HTMLDivElement>) => void;
  size?: 'md' | 'sm';
  mode?: 'container-tab' | 'trigger-tab' | 'split-button';
  className?: string;
  children?: ReactNode;
}

export function WorkspaceTab({
  active = false,
  icon,
  label,
  title,
  accentColor,
  statusIndicator,
  onSelect,
  onClose,
  closeLabel = 'Close tab',
  confirmClose = false,
  confirmLabel = 'End?',
  confirmAriaLabel,
  onConfirmClose,
  onContextMenu,
  size = 'md',
  mode = 'container-tab',
  className = '',
  children,
}: WorkspaceTabProps) {
  const style = accentColor
    ? ({ '--oq-tab-accent': accentColor } as CSSProperties)
    : undefined;

  const classes = [
    'oq-tab',
    size === 'sm' ? 'oq-tab-sm' : '',
    active ? 'active' : '',
    className,
  ]
    .filter(Boolean)
    .join(' ');

  const handleAuxClick = (e: MouseEvent<HTMLDivElement>) => {
    if (e.button === 1 && onClose) {
      e.preventDefault();
      onClose();
    }
  };

  const closeControl = confirmClose && onConfirmClose ? (
    <button
      type="button"
      className="oq-tab-confirm"
      onClick={(e) => {
        e.stopPropagation();
        onConfirmClose();
      }}
      aria-label={confirmAriaLabel ?? closeLabel}
    >
      {confirmLabel}
    </button>
  ) : onClose ? (
    <button
      type="button"
      className="oq-tab-close"
      onClick={(e) => {
        e.stopPropagation();
        onClose();
      }}
      aria-label={closeLabel}
      title={closeLabel}
    >
      <CloseIcon />
    </button>
  ) : null;

  if (mode === 'container-tab') {
    const handleKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        onSelect();
      }
    };

    return (
      <div
        role="tab"
        aria-selected={active}
        tabIndex={0}
        title={title}
        style={style}
        onClick={onSelect}
        onAuxClick={handleAuxClick}
        onKeyDown={handleKeyDown}
        onContextMenu={onContextMenu}
        className={classes}
      >
        {icon && <span className="oq-tab-icon">{icon}</span>}
        <span className="oq-tab-title">{label}</span>
        {statusIndicator}
        {closeControl}
        {children}
      </div>
    );
  }

  return (
    <div
      style={style}
      onAuxClick={handleAuxClick}
      onContextMenu={onContextMenu}
      className={classes}
    >
      <button
        type="button"
        role={mode === 'trigger-tab' ? 'tab' : undefined}
        aria-selected={mode === 'trigger-tab' ? active : undefined}
        title={title}
        className="oq-tab-trigger"
        onClick={onSelect}
      >
        {icon && <span className="oq-tab-icon">{icon}</span>}
        <span className="oq-tab-title">{label}</span>
        {statusIndicator}
      </button>
      {closeControl}
      {children}
    </div>
  );
}

