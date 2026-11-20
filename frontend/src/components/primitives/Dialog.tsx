import './ui-sdk-compat';
import { createContext, useContext, useId, useRef, type ReactNode } from 'react';
import { X } from 'lucide-react';
import {
  Dialog as UIDialog,
  DialogBackdrop,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from '@ui-sdk/react/dialog';

export type DialogSize = 'sm' | 'md' | 'lg' | 'xl' | '2xl';

export interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: ReactNode;
  description?: ReactNode;
  size?: DialogSize;
  children: ReactNode;
  footer?: ReactNode;
}

const SIZE_CLASSES: Record<DialogSize, string> = {
  sm: 'max-w-sm',
  md: 'max-w-lg',
  lg: 'max-w-2xl',
  xl: 'max-w-4xl',
  '2xl': 'max-w-[1400px]',
};

/** When true, <Dialog> renders directly as an in-flow page instead of a modal overlay. */
export const DialogPageContext = createContext(false);

export function Dialog(props: DialogProps) {
  const asPage = useContext(DialogPageContext);
  return asPage ? <DialogPage {...props} /> : <DialogOverlay {...props} />;
}

function DialogPage({ open, onOpenChange, title, description, children, footer }: DialogProps) {
  const titleId = useId();
  if (!open) return null;
  return (
    <section className="h-full flex flex-col bg-bg overflow-y-auto" aria-labelledby={titleId} data-dialog-body>
      <div className="w-full px-6 sm:px-8 py-6 space-y-6 flex-1 flex flex-col min-h-0">
        <header className="flex items-start justify-between gap-4 pb-4 border-b border-border shrink-0">
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-wider text-text-dim mb-1">
              Settings · Operations
            </div>
            <h1 className="text-[20px] font-semibold tracking-tight text-text-pri" id={titleId}>
              {title}
            </h1>
            {description && (
              <p className="mt-1 text-xs text-text-sec">{description}</p>
            )}
          </div>
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            aria-label="Close settings"
            title="Close settings (Esc)"
            className="h-8 w-8 flex items-center justify-center rounded-md text-text-mut hover:text-text-pri hover:bg-surface-hover transition-colors shrink-0"
          >
            <X size={16} aria-hidden="true" />
          </button>
        </header>
        <div className="flex-1 min-h-0 flex flex-col">
          {children}
        </div>
        {footer && (
          <footer className="pt-3 border-t border-border flex items-center justify-end gap-2 shrink-0">
            {footer}
          </footer>
        )}
      </div>
    </section>
  );
}

function DialogOverlay({
  open,
  onOpenChange,
  title,
  description,
  size = 'md',
  children,
  footer,
}: DialogProps) {
  const panelRef = useRef<HTMLDivElement | null>(null);

  if (!open) return null;

  return (
    <UIDialog
      open={open}
      onOpenChange={(nextOpen) => onOpenChange(nextOpen)}
      modal
    >
      <DialogBackdrop className="fixed inset-0 z-50 bg-[var(--overlay)] backdrop-blur-xs" />
      <DialogContent
        ref={panelRef}
        aria-modal="true"
        initialFocus={() => {
          const root = panelRef.current;
          if (!root) return undefined;
          const auto = root.querySelector<HTMLElement>('[autofocus]');
          if (auto) return auto;
          const bodyTarget = root.querySelector<HTMLElement>(
            '[data-dialog-body] button:not([disabled]), [data-dialog-body] input:not([disabled]), [data-dialog-body] select:not([disabled]), [data-dialog-body] textarea:not([disabled]), [data-dialog-body] a[href], [data-dialog-body] [tabindex]:not([tabindex="-1"])',
          );
          return bodyTarget ?? root;
        }}
        className={`fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-[calc(100vw-2rem)] ${SIZE_CLASSES[size]} max-h-[85vh] flex flex-col rounded-[var(--radius-lg)] bg-[var(--surface)] border border-[var(--border-strong)] shadow-[var(--shadow-elev)] overflow-hidden focus:outline-none`}
      >
        <header className="flex items-start justify-between gap-4 px-5 py-3.5 border-b border-[var(--border)] shrink-0">
          <div className="min-w-0">
            <DialogTitle className="text-[16px] font-semibold text-[var(--text-pri)] tracking-[-0.01em]">
              {title}
            </DialogTitle>
            {description && (
              <DialogDescription className="mt-0.5 text-xs text-[var(--text-sec)]">
                {description}
              </DialogDescription>
            )}
          </div>
          <DialogClose
            aria-label="Close dialog"
            className="h-7 w-7 -mr-1 -mt-0.5 shrink-0 inline-flex items-center justify-center rounded-[var(--radius-sm)] text-[var(--text-dim)] hover:text-[var(--text-pri)] hover:bg-[var(--elev)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent)] transition-colors"
          >
            <X size={15} aria-hidden="true" />
          </DialogClose>
        </header>
        <div className="flex-1 min-h-0 overflow-y-auto px-5 py-5" data-dialog-body>
          {children}
        </div>
        {footer && (
          <footer className="flex items-center justify-end gap-2 px-5 py-3 border-t border-[var(--border)] bg-[var(--elev)]/40 shrink-0">
            {footer}
          </footer>
        )}
      </DialogContent>
    </UIDialog>
  );
}
