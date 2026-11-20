import './ui-sdk-compat';
import type { ReactNode } from 'react';
import { AlertTriangle } from 'lucide-react';
import {
  AlertDialog,
  AlertDialogBackdrop,
  AlertDialogClose,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogTitle,
} from '@ui-sdk/react/alert-dialog';
import { Button } from './Button';

export interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  tone?: 'danger' | 'accent';
  busy?: boolean;
  onConfirm: () => void | Promise<void>;
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel = 'Confirm',
  cancelLabel = 'Cancel',
  tone = 'danger',
  busy = false,
  onConfirm,
}: ConfirmDialogProps) {
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogBackdrop className="fixed inset-0 z-50 bg-[var(--overlay)] backdrop-blur-xs" />
      <AlertDialogContent
        aria-modal="true"
        className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-full max-w-md rounded-[var(--radius-lg)] bg-[var(--surface)] border border-[var(--border-strong)] p-5 shadow-[var(--shadow-elev)] focus:outline-none"
      >
        <div className="flex items-start gap-3">
          {tone === 'danger' && (
            <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-[var(--danger)]/10 border border-[var(--danger)]/25 text-[var(--danger)]">
              <AlertTriangle size={15} aria-hidden="true" />
            </div>
          )}
          <div className="min-w-0 flex-1 space-y-1.5">
            <AlertDialogTitle className="text-sm font-semibold text-[var(--text-pri)]">
              {title}
            </AlertDialogTitle>
            {description && (
              <AlertDialogDescription className="text-xs leading-relaxed text-[var(--text-sec)]">
                {description}
              </AlertDialogDescription>
            )}
          </div>
        </div>
        <div className="mt-5 flex items-center justify-end gap-2">
          <AlertDialogClose
            render={
              <Button variant="ghost" size="sm" disabled={busy}>
                {cancelLabel}
              </Button>
            }
          />
          <Button
            variant={tone === 'danger' ? 'danger' : 'accent'}
            size="sm"
            loading={busy}
            onClick={() => {
              void onConfirm();
            }}
          >
            {confirmLabel}
          </Button>
        </div>
      </AlertDialogContent>
    </AlertDialog>
  );
}
