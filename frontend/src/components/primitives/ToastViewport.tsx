import { CheckCircle, AlertTriangle, Info, XCircle, X, ExternalLink } from 'lucide-react';
import { useToastStore, type Toast } from '@/stores/toast';

const variantConfig = {
  info: { icon: Info, border: 'border-l-info', text: 'text-info' },
  success: { icon: CheckCircle, border: 'border-l-success', text: 'text-success' },
  warn: { icon: AlertTriangle, border: 'border-l-warn', text: 'text-warn' },
  danger: { icon: XCircle, border: 'border-l-danger', text: 'text-danger' },
  progress: { icon: Info, border: 'border-l-accent', text: 'text-accent' },
};

function ToastItem({ toast }: { toast: Toast }) {
  const dismiss = useToastStore((s) => s.dismiss);
  const config = variantConfig[toast.variant];
  const Icon = config.icon;

  return (
    <div
      className={`relative flex items-start gap-3 p-3.5 rounded-[var(--radius-lg)] border border-border border-l-4 ${config.border} bg-surface shadow-[var(--shadow)]`}
      role={toast.variant === 'danger' ? 'alert' : 'status'}
      aria-live={toast.variant === 'danger' ? 'assertive' : 'polite'}
    >
      <Icon size={16} className={`${config.text} mt-0.5 shrink-0`} />
      <div className="flex-1 min-w-0">
        <p className="text-[14px] font-semibold text-text-pri">{toast.title}</p>
        {toast.description && (
          <p className="text-[13px] text-text-mut mt-0.5">{toast.description}</p>
        )}
        {toast.variant === 'progress' && toast.progress !== undefined && (
          <div className="h-1 mt-2 rounded-full bg-border overflow-hidden">
            <div
              className="h-full bg-accent transition-all duration-300 rounded-full"
              style={{ width: `${Math.round(toast.progress ?? 0)}%` }}
            />
          </div>
        )}
        {toast.link && (
          <a
            href={toast.link.href}
            target="_blank"
            rel="noopener noreferrer"
            className="mt-1.5 inline-flex items-center gap-1 text-[11px] font-medium text-accent hover:underline"
          >
            <ExternalLink size={10} className="shrink-0" />
            {toast.link.label}
          </a>
        )}
        {toast.action && (
          <button
            type="button"
            onClick={() => { toast.action!.onClick(); dismiss(toast.id); }}
            className="mt-2 text-[11px] font-medium text-accent hover:underline"
          >
            {toast.action.label}
          </button>
        )}
      </div>
      <button
        type="button"
        onClick={() => dismiss(toast.id)}
        className="text-text-mut hover:text-text-pri hover:bg-elev rounded-md p-1 -m-1 shrink-0"
        aria-label="Dismiss notification"
      >
        <X size={14} />
      </button>
    </div>
  );
}

export function ToastViewport() {
  const toasts = useToastStore((s) => s.toasts);
  const visible = toasts.slice(0, 5);

  return (
    <div className="fixed right-4 bottom-8 z-[9600] w-[min(380px,calc(100vw-2rem))] flex flex-col gap-2 max-h-[440px] scrollbar-none">
      {visible.map((t) => (
        <ToastItem key={t.id} toast={t} />
      ))}
    </div>
  );
}

ToastViewport.displayName = 'ToastViewport';
