import { Activity, X } from 'lucide-react';
import { Badge } from '@/design-system/primitives';
import { usePlatformStore } from '../platform/store';

export function ActivityDrawer({ open, onClose }: { open: boolean; onClose: () => void }) {
  const activities = usePlatformStore((s) => s.activities);
  if (!open) return null;

  return (
    <aside
      aria-label="Activity Center"
      className="fixed right-4 top-14 z-40 w-80 max-h-[70vh] rounded-[var(--radius-lg)] border border-border bg-surface shadow-[var(--shadow-elev)] flex flex-col overflow-hidden"
    >
      <div className="px-4 py-2.5 border-b border-border bg-elev flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs font-semibold text-text-pri">
          <Activity size={14} className="text-accent" aria-hidden="true" />
          Activity Center
        </div>
        <button
          type="button"
          aria-label="Close Activity Center"
          onClick={onClose}
          className="text-text-dim hover:text-text-pri"
        >
          <X size={14} aria-hidden="true" />
        </button>
      </div>
      <div className="flex-1 overflow-y-auto divide-y divide-border text-xs">
        {activities.length === 0 ? (
          <p className="p-4 text-text-dim">No recent background transfers, conversions, or tunnels.</p>
        ) : (
          activities.map((a) => (
            <div key={a.id} className="p-3 space-y-1">
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium text-text-pri">{a.title}</span>
                <Badge tone={a.status === 'done' ? 'success' : a.status === 'error' ? 'danger' : 'info'}>
                  {a.status}
                </Badge>
              </div>
              <div className="text-text-mut">{a.detail}</div>
              <div className="text-[11px] text-text-dim">{a.ts}</div>
            </div>
          ))
        )}
      </div>
    </aside>
  );
}

