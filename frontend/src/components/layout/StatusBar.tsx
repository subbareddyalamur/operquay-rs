import { useMemo } from 'react';
import { RefreshCw } from 'lucide-react';
import { useSessionsStore } from '@/stores/sessions';
import { useInstancesStore } from '@/stores/instances';
import { useAuthStore, hasPermission } from '@/stores/auth';
import { getAllInstances } from '@/lib/filter';
import { StatusDot } from '@/components/primitives';

export function StatusBar() {
  const sessionCount = useSessionsStore((s) => s.sessions.length);
  const busy = useInstancesStore((s) => s.loading || s.discovering);
  const lastDiscoveryAt = useInstancesStore((s) => s.lastDiscoveryAt);
  const accounts = useInstancesStore((s) => s.accounts);
  const { instanceCount, runningCount } = useMemo(() => {
    const all = getAllInstances(accounts);
    return {
      instanceCount: all.length,
      runningCount: all.filter((i) => i.state === 'running').length,
    };
  }, [accounts]);
  const roleCount = useInstancesStore((s) => s.userRoles.filter(role => role.live !== false).length);
  const triggerDiscovery = useInstancesStore((s) => s.triggerDiscovery);
  const userMode = useAuthStore((s) => s.config?.aws_access_mode === 'user');
  const canSharedDiscovery = useAuthStore((s) => !s.me || hasPermission(s.me, 'instances:scan'));

  // User-mode fetches use the person's own roles; shared discovery stays operator-only.
  const canRefetch = userMode ? roleCount > 0 : canSharedDiscovery;
  const fetchTime = lastDiscoveryAt ? new Date(lastDiscoveryAt).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' }) : null;

  return (
    <footer className="h-[26px] flex items-center px-3 gap-4 bg-side border-t border-border text-[12px] text-text-mut overflow-hidden select-none">
      <span className="inline-flex items-center gap-1.5 tabular-nums text-text-mut">
        {runningCount > 0 && <StatusDot state="running" />}
        <span>{instanceCount} instance{instanceCount === 1 ? '' : 's'}</span>
        {instanceCount > 0 && (
          <span className="text-text-dim">({runningCount} running)</span>
        )}
      </span>
      {busy ? <span>Discovering…</span> : fetchTime && <span title={new Date(lastDiscoveryAt!).toLocaleString()}>Last fetch {fetchTime}</span>}
      {canRefetch && <button
        type="button"
        onClick={() => void triggerDiscovery()}
        disabled={busy}
        className="inline-flex items-center gap-1 h-5 px-1.5 -mx-1 rounded text-text-mut hover:text-accent hover:bg-elev disabled:opacity-50 disabled:hover:bg-transparent disabled:hover:text-text-mut focus-visible:outline-2 focus-visible:outline-accent transition-colors"
        title={userMode ? 'Fetch instances from every connected AWS account' : 'Fetch instances from all AWS accounts'}
      >
        <RefreshCw size={11} aria-hidden="true" className={busy ? 'animate-spin motion-reduce:animate-none' : ''} />
        Fetch
      </button>}
      {sessionCount > 0 && (
        <span className="tabular-nums text-text-pri">{sessionCount} active session{sessionCount !== 1 ? 's' : ''}</span>
      )}
      <span className="ml-auto hidden sm:inline-flex items-center gap-3 text-[11px] text-text-dim font-mono">
        <span>⌘K Palette</span>
        <span>⌘B Sidebar</span>
      </span>
    </footer>
  );
}
