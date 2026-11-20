import { useEffect, useLayoutEffect, useRef, useState, useCallback, useMemo } from 'react';
import { Search } from 'lucide-react';
import { usePaletteStore } from '@/stores/palette';
import { useInstancesStore } from '@/stores/instances';
import { useSessionsStore } from '@/stores/sessions';
import { buildPaletteGroups } from '@/lib/palette-providers';
import type { PaletteItem } from '@/lib/palette-providers';
import { getAllInstances, getFilteredAccounts } from '@/lib/filter';
import { PaletteRow } from './PaletteRow';
import { hasPermission, useAuthStore } from '@/stores/auth';
import { useAIStore } from '@/stores/ai';
import { useLayoutStore } from '@/stores/layout';
import { useThemeStore } from '@/stores/theme';
import { assistantName, useSettingsStore } from '@/stores/settings';

export function CmdKPalette() {
  const open = usePaletteStore((s) => s.open);
  const query = usePaletteStore((s) => s.query);
  const setQuery = usePaletteStore((s) => s.setQuery);
  const setOpen = usePaletteStore((s) => s.setOpen);

  const accounts = useInstancesStore((s) => s.accounts);
  const favorites = useInstancesStore((s) => s.favorites);
  const roleCount = useInstancesStore((s) => s.userRoles.filter((r) => r.live !== false).length);
  const sessions = useSessionsStore((s) => s.sessions);
  const canAudit = useAuthStore((s) => hasPermission(s.me, 'audit:read'));
  const canRecordings = useAuthStore((s) => hasPermission(s.me, 'recordings:read'));
  const userMode = useAuthStore((s) => s.config?.aws_access_mode === 'user');
  const canSSH = useAuthStore((s) => Boolean(s.me) && (s.me?.role !== 'readonly' || hasPermission(s.me, 'session:ssh')));
  const canRefetchPerm = useAuthStore((s) => Boolean(s.me) && (s.me?.role !== 'readonly' || hasPermission(s.me, 'instances:scan')));
  const readonly = !canSSH;
  const canUseAI = useAuthStore((s) => Boolean(s.me) && (s.me?.role !== 'readonly' || hasPermission(s.me, 'ai:use')));
  const canRefetch = userMode ? roleCount > 0 : canRefetchPerm;
  const name = assistantName(useSettingsStore((s) => s.assistantName));
  const enableKubernetes = useSettingsStore((s) => s.enableKubernetes ?? true);
  const enableDatabases = useSettingsStore((s) => s.enableDatabases ?? true);

  const instances = useMemo(
    () => getAllInstances(getFilteredAccounts(accounts, query)),
    [accounts, query],
  );

  const [activeIdx, setActiveIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const groups = buildPaletteGroups(query, {
    instances,
    favoriteIds: favorites,
    recentSessions: sessions.map((s) => ({ id: s.id, instanceName: s.instanceName, type: s.type, createdAt: s.createdAt })),
    onSSH: (instanceId, instanceName) => {
      setOpen(false);
      if (readonly) {
        useLayoutStore.getState().setView('session');
        useLayoutStore.getState().showDetails(instanceId);
        return;
      }
      window.dispatchEvent(new CustomEvent('ct:open-ssh', { detail: { instanceId, instanceName } }));
    },
    onRDP: () => setOpen(false),
    onDetails: (instanceId) => {
      setOpen(false);
      useLayoutStore.getState().setView('session');
      useLayoutStore.getState().showDetails(instanceId);
    },
    onSelectSession: (sessionId) => {
      setOpen(false);
      useLayoutStore.getState().setView('session');
      useSessionsStore.getState().setActive(sessionId);
    },
    onOpenSettings: () => { setOpen(false); useLayoutStore.getState().openSettings('appearance'); },
    onToggleAI: () => { setOpen(false); const ai = useAIStore.getState(); ai.setOpen(!ai.open); },
    onCycleTheme: () => { setOpen(false); useThemeStore.getState().cycleTheme(); },
    enableKubernetes,
    enableDatabases,
    onSwitchWorkspace: (view) => { setOpen(false); useLayoutStore.getState().setView(view); },
    onToggleSidebar: () => { setOpen(false); useLayoutStore.getState().toggleSidebar(); },
    onRefetch: canRefetch ? () => { setOpen(false); void useInstancesStore.getState().triggerDiscovery(); } : undefined,
    onOpenCloudConnections: !readonly ? () => { setOpen(false); window.dispatchEvent(new CustomEvent('ct:open-aws-accounts')); } : undefined,
    onOpenAudit: canAudit ? () => { setOpen(false); useLayoutStore.getState().openSettings('audit'); } : undefined,
    onOpenRecordings: canRecordings ? () => { setOpen(false); useLayoutStore.getState().openSettings('recordings'); } : undefined,
    assistantName: name,
  }).map((group) => ({ ...group, items: group.items.filter((item) => canUseAI || item.id !== 'cmd-ai') })).filter((group) => group.items.length > 0);

  const allItems: PaletteItem[] = groups.flatMap((g) => g.items);

  const clampedIdx = allItems.length > 0 ? Math.min(activeIdx, allItems.length - 1) : 0;
  const activeItem = allItems[clampedIdx];

  useEffect(() => {
    if (!open) return;
    const el = listRef.current?.querySelector<HTMLElement>('[data-palette-idx-active="true"]');
    el?.scrollIntoView?.({ block: 'nearest' });
  }, [open, clampedIdx, query]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      switch (e.key) {
        case 'ArrowDown':
          e.preventDefault();
          setActiveIdx((i) => Math.min(i + 1, Math.max(0, allItems.length - 1)));
          break;
        case 'ArrowUp':
          e.preventDefault();
          setActiveIdx((i) => Math.max(i - 1, 0));
          break;
        case 'Home':
          e.preventDefault();
          setActiveIdx(0);
          break;
        case 'End':
          e.preventDefault();
          setActiveIdx(Math.max(0, allItems.length - 1));
          break;
        case 'PageDown':
          e.preventDefault();
          setActiveIdx((i) => Math.min(i + 5, Math.max(0, allItems.length - 1)));
          break;
        case 'PageUp':
          e.preventDefault();
          setActiveIdx((i) => Math.max(i - 5, 0));
          break;
        case 'Enter': {
          e.preventDefault();
          const item = allItems[clampedIdx];
          if (item) {
            if ((e.metaKey || e.ctrlKey) && item.id.startsWith('inst-')) {
              const instanceId = item.id.slice(5);
              useLayoutStore.getState().setView('session');
              useLayoutStore.getState().showDetails(instanceId);
            } else {
              item.action();
            }
            setOpen(false);
          }
          break;
        }
        case 'Escape':
          e.preventDefault();
          setOpen(false);
          break;
      }
    },
    [allItems, clampedIdx, setOpen],
  );

  useLayoutEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    inputRef.current?.focus();
    return () => { if (previous?.isConnected) previous.focus(); };
  }, [open]);

  useEffect(() => { if (open) setActiveIdx(0); }, [open]);

  useEffect(() => {
    setActiveIdx(0);
  }, [query]);

  if (!open) return null;

  let runningIdx = 0;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh]"
      style={{ background: 'var(--overlay)' }}
      onClick={() => setOpen(false)}
    >
      <div
        className="w-full max-w-[600px] rounded-[var(--radius-lg)] border border-[var(--border-strong)] bg-[var(--glass-bg)] backdrop-blur-md shadow-[var(--shadow-elev)] overflow-hidden"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
        role="combobox"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-activedescendant={activeItem ? `palette-opt-${activeItem.id}` : undefined}
        aria-label="Command palette"
      >
        <div className="flex items-center gap-3 px-4 py-3 border-b border-border">
          <Search size={16} className="text-text-dim shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Type instance name, command, or snippet…"
            className="flex-1 bg-transparent text-[13px] text-text-pri placeholder:text-text-dim outline-none"
            aria-label="Search commands and instances"
          />
          {query && (
            <button
              type="button"
              className="text-[10px] text-text-dim hover:text-text-pri px-1.5 py-0.5 rounded border border-border"
              onClick={() => setQuery('')}
            >
              clear
            </button>
          )}
          <kbd className="text-[10px] text-text-dim px-1.5 py-0.5 rounded border border-border font-mono">esc</kbd>
        </div>

        <div ref={listRef} role="listbox" className="max-h-[400px] overflow-y-auto py-1" aria-label="Results">
          {groups.length === 0 && (
            <div className="px-4 py-8 text-center text-[13px] text-text-dim">
              No results for &ldquo;{query}&rdquo;
            </div>
          )}
          {groups.map((group) => {
            const groupStart = runningIdx;
            runningIdx += group.items.length;
            return (
              <div key={group.label}>
                <div className="px-4 py-1.5 text-[10px] font-semibold uppercase tracking-widest text-text-dim">
                  {group.label}
                </div>
                {group.items.map((item, localIdx) => {
                  const globalIdx = groupStart + localIdx;
                  return (
                    <PaletteRow
                      key={item.id}
                      id={`palette-opt-${item.id}`}
                      item={item}
                      active={globalIdx === clampedIdx}
                      onActivate={() => {
                        item.action();
                        setOpen(false);
                      }}
                      onMouseEnter={() => setActiveIdx(globalIdx)}
                    />
                  );
                })}
              </div>
            );
          })}
        </div>

        <div className="flex items-center gap-4 px-4 py-2 border-t border-border bg-bg/80 text-[12px] text-text-dim whitespace-nowrap overflow-hidden">
          <span>↑↓ navigate</span>
          <span>Home/End jump</span>
          <span>↵ connect</span>
          <span>⌘↵ details</span>
          <span>esc close</span>
          <span className="ml-auto hidden sm:inline">space-separated tokens AND-match</span>
        </div>
      </div>
    </div>
  );
}
