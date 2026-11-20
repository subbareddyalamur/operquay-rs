import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { LayoutGrid } from 'lucide-react';
import { createTypeahead, isTypeaheadKey, labelOf } from '@ui-sdk/core';
import { useSessionsStore, type Session } from '@/stores/sessions';
import { useInstancesStore } from '@/stores/instances';
import { useLayoutStore } from '@/stores/layout';
import { useSettingsStore } from '@/stores/settings';
import { isProdEnv } from '@/components/terminal/SessionStrip';
import { WorkspaceTab, WorkspaceTabBar } from '@/components/primitives/WorkspaceTabs';
import { matchEnvRule, middleTruncate } from '@/lib/env';

const KIND: Record<Session['type'], { label: string; tone: string }> = {
  ssh: { label: 'SSH', tone: 'text-success bg-success/10 border-success/25' },
  rdp: { label: 'RDP', tone: 'text-info bg-info/10 border-info/25' },
  topology: { label: 'NET', tone: 'text-text-mut bg-elev border-border' },
};

function useEnvFor(instanceId: string): string {
  return useInstancesStore((s) => {
    if (!instanceId) return '';
    for (const a of s.accounts) for (const r of a.regions) for (const g of r.groups) {
      const hit = g.instances.find((i) => i.instance_id === instanceId);
      if (hit) return hit.tags?.['Environment'] ?? hit.tags?.['environment'] ?? hit.tag2_value ?? '';
    }
    return '';
  });
}

function SessionTab({ session, active }: { session: Session; active: boolean }) {
  const closeSession = useSessionsStore((s) => s.closeSession);
  const closeOthers = useSessionsStore((s) => s.closeOthers);
  const setActive = useSessionsStore((s) => s.setActive);
  const envColors = useSettingsStore((s) => s?.envColors);
  const enableEnvBorders = useSettingsStore((s) => s?.enableEnvBorders ?? true);
  const inventoryEnv = useEnvFor(session.instanceId);
  const env = session.userRDP || session.userSSH || session.userTopology ? session.env ?? '' : inventoryEnv;
  const prod = isProdEnv(env);
  const customRule = enableEnvBorders ? matchEnvRule(env, envColors) : undefined;
  const kind = KIND[session.type];
  const [menu, setMenu] = useState<{ x: number; y: number } | null>(null);
  const [confirmClose, setConfirmClose] = useState(false);

  useEffect(() => {
    if (!confirmClose) return;
    const t = window.setTimeout(() => setConfirmClose(false), 2500);
    return () => window.clearTimeout(t);
  }, [confirmClose]);

  const accentColor = prod ? 'var(--warn)' : customRule?.color;
  const needsConfirm = prod && session.status === 'connected';

  const requestClose = () => {
    if (needsConfirm && !confirmClose) {
      setConfirmClose(true);
      return;
    }
    setConfirmClose(false);
    closeSession(session.id);
  };

  return (
    <WorkspaceTab
      mode="container-tab"
      active={active}
      icon={<span className={`font-mono text-[10px] font-semibold px-1.5 py-[1px] rounded border ${kind.tone}`}>{kind.label}</span>}
      label={middleTruncate(session.instanceName, 26)}
      title={`${session.instanceName}${env ? ` · ${env}` : ''}`}
      accentColor={accentColor}
      statusIndicator={
        session.status === 'error' ? (
          <span className="w-1.5 h-1.5 rounded-full bg-danger shrink-0" aria-label="Connection failed" />
        ) : session.status === 'connecting' ? (
          <span className="w-1.5 h-1.5 rounded-full bg-warn motion-safe:animate-pulse shrink-0" aria-label="Connecting" />
        ) : session.status === 'connected' ? (
          <span className="w-1.5 h-1.5 rounded-full bg-success shrink-0" aria-label="Connected" />
        ) : undefined
      }
      onSelect={() => setActive(session.id)}
      onClose={requestClose}
      closeLabel={`Close ${session.instanceName}`}
      confirmClose={confirmClose}
      confirmLabel="End?"
      confirmAriaLabel={`Confirm close ${session.instanceName}`}
      onConfirmClose={() => {
        setConfirmClose(false);
        closeSession(session.id);
      }}
      onContextMenu={(e) => {
        e.preventDefault();
        setMenu({ x: e.clientX, y: e.clientY });
      }}
    >
      {menu && (
        <TabContextMenu
          x={menu.x}
          y={menu.y}
          onClose={() => setMenu(null)}
          items={[
            { label: 'Close', run: () => closeSession(session.id) },
            { label: 'Close others', run: () => closeOthers(session.id) },
            ...(session.instanceId ? [{ label: 'Details', run: () => useLayoutStore.getState().showDetails(session.instanceId) }] : []),
          ]}
        />
      )}
    </WorkspaceTab>
  );
}

function TabContextMenu({
  x,
  y,
  items,
  onClose,
}: {
  x: number;
  y: number;
  items: Array<{ label: string; run: () => void }>;
  onClose: () => void;
}) {
  const menuRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const typeahead = useMemo(() => createTypeahead(500), []);

  const dismiss = useCallback((restoreFocus = false) => {
    typeahead.reset();
    onClose();
    if (restoreFocus) {
      queueMicrotask(() => previousFocusRef.current?.focus());
    }
  }, [onClose, typeahead]);

  useEffect(() => {
    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const raf = requestAnimationFrame(() => {
      menuRef.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus();
    });
    const onEscape = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        dismiss(true);
      }
    };
    document.addEventListener('keydown', onEscape);
    return () => {
      cancelAnimationFrame(raf);
      document.removeEventListener('keydown', onEscape);
    };
  }, [dismiss]);

  return (
    <>
      <div
        className="fixed inset-0 z-[299]"
        onClick={(e) => { e.stopPropagation(); dismiss(false); }}
        onContextMenu={(e) => { e.preventDefault(); dismiss(false); }}
      />
      <div
        ref={menuRef}
        role="menu"
        aria-label="Session tab actions"
        className="fixed z-[300] rounded-[var(--radius-lg)] shadow-[var(--shadow-elev)] bg-[var(--glass-bg)] backdrop-blur-md border border-[var(--border-strong)] p-1 min-w-[180px]"
        style={{ left: x, top: y }}
        onKeyDown={(e) => {
          const buttons = Array.from(menuRef.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? []);
          if (!buttons.length) return;
          const idx = buttons.indexOf(document.activeElement as HTMLElement);
          if (e.key === 'ArrowDown') {
            e.preventDefault();
            buttons[(idx + 1) % buttons.length]?.focus();
          } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            buttons[(idx - 1 + buttons.length) % buttons.length]?.focus();
          } else if (e.key === 'Home') {
            e.preventDefault();
            buttons[0]?.focus();
          } else if (e.key === 'End') {
            e.preventDefault();
            buttons[buttons.length - 1]?.focus();
          } else if (e.key === 'Tab') {
            dismiss(false);
          } else if (isTypeaheadKey(e.nativeEvent)) {
            const next = typeahead(e.key, buttons.map(labelOf), idx);
            if (next >= 0) {
              e.preventDefault();
              buttons[next]?.focus();
            }
          }
        }}
      >
        {items.map((item) => (
          <button
            key={item.label}
            type="button"
            role="menuitem"
            className="w-full text-left px-2.5 h-8 rounded-[var(--radius)] text-[13px] text-text-pri hover:bg-[var(--surface-hover)] focus:bg-[var(--surface-hover)] focus:outline-none"
            onClick={(e) => { e.stopPropagation(); dismiss(false); item.run(); }}
          >
            {item.label}
          </button>
        ))}
      </div>
    </>
  );
}

export function TabBar() {
  const sessions = useSessionsStore((s) => s.sessions);
  const activeId = useSessionsStore((s) => s.activeId);
  const view = useLayoutStore((s) => s.view);
  const setSlot = useLayoutStore((s) => s.setSessionActionsEl);
  const overviewActive = view === 'session' && activeId === null;

  return (
    <WorkspaceTabBar
      ariaLabel="Open sessions"
      emptyText={sessions.length === 0 ? 'Open an instance to start a connection.' : undefined}
      actionsRef={setSlot}
    >
      <button
        type="button"
        onClick={() => {
          useSessionsStore.getState().setActive(null);
          useLayoutStore.getState().setView('session');
        }}
        aria-label="Fleet overview"
        title="Fleet overview"
        className={`oq-tab pr-2.5 ${overviewActive ? 'active' : ''}`}
      >
        <LayoutGrid size={13} className="oq-tab-icon" aria-hidden="true" />
        <span className="oq-tab-title">Overview</span>
      </button>
      {sessions.map((s) => (
        <SessionTab key={s.id} session={s} active={view === 'session' && s.id === activeId} />
      ))}
    </WorkspaceTabBar>
  );
}
