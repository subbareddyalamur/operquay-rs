import { useRef, useState, useCallback, useEffect } from 'react';
import { X } from 'lucide-react';
import { Xterm, type XtermRef } from './Xterm';
import { SessionStrip, isProdEnv } from './SessionStrip';
import { EnvBorder } from './EnvBorder';
import { getTerminalWS } from '@/lib/ws';
import type { Instance } from '@/stores/instances';
import { RdpDesktopClient } from '@/components/rdp/RdpDesktopClient';
import { useSessionsStore } from '@/stores/sessions';
import { useToastStore } from '@/stores/toast';
import { api } from '@/lib/api';
import { nanoid } from 'nanoid';
import { TopologyRoute } from '@/components/topology/TopologyRoute';
import { useInstancesStore } from '@/stores/instances';
import { useLayoutStore } from '@/stores/layout';
import { TerminalSearch } from './TerminalSearch';

export interface TerminalSessionProps {
  instance: Pick<Instance, 'instance_id' | 'name' | 'aws_profile' | 'aws_region'> & Partial<Instance>;
  sessionId: string;
  sessionType?: 'ssh' | 'rdp' | 'topology';
  rdpToken?: string;
  rdpConnectStatus?: 'connecting' | 'error';
  rdpRecordingName?: string;
  userScoped?: boolean;
}

interface SplitTarget {
  sessionId: string;
  instanceId: string;
  instanceName: string;
  awsProfile: string;
  awsRegion: string;
  userScoped: boolean;
}

export function TerminalSession({ instance, sessionId, sessionType = 'ssh', rdpToken, rdpConnectStatus, rdpRecordingName, userScoped = false }: TerminalSessionProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<XtermRef>(null);
  const focusedPane = useRef<'main' | 'split'>('main');
  const exportAbort = useRef<AbortController | null>(null);
  const [recording, setRecording] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchResults, setSearchResults] = useState<{ index: number; count: number } | null>(null);
  const [splitTarget, setSplitTarget] = useState<SplitTarget | null>(null);
  const [showSplitPicker, setShowSplitPicker] = useState(false);
  const detailsOpen = useLayoutStore((s) => s.detailsInstanceId === instance.instance_id);
  const toggleDetails = useLayoutStore((s) => s.toggleDetails);
  const status = useSessionsStore((s) => s.sessions.find((x) => x.id === sessionId)?.status);
  const splitXtermRef = useRef<XtermRef>(null);
  const closeSession = useSessionsStore((s) => s.closeSession);
  const sessions = useSessionsStore((s) => s.sessions);
  const accounts = useInstancesStore((s) => s.accounts);
  const toast = useToastStore.getState;

  useEffect(() => () => exportAbort.current?.abort(), []);

  const allInstances = accounts.flatMap((a) => a.regions).flatMap((r) => r.groups).flatMap((g) => g.instances);
  const sshSessions = sessions.filter((s) => s.type === 'ssh' && s.id !== sessionId && Boolean(s.userSSH) === userScoped);

  const handleDetails = useCallback(() => {
    toggleDetails(instance.instance_id);
  }, [instance.instance_id, toggleDetails]);

  const handleExport = useCallback(async () => {
    const id = toast().push({ variant: 'info', title: 'Exporting session log…', duration: null });
    let controller: AbortController | undefined;
    try {
      if (userScoped) {
        exportAbort.current?.abort();
        controller = new AbortController();
        exportAbort.current = controller;
        const response = await fetch('/api/aws/session-export', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ session_id: sessionId }),
          signal: controller.signal,
        });
        if (!response.ok) {
          let errMsg = `Export failed (HTTP ${response.status})`;
          try {
            const txt = await response.text();
            if (txt) {
              try {
                const j = JSON.parse(txt) as { error?: string; message?: string };
                errMsg = j.error || j.message || txt;
              } catch {
                errMsg = txt.slice(0, 180);
              }
            }
          } catch {
            void 0;
          }
          toast().update(id, { variant: 'danger', title: 'Export failed', description: errMsg, duration: 8000 });
          return;
        }
        const blob = await response.blob();
        if (controller.signal.aborted) { toast().dismiss(id); return; }
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = `${instance.instance_id}-session.log`;
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 5000);
        toast().update(id, { variant: 'success', title: 'Export complete', duration: 4000 });
        return;
      }
      const result = await api.post<{ filename: string; url: string; download_url?: string; error?: string }>('/export-session', { session_id: sessionId });
      const dlUrl = result.ok ? (result.data?.url || result.data?.download_url) : '';
      if (result.ok && dlUrl) {
        const a = document.createElement('a');
        a.href = dlUrl;
        a.download = result.data.filename || 'session-export.txt';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        toast().update(id, { variant: 'success', title: 'Export complete', description: result.data.filename, duration: 4000 });
      } else {
        const desc = result.ok ? 'No download URL returned' : (result.error.message || `Server error (HTTP ${result.error.status})`);
        toast().update(id, { variant: 'danger', title: 'Export failed', description: desc, duration: 8000 });
      }
    } catch (err) {
      const msg = err instanceof Error && err.message ? err.message : 'Unable to reach export endpoint';
      if (!controller?.signal.aborted) toast().update(id, { variant: 'danger', title: 'Export failed', description: msg, duration: 8000 });
      else toast().dismiss(id);
    } finally {
      if (controller && exportAbort.current === controller) exportAbort.current = null;
    }
  }, [sessionId, toast, userScoped, instance.instance_id]);

  useEffect(() => {
    if (sessionType !== 'rdp') return;
    if (!rdpRecordingName || status !== 'connected') { setRecording(false); return; }
    let live = true;
    let timer: ReturnType<typeof setTimeout>;
    const check = async () => {
      const result = await api.get<Array<{ name: string; size: number }>>('/recordings');
      if (!live) return;
      setRecording(result.ok && Array.isArray(result.data) && result.data.some(file => file.name === rdpRecordingName && file.size > 0));
      timer = setTimeout(() => void check(), 3000);
    };
    void check();
    return () => { live = false; clearTimeout(timer); };
  }, [sessionType, rdpRecordingName, status]);

  const handleSplit = useCallback(() => {
    if (splitTarget) {
      getTerminalWS(splitTarget.userScoped).send({ type: 'close_session', payload: { session_id: splitTarget.sessionId } });
      splitXtermRef.current?.dispose();
      setSplitTarget(null);
      focusedPane.current = 'main';
      return;
    }
    setShowSplitPicker(true);
  }, [splitTarget]);

  const handlePickSplit = useCallback((picked: typeof sshSessions[0]) => {
    setShowSplitPicker(false);
    const inst = allInstances.find((i) => i.instance_id === picked.instanceId);
    setSplitTarget({
      sessionId: `${picked.instanceId}-split-${nanoid(6)}`,
      instanceId: picked.instanceId,
      instanceName: picked.instanceName,
      awsProfile: picked.userSSH ? `user:${picked.userSSH.roleID}` : inst?.aws_profile ?? '',
      awsRegion: picked.userSSH?.region ?? inst?.aws_region ?? '',
      userScoped: Boolean(picked.userSSH),
    });
  }, [allInstances]);

  const handleFullscreen = useCallback(() => {
    const el = containerRef.current;
    if (!el) return;
    if (!document.fullscreenElement) {
      void el.requestFullscreen();
    } else {
      void document.exitFullscreen();
    }
  }, []);

  const handleEnd = useCallback(() => {
    closeSession(sessionId);
    getTerminalWS(userScoped).send({ type: 'close_session', payload: { session_id: sessionId } });
    xtermRef.current?.dispose();
  }, [sessionId, closeSession, userScoped]);

  const handleSearchOpen = useCallback(() => setSearchOpen((v) => !v), []);

  const handleSearchClose = useCallback(() => {
    setSearchOpen(false);
    setSearchResults(null);
    xtermRef.current?.clearSearch();
    xtermRef.current?.focus();
  }, []);

  const handleSearchNext = useCallback((q: string) => {
    xtermRef.current?.search(q);
  }, []);

  const handleSearchPrev = useCallback((q: string) => {
    xtermRef.current?.search(q);
    xtermRef.current?.searchPrevious();
  }, []);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'f') {
        e.preventDefault();
        setSearchOpen((v) => !v);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const tags = instance.tags;
  const envLabel = tags?.['Environment'] ?? tags?.['environment'] ?? instance.tag2_value ?? '';
  const envName = envLabel.toLowerCase();
  const prod = isProdEnv(envName);
  const frame = prod ? 'border-2 border-warn' : 'border-2 border-transparent';
  const envBorderTags = prod ? {} : (tags ?? {});

  if (sessionType === 'topology') {
    return (
      <div ref={containerRef} className="flex flex-col h-full bg-bg">
        <TopologyRoute instanceId={instance.instance_id} />
      </div>
    );
  }

  if (sessionType === 'rdp') {
    return (
      <div ref={containerRef} className={`flex flex-col h-full ${frame}`} aria-label={prod ? 'Production session' : undefined}>
        <SessionStrip
          kind="rdp"
          name={instance.name}
          instanceId={instance.instance_id}
          env={envLabel}
          status={rdpConnectStatus ?? status}
          recording={recording}
          detailsOpen={detailsOpen}
          onDetails={handleDetails}
          sessionId={sessionId}
          more={[
            { label: 'Send Ctrl+Alt+Del', onSelect: () => window.dispatchEvent(new CustomEvent('ct:rdp-ctrl-alt-del', { detail: { sessionId } })) },
            { label: 'Full screen', onSelect: handleFullscreen },
          ]}
          onEnd={() => { closeSession(sessionId); }}
        />
        <div className="flex-1 min-h-0">
          {rdpToken ? (
            <RdpDesktopClient
              sessionId={sessionId}
              token={rdpToken}
              onSessionEnded={() => {
                closeSession(sessionId);
              }}
            />
          ) : (
            <div className="flex items-center justify-center h-full text-text-dim text-[13px]">
              {rdpConnectStatus === 'error' ? 'Connection failed' : 'Connecting to RDP…'}
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div ref={containerRef} className={`flex flex-col h-full ${frame}`} aria-label={prod ? 'Production session' : undefined}>
      <SessionStrip
        kind="ssh"
        name={instance.name}
        instanceId={instance.instance_id}
        env={envLabel}
        status={status}
        recording={recording}
        onFind={handleSearchOpen}
        findOpen={searchOpen}
        detailsOpen={detailsOpen}
        onDetails={handleDetails}
        sessionId={sessionId}
        more={[
          { label: splitTarget ? 'Close split' : 'Split with another session', onSelect: handleSplit },
          { label: 'Export session log', onSelect: () => void handleExport() },
          { label: 'Full screen', onSelect: handleFullscreen },
        ]}
        onEnd={handleEnd}
      />
      <div className={`flex-1 relative min-h-0 ${splitTarget ? 'flex' : ''}`}>
        {/* Split session picker overlay */}
        {showSplitPicker && (
          <div
            role="dialog"
            aria-modal="true"
            aria-label="Select session to split with"
            className="absolute inset-0 z-20 flex items-center justify-center bg-[var(--overlay)]"
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                e.stopPropagation();
                setShowSplitPicker(false);
                return;
              }
              if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                const items = Array.from(
                  e.currentTarget.querySelectorAll<HTMLButtonElement>('ul button'),
                );
                if (items.length === 0) return;
                e.preventDefault();
                const cur = items.indexOf(document.activeElement as HTMLButtonElement);
                const next = e.key === 'ArrowDown'
                  ? (cur < 0 ? 0 : (cur + 1) % items.length)
                  : (cur <= 0 ? items.length - 1 : cur - 1);
                items[next]?.focus();
              }
            }}
          >
            <div className="bg-surface border border-border rounded-[var(--radius-lg)] shadow-[var(--shadow)] w-80 overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-border">
                <span className="text-[13px] font-semibold text-text-pri">Select session to split with</span>
                <button
                  type="button"
                  aria-label="Close split picker"
                  autoFocus={sshSessions.length === 0}
                  onClick={() => setShowSplitPicker(false)}
                  className="text-text-dim hover:text-text-pri transition-colors"
                >
                  <X size={14} />
                </button>
              </div>
              {sshSessions.length === 0 ? (
                <div className="px-4 py-6 text-center text-[12px] text-text-dim">
                  No other SSH sessions open
                </div>
              ) : (
                <ul className="max-h-64 overflow-y-auto">
                  {sshSessions.map((s, idx) => (
                    <li key={s.id}>
                      <button
                        type="button"
                        autoFocus={idx === 0}
                        onClick={() => handlePickSplit(s)}
                        className="w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-surface-hover focus-visible:bg-surface-hover transition-colors focus:outline-none"
                      >
                        <span className="w-2 h-2 rounded-full bg-success shrink-0" />
                        <div className="min-w-0">
                          <div className="text-[12px] font-medium text-text-pri truncate">{s.instanceName}</div>
                          <div className="text-[11px] text-text-dim font-mono truncate">{s.instanceId}</div>
                        </div>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        )}

        <div className={`${splitTarget ? 'w-1/2 border-r border-border' : 'w-full h-full'} relative`} onFocusCapture={() => { focusedPane.current = 'main'; }} onMouseDownCapture={() => { focusedPane.current = 'main'; }}>
          {searchOpen && (
            <TerminalSearch
              onNext={handleSearchNext}
              onPrev={handleSearchPrev}
              onClose={handleSearchClose}
              resultIndex={searchResults?.index ?? -1}
              resultCount={searchResults?.count ?? 0}
            />
          )}
          <EnvBorder tags={envBorderTags}>
            <Xterm
              ref={xtermRef}
              instanceId={instance.instance_id}
              instanceName={instance.name}
              sessionId={sessionId}
              awsProfile={instance.aws_profile}
              awsRegion={instance.aws_region}
              environment={envName}
              userScoped={userScoped}
              onRecordingChange={setRecording}
              onSearchResults={(index, count) => setSearchResults({ index, count })}
            />
          </EnvBorder>
        </div>
        {splitTarget && (
          <div className="w-1/2 relative flex flex-col" onFocusCapture={() => { focusedPane.current = 'split'; }} onMouseDownCapture={() => { focusedPane.current = 'split'; }}>
            <div className="flex items-center gap-2 px-3 h-7 bg-surface border-b border-border shrink-0">
              <span className="w-1.5 h-1.5 rounded-full bg-success shrink-0" />
              <span className="text-[11px] font-medium text-text-pri truncate">{splitTarget.instanceName}</span>
              <span className="text-[10px] text-text-dim font-mono truncate flex-1">{splitTarget.instanceId}</span>
              <button
                type="button"
                onClick={() => {
                  getTerminalWS(splitTarget.userScoped).send({ type: 'close_session', payload: { session_id: splitTarget.sessionId } });
                  splitXtermRef.current?.dispose();
                  setSplitTarget(null);
                  focusedPane.current = 'main';
                }}
                className="text-text-dim hover:text-danger transition-colors shrink-0"
                aria-label="Close split pane"
              >
                <X size={12} />
              </button>
            </div>
            <div className="flex-1 min-h-0">
              <EnvBorder tags={allInstances.find((i) => i.instance_id === splitTarget.instanceId)?.tags ?? {}}>
                <Xterm
                  ref={splitXtermRef}
                  instanceId={splitTarget.instanceId}
                  instanceName={splitTarget.instanceName}
                  sessionId={splitTarget.sessionId}
                  awsProfile={splitTarget.awsProfile}
                  awsRegion={splitTarget.awsRegion}
                  userScoped={splitTarget.userScoped}
                />
              </EnvBorder>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

TerminalSession.displayName = 'TerminalSession';
