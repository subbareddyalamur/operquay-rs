import { useEffect, useState } from 'react';
import { createPortal } from 'react-dom';
import { useLayoutStore } from '@/stores/layout';
import { useSessionsStore } from '@/stores/sessions';
import { useSettingsStore } from '@/stores/settings';
import { useSettingsStore as useRdpSettingsStore } from '@/rust-engines/settings/store';
import { DEFAULT_KEYBOARD_LAYOUTS } from '@/rust-engines/settings/schema';
import { Menu, type MenuItem } from '@/components/primitives/Menu';
import { isProdName, matchEnvRule } from '@/lib/env';
import type { SessionStatus } from '@/stores/sessions';

export const isProdEnv = isProdName;

export interface SessionStripProps {
  kind: 'ssh' | 'rdp';
  name: string;
  instanceId: string;
  env: string;
  status?: SessionStatus | 'connecting' | 'error';
  recording: boolean;
  onFind?: () => void;
  findOpen?: boolean;
  detailsOpen: boolean;
  onDetails: () => void;
  more: MenuItem[];
  /** With a session ID, the strip renders in the session tab row while that session is active. */
  sessionId?: string;
  onEnd: () => void;
}

function EnvMark({ env }: { env: string }) {
  const envColors = useSettingsStore((s) => s?.envColors);
  const enableEnvBorders = useSettingsStore((s) => s?.enableEnvBorders ?? true);
  const prod = isProdEnv(env);
  const label = (env || 'no env').toUpperCase();
  const customRule = enableEnvBorders ? matchEnvRule(env, envColors) : undefined;
  const customStyle = customRule && !prod
    ? { borderColor: customRule.color, color: customRule.color, backgroundColor: `color-mix(in srgb, ${customRule.color} 12%, transparent)` }
    : undefined;
  return (
    <span
      style={customStyle}
      className={`font-mono text-[10px] tracking-[0.06em] px-1.5 py-[1px] rounded border shrink-0 ${
        prod ? 'text-warn bg-warn-ink border-warn' : 'text-text-mut border-border'
      }`}
    >
      {label}
    </span>
  );
}

const btn = 'h-6 px-2 rounded-md text-[11px] transition-colors';
const quiet = `${btn} text-text-mut hover:text-text-pri hover:bg-elev`;
const pressed = `${btn} bg-elev text-text-pri`;

/**
 * The strip above a session. It answers which machine, which environment,
 * and whether the session is recorded. The shell login name is not shown:
 * after `sudo su` the browser cannot know it.
 */
export function SessionStrip({
  kind, name, instanceId, env, status, recording,
  onFind, findOpen, detailsOpen, onDetails, more, onEnd, sessionId,
}: SessionStripProps) {
  const slot = useLayoutStore((s) => s.sessionActionsEl);
  const isActiveTab = useSessionsStore((s) => s.activeId === sessionId);
  const onSessionView = useLayoutStore((s) => s.view === 'session');
  const active = isActiveTab && onSessionView;
  const [confirmEnd, setConfirmEnd] = useState(false);
  const [copied, setCopied] = useState(false);
  const defaultKbdLayout = useRdpSettingsStore((s) => s.saved.keyboard_layout);
  const loadedLayouts = useRdpSettingsStore((s) => s.keyboardLayouts);
  const [kbdLayout, setKbdLayout] = useState(defaultKbdLayout);
  useEffect(() => {
    setKbdLayout(defaultKbdLayout);
  }, [defaultKbdLayout, sessionId]);
  const layouts = loadedLayouts.length > 0 ? loadedLayouts : DEFAULT_KEYBOARD_LAYOUTS;

  const statusText =
    status === 'connecting' ? 'Connecting…'
    : status === 'error' ? 'Connection failed'
    : status === 'disconnected' ? 'Disconnected'
    : null;

  const compact = Boolean(slot && sessionId);
  const content = (
    <>
      <EnvMark env={env} />
      <span
        className={`font-mono text-[10px] font-semibold px-1.5 py-[1px] rounded border shrink-0 ${
          kind === 'rdp'
            ? 'text-info bg-info/10 border-info/25'
            : 'text-success bg-success/10 border-success/25'
        }`}
      >
        {kind.toUpperCase()}
      </span>
      {!compact && <span className="font-semibold text-text-pri truncate min-w-0" title={name}>{name}</span>}
      <button
        type="button"
        className="font-mono text-[11px] text-text-mut hover:text-text-pri px-1.5 py-[1px] rounded bg-bg border border-border hover:border-text-dim transition-colors shrink-0"
        title="Copy instance id"
        onClick={() => {
          void navigator.clipboard?.writeText(instanceId);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1200);
        }}
      >
        {copied ? 'Copied' : instanceId}
      </button>
      {statusText && (
        <span className={`shrink-0 ${status === 'error' ? 'text-danger' : 'text-text-mut'}`}>{statusText}</span>
      )}
      {recording && <span role="img" aria-label="Recording" title="Recording" className="w-2 h-2 rounded-full bg-red-500 motion-safe:animate-pulse shrink-0" />}

      <div className="ml-auto flex items-center gap-0.5 shrink-0">
        {confirmEnd ? (
          <span className="inline-flex items-center gap-2 text-text-pri">
            End {name}?
            <button type="button" onClick={() => { setConfirmEnd(false); onEnd(); }} className="h-6 px-2 rounded-md text-[11px] border border-danger text-danger" autoFocus>
              End session
            </button>
            <button type="button" onClick={() => setConfirmEnd(false)} className="h-6 px-2 rounded-md text-[11px] border border-border text-text-pri">
              Stay
            </button>
          </span>
        ) : (
          <>
            {kind === 'rdp' && sessionId && (
              <>
                <select
                  aria-label="Remote keyboard layout"
                  value={kbdLayout}
                  onChange={(e) => {
                    const layout = e.target.value;
                    setKbdLayout(layout);
                    window.dispatchEvent(
                      new CustomEvent('ct:rdp-keyboard-layout', { detail: { sessionId, layout } }),
                    );
                  }}
                  className="h-6 max-w-[152px] px-1.5 rounded-md bg-bg border border-border text-[11px] text-text-pri outline-none focus:border-accent"
                  title="Switch Windows keyboard layout on the fly without reconnecting"
                >
                  {layouts.map((l) => (
                    <option key={l.id} value={l.id}>
                      {l.label}
                    </option>
                  ))}
                </select>
                <button
                  type="button"
                  onClick={() => window.dispatchEvent(new CustomEvent('ct:rdp-alt-tab', { detail: { sessionId } }))}
                  className={quiet}
                  title="Open Windows persistent task switcher (Ctrl+Alt+Tab)"
                >
                  Alt+Tab
                </button>
                <button
                  type="button"
                  onClick={() => window.dispatchEvent(new CustomEvent('ct:rdp-fit-window', { detail: { sessionId } }))}
                  className={quiet}
                  title="Fit remote desktop resolution to current tab"
                >
                  Fit
                </button>
                <button
                  type="button"
                  onClick={() => window.dispatchEvent(new CustomEvent('ct:rdp-ctrl-alt-del', { detail: { sessionId } }))}
                  className={quiet}
                  title="Send Ctrl+Alt+Del to remote desktop"
                >
                  Ctrl+Alt+Del
                </button>
              </>
            )}
            {onFind && (
              <button type="button" onClick={onFind} aria-pressed={findOpen} className={findOpen ? pressed : quiet} title="Find in scrollback (⌘F)">
                Find
              </button>
            )}
            <button type="button" onClick={onDetails} aria-pressed={detailsOpen} className={detailsOpen ? pressed : quiet}>
              Details
            </button>
            {more.length > 0 && (
              <Menu label="More session actions" trigger={<span>More</span>} triggerClassName={quiet} sections={[{ items: more }]} />
            )}
            <span className="w-px h-3.5 bg-border mx-1.5" aria-hidden="true" />
            <button type="button" onClick={() => setConfirmEnd(true)} className={`${btn} text-danger hover:bg-elev`}>
              End
            </button>
          </>
        )}
      </div>
    </>
  );

  if (compact) return active ? createPortal(<div className="h-full flex items-center gap-2.5 px-3 text-[12px] min-w-0">{content}</div>, slot!) : null;
  return (
    <div className="h-9 flex items-center gap-2.5 px-3 bg-surface border-b border-border shrink-0 text-[12px] min-w-0">
      {content}
    </div>
  );
}
