import { useEffect, useId, useState, type FormEvent } from 'react';
import { Lock, Server, X } from 'lucide-react';
import { Badge, Button, Card, SegmentedControl } from '@/design-system/primitives';
import { issueSessionTicket, type LaunchMode, type LaunchSessionResponse } from './launchApi';

export interface ActiveLaunchedSession {
  protocol: 'rdp' | 'vnc';
  targetHost: string;
  launchMode: LaunchMode;
  wsUrl?: string;
}

export function SessionLauncherDialog({
  open,
  defaultLayout,
  onClose,
  onLaunched,
}: {
  open: boolean;
  defaultLayout: string;
  onClose: () => void;
  onLaunched: (session: ActiveLaunchedSession) => void;
}) {
  const titleId = useId();
  const hostId = useId();
  const portId = useId();
  const userId = useId();
  const passId = useId();
  const pinId = useId();

  const [protocol, setProtocol] = useState<'rdp' | 'vnc'>('vnc');
  const [launchMode, setLaunchMode] = useState<LaunchMode>('ssm_tunnel');
  const [targetHost, setTargetHost] = useState('ssm-loopback');
  const [targetPort, setTargetPort] = useState('0');
  const [username, setUsername] = useState('CORP\\admin');
  const [password, setPassword] = useState('');
  const [certPin, setCertPin] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  const handleModeChange = (next: LaunchMode) => {
    setLaunchMode(next);
    if (next === 'ssm_tunnel') {
      setProtocol('vnc');
      setTargetHost('ssm-loopback');
      setTargetPort('0');
    } else if (next === 'direct_tcp') {
      setTargetHost('10.20.4.15');
      setTargetPort(protocol === 'vnc' ? '5900' : '3389');
    } else {
      setTargetHost('win2025-demo.internal');
      setTargetPort('3389');
    }
  };

  const handleProtocolChange = (next: 'rdp' | 'vnc') => {
    setProtocol(next);
    if (launchMode === 'direct_tcp') {
      setTargetPort(next === 'vnc' ? '5900' : '3389');
    }
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);
    setSubmitting(true);
    const ephemeralPassword = password;
    // Clear raw secret immediately out of React input state before async network completion
    setPassword('');
    try {
      const parsedPort = Number.parseInt(targetPort, 10);
      const res: LaunchSessionResponse = await issueSessionTicket({
        protocol,
        launch_mode: launchMode,
        target_host: targetHost.trim() || undefined,
        target_port: Number.isFinite(parsedPort) ? parsedPort : undefined,
        username: username.trim() || undefined,
        password: ephemeralPassword,
        width: 1280,
        height: 720,
        keyboard_layout: defaultLayout,
        expected_cert_sha256_hex: certPin.trim() || undefined,
      });
      onLaunched({
        protocol: res.protocol,
        targetHost: targetHost.trim() || 'win2025-demo.internal',
        launchMode: res.launch_mode,
        wsUrl: res.ws_url,
      });
      onClose();
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : 'Unable to issue ephemeral ticket');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-[var(--overlay)] backdrop-blur-sm flex items-center justify-center p-4"
      role="presentation"
    >
      <Card
        elevated
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="w-full max-w-lg p-5 space-y-4 border-border-strong"
      >
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Server size={16} className="text-accent" aria-hidden="true" />
              <h2 id={titleId} className="text-[16px] font-semibold text-text-pri">
                Connect Ephemeral Desktop Target
              </h2>
            </div>
            <p className="mt-1 text-xs text-text-mut">
              Credentials are exchanged for a 60s single-use WebSocket ticket and wiped from browser state.
            </p>
          </div>
          <Button
            variant="ghost"
            size="xs"
            onClick={onClose}
            aria-label="Close target connection dialog"
            icon={<X size={14} aria-hidden="true" />}
          >
            Close
          </Button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <SegmentedControl
              label="Protocol"
              value={protocol}
              onChange={handleProtocolChange}
              options={[
                { value: 'rdp', label: 'RDP (3389)' },
                { value: 'vnc', label: 'VNC (5900)' },
              ]}
            />
            <SegmentedControl
              label="Transport Path"
              value={launchMode}
              onChange={handleModeChange}
              options={[
                { value: 'ssm_tunnel', label: 'SSM Tunnel' },
                { value: 'direct_tcp', label: 'Direct TCP' },
                { value: 'demo', label: 'Sandbox' },
              ]}
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="sm:col-span-2 space-y-1">
              <label htmlFor={hostId} className="block text-xs font-medium text-text-pri">
                Target Hostname / Instance
              </label>
              <input
                id={hostId}
                type="text"
                value={targetHost}
                onChange={(e) => setTargetHost(e.target.value)}
                required={launchMode === 'direct_tcp'}
                placeholder="10.0.12.34 or ssm-loopback"
                className="w-full h-9 px-3 rounded-[var(--radius-sm)] border border-border bg-bg text-sm text-text-pri"
              />
            </div>
            <div className="space-y-1">
              <label htmlFor={portId} className="block text-xs font-medium text-text-pri">
                Port
              </label>
              <input
                id={portId}
                type="number"
                min={0}
                max={65535}
                value={targetPort}
                onChange={(e) => setTargetPort(e.target.value)}
                className="w-full h-9 px-3 rounded-[var(--radius-sm)] border border-border bg-bg text-sm text-text-pri tabular-mono"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-1">
              <label htmlFor={userId} className="block text-xs font-medium text-text-pri">
                Username (Domain\User)
              </label>
              <input
                id={userId}
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full h-9 px-3 rounded-[var(--radius-sm)] border border-border bg-bg text-sm text-text-pri"
              />
            </div>
            <div className="space-y-1">
              <label htmlFor={passId} className="block text-xs font-medium text-text-pri">
                Password (Ephemeral Zeroize)
              </label>
              <input
                id={passId}
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Optional for SSM/Sandbox"
                autoComplete="off"
                className="w-full h-9 px-3 rounded-[var(--radius-sm)] border border-border bg-bg text-sm text-text-pri"
              />
            </div>
          </div>

          <div className="space-y-1">
            <label htmlFor={pinId} className="block text-xs font-medium text-text-pri">
              Optional TLS Cert SHA-256 Pin (TOFU Override)
            </label>
            <input
              id={pinId}
              type="text"
              value={certPin}
              onChange={(e) => setCertPin(e.target.value)}
              placeholder="64 hex chars (optional — auto-pinned on first TOFU connect)"
              className="w-full h-9 px-3 rounded-[var(--radius-sm)] border border-border bg-bg text-xs text-text-pri tabular-mono"
            />
          </div>

          {errorMsg && (
            <div
              role="alert"
              className="px-3 py-2 rounded-[var(--radius-sm)] border border-border bg-[var(--danger-dim)] text-xs text-danger"
            >
              {errorMsg}
            </div>
          )}

          <div className="flex items-center justify-between gap-3 pt-2 border-t border-border">
            <Badge tone="accent">
              <Lock size={11} aria-hidden="true" />
              Single-Use Ticket · 60s TTL
            </Badge>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={onClose}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" size="sm" loading={submitting}>
                Mint Ticket &amp; Connect
              </Button>
            </div>
          </div>
        </form>
      </Card>
    </div>
  );
}
