import { useEffect, useRef, useState } from 'react';
import { api } from '@/lib/api';
import { canSendCredentials } from '@/lib/credentialTransport';
import { RdpDesktopClient } from '@/components/rdp/RdpDesktopClient';
import { RDPCredentialsModal, type RDPCredentials } from '@/components/rdp/RDPCredentialsModal';
import { SessionStrip, isProdEnv } from '@/components/terminal/SessionStrip';
import { useSessionsStore } from '@/stores/sessions';
import { useLayoutStore } from '@/stores/layout';

type Props = { id: string; roleID: string; instanceID: string; instanceName: string; region: string; env?: string; active?: boolean; onClose: () => void };

export function UserAWSRDP({ id, roleID, instanceID, instanceName, region, env = '', active: isVisible = true, onClose }: Props) {
  const [dialogOpen, setDialogOpen] = useState(true);
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [recordingName, setRecordingName] = useState('');
  const [recording, setRecording] = useState(false);
  const status = useSessionsStore(s => s.sessions.find(session => session.id === id)?.status);
  const detailsOpen = useLayoutStore(s => s.detailsInstanceId === instanceID);
  const container = useRef<HTMLElement>(null);
  const active = useRef(true);
  const forward = useRef('');
  useEffect(() => {
    active.current = true;
    return () => { active.current = false; if (forward.current) void api.post('/api/aws/rdp/stop', { forward_id: forward.current }); };
  }, []);
  useEffect(() => {
    if (!recordingName || status !== 'connected') { setRecording(false); return; }
    let live = true;
    let timer: ReturnType<typeof setTimeout>;
    const check = async () => {
      const result = await api.get<Array<{ name: string; size: number }>>('/recordings');
      if (!live) return;
      setRecording(result.ok && Array.isArray(result.data) && result.data.some(file => file.name === recordingName && file.size > 0));
      timer = setTimeout(() => void check(), 3000);
    };
    void check();
    return () => { live = false; clearTimeout(timer); };
  }, [recordingName, status]);

  const connect = async (credentials: RDPCredentials) => {
    setError('');
    if (!canSendCredentials('/api/aws/rdp/start')) { setError('HTTPS is required for RDP credentials.'); return; }
    setDialogOpen(false);
    setBusy(true);
    useSessionsStore.getState().updateStatus(id, 'connecting');
    const rawW = container.current?.clientWidth && container.current.clientWidth >= 320
      ? container.current.clientWidth
      : ((typeof window !== 'undefined' ? window.innerWidth : 1280) - 240);
    const rawH = container.current?.clientHeight && container.current.clientHeight >= 240
      ? container.current.clientHeight - 36
      : ((typeof window !== 'undefined' ? window.innerHeight : 720) - 88);
    const width = Math.max(320, Math.min(4096, Math.floor(rawW))) & ~1;
    const height = Math.max(240, Math.min(4096, Math.floor(rawH)));
    const pending = api.post<{ token: string; forward_id: string; recording_name?: string }>('/api/aws/rdp/start', { instance_id: instanceID, instance_name: instanceName, aws_profile: `user:${roleID}`, aws_region: region, width, height, ...credentials });
    const result = await pending;
    if (!active.current) { if (result.ok) void api.post('/api/aws/rdp/stop', { forward_id: result.data.forward_id }); return; }
    setBusy(false);
    if (!result.ok) { setError(rdpStartError(result.error?.message ?? '')); useSessionsStore.getState().updateStatus(id, 'error'); return; }
    forward.current = result.data.forward_id; setRecordingName(result.data.recording_name ?? ''); setToken(result.data.token);
  };
  return <section ref={container} className={`flex flex-col h-full bg-bg border-2 ${isProdEnv(env) ? 'border-warn' : 'border-transparent'}`} aria-label={`RDP for ${instanceID}`}>
    <SessionStrip kind="rdp" name={instanceName || instanceID} instanceId={instanceID} env={env} status={status} recording={recording} detailsOpen={detailsOpen} onDetails={() => useLayoutStore.getState().toggleDetails(instanceID)} sessionId={id} more={[
      { label: 'Send Ctrl+Alt+Del', onSelect: () => window.dispatchEvent(new CustomEvent('ct:rdp-ctrl-alt-del', { detail: { sessionId: id } })) },
      { label: 'Full screen', onSelect: () => { if (document.fullscreenElement) void document.exitFullscreen(); else void container.current?.requestFullscreen(); } },
    ]} onEnd={onClose} />
    {token ? <div className="flex-1 min-h-0 bg-black"><RdpDesktopClient sessionId={id} token={token} userScoped onSessionEnded={onClose} /></div> : busy ? <p role="status">Connecting to RDP…</p> : null}
    <RDPCredentialsModal open={dialogOpen && isVisible} reconnect={status === 'disconnected'} instance={{ name: instanceName || instanceID }} onSubmit={credentials => void connect(credentials)} onCancel={onClose} />
    {error && <><p role="alert" className="text-sm text-danger">{error}</p><button type="button" onClick={() => setDialogOpen(true)}>Retry RDP</button></>}
  </section>;
}

// The server returns {"error": "..."} with an actionable reason when AWS refuses the tunnel.
function rdpStartError(body: string): string {
  try {
    const message = (JSON.parse(body) as { error?: unknown }).error;
    if (typeof message === 'string' && message && message !== 'RDP forward unavailable') return message;
  } catch { /* fall through */ }
  return 'RDP could not start. Check your AWS role and forwarder connection.';
}
