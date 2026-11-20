import { useEffect, useRef, useState, type FormEvent } from 'react';
import { api } from '@/lib/api';

type Forward = { id: string; port: number; code: string };

export function UserAWSForward({ roleID, instanceID, instanceName, region, open }: { roleID: string; instanceID: string; instanceName: string; region: string; open?: boolean }) {
  const [port, setPort] = useState('');
  const [forwards, setForwards] = useState<Forward[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const timers = useRef<number[]>([]);
  useEffect(() => () => { timers.current.forEach(window.clearTimeout); }, []);

  async function start(event: FormEvent) {
    event.preventDefault();
    const number = Number(port);
    if (!Number.isInteger(number) || number < 1 || number > 65535) { setMessage('Enter a valid TCP port.'); return; }
    setBusy(true); setMessage('');
    const result = await api.post<{ forward_id: string; pairing_code: string }>('/api/aws/forward/start', { binding_id: roleID, instance_id: instanceID, instance_name: instanceName, region, port: number });
    setBusy(false);
    if (!result.ok) { setMessage('Could not start forwarding. Check the role and try again.'); return; }
    const { forward_id: id, pairing_code: code } = result.data;
    setForwards(previous => [...previous, { id, port: number, code }]);
    timers.current.push(window.setTimeout(() => setForwards(previous => previous.map(forward => forward.id === id ? { ...forward, code: '' } : forward)), 60000));
  }

  async function stop(id: string) {
    setBusy(true); setMessage('');
    const result = await api.post('/api/aws/forward/stop', { forward_id: id });
    setBusy(false);
    if (!result.ok) { setMessage('Could not stop forwarding; the helper may already have disconnected.'); return; }
    setForwards(previous => previous.filter(forward => forward.id !== id));
    setMessage('Stop requested; the helper will disconnect. Server cleanup can take up to 90 seconds.');
  }

  return <details open={open} className="mt-2 border border-border rounded p-2">
    <summary className="cursor-pointer">Port forwarding</summary>
    <p className="mt-2 text-xs text-text-mut">TCP only. Build the local helper before starting: <code>go build -o operquay-forward ./cmd/operquay-forward</code>. For a private Operquay certificate authority, pass its PEM file with <code>-ca</code>.</p>
    <form className="flex flex-wrap items-end gap-2 mt-2" onSubmit={event => void start(event)}>
      <label className="text-xs">Remote TCP port<input aria-label={`Remote TCP port for ${instanceID}`} type="number" min="1" max="65535" required value={port} onChange={event => setPort(event.target.value)} className="ml-2 w-24 rounded border border-border bg-elev p-1" /></label>
      <button type="submit" disabled={busy} aria-label={`Start forward for ${instanceID}`} className="px-3 py-1 border border-border rounded disabled:opacity-50">Start forward</button>
    </form>
    {message && <p role="status" className="text-xs mt-2">{message}</p>}
    {forwards.map(forward => <div key={forward.id} className="mt-2 border-t border-border pt-2 text-xs">
      <p>Remote port {forward.port}. The local helper binds only to 127.0.0.1.</p>
      {forward.code && <><p className="mt-1">Within 60 seconds, run <code>./operquay-forward -url {window.location.origin} -local-port &lt;local-port&gt;</code> on your computer and enter this one-time code:</p><code className="block break-all mt-1">{forward.code}</code><p>Do not share this code.</p></>}
      <p className="mt-1 text-text-mut">Stop with Ctrl+C in the helper or use the button below. Other local users may connect to your loopback port.</p>
      <button type="button" disabled={busy} aria-label={`Stop forward to port ${forward.port}`} className="mt-1 px-3 py-1 border border-border rounded" onClick={() => void stop(forward.id)}>Stop forwarding</button>
    </div>)}
  </details>;
}
