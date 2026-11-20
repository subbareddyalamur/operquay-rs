import { useEffect, useRef, useState, type FormEvent } from 'react';
import { apiPost } from '@/lib/api';
import type { UserTopologyScope } from '@/hooks/useTopology';

type Analysis = { reachable: boolean; hops: { index: number; detail: string }[]; explanations?: string[] };

export function UserDeepAnalysis({ instanceId, scope }: { instanceId: string; scope: UserTopologyScope }) {
  const [destination, setDestination] = useState('');
  const [port, setPort] = useState('');
  const [protocol, setProtocol] = useState('tcp');
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState<Analysis | null>(null);
  const [error, setError] = useState('');
  const request = useRef<AbortController | null>(null);
  useEffect(() => () => request.current?.abort(), []);

  async function run(event: FormEvent) {
    event.preventDefault();
    const controller = new AbortController();
    request.current = controller;
    setPending(true); setResult(null); setError('');
    const target = destination.trim();
    const response = await apiPost<Analysis>('/api/aws/topology/deep-analyze', {
      binding_id: scope.roleID, region: scope.region, sourceInstanceId: instanceId,
      ...(target.startsWith('i-') ? { destInstanceId: target } : { destIp: target }),
      protocol, port: Number(port),
    }, controller.signal);
    if (controller.signal.aborted) return;
    request.current = null;
    setPending(false);
    if (response.ok) setResult(response.value);
    else setError('Analysis failed or access expired. Temporary AWS resources may require cleanup.');
  }

  return <details className="border-b border-border bg-surface px-3 py-2 text-sm text-text-pri">
    <summary className="cursor-pointer">Deep reachability analysis</summary>
    <p className="mt-2 text-xs text-text-mut">Creates temporary AWS Network Insights resources and may incur charges. Cancellation or a cleanup failure can leave resources in AWS.</p>
    <form onSubmit={event => void run(event)} className="mt-2 flex flex-wrap items-end gap-2">
      <label className="text-xs">Destination instance or IP<input required aria-label="Destination instance or IP" value={destination} onChange={event => setDestination(event.target.value)} className="ml-2 rounded border border-border bg-elev p-1 text-text-pri" /></label>
      <label className="text-xs">Protocol<select aria-label="Protocol" value={protocol} onChange={event => setProtocol(event.target.value)} className="ml-2 rounded border border-border bg-elev p-1 text-text-pri"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
      <label className="text-xs">Destination port<input required aria-label="Destination port" type="number" min="1" max="65535" value={port} onChange={event => setPort(event.target.value)} className="ml-2 w-20 rounded border border-border bg-elev p-1 text-text-pri" /></label>
      <button type="submit" disabled={pending} className="rounded border border-border px-2 py-1 disabled:opacity-50">Run deep analysis</button>
      {pending && <button type="button" className="rounded border border-border px-2 py-1" onClick={() => { request.current?.abort(); request.current = null; setPending(false); setError('Analysis cancelled. Temporary AWS resources may require cleanup.'); }}>Cancel analysis</button>}
    </form>
    {pending && <p role="status" className="mt-2">Analyzing… this can take up to two minutes.</p>}
    {error && <p role="alert" className="mt-2 text-danger">{error}</p>}
    {result && <div className="mt-2"><p>{result.reachable ? 'AWS reports the path is reachable.' : 'AWS reports the path is not reachable.'}</p><ul>{result.hops.map(hop => <li key={hop.index}>{hop.detail}</li>)}</ul>{result.explanations?.map((explanation, index) => <p key={index}>{explanation}</p>)}</div>}
  </details>;
}
