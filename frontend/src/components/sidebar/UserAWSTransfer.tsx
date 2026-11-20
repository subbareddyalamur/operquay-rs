import { useEffect, useRef, useState } from 'react';
import { canSendCredentials } from '@/lib/credentialTransport';
import { FileBrowserModal } from '@/components/modals/FileBrowserModal';

type Props = { mode: 'upload' | 'download'; roleID: string; instanceID: string; region: string; platform: string; onClose: () => void };

export function UserAWSTransfer({ mode, roleID, instanceID, region, platform: initialPlatform, onClose }: Props) {
  const [path, setPath] = useState('');
  const [platform, setPlatform] = useState(initialPlatform === 'windows' ? 'windows' : initialPlatform === 'linux' ? 'linux' : '');
  const [file, setFile] = useState<File | null>(null);
  const [express, setExpress] = useState(false);
  const [bucket, setBucket] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [browsing, setBrowsing] = useState(false);
  const request = useRef<AbortController | null>(null);
  useEffect(() => () => request.current?.abort(), []);

  const submit = async () => {
    setError(''); setMessage('');
    const endpoint = `/api/aws/transfer/${mode}`;
    if (!canSendCredentials(endpoint)) { setError('HTTPS is required for file transfers.'); return; }
    if (mode === 'upload' && (!file || file.size > 32 * 1024 * 1024)) { setError('Choose a file no larger than 32 MiB.'); return; }
    if (mode === 'upload' && !window.confirm(`Upload to ${path}? An existing file may be overwritten.`)) return;
    const fields = { binding_id: roleID, instance_id: instanceID, region, remote_path: path, platform, ...(express ? { express_bucket:bucket.trim() } : {}) };
    const controller = new AbortController(); request.current = controller; setBusy(true);
    try {
      let response: Response;
      if (mode === 'upload') {
        const form = new FormData();
        for (const [key, value] of Object.entries(fields)) form.set(key, value);
        form.set('file', file!);
        response = await fetch(endpoint, { method: 'POST', credentials: 'same-origin', body: form, signal: controller.signal });
      } else {
        response = await fetch(endpoint, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(fields), signal: controller.signal });
      }
      if (!response.ok) throw new Error('transfer failed');
      if (mode === 'download') {
        const result = await response.json() as { data: string; filename: string };
        const bytes = Uint8Array.from(atob(result.data), c => c.charCodeAt(0));
        const url = URL.createObjectURL(new Blob([bytes]));
        const anchor = document.createElement('a'); anchor.href = url; anchor.download = result.filename || 'download'; anchor.click();
        setTimeout(() => URL.revokeObjectURL(url), 5000);
      }
      setMessage(mode === 'upload' ? 'Upload complete.' : 'Download complete.');
    } catch {
      if (!controller.signal.aborted) setError(express ? 'Transfer failed or authorization expired. The transfer or S3 cleanup may be incomplete.' : 'Transfer failed or AWS authorization expired.');
    } finally { if (!controller.signal.aborted) setBusy(false); }
  };

  const field = 'block w-full mt-1 px-3 py-2 bg-elev border border-border rounded text-text-pri';
  return <section className="bg-surface border border-border rounded-lg p-4 space-y-3" aria-label={`${mode === 'upload' ? 'Upload' : 'Download'} for ${instanceID}`}>
    <div className="flex justify-between gap-3"><h2 className="font-semibold">{mode === 'upload' ? 'Upload to' : 'Download from'} {instanceID}</h2><button type="button" onClick={onClose}>Close</button></div>
    <label className="block text-sm">Remote path<input className={field} value={path} disabled={busy} onChange={e => setPath(e.target.value)} /></label>
    <label className="block text-sm">Instance platform<select className={field} value={platform} disabled={busy} onChange={e => setPlatform(e.target.value)}><option value="">Select platform</option><option value="linux">Linux</option><option value="windows">Windows</option></select></label>
    <button type="button" disabled={busy || !platform} className="px-3 py-2 border border-border rounded disabled:opacity-50" onClick={() => setBrowsing(true)}>Browse files</button>
    {browsing && <FileBrowserModal open onOpenChange={setBrowsing} instanceId={instanceID} instanceName={instanceID} awsRegion={region} userRoleID={roleID} platform={platform} onUpload={selected => { setPath(selected.endsWith('/') || selected.endsWith('\\') ? selected : `${selected}${platform === 'windows' ? '\\' : '/'}`); setBrowsing(false); }} onDownload={selected => { setPath(selected); setBrowsing(false); }} />}
    {mode === 'upload' && <label className="block text-sm">File<input type="file" className={field} disabled={busy} onChange={e => setFile(e.target.files?.[0] ?? null)} /></label>}
    <label className="block text-sm"><input type="checkbox" checked={express} disabled={busy} onChange={e => setExpress(e.target.checked)} /> Express via S3</label>
    {express && <><label className="block text-sm">S3 bucket<input className={field} value={bucket} disabled={busy} onChange={e => setBucket(e.target.value)} /></label><p className="text-sm text-warn">Bucket permissions determine who can read or modify temporary files. The instance needs AWS CLI and S3 access; the selected role needs S3 access and permission to list and delete object versions. Use an absolute instance path and a lifecycle rule to remove temporary objects and incomplete uploads. Cancellation may leave a temporary file on the instance or a command running.</p></>}
    <p className="text-sm text-text-mut">Transfers use AWS Systems Manager and are limited to 32 MiB. Cancellation may not stop a command already running on the instance.</p>
    <button type="button" disabled={busy || !path.trim() || !platform || (express && !bucket.trim())} className="px-3 py-2 border border-border rounded disabled:opacity-50" onClick={() => void submit()}>{busy ? 'Transferring…' : mode === 'upload' ? 'Upload file' : 'Download file'}</button>
    {message && <p role="status" className="text-sm text-text-mut">{message}</p>}{error && <p role="alert" className="text-sm text-danger">{error}</p>}
  </section>;
}
