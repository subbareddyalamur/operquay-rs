import { useEffect, useState, type FormEvent } from 'react';
import { api } from '@/lib/api';

type Clone = { id: string; source_instance_id: string; clone_name: string; region: string; image_id?: string; image_name: string; phase: string; instance_id?: string };
type Settings = { ami_id: string; instance_type: string; subnet_id: string; security_group_ids: string[] | null; key_name: string; iam_profile: string; tags: Record<string, string> | null; available_subnets?: { subnet_id: string; name: string; az: string }[] | null; available_sgs?: { group_id: string; group_name: string }[] | null; warnings?: string[] };

export function UserAWSClone({ roleID, region, instanceID, instanceName, open }: { roleID: string; region: string; instanceID: string; instanceName: string; open?: boolean }) {
  const [name, setName] = useState(`${instanceName}-clone`);
  const [clones, setClones] = useState<Clone[]>([]);
  const [recoverable, setRecoverable] = useState<Clone[] | null>(null);
  const [incomplete, setIncomplete] = useState(false);
  const [intent, setIntent] = useState<{ id: string; name: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [editing, setEditing] = useState<{ id: string; settings: Settings; groups: string; tags: string } | null>(null);
  const query = `binding_id=${encodeURIComponent(roleID)}`;
  const put = (clone: Clone) => setClones(previous => [clone, ...previous.filter(item => item.id !== clone.id)]);

  async function list() {
    const result = await api.get<Clone[]>(`/api/aws/clones?${query}`);
    if (result.ok) setClones(previous => [...previous, ...result.data.filter(item => item.source_instance_id === instanceID && item.region === region && !previous.some(current => current.id === item.id))]);
    else setError('Could not load clone operations for this role.');
  }

  async function findEarlier() {
    setBusy(true); setError('');
    const result = await api.get<{ operations: Clone[]; incomplete: boolean }>(`/api/aws/clones/recoverable?${query}&instance_id=${encodeURIComponent(instanceID)}&region=${encodeURIComponent(region)}`);
    setBusy(false);
    if (!result.ok) { setError('Could not check earlier clone operations.'); return; }
    setRecoverable(result.data.operations); setIncomplete(result.data.incomplete);
  }

  async function recover(id: string) {
    if (!window.confirm('Transfer this clone operation to the current login and AWS role? The old scope will lose access. AWS resources will not be changed.')) return;
    setBusy(true); setError('');
    const result = await api.post<Clone>(`/api/aws/clones/${encodeURIComponent(id)}/recover`, { binding_id:roleID });
    setBusy(false);
    if (!result.ok) { setError('AWS could not confirm this operation with the selected role, or its scope changed. No resource was deleted.'); return; }
    put(result.data); setRecoverable(previous => previous?.filter(item => item.id !== id) ?? null);
  }

  async function start(event: FormEvent) {
    event.preventDefault();
    const request = intent ?? { id: crypto.randomUUID(), name: name.trim() };
    if (!request.name) { setError('Enter a clone name.'); return; }
    if (!window.confirm('Create an AMI and snapshots? They may incur charges. The source is not rebooted, so the image is crash-consistent.')) return;
    setIntent(request); setBusy(true); setError('');
    const result = await api.post<Clone>('/api/aws/clones/start', { request_id:request.id, binding_id:roleID, region, instance_id:instanceID, clone_name:request.name });
    setBusy(false);
    if (!result.ok) { setError(`The request outcome is unknown. Retry this same request or check AWS before starting another (request ${request.id}).`); return; }
    put(result.data); setIntent(null);
  }

  async function check(id: string) {
    setBusy(true); setError('');
    const result = await api.get<Clone>(`/api/aws/clones/${encodeURIComponent(id)}?${query}`);
    setBusy(false);
    if (!result.ok) { setError('Could not check clone status. No AWS resource was removed.'); return; }
    put(result.data);
  }

  async function configure(id: string) {
    setBusy(true); setError('');
    const result = await api.get<Settings>(`/api/aws/clones/${encodeURIComponent(id)}/settings?${query}`);
    setBusy(false);
    if (!result.ok) { setError('Could not load source settings.'); return; }
    setEditing({ id, settings:result.data, groups:(result.data.security_group_ids ?? []).join(', '), tags:JSON.stringify(result.data.tags ?? {}, null, 2) });
  }

  async function launch(event: FormEvent) {
    event.preventDefault();
    if (!editing) return;
    let tags: unknown;
    try { tags = JSON.parse(editing.tags); } catch { setError('Tags must be a JSON object of string values.'); return; }
    if (!tags || typeof tags !== 'object' || Array.isArray(tags) || Object.values(tags).some(value => typeof value !== 'string')) { setError('Tags must be a JSON object of string values.'); return; }
    const { ami_id, instance_type, subnet_id, key_name, iam_profile } = editing.settings;
    const settings = { ami_id, instance_type, subnet_id, key_name, iam_profile, security_group_ids: editing.groups.split(',').map(group => group.trim()).filter(Boolean), tags };
    if (!window.confirm('Launch one EC2 instance using these settings? AWS charges may apply.')) return;
    setBusy(true); setError('');
    const result = await api.post<Clone>(`/api/aws/clones/${encodeURIComponent(editing.id)}/launch`, { binding_id:roleID, settings });
    setBusy(false);
    if (!result.ok) { setError('Launch outcome may be unknown. Check status before attempting another launch.'); setEditing(null); return; }
    put(result.data); setEditing(null);
  }

  // list() de-duplicates, so a toggle event fired for the initially open dialog is harmless.
  useEffect(() => { if (open) void list(); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  const field = 'ml-2 rounded border border-border bg-elev p-1 text-text-pri';
  return <details open={open} className="mt-2 border border-border rounded p-2" onToggle={event => { if (event.currentTarget.open) void list(); }}>
    <summary className="cursor-pointer">Clone instance</summary>
    <p className="mt-2 text-xs text-text-mut">AMI snapshots and a new instance can incur charges. Operquay never automatically deletes them.</p>
    <form onSubmit={event => void start(event)} className="mt-2 flex flex-wrap items-end gap-2">
      <label className="text-xs">Clone name<input aria-label={`Clone name for ${instanceID}`} required maxLength={128} disabled={busy || !!intent} value={name} onChange={event => setName(event.target.value)} className={field} /></label>
      <button type="submit" disabled={busy} aria-label={`Create clone image for ${instanceID}`} className="px-3 py-1 border border-border rounded disabled:opacity-50">{intent ? 'Retry same request' : 'Create clone image'}</button>
    </form>
    {error && <p role="alert" className="mt-2 text-xs text-danger">{error}</p>}
    <p className="mt-2 text-xs text-text-mut">Showing the latest 100 operations for this login and role. Earlier operations require explicit recovery and AWS confirmation.</p>
    <button type="button" disabled={busy} aria-label={`Find earlier clones for ${instanceID}`} className="mt-1 px-2 py-1 border border-border rounded" onClick={() => void findEarlier()}>Find earlier clones</button>
    {recoverable && <div className="mt-2 text-xs">
      {incomplete && <p>Some earlier operations may be missing because AWS could not confirm them or the search was limited. A missing result does not prove resources were not created.</p>}
      {recoverable.length === 0 && <p>No confirmed earlier clones found.</p>}
      {recoverable.map(clone => <p key={clone.id} className="mt-1">{clone.clone_name} · {clone.id} <button type="button" disabled={busy} aria-label={`Recover clone ${clone.id}`} className="ml-2 px-2 py-1 border border-border rounded" onClick={() => void recover(clone.id)}>Recover</button></p>)}
    </div>}
    {clones.map(clone => <div key={clone.id} className="mt-2 border-t border-border pt-2 text-xs">
      <p><strong>{clone.clone_name}</strong> · {clone.id}</p>
      {clone.phase === 'create_unknown' && <p>AMI outcome is unknown. Check status; no result does not prove creation failed.</p>}
      {clone.phase === 'image_pending' && <p>AMI creation is pending: {clone.image_id}.</p>}
      {clone.phase === 'image_ready' && <p>AMI is ready: {clone.image_id}.</p>}
      {clone.phase === 'image_failed' && <p>AMI creation failed. AWS resources may remain.</p>}
      {clone.phase === 'launch_unknown' && <p>Launch outcome is unknown. Check status; do not start another clone until you have checked AWS.</p>}
      {clone.phase === 'complete' && <p>Instance launched: {clone.instance_id}. The AMI remains in AWS.</p>}
      <button type="button" disabled={busy} aria-label={`Check clone ${clone.id}`} className="mt-1 mr-2 px-2 py-1 border border-border rounded" onClick={() => void check(clone.id)}>Check status</button>
      {clone.phase === 'image_ready' && <button type="button" disabled={busy} aria-label={`Configure clone ${clone.id}`} className="mt-1 px-2 py-1 border border-border rounded" onClick={() => void configure(clone.id)}>Configure launch</button>}
    </div>)}
    {editing && <form onSubmit={event => void launch(event)} className="mt-3 space-y-2 border-t border-border pt-2 text-xs">
      <p>Review settings for {editing.settings.ami_id}.</p>
      {editing.settings.warnings?.map(warning => <p role="status" key={warning}>{warning}</p>)}
      <label className="block">Instance type<input aria-label="Clone instance type" required value={editing.settings.instance_type} onChange={event => setEditing({ ...editing, settings:{ ...editing.settings, instance_type:event.target.value } })} className={field} /></label>
      <label className="block">Subnet ID<input aria-label="Clone subnet ID" required list={`clone-subnets-${editing.id}`} value={editing.settings.subnet_id} onChange={event => setEditing({ ...editing, settings:{ ...editing.settings, subnet_id:event.target.value } })} className={field} /></label>
      <datalist id={`clone-subnets-${editing.id}`}>{(editing.settings.available_subnets ?? []).map(subnet => <option key={subnet.subnet_id} value={subnet.subnet_id}>{subnet.name} {subnet.az}</option>)}</datalist>
      <label className="block">Security group IDs (comma-separated)<input aria-label="Clone security group IDs" value={editing.groups} onChange={event => setEditing({ ...editing, groups:event.target.value })} className={field} /></label>
      {(editing.settings.available_sgs ?? []).length > 0 && <p>Available groups: {editing.settings.available_sgs?.map(group => `${group.group_id} (${group.group_name})`).join(', ')}</p>}
      <label className="block">Key pair name<input aria-label="Clone key pair" value={editing.settings.key_name ?? ''} onChange={event => setEditing({ ...editing, settings:{ ...editing.settings, key_name:event.target.value } })} className={field} /></label>
      <label className="block">IAM instance profile ARN<input aria-label="Clone instance profile" value={editing.settings.iam_profile ?? ''} onChange={event => setEditing({ ...editing, settings:{ ...editing.settings, iam_profile:event.target.value } })} className={field} /></label>
      <label className="block">Tags (JSON)<textarea aria-label="Clone tags" value={editing.tags} onChange={event => setEditing({ ...editing, tags:event.target.value })} className={`${field} block w-full`} rows={4} /></label>
      <button type="submit" disabled={busy} className="px-3 py-1 border border-border rounded">Launch clone</button>
      <button type="button" disabled={busy} className="ml-2 px-3 py-1 border border-border rounded" onClick={() => setEditing(null)}>Cancel</button>
    </form>}
  </details>;
}
