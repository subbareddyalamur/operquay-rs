import { useEffect, useState } from 'react';
import { apiGet } from '@/lib/api';

type ConnectedRole = { id: string; label: string; account_id: string };

export function UserTopologyPeers({ roleID, selected, onChange }: { roleID: string; selected: string[]; onChange: (ids: string[]) => void }) {
  const [roles, setRoles] = useState<ConnectedRole[]>([]);
  const [error, setError] = useState('');
  useEffect(() => {
    let active = true;
    void apiGet<ConnectedRole[]>('/api/aws/connected-roles').then(result => {
      if (!active) return;
      if (result.ok) setRoles(result.value);
      else setError('Connected roles could not be loaded.');
    });
    return () => { active = false; };
  }, []);
  const sourceAccount = roles.find(role => role.id === roleID)?.account_id;
  const selectedAccounts = new Set(roles.filter(role => selected.includes(role.id)).map(role => role.account_id));
  return <details className="border-b border-border bg-surface px-3 py-2 text-sm text-text-pri">
    <summary className="cursor-pointer">Peer account roles</summary>
    <p className="mt-2 text-xs text-text-mut">Select connected roles explicitly, at most one per other account. Unselected accounts remain unavailable.</p>
    {error && <p role="alert" className="text-danger">{error}</p>}
    {!error && !sourceAccount && <p className="text-text-mut">Source role unavailable; reconnect it to select peers.</p>}
    {sourceAccount && roles.filter(role => role.id !== roleID).map(role => {
      const checked = selected.includes(role.id);
      const disabled = role.account_id === sourceAccount || (!checked && (selectedAccounts.has(role.account_id) || selected.length >= 8));
      return <label key={role.id} className="block py-1"><input type="checkbox" checked={checked} disabled={disabled} onChange={() => onChange(checked ? selected.filter(id => id !== role.id) : [...selected, role.id].sort())} /> {role.label} · {role.account_id}</label>;
    })}
  </details>;
}
