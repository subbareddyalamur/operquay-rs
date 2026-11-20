import { useState } from 'react';
import { Button, Input } from '@/components/primitives';
import { api } from '@/lib/api';
import { canSendCredentials } from '@/lib/credentialTransport';
import { useAuthStore } from '@/stores/auth';

export function AdminPasswordForm() {
  const me = useAuthStore((s) => s.me);
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  if (!me || me.role !== 'admin' || me.email.toLowerCase() !== 'admin@local' || me.method === 'sso') return null;

  const submit = async () => {
    setError('');
    if (!canSendCredentials('/api/auth/admin-password')) {
      setError('HTTPS is required to change the password. Open Operquay at its HTTPS address.');
      return;
    }
    setBusy(true);
    const result = await api.post<{ status: string }>('/api/auth/admin-password', { current_password: current, new_password: next });
    if (!result.ok) {
      setError(result.error.status === 401 ? 'Current password was not accepted.' : result.error.status === 400 ? 'Password must be between 12 and 72 bytes.' : result.error.status === 429 ? 'Too many attempts. Try again later.' : 'Could not change the password.');
      setBusy(false);
      return;
    }
    setCurrent('');
    setNext('');
    setConfirm('');
    await useAuthStore.getState().load();
    useAuthStore.setState({ expired: true, signInOpen: true });
  };

  return (
    <form className="bg-elev/50 border border-border rounded-md p-3 space-y-3 max-w-lg" onSubmit={(e) => { e.preventDefault(); void submit(); }}>
      <div className="text-[13px] font-semibold text-text-pri">Change admin@local password</div>
      <p className="text-[11px] text-text-mut">Changing it signs out existing password sessions. The bootstrap password in .env is not updated.</p>
      <label className="block space-y-1 text-[12px] text-text-mut">Current password<Input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} /></label>
      <label className="block space-y-1 text-[12px] text-text-mut">New password<Input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} /></label>
      <label className="block space-y-1 text-[12px] text-text-mut">Confirm new password<Input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} /></label>
      {confirm && next !== confirm && <p className="text-[11px] text-danger">Passwords do not match.</p>}
      {error && <p role="alert" className="text-[12px] text-danger">{error}</p>}
      <Button type="submit" size="sm" loading={busy} disabled={busy || !current || !next || next !== confirm}>Change password</Button>
    </form>
  );
}
